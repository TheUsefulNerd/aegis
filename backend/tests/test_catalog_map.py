"""The real reviewed STIG mapping file (rules/stig_catalog_map.yaml): every
mapping points at a rule that exists in the imported DISA catalog with the
same check text, every field it reads exists, and mapped rules decide
end-to-end through the API (AI off) on explicit evidence only."""
import io
import json
import os

import yaml

from app import catalog_rules, rule_engine
from app.canonical_schema import FIELD_METADATA
from app.main import _predicate_fields


def _map():
    return yaml.safe_load(open(catalog_rules.MAP_FILE, encoding="utf-8"))["benchmarks"]


def test_every_mapping_is_fresh_against_the_imported_catalog():
    maps = _map()
    assert maps, "stig_catalog_map.yaml has no mappings"
    for bench, rules in maps.items():
        cat = json.load(open(os.path.join(catalog_rules.CATALOG_DIR, f"{bench}.json"), encoding="utf-8"))["rules"]
        for vid, m in rules.items():
            assert vid in cat, (bench, vid)
            assert m["check_sha"] == cat[vid]["check_sha"], (bench, vid)
            assert m.get("note"), (bench, vid)
    assert all(c["needs_rereview"] == [] for c in catalog_rules.coverage())


def test_every_predicate_field_exists_and_every_mapping_loads():
    maps = _map()
    rows = catalog_rules.rule_rows()
    assert len(rows) == sum(len(r) for r in maps.values())
    for row in rows:
        fields = _predicate_fields(row["check_type"], row["predicate"])
        assert fields and all(f in FIELD_METADATA for f in fields), row["standard_ref"]
        assert row["control_family"] in ("AC", "AU", "IA", "SC", "CM")
        # Every predicate stays NOT_EVALUATED with no evidence at all.
        assert rule_engine.evaluate(row["check_type"], row["predicate"], {}).result == rule_engine.NOT_EVALUATED


def test_catalog_ids_do_not_collide_with_hand_written_stig_rules():
    hand = yaml.safe_load(open(os.path.join(os.path.dirname(catalog_rules.MAP_FILE), "stig_cisco_ios_xe.yaml"),
                               encoding="utf-8"))
    hand_ids = {r["id"].replace("STIG-", "") for r in hand["rules"]}
    mapped = {v for rules in _map().values() for v in rules}
    assert not hand_ids & mapped


def test_range_on_a_list_counts_distinct_entries():
    pred = {"field": "AU.ntp_servers", "min": 2}
    assert rule_engine.evaluate("range", pred, {"AU.ntp_servers": ["10.0.0.1", "10.0.0.2"]}).result == "PASS"
    assert rule_engine.evaluate("range", pred, {"AU.ntp_servers": ["10.0.0.1", "10.0.0.1"]}).result == "FAIL"
    assert rule_engine.evaluate("range", pred, {"AU.ntp_servers": []}).result == "FAIL"
    assert rule_engine.evaluate("range", pred, {}).result == "NOT_EVALUATED"


GOOD_JUNOS = """set version 20.4R3.8
set system host-name r1
set system login password minimum-length 15
set system login retry-options tries-before-disconnect 3
set system ntp server 10.0.0.1
set system ntp server 10.0.0.2
set system services ssh protocol-version v2
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha2-256
set system tacplus-server 10.0.0.9 port 49
"""
BAD_JUNOS = """set version 20.4R3.8
set system host-name r1
set system login password minimum-length 8
set system login retry-options tries-before-disconnect 5
set system ntp server 10.0.0.1
set system services ssh protocol-version v2
set system services ssh macs hmac-sha2-512
set system services ssh macs hmac-sha1
"""


def _run(client, name, text):
    res = client.post("/ingest", files={"file": (name, io.BytesIO(text.encode()), "text/plain")})
    assert res.status_code == 200, res.text
    return {f["rule_id"]: f for f in client.post(f"/configs/{res.json()['config_id']}/evaluate").json()["findings"]}


def test_mapped_junos_rules_pass_on_explicit_evidence_and_fail_on_a_bad_config(client):
    good = _run(client, "srx-good.conf", GOOD_JUNOS)
    for vid in ("V-223217", "V-223188", "V-223205", "V-223225", "V-229025"):
        assert good[vid]["result"] == "PASS", (vid, good[vid])
    bad = _run(client, "srx-bad.conf", BAD_JUNOS)
    for vid in ("V-223217", "V-223188", "V-223205", "V-223225"):
        assert bad[vid]["result"] == "FAIL", (vid, bad[vid])
    assert bad["V-229025"]["result"] == "NOT_EVALUATED"  # no auth-server line: no evidence either way
    assert bad["V-223217"]["remediation_source"] == "DISA STIG fix text"
    assert "minimum-length 15" in bad["V-223217"]["remediation"]


CISCO = """version 17.9
hostname r1
ip ssh version 2
{mac}
line vty 0 4
 exec-timeout 5 0
 transport input ssh
"""


def test_compound_rule_reports_its_weakest_evidence(client):
    ok = _run(client, "r-ok.cfg", CISCO.format(mac="ip ssh server algorithm mac hmac-sha2-256"))
    assert ok["V-215844"]["result"] == "PASS" and ok["V-215844"]["confidence_tier"] == "tier1"
    # No MAC list: the IOS-XE default includes hmac-sha1 - FAIL, on the default.
    dflt = _run(client, "r-default.cfg", CISCO.format(mac="!"))
    assert dflt["V-215844"]["result"] == "FAIL" and dflt["V-215844"]["confidence_tier"] == "vendor_default"


def test_short_cisco_login_block_is_not_a_compliant_lockout(client):
    got = _run(client, "r-block.cfg", CISCO.format(mac="login block-for 60 attempts 3 within 120"))
    assert got["V-215813"]["result"] == "FAIL"
    got = _run(client, "r-block2.cfg", CISCO.format(mac="login block-for 900 attempts 3 within 120"))
    assert got["V-215813"]["result"] == "PASS"


# ---- 2026-09-28: more STIG rules; each block/entry-scoped mechanism gets an
# adversarial case (one object compliant, another not) that must not PASS.

IOS = "version 15.2\nhostname r2\nservice password-encryption\nip ssh version 2\n"


def _ifaces(*bodies):
    return "".join(f"interface GigabitEthernet{i}\n{b}" for i, b in enumerate(bodies, 1))


def test_all_external_interface_rules_pass_only_when_every_interface_complies(client):
    one = _run(client, "i1.cfg", IOS + _ifaces(" no ip redirects\n no ip proxy-arp\n", " ip address 10.0.0.1 255.255.255.0\n"))
    assert one["V-216657"]["result"] == "NOT_EVALUATED" and one["V-216676"]["result"] == "NOT_EVALUATED"
    both = _run(client, "i2.cfg", IOS + _ifaces(" no ip redirects\n no ip proxy-arp\n", " no ip redirects\n no ip proxy-arp\n"))
    assert both["V-216657"]["result"] == "PASS" and both["V-216676"]["result"] == "PASS"


def test_unreachables_needs_null0_too(client):
    body = " no ip unreachables\n"
    no_null = _run(client, "u1.cfg", IOS + _ifaces(body, body))
    assert no_null["V-216655"]["result"] == "NOT_EVALUATED"
    with_null = _run(client, "u2.cfg", IOS + _ifaces(body, body) + "interface Null0\n no ip unreachables\n")
    assert with_null["V-216655"]["result"] == "PASS"


def test_one_interface_without_cdp_is_not_a_device_wide_pass(client):
    # Found 2026-09-28: `no cdp enable` on one interface passed the
    # hand-written STIG V-216675 for the whole device.
    one = _run(client, "c1.cfg", IOS + _ifaces(" no cdp enable\n", " ip address 10.0.0.1 255.255.255.0\n"))
    assert one["STIG-V-216675"]["result"] != "PASS"
    glob = _run(client, "c2.cfg", IOS + "no cdp run\n" + _ifaces(" ip address 10.0.0.1 255.255.255.0\n"))
    assert glob["STIG-V-216675"]["result"] == "PASS"


def test_a_stray_interface_line_in_a_fragment_proves_nothing(client):
    # A medium-confidence Cisco fragment: a VTY block, no interface blocks.
    got = _run(client, "frag.cfg", "hostname r3\nno ip redirects\nno cdp enable\nline vty 0 4\n transport input ssh\n")
    assert got["V-216657"]["result"] == "NOT_EVALUATED"
    assert got["STIG-V-216675"]["result"] == "NOT_EVALUATED"


def test_management_timeout_covers_console_vty_and_http(client):
    lines = "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 5 0\n"
    ok = _run(client, "t1.cfg", IOS + "no ip http server\nno ip http secure-server\n" + lines)
    assert ok["V-215833"]["result"] == "PASS"
    http = _run(client, "t2.cfg", IOS + "ip http secure-server\n" + lines)
    assert http["V-215833"]["result"] == "NOT_EVALUATED"  # HTTPS on, no idle policy shown
    vty2 = _run(client, "t3.cfg", IOS + "no ip http server\nno ip http secure-server\n" + lines
                + "line vty 5 15\n transport input ssh\n")
    assert vty2["V-215833"]["result"] == "FAIL"  # vty 5 15 runs at the 10-minute default
    con = _run(client, "t4.cfg", IOS + "no ip http server\nno ip http secure-server\n"
               "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 5 0\n")
    assert con["V-215833"]["result"] == "FAIL"


def test_aux_port_enabled_is_unknown_not_fail(client):
    on = _run(client, "a1.cfg", IOS + "line aux 0\n transport input none\n")
    assert on["V-216661"]["result"] == "NOT_EVALUATED"
    off = _run(client, "a2.cfg", IOS + "line aux 0\n no exec\n")
    assert off["V-216661"]["result"] == "PASS"


JUNOS = """set version 21.4R1
set system host-name srx
set system services ssh protocol-version v2
{extra}
"""


def test_junos_syslog_severity_and_facility_are_read_per_host(client):
    notice = _run(client, "j1.conf", JUNOS.format(extra="set system syslog host 10.0.0.9 any notice"))
    assert notice["V-223194"]["result"] == "FAIL" and notice["V-223181"]["result"] == "FAIL"
    change = _run(client, "j2.conf", JUNOS.format(extra="set system syslog host 10.0.0.9 change-log info"))
    assert change["V-223181"]["result"] == "PASS" and change["V-223194"]["result"] == "FAIL"
    both = _run(client, "j3.conf", JUNOS.format(
        extra="set system syslog host 10.0.0.9 any any\nset system syslog file messages any any"))
    assert both["V-223187"]["result"] == "PASS" and both["V-223195"]["result"] == "PASS"


def test_junos_ssh_root_login_and_every_snmpv3_user(client):
    allow = _run(client, "j4.conf", JUNOS.format(extra="set system services ssh root-login allow"))
    assert allow["V-223212"]["result"] == "FAIL"
    deny = _run(client, "j5.conf", JUNOS.format(extra="set system services ssh root-login deny"))
    assert deny["V-223212"]["result"] == "PASS"
    users = ("set snmp v3 usm local-engine user a authentication-sha256 authentication-key k1\n"
             "set snmp v3 usm local-engine user a privacy-aes128 privacy-key k2\n"
             "set snmp v3 usm local-engine user b authentication-md5 authentication-key k3\n")
    mixed = _run(client, "j6.conf", JUNOS.format(extra=users))
    assert mixed["V-223224"]["result"] == "FAIL" and mixed["V-223226"]["result"] == "FAIL"
    good = (users.replace("user b authentication-md5", "user b authentication-sha256")
            + "set snmp v3 usm local-engine user b privacy-aes128 privacy-key k4\n")
    assert _run(client, "j7.conf", JUNOS.format(extra=good))["V-223224"]["result"] == "PASS"


FORTI = """#config-version=FGT60F-7.2.5-FW-build1517:opmode=0:vdom=0
config system global
    set hostname "fw2"
{glob}
end
{extra}
"""


def test_fortigate_admintimeout_and_lockout_are_exact(client):
    dflt = _run(client, "f1.conf", FORTI.format(glob="", extra=""))
    assert dflt["V-234213"]["result"] == "FAIL" and dflt["V-234168"]["result"] == "FAIL"  # defaults 5 min / 60 s
    ok = _run(client, "f2.conf", FORTI.format(glob="    set admintimeout 10\n    set admin-lockout-threshold 3\n"
                                                    "    set admin-lockout-duration 900", extra=""))
    assert ok["V-234213"]["result"] == "PASS" and ok["V-234168"]["result"] == "PASS"
    short = _run(client, "f3.conf", FORTI.format(glob="    set admintimeout 5", extra=""))
    assert short["V-234213"]["result"] == "FAIL"


def test_fortigate_every_ldap_server_and_snmp_user(client):
    ldap = ('config user ldap\n    edit "a"\n        set server 10.0.0.1\n        set secure ldaps\n    next\n'
            '    edit "b"\n        set server 10.0.0.2\n    next\nend')
    got = _run(client, "f4.conf", FORTI.format(glob="", extra=ldap))
    assert got["V-234208"]["result"] == "FAIL"
    both = ldap.replace("set server 10.0.0.2", "set server 10.0.0.2\n        set secure ldaps")
    assert _run(client, "f5.conf", FORTI.format(glob="", extra=both))["V-234208"]["result"] == "PASS"
    snmp = 'config system snmp user\n    edit "u"\n        set security-level auth-priv\n    next\nend'
    assert _run(client, "f6.conf", FORTI.format(glob="", extra=snmp))["V-234201"]["result"] == "FAIL"  # default sha1
    strong = snmp.replace("auth-priv\n", "auth-priv\n        set auth-proto sha256\n")
    assert _run(client, "f7.conf", FORTI.format(glob="", extra=strong))["V-234201"]["result"] == "PASS"


def test_fortigate_ntp_needs_two_custom_servers_and_sync(client):
    ntp = ('config system ntp\n    set ntpsync enable\n    set type custom\n    config ntpserver\n'
           '        edit 1\n            set server "10.0.0.1"\n        next\n'
           '        edit 2\n            set server "10.0.0.2"\n        next\n    end\nend')
    assert _run(client, "f8.conf", FORTI.format(glob="", extra=ntp))["V-234183"]["result"] == "PASS"
    guard = ntp.replace("set type custom", "set type fortiguard")
    assert _run(client, "f9.conf", FORTI.format(glob="", extra=guard))["V-234183"]["result"] == "FAIL"
    one = ntp.replace('        edit 2\n            set server "10.0.0.2"\n        next\n', "")
    assert _run(client, "f10.conf", FORTI.format(glob="", extra=one))["V-234183"]["result"] == "FAIL"


def test_junos_minimum_release_from_the_version_line(client):
    new = _run(client, "v1.conf", "set version 15.1X49-D15.4\nset system host-name a\nset system services ssh\n")
    assert new["V-223236"]["result"] == "PASS"
    old = _run(client, "v2.conf", "set version 11.4R7.5\nset system host-name a\nset system services ssh\n")
    assert old["V-223236"]["result"] == "FAIL"
    for v in ("12.1X44-D10", "20200609.165031.6_builder.r1115480"):
        got = _run(client, "v3.conf", f"set version {v}\nset system host-name a\nset system services ssh\n")
        assert got["V-223236"]["result"] == "NOT_EVALUATED", v
