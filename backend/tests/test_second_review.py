"""Regression tests for the false PASSes found by the second adversarial
review (2026-09-27). Each case is the reviewer's repro config; the verdict
must be FAIL or NOT_EVALUATED, never PASS."""
import io

import pytest

BASE = """version 15.2
hostname R1
enable secret 9 [REDACTED:ENABLE_SECRET_HASH]
service password-encryption
no ip source-route
no service pad
ip ssh version 2
"""
VTY = "line vty 0 4\n transport input ssh\n"


def _verdicts(client, text, name="r.cfg"):
    body = client.post("/ingest", files={"file": (name, io.BytesIO(text.encode()), "text/plain")}).json()
    return {f["rule_id"]: f["result"] for f in client.post(f"/configs/{body['config_id']}/evaluate").json()["findings"]}


CASES = {
    # interface QoS policy is not control-plane protection
    "cpp_on_interface": (BASE + "interface Gi1\n service-policy input QOS-MARK\n!\n" + VTY, ["STIG-V-216650"]),
    # one VTY block without access-class leaves those lines open
    "vty_access_class_one_block": (BASE + "access-list 10 permit 10.0.0.0 0.0.0.255\nline vty 0 4\n access-class 10 in\n"
                                   " transport input ssh\nline vty 5 15\n transport input ssh\n", ["CIS-1.2.5"]),
    # exec-timeout 10 3000 is 60 minutes
    "exec_timeout_seconds": (BASE + "line vty 0 4\n exec-timeout 10 3000\n transport input ssh\n", ["CIS-1.2.8"]),
    # an object-group entry before the deny must not be dropped
    "object_group_before_deny": (BASE + "object-group service TELNETS\n tcp eq telnet\nip access-list extended EDGE\n"
                                 " permit object-group TELNETS any any\n deny tcp any any eq telnet\n permit ip any any\n"
                                 "interface Gi1\n ip access-group EDGE in\n" + VTY,
                                 ["CIS-SUPPLEMENT-ACL-TELNET", "NIST-AC-4", "ISO-A.8.20"]),
    # an IPv6 permit-all before the deny
    "ipv6_permit_all": (BASE + "ipv6 access-list V6IN\n permit ipv6 any any\n deny tcp any any eq telnet\n"
                        "interface Gi1\n ipv6 traffic-filter V6IN in\n" + VTY, ["CIS-SUPPLEMENT-ACL-TELNET", "NIST-AC-4"]),
    # an ACL nothing applies protects nothing
    "unapplied_acl": (BASE + "access-list 101 deny tcp any any eq 23\naccess-list 101 permit ip any any\n"
                      "interface Gi1\n ip address 1.1.1.1 255.255.255.0\n" + VTY, ["CIS-SUPPLEMENT-ACL-TELNET", "NIST-AC-4"]),
    # an applied but undefined ACL permits everything on IOS
    "applied_undefined_acl": (BASE + "access-list 101 deny tcp any any eq 23\naccess-list 101 permit ip any any\n"
                              "interface Gi1\n ip access-group 101 in\ninterface Gi2\n ip access-group 150 in\n" + VTY,
                              ["CIS-SUPPLEMENT-ACL-TELNET", "NIST-AC-4"]),
    # a type-7 enable password next to enable secret 9, in either order
    "enable_password_first": (BASE.replace("enable secret 9", "enable password 7 [REDACTED:TYPE7_PASSWORD]\nenable secret 9") + VTY,
                              ["CIS-1.4.1", "NIST-IA-5-1-d"]),
    "enable_password_last": (BASE + "enable password 7 [REDACTED:TYPE7_PASSWORD]\n" + VTY, ["CIS-1.4.1", "NIST-IA-5-1-d"]),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_no_false_pass(client, case):
    text, rules = CASES[case]
    got = _verdicts(client, text)
    assert {r: got.get(r) for r in rules if got.get(r) == "PASS"} == {}


FORTI = """#config-version=FGVM64-7.2.5-FW-build1517:opmode=0:vdom=0
config system global
    set hostname "fw1"
end
config system password-policy
    set minimum-length 15
    set min-upper-case-letter 1
    set change-8-characters enable
end
config system interface
    edit "port1"
        set allowaccess ping https ssh
    next
end
config firewall address
    edit "LAN_NET"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "EVERYTHING"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN_NET" "all"
        set dstaddr "all"
        set action accept
        set service "TELNET"
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "TELNET"
    next
end
"""


def test_fortigate_every_policy_address_counts(client):
    got = _verdicts(client, FORTI, "f.conf")
    assert got["NIST-AC-4"] == "FAIL" and got["ISO-A.8.20"] == "FAIL"


def test_fortigate_address_object_without_subnet_is_all(client):
    text = FORTI.replace('set srcaddr "LAN_NET" "all"', 'set srcaddr "EVERYTHING"')
    assert _verdicts(client, text, "f.conf")["NIST-AC-4"] == "FAIL"


def test_fortigate_undefined_address_object_fails_closed(client):
    text = FORTI.replace('set srcaddr "LAN_NET" "all"', 'set srcaddr "NOT_DEFINED"')
    assert _verdicts(client, text, "f.conf")["NIST-AC-4"] == "NOT_EVALUATED"


def test_fortigate_password_rules_need_the_policy_enabled(client):
    got = _verdicts(client, FORTI, "f.conf")
    for vid in ("V-234203", "V-234204", "V-234221"):
        assert got[vid] != "PASS"
    on = _verdicts(client, FORTI.replace("    set minimum-length 15", "    set status enable\n    set minimum-length 15"), "f.conf")
    assert on["V-234203"] == "PASS" and on["V-234204"] == "PASS"


def test_reviewer_regex_needs_a_literal_anchor(client):
    client.post("/ingest", files={"file": ("x.txt", io.BytesIO(b"version 17.3\nline vty 0 4\nfoo bar baz\n"), "text/plain")})
    item = next(i for i in client.get("/review-queue").json() if i["raw_unit"] == "foo bar baz")
    url = f"/review-queue/{item['id']}/confirm"
    base = {"reviewer_id": "r", "canonical_field": "AC.telnet_enabled", "value": False, "pattern_type": "regex"}
    for broad in (".", r"^\S", "^foo", "foo bar"):
        assert client.post(url, json={**base, "syntax_pattern": broad}).status_code == 422, broad
    assert client.post(url, json={**base, "syntax_pattern": r"^foo bar \w+$"}).status_code == 200
