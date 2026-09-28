"""Regression tests for the final review (panel #3, 2026-09-28): each repro
must be FAIL or unknown, never PASS, and the fixed evidence must still PASS."""
import io
import json
import os

from app import cli, redaction, units

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "..", "samples")
BASE = """version 15.2
hostname R1
enable secret 9 [REDACTED:ENABLE_SECRET_HASH]
service password-encryption
no ip source-route
no service pad
ip ssh version 2
line vty 0 4
 transport input ssh
"""


def _verdicts(client, text, name="r.cfg"):
    body = client.post("/ingest", files={"file": (name, io.BytesIO(text.encode()), "text/plain")}).json()
    return {f["rule_id"]: f["result"] for f in client.post(f"/configs/{body['config_id']}/evaluate").json()["findings"]}


def test_no_logging_on_disables_every_syslog_host(client):
    got = _verdicts(client, BASE + "logging host 10.9.9.1\nlogging host 10.9.9.2\nno logging on\n")
    assert got["V-220139"] != "PASS" and got["CIS-2.2.4"] != "PASS" and got["NIST-AU-4-1"] != "PASS"


def test_ntp_authenticate_alone_is_not_ntp_authentication(client):
    assert _verdicts(client, BASE + "ntp authenticate\nntp server 10.1.1.1\n")["V-215843"] != "PASS"
    keyed = BASE + ("ntp authentication-key 1 hmac-sha2-256 [REDACTED:NTP_KEY]\nntp authenticate\n"
                    "ntp trusted-key 1\nntp server 10.1.1.1 key 1\n")
    assert _verdicts(client, keyed)["V-215843"] == "PASS"


def test_junos_inactive_and_deactivated_statements_are_not_evidence():
    brace = "system {\n    services {\n        ssh {\n            inactive: root-login deny;\n        }\n    }\n}\n"
    assert units.split_into_units(brace, "cli") == []
    s = "set system services ssh root-login deny\ndeactivate system services ssh root-login\n"
    assert "set system services ssh root-login deny" not in units.split_into_units(s, "cli")


def test_junos_deactivated_root_login_does_not_pass(client):
    raw = open(os.path.join(SAMPLES, "heldout", "heldout_03_junos_set_srx1.cfg"), encoding="utf-8").read()
    on = raw + "set system services ssh root-login deny\n"
    assert _verdicts(client, on, "j.cfg")["V-223212"] == "PASS"
    off = on + "deactivate system services ssh root-login\n"
    assert _verdicts(client, off, "j2.cfg")["V-223212"] != "PASS"


FORTI = """#config-version=FGVM64-7.2.5-FW-build1517:opmode=0:vdom=0
config system global
    set hostname "fw1"
end
config system password-policy
    set status enable
    set apply-to ipsec-preshared-key
    set minimum-length 15
    set min-upper-case-letter 1
end
config firewall policy
end
"""


def test_fortigate_password_policy_must_cover_admins(client):
    got = _verdicts(client, FORTI, "f.conf")
    assert got["V-234203"] != "PASS" and got["V-234204"] != "PASS"
    ok = _verdicts(client, FORTI.replace("set apply-to ipsec-preshared-key", "set apply-to admin-password"), "f2.conf")
    assert ok["V-234203"] == "PASS"


def test_junos_password_block_is_not_redacted():
    text = "system {\n    login {\n        password {\n            minimum-length 15;\n        }\n    }\n}\n"
    assert redaction.redact(text).text == text


def test_verify_of_an_empty_attestation_file_fails(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps([]))
    assert cli.main(["verify", str(p), "--fingerprint", "0" * 16]) == 1


# ---- final review #4 (2026-09-28 evening) ----

FORTI_LOG = """#config-version=FGVM64-7.2.5-FW-build1517:opmode=0:vdom=0
config system global
    set hostname "fw1"
end
config log syslogd setting
    set status disable
    set server "10.1.1.1"
end
config firewall policy
end
"""


def test_fortigate_log_server_counts_only_when_enabled(client):
    assert _verdicts(client, FORTI_LOG, "f.conf")["NIST-AU-4-1"] != "PASS"
    assert _verdicts(client, FORTI_LOG.replace("    set status disable\n", ""), "f2.conf")["NIST-AU-4-1"] != "PASS"
    on = _verdicts(client, FORTI_LOG.replace("set status disable", "set status enable"), "f3.conf")
    assert on["NIST-AU-4-1"] == "PASS"


def test_ia_5_1_d_covers_local_user_passwords(client):
    for weak in ("username admin privilege 15 password 0 [REDACTED:CLI_PASSWORD]\n",
                 "username admin password 7 [REDACTED:TYPE7_PASSWORD]\n",
                 "username admin secret 5 [REDACTED:USER_SECRET_HASH]\n"):
        assert _verdicts(client, BASE + weak)["NIST-IA-5-1-d"] != "PASS", weak
    assert _verdicts(client, BASE + "username admin secret 9 [REDACTED:USER_SECRET_HASH]\n")["NIST-IA-5-1-d"] == "PASS"


def test_crlf_config_is_recognized(client):
    body = client.post("/ingest", files={"file": ("crlf.cfg", io.BytesIO(BASE.replace("\n", "\r\n").encode()), "text/plain")}).json()
    assert body["vendor"] == "cisco_ios"


def test_coverage_counts_the_hand_written_rtr_rules(client):
    rtr = next(b for b in client.get("/frameworks/coverage").json()["benchmarks"] if b["name"] == "Cisco_IOS_XE_Router_RTR")
    assert rtr["automated"] >= 15


ACL_RULES = ["CIS-SUPPLEMENT-ACL-TELNET", "NIST-AC-4", "ISO-A.8.20"]


def test_acl_applied_only_outbound_is_not_inbound_protection(client):
    cfg = BASE + ("access-list 101 deny tcp any any eq 23\naccess-list 101 permit ip any any\n"
                  "interface Gi1\n ip access-group 101 out\n")
    got = _verdicts(client, cfg)
    assert all(got[r] != "PASS" for r in ACL_RULES)


def test_time_ranged_deny_is_not_always_active(client):
    cfg = BASE + ("access-list 101 deny tcp any any eq 23 time-range NEVER\naccess-list 101 permit ip any any\n"
                  "interface Gi1\n ip access-group 101 in\n")
    got = _verdicts(client, cfg)
    assert all(got[r] != "PASS" for r in ACL_RULES)


def test_named_acl_is_evaluated_by_sequence_number(client):
    cfg = BASE + ("ip access-list extended E\n 20 deny tcp any any eq telnet\n 10 permit ip any any\n"
                  "interface Gi1\n ip access-group E in\n")
    got = _verdicts(client, cfg)
    assert all(got[r] != "PASS" for r in ACL_RULES)


def test_empty_banner_is_no_banner(client):
    assert _verdicts(client, BASE + "banner login ^C^C\n")["CIS-1.3.2"] != "PASS"
    assert _verdicts(client, BASE + "banner login ^C\nAuthorized access only\n^C\n")["CIS-1.3.2"] == "PASS"


def test_no_ip_ssh_version_2_is_not_v2(client):
    assert _verdicts(client, BASE + "no ip ssh version 2\n")["CIS-2.1.1.2"] != "PASS"


def test_junos_syslog_host_without_facility_sends_nothing(client):
    raw = open(os.path.join(SAMPLES, "heldout", "heldout_03_junos_set_srx1.cfg"), encoding="utf-8").read()
    assert _verdicts(client, raw + "set system syslog host 10.1.1.1\n", "j.cfg")["NIST-AU-4-1"] != "PASS"
    assert _verdicts(client, raw + "set system syslog host 10.1.1.1 any info\n", "j2.cfg")["NIST-AU-4-1"] == "PASS"
