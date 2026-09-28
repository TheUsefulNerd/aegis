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
