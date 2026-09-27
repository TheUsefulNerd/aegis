"""Juniper Junos and Fortinet FortiOS were added as data only (seed YAML with
a fingerprint block + Tier-1 patterns; generic block flattening). These tests
pin that the full pipeline works on them with the AI switched off."""
import glob
import os

import yaml
from conftest import read_sample, sample_path

from app import fingerprint, redaction, units

DEMO = "sample_input_config_files"


def _ingest(client, name):
    with open(sample_path(DEMO, name), "rb") as f:
        res = client.post("/ingest", files={"file": (name, f, "text/plain")})
    assert res.status_code == 200, res.text
    return res.json()


def _eval(client, cfg):
    return {f["rule_id"]: f for f in client.post(f"/configs/{cfg}/evaluate").json()["findings"]}


def test_vendors_are_defined_by_seed_files_not_code():
    seeds = glob.glob(os.path.join(os.path.dirname(fingerprint.__file__), "seeds", "*.yaml"))
    with_fp = {yaml.safe_load(open(p, encoding="utf-8"))["vendor"] for p in seeds
               if "fingerprint" in (yaml.safe_load(open(p, encoding="utf-8")) or {})}
    assert {"cisco_ios", "pfsense", "sonic", "juniper_junos", "fortinet_fortios"} <= with_fp
    src = open(fingerprint.__file__, encoding="utf-8").read()
    assert "juniper" not in src.lower() and "fortinet" not in src.lower()


def test_junos_hierarchy_keeps_parent_context():
    text = "version 20.4R3.8;\nsystem {\n    services {\n        telnet;\n    }\n}\n"
    assert units.split_into_units(text, "cli") == ["set version 20.4R3.8", "set system services telnet"]
    assert fingerprint.fingerprint(text)["vendor"] == "juniper_junos"
    assert fingerprint.fingerprint("version 15.5\nline vty 0 4\n")["vendor"] == "cisco_ios"


def test_fortios_blocks_keep_parent_context():
    text = "config system global\n    set admintimeout 5\nend\nconfig system interface\n    edit \"wan1\"\n" \
           "        set allowaccess ping ssh\n    next\nend\n"
    assert units.split_into_units(text, "cli") == [
        "system global set admintimeout 5", "system interface edit wan1 set allowaccess ping ssh"]


def test_junos_end_to_end(client):
    body = _ingest(client, "07_juniper_srx_branch.conf")
    assert body["vendor"] == "juniper_junos" and body["hostname"] == "srx-branch-07"
    assert body["firmware_version"] == "20.4R3.8"
    f = body["fields"]
    assert f["AC.telnet_enabled"] is True and f["IA.ssh_version"] == 2 and f["SC.webgui_protocol"] is False
    assert f["AC.session_idle_timeout_minutes"] == 30 and "10.20.0.15" in f["AU.logging_host"]
    assert f["AC.snmp_community_strings"] == ["public"]
    r = _eval(client, body["config_id"])
    assert r["NIST-AC-17-2"]["result"] == "FAIL" and r["NIST-AC-17-2"]["confidence_tier"] == "tier1"
    assert r["NIST-SC-8"]["result"] == "PASS"
    assert "CIS-1.2.2" not in r  # Cisco benchmarks never apply to a Juniper device


def test_fortios_end_to_end(client):
    body = _ingest(client, "08_fortigate_60f_edge.conf")
    assert body["vendor"] == "fortinet_fortios" and body["model"] == "FGT60F"
    f = body["fields"]
    assert f["AC.telnet_enabled"] is True and f["AC.session_idle_timeout_minutes"] == 480
    assert f["AU.logging_enabled"] is True and f["AC.snmp_community_strings"] == ["public"]
    assert _eval(client, body["config_id"])["NIST-AC-17-2"]["result"] == "FAIL"


def test_new_vendor_secrets_never_survive_redaction():
    for name in ("07_juniper_srx_branch.conf", "08_fortigate_60f_edge.conf"):
        out = redaction.redact(read_sample(DEMO, name)).text
        assert "FAKE" not in out, name
