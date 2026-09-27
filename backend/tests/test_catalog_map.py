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
