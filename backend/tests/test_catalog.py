"""Benchmark catalogs (stig_sync / catalog_rules): only reviewed mappings
whose check text still matches the imported release are evaluated; a rule
DISA changed upstream is set aside for re-review; coverage is stated against
the whole benchmark. Fully offline (no network)."""
import json

import yaml

from app import catalog_rules, stig_sync


def _setup(tmp_path, monkeypatch, check_now="check v2"):
    cat = tmp_path / "catalog"
    cat.mkdir()
    (cat / "sources.yaml").write_text(yaml.safe_dump({"benchmarks": [
        {"name": "Demo_NDM", "vendor": "cisco_ios", "label": "Demo NDM STIG"}]}))
    rules = {
        "V-1": {"title": "exec timeout", "severity": "medium", "check": "check v1", "check_sha": stig_sync.check_sha("check v1")},
        "V-2": {"title": "telnet off", "severity": "high", "check": check_now, "check_sha": stig_sync.check_sha(check_now)},
        "V-3": {"title": "documented procedure", "severity": "low", "check": "ask the ISSO", "check_sha": "x"},
    }
    (cat / "Demo_NDM.json").write_text(json.dumps({"version": "1", "release": "2", "released": "01 Jan 2026",
                                                    "rules": rules}))
    mp = tmp_path / "map.yaml"
    mp.write_text(yaml.safe_dump({"benchmarks": {"Demo_NDM": {
        "V-1": {"check_type": "range", "predicate": {"field": "AC.session_idle_timeout_minutes", "max": 10},
                "check_sha": stig_sync.check_sha("check v1")},
        "V-2": {"check_type": "boolean", "predicate": {"field": "AC.telnet_enabled", "equals": False},
                "check_sha": stig_sync.check_sha("check v2")},
    }}}))
    monkeypatch.setattr(catalog_rules, "CATALOG_DIR", str(cat))
    monkeypatch.setattr(catalog_rules, "MAP_FILE", str(mp))


def test_fresh_mappings_become_rules(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    rows = {r["standard_ref"]: r for r in catalog_rules.rule_rows()}
    assert set(rows) == {"V-1", "V-2"}
    assert rows["V-2"]["severity"] == "CAT_I" and rows["V-2"]["applies_to_vendors"] == ["cisco_ios"]
    assert rows["V-1"]["standard_version"] == "Demo NDM STIG V1R2"


def test_changed_upstream_check_is_set_aside_for_rereview(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, check_now="check v2, revised by DISA")
    assert {r["standard_ref"] for r in catalog_rules.rule_rows()} == {"V-1"}
    cov = catalog_rules.coverage()[0]
    assert cov["total"] == 3 and cov["automated"] == 1 and cov["manual"] == 2 and cov["needs_rereview"] == ["V-2"]


def test_diff_reports_added_removed_and_changed():
    old = {"rules": {"V-1": {"check_sha": "a"}, "V-2": {"check_sha": "b"}}}
    new = {"rules": {"V-2": {"check_sha": "c"}, "V-3": {"check_sha": "d"}}}
    assert stig_sync.diff(old, new) == {"added": ["V-3"], "removed": ["V-1"], "check_changed": ["V-2"]}


def test_coverage_endpoint_reports_every_tracked_benchmark(client):
    body = client.get("/frameworks/coverage").json()
    names = {b["name"] for b in body["benchmarks"]}
    assert {"Cisco_IOS_XE_Router_NDM", "Juniper_SRX_Services_Gateway_NDM", "Fortinet_FortiGate_Firewall_NDM"} <= names
    for b in body["benchmarks"]:
        assert b["automated"] + b["manual"] == b["total"] > 0
