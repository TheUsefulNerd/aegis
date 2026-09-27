"""Rules from imported benchmark catalogs (catalog/*.json, see stig_sync.py).

A catalog rule becomes an evaluated AEGIS rule only through a reviewed
mapping in rules/stig_catalog_map.yaml, and only while the mapping's recorded
check_sha still matches the catalog: if DISA changes a rule's check text in a
new release, its mapping is set aside as "needs re-review" rather than
silently evaluating a check written for the old text. Everything else in the
catalog is reported as manual review, so coverage is always stated against
the whole benchmark.
"""
import json
import os

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.join(HERE, "catalog")
MAP_FILE = os.path.join(HERE, "rules", "stig_catalog_map.yaml")
_SEVERITY = {"high": "CAT_I", "medium": "CAT_II", "low": "CAT_III"}


def _sources() -> list:
    p = os.path.join(CATALOG_DIR, "sources.yaml")
    return yaml.safe_load(open(p, encoding="utf-8"))["benchmarks"] if os.path.exists(p) else []


def _catalog(name: str):
    p = os.path.join(CATALOG_DIR, f"{name}.json")
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None


def _mappings() -> dict:
    if not os.path.exists(MAP_FILE):
        return {}
    return (yaml.safe_load(open(MAP_FILE, encoding="utf-8")) or {}).get("benchmarks") or {}


def rule_rows() -> list:
    """Rule-table rows for every fresh reviewed mapping."""
    rows = []
    maps = _mappings()
    for src in _sources():
        cat = _catalog(src["name"])
        if not cat:
            continue
        version = f"{src['label']} V{cat['version']}R{cat['release']}"
        for vid, m in (maps.get(src["name"]) or {}).items():
            rule = cat["rules"].get(vid)
            if rule is None or m.get("check_sha") != rule["check_sha"]:
                continue  # removed upstream, or check text changed: needs re-review
            rows.append({
                "standard_ref": vid, "standard_version": version, "framework": "STIG",
                "control_family": m.get("control_family") or m["predicate"].get("field", "CM.").split(".")[0],
                "check_type": m["check_type"], "predicate": m["predicate"],
                "severity": _SEVERITY.get(rule["severity"], "CAT_II"), "title": rule["title"],
                "remediation_template_ref": m.get("remediation_template_ref"),
                "applies_to_vendors": [src["vendor"]],
            })
    return rows


def coverage(extra_implemented: dict = None) -> list:
    """Per benchmark: total rules, automated, needing re-review, manual."""
    extra_implemented = extra_implemented or {}
    maps = _mappings()
    out = []
    for src in _sources():
        cat = _catalog(src["name"])
        if not cat:
            continue
        m = maps.get(src["name"]) or {}
        fresh = [v for v, x in m.items() if v in cat["rules"] and x.get("check_sha") == cat["rules"][v]["check_sha"]]
        stale = [v for v, x in m.items() if v not in cat["rules"] or x.get("check_sha") != cat["rules"][v]["check_sha"]]
        implemented = sorted(set(fresh) | (set(extra_implemented.get(src["name"], [])) & set(cat["rules"])))
        out.append({
            "benchmark": src["label"], "name": src["name"], "vendor": src["vendor"],
            "release": f"V{cat['version']}R{cat['release']}", "released": cat.get("released"),
            "source": cat.get("source"), "total": len(cat["rules"]), "automated": len(implemented),
            "needs_rereview": stale, "manual": len(cat["rules"]) - len(implemented),
        })
    return out
