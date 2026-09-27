"""DISA STIG catalog sync: detect new benchmark releases and import every rule.

DISA publishes STIGs publicly; cyber.trackr.live serves the same content as
JSON (every benchmark, version, release date, and per rule: DISA id, severity,
check text, fix text, CCI references). This module:

  python -m app.stig_sync check            # which tracked benchmarks have a newer release
  python -m app.stig_sync fetch <name>     # import the latest release into catalog/<name>.json
  python -m app.stig_sync fetch-all        # every tracked benchmark

The catalog is the full benchmark. Turning a rule's prose check into an
executable check is a reviewed mapping (rules/stig_catalog_map.yaml); only
mapped rules are evaluated, the rest are reported as manual review. When a
new release changes a mapped rule's check text, that mapping is set aside as
"needs re-review" instead of silently evaluating an outdated check.
"""
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.request

import yaml

API = "https://cyber.trackr.live/api/stig"
HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_DIR = os.path.join(HERE, "catalog")
SOURCES = os.path.join(CATALOG_DIR, "sources.yaml")


def _get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "AEGIS-stig-sync/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def sources() -> list:
    return yaml.safe_load(open(SOURCES, encoding="utf-8"))["benchmarks"]


def local(name: str):
    p = os.path.join(CATALOG_DIR, f"{name}.json")
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None


def latest(index: dict, name: str) -> dict:
    releases = index.get(name) or []
    if not releases:
        raise KeyError(f"benchmark {name!r} not found upstream")
    return max(releases, key=lambda r: (int(r["version"]), int(r["release"])))


def check_sha(text: str) -> str:
    return hashlib.sha256((text or "").strip().encode()).hexdigest()[:16]


def check() -> list:
    index = _get(API)
    out = []
    for src in sources():
        up = latest(index, src["name"])
        have = local(src["name"])
        cur = f"V{have['version']}R{have['release']}" if have else None
        new = f"V{up['version']}R{up['release']}"
        out.append({"benchmark": src["name"], "local": cur, "upstream": new, "upstream_released": up["released"],
                    "update_available": cur != new})
    return out


def fetch(name: str, delay: float = 0.15) -> dict:
    index = _get(API)
    up = latest(index, name)
    base = f"{API}/{name}/{up['version']}/{up['release']}"
    head = _get(base)
    rules = {}
    for vid in sorted(head["requirements"]):
        d = _get(f"{base}/{vid}")
        rules[vid] = {
            "rule": d.get("rule"), "stig_id": d.get("version"), "severity": d.get("severity"),
            "title": d.get("requirement-title"), "check": d.get("check-text"), "fix": d.get("fix-text"),
            "cci": [i for i in d.get("identifiers", []) if i.startswith("CCI-")],
            "check_sha": check_sha(d.get("check-text")),
        }
        time.sleep(delay)
    old = local(name)
    doc = {"benchmark": name, "title": head.get("title"), "version": up["version"], "release": up["release"],
           "released": up["released"], "fetched": dt.date.today().isoformat(),
           "source": f"https://cyber.trackr.live/stig/{name}/{up['version']}/{up['release']} (DISA STIG content)",
           "rules": rules}
    os.makedirs(CATALOG_DIR, exist_ok=True)
    json.dump(doc, open(os.path.join(CATALOG_DIR, f"{name}.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    return {"benchmark": name, "release": f"V{up['version']}R{up['release']}", "rules": len(rules),
            "diff": diff(old, doc) if old else None}


def diff(old: dict, new: dict) -> dict:
    o, n = old["rules"], new["rules"]
    return {"added": sorted(set(n) - set(o)), "removed": sorted(set(o) - set(n)),
            "check_changed": sorted(v for v in set(o) & set(n) if o[v]["check_sha"] != n[v]["check_sha"])}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        for row in check():
            print(json.dumps(row))
    elif cmd == "fetch":
        print(json.dumps(fetch(sys.argv[2]), indent=1))
    elif cmd == "fetch-all":
        for src in sources():
            print(json.dumps(fetch(src["name"])))
    else:
        sys.exit(f"unknown command {cmd!r}")
