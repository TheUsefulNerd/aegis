"""Fingerprinting: which vendor, and which format (cli text / JSON / XML).

The format split is generic code - it's the raw shape of the file, which the
unit splitter needs before anything else can run. WHICH VENDOR is data, not
code: every seeds/<vendor>.yaml may carry a `fingerprint:` block, so adding
a vendor is one YAML file (its signature + its knowledge-base rows) with no
code change and no redeploy.

    fingerprint:
      format: cli            # cli | xml | json
      version_family: junos
      priority: 10           # lower is tried first (specific before generic)
      signals:               # regexes (multiline) against the raw file,
        - '^version \\S+;$'   #   or `json_keys:` (any top-level key) for JSON
      min: 1                 # signals needed to claim this vendor
      high_at: 2             # signals needed for "high" confidence
"""
import functools
import glob
import json
import os
import re

import yaml

_SEEDS_DIR = os.path.join(os.path.dirname(__file__), "seeds")


@functools.lru_cache(maxsize=1)
def _signatures() -> tuple:
    sigs = []
    for path in sorted(glob.glob(os.path.join(_SEEDS_DIR, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        fp = doc.get("fingerprint")
        if not fp:
            continue
        sigs.append({
            "vendor": doc["vendor"],
            "format": fp.get("format", "cli"),
            "version_family": fp.get("version_family"),
            "priority": fp.get("priority", 50),
            "signals": [re.compile(s, re.MULTILINE) for s in fp.get("signals", [])],
            "json_keys": set(fp.get("json_keys", [])),
            "min": fp.get("min", 1),
            "high_at": fp.get("high_at", 1),
        })
    return tuple(sorted(sigs, key=lambda s: (s["priority"], s["vendor"])))


def reload_signatures() -> None:
    _signatures.cache_clear()


def _detect_format(stripped: str):
    """-> (format, parsed_json_or_None)."""
    if stripped[:1] in ("{", "["):
        try:
            return "json", json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass
    if stripped.startswith("<"):
        return "xml", None  # with or without an <?xml ...?> prolog
    return "cli", None


def fingerprint(raw_text: str, learned: list = None) -> dict:
    """Returns {vendor, version_family, format, confidence}.
    format is one of "json" | "xml" | "cli" - tells the caller how to split
    the file into units for resolve_unit (§3, step 4)."""
    stripped = raw_text.strip()
    fmt, obj = _detect_format(stripped)
    # Long exports put later sections (FortiOS `config firewall policy`) far
    # down; the held-out FortiGate-VM backup had it at line 3087.
    head = stripped[:200000]
    for sig in _signatures():
        if sig["format"] != fmt:
            continue
        if fmt == "json":
            hits = len(sig["json_keys"] & set(obj.keys())) if isinstance(obj, dict) else 0
            hits += sum(1 for s in sig["signals"] if s.search(head))
        else:
            hits = sum(1 for s in sig["signals"] if s.search(head))
        if hits >= sig["min"]:
            return {"vendor": sig["vendor"], "version_family": sig["version_family"], "format": fmt,
                    "confidence": "high" if hits >= sig["high_at"] else "medium"}
    # Vendors a reviewer named in the GUI (a literal header line each) - only
    # for files no built-in signature claims, so a reviewer's line can never
    # re-label a known vendor's configs.
    for sig in learned or []:
        if sig["format"] == fmt and sig["signal"] in head:
            return {"vendor": sig["vendor"], "version_family": None, "format": fmt, "confidence": "learned"}
    # No signature matched. Per architecture-document.md §3 step 3a this
    # degrades gracefully: every unit routes through Tier 2/3 more often, it
    # doesn't fail outright.
    vendor = {"json": "unknown_json", "xml": "unknown_xml"}.get(fmt, "unknown")
    return {"vendor": vendor, "version_family": None, "format": fmt, "confidence": "low"}
