"""Vendor defaults: what a device does when its config doesn't mention a
setting. Data, not code - each seeds/<vendor>.yaml may carry:

    defaults:                        # device-wide
      - {field: IA.password_encryption_enabled, value: false, note: "..."}
    interface_defaults:              # per interface block (indented CLI)
      - field: SC.proxy_arp_enabled
        value: true                  # the per-interface default
        unless: '^\\s*no ip proxy-arp\\s*$'
        skip: '^interface (Loopback|Null|Tunnel)'

A default fills a field only when no line in the config set it, only for a
high-confidence fingerprint (a full export, not a fragment), and it is
recorded as its own provenance tier ("vendor_default"). The evaluator lets a
default make a rule FAIL but never PASS: a pass that rests on an unstated
default stays NOT_EVALUATED, so an incomplete export can never look compliant.
"""
import functools
import glob
import os
import re

import yaml

_SEEDS_DIR = os.path.join(os.path.dirname(__file__), "seeds")


@functools.lru_cache(maxsize=1)
def _load() -> dict:
    out = {}
    for path in sorted(glob.glob(os.path.join(_SEEDS_DIR, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        if doc.get("defaults") or doc.get("interface_defaults"):
            out[doc["vendor"]] = {"defaults": doc.get("defaults") or [],
                                  "interface_defaults": doc.get("interface_defaults") or []}
    return out


def reload() -> None:
    _load.cache_clear()


def _interface_blocks(raw_text: str) -> list:
    """[(header, [body lines])] for `interface X` blocks in indented CLI."""
    blocks, cur = [], None
    for line in raw_text.splitlines():
        if re.match(r"^interface\s+\S+", line):
            cur = (line.strip(), [])
            blocks.append(cur)
        elif cur is not None and line[:1] in (" ", "\t"):
            cur[1].append(line)
        elif line.strip() and not line.startswith("!"):
            cur = None
    return blocks


def apply(vendor: str, confidence: str, raw_text: str, fields: dict, provenance: dict) -> list:
    """Fill defaults in place; returns the fields that were filled."""
    spec = _load().get(vendor)
    if not spec or confidence != "high":
        return []
    filled = []
    for d in spec["interface_defaults"]:
        blocks = [b for b in _interface_blocks(raw_text) if not (d.get("skip") and re.match(d["skip"], b[0]))]
        if not blocks:
            continue
        unless = re.compile(d["unless"])
        at_default = [hdr for hdr, body in blocks if not any(unless.match(l) for l in body)]
        field = d["field"]
        if at_default:
            # At least one interface is left at the default: that is the
            # device's real posture, whatever other interfaces say.
            fields[field] = d["value"]
            provenance[field] = {"confidence_tier": "vendor_default", "kb_entry_id": None, "kb_entry_version": None,
                                 "source_unit": f"{at_default[0]} (no `{d['unless_text']}`)" if d.get("unless_text")
                                 else at_default[0],
                                 "all_sources": [f"{h}: {vendor} default" for h in at_default],
                                 "note": d.get("note")}
            filled.append(field)
        elif field not in fields:
            fields[field] = not d["value"] if isinstance(d["value"], bool) else fields.get(field)
    for d in spec["defaults"]:
        field = d["field"]
        if field in fields:
            continue
        fields[field] = d["value"]
        provenance[field] = {"confidence_tier": "vendor_default", "kb_entry_id": None, "kb_entry_version": None,
                             "source_unit": f"(not set in this config: {vendor} default)",
                             "all_sources": [f"(not set in this config: {vendor} default)"], "note": d.get("note")}
        filled.append(field)
    return filled
