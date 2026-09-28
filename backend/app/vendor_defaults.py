"""Vendor defaults: what a device does when its config doesn't mention a
setting. Data, not code - each seeds/<vendor>.yaml may carry:

    defaults:                        # device-wide
      - {field: IA.password_encryption_enabled, value: false, note: "..."}
    interface_defaults:              # per interface block (indented CLI)
      - field: SC.proxy_arp_enabled
        value: true                  # the per-interface default
        unless: '^\\s*no ip proxy-arp\\s*$'
        skip: '^interface (Loopback|Null|Tunnel)'
        block: '^line vty '          # optional: other block kinds (default: interface)
        only_if: '^version 1[0-5]\\.'  # optional: only when the export matches
    line_scoped:                     # a field that only certain blocks decide
      - field: AC.session_idle_timeout_minutes
        block: '^line vty '
        value_from: '^\\s*exec-timeout (\\d+)'
        default: 10                  # for a block that doesn't set it
    absent_facts:                    # explicit evidence from every matching line
      - field: AC.telnet_enabled
        value: false
        lines: '^system interface edit \\S+ (ipv6 )?set (ip6-)?allowaccess '
        none_match: '\\btelnet\\b'
    unit_facts:                      # a line present anywhere decides a field
      - {field: SC.web_management_enabled, value: true, any: '^set system services web-management\\b'}
      - {field: SC.http_mgmt_enabled, value: false, all: ['^no ip http server$', '^no ip http secure-server$']}
    entry_scoped:                    # every table entry must carry the lines (full export only)
      - field: IA.ldap_uses_ldaps
        entry: '^user ldap edit (\\S+) '
        require: ['^set secure ldaps\\b']

interface_defaults entries may also carry `when_missing: unknown` (for checks
on "all EXTERNAL interfaces": AEGIS can't tell which interfaces are external,
so every interface compliant is a PASS, and any interface at the default is
unknown rather than a FAIL), `skip_if` (a line that makes the entry moot,
e.g. `no cdp run`) and `require_block` (a block that must exist, e.g. Null0).

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
        keys = ("defaults", "interface_defaults", "line_scoped", "absent_facts", "unit_facts", "entry_scoped")
        if any(doc.get(k) for k in keys) or doc.get("acl_bindings"):
            out[doc["vendor"]] = {**{k: doc.get(k) or [] for k in keys}, "acl_bindings": doc.get("acl_bindings")}
    return out


def acl_bindings_explicit(vendor: str) -> bool:
    """True when the vendor's config states which ACLs are in force (Cisco
    `ip access-group` / `access-class`): an ACL no line applies is then not
    evaluated. Other vendors' rule tables are in force by construction."""
    return (_load().get(vendor) or {}).get("acl_bindings") == "explicit"


def reload() -> None:
    _load.cache_clear()


def _interface_blocks(raw_text: str, block: str = r"^interface\s+\S+") -> list:
    """[(header, [body lines])] for `interface X` (or `block`) blocks in indented CLI."""
    blocks, cur = [], None
    for line in raw_text.splitlines():
        if re.match(block, line):
            cur = (line.strip(), [])
            blocks.append(cur)
        elif cur is not None and line[:1] in (" ", "\t"):
            cur[1].append(line)
        elif line.strip() and not line.startswith("!"):
            cur = None
    return blocks


def _default_prov(source_unit: str, all_sources: list, note) -> dict:
    return {"confidence_tier": "vendor_default", "kb_entry_id": None, "kb_entry_version": None,
            "source_unit": source_unit, "all_sources": all_sources, "note": note}


def _worst_number(values: list):
    """Least secure of several timeouts: 0 disables the timeout entirely."""
    return 0 if 0 in values else max(values)


def apply(vendor: str, confidence: str, raw_text: str, fields: dict, provenance: dict, units: list = None) -> list:
    """Fill defaults in place; returns the fields that were filled."""
    spec = _load().get(vendor)
    # Block-scoped entries read only blocks present in the file, so they run
    # for a fragment too; device-wide defaults need a full export.
    if not spec or confidence not in ("high", "medium"):
        return []
    filled = []
    for d in spec["line_scoped"]:
        # Only these blocks decide the field (CIS 1.2.8 is about `line vty`;
        # `exec-timeout 0 0` on the console must not fail it), and a block
        # that doesn't set it runs at the default - so a compliant line in
        # one VTY block can't hide another VTY block left at the default.
        blocks = _interface_blocks(raw_text, d["block"])
        if not blocks:
            continue
        rx = re.compile(d["value_from"])
        per_block = []
        for hdr, body in blocks:
            hit = next((m for m in map(rx.match, body) if m), None)
            value = d["default"]
            if hit:
                # An optional second capture is seconds (`exec-timeout 10 3000`
                # is 60 minutes, not 10).
                secs = hit.group(2) if rx.groups >= 2 else None
                value = int(hit.group(1)) + (int(secs) / 60 if secs else 0)
            per_block.append((hdr, value, hit.string.strip() if hit else None))
        worst = _worst_number([v for _, v, _ in per_block])
        # If a block at the default ties for worst, the verdict rests on the
        # default (so it can FAIL but never PASS).
        worst_blocks = [b for b in per_block if b[1] == worst]
        hdr, _, line = next((b for b in worst_blocks if b[2] is None), worst_blocks[0])
        sources = [f"{h}: {ln}" if ln else f"{h}: (not set: {vendor} default {v})" for h, v, ln in per_block]
        fields[d["field"]] = worst
        if line is None:
            provenance[d["field"]] = _default_prov(f"{hdr} (not set: {vendor} default {worst})", sources, d.get("note"))
        else:
            prior = provenance.get(d["field"]) or {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None}
            if prior.get("confidence_tier") == "vendor_default":
                prior = {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None}
            provenance[d["field"]] = {**prior, "source_unit": f"{hdr}: {line}", "all_sources": sources}
        filled.append(d["field"])
    for d in spec["absent_facts"] if confidence == "high" else []:
        # Explicit evidence, not a default: every line of this kind is in the
        # (full) export and none of them enables the setting.
        rx = re.compile(d["lines"])
        lines = [u for u in units or [] if rx.match(u)]
        if not lines or d["field"] in fields or any(re.search(d["none_match"], u) for u in lines):
            continue
        fields[d["field"]] = d["value"]
        provenance[d["field"]] = {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None,
                                  "source_unit": f"all {len(lines)} such lines omit it, e.g. {lines[0]}",
                                  "all_sources": lines, "note": d.get("note")}
        filled.append(d["field"])
    for d in spec["unit_facts"]:
        # Positive evidence from a line anywhere in the file (or from every
        # line of a set being present). The first fact that holds for a field
        # decides it; list them insecure-first.
        field = d["field"]
        if field in filled:
            continue
        us = units or []
        if "any" in d:
            hits = [u for u in us if re.match(d["any"], u)]
        else:
            per = [[u for u in us if re.match(rx, u)] for rx in d["all"]]
            hits = [h[0] for h in per] if all(per) else []
        if not hits:
            continue
        fields[field] = d["value"]
        provenance[field] = {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None,
                             "source_unit": hits[0], "all_sources": hits, "note": d.get("note")}
        filled.append(field)
    for d in spec["entry_scoped"] if confidence == "high" else []:
        # Every entry of a table (each LDAP server, each SNMPv3 user) must
        # carry the required lines; one entry without them decides the field.
        rx = re.compile(d["entry"])
        entries: dict = {}
        for u in units or []:
            m = rx.match(u)
            if m:
                entries.setdefault(m.group(1), []).append(u[m.end():])
        if not entries:
            continue
        bad = [e for e, lines in entries.items()
               if not all(any(re.match(req, l) for l in lines) for req in d["require"])]
        field = d["field"]
        fields[field] = not bad
        if bad:
            provenance[field] = _default_prov(f"{d.get('label', 'entry')} {bad[0]}: required setting not set",
                                              [f"{e}: required setting not set" for e in bad], d.get("note"))
        else:
            src = [u for u in units if rx.match(u) and any(re.match(req, u[rx.match(u).end():]) for req in d["require"])]
            provenance[field] = {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None,
                                 "source_unit": src[0], "all_sources": src, "note": d.get("note")}
        filled.append(field)
    for d in spec["interface_defaults"]:
        if d.get("only_if") and not re.search(d["only_if"], raw_text, re.M):
            continue
        if d.get("skip_if") and re.search(d["skip_if"], raw_text, re.M):
            continue
        field = d["field"]
        unknown_if_missing = d.get("when_missing") == "unknown"
        if d.get("require_block") and not re.search(d["require_block"], raw_text, re.M):
            if unknown_if_missing:
                fields.pop(field, None)
                provenance.pop(field, None)
            continue
        blocks = [b for b in _interface_blocks(raw_text, d.get("block") or r"^interface\s+\S+")
                  if not (d.get("skip") and re.match(d["skip"], b[0]))]
        if not blocks:
            if unknown_if_missing:  # a stray line without its blocks proves nothing
                fields.pop(field, None)
                provenance.pop(field, None)
            continue
        unless = re.compile(d["unless"])
        at_default = [hdr for hdr, body in blocks if not any(unless.match(l) for l in body)]
        if at_default and unknown_if_missing:
            # Some interface lacks the line and AEGIS can't tell whether it is
            # external: unknown, and partial per-line evidence must not stand.
            fields.pop(field, None)
            provenance.pop(field, None)
            continue
        if not at_default and unknown_if_missing:
            fields.pop(field, None)  # every block complies: this entry owns the field
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
        elif field not in fields and isinstance(d["value"], bool):
            # Every block carries the line: that is explicit evidence.
            lines = [f"{hdr}: {l.strip()}" for hdr, body in blocks for l in body if unless.match(l)]
            fields[field] = not d["value"]
            provenance[field] = {"confidence_tier": "tier1", "kb_entry_id": None, "kb_entry_version": None,
                                 "source_unit": lines[0], "all_sources": lines, "note": d.get("note")}
            filled.append(field)
    if confidence != "high":
        return filled  # device-wide defaults only for a full export
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
