"""Splits a raw config into resolve_unit-sized pieces, depending on the
format fingerprint.py detected. This is the pre-processor from
architecture-document.md §3 step 3c: JSON/XML get flattened into path-like
pseudo-lines so the SAME resolve_unit pipeline applies uniformly - not a
second parser.

Cross-reference preservation (§3 step 3.5) is explicitly deferred this week
(architecture-document.md §7) - this flattening does NOT preserve references
between units (e.g. an AAA method-list name, or one security-group rule
pointing at another). Demo control sets are chosen to not need it.
"""
import json
import xml.etree.ElementTree as ET

# SONiC's ACL_RULE table (config_db.json) - action/protocol vocab mapped to
# the same vocabulary the Cisco-oriented ACL parser (rule_engine.py's
# _parse_acl_line) already understands, so a synthesized line flows through
# that SAME parser unchanged rather than needing a second, vendor-specific
# ACL evaluator.
_SONIC_PROTO_NUM_TO_NAME = {"1": "icmp", "6": "tcp", "17": "udp"}
_SONIC_ACTION_MAP = {"FORWARD": "permit", "ACCEPT": "permit", "DROP": "deny", "REJECT": "deny", "DENY": "deny"}


def split_into_units(raw_text: str, fmt: str) -> list:
    if fmt == "json":
        return _flatten_json(json.loads(raw_text))
    if fmt == "xml":
        return _flatten_xml(raw_text)
    return _split_cli(raw_text)


def _split_cli(raw_text: str) -> list:
    units = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        units.append(stripped)
    return units


def _flatten_acl_rule_table(rule_table: dict) -> list:
    """SONiC's ACL_RULE table rows are each already one flat dict, keyed
    "<ACL_TABLE_NAME>|<RULE_NAME>" - e.g. {"PRIORITY": "9999",
    "PACKET_ACTION": "DROP", "IP_PROTOCOL": "6", "L4_DST_PORT": "23"}.
    Generic recursive flattening shreds that one rule into 4 separate,
    order-losing leaf units - exactly why ordered-first-match ACL evaluation
    could never parse a real SONiC device's rules (found via manual testing
    2026-09-15: every ACL-dependent finding came back NOT_EVALUATED with
    "no ACL line could be parsed", even though the rule data was right
    there). Reassemble each row into ONE Cisco-ACL-syntax line instead, so
    it flows through the existing parser (rule_engine.py's _parse_acl_line)
    unchanged - no second, vendor-specific ACL evaluator needed.
    """
    rows = []
    for rule_key, attrs in rule_table.items():
        if not isinstance(attrs, dict):
            continue
        action = _SONIC_ACTION_MAP.get(str(attrs.get("PACKET_ACTION", "")).upper())
        if action is None:
            continue  # unrecognized action - don't guess, drop this row
        proto_num = str(attrs.get("IP_PROTOCOL", ""))
        proto = _SONIC_PROTO_NUM_TO_NAME.get(proto_num, proto_num or "ip")
        src = attrs.get("SRC_IP", "any")
        dst = attrs.get("DST_IP", "any")
        port = attrs.get("L4_DST_PORT")
        line = f"access-list 100 {action} {proto} {src} {dst}"
        if port:
            line += f" eq {port}"
        try:
            priority = int(attrs.get("PRIORITY", 0) or 0)
        except (TypeError, ValueError):
            priority = 0
        rows.append((priority, line))
    # Higher SONiC PRIORITY is evaluated first - preserve that order since
    # first-match evaluation depends on it, same as Cisco ACL line order in
    # the original config mattering for the same predicate.
    rows.sort(key=lambda r: r[0], reverse=True)
    return [line for _, line in rows]


def _flatten_json(obj, prefix: str = "") -> list:
    units = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "ACL_RULE" and prefix == "" and isinstance(v, dict):
                units.extend(_flatten_acl_rule_table(v))
                continue
            path = f"{prefix}.{k}" if prefix else str(k)
            child_units = _flatten_json(v, path)
            if not child_units:
                # v is {} or [] - the key's existence IS the data point.
                # SONiC's config_db.json does this constantly (e.g. a syslog
                # server table keyed by IP with an empty settings body) -
                # without this, that fact would silently vanish instead of
                # becoming a resolvable unit.
                units.append(f"{path}=<present>")
            else:
                units.extend(child_units)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            units.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        units.append(f"{prefix}={obj}")
    return units


_PF_ACTION = {"pass": "permit", "block": "deny", "reject": "deny"}


def _pf_addr(elem) -> str:
    """pfSense <source>/<destination>: <any/> (an EMPTY element - generic
    flattening drops it entirely), <network>lan</network>, or
    <address>198.51.100.7</address>, optionally negated with <not/>."""
    if elem is None:
        return "any"
    neg = "not-" if elem.find("not") is not None else ""
    if elem.find("any") is not None:
        return neg + "any"
    for tag in ("address", "network"):
        v = (elem.findtext(tag) or "").strip()
        if v:
            return neg + v.replace(" ", "")
    return neg + "any"


def _pfsense_rule_units(rule, path: str) -> list:
    """Reassemble one pfSense filter rule into ONE ACL-syntax line (the same
    approach as SONiC's ACL_RULE table above). Flattened generically, a rule
    becomes sibling units (`type=block`, `destination.port=23`, ...) that are
    each classified alone - found live twice: a rule that BLOCKS telnet was
    classified as telnet ENABLED from its `destination.port=23` unit, because
    the `type=block` sibling wasn't visible (architecture-document.md §3.5).
    Rule order is preserved: pfSense evaluates filter rules first-match too.
    The description is still emitted as its own unit so the input-sanity gate
    scans it (it's attacker-controllable free text)."""
    units = []
    descr = (rule.findtext("descr") or "").strip()
    if descr:
        units.append(f"{path}.descr={descr}")
    action = _PF_ACTION.get((rule.findtext("type") or "").strip().lower())
    if action is None or rule.find("disabled") is not None:
        return units  # floating "match" rules and disabled rules decide nothing
    proto = (rule.findtext("protocol") or "").strip().lower() or "ip"
    if proto in ("any", "tcp/udp"):
        proto = "ip" if proto == "any" else "tcp"
    iface = (rule.findtext("interface") or "any").strip()
    dst = rule.find("destination")
    line = f"access-list pfsense-{iface} {action} {proto} {_pf_addr(rule.find('source'))} {_pf_addr(dst)}"
    port = (dst.findtext("port") or "").strip() if dst is not None else ""
    if port.isdigit():
        line += f" eq {port}"
    elif port:
        a, _, b = port.replace("-", ":").partition(":")
        line += f" range {a} {b or a}"
    if rule.find("log") is not None:
        line += " log"
    units.append(line)
    return units


def _flatten_xml(raw_text: str) -> list:
    """Sibling elements sharing a tag (e.g. two <rule> entries under one
    <filter>) get an index suffix, same convention as JSON list flattening -
    without it, both rules' children would silently collide onto the exact
    same path (both "filter.rule.type") and become indistinguishable. Found
    via real testing against a pfSense-style two-rule filter block, not
    theoretical."""
    units = []
    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError:
        return units

    def walk(elem, path):
        text = (elem.text or "").strip()
        if text and len(list(elem)) == 0:
            units.append(f"{path}={text}")

        if path == "pfsense.filter":
            rules = [c for c in elem if c.tag == "rule"]
            for idx, rule in enumerate(rules):
                units.extend(_pfsense_rule_units(rule, f"{path}.rule[{idx}]"))
            for child in elem:
                if child.tag != "rule":
                    walk(child, f"{path}.{child.tag}")
            return

        seen: dict = {}
        for child in elem:
            same_tag_count = sum(1 for c in elem if c.tag == child.tag)
            if same_tag_count > 1:
                idx = seen.get(child.tag, 0)
                seen[child.tag] = idx + 1
                child_path = f"{path}.{child.tag}[{idx}]"
            else:
                child_path = f"{path}.{child.tag}"
            walk(child, child_path)

    walk(root, root.tag)
    return units
