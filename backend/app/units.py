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
import re
import xml.etree.ElementTree as ET

# SONiC's ACL_RULE table (config_db.json) - action/protocol vocab mapped to
# the same vocabulary the Cisco-oriented ACL parser (rule_engine.py's
# _parse_acl_line) already understands, so a synthesized line flows through
# that SAME parser unchanged rather than needing a second, vendor-specific
# ACL evaluator.
_SONIC_PROTO_NUM_TO_NAME = {"1": "icmp", "6": "tcp", "17": "udp"}
_SONIC_ACTION_MAP = {"FORWARD": "permit", "ACCEPT": "permit", "DROP": "deny", "REJECT": "deny", "DENY": "deny"}


class UnparseableConfig(ValueError):
    """A file whose detected format can't be read. Raised instead of
    returning zero units: an empty unit list looks like a config with no
    settings, and every rule would quietly come back "unknown"."""


def split_into_units(raw_text: str, fmt: str) -> list:
    if fmt == "json":
        try:
            return _flatten_json(json.loads(raw_text))
        except json.JSONDecodeError as e:
            raise UnparseableConfig(str(e))
    if fmt == "xml":
        return _flatten_xml(raw_text)
    if _BRACE_BLOCK_RE.search(raw_text):
        return _drop_deactivated(_flatten_braces(raw_text))
    if _CONFIG_BLOCK_RE.search(raw_text):
        return _flatten_config_blocks(raw_text)
    return _drop_deactivated(_split_cli(raw_text))


def _drop_deactivated(units: list) -> list:
    """Junos set-style `deactivate <path>`: the statements under that path
    stay in the config but are NOT applied, so they must not count as
    evidence (final review: `deactivate system services ssh root-login`
    left root-login deny passing a STIG check)."""
    paths = [u[len("deactivate "):].strip() for u in units if u.startswith("deactivate ")]
    if not paths:
        return units
    return [u for u in units
            if not any(u == "set " + q or u.startswith("set " + q + " ") for q in paths)]


# Block-structured CLI dialects, flattened generically (no vendor names in
# the code): each leaf line becomes one unit carrying its full parent path,
# so `telnet;` inside `system { services { ... } }` is classified as
# "set system services telnet", never as a bare word out of context.
_BRACE_BLOCK_RE = re.compile(r"^\s*[\w-][^\n;]*\{\s*$", re.MULTILINE)          # `system {`
_CONFIG_BLOCK_RE = re.compile(r"^\s*config\s+\S+.*$\n(?:.*\n)*?^\s*end\s*$", re.MULTILINE)  # config ... end


def _flatten_braces(raw_text: str) -> list:
    """`a { b { c d; } }` -> ["set a b c d"], the same form as set-style
    exports, so one set of patterns covers both."""
    # `inactive:` marks a statement or a whole block the device does not
    # apply; nothing under it counts as evidence (final review found
    # inactive root-login / syslog statements passing STIG checks).
    units, stack, inactive = [], [], []
    for line in raw_text.splitlines():
        t = line.strip()
        if not t or t.startswith(("#", "/*", "*", "//")):
            continue
        off = t.startswith("inactive:")
        t = re.sub(r"^(inactive|protect):\s*", "", t)
        t = re.sub(r"\s*##.*$", "", t)  # Junos trailing annotations (`## SECRET-DATA`)
        if t.endswith("{"):
            stack.append(t[:-1].strip())
            inactive.append(off or (bool(inactive) and inactive[-1]))
        elif t.startswith("}"):
            if stack:
                stack.pop()
                inactive.pop()
        elif off or (inactive and inactive[-1]):
            continue
        else:
            leaf = t[:-1].strip() if t.endswith(";") else t
            if leaf.startswith("set ") and not stack:
                units.append(leaf)  # already set-style
            else:
                units.append("set " + " ".join(stack + [leaf]))
    return units


def _flatten_config_blocks(raw_text: str) -> list:
    """`config system global / set x y / end` -> ["system global set x y"];
    `edit <id>` ... `next` scopes a table entry. Firewall-policy entries are
    additionally reassembled into ordered ACL lines (like pfSense filter
    rules), because a policy's meaning is spread over several `set` lines."""
    units, stack, policy, policies = [], [], None, []
    objects = {"address": {}, "addrgrp": {}}  # firewall address / addrgrp tables, for policy addresses
    obj = None
    for line in raw_text.splitlines():
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        if t.startswith("config "):
            stack.append(t[len("config "):].strip())
        elif t.startswith("edit "):
            stack.append("edit " + t[len("edit "):].strip().strip('"'))
            if stack[:-1] == ["firewall policy"]:
                policy = {}
            elif stack[:-1] in (["firewall address"], ["firewall addrgrp"]):
                obj = objects[stack[0].split()[1]].setdefault(stack[-1][5:], {})
        elif t in ("next", "end"):
            if policy is not None and t == "next":
                policies.append(policy)
                policy = None
            if t == "next":
                obj = None
            if stack:
                stack.pop()
        else:
            units.append(" ".join(stack + [t]) if stack else t)
            target = policy if policy is not None else obj
            if target is not None and t.startswith("set "):
                key, _, val = t[4:].partition(" ")
                target[key] = [v.strip('"') for v in val.split()]
    # Policies after all objects are known (policy order is kept).
    for p in policies:
        units.extend(_policy_acl_lines(p, objects))
    return units


# FortiOS predefined services -> (protocol, port or None)
_FORTI_SERVICES = {"ALL": ("ip", None), "ALL_TCP": ("tcp", None), "ALL_UDP": ("udp", None), "ALL_ICMP": ("icmp", None),
                   "PING": ("icmp", None), "TELNET": ("tcp", 23), "SSH": ("tcp", 22), "HTTP": ("tcp", 80),
                   "HTTPS": ("tcp", 443), "FTP": ("tcp", 21), "SMTP": ("tcp", 25), "DNS": ("udp", 53),
                   "SNMP": ("udp", 161), "NTP": ("udp", 123), "RDP": ("tcp", 3389), "SAMBA": ("tcp", 445)}


def _forti_addr_kind(name: str, objects: dict, depth: int = 0) -> str:
    """'any' | 'specific' | 'unknown' for one FortiOS address name."""
    if name == "all":
        return "any"
    if depth > 8:
        return "unknown"
    grp = objects["addrgrp"].get(name)
    if grp is not None:
        kinds = [_forti_addr_kind(m, objects, depth + 1) for m in grp.get("member") or []]
        if not kinds or "unknown" in kinds:
            return "unknown"
        return "any" if "any" in kinds else "specific"
    a = objects["address"].get(name)
    if a is None:
        return "unknown"  # not defined in this export: can't tell what it covers
    kind = (a.get("type") or ["ipmask"])[0]
    if kind == "ipmask":
        # FortiOS default subnet is 0.0.0.0/0, and `show` hides defaults.
        sub = a.get("subnet") or ["0.0.0.0", "0.0.0.0"]
        return "any" if sub[-1] in ("0.0.0.0", "0") or sub[0].endswith("/0") else "specific"
    if kind == "iprange":
        rng = (a.get("start-ip") or ["?"])[0], (a.get("end-ip") or ["?"])[0]
        return "any" if rng == ("0.0.0.0", "255.255.255.255") else "specific"
    if kind == "fqdn":
        return "specific"
    return "unknown"  # geography, dynamic, wildcard...: not modelled


def _forti_addr(p: dict, key: str, objects: dict) -> str:
    """ACL address token for a policy's srcaddr/dstaddr (several names = any
    of them): 'any', 'host NAME', or an `object NAME` the engine can't read,
    so an unresolvable address fails closed instead of reading as specific."""
    names = p.get(key) or ["all"]
    if (p.get(key + "-negate") or ["disable"])[0] == "enable":
        return "object negated-" + names[0]
    kinds = {n: _forti_addr_kind(n, objects) for n in names}
    if "any" in kinds.values():
        return "any"
    unknown = [n for n, k in kinds.items() if k == "unknown"]
    return f"object {unknown[0]}" if unknown else "host " + names[0]


def _policy_acl_lines(p: dict, objects: dict = None) -> list:
    """One `access-list fortios-<srcintf> ...` line per service of a policy,
    in policy order. A disabled policy decides nothing; an unknown service
    or address becomes a line the rule engine cannot read (so it fails
    closed). Every srcaddr/dstaddr name counts, not just the first (second
    review: `set srcaddr "LAN_NET" "all"` was read as LAN_NET only)."""
    objects = objects or {"address": {}, "addrgrp": {}}
    if (p.get("status") or [""])[0] == "disable":
        return []
    action = {"accept": "permit", "deny": "deny"}.get((p.get("action") or ["deny"])[0])
    if action is None:
        return []
    src = _forti_addr(p, "srcaddr", objects)
    dst = _forti_addr(p, "dstaddr", objects)
    iface = (p.get("srcintf") or ["any"])[0]
    lines = []
    for svc in p.get("service") or ["ALL"]:
        proto, port = _FORTI_SERVICES.get(svc.upper(), (f"service-{svc}", None))
        line = f"access-list fortios-{iface} {action} {proto} {src} {dst}"
        if port:
            line += f" eq {port}"
        lines.append(line)
    return lines


_BANNER_RE = re.compile(r"^banner\s+(\S+)\s+(\S)(\S?)(.*)$")


def _split_cli(raw_text: str) -> list:
    """One unit per config line, except inside a banner. Banner text is
    operator prose: a banner containing `transport input ssh` must not be
    read as the device's real VTY setting (found in review: it was, and three
    CIS checks passed on words inside a banner). Only the banner's header
    line is kept, which records that a banner exists."""
    units = []
    lines = raw_text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        i += 1
        if not stripped or stripped.startswith("!"):
            continue
        m = _BANNER_RE.match(stripped)
        if m:
            # Delimiter is one char, or the two-char caret form `^C`.
            delim = m.group(2) + m.group(3) if m.group(2) == "^" and m.group(3) else m.group(2)
            rest = stripped[m.start(2) + len(delim):]
            if delim in rest:
                text = rest.split(delim)[0]
            else:  # multi-line banner: skip until the closing delimiter
                body = []
                while i < len(lines) and delim not in lines[i]:
                    body.append(lines[i])
                    i += 1
                if i < len(lines):
                    body.append(lines[i].split(delim)[0])
                i += 1
                text = "".join(body)
            if text.strip():  # an empty banner is no banner (final review #4)
                units.append(f"banner {m.group(1)} {delim}")
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
    if "<!DOCTYPE" in raw_text or "<!ENTITY" in raw_text:
        # Device config exports never need a DTD; refusing one closes the
        # entity-expansion ("billion laughs") family of XML attacks.
        raise UnparseableConfig("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError as e:
        raise UnparseableConfig(str(e))

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
