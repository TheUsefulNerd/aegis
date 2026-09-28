"""Deterministic rule engine - architecture-document.md §3 step 6. No LLM
involvement in producing a verdict, by design: compliance verdicts must be
auditable and reproducible.

Six generic predicate evaluators, not per-rule code. Finding.result is always
one of PASS / FAIL / NOT_EVALUATED - a rule whose required field never
resolved returns NOT_EVALUATED, never a silent PASS (fail-closed by
construction, per §3's headline invariant).
"""
import re
from dataclasses import dataclass, field
from typing import Optional

PASS, FAIL, NOT_EVALUATED = "PASS", "FAIL", "NOT_EVALUATED"


@dataclass
class EvalResult:
    result: str
    evidence: dict = field(default_factory=dict)


def _get(fields: dict, name: str):
    """Returns (value, present). A field that's an empty list still counts
    as "present" - e.g. an empty acl_rules list is a real (if odd) state,
    not the same as "we never resolved this field at all"."""
    if name not in fields:
        return None, False
    return fields[name], True


def evaluate(check_type: str, predicate: dict, fields: dict) -> EvalResult:
    evaluator = _EVALUATORS.get(check_type)
    if evaluator is None:
        return EvalResult(NOT_EVALUATED, {"error": f"unknown check_type {check_type!r}"})
    return evaluator(predicate, fields)


_TRUE_STR = ("true", "1", "yes", "enabled", "enable", "on")
_FALSE_STR = ("false", "0", "no", "disabled", "disable", "off")


def _coerce_bool(v) -> Optional[bool]:
    """Values reaching here can be a real bool, or a string typed into a
    plain HTML input by a reviewer (e.g. "false") - naive `bool(v)` would
    silently misread the non-empty string "false" as truthy. Known string
    forms are coerced explicitly; anything else is None (not understood),
    never quietly False: an unrecognized "on" read as False once passed a
    telnet check."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in _TRUE_STR:
            return True
        if s in _FALSE_STR:
            return False
    return None


def _eval_boolean(predicate: dict, fields: dict) -> EvalResult:
    value, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    # A boolean check on a list field asks "is at least one configured?"
    # (e.g. a remote log host).
    actual = bool(value) if isinstance(value, list) else _coerce_bool(value)
    if actual is None:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"], "reason": "value not understood",
                                          "actual": value})
    ok = actual == _coerce_bool(predicate["equals"])
    return EvalResult(PASS if ok else FAIL, {"field": predicate["field"], "actual": value})


def _eval_range(predicate: dict, fields: dict) -> EvalResult:
    value, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    if isinstance(value, bool):
        # `float(True)` is 1.0 - a boolean reaching a numeric check is a
        # classification error upstream, not the number 1.
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"], "reason": "not numeric", "actual": value})
    if isinstance(value, list):
        # A range on a list counts its distinct entries ("at least two NTP
        # servers"). An empty list is only ever a vendor default (no line
        # added to it), which can FAIL here but never PASS.
        num = len({str(v).strip().lower() for v in value})
        lo, hi = predicate.get("min", float("-inf")), predicate.get("max", float("inf"))
        return EvalResult(PASS if lo <= num <= hi else FAIL,
                          {"field": predicate["field"], "actual": value, "count": num})
    try:
        num = float(value)
    except (TypeError, ValueError):
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"], "reason": "not numeric", "actual": value})
    lo = predicate.get("min", float("-inf"))
    hi = predicate.get("max", float("inf"))
    ok = lo <= num <= hi
    # `exclusive_min` for values where the bound itself means "off" - e.g.
    # `exec-timeout 0` is "never time out", which must not satisfy "<= 10
    # minutes".
    if "exclusive_min" in predicate and num <= predicate["exclusive_min"]:
        ok = False
    return EvalResult(PASS if ok else FAIL, {"field": predicate["field"], "actual": value})


def _eval_compound(predicate: dict, fields: dict) -> EvalResult:
    op = predicate["op"].upper()
    if op == "NOT":
        inner = evaluate(predicate["condition"]["check_type"], predicate["condition"]["predicate"], fields)
        flipped = {PASS: FAIL, FAIL: PASS, NOT_EVALUATED: NOT_EVALUATED}[inner.result]
        return EvalResult(flipped, {"inner": inner.evidence})

    sub_results = [
        evaluate(c["check_type"], c["predicate"], fields) for c in predicate["conditions"]
    ]
    evidence = {"sub_results": [r.result for r in sub_results]}
    results = [r.result for r in sub_results]
    if op == "AND":
        if FAIL in results:
            return EvalResult(FAIL, evidence)
        if NOT_EVALUATED in results:
            return EvalResult(NOT_EVALUATED, evidence)
        return EvalResult(PASS, evidence)
    if op == "OR":
        if PASS in results:
            return EvalResult(PASS, evidence)
        if NOT_EVALUATED in results:
            return EvalResult(NOT_EVALUATED, evidence)
        return EvalResult(FAIL, evidence)
    return EvalResult(NOT_EVALUATED, {"error": f"unknown compound op {op!r}"})


def _eval_relational(predicate: dict, fields: dict) -> EvalResult:
    """"IF if_field == if_equals, THEN then_field == then_equals" - a
    condition that doesn't apply (antecedent false) is vacuously PASS, not
    NOT_EVALUATED, since we DID determine the antecedent doesn't hold."""
    if_value, if_present = _get(fields, predicate["if_field"])
    if not if_present:
        return EvalResult(NOT_EVALUATED, {"reason": "antecedent field unresolved", "field": predicate["if_field"]})
    if if_value != predicate["if_equals"]:
        return EvalResult(PASS, {"reason": "antecedent false, rule not applicable"})
    then_value, then_present = _get(fields, predicate["then_field"])
    if not then_present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["then_field"]})
    ok = then_value == predicate["then_equals"]
    return EvalResult(PASS if ok else FAIL, {"field": predicate["then_field"], "actual": then_value})


def _eval_set_membership(predicate: dict, fields: dict) -> EvalResult:
    values, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    values = values if isinstance(values, list) else [values]
    mode = predicate["mode"]
    # Case-insensitive: a config's `SHA1` once passed a deny-list of "sha1".
    fold = lambda v: v.strip().lower() if isinstance(v, str) else v
    allow_or_deny = {fold(v) for v in predicate["values"]}
    values_folded = [(v, fold(v)) for v in values]
    if mode == "all_in":
        bad = [v for v, f in values_folded if f not in allow_or_deny]
        return EvalResult(FAIL if bad else PASS, {"not_allowed": bad})
    if mode == "none_in":
        bad = [v for v, f in values_folded if f in allow_or_deny]
        return EvalResult(FAIL if bad else PASS, {"forbidden_found": bad})
    return EvalResult(NOT_EVALUATED, {"error": f"unknown mode {mode!r}"})


# --- ordered/first-match: the headline predicate type -----------------------
# Simulates first-match ACL evaluation order, because a membership check
# alone ("does a deny-23 rule exist somewhere") would score a config as safe
# even when an earlier permissive rule makes that deny rule dead code.
#
# Fail-closed by design (hardened 2026-09-27 after an adversarial review
# found false PASSes): every line is parsed with a small grammar
# (`action proto src [src-ports] dst [dst-ports] ...`); a line that has an
# action but can't be fully understood (object-groups, unknown port names)
# makes the verdict NOT_EVALUATED if it comes before the decision, never a
# silent skip. A deny only decides the question if it COVERS all of the
# traffic in question; any permit that OVERLAPS it is a violation.
# ACLs are evaluated one list at a time (lines are keyed `access-list <id>`
# or `[<name>]`), and only lists that are actually applied, when the config
# says which ones are (field AC.acl_bindings) - an unapplied ACL's deny must
# not hide a permit-all on the list that is really in use.

_PROTO_NUM = {"0": "ip", "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ahp", "89": "ospf"}
_PROTOCOLS = {"ip", "tcp", "udp", "icmp", "gre", "esp", "ahp", "ospf", "eigrp", "pim", "igmp", "ipinip", "sctp", "any"}
_NAMED_PORTS = {"telnet": 23, "ssh": 22, "www": 80, "http": 80, "https": 443, "ftp": 21, "ftp-data": 20, "smtp": 25,
                "snmp": 161, "snmptrap": 162, "domain": 53, "tftp": 69, "ntp": 123, "bgp": 179, "ldap": 389,
                "syslog": 514, "pop3": 110, "imap": 143, "cmd": 514, "login": 513, "exec": 512, "sunrpc": 111,
                "netbios-ns": 137, "netbios-dgm": 138, "netbios-ss": 139, "bootps": 67, "bootpc": 68, "isakmp": 500}
_PORT_OPS = ("eq", "neq", "gt", "lt", "range")
_TRAILERS = ("log", "log-input", "established", "time-range", "dscp", "precedence", "fragments", "tos", "ttl")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_GROUP_RE = re.compile(r"^\s*(?:access-list\s+(\S+)|\[([^\]]+)\])", re.IGNORECASE)
_ACTION_RE = re.compile(r"\b(permit|deny)\b", re.IGNORECASE)
_SEQ_RE = re.compile(r"^\s*(?:\[[^\]]+\]\s*)?(\d+)\s+(?:permit|deny)\b", re.IGNORECASE)


class _Unparsed(Exception):
    pass


def _port_token(t: str) -> Optional[int]:
    if t.isdigit():
        return int(t)
    return _NAMED_PORTS.get(t.lower())


def _parse_addr(toks: list, i: int):
    """-> (kind, next_index); kind is 'any' or 'specific'."""
    if i >= len(toks):
        raise _Unparsed("missing address")
    t = toks[i].lower()
    if t in ("any", "any4", "any6", "0.0.0.0/0", "::/0"):
        return "any", i + 1
    if t == "host":
        return "specific", i + 2
    if t in ("object-group", "addrgroup", "net-group", "object"):
        raise _Unparsed("object-group address, group contents not modeled")
    if t.startswith("not-"):
        raise _Unparsed("negated address")
    if _IPV4.match(t):
        if i + 1 < len(toks) and _IPV4.match(toks[i + 1]):
            if t == "0.0.0.0" and toks[i + 1] == "255.255.255.255":
                return "any", i + 2
            return "specific", i + 2
        return "specific", i + 1
    if "/" in t or ":" in t or re.match(r"^[a-z][\w.-]*$", t):
        # CIDR, IPv6, or a named network/alias (pfSense "lan", "wan", ...)
        return "specific", i + 1
    raise _Unparsed(f"address {t!r}")


def _is_port_word(t: str) -> bool:
    return _port_token(t) is not None


def _parse_ports(toks: list, i: int):
    """-> (portspec, next_index); portspec None means every port."""
    if i >= len(toks) or toks[i].lower() not in _PORT_OPS:
        return None, i
    op = toks[i].lower()
    i += 1
    if op == "range":
        if i + 1 >= len(toks):
            raise _Unparsed("incomplete range")
        a, b = _port_token(toks[i]), _port_token(toks[i + 1])
        if a is None or b is None:
            raise _Unparsed("unknown port name in range")
        return ("range", a, b), i + 2
    if op in ("gt", "lt"):
        if i >= len(toks) or _port_token(toks[i]) is None:
            raise _Unparsed(f"unknown port after {op}")
        return (op, _port_token(toks[i])), i + 1
    ports = set()
    while i < len(toks):
        t = toks[i].lower()
        if t in ("any", "host") or t in _TRAILERS or t in _PORT_OPS or _IPV4.match(t):
            break
        p = _port_token(t)
        if p is None:
            if not ports:
                raise _Unparsed(f"unknown port name {t!r}")
            break
        ports.add(p)
        i += 1
    if not ports:
        raise _Unparsed(f"no port after {op}")
    return (op, frozenset(ports)), i


def _port_covers(spec, port: int) -> bool:
    if spec is None:
        return True
    op = spec[0]
    if op == "eq":
        return port in spec[1]
    if op == "neq":
        return port not in spec[1]
    if op == "gt":
        return port > spec[1]
    if op == "lt":
        return port < spec[1]
    return spec[1] <= port <= spec[2]  # range


def _acl_group(line: str) -> str:
    m = _GROUP_RE.match(line)
    return (m.group(1) or m.group(2)) if m else "_"


def _parse_acl_line(line: str):
    """-> dict for a rule; None for a line that is not a rule at all (a
    remark, an `ip access-group` binding); a dict with "unparsed" for a
    rule that can't be fully understood."""
    if not isinstance(line, str):
        return None
    m = _ACTION_RE.search(line)
    if not m:
        return None
    if "remark" in line[: m.start()].lower().split():
        return None  # `access-list 101 remark deny telnet` is a comment
    toks = line[m.end():].split()
    base = {"action": m.group(1).lower(), "raw": line, "group": _acl_group(line)}
    try:
        if not toks:
            raise _Unparsed("empty rule")
        proto = _PROTO_NUM.get(toks[0].lower(), toks[0].lower())
        if proto == "ipv6":
            proto = "ip"  # an IPv6 list's `permit ipv6 any any` is all traffic, like `ip`
        if proto in _PROTOCOLS:
            i = 1
        elif _IPV4.match(proto) or proto in ("host",):
            proto, i = "ip", 0  # standard ACL: `permit 10.0.0.0 0.0.0.255`
        elif proto.isdigit():
            proto, i = f"proto-{proto}", 1
        else:
            raise _Unparsed(f"protocol {proto!r}")
        if proto == "any":
            proto = "ip"
        src, i = _parse_addr(toks, i)
        src_ports, i = _parse_ports(toks, i)
        if i < len(toks) and toks[i].lower() not in _TRAILERS:
            dst, i = _parse_addr(toks, i)
            dst_ports, i = _parse_ports(toks, i)
        else:
            dst, dst_ports = "any", None  # standard ACL: source only
    except _Unparsed as e:
        return {**base, "unparsed": str(e)}
    if "time-range" in (t.lower() for t in toks):
        # Active only during its time range: it can't be counted on to deny
        # (final review #4), so it is read as not understood.
        return {**base, "unparsed": "time-range: not always active"}
    return {**base, "protocol": proto, "src": src, "src_ports": src_ports, "dst": dst, "dst_ports": dst_ports,
            "src_any": src == "any"}


def _proto_overlaps(rule_proto: str, want: str) -> bool:
    return want in ("any", "ip") or rule_proto in ("ip", want)


def _proto_covers(rule_proto: str, want: str) -> bool:
    return rule_proto == "ip" or (want not in ("any", "ip") and rule_proto == want)


def _overlaps(p: dict, match: dict) -> bool:
    """Could this rule apply to ANY of the traffic in question?"""
    if not _proto_overlaps(p["protocol"], match["protocol"]):
        return False
    if match.get("source") == "any" and p["src"] != "any":
        return False  # a rule for specific sources is not "from any source"
    if match.get("any_port"):
        return True
    if match.get("port") is None:
        # "Arbitrary traffic of this protocol" (deny-by-default): a permit
        # for specific ports is an allowed exception, not a violation.
        return p["dst_ports"] is None
    return _port_covers(p["dst_ports"], match["port"])


def _covers(p: dict, match: dict) -> bool:
    """Does this rule decide ALL of the traffic in question?"""
    if not _proto_covers(p["protocol"], match["protocol"]):
        return False
    if p["src"] != "any" or p["dst"] != "any" or p["src_ports"] is not None:
        return False
    if match.get("any_port") or match.get("port") is None:
        return p["dst_ports"] is None
    return _port_covers(p["dst_ports"], match["port"])


def _first_match_one(parsed: list, match: dict, wanted: str) -> EvalResult:
    for p in parsed:
        if "unparsed" in p:
            if p["action"] == wanted:
                continue  # an unreadable deny can never make this PASS; at worst a safe false FAIL
            return EvalResult(NOT_EVALUATED, {"reason": f"ACL line not understood ({p['unparsed']}) before any "
                                                        f"rule decided this", "unparsed_line": p["raw"]})
        if p["action"] == wanted:
            if _covers(p, match):
                return EvalResult(PASS, {"first_match": p["raw"]})
        elif _overlaps(p, match):
            return EvalResult(FAIL, {"first_match": p["raw"]})
    return EvalResult(NOT_EVALUATED, {"reason": "no rule decides this traffic (only the implicit end-of-list "
                                                "default, not verified)", "no_decision": True})


def _eval_ordered_first_match(predicate: dict, fields: dict) -> EvalResult:
    rules, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    rules = rules if isinstance(rules, list) else [rules]
    match = predicate["match"]  # e.g. {"protocol": "tcp", "port": 23, "source": "any"}
    wanted = predicate.get("want_action_if_matched", "deny")

    groups: dict = {}
    for r in rules:
        p = _parse_acl_line(r)
        if p is not None:
            groups.setdefault(p["group"], []).append(p)
    if not groups:
        return EvalResult(NOT_EVALUATED, {"reason": "no ACL line could be parsed", "raw_rules": rules})
    for g, entries in groups.items():
        # IOS evaluates a named ACL by sequence number, not by where the line
        # sits in the file (final review #4: `20 deny` listed before `10 permit`).
        seqs = [_SEQ_RE.match(p["raw"]) for p in entries]
        if all(seqs):
            groups[g] = [p for _, p in sorted(zip((int(m.group(1)) for m in seqs), entries), key=lambda x: x[0])]
    # AC.acl_bindings present (even empty) means the vendor says which lists
    # are in force (Cisco: ip access-group / access-class / traffic-filter).
    bindings = fields.get("AC.acl_bindings")
    if bindings is not None:
        undefined = [b for b in bindings if b not in groups]
        if undefined:
            # IOS permits everything through an applied list that doesn't
            # exist; the other lists' denies must not hide that.
            return EvalResult(NOT_EVALUATED, {"reason": "an applied ACL is not defined in the config",
                                              "undefined": undefined})
        if not bindings:
            return EvalResult(NOT_EVALUATED, {"reason": "no ACL is applied to any interface or line"})
    considered = [g for g in groups if g in bindings] if bindings is not None else list(groups)
    unapplied = [g for g in groups if g not in considered]

    if predicate.get("scope") == "all_matches":
        # "No rule of this shape may exist with the wrong action" - e.g.
        # CIS pfSense 4.1.2, no allow rule from Any source ANYWHERE in the
        # list. Order is irrelevant here; every matching rule must comply.
        live = [p for g in considered for p in groups[g]]
        offending = [p["raw"] for p in live if "unparsed" not in p and p["action"] != wanted and _overlaps(p, match)]
        if offending:
            return EvalResult(FAIL, {"offending_rules": offending})
        unparsed = [p["raw"] for p in live if "unparsed" in p and p["action"] != wanted]
        if unparsed:
            return EvalResult(NOT_EVALUATED, {"reason": "ACL lines not understood", "unparsed_lines": unparsed})
        return EvalResult(PASS, {"offending_rules": []})

    per_group = {g: _first_match_one(groups[g], match, wanted) for g in considered}
    # A list where no rule touches this traffic permits none of it (the
    # default is deny), so it neither fails nor passes the device: FAIL if
    # any list fails, NOT_EVALUATED if any list has an unreadable line in the
    # way, PASS if some list explicitly decides it, else NOT_EVALUATED.
    kind = {g: ("NONE" if r.evidence.get("no_decision") else r.result) for g, r in per_group.items()}
    for verdict in (FAIL, NOT_EVALUATED, PASS, "NONE"):
        hit = [g for g, k in kind.items() if k == verdict]
        if hit:
            ev = dict(per_group[hit[0]].evidence)
            ev["acl"] = hit[0]
            if len(per_group) > 1:
                ev["per_acl"] = {g: r.result for g, r in per_group.items()}
            ev.pop("no_decision", None)
            if unapplied:
                ev["not_applied"] = unapplied
            return EvalResult(NOT_EVALUATED if verdict == "NONE" else verdict, ev)
    return EvalResult(NOT_EVALUATED, {})


_EVALUATORS = {
    "boolean": _eval_boolean,
    "range": _eval_range,
    "compound": _eval_compound,
    "relational": _eval_relational,
    "set-membership": _eval_set_membership,
    "ordered-first-match": _eval_ordered_first_match,
}
