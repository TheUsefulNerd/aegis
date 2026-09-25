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


def _coerce_bool(v) -> bool:
    """Values reaching here can be a real bool, or a string typed into a
    plain HTML input by a reviewer (e.g. "false") - naive `bool(v)` would
    silently misread the non-empty string "false" as truthy. Coerce known
    string forms explicitly instead of trusting Python truthiness."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "enabled")
    return bool(v)


def _eval_boolean(predicate: dict, fields: dict) -> EvalResult:
    value, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    ok = _coerce_bool(value) == _coerce_bool(predicate["equals"])
    return EvalResult(PASS if ok else FAIL, {"field": predicate["field"], "actual": value})


def _eval_range(predicate: dict, fields: dict) -> EvalResult:
    value, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    if isinstance(value, bool):
        # `float(True)` is 1.0 - a boolean reaching a numeric check is a
        # classification error upstream, not the number 1.
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"], "reason": "not numeric", "actual": value})
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
    allow_or_deny = set(predicate["values"])
    if mode == "all_in":
        bad = [v for v in values if v not in allow_or_deny]
        return EvalResult(FAIL if bad else PASS, {"not_allowed": bad})
    if mode == "none_in":
        bad = [v for v in values if v in allow_or_deny]
        return EvalResult(FAIL if bad else PASS, {"forbidden_found": bad})
    return EvalResult(NOT_EVALUATED, {"error": f"unknown mode {mode!r}"})


# --- ordered/first-match: the headline predicate type -----------------------
# Simulates first-match ACL evaluation order, because a membership check
# alone ("does a deny-23 rule exist somewhere") would score a config as safe
# even when an earlier permissive rule makes that deny rule dead code.
# Scope note: this parses simple Cisco-style extended-ACL text lines
# specifically. Cross-reference reassembly of multi-line structured formats
# (e.g. SONiC's flattened ACL_RULE table entries) is the deferred §3.5
# cross-reference-linking work - out of scope for this predicate today.

# `[access-list N] permit|deny <proto> <src...> <dst...> [eq <port>]`. The
# address specs are deliberately not parsed: an earlier regex tried to, and
# `\S+(?:\s+\S+)?` for each address was ambiguous - for `permit tcp any any
# eq 22` it read the source as "any any" and the destination as "eq 22", so
# the port was silently never parsed whenever both addresses were `any`
# (the most common shape there is). Only action, protocol and destination
# port matter to the evaluator; the destination port is the LAST `eq`.
_ACL_HEAD_RE = re.compile(r"\b(?P<action>permit|deny)\s+(?P<proto>\w+)\b(?P<rest>.*)$", re.IGNORECASE)
_ACL_EQ_RE = re.compile(r"\beq\s+(\S+)", re.IGNORECASE)
_NAMED_PORTS = {"telnet": 23, "ssh": 22, "www": 80, "http": 80, "https": 443, "ftp": 21, "smtp": 25, "snmp": 161}


def _parse_acl_line(line: str) -> Optional[dict]:
    if not isinstance(line, str):
        return None
    m = _ACL_HEAD_RE.search(line)
    if not m:
        return None
    ports = _ACL_EQ_RE.findall(m.group("rest"))
    port = None
    if ports:
        token = ports[-1].lower()
        port = int(token) if token.isdigit() else _NAMED_PORTS.get(token)
        if port is None:
            return None  # a named port we don't know - don't guess its number
    return {
        "action": m.group("action").lower(),
        "protocol": m.group("proto").lower(),
        "port": port,
        "raw": line,
    }


def _eval_ordered_first_match(predicate: dict, fields: dict) -> EvalResult:
    rules, present = _get(fields, predicate["field"])
    if not present:
        return EvalResult(NOT_EVALUATED, {"field": predicate["field"]})
    rules = rules if isinstance(rules, list) else [rules]

    match = predicate["match"]  # {"protocol": "tcp", "port": 23}
    parsed = [_parse_acl_line(r) for r in rules]

    for p in parsed:
        if p is None:
            continue
        proto_matches = p["protocol"] in ("ip", match["protocol"])
        if match.get("port") is None:
            # The question is "what happens to ARBITRARY traffic of this
            # protocol" (e.g. deny-by-default) - only a rule covering every
            # port answers that. Counting a port-specific line here let
            # `[deny tcp any any eq 23, permit ip any any]` PASS a
            # deny-by-default check although the ACL ends in permit-all.
            port_matches = p["port"] is None
        else:
            port_matches = p["port"] is None or p["port"] == match["port"]
        if proto_matches and port_matches:
            # First matching rule in sequence - its action decides this,
            # regardless of any later rule that also happens to match.
            wanted = predicate.get("want_action_if_matched", "deny")
            ok = p["action"] == wanted
            return EvalResult(PASS if ok else FAIL, {"first_match": p["raw"]})

    if not any(parsed):
        # Nothing parsed at all - can't honestly claim to have evaluated this,
        # rather than assume an implicit-deny default we can't verify we
        # actually captured every rule for.
        return EvalResult(NOT_EVALUATED, {"reason": "no ACL line could be parsed", "raw_rules": rules})
    # Rules parsed, but none matched the protocol/port in question -
    # no rule addresses this traffic at all.
    return EvalResult(NOT_EVALUATED, {"reason": "no rule matches the given protocol/port", "raw_rules": rules})


_EVALUATORS = {
    "boolean": _eval_boolean,
    "range": _eval_range,
    "compound": _eval_compound,
    "relational": _eval_relational,
    "set-membership": _eval_set_membership,
    "ordered-first-match": _eval_ordered_first_match,
}
