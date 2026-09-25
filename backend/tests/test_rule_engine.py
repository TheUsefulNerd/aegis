"""All 6 predicate types. The invariant that matters most: a field that was
never resolved is NOT_EVALUATED - never a silent PASS."""
import pytest

from app.rule_engine import FAIL, NOT_EVALUATED, PASS, evaluate


def test_missing_field_is_not_evaluated_for_every_type():
    empty = {}
    assert evaluate("boolean", {"field": "AC.telnet_enabled", "equals": False}, empty).result == NOT_EVALUATED
    assert evaluate("range", {"field": "IA.ssh_version", "min": 2, "max": 2}, empty).result == NOT_EVALUATED
    assert evaluate("set-membership", {"field": "X", "mode": "none_in", "values": ["a"]}, empty).result == NOT_EVALUATED
    assert evaluate("ordered-first-match", {"field": "AC.acl_rules", "match": {"protocol": "tcp", "port": 23}},
                    empty).result == NOT_EVALUATED
    assert evaluate("relational", {"if_field": "A", "if_equals": True, "then_field": "B", "then_equals": True},
                    empty).result == NOT_EVALUATED


def test_unknown_check_type_is_not_evaluated():
    assert evaluate("made-up", {}, {"x": 1}).result == NOT_EVALUATED


@pytest.mark.parametrize("value, expected", [
    (False, PASS), (True, FAIL), ("false", PASS), ("true", FAIL), ("enabled", FAIL),
])
def test_boolean_coerces_reviewer_strings(value, expected):
    # "false" typed into a form must not be read as truthy.
    r = evaluate("boolean", {"field": "AC.telnet_enabled", "equals": False}, {"AC.telnet_enabled": value})
    assert r.result == expected


@pytest.mark.parametrize("value, expected", [(2, PASS), (1, FAIL), ("2", PASS), ("abc", NOT_EVALUATED)])
def test_range(value, expected):
    r = evaluate("range", {"field": "IA.ssh_version", "min": 2, "max": 2}, {"IA.ssh_version": value})
    assert r.result == expected


def test_range_rejects_boolean_instead_of_reading_it_as_one():
    # float(True) == 1.0 - a mis-typed classification must not become a FAIL.
    r = evaluate("range", {"field": "IA.ssh_version", "min": 2, "max": 2}, {"IA.ssh_version": True})
    assert r.result == NOT_EVALUATED


@pytest.mark.parametrize("minutes, expected", [(5, PASS), (10, PASS), (15, FAIL), (0, FAIL)])
def test_range_exclusive_min_fails_a_disabled_timeout(minutes, expected):
    # B7: exec-timeout 0 means "never time out".
    pred = {"field": "AC.session_idle_timeout_minutes", "max": 10, "exclusive_min": 0}
    assert evaluate("range", pred, {"AC.session_idle_timeout_minutes": minutes}).result == expected


def test_compound_and_or_not():
    t = {"check_type": "boolean", "predicate": {"field": "a", "equals": True}}
    f = {"check_type": "boolean", "predicate": {"field": "b", "equals": True}}
    u = {"check_type": "boolean", "predicate": {"field": "missing", "equals": True}}
    fields = {"a": True, "b": False}
    assert evaluate("compound", {"op": "AND", "conditions": [t, f]}, fields).result == FAIL
    assert evaluate("compound", {"op": "AND", "conditions": [t, u]}, fields).result == NOT_EVALUATED
    assert evaluate("compound", {"op": "OR", "conditions": [f, t]}, fields).result == PASS
    assert evaluate("compound", {"op": "NOT", "condition": f}, fields).result == PASS
    assert evaluate("compound", {"op": "NOT", "condition": u}, fields).result == NOT_EVALUATED


def test_relational_vacuous_pass_when_antecedent_false():
    pred = {"if_field": "A", "if_equals": True, "then_field": "B", "then_equals": True}
    assert evaluate("relational", pred, {"A": False}).result == PASS
    assert evaluate("relational", pred, {"A": True, "B": True}).result == PASS
    assert evaluate("relational", pred, {"A": True, "B": False}).result == FAIL


def test_set_membership():
    pred = {"field": "AC.snmp_community_strings", "mode": "none_in", "values": ["public", "private"]}
    assert evaluate("set-membership", pred, {"AC.snmp_community_strings": ["[REDACTED:SNMP_COMMUNITY]"]}).result == PASS
    assert evaluate("set-membership", pred, {"AC.snmp_community_strings": ["public"]}).result == FAIL


TELNET = {"field": "AC.acl_rules", "match": {"protocol": "tcp", "port": 23}, "want_action_if_matched": "deny"}
DEFAULT_DENY = {"field": "AC.acl_rules", "match": {"protocol": "tcp", "port": None}, "want_action_if_matched": "deny"}


def test_first_match_order_decides_not_mere_presence():
    # The headline case: the deny-23 exists, but a permit-all shadows it.
    shadowed = ["access-list 101 permit ip any any", "access-list 101 deny tcp any any eq 23"]
    correct = ["access-list 101 deny tcp any any eq 23", "access-list 101 permit ip any any"]
    r = evaluate("ordered-first-match", TELNET, {"AC.acl_rules": shadowed})
    assert r.result == FAIL and r.evidence["first_match"] == shadowed[0]
    assert evaluate("ordered-first-match", TELNET, {"AC.acl_rules": correct}).result == PASS


def test_deny_by_default_is_not_satisfied_by_a_port_specific_deny():
    # B6: only a rule covering every port answers "what happens to arbitrary TCP".
    acl = ["access-list 101 deny tcp any any eq 23", "access-list 101 permit ip any any"]
    r = evaluate("ordered-first-match", DEFAULT_DENY, {"AC.acl_rules": acl})
    assert r.result == FAIL and r.evidence["first_match"] == acl[1]
    closed = ["access-list 101 permit tcp any any eq 22", "access-list 101 deny ip any any"]
    assert evaluate("ordered-first-match", DEFAULT_DENY, {"AC.acl_rules": closed}).result == PASS


def test_acl_parser_reads_port_when_both_addresses_are_any():
    from app.rule_engine import _parse_acl_line
    assert _parse_acl_line("access-list 101 permit tcp any any eq 22")["port"] == 22
    assert _parse_acl_line("access-list 101 deny tcp host 10.0.0.1 any eq telnet")["port"] == 23
    assert _parse_acl_line("deny   ip object-group BLACKBALLED any log")["port"] is None
    assert _parse_acl_line(" permit tcp 10.0.0.0 0.0.0.255 any eq 443")["port"] == 443


def test_unparseable_acl_is_not_evaluated_not_pass():
    assert evaluate("ordered-first-match", TELNET, {"AC.acl_rules": ["garbage"]}).result == NOT_EVALUATED


ANY_SOURCE_ALLOW = {"field": "AC.acl_rules", "match": {"protocol": "any", "source": "any", "any_port": True},
                    "scope": "all_matches", "want_action_if_matched": "deny"}


def test_no_allow_rule_from_any_source_anywhere():
    # CIS pfSense 4.1.2. The LAN default-allow (source = lan) is compliant;
    # an allow from Any source fails wherever it sits in the list.
    ok = ["access-list pfsense-wan deny tcp any wanip eq 23", "access-list pfsense-lan permit ip lan any"]
    assert evaluate("ordered-first-match", ANY_SOURCE_ALLOW, {"AC.acl_rules": ok}).result == PASS
    bad = ok + ["access-list pfsense-wan permit tcp any any eq 443"]
    r = evaluate("ordered-first-match", ANY_SOURCE_ALLOW, {"AC.acl_rules": bad})
    assert r.result == FAIL and r.evidence["offending_rules"] == [bad[-1]]


def test_protocol_any_matches_every_protocol():
    pred = {"field": "AC.acl_rules", "match": {"protocol": "any", "port": None}, "want_action_if_matched": "deny"}
    assert evaluate("ordered-first-match", pred, {"AC.acl_rules": ["access-list 1 permit udp any any"]}).result == FAIL
