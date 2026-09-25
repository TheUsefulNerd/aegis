"""Tiered resolution: Tier 1 exact/regex KB match -> Tier 2 LLM (accepted at
confidence >= 0.6) -> Tier 3 human review queue, deduped."""
from app import llm_client, resolve
from app.llm_client import LLMCandidate
from app.models import KnowledgeBaseEntry, ReviewQueueItem


def _candidate(field="AC.telnet_enabled", value=False, confidence=0.9):
    return LLMCandidate(canonical_field=field, value=value, confidence=confidence, reasoning="r",
                        provider="test", model_version="test")


def test_tier1_exact_seed_match_needs_no_llm(db, monkeypatch):
    def _fail(*a, **k):
        raise AssertionError("Tier 1 hit must not call the LLM")
    monkeypatch.setattr(llm_client, "classify", _fail)
    r = resolve.resolve_unit(db, "service password-encryption", "cisco_ios")
    assert r.tier == "tier1" and r.canonical_field == "IA.password_encryption_enabled"


def test_redacted_line_still_matches_its_seed(db):
    # The seed is written against the post-redaction text, so the hash value
    # never matters - only the type digit.
    r = resolve.resolve_unit(db, "enable secret 9 [REDACTED:ENABLE_SECRET_HASH]", "cisco_ios")
    assert r.tier == "tier1" and r.value == "secret_type_9"


def test_tier1_is_vendor_scoped(db):
    # A Cisco seed must not match the same text on another vendor.
    r = resolve.resolve_unit(db, "service password-encryption", "pfsense")
    assert r.tier != "tier1"


def test_tier2_accepted_at_threshold(db, monkeypatch):
    monkeypatch.setattr(llm_client, "classify", lambda *a, **k: _candidate(confidence=0.6))
    r = resolve.resolve_unit(db, "transport input none", "cisco_ios")
    assert r.tier == "tier2_accepted" and r.canonical_field == "AC.telnet_enabled"


def test_low_confidence_goes_to_review_with_the_suggestion(db, monkeypatch):
    monkeypatch.setattr(llm_client, "classify", lambda *a, **k: _candidate(confidence=0.4))
    r = resolve.resolve_unit(db, "weird-directive 1", "cisco_ios")
    assert r.tier == "tier3_pending"
    item = db.get(ReviewQueueItem, r.review_queue_id)
    assert item.candidate_mapping["canonical_field"] == "AC.telnet_enabled"


def test_llm_unavailable_goes_to_review_never_crashes(db):
    r = resolve.resolve_unit(db, "weird-directive 2", "cisco_ios")
    assert r.tier == "tier3_pending"
    assert db.get(ReviewQueueItem, r.review_queue_id).candidate_mapping is None


def test_same_pending_line_is_deduped(db):
    a = resolve.resolve_unit(db, "weird-directive 3", "cisco_ios")
    b = resolve.resolve_unit(db, "weird-directive 3", "cisco_ios")
    assert a.review_queue_id == b.review_queue_id
    assert db.query(ReviewQueueItem).filter_by(raw_unit="weird-directive 3").count() == 1


def test_similar_entries_come_from_the_same_vendor_only(db):
    db.add(KnowledgeBaseEntry(vendor="pfsense", pattern_type="exact", syntax_pattern="pf-only-pattern",
                              canonical_field="AU.logging_enabled", embedding_vector=resolve.embed("x"),
                              source="tier1_seed"))
    db.add(KnowledgeBaseEntry(vendor="cisco_ios", pattern_type="exact", syntax_pattern="cisco-pattern",
                              canonical_field="AU.logging_enabled", embedding_vector=resolve.embed("y"),
                              source="tier1_seed"))
    db.commit()
    similar = resolve._similar_kb_entries(db, "anything", "cisco_ios", "default")
    patterns = {s["syntax_pattern"] for s in similar}
    assert "cisco-pattern" in patterns and "pf-only-pattern" not in patterns


def test_regex_seed_resolves_any_numbered_acl_line_with_the_line_as_value(db):
    r = resolve.resolve_unit(db, "access-list 150 permit tcp any host 192.0.2.5 eq 443", "cisco_ios")
    assert r.tier == "tier1" and r.canonical_field == "AC.acl_rules"
    assert r.value == "access-list 150 permit tcp any host 192.0.2.5 eq 443"


def test_reassembled_pfsense_rule_is_tier1(db):
    r = resolve.resolve_unit(db, "access-list pfsense-wan deny tcp any wanip eq 23", "pfsense")
    assert r.tier == "tier1" and r.value == "access-list pfsense-wan deny tcp any wanip eq 23"
