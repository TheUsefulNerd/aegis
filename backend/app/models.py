"""Data model - matches architecture-document.md §6 (Data model) with the
Tier-1 correction from the Sept-13 embedding spike folded in: KnowledgeBaseEntry
gets an explicit `pattern_type` (exact|regex) since Tier 1 is now
structural/exact matching, not a fuzzy cosine gate. `embedding_vector` is kept
as a supporting signal for Tier 2/3 (candidate suggestions), not as the Tier-1
gate."""
import datetime as dt
import uuid

from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, JSON, Text, ForeignKey, Integer
)
from sqlalchemy.orm import relationship

from .db import Base


def _id():
    return str(uuid.uuid4())


class KnowledgeBaseEntry(Base):
    __tablename__ = "kb_entries"

    id = Column(String, primary_key=True, default=_id)
    version = Column(Integer, nullable=False, default=1)
    tenant_id = Column(String, nullable=False, default="default")
    vendor = Column(String, nullable=False)
    version_family = Column(String, nullable=True)
    pattern_type = Column(String, nullable=False)  # "exact" | "regex"
    syntax_pattern = Column(Text, nullable=False)
    canonical_field = Column(String, nullable=False)
    value = Column(JSON, nullable=True)  # the value this pattern asserts once matched
    embedding_vector = Column(JSON, nullable=True)  # supporting signal only
    confidence = Column(Float, nullable=True)
    source = Column(String, nullable=False)  # tier1_seed | tier2_llm | tier3_human
    llm_model_version = Column(String, nullable=True)
    llm_prompt_version = Column(String, nullable=True)
    langfuse_trace_id = Column(String, nullable=True)
    confirmed_by = Column(String, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    superseded_by = Column(String, nullable=True)
    # The reviewer's judgment of whether this pattern matters for security at
    # all - distinct from `source`/confidence, which only record HOW a mapping
    # was decided. Copied from the confirming ReviewQueueItem so it carries
    # forward to every future Tier-1 match of this pattern.
    is_security_relevant = Column(Boolean, nullable=True)
    reviewer_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=_id)
    tenant_id = Column(String, nullable=False, default="default")
    hostname = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    model = Column(String, nullable=True)
    firmware_version = Column(String, nullable=True)
    source_file = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    # Per-type COUNTS only ([{type, count}]) - never the secret values
    # themselves, which exist only in memory for the duration of /ingest.
    redaction_hits = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class CanonicalConfig(Base):
    __tablename__ = "canonical_configs"

    id = Column(String, primary_key=True, default=_id)
    tenant_id = Column(String, nullable=False, default="default")
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    vendor = Column(String, nullable=False)
    version = Column(String, nullable=True)
    parse_coverage_pct = Column(JSON, nullable=True)  # {overall, by_severity:{...}}
    fields = Column(JSON, nullable=True)  # {nist_family.field: scalar|list}
    provenance = Column(JSON, nullable=True)  # {field: {kb_entry_id, kb_entry_version, confidence_tier, source_unit_ids}}
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    device = relationship("Device")


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True, default=_id)
    standard_ref = Column(String, nullable=False)  # e.g. "CIS-1.1.1"
    standard_version = Column(String, nullable=False)
    control_family = Column(String, nullable=False)  # NIST 800-53 family, e.g. "AC"
    check_type = Column(String, nullable=False)
    # boolean|range|compound|relational|set-membership|ordered-first-match
    predicate = Column(JSON, nullable=False)
    severity = Column(String, nullable=False)  # CAT_I|CAT_II|CAT_III
    remediation_template_ref = Column(String, nullable=True)
    framework = Column(String, nullable=False)  # CIS|NIST|STIG|ISO
    title = Column(String, nullable=True)
    # e.g. ["cisco_ios"] for a vendor-specific benchmark; null = applies to
    # every vendor (NIST/ISO). Without this, a Cisco router was being scored
    # against - and cited as failing - the CIS *pfSense* benchmark.
    applies_to_vendors = Column(JSON, nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_id)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    rule_id = Column(String, ForeignKey("rules.id"), nullable=False)
    rule_version_at_evaluation = Column(String, nullable=True)
    result = Column(String, nullable=False)  # PASS|FAIL|NOT_EVALUATED
    severity = Column(String, nullable=False)
    evaluated_at = Column(DateTime, default=dt.datetime.utcnow)
    confidence_tier = Column(String, nullable=True)  # tier1|tier2_accepted|tier3_human_confirmed
    evidence = Column(JSON, nullable=True)  # {source_unit_ids, kb_entry_id, kb_entry_version}
    remediation_text = Column(Text, nullable=True)
    remediation_source = Column(String, nullable=True)  # template|llm-drafted-confirmed
    stale = Column(Boolean, default=False)

    device = relationship("Device")
    rule = relationship("Rule")


class ReviewQueueItem(Base):
    __tablename__ = "review_queue"

    id = Column(String, primary_key=True, default=_id)
    tenant_id = Column(String, nullable=False, default="default")
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    raw_unit = Column(Text, nullable=False)  # redacted + sanitized
    context = Column(Text, nullable=True)
    candidate_mapping = Column(JSON, nullable=True)  # {canonical_field, value, confidence, reasoning}
    similar_kb_entries = Column(JSON, nullable=True)  # supporting signal shown to reviewer
    confidence = Column(Float, nullable=True)
    langfuse_trace_id = Column(String, nullable=True)  # set when a Tier-2 candidate exists
    langfuse_observation_id = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")  # pending|confirmed|rejected
    reviewer_id = Column(String, nullable=True)
    # Why this item is here when it's NOT an ordinary low-confidence Tier-3
    # miss. "sanity_gate" = blocked as a suspected prompt injection before any
    # LLM call; null = the AI simply wasn't sure. Without this the two were
    # indistinguishable in the queue - an active attack looked like any other
    # pending line.
    flag_type = Column(String, nullable=True)
    flag_reason = Column(Text, nullable=True)
    is_security_relevant = Column(Boolean, nullable=True)
    reviewer_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
