"""resolve_unit - ONE function, ONE knowledge base (architecture-document.md
§1, §3 step 4). Tier 1 is exact/structural matching (corrected Sept 13 after
the embedding spike - see §3 step 4's revision note); embedding similarity is
a supporting signal for Tier 2/3, not the Tier-1 gate.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sqlalchemy.orm import Session

from . import llm_client
from .canonical_schema import CANONICAL_FIELDS, is_valid_field
from .models import KnowledgeBaseEntry, ReviewQueueItem

_embedding_model = None


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer
        _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedding_model


def embed(text: str) -> list:
    vec = _get_embedding_model().encode(text, normalize_embeddings=True)
    return vec.tolist()


def _cosine(a: list, b: list) -> float:
    a, b = np.array(a), np.array(b)
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


@dataclass
class ResolveResult:
    tier: str  # "tier1" | "tier2_accepted" | "tier3_pending"
    canonical_field: Optional[str] = None
    value: object = None
    kb_entry_id: Optional[str] = None
    kb_entry_version: Optional[int] = None
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
    review_queue_id: Optional[str] = None
    similar_kb_entries: list = field(default_factory=list)
    langfuse_trace_id: Optional[str] = None
    langfuse_observation_id: Optional[str] = None


def _tier1_exact_match(db: Session, unit_text: str, vendor: str, tenant_id: str) -> Optional[KnowledgeBaseEntry]:
    """Exact/structural match only - deterministic, no cosine similarity
    involved. This IS what "known vendor" means (architecture-document.md §1)."""
    candidates = (
        db.query(KnowledgeBaseEntry)
        .filter(
            KnowledgeBaseEntry.tenant_id == tenant_id,
            KnowledgeBaseEntry.vendor == vendor,
            KnowledgeBaseEntry.superseded_by.is_(None),
        )
        .all()
    )
    for entry in candidates:
        if entry.pattern_type == "exact" and entry.syntax_pattern.strip() == unit_text.strip():
            return entry
        if entry.pattern_type == "regex":
            try:
                if re.search(entry.syntax_pattern, unit_text):
                    return entry
            except re.error:
                continue
    return None


def _similar_kb_entries(db: Session, unit_text: str, vendor: str, tenant_id: str, top_k: int = 5) -> list:
    """Supporting signal only (not a gate) - ranked candidates shown to the
    LLM prompt and to a Tier-3 human reviewer."""
    # Same vendor only: a pfSense or SONiC pattern shown as "similar" to a
    # Cisco line is noise at best and misleading context for the LLM at
    # worst (lead-claude-task-tracker.md §9).
    entries = (
        db.query(KnowledgeBaseEntry)
        .filter(
            KnowledgeBaseEntry.tenant_id == tenant_id,
            KnowledgeBaseEntry.vendor == vendor,
            KnowledgeBaseEntry.embedding_vector.isnot(None),
            KnowledgeBaseEntry.superseded_by.is_(None),
        )
        .all()
    )
    if not entries:
        return []
    unit_vec = embed(unit_text)
    scored = [
        (_cosine(unit_vec, e.embedding_vector), e)
        for e in entries
    ]
    scored.sort(key=lambda p: p[0], reverse=True)
    return [
        {"syntax_pattern": e.syntax_pattern, "canonical_field": e.canonical_field, "similarity": round(s, 3)}
        for s, e in scored[:top_k]
    ]


def resolve_unit(
    db: Session,
    unit_text: str,
    vendor: str,
    device_id: str = None,
    tenant_id: str = "default",
    context: str = "",
) -> ResolveResult:
    # Tier 1: exact/structural match.
    hit = _tier1_exact_match(db, unit_text, vendor, tenant_id)
    if hit is not None:
        return ResolveResult(
            tier="tier1",
            canonical_field=hit.canonical_field,
            # A regex entry for a list field (e.g. "any numbered ACL line")
            # carries no fixed value - the matched line IS the value.
            value=hit.value if hit.value is not None else (
                unit_text if CANONICAL_FIELDS.get(hit.canonical_field) == "list" else True
            ),
            kb_entry_id=hit.id,
            kb_entry_version=hit.version,
            confidence=1.0,
        )

    # Tier 2: LLM, with similar KB entries as supporting context.
    similar = _similar_kb_entries(db, unit_text, vendor, tenant_id)
    candidate = llm_client.classify(unit_text, context, similar)

    if candidate is not None and candidate.canonical_field != "UNKNOWN" and candidate.confidence >= 0.6:
        return ResolveResult(
            tier="tier2_accepted",
            canonical_field=candidate.canonical_field,
            value=candidate.value,
            confidence=candidate.confidence,
            reasoning=candidate.reasoning,
            similar_kb_entries=similar,
            langfuse_trace_id=candidate.langfuse_trace_id,
            langfuse_observation_id=candidate.langfuse_observation_id,
        )

    # Tier 3: LLM unavailable, invalid, UNKNOWN, or low self-reported
    # confidence - queue for human review. Never a crash, never a silent drop.
    #
    # Dedupe first: re-ingesting the same or a similar config (routine during
    # testing, and realistic for a real device re-audited later) would
    # otherwise pile up identical pending items for the same line every time,
    # which reads as broken clutter rather than a real queue. If an
    # unresolved item for this exact vendor+text is already pending, reuse it
    # instead of creating a duplicate.
    existing = (
        db.query(ReviewQueueItem)
        .filter(
            ReviewQueueItem.tenant_id == tenant_id,
            ReviewQueueItem.raw_unit == unit_text,
            ReviewQueueItem.status == "pending",
        )
        .first()
    )
    if existing is not None:
        return ResolveResult(tier="tier3_pending", review_queue_id=existing.id, similar_kb_entries=similar)

    item = ReviewQueueItem(
        tenant_id=tenant_id,
        device_id=device_id,
        raw_unit=unit_text,
        context=context,
        candidate_mapping=(
            {
                "canonical_field": candidate.canonical_field,
                "value": candidate.value,
                "confidence": candidate.confidence,
                "reasoning": candidate.reasoning,
            }
            if candidate is not None
            else None
        ),
        similar_kb_entries=similar,
        confidence=candidate.confidence if candidate is not None else None,
        langfuse_trace_id=candidate.langfuse_trace_id if candidate is not None else None,
        langfuse_observation_id=candidate.langfuse_observation_id if candidate is not None else None,
        status="pending",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return ResolveResult(tier="tier3_pending", review_queue_id=item.id, similar_kb_entries=similar)
