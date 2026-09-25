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
from .canonical_schema import CANONICAL_FIELDS, NOT_SECURITY, is_valid_field
from .models import KnowledgeBaseEntry, LLMCacheEntry, ReviewQueueItem

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
    tier: str  # "tier1" | "tier2_accepted" | "tier3_pending" | "not_security"
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


def _similar_kb_entries(db: Session, unit_text: str, vendor: str, tenant_id: str, top_k: int = 5) -> list:
    """Supporting signal only (not a gate) - ranked same-vendor candidates
    shown to the LLM prompt and to a Tier-3 human reviewer. Same vendor only:
    a pfSense or SONiC pattern shown as "similar" to a Cisco line is noise at
    best and misleading context at worst (lead-claude-task-tracker.md §9)."""
    return _similar_many(_tier1_entries(db, vendor, tenant_id), [unit_text], top_k)[0]


def embed_many(texts: list) -> list:
    """One encode() call for a whole file instead of one per line."""
    if not texts:
        return []
    return [v.tolist() for v in _get_embedding_model().encode(texts, normalize_embeddings=True)]


def _tier1_entries(db: Session, vendor: str, tenant_id: str) -> list:
    """Loaded once per file, not once per line (it was a query per unit)."""
    return (
        db.query(KnowledgeBaseEntry)
        .filter(
            KnowledgeBaseEntry.tenant_id == tenant_id,
            KnowledgeBaseEntry.vendor == vendor,
            KnowledgeBaseEntry.superseded_by.is_(None),
        )
        .all()
    )


def _match_tier1(entries: list, unit_text: str) -> Optional[KnowledgeBaseEntry]:
    for entry in entries:
        if entry.pattern_type == "exact" and entry.syntax_pattern.strip() == unit_text.strip():
            return entry
        if entry.pattern_type == "regex":
            try:
                if re.search(entry.syntax_pattern, unit_text):
                    return entry
            except re.error:
                continue
    return None


def _similar_many(entries: list, unit_texts: list, top_k: int = 5) -> list:
    """Supporting signal only - same as _similar_kb_entries, batched."""
    with_vec = [e for e in entries if e.embedding_vector is not None]
    if not with_vec or not unit_texts:
        return [[] for _ in unit_texts]
    mat = np.array([e.embedding_vector for e in with_vec], dtype=float)
    mat /= np.maximum(np.linalg.norm(mat, axis=1, keepdims=True), 1e-12)
    out = []
    for vec in embed_many(unit_texts):
        v = np.array(vec, dtype=float)
        v /= max(np.linalg.norm(v), 1e-12)
        scores = mat @ v
        order = np.argsort(-scores)[:top_k]
        out.append([{"syntax_pattern": with_vec[i].syntax_pattern, "canonical_field": with_vec[i].canonical_field,
                     "similarity": round(float(scores[i]), 3)} for i in order])
    return out


def _cached_candidates(db: Session, vendor: str, texts: list) -> dict:
    if not texts:
        return {}
    rows = (
        db.query(LLMCacheEntry)
        .filter(LLMCacheEntry.vendor == vendor, LLMCacheEntry.prompt_version == llm_client.BATCH_PROMPT_VERSION,
                LLMCacheEntry.unit_text.in_(texts))
        .all()
    )
    return {
        r.unit_text: llm_client.LLMCandidate(
            canonical_field=r.response["canonical_field"], value=r.response["value"],
            confidence=float(r.response["confidence"]), reasoning=r.response.get("reasoning", ""),
            provider=r.response.get("provider", "cache"), model_version=r.response.get("model_version", ""),
            prompt_version=r.prompt_version,
        )
        for r in rows
    }


def resolve_units(
    db: Session,
    unit_texts: list,
    vendor: str,
    device_id: str = None,
    tenant_id: str = "default",
) -> list:
    """Resolve a whole file's units at once: one Tier-1 pass, cached AI
    answers reused, every remaining line classified in parallel batches,
    then Tier 3 for anything not confidently accepted. Returns one
    ResolveResult per input unit, in input order (ACL order matters)."""
    entries = _tier1_entries(db, vendor, tenant_id)
    results: list = [None] * len(unit_texts)
    misses: dict = {}  # unit text -> [indexes]
    for i, text in enumerate(unit_texts):
        hit = _match_tier1(entries, text)
        if hit is not None and hit.canonical_field == NOT_SECURITY:
            # Known structure, or a line a human already judged irrelevant:
            # instant, no AI call, no review item.
            results[i] = ResolveResult(tier="not_security", kb_entry_id=hit.id, confidence=1.0)
        elif hit is not None:
            results[i] = ResolveResult(
                tier="tier1",
                canonical_field=hit.canonical_field,
                # A regex entry for a list field (e.g. "any numbered ACL line")
                # carries no fixed value - the matched line IS the value.
                value=hit.value if hit.value is not None else (
                    text if CANONICAL_FIELDS.get(hit.canonical_field) == "list" else True
                ),
                kb_entry_id=hit.id,
                kb_entry_version=hit.version,
                confidence=1.0,
            )
        else:
            misses.setdefault(text, []).append(i)

    texts = list(misses)
    similar = dict(zip(texts, _similar_many(entries, texts)))
    candidates = _cached_candidates(db, vendor, texts)
    pending = {
        i.raw_unit: i for i in db.query(ReviewQueueItem).filter(
            ReviewQueueItem.tenant_id == tenant_id, ReviewQueueItem.status == "pending",
            ReviewQueueItem.raw_unit.in_(texts),
        ).all()
    } if texts else {}
    # A line already waiting for a human is not sent to the AI again - the
    # human owns that decision now, and re-asking only burns quota and time
    # on every re-upload of the same config.
    todo = [t for t in texts if t not in candidates and t not in pending]
    for text, cand in zip(todo, llm_client.classify_batch(todo, [similar[t] for t in todo])):
        if cand is None:
            continue  # unavailable / invalid: never cached, goes to a human
        candidates[text] = cand
        db.add(LLMCacheEntry(vendor=vendor, unit_text=text, prompt_version=llm_client.BATCH_PROMPT_VERSION,
                             response={"canonical_field": cand.canonical_field, "value": cand.value,
                                       "confidence": cand.confidence, "reasoning": cand.reasoning,
                                       "provider": cand.provider, "model_version": cand.model_version}))

    for text, idxs in misses.items():
        cand = candidates.get(text)
        if cand is not None and cand.canonical_field != "UNKNOWN" and cand.confidence >= 0.6:
            res = ResolveResult(
                tier="tier2_accepted", canonical_field=cand.canonical_field, value=cand.value,
                confidence=cand.confidence, reasoning=cand.reasoning, similar_kb_entries=similar[text],
                langfuse_trace_id=cand.langfuse_trace_id, langfuse_observation_id=cand.langfuse_observation_id,
            )
        else:
            # Tier 3: AI unavailable, invalid, UNKNOWN, or not confident.
            # Deduped: an identical line already waiting for review is reused
            # instead of piling up duplicates on every re-upload.
            item = pending.get(text)
            if item is None:
                item = ReviewQueueItem(
                    tenant_id=tenant_id, device_id=device_id, raw_unit=text, context="",
                    candidate_mapping=({"canonical_field": cand.canonical_field, "value": cand.value,
                                        "confidence": cand.confidence, "reasoning": cand.reasoning}
                                       if cand is not None else None),
                    similar_kb_entries=similar[text],
                    confidence=cand.confidence if cand is not None else None,
                    langfuse_trace_id=cand.langfuse_trace_id if cand is not None else None,
                    langfuse_observation_id=cand.langfuse_observation_id if cand is not None else None,
                    status="pending",
                )
                db.add(item)
                db.flush()  # assigns item.id without a commit per line
                pending[text] = item
            res = ResolveResult(tier="tier3_pending", review_queue_id=item.id, similar_kb_entries=similar[text])
        for i in idxs:
            results[i] = res
    db.commit()
    return results


def resolve_unit(
    db: Session,
    unit_text: str,
    vendor: str,
    device_id: str = None,
    tenant_id: str = "default",
    context: str = "",
) -> ResolveResult:
    """Single-unit form of resolve_units (same tiers, same rules)."""
    return resolve_units(db, [unit_text], vendor, device_id=device_id, tenant_id=tenant_id)[0]
