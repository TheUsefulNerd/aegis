"""Tamper-evident record of human decisions.

Every pattern a reviewer teaches (a confirmed mapping, or a "not security
relevant" decision) is linked into a SHA-256 hash chain: each entry's hash
covers its own content AND the previous entry's hash. Editing, deleting or
reordering any past decision - directly in the database - breaks every hash
after it, and `verify()` reports exactly where. This is what makes "a human
decided this" an auditable claim rather than a label.

Seed patterns shipped with AEGIS are not chained; they are versioned files in
the repository.
"""
import hashlib
import json

from sqlalchemy.orm import Session

from .models import KnowledgeBaseEntry

GENESIS = "0" * 64


def _payload(e: KnowledgeBaseEntry) -> str:
    return json.dumps({
        "id": e.id, "tenant": e.tenant_id, "vendor": e.vendor, "pattern_type": e.pattern_type,
        "pattern": e.syntax_pattern, "field": e.canonical_field, "value": e.value,
        "reviewer": e.confirmed_by, "at": e.confirmed_at.isoformat() if e.confirmed_at else None,
        "security_relevant": e.is_security_relevant, "notes": e.reviewer_notes,
    }, sort_keys=True, default=str)


def _digest(prev: str, e: KnowledgeBaseEntry) -> str:
    return hashlib.sha256((prev + _payload(e)).encode()).hexdigest()


def _chained(db: Session) -> list:
    return (db.query(KnowledgeBaseEntry)
            .filter(KnowledgeBaseEntry.audit_seq.isnot(None))
            .order_by(KnowledgeBaseEntry.audit_seq).all())


def append(db: Session, entry: KnowledgeBaseEntry) -> None:
    """Link a new human-decided entry onto the chain. Call after the entry's
    fields are final and it has an id (after db.flush())."""
    last = (db.query(KnowledgeBaseEntry).filter(KnowledgeBaseEntry.audit_seq.isnot(None))
            .order_by(KnowledgeBaseEntry.audit_seq.desc()).first())
    entry.audit_seq = (last.audit_seq + 1) if last else 1
    entry.audit_prev_hash = last.audit_hash if last else GENESIS
    entry.audit_hash = _digest(entry.audit_prev_hash, entry)


def verify(db: Session) -> dict:
    prev = GENESIS
    entries = _chained(db)
    for n, e in enumerate(entries, start=1):
        if e.audit_seq != n:
            return {"ok": False, "entries": len(entries), "broken_at": n, "reason": "a decision is missing"}
        if e.audit_prev_hash != prev or e.audit_hash != _digest(prev, e):
            return {"ok": False, "entries": len(entries), "broken_at": n, "entry_id": e.id,
                    "reason": "a recorded decision was changed after it was made"}
        prev = e.audit_hash
    return {"ok": True, "entries": len(entries), "head": prev}
