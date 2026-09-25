"""Loads Tier-1 seed KB entries (backend/app/seeds/*.yaml) - the deterministic
"known vendor syntax" layer described in architecture-document.md §1/§3 step
4, which had never actually been wired up before 2026-09-15 (see each seed
file's header comment for how that gap was found). Same idempotent-on-startup
shape as rules_loader.py's load_rule_files.
"""
import glob
import os

import yaml
from sqlalchemy.orm import Session

from .models import KnowledgeBaseEntry

_SEEDS_DIR = os.path.join(os.path.dirname(__file__), "seeds")


def load_seed_kb(db: Session, tenant_id: str = "default") -> int:
    loaded = 0
    for path in sorted(glob.glob(os.path.join(_SEEDS_DIR, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        vendor = doc["vendor"]
        for e in doc["entries"]:
            # "regex" entries match a whole family of lines deterministically
            # (e.g. every numbered ACL line); `value` may be omitted for a
            # list field, meaning "the matched line itself" (resolve.py).
            pattern_type = e.get("pattern_type", "exact")
            existing = (
                db.query(KnowledgeBaseEntry)
                .filter(
                    KnowledgeBaseEntry.tenant_id == tenant_id,
                    KnowledgeBaseEntry.vendor == vendor,
                    KnowledgeBaseEntry.pattern_type == pattern_type,
                    KnowledgeBaseEntry.syntax_pattern == e["syntax_pattern"],
                )
                .first()
            )
            fields = dict(
                canonical_field=e["canonical_field"],
                value=e.get("value"),
                confidence=1.0,
            )
            if existing:
                for k, v in fields.items():
                    setattr(existing, k, v)
            else:
                db.add(
                    KnowledgeBaseEntry(
                        tenant_id=tenant_id,
                        vendor=vendor,
                        pattern_type=pattern_type,
                        syntax_pattern=e["syntax_pattern"],
                        source="tier1_seed",
                        **fields,
                    )
                )
                loaded += 1
    db.commit()
    return loaded
