"""Loads rule YAML files (backend/app/rules/*.yaml) into the Rule table.

A framework revision is a new/updated YAML file, not a code change
(architecture-document.md §3 step 6). Idempotent: re-running on an existing
DB updates rules already seeded from the same (framework, standard_version)
rather than duplicating them, so this is safe to call on every startup.
"""
import glob
import os

import yaml
from sqlalchemy.orm import Session

from .models import Rule

_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_rule_files(db: Session) -> int:
    loaded = 0
    for path in sorted(glob.glob(os.path.join(_RULES_DIR, "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        framework = doc["framework"]
        standard_version = doc["standard_version"]
        applies_to_vendors = doc.get("applies_to_vendors")  # None = vendor-neutral
        for r in doc["rules"]:
            existing = (
                db.query(Rule)
                .filter(
                    Rule.standard_ref == r["id"],
                    Rule.standard_version == standard_version,
                    Rule.framework == framework,
                )
                .first()
            )
            fields = dict(
                standard_ref=r["id"],
                standard_version=standard_version,
                control_family=r["control_family"],
                check_type=r["check_type"],
                predicate=r["predicate"],
                severity=r["severity"],
                remediation_template_ref=r.get("remediation_template_ref"),
                framework=framework,
                title=r.get("title"),
                applies_to_vendors=applies_to_vendors,
            )
            if existing:
                for k, v in fields.items():
                    setattr(existing, k, v)
            else:
                db.add(Rule(**fields))
                loaded += 1
    db.commit()
    return loaded
