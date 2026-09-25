from typing import Optional
from pydantic import BaseModel


class ConfirmMapping(BaseModel):
    canonical_field: str
    value: object = None
    reviewer_id: str
    pattern_type: str = "exact"  # "exact" | "regex"
    syntax_pattern: Optional[str] = None  # defaults to the queue item's raw_unit
    is_security_relevant: Optional[bool] = None
    reviewer_notes: Optional[str] = None


class RejectMapping(BaseModel):
    reviewer_id: str
    reason: Optional[str] = None
    reviewer_notes: Optional[str] = None
