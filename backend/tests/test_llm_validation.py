"""Tier-2 output is untrusted until it passes schema validation; anything
rejected routes to Tier 3 instead of silently corrupting a finding."""
import pytest

from app.llm_client import _extract_json, _validate


def _resp(field, value, confidence=0.9):
    return {"canonical_field": field, "value": value, "confidence": confidence, "reasoning": "r"}


def test_valid_response_is_accepted():
    assert _validate(_resp("AC.telnet_enabled", False))["value"] is False


@pytest.mark.parametrize("raw", [
    _resp("Logging and Monitoring", True),      # invented field name (real Gemini bug)
    _resp("AC.telnet_enabled", True, 1.5),       # confidence out of range
    {"canonical_field": "AC.telnet_enabled"},    # missing keys
    "not a dict",
])
def test_malformed_or_hallucinated_is_rejected(raw):
    assert _validate(raw) is None


@pytest.mark.parametrize("raw", [
    _resp("SC.webgui_protocol", "https"),   # boolean field, descriptive string (pfSense bug)
    _resp("IA.ssh_version", True),          # numeric field, boolean (sshdkeyonly bug)
    _resp("IA.ssh_version", "2"),           # numeric field, string
    _resp("AC.privileged_password_type", 9),  # string field, number
])
def test_value_type_must_match_field_kind(raw):
    assert _validate(raw) is None


def test_unknown_passes_with_any_value():
    assert _validate(_resp("UNKNOWN", None, 0.1)) is not None


def test_json_is_extracted_from_surrounding_prose():
    assert _extract_json('Sure! {"canonical_field": "UNKNOWN", "value": null} done') == {
        "canonical_field": "UNKNOWN", "value": None,
    }
    assert _extract_json("no json here") is None
