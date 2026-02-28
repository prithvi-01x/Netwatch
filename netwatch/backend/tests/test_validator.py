"""
tests/test_validator.py

Tests for llm/validator.py — LLM output parsing, JSON extraction,
schema validation, enum clamping, and field truncation.
"""

from __future__ import annotations

import json

import pytest

from netwatch.backend.llm.validator import validate_llm_response
from netwatch.backend.llm.models import LLMExplanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_json(**overrides) -> str:
    data = {
        "summary": "A port scan was detected from the source host.",
        "severity_reasoning": "Scanning precedes exploitation.",
        "recommended_action": "Block the source IP at the firewall.",
        "ioc_tags": ["port-scan", "reconnaissance"],
        "llm_confidence": "HIGH",
        "attack_phase": "reconnaissance",
    }
    data.update(overrides)
    return json.dumps(data)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestValidatorHappyPath:

    def test_valid_json_returns_explanation(self):
        result = validate_llm_response(_valid_json())
        assert isinstance(result, LLMExplanation)

    def test_summary_populated(self):
        result = validate_llm_response(_valid_json())
        assert result.summary == "A port scan was detected from the source host."

    def test_severity_reasoning_populated(self):
        result = validate_llm_response(_valid_json())
        assert result.severity_reasoning == "Scanning precedes exploitation."

    def test_recommended_action_populated(self):
        result = validate_llm_response(_valid_json())
        assert result.recommended_action == "Block the source IP at the firewall."

    def test_ioc_tags_populated(self):
        result = validate_llm_response(_valid_json())
        assert "port-scan" in result.ioc_tags
        assert "reconnaissance" in result.ioc_tags

    def test_llm_confidence_populated(self):
        result = validate_llm_response(_valid_json())
        assert result.llm_confidence == "HIGH"

    def test_attack_phase_populated(self):
        result = validate_llm_response(_valid_json())
        assert result.attack_phase == "reconnaissance"

    def test_fallback_used_is_false(self):
        result = validate_llm_response(_valid_json())
        assert result.fallback_used is False


# ---------------------------------------------------------------------------
# Markdown fence stripping
# ---------------------------------------------------------------------------

class TestMarkdownFenceStripping:

    def test_strips_json_fence(self):
        raw = f"```json\n{_valid_json()}\n```"
        result = validate_llm_response(raw)
        assert result is not None

    def test_strips_plain_fence(self):
        raw = f"```\n{_valid_json()}\n```"
        result = validate_llm_response(raw)
        assert result is not None

    def test_ignores_preamble_text(self):
        raw = f"Here is my analysis:\n{_valid_json()}\nDone."
        result = validate_llm_response(raw)
        assert result is not None


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

class TestValidatorMalformedInput:

    def test_empty_string_returns_none(self):
        assert validate_llm_response("") is None

    def test_whitespace_only_returns_none(self):
        assert validate_llm_response("   \n  ") is None

    def test_invalid_json_returns_none(self):
        assert validate_llm_response("{not valid json}") is None

    def test_json_array_instead_of_dict_returns_none(self):
        assert validate_llm_response('["a", "b"]') is None

    def test_missing_summary_returns_none(self):
        data = json.loads(_valid_json())
        del data["summary"]
        assert validate_llm_response(json.dumps(data)) is None

    def test_missing_severity_reasoning_returns_none(self):
        data = json.loads(_valid_json())
        del data["severity_reasoning"]
        assert validate_llm_response(json.dumps(data)) is None

    def test_missing_recommended_action_returns_none(self):
        data = json.loads(_valid_json())
        del data["recommended_action"]
        assert validate_llm_response(json.dumps(data)) is None

    def test_empty_summary_returns_none(self):
        assert validate_llm_response(_valid_json(summary="")) is None

    def test_plain_text_no_json_returns_none(self):
        assert validate_llm_response("This is a port scan, block it.") is None


# ---------------------------------------------------------------------------
# Enum clamping
# ---------------------------------------------------------------------------

class TestValidatorEnumClamping:

    def test_invalid_confidence_clamped_to_uncertain(self):
        result = validate_llm_response(_valid_json(llm_confidence="EXTREME"))
        assert result is not None
        assert result.llm_confidence == "UNCERTAIN"

    def test_confidence_case_insensitive(self):
        result = validate_llm_response(_valid_json(llm_confidence="high"))
        assert result is not None
        assert result.llm_confidence == "HIGH"

    def test_invalid_attack_phase_clamped_to_unknown(self):
        result = validate_llm_response(_valid_json(attack_phase="space-invasion"))
        assert result is not None
        assert result.attack_phase == "unknown"

    def test_all_valid_confidences_accepted(self):
        for conf in ("HIGH", "MEDIUM", "LOW", "UNCERTAIN"):
            result = validate_llm_response(_valid_json(llm_confidence=conf))
            assert result.llm_confidence == conf

    def test_all_valid_attack_phases_accepted(self):
        phases = ["reconnaissance", "initial-access", "lateral-movement",
                  "exfiltration", "c2", "unknown"]
        for phase in phases:
            result = validate_llm_response(_valid_json(attack_phase=phase))
            assert result.attack_phase == phase


# ---------------------------------------------------------------------------
# IOC tags sanitization
# ---------------------------------------------------------------------------

class TestValidatorIocTags:

    def test_tags_capped_at_8(self):
        tags = [f"tag{i}" for i in range(15)]
        result = validate_llm_response(_valid_json(ioc_tags=tags))
        assert result is not None
        assert len(result.ioc_tags) <= 8

    def test_tags_truncated_to_50_chars(self):
        long_tag = "a" * 100
        result = validate_llm_response(_valid_json(ioc_tags=[long_tag]))
        assert result is not None
        assert all(len(t) <= 50 for t in result.ioc_tags)

    def test_non_list_tags_treated_as_empty(self):
        result = validate_llm_response(_valid_json(ioc_tags="not-a-list"))
        assert result is not None
        assert result.ioc_tags == []

    def test_missing_tags_defaults_to_empty(self):
        data = json.loads(_valid_json())
        del data["ioc_tags"]
        result = validate_llm_response(json.dumps(data))
        assert result is not None
        assert result.ioc_tags == []