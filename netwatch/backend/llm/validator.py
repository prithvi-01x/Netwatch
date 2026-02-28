"""
llm/validator.py

Validates and parses the raw text output from the LLM into an LLMExplanation.

If the model returns malformed JSON, wraps output in markdown fences,
or produces values outside the allowed schema, the response is rejected
and the caller falls back to a static explanation.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Literal

from .models import LLMExplanation

logger = logging.getLogger(__name__)

_VALID_CONFIDENCE: frozenset[str] = frozenset({"HIGH", "MEDIUM", "LOW", "UNCERTAIN"})
_VALID_ATTACK_PHASES: frozenset[str] = frozenset({
    "reconnaissance", "initial-access", "lateral-movement",
    "exfiltration", "c2", "unknown",
})
_MAX_FIELD_LEN = 500
_MAX_TAGS = 8
_MAX_TAG_LEN = 50


def validate_llm_response(raw_text: str) -> LLMExplanation | None:
    """
    Parse and validate raw LLM output into an LLMExplanation.

    Returns None if the output is malformed or fails schema validation.
    The caller is responsible for using a fallback in that case.
    """
    if not raw_text or not raw_text.strip():
        logger.warning("LLM returned empty response")
        return None

    text = raw_text.strip()

    # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
    fence_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence_match:
        text = fence_match.group(1)

    # Find the first {...} block in case there's preamble text
    brace_match = re.search(r"\{[\s\S]+\}", text)
    if brace_match:
        text = brace_match.group(0)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("LLM output is not valid JSON: %s | raw=%r", exc, raw_text[:200])
        return None

    if not isinstance(data, dict):
        logger.warning("LLM output parsed but is not a dict: %r", type(data))
        return None

    # Required fields
    summary = _get_str(data, "summary")
    severity_reasoning = _get_str(data, "severity_reasoning")
    recommended_action = _get_str(data, "recommended_action")
    if not summary or not severity_reasoning or not recommended_action:
        logger.warning("LLM output missing required fields: %r", list(data.keys()))
        return None

    # IOC tags — list of short strings
    raw_tags = data.get("ioc_tags", [])
    if not isinstance(raw_tags, list):
        raw_tags = []
    ioc_tags = [
        str(t)[:_MAX_TAG_LEN]
        for t in raw_tags[:_MAX_TAGS]
        if isinstance(t, (str, int))
    ]

    # Enum fields — fall back to safe defaults if invalid
    llm_confidence = str(data.get("llm_confidence", "UNCERTAIN")).upper()
    if llm_confidence not in _VALID_CONFIDENCE:
        llm_confidence = "UNCERTAIN"

    attack_phase = str(data.get("attack_phase", "unknown")).lower()
    if attack_phase not in _VALID_ATTACK_PHASES:
        attack_phase = "unknown"

    return LLMExplanation(
        summary=summary,
        severity_reasoning=severity_reasoning,
        recommended_action=recommended_action,
        ioc_tags=ioc_tags,
        attack_phase=attack_phase,
        llm_confidence=llm_confidence,  # type: ignore[arg-type]
        fallback_used=False,
    )


def _get_str(data: dict, key: str) -> str:
    """Extract a string field, truncating to _MAX_FIELD_LEN. Returns '' if missing."""
    val = data.get(key, "")
    if not isinstance(val, str):
        val = str(val)
    return val.strip()[:_MAX_FIELD_LEN]
