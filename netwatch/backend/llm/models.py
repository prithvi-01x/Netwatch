"""
llm/models.py

Data models for the LLM integration layer (Phase 5).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class LLMExplanation:
    """
    Structured explanation returned by the LLM (or fallback) for an alert.

    All fields are plain strings/lists — safe to serialise to JSON and
    broadcast over WebSocket without further processing.
    """

    summary: str
    """1–2 sentence plain-English explanation of what was detected."""

    severity_reasoning: str
    """Why this severity level was assigned."""

    recommended_action: str
    """One specific, actionable response step."""

    ioc_tags: list[str] = field(default_factory=list)
    """e.g. ['port-scan', 'reconnaissance', 'automated-tool']"""

    attack_phase: str = "unknown"
    """MITRE ATT&CK-style phase: reconnaissance | initial-access |
    lateral-movement | exfiltration | c2 | unknown"""

    llm_confidence: Literal["HIGH", "MEDIUM", "LOW", "UNCERTAIN"] = "LOW"
    """Model's self-reported confidence in the explanation."""

    fallback_used: bool = False
    """True if LLM was unavailable and a static fallback was returned."""

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "severity_reasoning": self.severity_reasoning,
            "recommended_action": self.recommended_action,
            "ioc_tags": self.ioc_tags,
            "attack_phase": self.attack_phase,
            "llm_confidence": self.llm_confidence,
            "fallback_used": self.fallback_used,
        }
