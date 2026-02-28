"""
engine/models.py

Data models for Phase 3 — Detection Engine.

Severity  — 4-level enum used in Alert and BaseRule
RuleResult — returned by every rule's analyze() method
Alert      — emitted when a rule fires above the confidence threshold
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# RuleResult — lightweight return value from every rule.analyze() call
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RuleResult:
    """
    Return value of BaseRule.analyze().

    Rules must NEVER raise — catch internally and return a non-triggered result.
    Evidence must contain only JSON-serializable types (str, int, float, list, dict).
    """

    triggered: bool
    confidence: float       # 0.0 … 1.0
    evidence: dict[str, Any]
    description: str

    def __repr__(self) -> str:
        return (
            f"RuleResult(triggered={self.triggered} "
            f"conf={self.confidence:.2f} desc={self.description!r})"
        )


# ---------------------------------------------------------------------------
# Alert — emitted when a rule fires above the engine's confidence threshold
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    Threat alert produced by the detection engine.

    Created when a RuleResult.triggered is True AND
    RuleResult.confidence >= DetectionEngine.confidence_threshold.
    """

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """Unique UUID4 identifier."""

    timestamp: float = field(default_factory=time.time)
    """Wall-clock time at alert creation."""

    rule_name: str = ""
    """Identifier matching the rule that fired, e.g. 'port_scan'."""

    severity: Severity = Severity.LOW

    confidence: float = 0.0
    """Confidence from the underlying RuleResult [0.0, 1.0]."""

    src_ip: str = ""
    """Primary source IP involved in the suspicious activity."""

    dst_ip: str = "multiple"
    """Primary destination IP, or 'multiple' when many are involved."""

    evidence: dict[str, Any] = field(default_factory=dict)
    """Rule-specific JSON-serializable evidence."""

    description: str = ""
    """One-sentence human-readable summary from the rule."""

    window_start: float = 0.0
    window_end: float = 0.0
    window_size_seconds: int = 0

    def __repr__(self) -> str:
        return (
            f"Alert({self.rule_name!r} {self.severity.value} "
            f"conf={self.confidence:.2f} src={self.src_ip!r})"
        )
