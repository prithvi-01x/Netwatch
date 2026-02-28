"""
engine/rules/base.py

Abstract base class that all detection rules must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity


class BaseRule(ABC):
    """
    Contract that every detection rule must satisfy.

    Class-level attributes:
        name     — unique snake_case identifier used in Alert.rule_name
        severity — default Severity; rules may override per-result
        enabled  — False for stubs not yet implemented

    The analyze() method MUST:
        - Never raise an exception (catch internally, return non-triggered result)
        - Complete in < 50 ms
        - Return only JSON-serializable types in evidence
    """

    name: str = ""
    severity: Severity = Severity.LOW
    enabled: bool = True

    @abstractmethod
    def analyze(self, window: AggregatedWindow) -> RuleResult:
        """
        Analyze an aggregated window and return a RuleResult.

        Must never raise — catch all exceptions internally.
        """
        ...

    def __repr__(self) -> str:
        return f"<Rule:{self.name} enabled={self.enabled}>"
