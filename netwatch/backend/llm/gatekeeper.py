"""
llm/gatekeeper.py

LLMGatekeeper — decides whether an alert should be sent to the LLM.

Checks (in order):
  1. Cache hit  → skip LLM, use cached explanation
  2. Severity   → LOW alerts skipped by default
  3. Confidence → below min_confidence threshold → skip
  4. Rate limit → max N calls per minute (sliding window)
  5. Cooldown   → 30s per (src_ip, rule) pair to prevent hammering
"""

from __future__ import annotations

import logging
import time
from collections import deque

from .cache import ExplanationCache

logger = logging.getLogger(__name__)


class LLMGatekeeper:
    """
    Guards the LLM from being called too frequently or unnecessarily.

    All decision logic is synchronous and fast (no I/O).
    """

    def __init__(
        self,
        min_confidence: float = 0.5,
        required_severities: frozenset[str] = frozenset({"MEDIUM", "HIGH", "CRITICAL"}),
        max_calls_per_minute: int = 10,
        cooldown_seconds: int = 30,
    ) -> None:
        self.min_confidence = min_confidence
        self.required_severities = required_severities
        self.max_calls_per_minute = max_calls_per_minute
        self.cooldown_seconds = cooldown_seconds

        # Sliding window: timestamps of recent LLM calls
        self._call_times: deque[float] = deque()
        # Per (src_ip, rule_name) → last called timestamp
        self._cooldowns: dict[str, float] = {}

    def should_call(
        self, alert_dict: dict, cache: ExplanationCache
    ) -> tuple[bool, str]:
        """
        Return (should_call, reason_string).

        Reasons for skipping: CACHE_HIT, LOW_SEVERITY, LOW_CONFIDENCE,
                              RATE_LIMITED, COOLDOWN.
        Reason for calling:   APPROVED.
        """
        # 1. Cache check
        if cache.get(alert_dict) is not None:
            return False, "CACHE_HIT"

        # 2. Severity filter
        severity = str(alert_dict.get("severity", "")).upper()
        if severity not in self.required_severities:
            return False, "LOW_SEVERITY"

        # 3. Confidence threshold
        confidence = float(alert_dict.get("confidence", 0))
        if confidence < self.min_confidence:
            return False, "LOW_CONFIDENCE"

        now = time.time()

        # 4. Rate limit: sliding 60s window
        self._call_times = deque(
            t for t in self._call_times if now - t < 60.0
        )
        if len(self._call_times) >= self.max_calls_per_minute:
            logger.warning(
                "LLM rate limit reached (%d calls/min)", self.max_calls_per_minute
            )
            return False, "RATE_LIMITED"

        # 5. Per-source cooldown
        cooldown_key = f"{alert_dict.get('src_ip', '')}:{alert_dict.get('rule_name', '')}"
        last_called = self._cooldowns.get(cooldown_key, 0.0)
        if now - last_called < self.cooldown_seconds:
            return False, "COOLDOWN"

        # Approved — record this call
        self._call_times.append(now)
        self._cooldowns[cooldown_key] = now
        return True, "APPROVED"
