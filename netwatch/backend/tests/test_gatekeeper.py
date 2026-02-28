"""
tests/test_gatekeeper.py

Tests for llm/gatekeeper.py — LLMGatekeeper decision logic.
Covers cache hits, severity filter, confidence threshold, rate limiting,
and per-source cooldown.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatch.backend.llm.cache import ExplanationCache
from netwatch.backend.llm.gatekeeper import LLMGatekeeper
from netwatch.backend.llm.models import LLMExplanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(
    rule="port_scan",
    src="1.2.3.4",
    severity="HIGH",
    confidence=0.75,
) -> dict:
    return {"rule_name": rule, "src_ip": src, "severity": severity, "confidence": confidence}


def _expl() -> LLMExplanation:
    return LLMExplanation(
        summary="s", severity_reasoning="r", recommended_action="a",
        attack_phase="reconnaissance", llm_confidence="MEDIUM",
    )


def _gatekeeper(**kwargs) -> LLMGatekeeper:
    defaults = dict(
        min_confidence=0.5,
        required_severities=frozenset({"MEDIUM", "HIGH", "CRITICAL"}),
        max_calls_per_minute=10,
        cooldown_seconds=30,
    )
    defaults.update(kwargs)
    return LLMGatekeeper(**defaults)


def _empty_cache() -> ExplanationCache:
    return ExplanationCache()


def _cache_with(alert: dict) -> ExplanationCache:
    c = ExplanationCache()
    c.put(alert, _expl())
    return c


# ---------------------------------------------------------------------------
# Cache hit check
# ---------------------------------------------------------------------------

class TestGatekeeperCacheHit:

    def test_cache_hit_returns_false_with_reason(self):
        alert = _alert()
        gk = _gatekeeper()
        should_call, reason = gk.should_call(alert, _cache_with(alert))
        assert should_call is False
        assert reason == "CACHE_HIT"

    def test_cache_miss_does_not_short_circuit(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(), _empty_cache())
        # Will pass cache check — reason will be APPROVED or something else
        assert reason != "CACHE_HIT"


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

class TestGatekeeperSeverity:

    def test_low_severity_is_rejected(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(severity="LOW"), _empty_cache())
        assert should_call is False
        assert reason == "LOW_SEVERITY"

    def test_medium_severity_passes(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(severity="MEDIUM"), _empty_cache())
        assert reason != "LOW_SEVERITY"

    def test_high_severity_passes(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(severity="HIGH"), _empty_cache())
        assert reason != "LOW_SEVERITY"

    def test_critical_severity_passes(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(severity="CRITICAL"), _empty_cache())
        assert reason != "LOW_SEVERITY"

    def test_severity_check_is_case_insensitive(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(severity="high"), _empty_cache())
        assert reason != "LOW_SEVERITY"


# ---------------------------------------------------------------------------
# Confidence threshold
# ---------------------------------------------------------------------------

class TestGatekeeperConfidence:

    def test_below_threshold_is_rejected(self):
        gk = _gatekeeper(min_confidence=0.6)
        should_call, reason = gk.should_call(_alert(confidence=0.4), _empty_cache())
        assert should_call is False
        assert reason == "LOW_CONFIDENCE"

    def test_at_threshold_passes(self):
        gk = _gatekeeper(min_confidence=0.5)
        should_call, reason = gk.should_call(_alert(confidence=0.5), _empty_cache())
        assert reason != "LOW_CONFIDENCE"

    def test_above_threshold_passes(self):
        gk = _gatekeeper(min_confidence=0.5)
        should_call, reason = gk.should_call(_alert(confidence=0.9), _empty_cache())
        assert reason != "LOW_CONFIDENCE"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestGatekeeperRateLimit:

    def test_within_rate_limit_is_approved(self):
        gk = _gatekeeper(max_calls_per_minute=5, cooldown_seconds=0)
        cache = _empty_cache()
        for i in range(5):
            alert = _alert(src=f"10.0.0.{i}")
            should_call, reason = gk.should_call(alert, cache)
            assert should_call is True, f"Call {i} should be approved, got {reason}"

    def test_exceeding_rate_limit_is_rejected(self):
        gk = _gatekeeper(max_calls_per_minute=3, cooldown_seconds=0)
        cache = _empty_cache()
        for i in range(3):
            gk.should_call(_alert(src=f"10.0.0.{i}"), cache)
        # 4th call should be rate limited
        should_call, reason = gk.should_call(_alert(src="10.0.0.99"), cache)
        assert should_call is False
        assert reason == "RATE_LIMITED"

    def test_rate_limit_resets_after_window(self):
        gk = _gatekeeper(max_calls_per_minute=2, cooldown_seconds=0)
        cache = _empty_cache()
        now = time.time()

        # Fill the rate limit with old timestamps (>60s ago)
        gk._call_times.extend([now - 70, now - 65])

        # Now a new call should pass (old timestamps expired)
        should_call, reason = gk.should_call(_alert(), cache)
        assert should_call is True


# ---------------------------------------------------------------------------
# Cooldown
# ---------------------------------------------------------------------------

class TestGatekeeperCooldown:

    def test_same_src_and_rule_within_cooldown_is_rejected(self):
        gk = _gatekeeper(cooldown_seconds=30)
        cache = _empty_cache()
        alert = _alert()
        gk.should_call(alert, cache)  # first call records timestamp
        should_call, reason = gk.should_call(alert, cache)
        assert should_call is False
        assert reason == "COOLDOWN"

    def test_different_src_ip_bypasses_cooldown(self):
        gk = _gatekeeper(cooldown_seconds=30)
        cache = _empty_cache()
        gk.should_call(_alert(src="1.1.1.1"), cache)
        should_call, reason = gk.should_call(_alert(src="2.2.2.2"), cache)
        assert should_call is True

    def test_different_rule_bypasses_cooldown(self):
        gk = _gatekeeper(cooldown_seconds=30)
        cache = _empty_cache()
        gk.should_call(_alert(rule="port_scan"), cache)
        should_call, reason = gk.should_call(_alert(rule="syn_flood"), cache)
        assert should_call is True

    def test_cooldown_expires(self):
        gk = _gatekeeper(cooldown_seconds=30)
        cache = _empty_cache()
        alert = _alert()
        cooldown_key = f"{alert['src_ip']}:{alert['rule_name']}"
        # Simulate the last call was 60s ago
        gk._cooldowns[cooldown_key] = time.time() - 60
        should_call, reason = gk.should_call(alert, cache)
        assert should_call is True


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestGatekeeperApproved:

    def test_approved_returns_true_with_reason(self):
        gk = _gatekeeper()
        should_call, reason = gk.should_call(_alert(), _empty_cache())
        assert should_call is True
        assert reason == "APPROVED"

    def test_approved_records_call_time(self):
        gk = _gatekeeper()
        assert len(gk._call_times) == 0
        gk.should_call(_alert(), _empty_cache())
        assert len(gk._call_times) == 1

    def test_approved_records_cooldown(self):
        gk = _gatekeeper()
        alert = _alert()
        gk.should_call(alert, _empty_cache())
        key = f"{alert['src_ip']}:{alert['rule_name']}"
        assert key in gk._cooldowns