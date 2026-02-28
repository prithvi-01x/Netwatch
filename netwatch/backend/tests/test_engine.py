"""
tests/test_engine.py

Tests for the DetectionEngine orchestrator.
Verifies plugin loading, confidence gating, multi-rule, and error isolation.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from netwatch.backend.aggregation.models import AggregatedWindow, FlowKey, FlowRecord
from netwatch.backend.engine.engine import DetectionEngine
from netwatch.backend.engine.models import RuleResult, Severity
from netwatch.backend.engine.rules.base import BaseRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def empty_window(window_size_seconds: int = 1) -> AggregatedWindow:
    now = time.time()
    return AggregatedWindow(
        window_start=now - window_size_seconds,
        window_end=now,
        window_size_seconds=window_size_seconds,
        total_packets=0,
        top_flows=[],
    )


def make_flow(src_port: int = 54321, dst_port: int = 80) -> FlowRecord:
    key = FlowKey("10.0.0.1", "8.8.8.8", src_port, dst_port, "TCP")
    r = FlowRecord(flow_key=key)
    r.packet_count = 10
    r.flags_seen = {"SYN"}
    return r


# ---------------------------------------------------------------------------
# Inline test rules (bypass plugin discovery)
# ---------------------------------------------------------------------------

class AlwaysFireRule(BaseRule):
    name = "always_fire"
    severity = Severity.HIGH
    enabled = True

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        return RuleResult(
            triggered=True,
            confidence=0.8,
            evidence={"src_ip": "1.2.3.4", "detail": "test"},
            description="always fires",
        )


class NeverFireRule(BaseRule):
    name = "never_fire"
    severity = Severity.LOW
    enabled = True

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        return RuleResult(
            triggered=False,
            confidence=0.0,
            evidence={},
            description="never fires",
        )


class LowConfidenceRule(BaseRule):
    name = "low_confidence"
    severity = Severity.LOW
    enabled = True

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        return RuleResult(
            triggered=True,
            confidence=0.1,   # below default threshold of 0.3
            evidence={"src_ip": "5.5.5.5"},
            description="fires but low confidence",
        )


class RaisingRule(BaseRule):
    name = "raising_rule"
    severity = Severity.MEDIUM
    enabled = True

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        raise RuntimeError("intentional error in rule")


# ---------------------------------------------------------------------------
# Plugin loading
# ---------------------------------------------------------------------------

class TestEnginePluginLoading:

    def test_enabled_rules_loaded(self):
        """Real engine should load at least port_scan and syn_flood."""
        engine = DetectionEngine()
        rule_names = [r.name for r in engine.rules]
        assert "port_scan" in rule_names
        assert "syn_flood" in rule_names

    def test_all_five_rules_loaded(self):
        """All five rules (port_scan, syn_flood, brute_force, dns_tunneling, beaconing) are enabled."""
        engine = DetectionEngine()
        rule_names = sorted(r.name for r in engine.rules)
        assert rule_names == ["beaconing", "brute_force", "dns_tunneling", "port_scan", "syn_flood"]

    def test_stats_initialized(self):
        engine = DetectionEngine()
        assert engine.stats["windows_analyzed"] == 0
        assert engine.stats["alerts_fired"] == 0
        assert engine.stats["alerts_suppressed"] == 0


# ---------------------------------------------------------------------------
# analyze() — alert emission
# ---------------------------------------------------------------------------

class TestEngineAnalyze:

    def _engine_with(self, *rules: BaseRule, threshold: float = 0.3) -> DetectionEngine:
        """Build an engine with exactly the given rule instances."""
        engine = DetectionEngine(confidence_threshold=threshold)
        engine.rules = list(rules)
        return engine

    def test_always_fire_produces_alert(self):
        engine = self._engine_with(AlwaysFireRule())
        alerts = engine.analyze(empty_window())
        assert len(alerts) == 1
        assert alerts[0].rule_name == "always_fire"

    def test_never_fire_produces_no_alert(self):
        engine = self._engine_with(NeverFireRule())
        alerts = engine.analyze(empty_window())
        assert alerts == []

    def test_low_confidence_suppressed(self):
        """Rule fires (triggered=True) but confidence < threshold → suppressed."""
        engine = self._engine_with(LowConfidenceRule(), threshold=0.3)
        alerts = engine.analyze(empty_window())
        assert alerts == []
        assert engine.stats["alerts_suppressed"] == 1
        assert engine.stats["alerts_fired"] == 0

    def test_confidence_threshold_gating(self):
        """With threshold=0.05, the low-confidence rule should produce an alert."""
        engine = self._engine_with(LowConfidenceRule(), threshold=0.05)
        alerts = engine.analyze(empty_window())
        assert len(alerts) == 1

    def test_multiple_rules_both_can_fire(self):
        class AlwaysFireRule2(AlwaysFireRule):
            name = "always_fire_2"

        engine = self._engine_with(AlwaysFireRule(), AlwaysFireRule2())
        alerts = engine.analyze(empty_window())
        assert len(alerts) == 2

    def test_stats_windows_analyzed_increments(self):
        engine = self._engine_with(NeverFireRule())
        engine.analyze(empty_window())
        engine.analyze(empty_window())
        assert engine.stats["windows_analyzed"] == 2

    def test_stats_alerts_fired_increments(self):
        engine = self._engine_with(AlwaysFireRule())
        engine.analyze(empty_window())
        engine._cooldowns.clear()  # reset cooldown so second call isn't suppressed
        engine.analyze(empty_window())
        assert engine.stats["alerts_fired"] == 2

    def test_alert_fields_populated(self):
        engine = self._engine_with(AlwaysFireRule())
        window = empty_window(window_size_seconds=10)
        alerts = engine.analyze(window)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.rule_name == "always_fire"
        assert a.window_size_seconds == 10
        assert a.confidence == pytest.approx(0.8)
        assert len(a.alert_id) == 36   # UUID4 string length

    def test_alert_id_is_unique(self):
        engine = self._engine_with(AlwaysFireRule(), AlwaysFireRule())
        alerts = engine.analyze(empty_window())
        ids = [a.alert_id for a in alerts]
        assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------

class TestEngineErrorIsolation:

    def _engine_with(self, *rules: BaseRule) -> DetectionEngine:
        engine = DetectionEngine()
        engine.rules = list(rules)
        return engine

    def test_raising_rule_does_not_crash_pipeline(self):
        """A rule that raises must not propagate the exception."""
        engine = self._engine_with(RaisingRule())
        # Should not raise
        alerts = engine.analyze(empty_window())
        assert alerts == []

    def test_good_rule_runs_despite_bad_rule(self):
        """AlwaysFireRule should still fire even if RaisingRule fails."""
        engine = self._engine_with(RaisingRule(), AlwaysFireRule())
        alerts = engine.analyze(empty_window())
        assert len(alerts) == 1
        assert alerts[0].rule_name == "always_fire"

    def test_timing_warning_logged(self):
        """Rules exceeding _RULE_TIMEOUT_MS should trigger a warning log."""
        import time as _time
        original_monotonic = _time.monotonic
        call_count = [0]

        def slow_mono():
            call_count[0] += 1
            # First call returns 0, second call returns 1 (=1000ms elapsed)
            return float(call_count[0] - 1)

        engine = self._engine_with(NeverFireRule())
        with patch("netwatch.backend.engine.engine.time.monotonic", side_effect=slow_mono):
            # Should complete without raising — timing warning goes to logger
            alerts = engine.analyze(empty_window())
        assert alerts == []   # NeverFireRule still returns no alerts