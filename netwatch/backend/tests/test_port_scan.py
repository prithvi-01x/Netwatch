"""
tests/test_port_scan.py

Tests for engine/rules/port_scan.py.
Builds minimal AggregatedWindow / FlowRecord objects to drive the rule.
"""

from __future__ import annotations

import time

import pytest

from netwatch.backend.aggregation.models import AggregatedWindow, FlowKey, FlowRecord
from netwatch.backend.engine.models import Severity
from netwatch.backend.engine.rules.port_scan import PortScanRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_window(
    top_flows: list[FlowRecord],
    window_size_seconds: int = 1,
) -> AggregatedWindow:
    now = time.time()
    return AggregatedWindow(
        window_start=now - window_size_seconds,
        window_end=now,
        window_size_seconds=window_size_seconds,
        total_packets=sum(f.packet_count for f in top_flows),
        top_flows=top_flows,
    )


def make_flow(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str = "TCP",
    packet_count: int = 1,
    flags: set[str] | None = None,
) -> FlowRecord:
    key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
    r = FlowRecord(flow_key=key)
    r.packet_count = packet_count
    r.byte_count = packet_count * 64
    r.flags_seen = flags or {"SYN"}
    return r


def scanning_flows(src_ip: str, n_ports: int) -> list[FlowRecord]:
    """n_ports flows from src_ip each to a distinct destination port."""
    return [
        make_flow(src_ip, "192.168.0.1", 54321, dst_port)
        for dst_port in range(1, n_ports + 1)
    ]


# ---------------------------------------------------------------------------
# Below-threshold — no alert
# ---------------------------------------------------------------------------

class TestPortScanBelowThreshold:

    def test_no_flows_no_trigger(self):
        rule = PortScanRule()
        window = make_window([])
        result = rule.analyze(window)
        assert result.triggered is False

    def test_single_flow_no_trigger(self):
        rule = PortScanRule()
        window = make_window([make_flow("10.0.0.1", "8.8.8.8", 54000, 443)])
        result = rule.analyze(window)
        assert result.triggered is False

    def test_below_1s_threshold_no_trigger(self):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        # 14 ports — just below threshold
        window = make_window(scanning_flows("10.0.0.2", 14), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.triggered is False

    def test_below_10s_threshold_no_trigger(self):
        rule = PortScanRule()
        rule.min_ports_10s = 30
        window = make_window(scanning_flows("10.0.0.2", 20), window_size_seconds=10)
        result = rule.analyze(window)
        assert result.triggered is False


# ---------------------------------------------------------------------------
# At-threshold — triggers
# ---------------------------------------------------------------------------

class TestPortScanAtThreshold:

    def test_at_1s_threshold_triggers(self):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        window = make_window(scanning_flows("10.0.0.1", 15), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.triggered is True

    def test_at_10s_threshold_triggers(self):
        rule = PortScanRule()
        rule.min_ports_10s = 30
        window = make_window(scanning_flows("10.0.0.1", 30), window_size_seconds=10)
        result = rule.analyze(window)
        assert result.triggered is True

    def test_at_60s_threshold_triggers(self):
        rule = PortScanRule()
        rule.min_ports_60s = 50
        window = make_window(scanning_flows("10.0.0.1", 50), window_size_seconds=60)
        result = rule.analyze(window)
        assert result.triggered is True


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

class TestPortScanConfidence:

    def test_confidence_at_threshold_is_approx_0_33(self):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        window = make_window(scanning_flows("10.0.0.1", 15), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.triggered is True
        assert pytest.approx(result.confidence, rel=0.05) == 15 / (15 * 3)

    def test_confidence_at_3x_threshold_is_1_0(self):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        window = make_window(scanning_flows("10.0.0.1", 45), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.confidence == pytest.approx(1.0)

    def test_confidence_capped_at_1_0(self):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        # 100 ports >> 3× threshold
        window = make_window(scanning_flows("10.0.0.1", 100), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.confidence <= 1.0


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestPortScanSeverity:

    @pytest.mark.parametrize("n_ports,expected_severity", [
        (16,  Severity.LOW),      # conf ≈ 0.36
        (20,  Severity.MEDIUM),   # conf ≈ 0.44
        (35,  Severity.HIGH),     # conf ≈ 0.78
        (45,  Severity.CRITICAL), # conf = 1.0
    ])
    def test_severity_bands(self, n_ports, expected_severity):
        rule = PortScanRule()
        rule.min_ports_1s = 15
        window = make_window(scanning_flows("10.0.0.1", n_ports), window_size_seconds=1)
        # Severity is stored in evidence or accessible via _severity_for
        confidence = min(1.0, n_ports / (15 * 3))
        actual = PortScanRule._severity_for(confidence)
        assert actual == expected_severity


# ---------------------------------------------------------------------------
# Evidence dict
# ---------------------------------------------------------------------------

class TestPortScanEvidence:

    def test_evidence_contains_required_keys(self):
        rule = PortScanRule()
        rule.min_ports_1s = 5
        window = make_window(scanning_flows("10.0.0.1", 10), window_size_seconds=1)
        result = rule.analyze(window)
        assert result.triggered is True
        ev = result.evidence
        assert "src_ip" in ev
        assert "unique_ports_contacted" in ev
        assert "sampled_ports" in ev
        assert "window_size_seconds" in ev

    def test_sampled_ports_capped_at_10(self):
        rule = PortScanRule()
        rule.min_ports_1s = 5
        window = make_window(scanning_flows("10.0.0.1", 50), window_size_seconds=1)
        result = rule.analyze(window)
        assert len(result.evidence["sampled_ports"]) <= 10

    def test_evidence_is_json_serializable(self):
        import json
        rule = PortScanRule()
        rule.min_ports_1s = 5
        window = make_window(scanning_flows("10.0.0.1", 20), window_size_seconds=1)
        result = rule.analyze(window)
        # Should not raise
        json.dumps(result.evidence)

    def test_worst_src_ip_identified(self):
        rule = PortScanRule()
        rule.min_ports_1s = 5
        # Two sources — one scans 10 ports, one scans 3
        flows = scanning_flows("10.0.0.99", 10) + scanning_flows("10.0.0.1", 3)
        window = make_window(flows, window_size_seconds=1)
        result = rule.analyze(window)
        assert result.evidence["src_ip"] == "10.0.0.99"
        assert result.evidence["unique_ports_contacted"] == 10


# ---------------------------------------------------------------------------
# Exception safety
# ---------------------------------------------------------------------------

class TestPortScanErrorSafety:

    def test_bad_window_returns_non_triggered(self):
        """A malformed window should never cause an unhandled exception."""
        rule = PortScanRule()
        # Pass a window with a flow that has a broken flow_key
        from unittest.mock import MagicMock

        bad_flow = MagicMock()
        bad_flow.flow_key.src_ip = "1.2.3.4"
        bad_flow.flow_key.dst_port = "not-an-int"  # will break set logic eventually
        bad_window = make_window([])
        bad_window.top_flows = [bad_flow]

        # Should not raise
        result = rule.analyze(bad_window)
        assert isinstance(result.triggered, bool)
