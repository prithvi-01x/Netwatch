"""
tests/test_new_rules.py

Tests for the three newly-implemented detection rules:
brute_force, dns_tunneling, beaconing.
"""

from __future__ import annotations

import time

import pytest

from netwatch.backend.aggregation.models import AggregatedWindow, FlowKey, FlowRecord
from netwatch.backend.engine.rules.beaconing import BeaconingRule
from netwatch.backend.engine.rules.brute_force import BruteForceRule
from netwatch.backend.engine.rules.dns_tunneling import DnsTunnelingRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_window(
    top_flows: list[FlowRecord],
    window_size_seconds: int = 10,
) -> AggregatedWindow:
    now = time.time()
    return AggregatedWindow(
        window_start=now - window_size_seconds,
        window_end=now,
        window_size_seconds=window_size_seconds,
        total_packets=sum(f.packet_count for f in top_flows),
        protocol_counts={},
        top_flows=top_flows,
    )


def make_tcp_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    dst_port: int = 22,
    packet_count: int = 100,
    pps: float = 10.0,
    avg_payload: float = 64.0,
    flags: set[str] | None = None,
    duration: float = 10.0,
) -> FlowRecord:
    key = FlowKey(src_ip, dst_ip, 54321, dst_port, "TCP")
    r = FlowRecord(flow_key=key)
    r.packet_count = packet_count
    r.byte_count = int(packet_count * avg_payload)
    r._total_payload = int(packet_count * avg_payload)
    r.flags_seen = flags or {"SYN", "ACK"}
    if pps > 0:
        r.first_seen = time.time() - packet_count / pps
        r.last_seen = time.time()
    return r


def make_dns_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    packet_count: int = 50,
    avg_payload: float = 60.0,
) -> FlowRecord:
    key = FlowKey(src_ip, dst_ip, 54321, 53, "DNS")
    r = FlowRecord(flow_key=key)
    r.packet_count = packet_count
    r.byte_count = int(packet_count * avg_payload)
    r._total_payload = int(packet_count * avg_payload)
    return r


# ===========================================================================
# BruteForceRule
# ===========================================================================

class TestBruteForceRuleEnabled:
    def test_is_enabled(self):
        assert BruteForceRule.enabled is True


class TestBruteForceNoTrigger:

    def test_empty_window(self):
        rule = BruteForceRule()
        assert rule.analyze(make_window([])).triggered is False

    def test_non_auth_port_no_trigger(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=12345, packet_count=200, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_large_payload_no_trigger(self):
        """Large average payload = real session, not brute force."""
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=200, pps=10.0, avg_payload=4096.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_low_rate_no_trigger(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=200, pps=1.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_low_count_no_trigger(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=10, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False


class TestBruteForceDetected:

    def test_ssh_brute_force_triggers(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=100, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True

    def test_evidence_service_guess_ssh(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=100, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True
        assert result.evidence["service"] == "SSH"

    def test_evidence_has_required_keys(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=100, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        for key in ("src_ip", "dst_port", "attempt_count",
                    "attempts_per_minute", "service"):
            assert key in result.evidence

    def test_confidence_in_range(self):
        rule = BruteForceRule()
        flow = make_tcp_flow(dst_port=22, packet_count=100, pps=10.0, avg_payload=50.0)
        result = rule.analyze(make_window([flow]))
        assert 0.0 <= result.confidence <= 1.0

    def test_error_safety(self):
        """A bad window must not crash the rule."""
        from unittest.mock import MagicMock
        rule = BruteForceRule()
        bad = MagicMock()
        bad.top_flows = [MagicMock(side_effect=AttributeError("boom"))]
        result = rule.analyze(make_window([]))
        assert isinstance(result.triggered, bool)


# ===========================================================================
# DnsTunnelingRule
# ===========================================================================

class TestDnsTunnelingEnabled:
    def test_is_enabled(self):
        assert DnsTunnelingRule.enabled is True


class TestDnsTunnelingNoTrigger:

    def test_empty_window(self):
        rule = DnsTunnelingRule()
        assert rule.analyze(make_window([])).triggered is False

    def test_no_dns_flows(self):
        rule = DnsTunnelingRule()
        flow = make_tcp_flow(dst_port=80)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_low_query_count_no_trigger(self):
        rule = DnsTunnelingRule()
        rule.max_dns_queries_per_10s = 200
        flow = make_dns_flow(packet_count=50, avg_payload=60.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False


class TestDnsTunnelingDetected:

    def test_high_volume_triggers(self):
        rule = DnsTunnelingRule()
        rule.max_dns_queries_per_10s = 200
        flow = make_dns_flow(packet_count=300, avg_payload=60.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True
        assert result.evidence["trigger_reason"] in ("volume", "volume+payload_size")

    def test_large_payload_triggers(self):
        rule = DnsTunnelingRule()
        rule.max_dns_payload_bytes = 150.0
        flow = make_dns_flow(packet_count=5, avg_payload=400.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True
        assert "payload" in result.evidence["trigger_reason"]

    def test_confidence_in_range(self):
        rule = DnsTunnelingRule()
        rule.max_dns_queries_per_10s = 200
        flow = make_dns_flow(packet_count=500, avg_payload=60.0)
        result = rule.analyze(make_window([flow]))
        assert 0.0 <= result.confidence <= 1.0

    def test_evidence_keys(self):
        rule = DnsTunnelingRule()
        rule.max_dns_queries_per_10s = 100
        flow = make_dns_flow(packet_count=200, avg_payload=60.0)
        result = rule.analyze(make_window([flow]))
        for key in ("src_ip", "total_dns_queries", "avg_payload_size", "trigger_reason"):
            assert key in result.evidence


# ===========================================================================
# BeaconingRule
# ===========================================================================

class TestBeaconingEnabled:
    def test_is_enabled(self):
        assert BeaconingRule.enabled is True


def make_beacon_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "evil.c2.example.com",
    dst_port: int = 4444,
    duration: float = 120.0,
    pps: float = 0.5,
    avg_payload: float = 64.0,
) -> FlowRecord:
    key = FlowKey(src_ip, dst_ip, 54321, dst_port, "TCP")
    r = FlowRecord(flow_key=key)
    r.first_seen = time.time() - duration
    r.last_seen = time.time()
    r.packet_count = max(1, int(duration * pps))
    r.byte_count = int(r.packet_count * avg_payload)
    r._total_payload = r.byte_count
    r.flags_seen = {"ACK"}
    return r


class TestBeaconingNoTrigger:

    def test_empty_window(self):
        rule = BeaconingRule()
        assert rule.analyze(make_window([])).triggered is False

    def test_short_lived_flow_no_trigger(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(duration=10.0, pps=0.5)  # too short
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_common_port_no_trigger(self):
        """Traffic to port 443 should not be flagged as beaconing."""
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=443, duration=120.0, pps=0.5)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_high_rate_no_trigger(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=4444, duration=120.0, pps=50.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_large_payload_no_trigger(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=4444, duration=120.0, pps=0.5, avg_payload=2048.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False


class TestBeaconingDetected:

    def test_classic_beacon_triggers(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=4444, duration=120.0, pps=0.5, avg_payload=64.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True

    def test_confidence_in_range(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=4444, duration=300.0, pps=1.0, avg_payload=64.0)
        result = rule.analyze(make_window([flow]))
        assert 0.0 <= result.confidence <= 1.0

    def test_evidence_keys(self):
        rule = BeaconingRule()
        flow = make_beacon_flow(dst_port=4444, duration=120.0, pps=0.5, avg_payload=64.0)
        result = rule.analyze(make_window([flow]))
        for key in ("src_ip", "dst_ip", "dst_port", "duration_seconds",
                    "packets_per_second", "avg_payload_size"):
            assert key in result.evidence

    def test_severity_is_critical(self):
        assert BeaconingRule.severity.value == "CRITICAL"


# ===========================================================================
# Engine now loads 5 rules
# ===========================================================================

class TestEngineLoads5Rules:
    def test_all_five_rules_loaded(self):
        from netwatch.backend.engine.engine import DetectionEngine
        engine = DetectionEngine()
        names = {r.name for r in engine.rules}
        assert "port_scan"    in names
        assert "syn_flood"    in names
        assert "brute_force"  in names
        assert "dns_tunneling" in names
        assert "beaconing"    in names
        assert len(engine.rules) == 5