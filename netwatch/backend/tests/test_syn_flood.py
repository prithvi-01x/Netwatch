"""
tests/test_syn_flood.py

Tests for engine/rules/syn_flood.py.
"""

from __future__ import annotations

import time

import pytest

from netwatch.backend.aggregation.models import AggregatedWindow, FlowKey, FlowRecord
from netwatch.backend.engine.rules.syn_flood import SynFloodRule


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


def make_syn_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    packet_count: int = 200,
    pps_override: float | None = None,
    flags: set[str] | None = None,
) -> FlowRecord:
    key = FlowKey(src_ip, dst_ip, 54321, 80, "TCP")
    r = FlowRecord(flow_key=key)
    r.packet_count = packet_count
    r.byte_count = packet_count * 40
    r.flags_seen = flags if flags is not None else {"SYN"}
    # Force packets_per_second via duration manipulation
    if pps_override is not None:
        # last_seen - first_seen = packet_count / pps
        r.first_seen = time.time() - (packet_count / pps_override)
        r.last_seen = time.time()
    return r


# ---------------------------------------------------------------------------
# No flood — should not trigger
# ---------------------------------------------------------------------------

class TestSynFloodNoTrigger:

    def test_empty_window_no_trigger(self):
        rule = SynFloodRule()
        result = rule.analyze(make_window([]))
        assert result.triggered is False

    def test_acknowledged_flows_no_trigger(self):
        """SYN+SYN-ACK flows are normal handshakes — should not fire."""
        rule = SynFloodRule()
        flow = make_syn_flow(flags={"SYN", "SYN-ACK"}, packet_count=300)
        # Force high pps
        flow.first_seen = time.time() - 1.0
        flow.last_seen = time.time()
        window = make_window([flow])
        result = rule.analyze(window)
        assert result.triggered is False

    def test_low_rate_syn_flow_no_trigger(self):
        """SYN-only flow but rate below syn_rate_threshold → no trigger."""
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        # Force rate to 10 pps (below 50 threshold)
        flow = make_syn_flow(packet_count=50, pps_override=10.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False

    def test_low_count_syn_flow_no_trigger(self):
        """High rate but total packet count below threshold → no trigger."""
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=50, pps_override=100.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is False


# ---------------------------------------------------------------------------
# Flood detected
# ---------------------------------------------------------------------------

class TestSynFloodDetected:

    def test_high_rate_high_count_triggers(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True

    def test_exactly_at_threshold_triggers(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=100, pps_override=100.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True

    def test_multiple_syn_only_flows_aggregate(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        # Two flows, 60 packets each → 120 total ≥ 100 threshold
        flows = [
            make_syn_flow("10.0.0.1", "192.168.1.1", packet_count=60, pps_override=60.0),
            make_syn_flow("10.0.0.2", "192.168.1.1", packet_count=60, pps_override=60.0),
        ]
        result = rule.analyze(make_window(flows))
        assert result.triggered is True

    def test_10s_window_uses_higher_threshold(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        rule.min_syn_packets_10s = 500
        # 200 SYN packets at high rate — triggers 1s threshold but NOT 10s
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result_1s = rule.analyze(make_window([flow], window_size_seconds=1))
        result_10s = rule.analyze(make_window([flow], window_size_seconds=10))
        assert result_1s.triggered is True
        assert result_10s.triggered is False


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

class TestSynFloodConfidence:

    def test_confidence_in_0_1_range(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result = rule.analyze(make_window([flow]))
        assert 0.0 <= result.confidence <= 1.0

    def test_confidence_not_exceeds_1(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        # Massive flood
        flow = make_syn_flow(packet_count=10_000, pps_override=10_000.0)
        result = rule.analyze(make_window([flow]))
        assert result.confidence <= 1.0


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class TestSynFloodEvidence:

    def test_evidence_has_required_keys(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result = rule.analyze(make_window([flow]))
        assert result.triggered is True
        ev = result.evidence
        for key in ("src_ips", "total_syn_packets", "syn_only_flow_count",
                    "peak_syn_rate", "target_ips"):
            assert key in ev, f"Missing evidence key: {key}"

    def test_target_ips_capped_at_5(self):
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 50
        flows = [
            make_syn_flow("10.0.0.1", f"192.168.1.{i}", packet_count=20, pps_override=60.0)
            for i in range(10)
        ]
        result = rule.analyze(make_window(flows))
        if result.triggered:
            assert len(result.evidence["target_ips"]) <= 5

    def test_evidence_is_json_serializable(self):
        import json
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result = rule.analyze(make_window([flow]))
        if result.triggered:
            json.dumps(result.evidence)  # must not raise

    def test_no_set_types_in_evidence(self):
        """Evidence must not contain Python sets (not JSON-serializable)."""
        rule = SynFloodRule()
        rule.syn_rate_threshold = 50.0
        rule.min_syn_packets_1s = 100
        flow = make_syn_flow(packet_count=200, pps_override=200.0)
        result = rule.analyze(make_window([flow]))
        if result.triggered:
            for v in result.evidence.values():
                assert not isinstance(v, set), f"Evidence value is a set: {v}"
