"""
tests/test_flow_tracker.py

Tests for aggregation/flow_tracker.py.
No network access required — builds PacketMeta objects directly.
"""

from __future__ import annotations

import time

import pytest

from netwatch.backend.aggregation.flow_tracker import FlowTracker
from netwatch.backend.aggregation.models import FlowKey, make_flow_key
from netwatch.backend.models import PacketMeta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pkt(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=12345,
    dst_port=80,
    protocol="TCP",
    flags="SYN",
    payload_size=100,
    ttl=64,
    direction="outbound",
    ts=None,
) -> PacketMeta:
    return PacketMeta(
        timestamp=ts or time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        payload_size=payload_size,
        ttl=ttl,
        direction=direction,
    )


# ---------------------------------------------------------------------------
# FlowKey normalisation
# ---------------------------------------------------------------------------

class TestFlowKeyNormalisation:

    def test_lower_port_side_is_src(self):
        """Lower port number → src side, regardless of which end sent the packet."""
        # src_port=12345, dst_port=80 → normalised: src_port=80 (lower)
        key = make_flow_key("192.168.1.10", "8.8.8.8", 12345, 80, "TCP")
        assert key.src_port == 80
        assert key.dst_port == 12345

    def test_bidirectional_maps_to_same_key(self):
        """Forward and reverse packets must produce the same FlowKey."""
        fwd = make_flow_key("192.168.1.10", "8.8.8.8", 12345, 80, "TCP")
        rev = make_flow_key("8.8.8.8", "192.168.1.10", 80, 12345, "TCP")
        assert fwd == rev

    def test_equal_ports_sorted_by_ip(self):
        """When ports are equal, the smaller IP is placed as src."""
        key = make_flow_key("10.0.0.2", "10.0.0.1", 53, 53, "UDP")
        assert key.src_ip == "10.0.0.1"
        assert key.dst_ip == "10.0.0.2"

    def test_flow_key_is_hashable(self):
        key = make_flow_key("1.2.3.4", "5.6.7.8", 1000, 80, "TCP")
        d = {key: "value"}
        assert d[key] == "value"

    def test_flow_key_repr(self):
        key = FlowKey("1.2.3.4", "5.6.7.8", 80, 1000, "TCP")
        assert "1.2.3.4" in repr(key)
        assert "TCP" in repr(key)


# ---------------------------------------------------------------------------
# FlowTracker.update()
# ---------------------------------------------------------------------------

class TestFlowTrackerUpdate:

    def test_creates_new_flow_on_first_packet(self):
        tracker = FlowTracker()
        p = pkt()
        record = tracker.update(p)
        assert record.packet_count == 1
        assert record.byte_count == p.payload_size
        assert record.is_active is True
        assert len(tracker.flows) == 1

    def test_same_flow_accumulates_stats(self):
        tracker = FlowTracker()
        for _ in range(5):
            tracker.update(pkt(payload_size=50))
        assert len(tracker.flows) == 1
        record = next(iter(tracker.flows.values()))
        assert record.packet_count == 5
        assert record.byte_count == 250

    def test_different_protocols_are_separate_flows(self):
        tracker = FlowTracker()
        tracker.update(pkt(protocol="TCP"))
        tracker.update(pkt(protocol="UDP"))
        assert len(tracker.flows) == 2

    def test_bidirectional_traffic_is_one_flow(self):
        """Forward and reverse packets → same FlowRecord."""
        tracker = FlowTracker()
        tracker.update(pkt(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                           src_port=12345, dst_port=80))
        tracker.update(pkt(src_ip="8.8.8.8", dst_ip="192.168.1.10",
                           src_port=80, dst_port=12345))
        assert len(tracker.flows) == 1
        record = next(iter(tracker.flows.values()))
        assert record.packet_count == 2

    def test_flags_accumulated(self):
        tracker = FlowTracker()
        tracker.update(pkt(flags="SYN"))
        tracker.update(pkt(flags="SYN-ACK"))
        tracker.update(pkt(flags="ACK"))
        record = next(iter(tracker.flows.values()))
        assert record.flags_seen == {"SYN", "SYN-ACK", "ACK"}

    def test_avg_payload_size(self):
        tracker = FlowTracker()
        tracker.update(pkt(payload_size=100))
        tracker.update(pkt(payload_size=200))
        record = next(iter(tracker.flows.values()))
        assert record.avg_payload_size == pytest.approx(150.0)

    def test_pop_new_flow_count(self):
        tracker = FlowTracker()
        tracker.update(pkt(src_port=100, dst_port=80, protocol="TCP"))
        tracker.update(pkt(src_port=200, dst_port=80, protocol="TCP"))
        count = tracker.pop_new_flow_count()
        assert count == 2
        # After pop, counter resets
        assert tracker.pop_new_flow_count() == 0


# ---------------------------------------------------------------------------
# FlowTracker.expire_flows()
# ---------------------------------------------------------------------------

class TestFlowTrackerExpiry:

    def test_old_flow_is_expired(self):
        tracker = FlowTracker(ttl_seconds=60)
        p = pkt(ts=time.time() - 120)   # 2 minutes ago
        tracker.update(p)
        expired = tracker.expire_flows(timeout_seconds=60)
        assert len(expired) == 1
        assert expired[0].is_active is False
        assert len(tracker.flows) == 0

    def test_fresh_flow_is_not_expired(self):
        tracker = FlowTracker(ttl_seconds=60)
        tracker.update(pkt())   # now
        expired = tracker.expire_flows(timeout_seconds=60)
        assert expired == []
        assert len(tracker.flows) == 1

    def test_mixed_expiry(self):
        tracker = FlowTracker(ttl_seconds=60)
        # One old flow
        tracker.update(pkt(src_port=9999, ts=time.time() - 120))
        # One fresh flow  
        tracker.update(pkt(src_port=8888))
        expired = tracker.expire_flows(timeout_seconds=60)
        assert len(expired) == 1
        assert len(tracker.flows) == 1


# ---------------------------------------------------------------------------
# FlowTracker.get_top_flows()
# ---------------------------------------------------------------------------

class TestFlowTrackerTopFlows:

    def test_top_flows_sorted_by_packet_count(self):
        tracker = FlowTracker()
        # Flow A: 10 packets
        for _ in range(10):
            tracker.update(pkt(src_port=1111, dst_port=80, protocol="TCP"))
        # Flow B: 3 packets
        for _ in range(3):
            tracker.update(pkt(src_port=2222, dst_port=80, protocol="TCP"))

        top = tracker.get_top_flows(n=2)
        assert top[0].packet_count == 10
        assert top[1].packet_count == 3

    def test_top_flows_capped_at_n(self):
        tracker = FlowTracker()
        for i in range(20):
            tracker.update(pkt(src_port=i + 100, dst_port=80, protocol="TCP"))
        top = tracker.get_top_flows(n=5)
        assert len(top) == 5

    def test_top_flows_is_copy(self):
        """Mutating the returned list must not affect the tracker."""
        tracker = FlowTracker()
        tracker.update(pkt())
        top = tracker.get_top_flows()
        top.clear()
        assert len(tracker.flows) == 1


# ---------------------------------------------------------------------------
# FlowRecord — computed properties
# ---------------------------------------------------------------------------

class TestFlowRecordProperties:

    def test_packets_per_second_zero_on_single_packet(self):
        tracker = FlowTracker()
        tracker.update(pkt(ts=time.time()))
        record = next(iter(tracker.flows.values()))
        # Duration < 0.1 → pps should be 0.0
        assert record.packets_per_second == 0.0

    def test_packets_per_second_computed_over_duration(self):
        tracker = FlowTracker()
        now = time.time()
        tracker.update(pkt(ts=now - 10.0))   # first packet: 10 s ago
        for _ in range(9):
            tracker.update(pkt(ts=now))       # 9 more: now
        record = next(iter(tracker.flows.values()))
        # 10 packets over ~10 s ≈ 1.0 pps
        assert record.packets_per_second == pytest.approx(1.0, rel=0.1)
