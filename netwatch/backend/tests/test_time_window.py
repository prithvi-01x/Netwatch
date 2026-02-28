"""
tests/test_time_window.py

Tests for aggregation/time_window.py.
Uses unittest.mock.patch to control time.monotonic() and test window
boundaries deterministically without real waiting.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatch.backend.aggregation.models import FlowKey, FlowRecord
from netwatch.backend.aggregation.time_window import TimeWindowBucket
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
    direction="outbound",
) -> PacketMeta:
    return PacketMeta(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        payload_size=payload_size,
        ttl=64,
        direction=direction,
    )


def make_flow_record() -> FlowRecord:
    key = FlowKey("192.168.1.10", "8.8.8.8", 80, 12345, "TCP")
    return FlowRecord(flow_key=key)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestTimeWindowBucketInit:

    @pytest.mark.parametrize("size", [1, 10, 60])
    def test_valid_sizes_accepted(self, size):
        bucket = TimeWindowBucket(size)
        assert bucket._size == size

    def test_invalid_size_raises(self):
        with pytest.raises(AssertionError):
            TimeWindowBucket(5)


# ---------------------------------------------------------------------------
# Window boundary — add()
# ---------------------------------------------------------------------------

class TestTimeWindowBucketAdd:

    def test_no_window_before_elapsed(self):
        """Packets within the window duration → no AggregatedWindow returned."""
        bucket = TimeWindowBucket(1)
        # Pin the window start AND now to the same value so elapsed == 0 < 1s
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0  # anchor start inside the mock
            result = bucket.add(pkt(), make_flow_record())
        assert result is None

    def test_window_returned_when_elapsed(self):
        """Once the window elapses, add() returns the completed window."""
        bucket = TimeWindowBucket(1)
        flow = make_flow_record()

        # Window was started at t=1000.0
        bucket._window_start_mono = 1000.0

        # All subsequent monotonic() calls return 1001.5 → elapsed = 1.5 ≥ 1 s
        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            return_value=1001.5,
        ):
            result = bucket.add(pkt(), flow)

        assert result is not None
        assert result.window_size_seconds == 1

    def test_accumulates_packet_counts(self):
        """Multiple packets in the same window accumulate correctly."""
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        # Keep mono constant → window never elapses
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            for _ in range(5):
                bucket.add(pkt(payload_size=200), flow)
        assert bucket._total_packets == 5
        assert bucket._total_bytes == 1000

    def test_protocol_counts_accumulated(self):
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(protocol="TCP"), flow)
            bucket.add(pkt(protocol="TCP"), flow)
            bucket.add(pkt(protocol="DNS"), flow)

        assert bucket._protocol_counts["TCP"] == 2
        assert bucket._protocol_counts["DNS"] == 1

    def test_unique_ips_tracked(self):
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(src_ip="10.0.0.1"), flow)
            bucket.add(pkt(src_ip="10.0.0.2"), flow)
            bucket.add(pkt(src_ip="10.0.0.1"), flow)  # duplicate

        assert len(bucket._unique_src_ips) == 2

    def test_sealed_window_has_correct_fields(self):
        """The returned AggregatedWindow must contain accumulated data."""
        bucket = TimeWindowBucket(1)
        flow = make_flow_record()

        # First call: fill window
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(payload_size=50, protocol="TCP"), flow)
            bucket.add(pkt(payload_size=50, protocol="UDP"), flow)

        # Second call: window elapses → returns completed window
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1002.0):
            result = bucket.add(pkt(payload_size=10, protocol="TCP"), flow)

        assert result is not None
        assert result.total_packets == 2
        assert result.total_bytes == 100
        assert result.protocol_counts.get("TCP") == 1
        assert result.protocol_counts.get("UDP") == 1


# ---------------------------------------------------------------------------
# flush()
# ---------------------------------------------------------------------------

class TestTimeWindowBucketFlush:

    def test_flush_empty_returns_none(self):
        bucket = TimeWindowBucket(1)
        assert bucket.flush() is None

    def test_flush_partial_window_returns_window(self):
        bucket = TimeWindowBucket(60)
        flow = make_flow_record()
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(payload_size=100), flow)

        result = bucket.flush()
        assert result is not None
        assert result.total_packets == 1
        assert result.total_bytes == 100
        assert result.window_size_seconds == 60

    def test_flush_resets_state(self):
        """After flush(), the bucket should be empty."""
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(), flow)

        bucket.flush()
        assert bucket._total_packets == 0
        assert bucket.flush() is None  # second flush → empty

    def test_flush_with_top_flows(self):
        """flush() should include provided top_flows in the window."""
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        top = [flow]
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(), flow)

        result = bucket.flush(top_flows=top)
        assert result is not None
        assert len(result.top_flows) == 1

    def test_top_flows_capped_at_10(self):
        """Even if 15 flows are passed, only 10 should appear in the window."""
        bucket = TimeWindowBucket(10)
        flow = make_flow_record()
        fifteen_flows = [make_flow_record() for _ in range(15)]
        with patch("netwatch.backend.aggregation.time_window.time.monotonic",
                   return_value=1000.0):
            bucket._window_start_mono = 1000.0
            bucket.add(pkt(), flow)
        result = bucket.flush(top_flows=fifteen_flows)
        assert result is not None
        assert len(result.top_flows) == 10