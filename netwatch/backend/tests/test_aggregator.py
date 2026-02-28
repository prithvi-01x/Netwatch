"""
tests/test_aggregator.py

End-to-end tests for the Aggregator — puts PacketMeta objects onto the
input queue and asserts AggregatedWindow objects emerge from the output queue.

All tests use in-memory asyncio.Queue objects; no live network required.
Window boundaries are forced by patching time.monotonic() so tests run fast.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

from netwatch.backend.aggregation.aggregator import Aggregator
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
        ttl=64,
        direction=direction,
    )


async def drain_queue(q: asyncio.Queue, timeout: float = 0.2) -> list:
    """Drain everything currently in the queue within timeout seconds."""
    items = []
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            item = await asyncio.wait_for(q.get(), timeout=remaining)
            items.append(item)
        except asyncio.TimeoutError:
            break
    return items


# ---------------------------------------------------------------------------
# Aggregator stats
# ---------------------------------------------------------------------------

class TestAggregatorStats:

    @pytest.mark.asyncio
    async def test_stats_initialized(self):
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue()
        agg = Aggregator(iq, oq)
        assert agg.stats["packets_processed"] == 0
        assert agg.stats["flows_active"] == 0
        assert agg.stats["windows_emitted"] == 0

    @pytest.mark.asyncio
    async def test_stats_updated_after_packet(self):
        """Processing a packet increments packets_processed + flows_active."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue()
        agg = Aggregator(iq, oq)

        await iq.put(pkt())
        # Run _process_one() directly (bypasses the run() loop)
        await agg._process_one()

        assert agg.stats["packets_processed"] == 1
        assert agg.stats["flows_active"] == 1


# ---------------------------------------------------------------------------
# Aggregator window emission
# ---------------------------------------------------------------------------

class TestAggregatorWindowEmission:

    @pytest.mark.asyncio
    async def test_window_emitted_when_elapsed(self):
        """
        When a 1s window elapses, an AggregatedWindow ends up on the output queue.
        We force the window to elapse by making monotonic advance past 1 second.
        """
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue(maxsize=100)
        agg = Aggregator(iq, oq)

        # Set all three buckets' window_start to the past so they will seal
        past = 1000.0
        for bucket in agg._buckets.values():
            bucket._window_start_mono = past

        # Patch monotonic to return a time far in the future (all windows elapsed)
        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            return_value=past + 65.0,  # > 60 s → all three windows elapsed
        ):
            await iq.put(pkt())
            await agg._process_one()

        # Expect 3 windows (1s, 10s, 60s)
        windows = await drain_queue(oq)
        assert len(windows) == 3
        sizes = sorted(w.window_size_seconds for w in windows)
        assert sizes == [1, 10, 60]

    @pytest.mark.asyncio
    async def test_window_contains_correct_counts(self):
        """Accumulated totals appear in the sealed window."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue(maxsize=100)
        agg = Aggregator(iq, oq)

        # Fill 1s bucket with 3 packets and then seal
        past = 1000.0
        agg._buckets[1]._window_start_mono = past
        agg._buckets[1]._total_packets = 3
        agg._buckets[1]._total_bytes = 300
        agg._buckets[1]._protocol_counts = {"TCP": 3}

        # Advance only the 1s window past its boundary
        original_mono = time.monotonic
        call_count = {"n": 0}

        def fake_mono():
            call_count["n"] += 1
            # Only the 1s window check sees "elapsed"
            return past + 2.0

        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            side_effect=fake_mono,
        ):
            agg._buckets[10]._window_start_mono = past + 1.0   # not elapsed
            agg._buckets[60]._window_start_mono = past + 1.0   # not elapsed
            await iq.put(pkt(payload_size=50, protocol="TCP"))
            await agg._process_one()

        windows = await drain_queue(oq)
        one_sec = next((w for w in windows if w.window_size_seconds == 1), None)
        assert one_sec is not None
        assert one_sec.total_packets == 3
        assert one_sec.total_bytes == 300


# ---------------------------------------------------------------------------
# Aggregator flush on cancellation
# ---------------------------------------------------------------------------

class TestAggregatorFlushOnCancel:

    @pytest.mark.asyncio
    async def test_flush_called_on_cancel(self):
        """CancelledError triggers flush() on all three buckets."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue(maxsize=100)
        agg = Aggregator(iq, oq)

        # Put one packet in, process it (without elapsing window)
        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            return_value=1000.0,
        ):
            for bucket in agg._buckets.values():
                bucket._window_start_mono = 1000.0
            await iq.put(pkt())
            await agg._process_one()

        # Now manually flush to simulate what run() does on CancelledError
        await agg._flush_all()

        windows = await drain_queue(oq)
        # All three buckets had 1 packet — all three should flush
        assert len(windows) == 3

    @pytest.mark.asyncio
    async def test_flush_empty_bucket_emits_nothing(self):
        """Empty buckets produce no output on flush."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue(maxsize=100)
        agg = Aggregator(iq, oq)

        # Don't feed any packets — all buckets are empty
        await agg._flush_all()
        windows = await drain_queue(oq)
        assert windows == []


# ---------------------------------------------------------------------------
# FlowTracker integration
# ---------------------------------------------------------------------------

class TestAggregatorFlowTracking:

    @pytest.mark.asyncio
    async def test_multiple_distinct_flows(self):
        """Each unique 5-tuple should produce a separate flow."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue()
        agg = Aggregator(iq, oq)

        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            return_value=1000.0,
        ):
            for bucket in agg._buckets.values():
                bucket._window_start_mono = 1000.0
            for port in [111, 222, 333]:
                await iq.put(pkt(src_port=port, dst_port=80))
            for _ in range(3):
                await agg._process_one()

        assert agg.stats["flows_active"] == 3
        assert agg.stats["packets_processed"] == 3

    @pytest.mark.asyncio
    async def test_bidirectional_traffic_single_flow(self):
        """Reverse packet should map to the same flow as forward."""
        iq: asyncio.Queue = asyncio.Queue()
        oq: asyncio.Queue = asyncio.Queue()
        agg = Aggregator(iq, oq)

        with patch(
            "netwatch.backend.aggregation.time_window.time.monotonic",
            return_value=1000.0,
        ):
            for bucket in agg._buckets.values():
                bucket._window_start_mono = 1000.0

            # Forward
            await iq.put(pkt(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                              src_port=12345, dst_port=80))
            # Reverse
            await iq.put(pkt(src_ip="8.8.8.8", dst_ip="192.168.1.10",
                              src_port=80, dst_port=12345))
            await agg._process_one()
            await agg._process_one()

        assert agg.stats["flows_active"] == 1
        assert agg.stats["packets_processed"] == 2
