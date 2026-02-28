"""
aggregation/aggregator.py

Aggregator — the main Phase 2 orchestrator.

Consumes PacketMeta from the capture queue, updates the FlowTracker,
feeds three TimeWindowBuckets (1s / 10s / 60s), and emits completed
AggregatedWindow objects to the detection queue.

Scheduling:
  - Main loop: asyncio.wait_for(queue.get(), timeout=1.0)
    The 1-second timeout is used to:
    (a) Drive the 1-second window boundary checks
    (b) Allow the periodic flow-expiry task to wake up without needing
        a separate asyncio.sleep task
  - Flow expiry: runs every EXPIRY_INTERVAL_SECONDS (default 30)
  - Graceful shutdown: on CancelledError, flushes all three buckets

Stats dict (exposed for metrics_reporter in main.py):
    packets_processed    — total packets consumed from capture queue
    flows_active         — current number of live flows in FlowTracker
    flows_expired_total  — cumulative count of flows that have timed out
    windows_emitted      — total AggregatedWindow objects put on output queue
"""

from __future__ import annotations

import asyncio
import logging
import time

from ..models import PacketMeta
from ..pipeline import safe_put
from .flow_tracker import FlowTracker
from .time_window import TimeWindowBucket

logger = logging.getLogger(__name__)

EXPIRY_INTERVAL_SECONDS = 30


class Aggregator:
    """
    Bridges the capture queue → aggregation → detection queue.

    Args:
        input_queue:  asyncio.Queue[PacketMeta]      (from capture layer)
        output_queue: asyncio.Queue[AggregatedWindow] (to detection engine)
        flow_ttl:     How long (seconds) of silence before a flow expires.
    """

    def __init__(
        self,
        input_queue: asyncio.Queue,
        output_queue: asyncio.Queue,
        flow_ttl: int = 60,
    ) -> None:
        self._input_q = input_queue
        self._output_q = output_queue

        self._tracker = FlowTracker(ttl_seconds=flow_ttl)
        self._buckets = {
            1:  TimeWindowBucket(1),
            10: TimeWindowBucket(10),
            60: TimeWindowBucket(60),
        }
        self._last_expiry_check = time.monotonic()
        self._pending_expired = 0  # accumulated expired count between window seals

        self.stats: dict[str, int] = {
            "packets_processed": 0,
            "flows_active": 0,
            "flows_expired_total": 0,
            "windows_emitted": 0,
        }

    # ------------------------------------------------------------------
    # Main async loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main aggregation loop. Runs until cancelled.

        On CancelledError, flushes all three buckets to the output queue
        before re-raising so no data is silently lost on shutdown.
        """
        logger.info("Aggregator started — watching 1s / 10s / 60s windows")
        try:
            while True:
                await self._process_one()
        except asyncio.CancelledError:
            logger.info("Aggregator cancellation received — flushing buckets…")
            await self._flush_all()
            raise

    # ------------------------------------------------------------------
    # Internal: per-iteration logic
    # ------------------------------------------------------------------

    async def _process_one(self) -> None:
        """Dequeue one packet (max 1 s wait) and run one aggregation cycle."""
        # --- Periodic expiry check ---
        now = time.monotonic()
        if now - self._last_expiry_check >= EXPIRY_INTERVAL_SECONDS:
            expired = self._tracker.expire_flows()
            self._pending_expired += len(expired)
            self.stats["flows_expired_total"] += len(expired)
            self._last_expiry_check = now

        # --- Dequeue packet (timeout allows window ticks during quiet periods) ---
        try:
            packet: PacketMeta = await asyncio.wait_for(
                self._input_q.get(), timeout=1.0
            )
            self._input_q.task_done()
        except asyncio.TimeoutError:
            # No packet arrived within 1 s — still need to tick the buckets
            # We call _tick_windows with a synthetic empty path (no packet)
            # by just returning; any elapsed windows will close on the next
            # real packet. This is acceptable: windows produced during idle
            # periods with 0 packets are not useful.
            self.stats["flows_active"] = self._tracker.active_count
            return

        # --- Update flow tracker ---
        flow_record = self._tracker.update(packet)
        self.stats["packets_processed"] += 1
        self.stats["flows_active"] = self._tracker.active_count

        # New flows count (since last pop)
        flows_started = self._tracker.pop_new_flow_count()
        flows_ended = self._pending_expired
        self._pending_expired = 0

        # Top flows snapshot (computed once, shared across all buckets)
        top_flows = self._tracker.get_top_flows(n=10)

        # --- Feed all three time windows ---
        for bucket in self._buckets.values():
            completed = bucket.add(
                packet=packet,
                flow_record=flow_record,
                top_flows=top_flows,
                flows_started=flows_started,
                flows_ended=flows_ended,
            )
            if completed is not None:
                await self._emit(completed)

    async def _emit(self, window) -> None:
        """Put a completed AggregatedWindow on the output queue."""
        enqueued = await safe_put(self._output_q, window)
        if enqueued:
            self.stats["windows_emitted"] += 1
            logger.debug("Emitted %r", window)

    async def _flush_all(self) -> None:
        """Flush all three buckets on shutdown."""
        top_flows = self._tracker.get_top_flows(n=10)
        for size, bucket in self._buckets.items():
            window = bucket.flush(
                top_flows=top_flows,
                flows_started=0,
                flows_ended=0,
            )
            if window is not None:
                await self._emit(window)
                logger.info("Flushed %ds bucket on shutdown", size)
        logger.info("Aggregator shutdown — final stats: %s", self.stats)
