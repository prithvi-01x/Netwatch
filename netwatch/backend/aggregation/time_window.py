"""
aggregation/time_window.py

TimeWindowBucket — accumulates packet + flow stats into fixed-size time windows.

Design:
  - One instance per window size (1s, 10s, 60s)
  - Receives one (PacketMeta, FlowRecord) pair per packet
  - Returns a completed AggregatedWindow when the window elapses
  - Uses time.monotonic() for boundary checks (no wall-clock drift)
  - Uses time.time() for AggregatedWindow timestamps (human readability)
  - Never stores raw packets — only updates in-place counters

Thread safety: NOT thread-safe. Called exclusively from asyncio coroutine.
"""

from __future__ import annotations

import logging
import time

from ..models import PacketMeta
from .models import AggregatedWindow, FlowRecord

logger = logging.getLogger(__name__)


class TimeWindowBucket:
    """
    Accumulates per-packet statistics into a fixed-duration time window.

    When `add()` detects that `window_size_seconds` have elapsed since the
    window opened, it seals the current window into an `AggregatedWindow`,
    resets internal state, and returns the completed window.

    Args:
        window_size_seconds: Window duration in seconds (1, 10, or 60).
    """

    def __init__(self, window_size_seconds: int) -> None:
        assert window_size_seconds in (1, 10, 60), (
            f"window_size_seconds must be 1, 10, or 60 — got {window_size_seconds}"
        )
        self._size = window_size_seconds
        self._reset()
        logger.debug("TimeWindowBucket initialised — size=%ds", window_size_seconds)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(
        self,
        packet: PacketMeta,
        flow_record: FlowRecord,
        top_flows: list[FlowRecord] | None = None,
        flows_started: int = 0,
        flows_ended: int = 0,
    ) -> AggregatedWindow | None:
        """
        Add a packet (and its FlowRecord) to the current window.

        Args:
            packet:        The parsed packet to accumulate.
            flow_record:   The updated FlowRecord returned by FlowTracker.update().
            top_flows:     Snapshot of top flows passed in from FlowTracker.
                           Only used when the window seals.
            flows_started: Count of new flows started this window (from tracker).
            flows_ended:   Count of flows expired this window (from tracker).

        Returns:
            Completed AggregatedWindow if the window elapsed, else None.
        """
        now_mono = time.monotonic()

        # Check if the current window has elapsed
        if now_mono - self._window_start_mono >= self._size:
            completed = self._seal(
                top_flows=top_flows or [],
                flows_started=flows_started,
                flows_ended=flows_ended,
            )
            self._reset()
            # Accumulate the new packet into the fresh window
            self._accumulate(packet)
            return completed

        self._accumulate(packet)
        return None

    def flush(
        self,
        top_flows: list[FlowRecord] | None = None,
        flows_started: int = 0,
        flows_ended: int = 0,
    ) -> AggregatedWindow | None:
        """
        Force the current window closed and return it.

        Returns None if the window has no packets (nothing to emit).
        Used on shutdown to drain any partial window.
        """
        if self._total_packets == 0:
            return None
        window = self._seal(
            top_flows=top_flows or [],
            flows_started=flows_started,
            flows_ended=flows_ended,
        )
        self._reset()
        return window

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reset(self) -> None:
        """Start a fresh window."""
        self._window_start_mono = time.monotonic()
        self._window_start_wall = time.time()
        self._total_packets = 0
        self._total_bytes = 0
        self._unique_src_ips: set[str] = set()
        self._unique_dst_ips: set[str] = set()
        self._unique_dst_ports: set[int] = set()
        self._protocol_counts: dict[str, int] = {}

    def _accumulate(self, packet: PacketMeta) -> None:
        """Update running totals from a single packet."""
        self._total_packets += 1
        self._total_bytes += packet.payload_size
        self._unique_src_ips.add(packet.src_ip)
        self._unique_dst_ips.add(packet.dst_ip)
        if packet.dst_port:
            self._unique_dst_ports.add(packet.dst_port)
        self._protocol_counts[packet.protocol] = (
            self._protocol_counts.get(packet.protocol, 0) + 1
        )

    def _seal(
        self,
        top_flows: list[FlowRecord],
        flows_started: int,
        flows_ended: int,
    ) -> AggregatedWindow:
        """Seal the current window into an AggregatedWindow snapshot."""
        window_end = time.time()
        window = AggregatedWindow(
            window_start=self._window_start_wall,
            window_end=window_end,
            window_size_seconds=self._size,
            total_packets=self._total_packets,
            total_bytes=self._total_bytes,
            unique_src_ips=set(self._unique_src_ips),
            unique_dst_ips=set(self._unique_dst_ips),
            unique_dst_ports=set(self._unique_dst_ports),
            protocol_counts=dict(self._protocol_counts),
            top_flows=list(top_flows[:10]),   # cap to top 10
            flows_started=flows_started,
            flows_ended=flows_ended,
        )
        logger.debug(
            "Window sealed — size=%ds pkts=%d bytes=%d",
            self._size,
            self._total_packets,
            self._total_bytes,
        )
        return window
