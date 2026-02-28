"""
aggregation/flow_tracker.py

FlowTracker — maintains per-flow statistics for all active flows.

Design constraints:
  - No raw PacketMeta objects stored — only derived stats.
  - Flow key is normalised (lower-port side always = src) so bidirectional
    traffic on a TCP connection maps to the same FlowRecord.
  - Expired flows are removed from the active dict and returned to the caller
    so they can be counted in the outgoing AggregatedWindow.
  - Max flows cap (default 50 000) protects against unbounded growth on
    very busy networks; oldest flows are evicted when exceeded.
"""

from __future__ import annotations

import logging
import time

from ..models import PacketMeta
from .models import FlowKey, FlowRecord, make_flow_key

logger = logging.getLogger(__name__)

_MAX_FLOWS_DEFAULT = 50_000
_TTL_SECONDS_DEFAULT = 60


class FlowTracker:
    """
    Tracks live flow statistics keyed on normalised 5-tuple FlowKeys.

    Thread safety: NOT thread-safe. Designed to be called exclusively
    from the aggregator's asyncio coroutine — no locking needed.
    """

    def __init__(
        self,
        max_flows: int = _MAX_FLOWS_DEFAULT,
        ttl_seconds: int = _TTL_SECONDS_DEFAULT,
    ) -> None:
        self.flows: dict[FlowKey, FlowRecord] = {}
        self._max_flows = max_flows
        self._ttl_seconds = ttl_seconds
        self._new_flow_count: int = 0   # flows added since last reset
        logger.debug(
            "FlowTracker initialised — max_flows=%d ttl=%ds",
            max_flows,
            ttl_seconds,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, packet: PacketMeta) -> FlowRecord:
        """
        Update or create a FlowRecord for this packet's flow.

        Returns the updated FlowRecord.
        """
        key = make_flow_key(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        )

        if key in self.flows:
            record = self.flows[key]
            # Reactivate if it was previously expired but traffic resumed
            record.is_active = True
        else:
            record = FlowRecord(flow_key=key, first_seen=packet.timestamp)
            self.flows[key] = record
            self._new_flow_count += 1
            logger.debug("New flow: %r (total active: %d)", key, len(self.flows))
            # Enforce max-flows cap
            if len(self.flows) > self._max_flows:
                self._evict_oldest()

        # Update statistics — no raw packet stored after this point
        record.last_seen = packet.timestamp
        record.packet_count += 1
        record.byte_count += packet.payload_size
        record._total_payload += packet.payload_size
        if packet.flags:
            record.flags_seen.add(packet.flags)

        return record

    def expire_flows(self, timeout_seconds: int | None = None) -> list[FlowRecord]:
        """
        Mark flows as inactive if last_seen is older than timeout_seconds.

        Removes expired flows from the active dict.
        Returns the list of expired FlowRecord objects.

        Args:
            timeout_seconds: Override for TTL (uses instance default if None).
        """
        ttl = timeout_seconds if timeout_seconds is not None else self._ttl_seconds
        cutoff = time.time() - ttl
        expired: list[FlowRecord] = []

        keys_to_remove = [
            k for k, v in self.flows.items() if v.last_seen < cutoff
        ]
        for key in keys_to_remove:
            record = self.flows.pop(key)
            record.is_active = False
            expired.append(record)

        if expired:
            logger.info(
                "Expired %d flows (TTL=%ds, remaining active: %d)",
                len(expired),
                ttl,
                len(self.flows),
            )
        return expired

    def get_top_flows(self, n: int = 10) -> list[FlowRecord]:
        """
        Return top-N flows sorted by packet_count descending.
        Returns a copy — safe for the caller to hold without worrying about mutation.
        """
        sorted_flows = sorted(
            self.flows.values(),
            key=lambda r: r.packet_count,
            reverse=True,
        )
        return sorted_flows[:n]

    def pop_new_flow_count(self) -> int:
        """Return and reset the count of new flows since the last call."""
        count = self._new_flow_count
        self._new_flow_count = 0
        return count

    @property
    def active_count(self) -> int:
        return len(self.flows)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_oldest(self) -> None:
        """Evict the oldest flow(s) to stay within max_flows limit."""
        n_to_evict = len(self.flows) - self._max_flows
        if n_to_evict <= 0:
            return
        oldest = sorted(self.flows.items(), key=lambda kv: kv[1].last_seen)
        for key, _ in oldest[:n_to_evict]:
            self.flows.pop(key, None)
        logger.warning("Evicted %d oldest flows to stay within cap", n_to_evict)
