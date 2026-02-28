"""
aggregation/models.py

Data models for Phase 2 — Aggregation Layer.

These are the *authoritative* Phase 2 versions, replacing the placeholder
stubs that were defined in backend/models.py during Phase 1.

FlowKey    — hashable 5-tuple used as dict key in FlowTracker
FlowRecord — per-flow statistics (no raw packets stored)
AggregatedWindow — completed time-window snapshot fed to detection engine
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import NamedTuple


# ---------------------------------------------------------------------------
# FlowKey — hashable, normalised 5-tuple
# ---------------------------------------------------------------------------

class FlowKey(NamedTuple):
    """
    Normalised 5-tuple key for flow tracking.

    Normalisation rule (bidirectional symmetry):
        The side with the *lower* port number is always stored as src.
        If ports are equal, the lexicographically smaller IP is src.
    This ensures that both directions of a TCP connection map to the same key.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __repr__(self) -> str:
        return (
            f"{self.src_ip}:{self.src_port}"
            f"→{self.dst_ip}:{self.dst_port}"
            f"/{self.protocol}"
        )


def make_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
) -> FlowKey:
    """
    Build a normalised FlowKey from raw packet fields.

    Normalisation ensures bidirectional traffic maps to the same key:
    - Lower-port side → src
    - Tie-break: lexicographically smaller IP → src
    """
    if src_port < dst_port:
        return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
    elif dst_port < src_port:
        return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol)
    else:
        # Equal ports: sort by IP
        if src_ip <= dst_ip:
            return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol)


# ---------------------------------------------------------------------------
# FlowRecord — per-flow statistics
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    """
    Statistics for a single network flow (identified by FlowKey).

    No raw packets are stored — only derived counters.
    Memory is O(1) per flow.
    """

    flow_key: FlowKey

    first_seen: float = field(default_factory=time.time)
    """Unix timestamp of the first packet on this flow."""

    last_seen: float = field(default_factory=time.time)
    """Unix timestamp of the most recently seen packet."""

    packet_count: int = 0
    byte_count: int = 0

    flags_seen: set[str] = field(default_factory=set)
    """All distinct TCP flag strings observed ('SYN', 'ACK', etc.)."""

    _total_payload: int = field(default=0, repr=False)
    """Running sum of payload sizes — used to compute avg_payload_size."""

    is_active: bool = True
    """False once expire_flows() has marked this flow as timed-out."""

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def avg_payload_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self._total_payload / self.packet_count

    @property
    def packets_per_second(self) -> float:
        """
        Throughput in packets/second.
        Only computed when flow duration > 0.1 s to avoid near-zero division.
        """
        duration = self.last_seen - self.first_seen
        if duration < 0.1:
            return 0.0
        return self.packet_count / duration

    def __repr__(self) -> str:
        return (
            f"FlowRecord({self.flow_key!r} "
            f"pkts={self.packet_count} "
            f"bytes={self.byte_count} "
            f"pps={self.packets_per_second:.1f} "
            f"active={self.is_active})"
        )


# ---------------------------------------------------------------------------
# AggregatedWindow — completed time-window snapshot
# ---------------------------------------------------------------------------

@dataclass
class AggregatedWindow:
    """
    Snapshot of traffic statistics over a fixed time window.

    Produced by TimeWindowBucket when a window elapses.
    Consumed by the detection engine (Phase 3).

    No raw packets or full flow tables are stored.
    Memory is O(top_flows) — bounded to 10 FlowRecord objects.
    """

    window_start: float
    """Unix timestamp of the window's start."""

    window_end: float
    """Unix timestamp of the window's end."""

    window_size_seconds: int
    """Duration in seconds: 1, 10, or 60."""

    total_packets: int = 0
    total_bytes: int = 0

    unique_src_ips: set[str] = field(default_factory=set)
    unique_dst_ips: set[str] = field(default_factory=set)
    unique_dst_ports: set[int] = field(default_factory=set)

    protocol_counts: dict[str, int] = field(default_factory=dict)
    """e.g. {'TCP': 412, 'UDP': 88, 'DNS': 34}"""

    top_flows: list[FlowRecord] = field(default_factory=list)
    """Top 10 flows by packet count at window close."""

    flows_started: int = 0
    """New flows seen for the first time in this window."""

    flows_ended: int = 0
    """Flows that went inactive during this window."""

    def __repr__(self) -> str:
        return (
            f"AggregatedWindow("
            f"{self.window_size_seconds}s "
            f"pkts={self.total_packets} "
            f"bytes={self.total_bytes} "
            f"proto={self.protocol_counts} "
            f"flows={len(self.top_flows)})"
        )
