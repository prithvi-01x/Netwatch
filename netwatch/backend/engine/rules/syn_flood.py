"""
engine/rules/syn_flood.py

SYN Flood Detection Rule.

Detects a high rate of TCP SYN packets with few or no SYN-ACK responses —
characteristic of a SYN flood DoS attack or aggressive half-open scanning.

Detection strategy:
    Find TCP flows with "SYN" in flags_seen but NOT "SYN-ACK", where the
    packets_per_second rate is above syn_rate_threshold. If the aggregate
    packet count of those flows meets or exceeds the per-window threshold, fire.

Confidence blend:
    0.6 × (total_syn_packets / threshold) + 0.4 × (syn_only_ratio)
    — balances raw volume against the SYN-to-total-TCP ratio.

Stateless across windows: each call only examines the provided AggregatedWindow.
"""

from __future__ import annotations

import logging

from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity
from .base import BaseRule

logger = logging.getLogger(__name__)


class SynFloodRule(BaseRule):
    """Detects SYN flood / half-open scanning attacks."""

    name = "syn_flood"
    severity = Severity.CRITICAL
    enabled = True

    # ------------------------------------------------------------------
    # Configurable thresholds
    # ------------------------------------------------------------------
    syn_rate_threshold:    float = 50.0   # SYNs/sec per flow to be suspicious
    min_syn_packets_1s:    int   = 100    # total SYN-only packets in 1s window
    min_syn_packets_10s:   int   = 500    # total SYN-only packets in 10s window

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        try:
            return self._analyze(window)
        except Exception as exc:
            logger.exception("SynFloodRule.analyze() raised: %s", exc)
            return RuleResult(
                triggered=False,
                confidence=0.0,
                evidence={},
                description="internal error in syn_flood rule",
            )

    def _analyze(self, window: AggregatedWindow) -> RuleResult:
        threshold = self._threshold_for(window.window_size_seconds)

        # Collect all TCP flows in the window (protocol filter via flags_seen)
        tcp_flows = [
            f for f in window.top_flows
            if f.flags_seen  # only TCP flows have flag info
        ]
        total_tcp_flows = len(tcp_flows)

        # SYN-only flows: SYN seen, no SYN-ACK, and rate above threshold
        syn_only_flows = [
            f for f in tcp_flows
            if "SYN" in f.flags_seen
            and "SYN-ACK" not in f.flags_seen
            and f.packets_per_second >= self.syn_rate_threshold
        ]

        total_syn_packets = sum(f.packet_count for f in syn_only_flows)

        if not syn_only_flows or total_syn_packets < threshold:
            return RuleResult(
                triggered=False,
                confidence=0.0,
                evidence={},
                description="no SYN flood detected",
            )

        # Confidence blend: volume + ratio
        syn_only_ratio = len(syn_only_flows) / max(1, total_tcp_flows)
        confidence = min(
            1.0,
            (total_syn_packets / threshold) * 0.6 + syn_only_ratio * 0.4,
        )

        # Evidence — JSON serializable only (sorted lists, not sets)
        src_ips = sorted({f.flow_key.src_ip for f in syn_only_flows})
        target_ips = sorted({f.flow_key.dst_ip for f in syn_only_flows})[:5]
        peak_rate = max(
            (f.packets_per_second for f in syn_only_flows), default=0.0
        )

        evidence: dict = {
            "src_ips": src_ips,
            "total_syn_packets": total_syn_packets,
            "syn_only_flow_count": len(syn_only_flows),
            "peak_syn_rate": round(peak_rate, 2),
            "target_ips": target_ips,
            "window_size_seconds": window.window_size_seconds,
            "threshold": threshold,
        }

        primary_src = src_ips[0] if src_ips else "unknown"
        primary_dst = target_ips[0] if len(target_ips) == 1 else "multiple"

        return RuleResult(
            triggered=True,
            confidence=confidence,
            evidence=evidence,
            description=(
                f"SYN flood from {primary_src}: {total_syn_packets} SYN-only packets "
                f"at up to {peak_rate:.0f} pkt/s in {window.window_size_seconds}s window"
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _threshold_for(self, window_size: int) -> int:
        if window_size <= 1:
            return self.min_syn_packets_1s
        # 10s and 60s use the same threshold; 60s windows are less likely to
        # see sustained floods but we keep a consistent bar
        return self.min_syn_packets_10s
