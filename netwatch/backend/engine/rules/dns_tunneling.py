"""
engine/rules/dns_tunneling.py

DNS Tunneling Detection Rule — fully implemented.

Detects high-volume or large-payload DNS flows from a single host —
a common exfiltration technique where data is encoded in DNS queries/subdomains.

Strategy:
    - Group DNS flows by src_ip
    - Trigger on very high query count (volume exfiltration)
    - Trigger on large average payload (encoded data in subdomains)
    - Confidence = max(query_score, payload_score)
"""

from __future__ import annotations

import logging

from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity
from .base import BaseRule

logger = logging.getLogger(__name__)


class DnsTunnelingRule(BaseRule):
    """Detects data exfiltration via DNS tunneling."""

    name = "dns_tunneling"
    severity = Severity.HIGH
    enabled = True

    # ------------------------------------------------------------------
    # Configurable thresholds
    # ------------------------------------------------------------------
    max_dns_queries_per_10s: int   = 200
    max_dns_payload_bytes:   float = 150.0

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        try:
            return self._analyze(window)
        except Exception as exc:
            logger.exception("DnsTunnelingRule.analyze() raised: %s", exc)
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="internal error in dns_tunneling rule")

    def _analyze(self, window: AggregatedWindow) -> RuleResult:
        dns_flows = [
            f for f in window.top_flows
            if f.flow_key.protocol == "DNS"
        ]

        if not dns_flows:
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="no DNS flows in window")

        # Group by src_ip
        by_src: dict[str, list] = {}
        for flow in dns_flows:
            by_src.setdefault(flow.flow_key.src_ip, []).append(flow)

        best_src: str | None = None
        best_confidence = 0.0
        best_evidence: dict = {}

        q_threshold = self.max_dns_queries_per_10s
        p_threshold = self.max_dns_payload_bytes

        for src_ip, flows in by_src.items():
            total_queries = sum(f.packet_count for f in flows)
            n = len(flows)
            avg_payload = sum(f.avg_payload_size for f in flows) / n if n else 0.0

            query_score   = min(1.0, total_queries / (q_threshold * 2))
            payload_score = min(1.0, avg_payload / (p_threshold * 2))
            confidence    = max(query_score, payload_score)

            triggered_by_volume  = total_queries >= q_threshold
            triggered_by_payload = avg_payload >= p_threshold

            if (triggered_by_volume or triggered_by_payload) and confidence > best_confidence:
                best_confidence = confidence
                best_src = src_ip
                trigger_reason = (
                    "volume" if triggered_by_volume and not triggered_by_payload
                    else "payload_size" if triggered_by_payload and not triggered_by_volume
                    else "volume+payload_size"
                )
                best_evidence = {
                    "src_ip": src_ip,
                    "total_dns_queries": total_queries,
                    "avg_payload_size": round(avg_payload, 2),
                    "trigger_reason": trigger_reason,
                    "window_size_seconds": window.window_size_seconds,
                }

        if best_src is None:
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="no DNS tunneling detected")

        return RuleResult(
            triggered=True,
            confidence=best_confidence,
            evidence=best_evidence,
            description=(
                f"DNS tunneling suspected from {best_src}: "
                f"{best_evidence['total_dns_queries']} queries, "
                f"avg payload {best_evidence['avg_payload_size']}B "
                f"({best_evidence['trigger_reason']})"
            ),
        )
