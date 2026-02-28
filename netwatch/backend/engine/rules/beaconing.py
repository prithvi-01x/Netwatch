"""
engine/rules/beaconing.py  — Fixed

Fix: min_beacon_duration lowered from 60s → 45s so it can trigger before
FLOW_TTL_SECONDS (now 120s). Previously equal TTL meant flows expired
exactly at the trigger boundary and the rule never fired.
"""

from __future__ import annotations
import logging
from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity
from .base import BaseRule

logger = logging.getLogger(__name__)


class BeaconingRule(BaseRule):
    name = "beaconing"
    severity = Severity.CRITICAL
    enabled = True

    min_beacon_duration:  float = 45.0    # FIX: was 60.0 — must be < FLOW_TTL_SECONDS
    min_beacon_rate:      float = 0.1
    max_beacon_rate:      float = 2.0
    max_beacon_payload:   float = 128.0
    common_ports: frozenset[int] = frozenset({80, 443, 53, 22, 25, 587})

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        try:
            return self._analyze(window)
        except Exception as exc:
            logger.exception("BeaconingRule.analyze() raised: %s", exc)
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="internal error in beaconing rule")

    def _analyze(self, window: AggregatedWindow) -> RuleResult:
        suspicious = [
            f for f in window.top_flows
            if (f.last_seen - f.first_seen) >= self.min_beacon_duration
            and self.min_beacon_rate <= f.packets_per_second <= self.max_beacon_rate
            and f.avg_payload_size <= self.max_beacon_payload
            and f.flow_key.dst_port not in self.common_ports
        ]

        if not suspicious:
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="no beaconing detected")

        mid_rate = (self.min_beacon_rate + self.max_beacon_rate) / 2
        worst = min(suspicious, key=lambda f: abs(f.packets_per_second - mid_rate))
        duration = worst.last_seen - worst.first_seen
        duration_score = min(1.0, duration / (self.min_beacon_duration * 5))
        rate_score = 1.0 - abs(worst.packets_per_second - mid_rate) / mid_rate
        confidence = min(1.0, (duration_score * 0.6 + max(0.0, rate_score) * 0.4))

        evidence: dict = {
            "src_ip": worst.flow_key.src_ip,
            "dst_ip": worst.flow_key.dst_ip,
            "dst_port": worst.flow_key.dst_port,
            "duration_seconds": round(duration, 1),
            "packets_per_second": round(worst.packets_per_second, 3),
            "avg_payload_size": round(worst.avg_payload_size, 2),
            "window_size_seconds": window.window_size_seconds,
        }

        return RuleResult(
            triggered=True,
            confidence=confidence,
            evidence=evidence,
            description=(
                f"Possible beaconing: {worst.flow_key.src_ip}→"
                f"{worst.flow_key.dst_ip}:{worst.flow_key.dst_port} "
                f"at {worst.packets_per_second:.2f} pkt/s "
                f"for {duration:.0f}s (payload {worst.avg_payload_size:.0f}B)"
            ),
        )
