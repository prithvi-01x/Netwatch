"""
engine/rules/brute_force.py  — Fixed

Fix: min_total_attempts lowered 50 → 20 so fast tools like hydra are
caught earlier (they can do 20 attempts in under 1s).
"""

from __future__ import annotations
import logging
from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity
from .base import BaseRule

logger = logging.getLogger(__name__)

_SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    80: "HTTP", 443: "HTTPS", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-alt",
}


class BruteForceRule(BaseRule):
    name = "brute_force"
    severity = Severity.HIGH
    enabled = True

    min_attempts_per_sec:  float = 5.0
    min_total_attempts:    int   = 20    # FIX: was 50 — catch tools like hydra faster
    max_auth_payload_size: float = 256.0
    auth_ports: frozenset[int] = frozenset({22, 21, 23, 3389, 5900})

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        try:
            return self._analyze(window)
        except Exception as exc:
            logger.exception("BruteForceRule.analyze() raised: %s", exc)
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="internal error in brute_force rule")

    def _analyze(self, window: AggregatedWindow) -> RuleResult:
        candidates = [
            f for f in window.top_flows
            if f.flow_key.dst_port in self.auth_ports
            and f.packets_per_second >= self.min_attempts_per_sec
            and f.avg_payload_size <= self.max_auth_payload_size
            and f.packet_count >= self.min_total_attempts
        ]

        if not candidates:
            return RuleResult(triggered=False, confidence=0.0, evidence={},
                              description="no brute force detected")

        worst = max(candidates, key=lambda f: f.packet_count)
        service = _SERVICE_MAP.get(worst.flow_key.dst_port, "Unknown")
        confidence = min(1.0, worst.packet_count / (self.min_total_attempts * 5))

        evidence: dict = {
            "src_ip": worst.flow_key.src_ip,
            "dst_ip": worst.flow_key.dst_ip,
            "dst_port": worst.flow_key.dst_port,
            "service": service,
            "attempt_count": worst.packet_count,
            "attempts_per_minute": round(worst.packets_per_second * 60, 1),
            "avg_payload_size": round(worst.avg_payload_size, 1),
            "window_size_seconds": window.window_size_seconds,
        }

        return RuleResult(
            triggered=True,
            confidence=confidence,
            evidence=evidence,
            description=(
                f"Brute force on {service} (:{worst.flow_key.dst_port}) "
                f"from {worst.flow_key.src_ip}: "
                f"{worst.packet_count} attempts at "
                f"{worst.packets_per_second:.1f} pkt/s"
            ),
        )
