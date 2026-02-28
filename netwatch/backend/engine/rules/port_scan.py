"""
engine/rules/port_scan.py

Port Scan Detection Rule.

Detects a single source IP contacting an unusually high number of distinct
destination ports within a time window — classic horizontal or vertical scan.

Detection strategy:
    For each unique src_ip seen in the window's top_flows, collect all distinct
    dst_ports it contacted. If the count meets or exceeds the per-window threshold,
    the rule fires.

Stateless across windows: each call only examines the provided AggregatedWindow.
"""

from __future__ import annotations

import logging

from ...aggregation.models import AggregatedWindow
from ..models import RuleResult, Severity
from .base import BaseRule

logger = logging.getLogger(__name__)


class PortScanRule(BaseRule):
    """Detects port scanning by a single source IP."""

    name = "port_scan"
    severity = Severity.HIGH
    enabled = True

    # ------------------------------------------------------------------
    # Configurable thresholds (unique dst_ports per src_ip per window)
    # ------------------------------------------------------------------
    min_ports_1s:  int = 15
    min_ports_10s: int = 30
    min_ports_60s: int = 50

    # ------------------------------------------------------------------
    # BaseRule interface
    # ------------------------------------------------------------------

    def analyze(self, window: AggregatedWindow) -> RuleResult:
        try:
            return self._analyze(window)
        except Exception as exc:
            logger.exception("PortScanRule.analyze() raised: %s", exc)
            return RuleResult(
                triggered=False,
                confidence=0.0,
                evidence={},
                description="internal error in port_scan rule",
            )

    def _analyze(self, window: AggregatedWindow) -> RuleResult:
        threshold = self._threshold_for(window.window_size_seconds)

        # Build: src_ip → set of distinct dst_ports seen in top_flows
        ports_per_src: dict[str, set[int]] = {}
        for flow in window.top_flows:
            src = flow.flow_key.src_ip
            dst_port = flow.flow_key.dst_port
            ports_per_src.setdefault(src, set()).add(dst_port)

        # Also scan unique_dst_ports at window level (broader than top_flows)
        # For the highest-volume src, combine with window-level dst ports
        # (window.unique_dst_ports covers ALL packets, not just top_flows)

        # Find the worst offender
        worst_src: str | None = None
        worst_count: int = 0

        for src_ip, ports in ports_per_src.items():
            if len(ports) > worst_count:
                worst_count = len(ports)
                worst_src = src_ip

        if worst_src is None or worst_count < threshold:
            return RuleResult(
                triggered=False,
                confidence=0.0,
                evidence={},
                description="no port scan detected",
            )

        # Confidence: 0.33 at threshold, 1.0 at 3× threshold
        confidence = min(1.0, worst_count / (threshold * 3))
        severity = self._severity_for(confidence)
        sampled_ports = sorted(ports_per_src[worst_src])[:10]

        evidence: dict = {
            "src_ip": worst_src,
            "unique_ports_contacted": worst_count,
            "sampled_ports": sampled_ports,
            "window_size_seconds": window.window_size_seconds,
            "threshold": threshold,
        }

        return RuleResult(
            triggered=True,
            confidence=confidence,
            evidence=evidence,
            description=(
                f"{worst_src} contacted {worst_count} unique ports in "
                f"{window.window_size_seconds}s window (threshold={threshold})"
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _threshold_for(self, window_size: int) -> int:
        if window_size <= 1:
            return self.min_ports_1s
        if window_size <= 10:
            return self.min_ports_10s
        return self.min_ports_60s

    @staticmethod
    def _severity_for(confidence: float) -> Severity:
        if confidence >= 0.9:
            return Severity.CRITICAL
        if confidence >= 0.7:
            return Severity.HIGH
        if confidence >= 0.4:
            return Severity.MEDIUM
        return Severity.LOW
