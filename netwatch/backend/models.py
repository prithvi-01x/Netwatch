"""
backend/models.py

Shared dataclasses for every stage of the pipeline.
Defining all of them here locks the inter-stage contracts early
so downstream phases (aggregation, detection, LLM) can be developed
against a stable interface.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


# ---------------------------------------------------------------------------
# Stage 1 — Capture / Parser output
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PacketMeta:
    """Parsed representation of a single captured packet."""

    timestamp: float
    """Unix epoch timestamp (float64)."""

    src_ip: str
    """Source IP address, e.g. '192.168.1.5'."""

    dst_ip: str
    """Destination IP address, e.g. '10.0.0.1'."""

    src_port: int
    """Source port (0–65535). 0 for ICMP."""

    dst_port: int
    """Destination port (0–65535). 0 for ICMP."""

    protocol: str
    """One of: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'OTHER'."""

    flags: str
    """TCP flags string: 'SYN' | 'SYN-ACK' | 'RST' | 'FIN' | 'ACK' | ''."""

    payload_size: int
    """Layer-4 payload in bytes. 0 if no payload."""

    ttl: int
    """IP Time-To-Live (0–255)."""

    direction: str
    """One of: 'inbound' | 'outbound' | 'lateral'."""


# ---------------------------------------------------------------------------
# Stage 2 — Aggregation output  (canonical classes live in aggregation/models.py)
# ---------------------------------------------------------------------------

# These are re-exported here so downstream code (Alert, etc.) can import from
# backend.models without needing to know the internal sub-package layout.
from .aggregation.models import AggregatedWindow, FlowKey, FlowRecord  # noqa: E402


# ---------------------------------------------------------------------------
# Stage 3 — Detection output  (defined here; implemented in Phase 3)
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A threat alert produced by the detection engine."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = 0.0
    rule_name: str = ""
    """E.g. 'PORT_SCAN' | 'SYN_FLOOD' | 'BRUTE_FORCE' | 'DNS_TUNNELING' | 'BEACONING'."""

    severity: str = "LOW"
    """One of: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'."""

    confidence: float = 0.0
    """Detection confidence in [0.0, 1.0]."""

    src_ip: str = ""
    dst_ip: str | None = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    """Rule-specific evidence dict (sanitized before LLM use)."""

    raw_context: AggregatedWindow | None = None
    """The aggregation window that triggered detection (stripped before LLM send)."""


# ---------------------------------------------------------------------------
# Stage 4 — LLM output  (defined here; implemented in Phase 4)
# ---------------------------------------------------------------------------

@dataclass
class LLMExplanation:
    """Natural-language explanation produced by the LLM."""

    summary: str = ""
    """1–2 sentence plain-English explanation."""

    severity_reasoning: str = ""
    recommended_action: str = ""
    ioc_tags: List[str] = field(default_factory=list)
    """E.g. ['port-scan', 'reconnaissance']."""

    llm_confidence: str = "UNCERTAIN"
    """One of: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNCERTAIN'."""

    fallback_used: bool = False
    """True if LLM failed and a rule-based fallback was used."""


# ---------------------------------------------------------------------------
# Stage 5 — Final broadcast object  (defined here; implemented in Phase 5)
# ---------------------------------------------------------------------------

@dataclass
class EnrichedAlert:
    """Alert + LLM explanation, ready for WebSocket broadcast."""

    alert: Alert = field(default_factory=Alert)
    explanation: LLMExplanation = field(default_factory=LLMExplanation)
    enriched_at: float = 0.0
