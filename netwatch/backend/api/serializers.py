"""
api/serializers.py  — Phase 5 update

Added llm_explanation field to AlertResponse.
"""

from __future__ import annotations
from pydantic import BaseModel


class LLMExplanationResponse(BaseModel):
    summary: str
    severity_reasoning: str
    recommended_action: str
    ioc_tags: list[str] = []
    attack_phase: str = "unknown"
    llm_confidence: str = "LOW"
    fallback_used: bool = False


class AlertResponse(BaseModel):
    alert_id: str
    timestamp: float
    rule_name: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: str
    description: str
    evidence: dict
    window_start: float
    window_end: float
    window_size_seconds: int
    llm_explanation: LLMExplanationResponse | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_dict(cls, d: dict) -> "AlertResponse":
        llm_raw = d.get("llm_explanation")
        llm = None
        if isinstance(llm_raw, dict):
            try:
                llm = LLMExplanationResponse(**llm_raw)
            except Exception:
                llm = None

        return cls(
            alert_id=d["alert_id"],
            timestamp=d["timestamp"],
            rule_name=d["rule_name"],
            severity=d["severity"],
            confidence=d["confidence"],
            src_ip=d["src_ip"],
            dst_ip=d["dst_ip"],
            description=d["description"],
            evidence=d.get("evidence", {}),
            window_start=d.get("window_start", 0.0),
            window_end=d.get("window_end", 0.0),
            window_size_seconds=d.get("window_size_sec", d.get("window_size_seconds", 0)),
            llm_explanation=llm,
        )


class PaginatedAlertsResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    limit: int
    offset: int
    has_more: bool


class StatsResponse(BaseModel):
    total_alerts: int
    alerts_last_hour: int
    alerts_by_severity: dict[str, int]
    alerts_by_rule: dict[str, int]
    top_src_ips: list[dict]
    latest_alert_timestamp: float | None
    pipeline_stats: dict


class ConfigResponse(BaseModel):
    confidence_threshold: float
    port_scan_min_ports: int
    syn_flood_min_packets: int
    brute_force_min_attempts: int
    flow_expiry_seconds: int


class ConfigUpdateRequest(BaseModel):
    confidence_threshold: float | None = None
    port_scan_min_ports: int | None = None
    syn_flood_min_packets: int | None = None
    brute_force_min_attempts: int | None = None
    flow_expiry_seconds: int | None = None


class PortInfo(BaseModel):
    port: int
    protocol: str
    service: str
    state: str


class ContainerInfo(BaseModel):
    name: str
    image: str
    status: str
    ports: list[PortInfo]
    networks: list[str]
    ip: str
    cpu: str | None = None
    memory: str | None = None
    internal: bool


class TopologyResponse(BaseModel):
    containers: list[ContainerInfo]


class LLMStatusResponse(BaseModel):
    enabled: bool
    available: bool
    model: str
    ollama_url: str
    cache_size: int
    cache_hit_rate: float
    calls_made: int
    fallbacks_used: int
    timeouts: int
