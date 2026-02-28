"""
llm/prompt_builder.py

Builds sanitized prompts for the LLM from Alert dicts.

Security:
  - Whitelist-only evidence fields — raw payloads never reach the LLM.
  - Pattern-match and replace known injection strings.
  - All string fields are truncated and stripped of control characters.
  - The system prompt explicitly defines the model's role and output schema.
"""

from __future__ import annotations

import hashlib
import json
import re

_MAX_STRING_LEN = 120
_MAX_EVIDENCE_JSON_LEN = 600

# Injection patterns — replace match with a sanitized token
_INJECTION_RE = re.compile(
    r"ignore\s+(previous|all|prior)\s+instructions?"
    r"|you\s+are\s+(now|a)\s+"
    r"|forget\s+(everything|all|your)"
    r"|system\s*:"
    r"|assistant\s*:"
    r"|<\s*/?\s*(system|user|assistant)"
    r"|\[INST\]"
    r"|###\s*(instruction|system)",
    re.IGNORECASE,
)

# Only these evidence keys are allowed through to the LLM
_ALLOWED_EVIDENCE_KEYS = frozenset({
    "port_count", "unique_ports_contacted", "sampled_ports",
    "syn_rate", "total_syn_packets", "syn_only_flow_count", "peak_syn_rate",
    "target_ips", "attempt_count", "attempts_per_minute", "rst_ratio", "service",
    "query_entropy", "flagged_query_count", "queries_per_minute",
    "interval_variance", "mean_interval_sec", "connection_count",
    "duration_seconds", "packets_per_second", "avg_payload_size",
    "dst_port", "window_size_seconds", "threshold",
    "attack_type", "unique_sources",
})

SYSTEM_PROMPT = """\
You are a network security analyst assistant.
You will receive structured data about a detected network anomaly.
Your task: provide a clear, accurate security explanation.

RULES:
- Respond ONLY with valid JSON matching the schema below.
- No text before or after the JSON object.
- If uncertain, set llm_confidence to "UNCERTAIN".
- Do not speculate about attribution or actor identity.
- Base analysis ONLY on the provided data.

OUTPUT SCHEMA (respond with exactly this structure):
{
  "summary": "<1-2 sentence plain-English explanation>",
  "severity_reasoning": "<why this severity was assigned>",
  "recommended_action": "<one specific actionable step>",
  "ioc_tags": ["<tag1>", "<tag2>"],
  "llm_confidence": "HIGH|MEDIUM|LOW|UNCERTAIN",
  "attack_phase": "reconnaissance|initial-access|lateral-movement|exfiltration|c2|unknown"
}"""

_USER_TEMPLATE = """\
ANOMALY DETECTED — ANALYSIS REQUIRED

Detection Rule: {rule_name}
Timestamp: {timestamp_iso}
Source IP: {src_ip}
Destination IP: {dst_ip}
Severity: {severity}
Rule Confidence: {confidence}

Evidence Summary:
{evidence_json}

Network Context (window: {window_size}s):
- Total packets: {total_packets}
- Unique source IPs: {unique_src}
- Unique dest ports: {unique_dst_ports}
- Protocol mix: {protocols}

Provide your security analysis as JSON."""


def _sanitize_str(value: str) -> str:
    """Truncate, strip injection patterns and control characters."""
    value = str(value)[:_MAX_STRING_LEN]
    if _INJECTION_RE.search(value):
        return f"[SANITIZED:{hashlib.md5(value.encode()).hexdigest()[:8]}]"
    # Strip control characters and null bytes
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    value = value.replace('"', '\\"').replace("\n", " ").replace("\r", "")
    return value


def _sanitize_evidence(evidence: dict) -> dict:
    """Return a safe, minimal evidence dict containing only whitelisted keys."""
    safe: dict = {}
    for k, v in evidence.items():
        if k not in _ALLOWED_EVIDENCE_KEYS:
            continue
        if isinstance(v, (int, float)):
            safe[k] = v
        elif isinstance(v, str):
            safe[k] = _sanitize_str(v)
        elif isinstance(v, (list, tuple)):
            safe[k] = [
                _sanitize_str(str(item)) if isinstance(item, str) else item
                for item in list(v)[:10]
                if isinstance(item, (str, int, float))
            ]
        # Anything else (nested dicts, objects) is silently dropped
    return safe


def build_prompt(alert_dict: dict, window_context: dict | None = None) -> tuple[str, str]:
    """
    Build (system_prompt, user_prompt) from an alert dict.

    Args:
        alert_dict: Serialized Alert (plain dict from _alert_to_dict).
        window_context: Optional dict with window-level stats for extra context.

    Returns:
        (system_prompt, user_prompt) — both strings, safe to send to LLM.
    """
    from datetime import datetime, timezone

    safe_evidence = _sanitize_evidence(alert_dict.get("evidence", {}))
    evidence_json = json.dumps(safe_evidence, indent=2)[:_MAX_EVIDENCE_JSON_LEN]

    ts = alert_dict.get("timestamp", 0)
    try:
        ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        ts_iso = "unknown"

    ctx = window_context or {}

    user_prompt = _USER_TEMPLATE.format(
        rule_name=_sanitize_str(alert_dict.get("rule_name", "unknown")),
        timestamp_iso=ts_iso,
        src_ip=_sanitize_str(alert_dict.get("src_ip", "unknown")),
        dst_ip=_sanitize_str(alert_dict.get("dst_ip", "unknown")),
        severity=alert_dict.get("severity", "UNKNOWN"),
        confidence=round(float(alert_dict.get("confidence", 0)), 2),
        evidence_json=evidence_json,
        window_size=alert_dict.get("window_size_seconds", "?"),
        total_packets=ctx.get("total_packets", "?"),
        unique_src=ctx.get("unique_src_count", "?"),
        unique_dst_ports=ctx.get("unique_dst_ports_count", "?"),
        protocols=str(ctx.get("protocol_counts", {}))[:80],
    )

    return SYSTEM_PROMPT, user_prompt
