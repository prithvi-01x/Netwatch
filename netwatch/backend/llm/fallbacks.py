"""
llm/fallbacks.py

Static fallback LLMExplanation objects — one per detection rule.

Used when:
  - Ollama is not running
  - LLM returns malformed output
  - Alert is below the LLM call threshold (low severity / confidence)
  - Rate limit or cooldown is active

Fallbacks are honest: they set fallback_used=True and llm_confidence="LOW"
so the frontend can show a visual indicator that AI enrichment was skipped.
"""

from __future__ import annotations

from .models import LLMExplanation

_DEFAULT = LLMExplanation(
    summary="A network anomaly was detected by an automated rule.",
    severity_reasoning="Severity assigned by rule confidence score.",
    recommended_action="Review the evidence and investigate the source IP.",
    ioc_tags=["anomaly"],
    attack_phase="unknown",
    llm_confidence="LOW",
    fallback_used=True,
)

RULE_FALLBACKS: dict[str, LLMExplanation] = {
    "port_scan": LLMExplanation(
        summary=(
            "A host performed a systematic scan of multiple destination ports, "
            "indicating network reconnaissance activity."
        ),
        severity_reasoning=(
            "Port scanning is typically the first phase of an attack — "
            "mapping which services are available before exploitation."
        ),
        recommended_action=(
            "Block the source IP at the firewall and investigate whether the "
            "scanning host is authorised on this network."
        ),
        ioc_tags=["port-scan", "reconnaissance", "automated-tool"],
        attack_phase="reconnaissance",
        llm_confidence="LOW",
        fallback_used=True,
    ),
    "syn_flood": LLMExplanation(
        summary=(
            "A high volume of TCP SYN packets with few or no SYN-ACK responses "
            "was detected — characteristic of a SYN flood denial-of-service attack."
        ),
        severity_reasoning=(
            "SYN floods exhaust server connection tables, causing legitimate "
            "connections to be rejected."
        ),
        recommended_action=(
            "Enable SYN cookies on the target host, apply rate limiting to "
            "incoming SYN packets, and block the source IP if single-source."
        ),
        ioc_tags=["syn-flood", "dos", "tcp-attack"],
        attack_phase="initial-access",
        llm_confidence="LOW",
        fallback_used=True,
    ),
    "brute_force": LLMExplanation(
        summary=(
            "A large number of rapid connection attempts to an authentication "
            "service were detected, consistent with automated credential stuffing "
            "or brute-force login attempts."
        ),
        severity_reasoning=(
            "Successful brute force gives the attacker valid credentials, "
            "enabling further access."
        ),
        recommended_action=(
            "Block the source IP, enable account lockout on the target service, "
            "and review authentication logs for any successful logins."
        ),
        ioc_tags=["brute-force", "credential-stuffing", "authentication"],
        attack_phase="initial-access",
        llm_confidence="LOW",
        fallback_used=True,
    ),
    "dns_tunneling": LLMExplanation(
        summary=(
            "Abnormally high DNS query volume or large DNS payloads were detected "
            "from a single host, which may indicate data exfiltration via DNS tunneling."
        ),
        severity_reasoning=(
            "DNS tunneling encodes data in DNS queries to bypass firewalls, "
            "a common covert exfiltration technique."
        ),
        recommended_action=(
            "Inspect DNS queries from the source IP, block unusual DNS patterns "
            "at the resolver, and check for data leaving the network."
        ),
        ioc_tags=["dns-tunneling", "exfiltration", "covert-channel"],
        attack_phase="exfiltration",
        llm_confidence="LOW",
        fallback_used=True,
    ),
    "beaconing": LLMExplanation(
        summary=(
            "A flow with suspiciously regular, low-rate packets to an unusual port "
            "was detected — a behavioral signature of malware C2 communication."
        ),
        severity_reasoning=(
            "Regular beaconing indicates an established C2 channel; "
            "the host may already be compromised."
        ),
        recommended_action=(
            "Isolate the source host immediately, perform a malware scan, "
            "and block the destination IP/port at the perimeter firewall."
        ),
        ioc_tags=["beaconing", "c2", "malware", "persistence"],
        attack_phase="c2",
        llm_confidence="LOW",
        fallback_used=True,
    ),
}


def get_fallback(rule_name: str) -> LLMExplanation:
    """Return the static fallback for rule_name, or the generic default."""
    return RULE_FALLBACKS.get(rule_name, _DEFAULT)
