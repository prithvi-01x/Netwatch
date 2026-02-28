"""
capture/filter.py

BPF (Berkeley Packet Filter) string builder.

BPF filters are applied directly by libpcap at the kernel level,
so only matching packets are even handed to Python — this is the
first and cheapest line of filtering.

Usage:
    bpf = build_bpf_filter()                       # default: "ip"
    bpf = build_bpf_filter(protocols=["tcp","udp"]) # TCP + UDP only
    bpf = build_bpf_filter(exclude_ips=["10.0.0.1"])
"""

from __future__ import annotations

import logging
from typing import Sequence

logger = logging.getLogger(__name__)

# Allowed protocol keywords that libpcap understands
_VALID_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "arp", "ip", "ip6", "dns"})


def build_bpf_filter(
    protocols: Sequence[str] | None = None,
    exclude_ips: Sequence[str] | None = None,
    base: str = "ip",
) -> str:
    """
    Build a BPF filter string from high-level options.

    Args:
        protocols:   Optional list of protocols to include e.g. ['tcp', 'udp'].
                     When provided, only those protocols are captured.
                     When None, ``base`` is used (default: 'ip' = all IP traffic).
        exclude_ips: Optional list of host IPs to *exclude* from capture.
        base:        Root BPF clause when ``protocols`` is None. Default 'ip'.

    Returns:
        A BPF filter string ready to pass to Scapy's AsyncSniffer.

    Examples:
        >>> build_bpf_filter()
        'ip'
        >>> build_bpf_filter(protocols=['tcp', 'udp'])
        '(tcp or udp)'
        >>> build_bpf_filter(exclude_ips=['10.0.0.1', '10.0.0.2'])
        'ip and not (host 10.0.0.1 or host 10.0.0.2)'
        >>> build_bpf_filter(protocols=['tcp'], exclude_ips=['10.0.0.1'])
        '(tcp) and not (host 10.0.0.1)'
    """
    parts: list[str] = []

    # Protocol filter
    if protocols:
        validated = []
        for p in protocols:
            pl = p.lower()
            if pl not in _VALID_PROTOCOLS:
                logger.warning("Unknown protocol for BPF filter: %r — skipping", p)
                continue
            # libpcap doesn't have a 'dns' keyword; use port 53 instead
            if pl == "dns":
                validated.append("port 53")
            else:
                validated.append(pl)
        if validated:
            parts.append(f"({' or '.join(validated)})")
    else:
        parts.append(base)

    # IP exclusions
    if exclude_ips:
        host_clauses = " or ".join(f"host {ip}" for ip in exclude_ips)
        parts.append(f"not ({host_clauses})")

    bpf = " and ".join(parts) if parts else base
    logger.debug("Built BPF filter: %r", bpf)
    return bpf
