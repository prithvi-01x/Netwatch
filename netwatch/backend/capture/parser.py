"""
capture/parser.py

Converts a raw Scapy packet into a typed PacketMeta dataclass.

Design principles (from design doc §3.3):
  - This function is called from Scapy's callback thread (not asyncio).
    It must be synchronous and fast — no I/O, no blocking calls.
  - Returns None for non-IP packets (ARP, Ethernet-only, etc.),
    so the caller can safely skip them.
  - Never stores the original Scapy packet object; extracts only
    the fields we need so libpcap memory can be freed immediately.

Direction classification:
  - 'outbound' : src_ip is in local_network
  - 'inbound'  : dst_ip is in local_network (and src is external)
  - 'lateral'  : both IPs are local (internal east-west traffic)

TCP flags mapping (Scapy flags bitmask → human-readable string):
  SYN only          → 'SYN'
  SYN+ACK           → 'SYN-ACK'
  FIN               → 'FIN'
  RST               → 'RST'
  ACK only          → 'ACK'
  anything else     → '' (empty string)
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet  # type: ignore[import-untyped]

from ..models import PacketMeta

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TCP flag constants (Scapy uses a FlagValue / string notation)
# ---------------------------------------------------------------------------
_F_SYN = 0x02
_F_ACK = 0x10
_F_FIN = 0x01
_F_RST = 0x04
_F_PSH = 0x08
_F_URG = 0x20

# Flags that indicate data-bearing segments (PSH, URG)
# When any of these are set alongside ACK we treat the combination as unlabelled ("")
_F_DATA_FLAGS = _F_PSH | _F_URG

_DEFAULT_LOCAL_NET = ipaddress.ip_network("192.168.0.0/16")


def _parse_tcp_flags(flags_int: int) -> str:
    """
    Convert the TCP flags integer to a human-readable label.

    Only the most security-relevant flag combinations are labelled.
    ACK is returned only when it is the SOLE flag set (pure acknowledgement).
    Combinations like PSH+ACK or URG+ACK carry data and are not labelled.
    """
    syn = bool(flags_int & _F_SYN)
    ack = bool(flags_int & _F_ACK)
    fin = bool(flags_int & _F_FIN)
    rst = bool(flags_int & _F_RST)

    if syn and ack:
        return "SYN-ACK"
    if syn:
        return "SYN"
    if rst:
        return "RST"
    if fin:
        return "FIN"
    # ACK only when no data-bearing flags (PSH, URG) are also set
    if ack and not (flags_int & _F_DATA_FLAGS):
        return "ACK"
    return ""


def _classify_direction(
    src_ip: str,
    dst_ip: str,
    local_net: ipaddress.IPv4Network,
) -> str:
    """
    Classify traffic direction relative to the monitored local network.

    Returns one of: 'outbound' | 'inbound' | 'lateral'
    """
    try:
        src_addr = ipaddress.ip_address(src_ip)
        dst_addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return "lateral"  # malformed IP — treat as lateral, don't crash

    src_local = src_addr in local_net
    dst_local = dst_addr in local_net

    if src_local and dst_local:
        return "lateral"
    if src_local:
        return "outbound"
    if dst_local:
        return "inbound"
    # Neither IP is in the local network — transit / tunnelled traffic
    return "lateral"


def parse_packet(
    pkt: "Packet",
    local_net: ipaddress.IPv4Network | None = None,
) -> PacketMeta | None:
    """
    Parse a raw Scapy packet into a PacketMeta.

    Args:
        pkt:       Raw Scapy packet from AsyncSniffer callback.
        local_net: Your local network in CIDR notation (used for direction).
                   Defaults to 192.168.0.0/16.

    Returns:
        PacketMeta on success, None if the packet has no IP layer.
    """
    # Lazy import keeps this module importable without scapy in test env
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore[import-untyped]
        from scapy.layers.dns import DNS  # type: ignore[import-untyped]
    except ImportError:  # pragma: no cover
        raise

    if not pkt.haslayer(IP):
        return None  # ARP, raw Ethernet, etc. — caller increments non_ip counter

    net = local_net if local_net is not None else _DEFAULT_LOCAL_NET

    ip_layer = pkt[IP]
    src_ip: str = ip_layer.src
    dst_ip: str = ip_layer.dst
    ttl: int = int(ip_layer.ttl)
    timestamp: float = float(pkt.time) if hasattr(pkt, "time") else time.time()

    # -----------------------------------------------------------------------
    # Protocol, port, flags and payload extraction
    # -----------------------------------------------------------------------
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""
    payload_size: int = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = _parse_tcp_flags(int(tcp.flags))
        payload_size = len(bytes(tcp.payload)) if tcp.payload else 0
        protocol = "TCP"

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        payload_size = len(bytes(udp.payload)) if udp.payload else 0
        # Classify DNS before generic UDP
        if pkt.haslayer(DNS) or dst_port == 53 or src_port == 53:
            protocol = "DNS"
        else:
            protocol = "UDP"

    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        # ICMP payload = the data carried inside, e.g. ping payload
        icmp = pkt[ICMP]
        payload_size = len(bytes(icmp.payload)) if icmp.payload else 0

    else:
        protocol = "OTHER"

    direction = _classify_direction(src_ip, dst_ip, net)

    return PacketMeta(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        payload_size=payload_size,
        ttl=ttl,
        direction=direction,
    )
