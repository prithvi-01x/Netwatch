"""
tests/test_parser.py

Parametrized tests for capture/parser.py.
All tests use in-memory Scapy packet construction — NO live network required.
"""

from __future__ import annotations

import ipaddress

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP

from netwatch.backend.capture.parser import (
    _classify_direction,
    _parse_tcp_flags,
    parse_packet,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LOCAL_NET = ipaddress.ip_network("192.168.0.0/16")


def make_tcp(
    src="192.168.1.10",
    dst="8.8.8.8",
    sport=12345,
    dport=80,
    flags="S",      # Scapy flag notation: S=SYN, SA=SYN-ACK, R=RST, F=FIN, A=ACK
    payload=b"",
    ttl=64,
):
    pkt = IP(src=src, dst=dst, ttl=ttl) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / payload
    pkt.time = 1_700_000_000.0
    return pkt


def make_udp(src="192.168.1.10", dst="8.8.8.8", sport=5000, dport=9999, payload=b"hello"):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / payload
    pkt.time = 1_700_000_000.0
    return pkt


def make_dns_query(src="192.168.1.10", dst="8.8.8.8"):
    pkt = (
        IP(src=src, dst=dst)
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    pkt.time = 1_700_000_000.0
    return pkt


def make_icmp(src="10.0.0.1", dst="192.168.1.10"):
    pkt = IP(src=src, dst=dst) / ICMP()
    pkt.time = 1_700_000_000.0
    return pkt


# ---------------------------------------------------------------------------
# _parse_tcp_flags
# ---------------------------------------------------------------------------

class TestParseTcpFlags:
    @pytest.mark.parametrize("flags_int,expected", [
        (0x02, "SYN"),          # SYN only
        (0x12, "SYN-ACK"),      # SYN + ACK
        (0x04, "RST"),          # RST
        (0x01, "FIN"),          # FIN
        (0x10, "ACK"),          # ACK only
        (0x18, ""),             # PSH + ACK → no named label
        (0x00, ""),             # no flags
    ])
    def test_flag_mapping(self, flags_int, expected):
        assert _parse_tcp_flags(flags_int) == expected


# ---------------------------------------------------------------------------
# _classify_direction
# ---------------------------------------------------------------------------

class TestClassifyDirection:
    def test_outbound(self):
        assert _classify_direction("192.168.1.10", "8.8.8.8", LOCAL_NET) == "outbound"

    def test_inbound(self):
        assert _classify_direction("8.8.8.8", "192.168.1.10", LOCAL_NET) == "inbound"

    def test_lateral(self):
        assert _classify_direction("192.168.1.10", "192.168.1.20", LOCAL_NET) == "lateral"

    def test_both_external(self):
        # e.g. transit traffic — treated as lateral
        assert _classify_direction("1.2.3.4", "5.6.7.8", LOCAL_NET) == "lateral"

    def test_malformed_ip(self):
        # Should not raise, falls back to 'lateral'
        assert _classify_direction("999.999.999.999", "bad", LOCAL_NET) == "lateral"


# ---------------------------------------------------------------------------
# parse_packet — main function
# ---------------------------------------------------------------------------

class TestParsePacket:

    # -----------------------------------------------------------------------
    # Non-IP packets
    # -----------------------------------------------------------------------

    def test_non_ip_returns_none(self):
        from scapy.layers.l2 import ARP, Ether
        arp = Ether() / ARP()
        result = parse_packet(arp, LOCAL_NET)
        assert result is None

    # -----------------------------------------------------------------------
    # TCP
    # -----------------------------------------------------------------------

    def test_tcp_syn(self):
        pkt = make_tcp(flags="S")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.protocol == "TCP"
        assert meta.flags == "SYN"
        assert meta.src_ip == "192.168.1.10"
        assert meta.dst_ip == "8.8.8.8"
        assert meta.src_port == 12345
        assert meta.dst_port == 80
        assert meta.payload_size == 0
        assert meta.ttl == 64
        assert meta.direction == "outbound"

    def test_tcp_syn_ack(self):
        pkt = make_tcp(src="8.8.8.8", dst="192.168.1.10", flags="SA")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.flags == "SYN-ACK"
        assert meta.direction == "inbound"

    def test_tcp_rst(self):
        pkt = make_tcp(flags="R")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.flags == "RST"

    def test_tcp_fin(self):
        pkt = make_tcp(flags="F")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.flags == "FIN"

    def test_tcp_with_payload(self):
        pkt = make_tcp(flags="PA", payload=b"GET / HTTP/1.1\r\n")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.payload_size == len(b"GET / HTTP/1.1\r\n")

    def test_tcp_lateral(self):
        pkt = make_tcp(src="192.168.1.5", dst="192.168.1.20")
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.direction == "lateral"

    def test_tcp_timestamp(self):
        pkt = make_tcp()
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.timestamp == pytest.approx(1_700_000_000.0)

    # -----------------------------------------------------------------------
    # UDP
    # -----------------------------------------------------------------------

    def test_udp_basic(self):
        pkt = make_udp(dport=9999)
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.protocol == "UDP"
        assert meta.flags == ""
        assert meta.src_port == 5000
        assert meta.dst_port == 9999
        assert meta.payload_size == len(b"hello")

    # -----------------------------------------------------------------------
    # DNS
    # -----------------------------------------------------------------------

    def test_dns_query_detected_by_layer(self):
        pkt = make_dns_query()
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.protocol == "DNS"
        assert meta.dst_port == 53

    def test_udp_port_53_without_dns_layer(self):
        """UDP to port 53 with no DNS layer should still be classified DNS."""
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=54321, dport=53) / b"\x00\x01"
        pkt.time = 1_700_000_000.0
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.protocol == "DNS"

    # -----------------------------------------------------------------------
    # ICMP
    # -----------------------------------------------------------------------

    def test_icmp_basic(self):
        pkt = make_icmp()
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.protocol == "ICMP"
        assert meta.src_port == 0
        assert meta.dst_port == 0
        assert meta.flags == ""

    # -----------------------------------------------------------------------
    # Edge cases
    # -----------------------------------------------------------------------

    def test_ttl_preserved(self):
        pkt = make_tcp(ttl=128)
        meta = parse_packet(pkt, LOCAL_NET)
        assert meta is not None
        assert meta.ttl == 128

    def test_default_local_net(self):
        """parse_packet should work without explicit local_net."""
        pkt = make_tcp()
        meta = parse_packet(pkt)  # uses 192.168.0.0/16 default
        assert meta is not None
        assert meta.direction == "outbound"  # 192.168.1.10 is in default net
