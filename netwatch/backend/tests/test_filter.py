"""
tests/test_filter.py

Tests for capture/filter.py — BPF filter string builder.
"""

from __future__ import annotations

from netwatch.backend.capture.filter import build_bpf_filter


class TestBuildBpfFilterDefaults:

    def test_default_filter_is_ip(self):
        assert build_bpf_filter() == "ip"

    def test_custom_base(self):
        assert build_bpf_filter(base="ether") == "ether"


class TestBuildBpfFilterProtocols:

    def test_single_protocol(self):
        result = build_bpf_filter(protocols=["tcp"])
        assert result == "(tcp)"

    def test_multiple_protocols(self):
        result = build_bpf_filter(protocols=["tcp", "udp"])
        assert result == "(tcp or udp)"

    def test_dns_becomes_port_53(self):
        result = build_bpf_filter(protocols=["dns"])
        assert result == "(port 53)"

    def test_unknown_protocol_skipped(self):
        result = build_bpf_filter(protocols=["tcp", "BANANA"])
        assert result == "(tcp)"

    def test_all_unknown_protocols_falls_back(self):
        result = build_bpf_filter(protocols=["BANANA", "MANGO"])
        # validated list is empty → falls back to no protocol clause
        # parts stays empty, returns base
        assert result == "ip"

    def test_case_insensitive(self):
        result = build_bpf_filter(protocols=["TCP", "UDP"])
        assert result == "(tcp or udp)"


class TestBuildBpfFilterExcludeIps:

    def test_single_ip_exclusion(self):
        result = build_bpf_filter(exclude_ips=["10.0.0.1"])
        assert result == "ip and not (host 10.0.0.1)"

    def test_multiple_ip_exclusions(self):
        result = build_bpf_filter(exclude_ips=["10.0.0.1", "10.0.0.2"])
        assert result == "ip and not (host 10.0.0.1 or host 10.0.0.2)"


class TestBuildBpfFilterCombined:

    def test_protocol_and_exclusion(self):
        result = build_bpf_filter(protocols=["tcp"], exclude_ips=["10.0.0.1"])
        assert result == "(tcp) and not (host 10.0.0.1)"

    def test_dns_and_exclusion(self):
        result = build_bpf_filter(protocols=["dns"], exclude_ips=["10.0.0.1"])
        assert result == "(port 53) and not (host 10.0.0.1)"
