"""
tests/test_sniffer.py

Integration-style tests for PacketCapture using mocked AsyncSniffer.
No live network interface required.

Strategy:
  - Patch `netwatch.backend.capture.sniffer.AsyncSniffer` at CLASS level
    using `_make_fake_class(packet)`. Because PacketCapture calls
    `AsyncSniffer(prn=self._packet_callback, ...)`, the fake's __init__
    receives the real callback via the `prn` keyword argument.
  - FakeAsyncSniffer.start() immediately fires that callback with the
    injected packet — no threads, no asyncio.sleep weirdness needed for
    synchronous phases.
  - The thread-safe bridge (run_coroutine_threadsafe) still fires, so
    async tests do use a short await asyncio.sleep(0.05) to let it settle.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP

from netwatch.backend.capture.sniffer import PacketCapture
from netwatch.backend.metrics import METRICS


@pytest.fixture(autouse=True)
def reset_metrics():
    """Reset metrics counters before each test."""
    METRICS.reset_all()
    yield


# ---------------------------------------------------------------------------
# Fake AsyncSniffer — used as a CLASS-level patch
# ---------------------------------------------------------------------------

class FakeAsyncSniffer:
    """
    Mimics Scapy's AsyncSniffer interface.

    Instantiated by PacketCapture via AsyncSniffer(iface=..., prn=callback, ...),
    so `self.prn` is automatically set to the real `_packet_callback`.
    """

    # Class-level packet to inject — set by _make_fake_class()
    _inject_packet = None

    def __init__(self, iface=None, prn=None, store=None, filter=None, **kwargs):
        self.iface = iface
        self.prn = prn        # ← receives self._packet_callback from PacketCapture
        self.store = store
        self.filter = filter

    def start(self):
        assert self.store is False, "store must be False to prevent RAM accumulation"
        if self._inject_packet is not None and self.prn is not None:
            self.prn(self._inject_packet)   # fire callback synchronously

    def stop(self):
        pass

    def join(self, timeout=None):
        pass


def _make_fake_class(packet):
    """Return a FakeAsyncSniffer *class* that injects *packet* when start() is called."""

    class _Fake(FakeAsyncSniffer):
        _inject_packet = packet

    return _Fake


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_syn_packet():
    pkt = IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) / TCP(
        sport=12345, dport=80, flags="S"
    )
    pkt.time = 1_700_000_000.0
    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPacketCapture:

    @pytest.mark.asyncio
    async def test_parsed_packet_reaches_queue(self):
        """A valid TCP SYN → parses to PacketMeta and lands on the queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        loop = asyncio.get_event_loop()

        capture = PacketCapture(
            queue=q, loop=loop, iface="lo",
            bpf_filter="ip", local_net="192.168.0.0/16",
        )
        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(make_syn_packet()),
        ):
            capture.start()

        await asyncio.sleep(0.05)   # let run_coroutine_threadsafe settle

        assert not q.empty(), "Queue should contain the parsed PacketMeta"
        meta = q.get_nowait()
        assert meta.protocol == "TCP"
        assert meta.flags == "SYN"
        assert meta.src_ip == "192.168.1.10"
        assert meta.dst_ip == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_metrics_incremented_on_valid_packet(self):
        """packets_received and packets_parsed_ok increment for a valid packet."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        loop = asyncio.get_event_loop()
        capture = PacketCapture(queue=q, loop=loop, iface="lo")

        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(make_syn_packet()),
        ):
            capture.start()

        await asyncio.sleep(0.05)

        assert METRICS.packets_received.value == 1
        assert METRICS.packets_parsed_ok.value == 1
        assert METRICS.packets_parse_error.value == 0

    @pytest.mark.asyncio
    async def test_non_ip_packet_not_queued(self):
        """Non-IP packet (ARP) → not queued, packets_non_ip incremented."""
        from scapy.layers.l2 import ARP, Ether

        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        loop = asyncio.get_event_loop()

        arp_pkt = Ether() / ARP()
        arp_pkt.time = 1_700_000_000.0

        capture = PacketCapture(queue=q, loop=loop, iface="lo")

        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(arp_pkt),
        ):
            capture.start()

        await asyncio.sleep(0.05)

        assert q.empty(), "Non-IP packets must not be queued"
        assert METRICS.packets_non_ip.value == 1
        assert METRICS.packets_parsed_ok.value == 0

    @pytest.mark.asyncio
    async def test_parse_error_increments_metric(self):
        """A packet that raises on haslayer() → packets_parse_error incremented."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        loop = asyncio.get_event_loop()

        bad_pkt = MagicMock()
        bad_pkt.time = 1_700_000_000.0
        bad_pkt.haslayer.side_effect = RuntimeError("simulated parse error")

        capture = PacketCapture(queue=q, loop=loop, iface="lo")

        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(bad_pkt),
        ):
            capture.start()

        await asyncio.sleep(0.05)

        assert q.empty()
        assert METRICS.packets_parse_error.value == 1

    def test_start_stop_lifecycle(self):
        """start() → is_running==True; stop() → is_running==False."""
        q: asyncio.Queue = asyncio.Queue(maxsize=10)
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        capture = PacketCapture(queue=q, loop=loop, iface="lo")

        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(None),   # no packet — just test lifecycle
        ):
            capture.start()
            assert capture.is_running is True
            capture.stop()
            assert capture.is_running is False

    def test_double_start_is_idempotent(self):
        """Calling start() twice should not raise or create two sniffers."""
        q: asyncio.Queue = asyncio.Queue(maxsize=10)
        loop = MagicMock(spec=asyncio.AbstractEventLoop)

        capture = PacketCapture(queue=q, loop=loop, iface="lo")

        with patch(
            "netwatch.backend.capture.sniffer.AsyncSniffer",
            _make_fake_class(None),
        ):
            capture.start()
            capture.start()  # second start should be a no-op
            assert capture.is_running is True
