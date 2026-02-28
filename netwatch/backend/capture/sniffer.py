"""
capture/sniffer.py

PacketCapture — wraps Scapy's AsyncSniffer and bridges it safely
into the asyncio event loop via asyncio.run_coroutine_threadsafe.

Key design decisions (from design doc §3.3):
  - AsyncSniffer runs its callback in a SEPARATE THREAD managed by libpcap.
    We must never await or put() to an asyncio.Queue from that thread directly.
    Instead, we use run_coroutine_threadsafe() to schedule safe_put() on the
    main event loop from the callback thread.
  - store=False: Scapy must NEVER accumulate captured packets in RAM.
  - The BPF filter is applied at kernel level (cheapest possible rejection).
  - This module is intentionally thin — parsing logic lives in parser.py.

Lifecycle:
    capture = PacketCapture(queue, loop, iface="eth0")
    capture.start()
    # ... asyncio event loop runs ...
    capture.stop()
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from ..metrics import METRICS
from ..pipeline import safe_put
from .parser import parse_packet

# Import AsyncSniffer at module level so tests can patch it as a module attribute.
# The try/except allows importing this module in environments where scapy is not
# installed (e.g. type-checking), though scapy IS required at runtime.
try:
    from scapy.all import AsyncSniffer  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    AsyncSniffer = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Wraps Scapy's AsyncSniffer with a thread-safe asyncio.Queue bridge.

    The sniffer runs in a background thread (managed by libpcap / Scapy).
    Each captured packet is parsed synchronously in the callback thread,
    then the result is scheduled onto the asyncio event loop via
    run_coroutine_threadsafe.

    Args:
        queue:      asyncio.Queue[PacketMeta] — the capture queue from pipeline.py
        loop:       The running asyncio event loop (get with asyncio.get_event_loop())
        iface:      Network interface name, e.g. 'eth0', 'wlan0', 'lo'
        bpf_filter: BPF filter string (see capture/filter.py)
        local_net:  Local network CIDR for direction classification
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        iface: str = "eth0",
        bpf_filter: str = "ip",
        local_net: str = "192.168.0.0/16",
    ) -> None:
        self._queue = queue
        self._loop = loop
        self._iface = iface
        self._bpf_filter = bpf_filter
        self._local_net = ipaddress.ip_network(local_net, strict=False)
        self._sniffer = None
        self._running = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Callback — executes in Scapy's capture thread
    # ------------------------------------------------------------------

    def _packet_callback(self, pkt) -> None:
        """
        Called by Scapy for every captured packet.

        This runs in the libpcap/Scapy background thread.
        All work must be synchronous and fast.
        """
        METRICS.packets_received.inc()

        try:
            meta = parse_packet(pkt, local_net=self._local_net)
        except Exception as exc:
            METRICS.packets_parse_error.inc()
            logger.debug("Packet parse error: %s", exc, exc_info=False)
            return

        if meta is None:
            # Non-IP packet (ARP etc.) — silently skip
            METRICS.packets_non_ip.inc()
            return

        METRICS.packets_parsed_ok.inc()

        # Schedule safe_put on the asyncio event loop from this thread
        asyncio.run_coroutine_threadsafe(
            safe_put(self._queue, meta),
            self._loop,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the sniffer in its background thread."""
        with self._lock:
            if self._running:
                logger.warning("PacketCapture.start() called but already running")
                return

            if AsyncSniffer is None:  # pragma: no cover
                raise RuntimeError(
                    "scapy is not installed. Install it with: pip install scapy"
                )

            logger.info(
                "Starting packet capture — iface=%r filter=%r local_net=%s",
                self._iface,
                self._bpf_filter,
                self._local_net,
            )

            self._sniffer = AsyncSniffer(
                iface=self._iface,
                prn=self._packet_callback,
                store=False,          # CRITICAL: never accumulate in RAM
                filter=self._bpf_filter,
            )
            self._sniffer.start()
            self._running = True
            logger.info("PacketCapture started")

    def stop(self) -> None:
        """Gracefully stop the sniffer and wait for its thread to finish."""
        with self._lock:
            if not self._running:
                return
            if self._sniffer is not None:
                logger.info("Stopping packet capture…")
                try:
                    self._sniffer.stop()
                    # join() waits for the sniffer thread to exit cleanly
                    self._sniffer.join(timeout=5.0)
                except Exception as exc:  # pragma: no cover
                    logger.warning("Error stopping sniffer: %s", exc)
                finally:
                    self._sniffer = None
            self._running = False
            logger.info(
                "PacketCapture stopped — metrics: %s",
                METRICS.as_dict(),
            )

    @property
    def is_running(self) -> bool:
        return self._running

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"PacketCapture(iface={self._iface!r}, "
            f"filter={self._bpf_filter!r}, "
            f"running={self._running})"
        )
