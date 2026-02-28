"""
backend/metrics.py

Lightweight thread-safe counters for the capture pipeline.
No external dependencies — uses Python's threading.Lock.

Usage:
    from backend.metrics import METRICS
    METRICS.packets_received.inc()
    print(METRICS.as_dict())
"""

import threading


class Counter:
    """A thread-safe integer counter."""

    __slots__ = ("_value", "_lock")

    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, amount: int = 1) -> None:
        with self._lock:
            self._value += amount

    def reset(self) -> None:
        with self._lock:
            self._value = 0

    @property
    def value(self) -> int:
        with self._lock:
            return self._value

    def __repr__(self) -> str:  # pragma: no cover
        return f"Counter({self._value})"


class Metrics:
    """Singleton holding all pipeline counters."""

    def __init__(self) -> None:
        # --- Capture layer ---
        self.packets_received: Counter = Counter()
        """Raw Scapy callbacks fired."""

        self.packets_parsed_ok: Counter = Counter()
        """Packets that produced a valid PacketMeta."""

        self.packets_parse_error: Counter = Counter()
        """Packets that raised an exception during parsing."""

        self.packets_dropped: Counter = Counter()
        """PacketMeta objects that were dropped because the queue was full."""

        self.packets_non_ip: Counter = Counter()
        """Packets skipped because they have no IP layer (ARP, etc.)."""

    def as_dict(self) -> dict:
        """Return all counters as a plain dict (safe for JSON serialisation)."""
        return {
            "packets_received": self.packets_received.value,
            "packets_parsed_ok": self.packets_parsed_ok.value,
            "packets_parse_error": self.packets_parse_error.value,
            "packets_dropped": self.packets_dropped.value,
            "packets_non_ip": self.packets_non_ip.value,
        }

    def reset_all(self) -> None:
        """Reset every counter to zero (useful in tests)."""
        for attr in vars(self).values():
            if isinstance(attr, Counter):
                attr.reset()


# Module-level singleton — import from here everywhere
METRICS = Metrics()
