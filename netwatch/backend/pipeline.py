"""
backend/pipeline.py

Defines all interprocess asyncio.Queue instances and the ring-buffer
safe_put() helper used by the capture layer to enqueue without blocking.

Queue sizing rationale (from design doc §2.3):
  capture_queue   = 10_000  — absorbs packet bursts before aggregation
  detection_queue =  1_000  — aggregated windows; much lower volume
  alert_queue     =    500  — alerts from detection engine
  enriched_queue  =    500  — LLM-enriched alerts ready for broadcast

All queues use safe_put() which drops the *oldest* item when full
(ring-buffer semantics) rather than blocking the producer.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .metrics import METRICS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Queue definitions — import these from other modules
# ---------------------------------------------------------------------------

# Lazily initialised so tests can create fresh queues without import side effects.
# Call init_queues() once at startup (done inside main.py).

_queues_ready: bool = False

capture_queue: asyncio.Queue | None = None
detection_queue: asyncio.Queue | None = None
alert_queue: asyncio.Queue | None = None
enriched_queue: asyncio.Queue | None = None


def init_queues(
    capture_size: int = 10_000,
    detection_size: int = 1_000,
    alert_size: int = 500,
    enriched_size: int = 500,
) -> None:
    """
    Initialise all pipeline queues.
    Must be called from within a running asyncio event loop.
    """
    global capture_queue, detection_queue, alert_queue, enriched_queue, _queues_ready
    capture_queue = asyncio.Queue(maxsize=capture_size)
    detection_queue = asyncio.Queue(maxsize=detection_size)
    alert_queue = asyncio.Queue(maxsize=alert_size)
    enriched_queue = asyncio.Queue(maxsize=enriched_size)
    _queues_ready = True
    logger.info(
        "Pipeline queues initialised — sizes: capture=%d detection=%d alert=%d enriched=%d",
        capture_size,
        detection_size,
        alert_size,
        enriched_size,
    )


# ---------------------------------------------------------------------------
# Ring-buffer put helper
# ---------------------------------------------------------------------------

async def safe_put(queue: asyncio.Queue, item: Any) -> bool:
    """
    Non-blocking enqueue with ring-buffer drop semantics.

    If the queue is full, the *oldest* item is discarded to make room,
    METRICS.packets_dropped is incremented, and a warning is logged.

    Returns:
        True  — item was enqueued successfully.
        False — item could not be enqueued (extremely unlikely race condition).
    """
    if queue.full():
        try:
            queue.get_nowait()  # discard oldest item
            METRICS.packets_dropped.inc()
            logger.warning(
                "Queue full (%d/%d) — oldest item dropped to make room",
                queue.qsize(),
                queue.maxsize,
            )
        except asyncio.QueueEmpty:
            pass  # queue was drained between the full() check and get_nowait()

    try:
        queue.put_nowait(item)
        return True
    except asyncio.QueueFull:
        # Extremely rare: another coroutine filled the queue in the tiny window
        # between our get_nowait() and put_nowait().
        METRICS.packets_dropped.inc()
        logger.error("safe_put: queue still full after drop — item lost")
        return False
