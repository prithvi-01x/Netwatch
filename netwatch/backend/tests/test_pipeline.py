"""
tests/test_pipeline.py

Tests for pipeline.py — queue init + safe_put ring-buffer behavior.
"""

from __future__ import annotations

import asyncio

import pytest

from netwatch.backend.pipeline import init_queues, safe_put
from netwatch.backend.metrics import METRICS


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Reset drop counter before each test."""
    METRICS.packets_dropped.reset()
    yield


# ---------------------------------------------------------------------------
# init_queues
# ---------------------------------------------------------------------------

class TestInitQueues:

    def test_creates_all_queues(self):
        init_queues(capture_size=10, detection_size=5, alert_size=3, enriched_size=3)
        from netwatch.backend import pipeline
        assert pipeline.capture_queue.maxsize == 10
        assert pipeline.detection_queue.maxsize == 5
        assert pipeline.alert_queue.maxsize == 3
        assert pipeline.enriched_queue.maxsize == 3

    def test_queues_are_empty_after_init(self):
        init_queues(capture_size=5, detection_size=5, alert_size=5, enriched_size=5)
        from netwatch.backend import pipeline
        assert pipeline.capture_queue.empty()


# ---------------------------------------------------------------------------
# safe_put — ring-buffer behavior
# ---------------------------------------------------------------------------

class TestSafePut:

    @pytest.mark.asyncio
    async def test_puts_into_non_full_queue(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=3)
        result = await safe_put(q, "item1")
        assert result is True
        assert q.qsize() == 1

    @pytest.mark.asyncio
    async def test_drops_oldest_when_full(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        await q.put("old_1")
        await q.put("old_2")
        assert q.full()

        result = await safe_put(q, "new_1")
        assert result is True
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert items == ["old_2", "new_1"]

    @pytest.mark.asyncio
    async def test_increments_drop_counter(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=1)
        await q.put("first")
        before = METRICS.packets_dropped.value
        await safe_put(q, "second")
        after = METRICS.packets_dropped.value
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_succeeds_on_empty_queue(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        result = await safe_put(q, "data")
        assert result is True
        assert q.qsize() == 1

    @pytest.mark.asyncio
    async def test_sequential_puts_ring_buffer(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=3)
        for i in range(5):
            await safe_put(q, i)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert len(items) == 3
