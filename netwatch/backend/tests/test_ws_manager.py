"""
tests/test_ws_manager.py

Tests for api/ws_manager.py — WebSocket channel manager.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatch.backend.api.ws_manager import WebSocketManager


@pytest.fixture
def manager():
    return WebSocketManager()


def mock_ws(accept_side_effect=None):
    ws = AsyncMock()
    ws.accept = AsyncMock(side_effect=accept_side_effect)
    ws.send_text = AsyncMock()
    return ws


class TestConnect:

    @pytest.mark.asyncio
    async def test_connect_accepts_and_registers(self, manager):
        ws = mock_ws()
        await manager.connect(ws, "alerts")
        ws.accept.assert_called_once()
        assert manager.connection_count("alerts") == 1

    @pytest.mark.asyncio
    async def test_multiple_connections_on_same_channel(self, manager):
        ws1 = mock_ws()
        ws2 = mock_ws()
        await manager.connect(ws1, "alerts")
        await manager.connect(ws2, "alerts")
        assert manager.connection_count("alerts") == 2


class TestDisconnect:

    @pytest.mark.asyncio
    async def test_disconnect_removes_connection(self, manager):
        ws = mock_ws()
        await manager.connect(ws, "alerts")
        await manager.disconnect(ws, "alerts")
        assert manager.connection_count("alerts") == 0

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_is_noop(self, manager):
        ws = mock_ws()
        # Should not raise
        await manager.disconnect(ws, "alerts")
        assert manager.connection_count("alerts") == 0


class TestBroadcast:

    @pytest.mark.asyncio
    async def test_broadcast_sends_json_to_all(self, manager):
        ws1 = mock_ws()
        ws2 = mock_ws()
        await manager.connect(ws1, "alerts")
        await manager.connect(ws2, "alerts")

        message = {"type": "alert", "rule": "port_scan"}
        await manager.broadcast("alerts", message)

        expected = json.dumps(message, default=str)
        ws1.send_text.assert_called_once_with(expected)
        ws2.send_text.assert_called_once_with(expected)

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self, manager):
        ws_good = mock_ws()
        ws_bad = mock_ws()
        ws_bad.send_text = AsyncMock(side_effect=RuntimeError("connection reset"))

        await manager.connect(ws_good, "stats")
        await manager.connect(ws_bad, "stats")
        assert manager.connection_count("stats") == 2

        await manager.broadcast("stats", {"data": 1})

        # Bad connection should have been removed
        assert manager.connection_count("stats") == 1
        ws_good.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_to_empty_channel_is_noop(self, manager):
        # Should not raise
        await manager.broadcast("nonexistent", {"data": 1})

    @pytest.mark.asyncio
    async def test_broadcast_handles_datetime_objects(self, manager):
        """default=str ensures non-JSON types like datetime are handled."""
        from datetime import datetime
        ws = mock_ws()
        await manager.connect(ws, "test")
        await manager.broadcast("test", {"time": datetime(2025, 1, 1)})
        ws.send_text.assert_called_once()
        payload = ws.send_text.call_args[0][0]
        assert "2025" in payload


class TestConnectionCount:

    @pytest.mark.asyncio
    async def test_all_counts(self, manager):
        ws1 = mock_ws()
        ws2 = mock_ws()
        await manager.connect(ws1, "alerts")
        await manager.connect(ws2, "stats")

        counts = manager.all_counts()
        assert counts["alerts"] == 1
        assert counts["stats"] == 1

    @pytest.mark.asyncio
    async def test_unknown_channel_returns_zero(self, manager):
        assert manager.connection_count("nonexistent") == 0
