"""
api/ws_manager.py

WebSocketManager — manages active WebSocket connections across named channels.

Channels:
    "alerts" — receives Alert JSON as they fire
    "flows"  — receives top-10 flow snapshots every second
    "stats"  — receives pipeline stats every 5 seconds

Thread safety: designed to be called exclusively from asyncio coroutines.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages a set of named broadcast channels, each with N WebSocket clients."""

    def __init__(self) -> None:
        # channel → set of active WebSocket connections
        self._channels: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, websocket: WebSocket, channel: str) -> None:
        """Accept a new WebSocket and register it on the given channel."""
        await websocket.accept()
        self._channels[channel].add(websocket)
        logger.debug(
            "WS connected — channel=%r total=%d",
            channel,
            len(self._channels[channel]),
        )

    async def disconnect(self, websocket: WebSocket, channel: str) -> None:
        """Remove a WebSocket from its channel (no-op if not present)."""
        self._channels[channel].discard(websocket)
        logger.debug(
            "WS disconnected — channel=%r remaining=%d",
            channel,
            len(self._channels[channel]),
        )

    async def broadcast(self, channel: str, message: dict) -> None:
        """
        Send JSON-encoded *message* to all connections on *channel*.

        Silently removes connections that error during send.
        """
        if not self._channels[channel]:
            return

        payload = json.dumps(message, default=str)  # default=str handles datetime etc.
        dead: list[WebSocket] = []

        for ws in list(self._channels[channel]):
            try:
                await ws.send_text(payload)
            except (WebSocketDisconnect, RuntimeError, Exception) as exc:
                logger.debug("WS send failed (channel=%r): %s — removing", channel, exc)
                dead.append(ws)

        for ws in dead:
            self._channels[channel].discard(ws)

    def connection_count(self, channel: str) -> int:
        """Return the number of active connections on a channel."""
        return len(self._channels[channel])

    def all_counts(self) -> dict[str, int]:
        return {ch: len(conns) for ch, conns in self._channels.items()}


# Global singleton — imported by routes and main.py
ws_manager = WebSocketManager()
