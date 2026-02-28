"""
api/main.py  — Phase 5

Added:
  - llm_routes registered at /api/llm
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocketDisconnect

from .routes import alerts as alerts_router
from .routes import config as config_router
from .routes import stats as stats_router
from .routes import docker as docker_router
from .routes import llm as llm_router
from .routes import host_ports as host_ports_router
from .routes import graph as graph_router
from .ws_manager import ws_manager

logger = logging.getLogger(__name__)

_repository = None
_pipeline_stats_ref: dict = {}


def set_repository(repo) -> None:
    global _repository
    _repository = repo


def get_repository():
    if _repository is None:
        raise RuntimeError("Repository not initialised — call set_repository() first")
    return _repository


def set_pipeline_stats(stats_dict: dict) -> None:
    global _pipeline_stats_ref
    _pipeline_stats_ref = stats_dict


def get_pipeline_stats() -> dict:
    return dict(_pipeline_stats_ref)


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("FastAPI startup")
        yield
        logger.info("FastAPI shutdown")
        if _repository is not None:
            _repository._db.close()

    app = FastAPI(
        title="NetWatch — Network Traffic Analyzer",
        version="5.0.0",
        description="Real-time network traffic analysis with AI-assisted detection",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:3001",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # REST routers
    app.include_router(alerts_router.router,     prefix="/api")
    app.include_router(stats_router.router,      prefix="/api")
    app.include_router(config_router.router,     prefix="/api")
    app.include_router(docker_router.router,     prefix="/api")
    app.include_router(llm_router.router,        prefix="/api")
    app.include_router(host_ports_router.router)  # has /api/host prefix built-in
    app.include_router(graph_router.router,       prefix="/api")

    # WebSockets
    @app.websocket("/ws/alerts")
    async def ws_alerts(websocket: WebSocket):
        await ws_manager.connect(websocket, "alerts")
        try:
            while True:
                await websocket.receive_text()
        except (WebSocketDisconnect, Exception):
            await ws_manager.disconnect(websocket, "alerts")

    @app.websocket("/ws/flows")
    async def ws_flows(websocket: WebSocket):
        await ws_manager.connect(websocket, "flows")
        try:
            while True:
                await websocket.receive_text()
        except (WebSocketDisconnect, Exception):
            await ws_manager.disconnect(websocket, "flows")

    @app.websocket("/ws/stats")
    async def ws_stats_channel(websocket: WebSocket):
        await ws_manager.connect(websocket, "stats")
        try:
            while True:
                await websocket.receive_text()
        except (WebSocketDisconnect, Exception):
            await ws_manager.disconnect(websocket, "stats")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "ws_connections": ws_manager.all_counts()}

    return app
