"""
api/routes/config.py

GET /api/config  — return current in-memory detection thresholds
PUT /api/config  — update thresholds (takes effect on next window)

Uses a module-level singleton _live_config rather than a DB row,
so the pipeline can read it on every window without DB overhead.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from ..serializers import ConfigResponse, ConfigUpdateRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config", tags=["config"])


# ---------------------------------------------------------------------------
# In-memory live configuration singleton
# ---------------------------------------------------------------------------

_live_config: ConfigResponse = ConfigResponse(
    confidence_threshold=0.3,
    port_scan_min_ports=15,
    syn_flood_min_packets=100,
    brute_force_min_attempts=50,
    flow_expiry_seconds=60,
)


def get_live_config() -> ConfigResponse:
    """Return the current live configuration (read by the engine on each window)."""
    return _live_config


@router.get("", response_model=ConfigResponse)
async def read_config() -> ConfigResponse:
    """Return the current detection thresholds."""
    return _live_config


@router.put("", response_model=ConfigResponse)
async def update_config(update: ConfigUpdateRequest) -> ConfigResponse:
    """
    Update one or more detection thresholds.
    Only provided fields are changed; others remain unchanged.
    Changes take effect on the next aggregation window.
    """
    global _live_config

    current = _live_config.model_dump()
    patch = update.model_dump(exclude_none=True)
    current.update(patch)
    _live_config = ConfigResponse(**current)

    logger.info("Config updated: %s", patch)
    return _live_config
