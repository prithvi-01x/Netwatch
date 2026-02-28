"""
api/routes/stats.py

GET /api/stats         — aggregate statistics + live pipeline counters
GET /api/stats/history — recent stats snapshots
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ...storage.repository import AlertRepository
from ..serializers import StatsResponse

router = APIRouter(prefix="/stats", tags=["stats"])


def _get_repo() -> AlertRepository:
    from ..main import get_repository
    return get_repository()


def _get_pipeline_stats() -> dict:
    from ..main import get_pipeline_stats
    return get_pipeline_stats()


@router.get("", response_model=StatsResponse)
async def get_stats(
    repo: AlertRepository = Depends(_get_repo),
) -> StatsResponse:
    """Return aggregate alert statistics plus live pipeline counters."""
    summary = repo.get_stats_summary()
    pipeline = _get_pipeline_stats()
    return StatsResponse(
        total_alerts=summary["total_alerts"],
        alerts_last_hour=summary["alerts_last_hour"],
        alerts_by_severity=summary.get("alerts_by_severity", {}),
        alerts_by_rule=summary.get("alerts_by_rule", {}),
        top_src_ips=summary.get("top_src_ips", []),
        latest_alert_timestamp=summary.get("latest_alert_timestamp"),
        pipeline_stats=pipeline,
    )


@router.get("/history")
async def get_stats_history(
    limit: Annotated[int, Query(ge=1, le=1000)] = 60,
    repo: AlertRepository = Depends(_get_repo),
) -> list[dict]:
    """Return recent stats snapshots (newest first)."""
    return repo.get_recent_stats_snapshots(limit=limit)
