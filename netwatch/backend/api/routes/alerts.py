"""
api/routes/alerts.py

GET /api/alerts        — paginated alert list with optional filters
GET /api/alerts/{id}   — single alert lookup
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ...storage.repository import AlertRepository
from ..serializers import AlertResponse, PaginatedAlertsResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_repo() -> AlertRepository:
    """FastAPI dependency — replaced in tests via app.dependency_overrides."""
    from ..main import get_repository
    return get_repository()


@router.get("", response_model=PaginatedAlertsResponse)
async def list_alerts(
    limit:     Annotated[int,          Query(ge=1, le=500)] = 100,
    offset:    Annotated[int,          Query(ge=0)]         = 0,
    rule_name: Annotated[str | None,   Query()]             = None,
    severity:  Annotated[str | None,   Query()]             = None,
    src_ip:    Annotated[str | None,   Query()]             = None,
    since:     Annotated[float | None, Query()]             = None,
    repo:      AlertRepository = Depends(_get_repo),
) -> PaginatedAlertsResponse:
    """Return a paginated list of alerts, newest first."""
    filters = dict(rule_name=rule_name, severity=severity, src_ip=src_ip, since=since)
    rows = repo.get_alerts(limit=limit, offset=offset, **filters)
    total = repo.get_alert_count(**filters)
    items = [AlertResponse.from_dict(r) for r in rows]
    return PaginatedAlertsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    repo: AlertRepository = Depends(_get_repo),
) -> AlertResponse:
    """Return a single alert by ID."""
    row = repo.get_alert_by_id(alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return AlertResponse.from_dict(row)
