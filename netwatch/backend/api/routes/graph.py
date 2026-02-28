"""
api/routes/graph.py

GET /api/graph  — node + edge snapshot for the D3 attack graph.

Query params:
  since  float  Unix timestamp — only include alerts after this time.
                Defaults to last 1 hour.
  limit  int    Max edges to return (default 500).
"""
from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Query

router = APIRouter(prefix="/graph", tags=["graph"])


def _get_repo():
    from ..main import get_repository
    return get_repository()


@router.get("")
async def get_graph(
    since: Annotated[float | None, Query(description="Unix timestamp lower bound")] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
):
    """Return nodes and edges for the live attack graph."""
    repo = _get_repo()
    # Default: last hour
    effective_since = since if since is not None else time.time() - 3600
    return repo.get_graph_data(since=effective_since, limit=limit)
