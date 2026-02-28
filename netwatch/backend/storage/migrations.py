"""
storage/migrations.py

Phase 5 adds migration v2: llm_explanation column on alerts table.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from .database import Database

logger = logging.getLogger(__name__)


def migration_2(cur) -> None:
    """Phase 5: Add llm_explanation column to alerts table."""
    cur.execute(
        "ALTER TABLE alerts ADD COLUMN llm_explanation TEXT DEFAULT NULL"
    )


_MIGRATIONS: list[tuple[int, Callable]] = [
    (2, migration_2),
]


def apply_migrations(db: Database) -> None:
    cur = db.conn.cursor()
    cur.execute("SELECT MAX(version) FROM schema_version")
    row = cur.fetchone()
    current_version: int = row[0] if row[0] is not None else 0

    pending = [(v, fn) for v, fn in _MIGRATIONS if v > current_version]
    if not pending:
        logger.debug("No pending migrations (current schema version=%d)", current_version)
        return

    for version, migration_fn in pending:
        logger.info("Applying migration v%d …", version)
        try:
            migration_fn(cur)
            cur.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, time.time()),
            )
            db.conn.commit()
            logger.info("Migration v%d applied successfully", version)
        except Exception as exc:
            db.conn.rollback()
            logger.error("Migration v%d FAILED: %s — rolling back", version, exc)
            raise
