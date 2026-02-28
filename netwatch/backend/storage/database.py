"""
storage/database.py

SQLite connection and schema initialisation for the NetWatch storage layer.

Design decisions:
  - WAL journal mode for concurrent readers + one writer without blocking.
  - check_same_thread=False: asyncio coroutines run in the same thread as the
    event loop; SQLite is safe here because all writes are serialised through
    the repository (no concurrent writes from multiple threads).
  - busy_timeout=5000ms: instead of raising SQLITE_BUSY immediately, SQLite
    will spin-wait up to 5 seconds, allowing WAL readers to finish.
  - Foreign keys ON: future tables can reference alerts.alert_id safely.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

_CURRENT_SCHEMA_VERSION = 1


class Database:
    """
    Thin wrapper around a sqlite3 connection.

    Usage:
        db = Database("data/alerts.db")
        db.init_schema()
        # ... use db.conn directly or pass db to AlertRepository ...
        db.close()
    """

    def __init__(self, db_path: str = "data/alerts.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row  # rows behave like dicts
        self._configure()
        logger.info("Database opened — path=%r", db_path)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _configure(self) -> None:
        """Apply performance and safety PRAGMAs."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.execute("PRAGMA synchronous=NORMAL")  # safe with WAL
        self.conn.commit()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        """Create all tables and indexes if they don't already exist."""
        cur = self.conn.cursor()

        cur.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id        TEXT PRIMARY KEY,
                timestamp       REAL NOT NULL,
                rule_name       TEXT NOT NULL,
                severity        TEXT NOT NULL,
                confidence      REAL NOT NULL,
                src_ip          TEXT NOT NULL,
                dst_ip          TEXT NOT NULL,
                description     TEXT NOT NULL,
                evidence        TEXT NOT NULL,
                window_start    REAL NOT NULL,
                window_end      REAL NOT NULL,
                window_size_sec INTEGER NOT NULL,
                created_at      REAL NOT NULL DEFAULT (unixepoch('now', 'subsec'))
            );

            CREATE TABLE IF NOT EXISTS stats_snapshots (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        REAL NOT NULL,
                packets_seen     INTEGER NOT NULL,
                packets_dropped  INTEGER NOT NULL,
                flows_active     INTEGER NOT NULL,
                alerts_fired     INTEGER NOT NULL,
                windows_analyzed INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_name
                ON alerts(rule_name);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
                ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip
                ON alerts(src_ip);
        """)

        # Record schema version (ignore if already present)
        import time
        cur.execute(
            "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
            (_CURRENT_SCHEMA_VERSION, time.time()),
        )
        self.conn.commit()
        logger.info("Schema initialised (version=%d)", _CURRENT_SCHEMA_VERSION)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush and close the SQLite connection."""
        try:
            self.conn.commit()
            self.conn.close()
            logger.info("Database closed — path=%r", self.db_path)
        except Exception as exc:
            logger.warning("Error closing database: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a single parameterized statement."""
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, params_list: list) -> None:
        """Execute a parameterized statement against a list of parameter tuples."""
        self.conn.executemany(sql, params_list)

    def commit(self) -> None:
        self.conn.commit()
