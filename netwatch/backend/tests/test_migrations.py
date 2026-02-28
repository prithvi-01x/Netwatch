"""
tests/test_migrations.py

Tests for storage/migrations.py — schema versioning system.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from netwatch.backend.storage.database import Database
from netwatch.backend.storage.migrations import apply_migrations


@pytest.fixture
def db():
    d = Database(":memory:")
    d.init_schema()
    return d


def _current_version(db: Database) -> int | None:
    row = db.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return row[0] if row else None


class TestApplyMigrationsNoOp:

    def test_no_pending_migrations(self, db):
        """apply_migrations runs all known migrations — version is now at latest (2)."""
        apply_migrations(db)
        assert _current_version(db) == 2  # migration v2 was added after init_schema

    def test_double_apply_is_safe(self, db):
        apply_migrations(db)
        apply_migrations(db)


class TestApplyMigrationsWithEntries:

    def test_applies_migration_and_records_version(self, db):
        """Version 2 migration should run and record."""
        mock_fn = MagicMock()
        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, mock_fn)]):
            apply_migrations(db)
        mock_fn.assert_called_once()
        assert _current_version(db) == 2

    def test_already_applied_migration_skipped(self, db):
        """If version 2 is already done, it should not re-run."""
        mock_fn = MagicMock()
        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, mock_fn)]):
            apply_migrations(db)
            apply_migrations(db)
        mock_fn.assert_called_once()

    def test_multiple_migrations_applied_in_order(self, db):
        """Migrations should be applied in version order."""
        call_order: list[int] = []
        m2 = MagicMock(side_effect=lambda cur: call_order.append(2))
        m3 = MagicMock(side_effect=lambda cur: call_order.append(3))

        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, m2), (3, m3)]):
            apply_migrations(db)

        assert call_order == [2, 3]
        assert _current_version(db) == 3

    def test_partial_apply_resumes(self, db):
        """If v2 was already applied, only v3 should run."""
        m2 = MagicMock()
        m3 = MagicMock()

        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, m2)]):
            apply_migrations(db)
        m2.reset_mock()

        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, m2), (3, m3)]):
            apply_migrations(db)

        m2.assert_not_called()
        m3.assert_called_once()

    def test_failing_migration_rolls_back_and_raises(self, db):
        """A migration that raises should propagate."""
        def bad_migration(cur):
            raise RuntimeError("intentional failure")

        with patch("netwatch.backend.storage.migrations._MIGRATIONS", [(2, bad_migration)]):
            with pytest.raises(RuntimeError, match="intentional failure"):
                apply_migrations(db)

        # Version should remain at 1 (from init_schema)
        assert _current_version(db) == 1


class TestSchemaVersionTable:

    def test_schema_version_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        assert row is not None

    def test_init_schema_sets_version_1(self, db):
        assert _current_version(db) == 1