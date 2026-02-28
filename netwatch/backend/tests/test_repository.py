"""
tests/test_repository.py

Tests for storage/repository.py using in-memory SQLite (":memory:").
All tests are synchronous — repository is not async.
"""

from __future__ import annotations

import json
import time

import pytest

from netwatch.backend.storage.database import Database
from netwatch.backend.storage.repository import AlertRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """In-memory SQLite database, initialised fresh for each test."""
    d = Database(":memory:")
    d.init_schema()
    yield d
    d.close()


@pytest.fixture
def repo(db):
    return AlertRepository(db)


def make_alert(
    alert_id: str = "test-id-001",
    rule_name: str = "port_scan",
    severity: str = "HIGH",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "multiple",
    confidence: float = 0.75,
    ts: float | None = None,
    evidence: dict | None = None,
) -> dict:
    now = ts or time.time()
    return {
        "alert_id":            alert_id,
        "timestamp":           now,
        "rule_name":           rule_name,
        "severity":            severity,
        "confidence":          confidence,
        "src_ip":              src_ip,
        "dst_ip":              dst_ip,
        "description":         f"Test alert from {src_ip}",
        "evidence":            evidence or {"src_ip": src_ip, "ports": [80, 443]},
        "window_start":        now - 1.0,
        "window_end":          now,
        "window_size_seconds": 1,
    }


# ---------------------------------------------------------------------------
# save_alert
# ---------------------------------------------------------------------------

class TestSaveAlert:

    def test_saves_and_retrieves(self, repo):
        a = make_alert()
        repo.save_alert(a)
        result = repo.get_alert_by_id("test-id-001")
        assert result is not None
        assert result["alert_id"] == "test-id-001"
        assert result["rule_name"] == "port_scan"

    def test_duplicate_is_ignored(self, repo):
        a = make_alert()
        repo.save_alert(a)
        repo.save_alert(a)  # second insert — should not raise or duplicate
        results = repo.get_alerts()
        assert len(results) == 1

    def test_evidence_round_trips(self, repo):
        evidence = {"src_ip": "1.2.3.4", "ports": [22, 80, 443], "nested": {"k": "v"}}
        a = make_alert(evidence=evidence)
        repo.save_alert(a)
        result = repo.get_alert_by_id(a["alert_id"])
        assert result["evidence"] == evidence

    def test_non_serializable_evidence_stored_as_error(self, repo):
        """Non-JSON-serializable evidence should not crash save_alert."""
        a = make_alert(evidence={"bad": object()})  # object() is not serializable
        # Must not raise
        repo.save_alert(a)

    def test_multiple_alerts(self, repo):
        for i in range(5):
            repo.save_alert(make_alert(alert_id=f"id-{i}", src_ip=f"10.0.{i}.1"))
        assert repo.get_alert_count() == 5


# ---------------------------------------------------------------------------
# get_alerts — pagination + filters
# ---------------------------------------------------------------------------

class TestGetAlerts:

    def test_returns_newest_first(self, repo):
        now = time.time()
        repo.save_alert(make_alert(alert_id="old", ts=now - 100))
        repo.save_alert(make_alert(alert_id="new", ts=now))
        results = repo.get_alerts()
        assert results[0]["alert_id"] == "new"
        assert results[1]["alert_id"] == "old"

    def test_pagination(self, repo):
        for i in range(10):
            repo.save_alert(make_alert(alert_id=f"id-{i}"))
        page1 = repo.get_alerts(limit=5, offset=0)
        page2 = repo.get_alerts(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        ids = {r["alert_id"] for r in page1 + page2}
        assert len(ids) == 10

    def test_filter_by_rule_name(self, repo):
        repo.save_alert(make_alert(alert_id="ps", rule_name="port_scan"))
        repo.save_alert(make_alert(alert_id="sf", rule_name="syn_flood"))
        results = repo.get_alerts(rule_name="port_scan")
        assert len(results) == 1
        assert results[0]["rule_name"] == "port_scan"

    def test_filter_by_severity(self, repo):
        repo.save_alert(make_alert(alert_id="h", severity="HIGH"))
        repo.save_alert(make_alert(alert_id="c", severity="CRITICAL"))
        results = repo.get_alerts(severity="HIGH")
        assert all(r["severity"] == "HIGH" for r in results)

    def test_filter_by_src_ip(self, repo):
        repo.save_alert(make_alert(alert_id="a", src_ip="1.1.1.1"))
        repo.save_alert(make_alert(alert_id="b", src_ip="2.2.2.2"))
        results = repo.get_alerts(src_ip="1.1.1.1")
        assert len(results) == 1

    def test_filter_since(self, repo):
        now = time.time()
        repo.save_alert(make_alert(alert_id="old", ts=now - 7200))
        repo.save_alert(make_alert(alert_id="new", ts=now))
        results = repo.get_alerts(since=now - 3600)
        assert len(results) == 1
        assert results[0]["alert_id"] == "new"

    def test_empty_returns_empty_list(self, repo):
        assert repo.get_alerts() == []


# ---------------------------------------------------------------------------
# get_alert_by_id
# ---------------------------------------------------------------------------

class TestGetAlertById:

    def test_returns_none_for_missing(self, repo):
        assert repo.get_alert_by_id("no-such-id") is None

    def test_returns_correct_alert(self, repo):
        repo.save_alert(make_alert(alert_id="abc"))
        r = repo.get_alert_by_id("abc")
        assert r is not None
        assert r["alert_id"] == "abc"


# ---------------------------------------------------------------------------
# get_stats_summary
# ---------------------------------------------------------------------------

class TestGetStatsSummary:

    def test_empty_db(self, repo):
        summary = repo.get_stats_summary()
        assert summary["total_alerts"] == 0
        assert summary["alerts_last_hour"] == 0
        assert summary["alerts_by_severity"] == {}
        assert summary["latest_alert_timestamp"] is None

    def test_counts_by_severity(self, repo):
        repo.save_alert(make_alert(alert_id="h1", severity="HIGH"))
        repo.save_alert(make_alert(alert_id="h2", severity="HIGH"))
        repo.save_alert(make_alert(alert_id="c1", severity="CRITICAL"))
        summary = repo.get_stats_summary()
        assert summary["alerts_by_severity"]["HIGH"] == 2
        assert summary["alerts_by_severity"]["CRITICAL"] == 1
        assert summary["total_alerts"] == 3

    def test_top_src_ips(self, repo):
        for i in range(5):
            repo.save_alert(make_alert(alert_id=f"a{i}", src_ip="1.2.3.4"))
        repo.save_alert(make_alert(alert_id="z", src_ip="9.9.9.9"))
        summary = repo.get_stats_summary()
        ips = [e["src_ip"] for e in summary["top_src_ips"]]
        assert ips[0] == "1.2.3.4"


# ---------------------------------------------------------------------------
# save_stats_snapshot + get_recent_stats_snapshots
# ---------------------------------------------------------------------------

class TestStatSnapshots:

    def test_saves_and_retrieves(self, repo):
        snap = {
            "timestamp": time.time(),
            "packets_seen": 1000,
            "packets_dropped": 5,
            "flows_active": 20,
            "alerts_fired": 3,
            "windows_analyzed": 100,
        }
        repo.save_stats_snapshot(snap)
        results = repo.get_recent_stats_snapshots(limit=1)
        assert len(results) == 1
        assert results[0]["packets_seen"] == 1000

    def test_limit_respected(self, repo):
        for i in range(10):
            repo.save_stats_snapshot({"timestamp": time.time(), "packets_seen": i,
                                       "packets_dropped": 0, "flows_active": 0,
                                       "alerts_fired": 0, "windows_analyzed": 0})
        results = repo.get_recent_stats_snapshots(limit=3)
        assert len(results) == 3
