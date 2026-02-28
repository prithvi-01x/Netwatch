"""
tests/test_graph.py

Tests for the /api/graph endpoint and repository.get_graph_data().
"""

from __future__ import annotations

import time
import pytest

from netwatch.backend.storage.database import Database
from netwatch.backend.storage.repository import AlertRepository


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    db.init_schema()
    return AlertRepository(db)


def _make_alert(
    alert_id: str,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    rule_name: str = "port_scan",
    severity: str = "HIGH",
    confidence: float = 0.8,
    timestamp: float | None = None,
) -> dict:
    ts = timestamp if timestamp is not None else time.time()
    return {
        "alert_id":           alert_id,
        "timestamp":          ts,
        "rule_name":          rule_name,
        "severity":           severity,
        "confidence":         confidence,
        "src_ip":             src_ip,
        "dst_ip":             dst_ip,
        "description":        "test alert",
        "evidence":           {},
        "window_start":       ts - 10,
        "window_end":         ts,
        "window_size_seconds": 10,
    }


# ─── Basic graph data ─────────────────────────────────────────────────────────

class TestGraphDataBasic:

    def test_empty_db_returns_empty_graph(self, repo):
        result = repo.get_graph_data()
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_single_alert_creates_two_nodes(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        ids = {n["id"] for n in result["nodes"]}
        assert "10.0.0.1" in ids
        assert "192.168.1.1" in ids

    def test_single_alert_creates_one_edge(self, repo):
        repo.save_alert(_make_alert("a1"))
        result = repo.get_graph_data()
        assert len(result["edges"]) == 1

    def test_edge_has_correct_source_and_target(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        edge = result["edges"][0]
        assert edge["source"] == "10.0.0.1"
        assert edge["target"] == "192.168.1.1"

    def test_edge_count_aggregated(self, repo):
        # Two alerts with same src/dst/rule → should aggregate to count=2
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.1"))
        result = repo.get_graph_data()
        assert len(result["edges"]) == 1
        assert result["edges"][0]["count"] == 2

    def test_different_rules_produce_separate_edges(self, repo):
        repo.save_alert(_make_alert("a1", rule_name="port_scan"))
        repo.save_alert(_make_alert("a2", rule_name="syn_flood"))
        result = repo.get_graph_data()
        assert len(result["edges"]) == 2


# ─── Node fields ─────────────────────────────────────────────────────────────

class TestGraphNodeFields:

    def test_src_node_type_is_attacker(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert node["type"] == "attacker"

    def test_dst_node_type_is_victim(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "192.168.1.1")
        assert node["type"] == "victim"

    def test_node_alert_count(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.1"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert node["alert_count"] == 2

    def test_node_max_severity_escalates(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", severity="LOW"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.1", severity="CRITICAL"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert node["max_severity"] == "CRITICAL"

    def test_node_rules_is_list(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", rule_name="port_scan"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert isinstance(node["rules"], list)
        assert "port_scan" in node["rules"]

    def test_node_rules_deduped(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", rule_name="port_scan"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.1", rule_name="port_scan"))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert node["rules"].count("port_scan") == 1

    def test_node_last_seen_populated(self, repo):
        now = time.time()
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", timestamp=now))
        result = repo.get_graph_data()
        node = next(n for n in result["nodes"] if n["id"] == "10.0.0.1")
        assert abs(node["last_seen"] - now) < 2


# ─── Time filtering ───────────────────────────────────────────────────────────

class TestGraphTimeFilter:

    def test_since_filter_excludes_old_alerts(self, repo):
        old_ts = time.time() - 7200   # 2 hours ago
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", timestamp=old_ts))
        result = repo.get_graph_data(since=time.time() - 3600)  # last hour
        assert len(result["nodes"]) == 0

    def test_since_filter_includes_recent_alerts(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", timestamp=time.time()))
        result = repo.get_graph_data(since=time.time() - 3600)
        assert len(result["nodes"]) > 0

    def test_no_since_returns_all(self, repo):
        old_ts = time.time() - 86400
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", timestamp=old_ts))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.2", timestamp=time.time()))
        result = repo.get_graph_data(since=0)
        ids = {n["id"] for n in result["nodes"]}
        assert "10.0.0.1" in ids
        assert "10.0.0.2" in ids


# ─── Multiple attackers / victims ─────────────────────────────────────────────

class TestGraphMultipleNodes:

    def test_multiple_attackers_all_present(self, repo):
        for i in range(5):
            repo.save_alert(_make_alert(f"a{i}", src_ip=f"10.0.0.{i+1}", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        ids = {n["id"] for n in result["nodes"]}
        for i in range(5):
            assert f"10.0.0.{i+1}" in ids

    def test_shared_victim_has_correct_alert_count(self, repo):
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="192.168.1.1"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.2", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        victim = next(n for n in result["nodes"] if n["id"] == "192.168.1.1")
        assert victim["alert_count"] == 2

    def test_node_appearing_as_both_src_and_dst(self, repo):
        """A pivot host that is both victim (dst) and attacker (src)."""
        repo.save_alert(_make_alert("a1", src_ip="10.0.0.1", dst_ip="10.0.0.5"))
        repo.save_alert(_make_alert("a2", src_ip="10.0.0.5", dst_ip="192.168.1.1"))
        result = repo.get_graph_data()
        ids = {n["id"] for n in result["nodes"]}
        assert "10.0.0.5" in ids
