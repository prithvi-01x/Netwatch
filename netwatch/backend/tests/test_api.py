"""
tests/test_api.py

FastAPI route tests using TestClient (synchronous).
Dependency-injects an in-memory AlertRepository so no real DB is needed.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from netwatch.backend.api.main import create_app, set_repository, set_pipeline_stats
from netwatch.backend.storage.database import Database
from netwatch.backend.storage.repository import AlertRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    """TestClient sharing one in-memory DB for all tests in this module."""
    db = Database(":memory:")
    db.init_schema()
    repo = AlertRepository(db)
    set_repository(repo)
    set_pipeline_stats({"capture": {}, "aggregator": {}, "engine": {}})

    app = create_app()
    with TestClient(app) as c:
        yield c, repo
    db.close()


def seed_alert(repo: AlertRepository, **kwargs) -> str:
    """Helper to insert one alert and return its ID."""
    now = time.time()
    d = {
        "alert_id":            kwargs.get("alert_id", f"test-{now}"),
        "timestamp":           now,
        "rule_name":           kwargs.get("rule_name", "port_scan"),
        "severity":            kwargs.get("severity", "HIGH"),
        "confidence":          kwargs.get("confidence", 0.8),
        "src_ip":              kwargs.get("src_ip", "10.0.0.1"),
        "dst_ip":              "multiple",
        "description":         "test alert",
        "evidence":            {"src_ip": "10.0.0.1"},
        "window_start":        now - 1,
        "window_end":          now,
        "window_size_seconds": 1,
    }
    repo.save_alert(d)
    return d["alert_id"]


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def test_health(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------

class TestListAlerts:

    def test_empty_returns_paginated_response(self, client):
        c, _ = client
        resp = c.get("/api/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body
        assert "has_more" in body

    def test_populated_returns_alerts(self, client):
        c, repo = client
        aid = seed_alert(repo, alert_id="list-test-1")
        resp = c.get("/api/alerts")
        assert resp.status_code == 200
        ids = [a["alert_id"] for a in resp.json()["items"]]
        assert "list-test-1" in ids

    def test_limit_query_param(self, client):
        c, repo = client
        for i in range(5):
            seed_alert(repo, alert_id=f"limit-{i}")
        resp = c.get("/api/alerts?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) <= 2

    def test_filter_by_rule_name(self, client):
        c, repo = client
        seed_alert(repo, alert_id="rule-sf", rule_name="syn_flood")
        resp = c.get("/api/alerts?rule_name=syn_flood")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(a["rule_name"] == "syn_flood" for a in items)

    def test_filter_by_severity(self, client):
        c, repo = client
        seed_alert(repo, alert_id="sev-crit", severity="CRITICAL")
        resp = c.get("/api/alerts?severity=CRITICAL")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(a["severity"] == "CRITICAL" for a in items)

    def test_limit_max_capped_at_500(self, client):
        c, _ = client
        resp = c.get("/api/alerts?limit=9999")
        assert resp.status_code == 422   # validation error


# ---------------------------------------------------------------------------
# GET /api/alerts/{id}
# ---------------------------------------------------------------------------

class TestGetAlert:

    def test_returns_alert(self, client):
        c, repo = client
        aid = seed_alert(repo, alert_id="single-1")
        resp = c.get(f"/api/alerts/{aid}")
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == aid

    def test_404_for_unknown_id(self, client):
        c, _ = client
        resp = c.get("/api/alerts/no-such-id-xyz")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/stats
# ---------------------------------------------------------------------------

class TestStats:

    def test_stats_has_expected_fields(self, client):
        c, _ = client
        resp = c.get("/api/stats")
        assert resp.status_code == 200
        body = resp.json()
        for key in ("total_alerts", "alerts_last_hour", "alerts_by_severity",
                    "alerts_by_rule", "top_src_ips", "pipeline_stats"):
            assert key in body, f"Missing field: {key}"

    def test_total_alerts_is_integer(self, client):
        c, _ = client
        resp = c.get("/api/stats")
        assert isinstance(resp.json()["total_alerts"], int)


# ---------------------------------------------------------------------------
# GET /api/stats/history
# ---------------------------------------------------------------------------

class TestStatsHistory:

    def test_returns_list(self, client):
        c, repo = client
        repo.save_stats_snapshot({"timestamp": time.time(), "packets_seen": 10,
                                   "packets_dropped": 0, "flows_active": 2,
                                   "alerts_fired": 1, "windows_analyzed": 5})
        resp = c.get("/api/stats/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# GET /api/config + PUT /api/config
# ---------------------------------------------------------------------------

class TestConfig:

    def test_get_config(self, client):
        c, _ = client
        resp = c.get("/api/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "confidence_threshold" in body
        assert "port_scan_min_ports" in body

    def test_put_config_partial_update(self, client):
        c, _ = client
        resp = c.put("/api/config", json={"confidence_threshold": 0.5})
        assert resp.status_code == 200
        assert resp.json()["confidence_threshold"] == 0.5

    def test_put_config_other_fields_unchanged(self, client):
        c, _ = client
        orig = c.get("/api/config").json()["port_scan_min_ports"]
        c.put("/api/config", json={"confidence_threshold": 0.7})
        after = c.get("/api/config").json()["port_scan_min_ports"]
        assert after == orig


# ---------------------------------------------------------------------------
# GET /api/docker/topology
# ---------------------------------------------------------------------------

class TestDockerTopology:
    """
    The docker route uses a lazy-initialized private _client and calls
    _get_or_create_client() inside a thread executor. We patch that function
    directly — it's the correct seam — rather than the module-level variable.
    """

    def _make_mock_client(self):
        """Build a minimal mock Docker client that returns one container."""

        class MockContainer:
            name   = "netwatch-backend"
            status = "running"

            class MockImage:
                tags = ["mock/image:latest"]

            image = MockImage()
            attrs = {
                "NetworkSettings": {
                    "Networks": {"bridge": {"IPAddress": "172.17.0.2"}},
                    "Ports":    {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8000"}]},
                }
            }

            def stats(self, stream=False):
                # Return empty stats — the route handles missing keys gracefully
                return {}

        class MockContainers:
            def list(self, all=True):  # noqa: A002
                return [MockContainer()]

        class MockDockerClient:
            containers = MockContainers()

        return MockDockerClient()

    def test_get_docker_topology(self, client, monkeypatch):
        c, _ = client
        mock_client = self._make_mock_client()

        import netwatch.backend.api.routes.docker as docker_route

        # Patch _get_or_create_client — the actual lazy-init seam.
        # Also reset the module-level _client so the lazy path is exercised.
        monkeypatch.setattr(docker_route, "_client", None)
        monkeypatch.setattr(docker_route, "_get_or_create_client", lambda: mock_client)

        resp = c.get("/api/docker/topology")
        assert resp.status_code == 200
        body = resp.json()
        assert "containers" in body
        assert len(body["containers"]) == 1
        assert body["containers"][0]["name"] == "netwatch-backend"
        assert body["containers"][0]["status"] == "running"

    def test_topology_includes_port_info(self, client, monkeypatch):
        c, _ = client
        mock_client = self._make_mock_client()

        import netwatch.backend.api.routes.docker as docker_route

        monkeypatch.setattr(docker_route, "_client", None)
        monkeypatch.setattr(docker_route, "_get_or_create_client", lambda: mock_client)

        resp = c.get("/api/docker/topology")
        assert resp.status_code == 200
        container = resp.json()["containers"][0]
        assert isinstance(container["ports"], list)
        # Our mock has 8000/tcp exposed
        ports = [p["port"] for p in container["ports"]]
        assert 8000 in ports

    def test_topology_includes_ip(self, client, monkeypatch):
        c, _ = client
        mock_client = self._make_mock_client()

        import netwatch.backend.api.routes.docker as docker_route

        monkeypatch.setattr(docker_route, "_client", None)
        monkeypatch.setattr(docker_route, "_get_or_create_client", lambda: mock_client)

        resp = c.get("/api/docker/topology")
        assert resp.status_code == 200
        container = resp.json()["containers"][0]
        assert container["ip"] == "172.17.0.2"

    def test_topology_503_when_docker_unavailable(self, client, monkeypatch):
        """If Docker daemon is unreachable, the route must return 503."""
        import docker
        import netwatch.backend.api.routes.docker as docker_route

        c, _ = client

        monkeypatch.setattr(docker_route, "_client", None)
        monkeypatch.setattr(
            docker_route,
            "_get_or_create_client",
            lambda: (_ for _ in ()).throw(
                docker.errors.DockerException("socket not found")
            ),
        )

        resp = c.get("/api/docker/topology")
        assert resp.status_code == 503

    def test_topology_503_when_docker_unavailable_v2(self, client, monkeypatch):
        """Cleaner version of the 503 test using a real raising function."""
        import docker
        import netwatch.backend.api.routes.docker as docker_route

        def _raise():
            raise docker.errors.DockerException("daemon not running")

        monkeypatch.setattr(docker_route, "_client", None)
        monkeypatch.setattr(docker_route, "_get_or_create_client", _raise)

        c, _ = client
        resp = c.get("/api/docker/topology")
        assert resp.status_code == 503
        assert "Docker" in resp.json()["detail"]