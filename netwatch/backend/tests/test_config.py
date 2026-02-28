"""
tests/test_config.py

Tests for config.py — Pydantic Settings validation and defaults.
"""

from __future__ import annotations

from netwatch.backend.config import Settings


class TestSettingsDefaults:

    def test_default_interface(self):
        s = Settings()
        assert s.INTERFACE == "wlan0"

    def test_default_bpf_filter(self):
        s = Settings()
        assert s.BPF_FILTER == "ip"

    def test_default_local_network(self):
        s = Settings()
        assert s.LOCAL_NETWORK == "172.16.0.0/12"

    def test_default_flow_ttl(self):
        s = Settings()
        assert s.FLOW_TTL_SECONDS == 120  # raised from 60 so beaconing rule can trigger

    def test_default_confidence_threshold(self):
        s = Settings()
        assert s.DETECTION_CONFIDENCE_THRESHOLD == 0.3

    def test_default_queue_sizes(self):
        s = Settings()
        assert s.CAPTURE_QUEUE_SIZE == 10_000
        assert s.DETECTION_QUEUE_SIZE == 1_000
        assert s.ALERT_QUEUE_SIZE == 500
        assert s.ENRICHED_QUEUE_SIZE == 500

    def test_default_db_path(self):
        s = Settings()
        assert s.DB_PATH == "data/alerts.db"

    def test_default_api_host(self):
        s = Settings()
        assert s.API_HOST == "0.0.0.0"

    def test_default_api_port(self):
        s = Settings()
        assert s.API_PORT == 8000

    def test_default_log_level(self):
        s = Settings()
        assert s.LOG_LEVEL == "INFO"


class TestSettingsOverrides:

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("INTERFACE", "wlan0")
        monkeypatch.setenv("BPF_FILTER", "tcp")
        monkeypatch.setenv("API_PORT", "9000")
        s = Settings()
        assert s.INTERFACE == "wlan0"
        assert s.BPF_FILTER == "tcp"
        assert s.API_PORT == 9000

    def test_detection_threshold_override(self, monkeypatch):
        monkeypatch.setenv("DETECTION_CONFIDENCE_THRESHOLD", "0.8")
        s = Settings()
        assert s.DETECTION_CONFIDENCE_THRESHOLD == 0.8