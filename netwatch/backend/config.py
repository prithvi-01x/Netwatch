"""
backend/config.py

Application configuration via Pydantic Settings.
All values can be overridden with environment variables or a .env file.

Quick start — create a .env file in your project root:
    INTERFACE=wlan0
    LOCAL_NETWORK=172.16.0.0/12
    OLLAMA_URL=http://localhost:11434
    OLLAMA_MODEL=phi3:3.8b
"""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Capture
    INTERFACE: str = "wlan0"
    BPF_FILTER: str = "ip"
    LOCAL_NETWORK: str = "172.16.0.0/12"
    FLOW_TTL_SECONDS: int = 120   # raised from 60 so beaconing rule can trigger

    DETECTION_CONFIDENCE_THRESHOLD: float = 0.3

    # Whitelist — never trigger alerts for these IPs
    WHITELIST_IPS: list[str] = []

    # Alert cooldown — prevent same alert every window
    ALERT_COOLDOWN_SECONDS: int = 30

    # Queues
    CAPTURE_QUEUE_SIZE: int = 10_000
    DETECTION_QUEUE_SIZE: int = 1_000
    ALERT_QUEUE_SIZE: int = 500
    ENRICHED_QUEUE_SIZE: int = 500

    # Storage
    DB_PATH: str = "data/alerts.db"
    STATS_SNAPSHOT_MAX_ROWS: int = 2_000

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # LLM / Ollama
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "phi3:3.8b"
    LLM_ENABLED: bool = True
    LLM_MIN_CONFIDENCE: float = 0.5
    LLM_MAX_CALLS_PER_MINUTE: int = 10
    LLM_COOLDOWN_SECONDS: int = 30

    # Logging
    LOG_LEVEL: str = "INFO"

    @field_validator("WHITELIST_IPS", mode="before")
    @classmethod
    def parse_whitelist(cls, v):
        if isinstance(v, str):
            import json as _json
            v = v.strip()
            if v.startswith("["):
                try:
                    return _json.loads(v)
                except Exception:
                    pass
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v


settings = Settings()
