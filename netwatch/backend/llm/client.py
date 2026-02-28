"""
llm/client.py

Async Ollama HTTP client + full LLM enrichment pipeline.

Responsibilities:
  - POST to Ollama /api/chat with the sanitized prompt
  - Parse and validate the JSON response
  - Return LLMExplanation (or fallback on any failure)
  - Enforce an 8-second hard timeout per call

Usage:
    client = LLMClient(base_url="http://localhost:11434", model="phi3:3.8b")
    explanation = await client.explain(alert_dict, window_context)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from .cache import ExplanationCache
from .fallbacks import get_fallback
from .gatekeeper import LLMGatekeeper
from .models import LLMExplanation
from .prompt_builder import build_prompt
from .validator import validate_llm_response

logger = logging.getLogger(__name__)

_LLM_TIMEOUT_SECONDS = 8.0


class LLMClient:
    """
    Async Ollama client with caching, gating, and fallback support.

    Args:
        base_url:   Ollama server URL, e.g. "http://localhost:11434"
        model:      Ollama model tag, e.g. "phi3:3.8b" or "mistral"
        cache_size: Max LRU cache entries
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "phi3:3.8b",
        cache_size: int = 200,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._cache = ExplanationCache(maxsize=cache_size)
        self._gatekeeper = LLMGatekeeper()
        self._available: bool | None = None  # None = not yet checked
        self.stats: dict[str, int] = {
            "calls_made": 0,
            "cache_hits": 0,
            "fallbacks_used": 0,
            "timeouts": 0,
            "parse_errors": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def explain(
        self,
        alert_dict: dict,
        window_context: dict | None = None,
    ) -> LLMExplanation:
        """
        Return an LLMExplanation for the given alert.

        Never raises — always returns something (fallback if needed).
        """
        # 1. Gate check
        should_call, reason = self._gatekeeper.should_call(alert_dict, self._cache)

        if not should_call:
            if reason == "CACHE_HIT":
                self.stats["cache_hits"] += 1
                cached = self._cache.get(alert_dict)
                return cached  # type: ignore[return-value]
            # Below threshold / rate limited / cooldown
            self.stats["fallbacks_used"] += 1
            logger.debug(
                "LLM skipped for rule=%r src=%r reason=%s",
                alert_dict.get("rule_name"), alert_dict.get("src_ip"), reason,
            )
            return get_fallback(alert_dict.get("rule_name", ""))

        # 2. Check Ollama availability (cached after first check)
        if not await self._is_available():
            self.stats["fallbacks_used"] += 1
            logger.warning("Ollama unavailable — using fallback for %r", alert_dict.get("rule_name"))
            return get_fallback(alert_dict.get("rule_name", ""))

        # 3. Build prompt
        system_prompt, user_prompt = build_prompt(alert_dict, window_context)

        # 4. Call Ollama
        self.stats["calls_made"] += 1
        raw_response = await self._call_ollama(system_prompt, user_prompt)

        if raw_response is None:
            self.stats["fallbacks_used"] += 1
            return get_fallback(alert_dict.get("rule_name", ""))

        # 5. Validate output
        explanation = validate_llm_response(raw_response)
        if explanation is None:
            self.stats["parse_errors"] += 1
            self.stats["fallbacks_used"] += 1
            logger.warning(
                "LLM output failed validation for rule=%r — using fallback",
                alert_dict.get("rule_name"),
            )
            return get_fallback(alert_dict.get("rule_name", ""))

        # 6. Cache and return
        self._cache.put(alert_dict, explanation)
        logger.info(
            "LLM enriched alert rule=%r conf=%s phase=%s (cache_rate=%.0f%%)",
            alert_dict.get("rule_name"),
            explanation.llm_confidence,
            explanation.attack_phase,
            self._cache.hit_rate * 100,
        )
        return explanation

    async def health_check(self) -> bool:
        """Return True if Ollama is reachable and the model is available."""
        return await self._is_available(force=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _is_available(self, force: bool = False) -> bool:
        """Check Ollama availability, caching the result after first success."""
        if not _HTTPX_AVAILABLE:
            return False
        if self._available is True and not force:
            return True
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code == 200:
                    # Check that our model is actually pulled
                    data = resp.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    # Accept prefix match: "phi3:3.8b" matches ":mini-4k-instruct"
                    model_prefix = self.model.split(":")[0]
                    available = any(
                        m == self.model or m.startswith(model_prefix)
                        for m in models
                    )
                    if not available:
                        logger.warning(
                            "Ollama running but model %r not found. "
                            "Run: ollama pull %s",
                            self.model, self.model,
                        )
                        # Still mark as available — model check is best-effort
                    self._available = True
                    return True
        except Exception as exc:
            if self._available is not False:
                logger.info("Ollama not reachable at %s: %s", self.base_url, exc)
            self._available = False
        return False

    async def _call_ollama(
        self, system_prompt: str, user_prompt: str
    ) -> str | None:
        """
        POST to Ollama /api/chat.
        Returns raw response text or None on timeout/error.
        """
        if not _HTTPX_AVAILABLE:
            logger.error("httpx not installed — install with: pip install httpx")
            return None

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,   # Low temperature for consistent JSON output
                "num_predict": 300,   # ~200 tokens for our output schema
            },
        }

        try:
            async with asyncio.timeout(_LLM_TIMEOUT_SECONDS):
                async with httpx.AsyncClient(timeout=_LLM_TIMEOUT_SECONDS + 1) as client:
                    resp = await client.post(
                        f"{self.base_url}/api/chat",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    # Ollama /api/chat response: {"message": {"content": "..."}}
                    content = data.get("message", {}).get("content", "")
                    return content if content else None

        except asyncio.TimeoutError:
            self.stats["timeouts"] += 1
            logger.warning("Ollama call timed out after %.1fs", _LLM_TIMEOUT_SECONDS)
            return None
        except Exception as exc:
            logger.warning("Ollama call failed: %s", exc)
            self._available = False  # Mark unavailable to skip future calls briefly
            return None
