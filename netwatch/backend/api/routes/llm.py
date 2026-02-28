"""
api/routes/llm.py

GET /api/llm/status  — LLM health, model info, and call statistics
POST /api/llm/explain — On-demand explanation for any stored alert_id
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from ..serializers import LLMStatusResponse, LLMExplanationResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/llm", tags=["llm"])

# LLMClient reference — injected by main.py at startup
_llm_client = None


def set_llm_client(client) -> None:
    global _llm_client
    _llm_client = client


@router.get("/status", response_model=LLMStatusResponse)
async def llm_status() -> LLMStatusResponse:
    """Return LLM availability, model info, and runtime stats."""
    from ...config import settings

    if _llm_client is None:
        return LLMStatusResponse(
            enabled=settings.LLM_ENABLED,
            available=False,
            model=settings.OLLAMA_MODEL,
            ollama_url=settings.OLLAMA_URL,
            cache_size=0,
            cache_hit_rate=0.0,
            calls_made=0,
            fallbacks_used=0,
            timeouts=0,
        )

    available = await _llm_client.health_check()
    stats = _llm_client.stats

    return LLMStatusResponse(
        enabled=settings.LLM_ENABLED,
        available=available,
        model=settings.OLLAMA_MODEL,
        ollama_url=settings.OLLAMA_URL,
        cache_size=len(_llm_client._cache),
        cache_hit_rate=round(_llm_client._cache.hit_rate, 3),
        calls_made=stats.get("calls_made", 0),
        fallbacks_used=stats.get("fallbacks_used", 0),
        timeouts=stats.get("timeouts", 0),
    )


@router.post("/explain/{alert_id}", response_model=LLMExplanationResponse)
async def explain_alert(alert_id: str) -> LLMExplanationResponse:
    """
    On-demand LLM explanation for any stored alert.

    Useful for re-enriching old alerts or alerts that got fallbacks.
    Bypasses the gatekeeper's cooldown/severity filters.
    """
    from ..main import get_repository
    from ...llm.fallbacks import get_fallback

    repo = get_repository()
    alert_dict = repo.get_alert_by_id(alert_id)
    if alert_dict is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")

    if _llm_client is None:
        explanation = get_fallback(alert_dict.get("rule_name", ""))
    else:
        # Call LLM directly, bypassing gatekeeper for on-demand requests
        from ...llm.prompt_builder import build_prompt
        from ...llm.validator import validate_llm_response
        system_prompt, user_prompt = build_prompt(alert_dict)
        raw = await _llm_client._call_ollama(system_prompt, user_prompt)
        if raw:
            explanation = validate_llm_response(raw) or get_fallback(alert_dict.get("rule_name", ""))
        else:
            explanation = get_fallback(alert_dict.get("rule_name", ""))

    # Persist the fresh explanation
    repo.update_alert_llm(alert_id, explanation.to_dict())

    return LLMExplanationResponse(**explanation.to_dict())
