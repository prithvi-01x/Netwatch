"""
tests/test_cache.py

Tests for llm/cache.py — ExplanationCache LRU behaviour, key generation,
hit/miss counters, and eviction.
"""

from __future__ import annotations

import pytest

from netwatch.backend.llm.cache import ExplanationCache
from netwatch.backend.llm.models import LLMExplanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _expl(**kwargs) -> LLMExplanation:
    defaults = dict(
        summary="Test summary",
        severity_reasoning="Test reasoning",
        recommended_action="Test action",
        ioc_tags=["tag1"],
        attack_phase="reconnaissance",
        llm_confidence="MEDIUM",
        fallback_used=False,
    )
    defaults.update(kwargs)
    return LLMExplanation(**defaults)


def _alert(rule="port_scan", src="1.2.3.4", severity="HIGH", confidence=0.85) -> dict:
    return {"rule_name": rule, "src_ip": src, "severity": severity, "confidence": confidence}


# ---------------------------------------------------------------------------
# Basic get / put
# ---------------------------------------------------------------------------

class TestCacheGetPut:

    def test_miss_on_empty_cache(self):
        cache = ExplanationCache()
        assert cache.get(_alert()) is None

    def test_put_then_get_returns_explanation(self):
        cache = ExplanationCache()
        alert = _alert()
        expl = _expl()
        cache.put(alert, expl)
        result = cache.get(alert)
        assert result is expl

    def test_different_src_ip_is_cache_miss(self):
        cache = ExplanationCache()
        cache.put(_alert(src="1.1.1.1"), _expl())
        assert cache.get(_alert(src="2.2.2.2")) is None

    def test_different_rule_is_cache_miss(self):
        cache = ExplanationCache()
        cache.put(_alert(rule="port_scan"), _expl())
        assert cache.get(_alert(rule="syn_flood")) is None

    def test_different_severity_is_cache_miss(self):
        cache = ExplanationCache()
        cache.put(_alert(severity="HIGH"), _expl())
        assert cache.get(_alert(severity="LOW")) is None

    def test_confidence_bucketing_same_bucket_is_hit(self):
        """Confidence values in the same 0.1 bucket should share a cache key."""
        cache = ExplanationCache()
        cache.put(_alert(confidence=0.81), _expl())
        # 0.81 and 0.85 both round to 0.8 bucket
        assert cache.get(_alert(confidence=0.85)) is not None

    def test_confidence_bucketing_different_bucket_is_miss(self):
        cache = ExplanationCache()
        cache.put(_alert(confidence=0.81), _expl())
        # 0.91 rounds to 0.9 bucket — different key
        assert cache.get(_alert(confidence=0.91)) is None


# ---------------------------------------------------------------------------
# Hit / miss counters
# ---------------------------------------------------------------------------

class TestCacheCounters:

    def test_miss_increments_misses(self):
        cache = ExplanationCache()
        cache.get(_alert())
        assert cache.misses == 1
        assert cache.hits == 0

    def test_hit_increments_hits(self):
        cache = ExplanationCache()
        cache.put(_alert(), _expl())
        cache.get(_alert())
        assert cache.hits == 1
        assert cache.misses == 0

    def test_hit_rate_zero_when_empty(self):
        assert ExplanationCache().hit_rate == 0.0

    def test_hit_rate_calculated_correctly(self):
        cache = ExplanationCache()
        cache.put(_alert(), _expl())
        cache.get(_alert())   # hit
        cache.get(_alert(rule="other"))  # miss
        assert cache.hit_rate == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------

class TestCacheEviction:

    def test_len_reflects_entries(self):
        cache = ExplanationCache(maxsize=5)
        for i in range(3):
            cache.put(_alert(src=f"10.0.0.{i}"), _expl())
        assert len(cache) == 3

    def test_evicts_lru_when_full(self):
        cache = ExplanationCache(maxsize=3)
        a1 = _alert(src="1.0.0.1")
        a2 = _alert(src="1.0.0.2")
        a3 = _alert(src="1.0.0.3")
        a4 = _alert(src="1.0.0.4")

        cache.put(a1, _expl(summary="oldest"))
        cache.put(a2, _expl())
        cache.put(a3, _expl())
        cache.put(a4, _expl())  # should evict a1

        assert len(cache) == 3
        assert cache.get(a1) is None   # evicted
        assert cache.get(a4) is not None

    def test_get_updates_lru_order(self):
        """Accessing a1 after a2 was inserted should keep a1 alive past a3 insertion."""
        cache = ExplanationCache(maxsize=2)
        a1 = _alert(src="1.0.0.1")
        a2 = _alert(src="1.0.0.2")
        a3 = _alert(src="1.0.0.3")

        cache.put(a1, _expl())
        cache.put(a2, _expl())
        cache.get(a1)           # promote a1 → a2 is now LRU
        cache.put(a3, _expl())  # evicts a2

        assert cache.get(a1) is not None
        assert cache.get(a2) is None