"""
llm/cache.py

SHA256-keyed LRU cache for LLM explanations.

Cache key is derived from: rule_name + src_ip + severity + confidence_bucket.
Same attack pattern from the same source → same explanation → cache hit.
Expected hit rate: 60–80% in practice (attacks repeat patterns).
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict

from .models import LLMExplanation

logger = logging.getLogger(__name__)


class ExplanationCache:
    """
    LRU cache for LLMExplanation objects.

    Thread safety: NOT thread-safe — designed for use from a single asyncio
    coroutine (the LLM consumer task). No locking needed.
    """

    def __init__(self, maxsize: int = 200) -> None:
        self._cache: OrderedDict[str, LLMExplanation] = OrderedDict()
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0

    def _key(self, alert_dict: dict) -> str:
        """
        Build a cache key from stable alert fields.
        Confidence is quantised to 0.1 buckets to increase hit rate.
        """
        key_data = {
            "rule": alert_dict.get("rule_name", ""),
            "src_ip": alert_dict.get("src_ip", ""),
            "severity": alert_dict.get("severity", ""),
            "conf_bucket": round(float(alert_dict.get("confidence", 0)), 1),
        }
        raw = json.dumps(key_data, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def get(self, alert_dict: dict) -> LLMExplanation | None:
        """Return a cached explanation or None on miss."""
        key = self._key(alert_dict)
        if key in self._cache:
            self._cache.move_to_end(key)  # LRU update
            self.hits += 1
            logger.debug("Cache HIT key=%s (hits=%d misses=%d)", key, self.hits, self.misses)
            return self._cache[key]
        self.misses += 1
        return None

    def put(self, alert_dict: dict, explanation: LLMExplanation) -> None:
        """Store an explanation, evicting the LRU entry if at capacity."""
        key = self._key(alert_dict)
        self._cache[key] = explanation
        self._cache.move_to_end(key)
        if len(self._cache) > self.maxsize:
            evicted_key, _ = self._cache.popitem(last=False)
            logger.debug("Cache evicted LRU key=%s", evicted_key)

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def __len__(self) -> int:
        return len(self._cache)
