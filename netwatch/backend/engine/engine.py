"""
engine/engine.py  — Fixed version

Changes vs original:
  1. Alert cooldown: same (rule, src_ip) pair suppressed for ALERT_COOLDOWN_SECONDS
  2. IP whitelist: src_ips in WHITELIST_IPS never fire alerts
  3. Stats key added: "alerts_cooldown" counter
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import time
import uuid

from ..aggregation.models import AggregatedWindow
from ..config import settings
from .models import Alert, RuleResult, Severity
from .rules.base import BaseRule

logger = logging.getLogger(__name__)

_RULE_TIMEOUT_MS = 50.0


class DetectionEngine:
    def __init__(self, confidence_threshold: float = 0.3) -> None:
        self.confidence_threshold = confidence_threshold
        self.rules: list[BaseRule] = self._load_rules()

        # Cooldown tracking: "rule_name:src_ip" → last fired timestamp
        self._cooldowns: dict[str, float] = {}
        self._cooldown_sec: int = settings.ALERT_COOLDOWN_SECONDS

        # IP whitelist
        self._whitelist: frozenset[str] = frozenset(settings.WHITELIST_IPS)

        self.stats: dict[str, int] = {
            "windows_analyzed": 0,
            "alerts_fired": 0,
            "alerts_suppressed": 0,
            "alerts_cooldown": 0,
            "alerts_whitelisted": 0,
        }
        logger.info(
            "DetectionEngine loaded %d rule(s): %s | cooldown=%ds whitelist=%s",
            len(self.rules),
            [r.name for r in self.rules],
            self._cooldown_sec,
            list(self._whitelist) or "none",
        )

    def analyze(self, window: AggregatedWindow) -> list[Alert]:
        self.stats["windows_analyzed"] += 1
        alerts: list[Alert] = []

        for rule in self.rules:
            result = self._safe_analyze(rule, window)
            if not result.triggered:
                continue

            if result.confidence < self.confidence_threshold:
                self.stats["alerts_suppressed"] += 1
                continue

            alert = self._make_alert(rule, result, window)

            # Whitelist check
            if alert.src_ip in self._whitelist:
                self.stats["alerts_whitelisted"] += 1
                logger.debug("Alert suppressed — src_ip %r is whitelisted", alert.src_ip)
                continue

            # Cooldown check
            cooldown_key = f"{rule.name}:{alert.src_ip}"
            now = time.time()
            last_fired = self._cooldowns.get(cooldown_key, 0.0)
            if now - last_fired < self._cooldown_sec:
                self.stats["alerts_cooldown"] += 1
                logger.debug(
                    "Alert cooldown active for %r (%.0fs remaining)",
                    cooldown_key,
                    self._cooldown_sec - (now - last_fired),
                )
                continue

            self._cooldowns[cooldown_key] = now
            alerts.append(alert)
            self.stats["alerts_fired"] += 1
            logger.warning(
                "ALERT [%s] rule=%r conf=%.2f src=%r — %s",
                alert.severity.value,
                alert.rule_name,
                alert.confidence,
                alert.src_ip,
                alert.description,
            )

        return alerts

    def _safe_analyze(self, rule: BaseRule, window: AggregatedWindow) -> RuleResult:
        t0 = time.monotonic()
        try:
            result = rule.analyze(window)
        except Exception as exc:
            logger.exception("Rule %r raised an unhandled exception: %s", rule.name, exc)
            result = RuleResult(
                triggered=False, confidence=0.0, evidence={},
                description=f"rule error: {exc}",
            )
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms > _RULE_TIMEOUT_MS:
            logger.warning("Rule %r took %.1fms", rule.name, elapsed_ms)
        return result

    def _make_alert(self, rule: BaseRule, result: RuleResult, window: AggregatedWindow) -> Alert:
        src_ip = str(
            result.evidence.get("src_ip") or
            (result.evidence.get("src_ips") or ["unknown"])[0]
        )
        dst_ip = str(result.evidence.get("dst_ip", "multiple"))
        severity = result.evidence.get("severity", rule.severity)
        if not isinstance(severity, Severity):
            severity = rule.severity

        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=time.time(),
            rule_name=rule.name,
            severity=severity,
            confidence=result.confidence,
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=result.evidence,
            description=result.description,
            window_start=window.window_start,
            window_end=window.window_end,
            window_size_seconds=window.window_size_seconds,
        )

    def _load_rules(self) -> list[BaseRule]:
        import netwatch.backend.engine.rules as rules_pkg
        rules: list[BaseRule] = []
        for _, module_name, _ in pkgutil.iter_modules(rules_pkg.__path__):
            if module_name == "base":
                continue
            try:
                module = importlib.import_module(
                    f"netwatch.backend.engine.rules.{module_name}"
                )
            except Exception as exc:
                logger.error("Failed to import rule module %r: %s", module_name, exc)
                continue
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseRule)
                    and obj is not BaseRule
                    and obj.__module__ == module.__name__
                ):
                    try:
                        instance: BaseRule = obj()
                        if instance.enabled:
                            rules.append(instance)
                    except Exception as exc:
                        logger.error("Failed to instantiate rule %r: %s", obj, exc)
        return rules
