"""
storage/repository.py  — Fixed

Fix: save_stats_snapshot now prunes the table to STATS_SNAPSHOT_MAX_ROWS
after every insert to prevent unbounded DB growth.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from ..config import settings
from .database import Database

logger = logging.getLogger(__name__)


class AlertRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ==================================================================
    # Write methods
    # ==================================================================

    def save_alert(self, alert_dict: dict) -> None:
        try:
            evidence_json = json.dumps(alert_dict["evidence"])
        except (TypeError, ValueError) as exc:
            logger.error("save_alert: evidence not JSON-serializable: %s", exc)
            evidence_json = json.dumps({"error": "non-serializable evidence"})

        try:
            self._db.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    alert_id, timestamp, rule_name, severity, confidence,
                    src_ip, dst_ip, description, evidence,
                    window_start, window_end, window_size_sec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_dict["alert_id"],
                    alert_dict["timestamp"],
                    alert_dict["rule_name"],
                    alert_dict["severity"],
                    alert_dict["confidence"],
                    alert_dict["src_ip"],
                    alert_dict["dst_ip"],
                    alert_dict["description"],
                    evidence_json,
                    alert_dict["window_start"],
                    alert_dict["window_end"],
                    alert_dict["window_size_seconds"],
                ),
            )
            self._db.commit()
        except Exception as exc:
            logger.error("save_alert DB write failed: %s", exc)

    def update_alert_llm(self, alert_id: str, llm_dict: dict) -> None:
        """Persist LLM explanation fields onto an existing alert row."""
        try:
            llm_json = json.dumps(llm_dict)
            self._db.execute(
                "UPDATE alerts SET llm_explanation = ? WHERE alert_id = ?",
                (llm_json, alert_id),
            )
            self._db.commit()
        except Exception as exc:
            logger.error("update_alert_llm failed for %s: %s", alert_id, exc)

    def save_stats_snapshot(self, snapshot: dict) -> None:
        """Insert stats row and prune table to STATS_SNAPSHOT_MAX_ROWS oldest rows."""
        try:
            self._db.execute(
                """
                INSERT INTO stats_snapshots (
                    timestamp, packets_seen, packets_dropped,
                    flows_active, alerts_fired, windows_analyzed
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.get("timestamp", time.time()),
                    snapshot.get("packets_seen", 0),
                    snapshot.get("packets_dropped", 0),
                    snapshot.get("flows_active", 0),
                    snapshot.get("alerts_fired", 0),
                    snapshot.get("windows_analyzed", 0),
                ),
            )
            # FIX: prune oldest rows so table doesn't grow forever
            max_rows = settings.STATS_SNAPSHOT_MAX_ROWS
            self._db.execute(
                """
                DELETE FROM stats_snapshots
                WHERE id NOT IN (
                    SELECT id FROM stats_snapshots
                    ORDER BY timestamp DESC
                    LIMIT ?
                )
                """,
                (max_rows,),
            )
            self._db.commit()
        except Exception as exc:
            logger.error("save_stats_snapshot DB write failed: %s", exc)

    # ==================================================================
    # Read methods
    # ==================================================================

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        rule_name: str | None = None,
        severity: str | None = None,
        src_ip: str | None = None,
        since: float | None = None,
    ) -> list[dict]:
        where, params = self._build_where(
            rule_name=rule_name, severity=severity, src_ip=src_ip, since=since
        )
        sql = f"""
            SELECT * FROM alerts
            {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([min(limit, 500), offset])
        rows = self._db.execute(sql, tuple(params)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_alert_by_id(self, alert_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_alert_count(
        self,
        rule_name: str | None = None,
        severity: str | None = None,
        src_ip: str | None = None,
        since: float | None = None,
    ) -> int:
        where, params = self._build_where(
            rule_name=rule_name, severity=severity, src_ip=src_ip, since=since
        )
        row = self._db.execute(
            f"SELECT COUNT(*) FROM alerts {where}", tuple(params)
        ).fetchone()
        return row[0] if row else 0

    def get_stats_summary(self) -> dict:
        now = time.time()
        one_hour_ago = now - 3600

        total = self._db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        last_hour = self._db.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (one_hour_ago,)
        ).fetchone()[0]

        sev_rows = self._db.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall()
        alerts_by_severity = {r[0]: r[1] for r in sev_rows}

        rule_rows = self._db.execute(
            "SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name"
        ).fetchall()
        alerts_by_rule = {r[0]: r[1] for r in rule_rows}

        ip_rows = self._db.execute(
            """
            SELECT src_ip, COUNT(*) as cnt FROM alerts
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
            """
        ).fetchall()
        top_src_ips = [{"src_ip": r[0], "count": r[1]} for r in ip_rows]

        latest_row = self._db.execute("SELECT MAX(timestamp) FROM alerts").fetchone()
        latest_ts: float | None = latest_row[0] if latest_row else None

        return {
            "total_alerts": total,
            "alerts_last_hour": last_hour,
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_rule": alerts_by_rule,
            "top_src_ips": top_src_ips,
            "latest_alert_timestamp": latest_ts,
        }

    def get_recent_stats_snapshots(self, limit: int = 60) -> list[dict]:
        rows = self._db.execute(
            """
            SELECT id, timestamp, packets_seen, packets_dropped,
                   flows_active, alerts_fired, windows_analyzed
            FROM stats_snapshots
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (min(limit, 1000),),
        ).fetchall()
        return [dict(r) for r in rows]

    # ==================================================================
    # Internal helpers
    # ==================================================================

    @staticmethod
    def _build_where(
        rule_name: str | None,
        severity: str | None,
        src_ip: str | None,
        since: float | None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if rule_name:
            clauses.append("rule_name = ?")
            params.append(rule_name)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        return where, params

    @staticmethod
    def _row_to_dict(row: Any) -> dict:
        d = dict(row)
        try:
            d["evidence"] = json.loads(d.get("evidence", "{}"))
        except (TypeError, json.JSONDecodeError):
            d["evidence"] = {}
        # Deserialize LLM explanation if present
        llm_raw = d.get("llm_explanation")
        if llm_raw:
            try:
                d["llm_explanation"] = json.loads(llm_raw)
            except (TypeError, json.JSONDecodeError):
                d["llm_explanation"] = None
        return d

    def get_graph_data(self, since: float | None = None, limit: int = 500) -> dict:
        """
        Return node + edge data for the attack graph.

        Nodes = unique IPs (src or dst) seen in alerts within the window.
        Edges = alert flows between src→dst pairs, aggregated by rule.
        """
        cutoff = since if since is not None else 0.0
        rows = self._db.execute(
            """
            SELECT src_ip, dst_ip, rule_name,
                   CASE MAX(CASE severity
                       WHEN 'CRITICAL' THEN 4
                       WHEN 'HIGH'     THEN 3
                       WHEN 'MEDIUM'   THEN 2
                       ELSE 1 END)
                   WHEN 4 THEN 'CRITICAL'
                   WHEN 3 THEN 'HIGH'
                   WHEN 2 THEN 'MEDIUM'
                   ELSE 'LOW' END as severity,
                   AVG(confidence) as confidence,
                   COUNT(*) as count,
                   MAX(timestamp) as last_seen,
                   MIN(timestamp) as first_seen
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY src_ip, dst_ip, rule_name
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()

        # Build node registry
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for row in rows:
            src, dst, rule, sev, conf, count, last_seen, first_seen = (
                row["src_ip"], row["dst_ip"], row["rule_name"],
                row["severity"], row["confidence"], row["count"],
                row["last_seen"], row["first_seen"],
            )

            # Register / update src node (attacker)
            if src not in nodes:
                nodes[src] = {"id": src, "type": "attacker", "alert_count": 0,
                               "max_severity": "LOW", "rules": set(), "last_seen": 0}
            nodes[src]["alert_count"] += count
            nodes[src]["rules"].add(rule)
            nodes[src]["last_seen"] = max(nodes[src]["last_seen"], last_seen)
            if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(nodes[src]["max_severity"], 0):
                nodes[src]["max_severity"] = sev

            # Register / update dst node (victim)
            if dst not in nodes:
                nodes[dst] = {"id": dst, "type": "victim", "alert_count": 0,
                               "max_severity": "LOW", "rules": set(), "last_seen": 0}
            nodes[dst]["alert_count"] += count
            nodes[dst]["last_seen"] = max(nodes[dst]["last_seen"], last_seen)

            edges.append({
                "source": src,
                "target": dst,
                "rule_name": rule,
                "severity": sev,
                "confidence": round(conf, 2),
                "count": count,
                "last_seen": last_seen,
                "first_seen": first_seen,
            })

        # Serialise sets → lists
        node_list = []
        for n in nodes.values():
            n["rules"] = list(n["rules"])
            node_list.append(n)

        return {"nodes": node_list, "edges": edges}
