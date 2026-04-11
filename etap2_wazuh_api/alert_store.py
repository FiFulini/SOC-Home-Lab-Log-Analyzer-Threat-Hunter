"""
Alert Store — lokalna baza SQLite dla alertów pobranych z Wazuh API
Przechowuje alerty, deduplikuje po ID, umożliwia zapytania po zakresie dat i poziomie
"""

import json
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger("alert_store")

DB_PATH = "alerts.db"


# ──────────────────────────────────────────────
# Schema
# ──────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    level       INTEGER NOT NULL,
    rule_id     TEXT NOT NULL,
    description TEXT NOT NULL,
    groups      TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    agent_name  TEXT NOT NULL,
    srcip       TEXT,
    dstuser     TEXT,
    raw         TEXT NOT NULL,
    fetched_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_level     ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_srcip     ON alerts(srcip);
CREATE INDEX IF NOT EXISTS idx_agent     ON alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_rule_id   ON alerts(rule_id);
"""


# ──────────────────────────────────────────────
# Store
# ──────────────────────────────────────────────

class AlertStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)
        logger.info("Baza danych: %s", self.db_path)

    # ── Zapis ────────────────────────────────

    def save_alerts(self, alerts: list[dict]) -> tuple[int, int]:
        """
        Zapisuje listę alertów.
        Zwraca (nowe, zduplikowane) — dzięki INSERT OR IGNORE nie nadpisujemy istniejących.
        """
        fetched_at = datetime.utcnow().isoformat()
        new_count  = 0
        dup_count  = 0

        with self._conn() as conn:
            for a in alerts:
                row = (
                    a["id"],
                    a["timestamp"],
                    a["rule"]["level"],
                    a["rule"]["id"],
                    a["rule"]["description"],
                    json.dumps(a["rule"].get("groups", [])),
                    a["agent"]["id"],
                    a["agent"]["name"],
                    a.get("data", {}).get("srcip"),
                    a.get("data", {}).get("dstuser"),
                    json.dumps(a),
                    fetched_at,
                )
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO alerts
                       (id, timestamp, level, rule_id, description, groups,
                        agent_id, agent_name, srcip, dstuser, raw, fetched_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    row,
                )
                if cursor.rowcount > 0:
                    new_count += 1
                else:
                    dup_count += 1

        return new_count, dup_count

    # ── Odczyt ───────────────────────────────

    def get_alerts(
        self,
        min_level:  int = 0,
        date_from:  str = None,
        date_to:    str = None,
        agent_name: str = None,
        srcip:      str = None,
        limit:      int = 500,
    ) -> list[dict]:
        """Zwraca alerty z bazy wg podanych filtrów."""
        where  = ["level >= ?"]
        params = [min_level]

        if date_from:
            where.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            where.append("timestamp <= ?")
            params.append(date_to)
        if agent_name:
            where.append("agent_name = ?")
            params.append(agent_name)
        if srcip:
            where.append("srcip = ?")
            params.append(srcip)

        query = f"""
            SELECT raw FROM alerts
            WHERE {' AND '.join(where)}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [json.loads(r["raw"]) for r in rows]

    # ── Statystyki ───────────────────────────

    def get_stats(self) -> dict:
        """Statystyki bazy — liczba alertów, zakres dat, rozkład poziomów."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            if total == 0:
                return {"total": 0}

            ts_min, ts_max = conn.execute(
                "SELECT MIN(timestamp), MAX(timestamp) FROM alerts"
            ).fetchone()

            levels = conn.execute(
                "SELECT level, COUNT(*) as cnt FROM alerts GROUP BY level ORDER BY level"
            ).fetchall()

            top_ips = conn.execute(
                """SELECT srcip, COUNT(*) as cnt FROM alerts
                   WHERE srcip IS NOT NULL AND level >= 7
                   GROUP BY srcip ORDER BY cnt DESC LIMIT 5"""
            ).fetchall()

            top_agents = conn.execute(
                """SELECT agent_name, COUNT(*) as cnt FROM alerts
                   WHERE level >= 7
                   GROUP BY agent_name ORDER BY cnt DESC LIMIT 5"""
            ).fetchall()

        return {
            "total":      total,
            "ts_min":     ts_min,
            "ts_max":     ts_max,
            "by_level":   {str(r["level"]): r["cnt"] for r in levels},
            "top_ips":    {r["srcip"]: r["cnt"] for r in top_ips},
            "top_agents": {r["agent_name"]: r["cnt"] for r in top_agents},
        }

    def count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def newest_timestamp(self) -> str | None:
        """Timestamp najnowszego alertu w bazie — do pobierania tylko nowych."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MAX(timestamp) FROM alerts"
            ).fetchone()
        return row[0] if row else None
