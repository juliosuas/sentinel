"""SQLite database layer for events, alerts, and incidents."""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from core.config import Config

logger = logging.getLogger("sentinel.db")


class Database:
    """Thread-safe SQLite database for Sentinel."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.config.DB_PATH)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = self._conn
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                event_type TEXT,
                severity TEXT DEFAULT 'info',
                src_ip TEXT,
                dst_ip TEXT,
                username TEXT,
                hostname TEXT,
                raw TEXT,
                data JSON,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT DEFAULT 'medium',
                description TEXT,
                source TEXT,
                event_id INTEGER,
                ai_analysis TEXT,
                data JSON,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (event_id) REFERENCES events(id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                assignee TEXT,
                alert_id INTEGER,
                ai_analysis TEXT,
                response_actions JSON,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT,
                resolved_at TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        """)
        conn.commit()
        logger.info("Database initialized at %s", self.config.DB_PATH)

    def store_event(self, event: dict) -> int:
        """Store an event and return its ID."""
        conn = self._conn
        cur = conn.execute(
            """INSERT INTO events (timestamp, source, event_type, severity,
               src_ip, dst_ip, username, hostname, raw, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("source"),
                event.get("event_type"),
                event.get("severity", "info"),
                event.get("src_ip"),
                event.get("dst_ip"),
                event.get("username") or event.get("user"),
                event.get("hostname") or event.get("host"),
                event.get("raw"),
                json.dumps(event, default=str),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def store_alert(self, alert: dict) -> int:
        """Store an alert and return its ID."""
        conn = self._conn
        ai = alert.get("ai_analysis")
        ai_text = json.dumps(ai, default=str) if ai else None
        cur = conn.execute(
            """INSERT INTO alerts (timestamp, rule_id, rule_name, severity,
               description, source, ai_analysis, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.get("timestamp"),
                alert.get("rule_id"),
                alert.get("rule_name"),
                alert.get("severity", "medium"),
                alert.get("description"),
                alert.get("source"),
                ai_text,
                json.dumps(alert, default=str),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def store_incident(self, incident: dict):
        """Store an incident."""
        conn = self._conn
        ai = incident.get("ai_analysis")
        ai_text = json.dumps(ai, default=str) if ai else None
        conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, title, description, severity, status, ai_analysis,
                response_actions, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.get("id"),
                incident.get("title"),
                incident.get("description"),
                incident.get("severity", "medium"),
                incident.get("status", "open"),
                ai_text,
                json.dumps(incident.get("response_actions", []), default=str),
                incident.get("created_at"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()

    def get_events(self, limit: int = 100, offset: int = 0,
                   event_type: Optional[str] = None,
                   severity: Optional[str] = None,
                   src_ip: Optional[str] = None) -> list[dict]:
        """Query events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_alerts(self, limit: int = 100, offset: int = 0,
                   severity: Optional[str] = None) -> list[dict]:
        """Query alerts."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_incidents(self, limit: int = 100, status: Optional[str] = None) -> list[dict]:
        """Query incidents."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_incident(self, incident_id: str, updates: dict) -> bool:
        """Update an incident."""
        allowed = {"title", "description", "severity", "status", "assignee", "resolved_at"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        params = list(fields.values()) + [incident_id]
        self._conn.execute(
            f"UPDATE incidents SET {set_clause} WHERE id = ?", params
        )
        self._conn.commit()
        return True

    def get_stats(self) -> dict:
        """Get aggregate statistics."""
        conn = self._conn
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
        ).fetchone()[0]

        severity_dist = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall():
            severity_dist[row["severity"]] = row["cnt"]

        top_rules = []
        for row in conn.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM alerts GROUP BY rule_name ORDER BY cnt DESC LIMIT 10"
        ).fetchall():
            top_rules.append({"rule": row["rule_name"], "count": row["cnt"]})

        top_ips = []
        for row in conn.execute(
            """SELECT src_ip, COUNT(*) as cnt FROM events
               WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"""
        ).fetchall():
            top_ips.append({"ip": row["src_ip"], "count": row["cnt"]})

        return {
            "total_events": event_count,
            "total_alerts": alert_count,
            "total_incidents": incident_count,
            "open_incidents": open_incidents,
            "severity_distribution": severity_dist,
            "top_rules": top_rules,
            "top_source_ips": top_ips,
        }
