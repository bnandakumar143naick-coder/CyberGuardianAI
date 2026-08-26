"""
CyberGuardian AI - Database layer

Uses SQLite with parameterised queries only. Stores scan metadata and
results, but never stores raw uploaded images or full sensitive text
longer than necessary for the summary shown in history.
"""

import sqlite3
import json
from datetime import datetime, timezone


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Create the scans table if it doesn't already exist."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                input_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                indicators TEXT,
                summary TEXT,
                explanation TEXT,
                recommendations TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def save_scan(db_path: str, result: dict) -> int:
    """Persist a scan result. Returns the new row id."""
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """
            INSERT INTO scans
                (timestamp, input_type, risk_score, risk_level, threat_type,
                 indicators, summary, explanation, recommendations, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                result.get("input_type", "unknown"),
                int(result.get("risk_score", 0)),
                result.get("risk_level", "LOW"),
                result.get("threat_type", "UNKNOWN"),
                json.dumps(result.get("indicators", [])),
                result.get("summary", "")[:500],
                result.get("explanation", "")[:2000],
                json.dumps(result.get("recommendations", [])),
                now,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_history(db_path: str, limit: int = 50) -> list:
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_by_id(db_path: str, scan_id: int):
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


def get_dashboard_stats(db_path: str) -> dict:
    conn = get_connection(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        high = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE risk_level IN ('HIGH','CRITICAL')"
        ).fetchone()["c"]
        medium = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE risk_level = 'MEDIUM'"
        ).fetchone()["c"]
        low = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE risk_level = 'LOW'"
        ).fetchone()["c"]

        threat_rows = conn.execute(
            "SELECT threat_type, COUNT(*) AS c FROM scans GROUP BY threat_type"
        ).fetchall()
        threat_distribution = {r["threat_type"]: r["c"] for r in threat_rows}

        recent = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()

        return {
            "total_scans": total,
            "high_risk": high,
            "medium_risk": medium,
            "low_risk": low,
            "threat_distribution": threat_distribution,
            "recent_scans": [_row_to_dict(r) for r in recent],
        }
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["indicators"] = json.loads(d.get("indicators") or "[]")
    except (json.JSONDecodeError, TypeError):
        d["indicators"] = []
    try:
        d["recommendations"] = json.loads(d.get("recommendations") or "[]")
    except (json.JSONDecodeError, TypeError):
        d["recommendations"] = []
    return d
