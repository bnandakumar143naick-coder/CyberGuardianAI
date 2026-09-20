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
        # Additive-only (Phase 6/7): holds the full structured Phase 3/4/5
        # analysis (evidence, risk contribution breakdown, explainable AI)
        # plus source_app/sender, keyed by scan_id. Kept in its own table
        # rather than as new columns on `scans` so the original Phase 1
        # table, and every query against it, is completely untouched.
        # Scans saved before this table existed simply have no matching
        # row here — callers must handle that as a legacy/degraded case,
        # never assume every scan has one.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_details (
                scan_id INTEGER PRIMARY KEY,
                source_app TEXT,
                sender TEXT,
                full_analysis TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
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
        # SAFE is a distinct band introduced by the Phase 3/4 risk engine
        # (0-19, below LOW's 20-39) — counted separately so it isn't
        # silently dropped from every dashboard metric. Phase 1-era scans
        # never produced this risk_level, so this is purely additive.
        safe = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE risk_level = 'SAFE'"
        ).fetchone()["c"]

        threat_rows = conn.execute(
            "SELECT threat_type, COUNT(*) AS c FROM scans GROUP BY threat_type"
        ).fetchall()
        threat_distribution = {r["threat_type"]: r["c"] for r in threat_rows}

        avg_row = conn.execute("SELECT AVG(risk_score) AS avg_score FROM scans").fetchone()
        average_risk_score = round(avg_row["avg_score"]) if avg_row and avg_row["avg_score"] is not None else 0

        recent = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()

        return {
            "total_scans": total,
            "high_risk": high,
            "medium_risk": medium,
            "low_risk": low,
            "safe": safe,
            "average_risk_score": average_risk_score,
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


# ---------------------------------------------------------------------
# Phase 6/7: scan_details (full structured analysis, source_app, sender)
# ---------------------------------------------------------------------

def save_scan_details(db_path: str, scan_id: int, source_app: str, sender: str, full_analysis: dict) -> None:
    """
    Persist the full structured Phase 3/4/5 analysis for a scan, keyed by
    the scan_id already assigned by save_scan(). Additive to the Phase 1
    schema — never touches the `scans` table.
    """
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO scan_details (scan_id, source_app, sender, full_analysis)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, source_app, sender, json.dumps(full_analysis)),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_details(db_path: str, scan_id: int):
    """
    Returns {"scan_id", "source_app", "sender", "full_analysis": dict} or
    None if this scan has no stored detail (e.g. it was created by a
    Phase 1 endpoint, or predates this table). Callers must treat None
    as a normal, expected case, not an error.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM scan_details WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["full_analysis"] = json.loads(d.get("full_analysis") or "{}")
        except (json.JSONDecodeError, TypeError):
            d["full_analysis"] = {}
        return d
    finally:
        conn.close()


def get_app_distribution(db_path: str) -> dict:
    """
    Count stored scans grouped by source_app, for the Phase 7 analytics
    "threats by application" chart. Only counts scans that have a
    scan_details row (i.e. went through /api/v2/analyze-unified) — older
    Phase 1 scans never recorded a source app, so they're correctly
    excluded here rather than being guessed at.
    """
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT COALESCE(NULLIF(TRIM(source_app), ''), 'Other') AS app, COUNT(*) AS c
            FROM scan_details
            GROUP BY app
            """
        ).fetchall()
        return {r["app"]: r["c"] for r in rows}
    finally:
        conn.close()


def get_detail_stats(db_path: str) -> dict:
    """
    Real (not estimated) counts derived from the stored Phase 3/4 full
    analysis: how many notifications went through the unified pipeline,
    and how many actual URLs were found across them. Used by the
    analytics dashboard instead of a guessed multiplier.
    """
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT full_analysis FROM scan_details").fetchall()
    finally:
        conn.close()

    notifications_analyzed = len(rows)
    urls_analyzed = 0
    for row in rows:
        try:
            full = json.loads(row["full_analysis"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        urls_found = ((full.get("url_analysis") or {}).get("urls_found")) or []
        urls_analyzed += len(urls_found)

    return {
        "notifications_analyzed": notifications_analyzed,
        "urls_analyzed": urls_analyzed,
    }
