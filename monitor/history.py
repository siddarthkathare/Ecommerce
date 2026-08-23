"""
MONITOR AND IMPROVE
--------------------
Maps to the "MONITOR AND IMPROVE" box in the architecture diagram:

    Pipeline performance and security insights for continuous improvement.

Every scan run through app.py calls record_scan(...) here, which appends a
row to monitor/history.db (SQLite). The /monitor route in app.py reads this
back to chart trends over time: how many findings per run, how often the
security gate blocks deployment, and whether ML/Gemini findings are trending
down as the feedback loop retrains the model.
"""

import os
import sqlite3
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "history.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at REAL NOT NULL,
            source TEXT,
            critical INTEGER,
            high INTEGER,
            medium INTEGER,
            low INTEGER,
            secrets INTEGER,
            gate_status TEXT,
            deployment TEXT
        )
        """
    )
    return conn


def record_scan(source, findings, gate_status, deployment):
    conn = _get_conn()
    with conn:
        conn.execute(
            """
            INSERT INTO scan_history
                (scanned_at, source, critical, high, medium, low, secrets, gate_status, deployment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                source,
                findings.get("critical", 0),
                findings.get("high", 0),
                findings.get("medium", 0),
                findings.get("low", 0),
                findings.get("secrets", 0),
                gate_status,
                deployment,
            ),
        )
    conn.close()


def get_recent_scans(limit=25):
    conn = _get_conn()
    rows = conn.execute(
        "SELECT scanned_at, source, critical, high, medium, low, secrets, gate_status, deployment "
        "FROM scan_history ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()

    columns = [
        "scanned_at", "source", "critical", "high", "medium",
        "low", "secrets", "gate_status", "deployment",
    ]
    return [dict(zip(columns, row)) for row in rows][::-1]


def get_summary_stats():
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*), "
        "SUM(CASE WHEN gate_status = 'PASSED' THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN gate_status = 'FAILED' THEN 1 ELSE 0 END) "
        "FROM scan_history"
    ).fetchone()
    conn.close()

    total, passed, failed = row
    return {
        "total_scans": total or 0,
        "passed": passed or 0,
        "failed": failed or 0,
    }
