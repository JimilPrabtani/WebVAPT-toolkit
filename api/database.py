"""
api/database.py
───────────────
SQLite persistence layer for all scan data.

Why SQLite and not PostgreSQL?
  - Zero setup — no server to run, no credentials, file just appears
  - Perfect for a single-user security tool
  - Easy to upgrade to PostgreSQL later by swapping this file only

Schema design mirrors how Nessus stores scan data:
  scans       — one row per scan job (target, status, timestamps, summary)
  findings    — one row per vulnerability found (linked to scan by scan_id)

This separation matters: it lets you query "show me all HIGH findings
across all scans" without loading entire scan objects.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

# ── Database file location ────────────────────────────────────────────────
DB_PATH = Path(__file__).parent.parent / "data" / "scans.db"


def get_connection() -> sqlite3.Connection:
    """
    Open a connection to the SQLite database.
    check_same_thread=False is needed for FastAPI which uses async threading.
    row_factory makes rows behave like dicts — so row["target_url"] works.
    """
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create tables if they don't exist.
    Called once at server startup.
    Safe to call multiple times — IF NOT EXISTS prevents duplication.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # ── scans table ───────────────────────────────────────────────────────
    # Stores the top-level scan job.
    # status: "running" → "complete" → "failed"
    # summary_json: stores the severity counts dict as a JSON string
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              TEXT PRIMARY KEY,
            target_url      TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'running',
            started_at      TEXT NOT NULL,
            completed_at    TEXT,
            duration_secs   REAL,
            pages_crawled   INTEGER DEFAULT 0,
            total_findings  INTEGER DEFAULT 0,
            risk_score      INTEGER,
            overall_risk    TEXT,
            summary_json    TEXT,
            exec_summary    TEXT,
            error           TEXT
        )
    """)

    # ── findings table ────────────────────────────────────────────────────
    # One row per vulnerability. Linked to scans via scan_id (foreign key).
    # ai_analysis_json stores the full Gemini response for that finding.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL,
            vuln_type       TEXT NOT NULL,
            severity        TEXT NOT NULL,
            url             TEXT NOT NULL,
            detail          TEXT,
            evidence        TEXT,
            remediation     TEXT,
            ai_verified     INTEGER,
            cvss_score      REAL,
            created_at      TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # ── indexes ───────────────────────────────────────────────────────────
    # These make common queries fast even with thousands of findings.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url)")

    conn.commit()
    conn.close()


# ── WRITE operations ──────────────────────────────────────────────────────

def create_scan(target_url: str) -> str:
    """
    Insert a new scan record with status='running'.
    Returns the generated scan_id (UUID).
    Called the moment a scan request comes in, before scanning starts.
    This lets the API return immediately with a scan_id the client can poll.
    """
    scan_id = str(uuid.uuid4())
    conn    = get_connection()
    conn.execute("""
        INSERT INTO scans (id, target_url, status, started_at)
        VALUES (?, ?, 'running', ?)
    """, (scan_id, target_url, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return scan_id


def save_scan_results(scan_id: str, scan_result, exec_summary: dict):
    """
    Update the scan record with final results and insert all findings.
    Called after the full scan pipeline completes.

    scan_result: ScanResult object from scanner/models.py
    exec_summary: dict returned by Gemini analyzer
    """
    summary = scan_result.summary()
    conn    = get_connection()

    # Update the scan record
    conn.execute("""
        UPDATE scans SET
            status          = ?,
            completed_at    = ?,
            duration_secs   = ?,
            pages_crawled   = ?,
            total_findings  = ?,
            risk_score      = ?,
            overall_risk    = ?,
            summary_json    = ?,
            exec_summary    = ?,
            error           = ?
        WHERE id = ?
    """, (
        "failed" if scan_result.error else "complete",
        datetime.utcnow().isoformat(),
        scan_result.scan_duration,
        len(scan_result.pages_crawled),
        len(scan_result.findings),
        exec_summary.get("risk_score"),
        exec_summary.get("overall_risk"),
        json.dumps(summary),
        json.dumps(exec_summary) if exec_summary else None,
        scan_result.error,
        scan_id,
    ))

    # Insert each finding
    for f in scan_result.findings:
        conn.execute("""
            INSERT INTO findings
                (id, scan_id, vuln_type, severity, url, detail,
                 evidence, remediation, ai_verified, cvss_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            scan_id,
            f.vuln_type,
            f.severity,
            f.url,
            f.detail,
            f.evidence,
            f.remediation,
            1 if f.ai_verified is True else (0 if f.ai_verified is False else None),
            f.cvss_score,
            datetime.utcnow().isoformat(),
        ))

    conn.commit()
    conn.close()


def mark_scan_failed(scan_id: str, error: str):
    """Mark a scan as failed with an error message."""
    conn = get_connection()
    conn.execute("""
        UPDATE scans SET status='failed', error=?, completed_at=?
        WHERE id=?
    """, (error, datetime.utcnow().isoformat(), scan_id))
    conn.commit()
    conn.close()


# ── READ operations ───────────────────────────────────────────────────────

def get_scan(scan_id: str) -> dict | None:
    """Fetch a single scan record by ID. Returns None if not found."""
    conn = get_connection()
    row  = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return _scan_row_to_dict(row)


def get_scan_with_findings(scan_id: str) -> dict | None:
    """
    Fetch a scan + all its findings in one call.
    This is what the /scan/{id} endpoint returns.
    """
    conn = get_connection()

    scan_row = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    if not scan_row:
        conn.close()
        return None

    findings_rows = conn.execute("""
        SELECT * FROM findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                WHEN 'INFO'     THEN 5
                ELSE 6
            END
    """, (scan_id,)).fetchall()

    conn.close()

    result = _scan_row_to_dict(scan_row)
    result["findings"] = [dict(r) for r in findings_rows]
    return result


def get_all_scans(limit: int = 50) -> list[dict]:
    """
    Return scan history — most recent first, no findings included.
    Used by the /history endpoint and the Streamlit sidebar.
    """
    conn  = get_connection()
    rows  = conn.execute("""
        SELECT * FROM scans
        ORDER BY started_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [_scan_row_to_dict(r) for r in rows]


def get_target_history(target_url: str) -> list[dict]:
    """
    Return all scans for a specific target — enables trend analysis.
    This is the Nessus-style 'how has this asset changed over time' view.
    """
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM scans
        WHERE target_url = ?
        ORDER BY started_at DESC
    """, (target_url,)).fetchall()
    conn.close()
    return [_scan_row_to_dict(r) for r in rows]


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and all its findings. Returns True if found."""
    conn   = get_connection()
    cursor = conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


# ── Helpers ───────────────────────────────────────────────────────────────

def _scan_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a plain dict, parsing JSON fields."""
    d = dict(row)
    for field in ("summary_json", "exec_summary"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
