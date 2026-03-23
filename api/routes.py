"""
api/routes.py
─────────────
All HTTP endpoints for the WebPenTest AI Toolkit API.

Endpoint map:
  POST   /scan              → Start a new scan (returns immediately with scan_id)
  GET    /scan/{id}         → Get full scan results + findings
  GET    /scan/{id}/status  → Lightweight status check (for polling)
  GET    /history           → List all past scans
  GET    /history/{target}  → Scan history for a specific target (trend analysis)
  GET    /stats             → Aggregate stats across all scans
  DELETE /scan/{id}         → Delete a scan record

Why async background tasks?
  Scanning takes 30-180 seconds. If we ran it synchronously,
  the HTTP connection would hang the entire time.
  Instead: client sends POST → gets scan_id back in <1 second
           client polls GET /scan/{id}/status every 3 seconds
           when status = "complete", client fetches full results
  This is exactly how Nessus, Tenable.io, and Qualys work.
"""

import json
import uuid
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse

from api.limiter import limiter, RATE_LIMITING_AVAILABLE

from config import ALLOW_PRIVATE_TARGETS, is_ssrf_safe
from api.database import (
    create_scan,
    save_scan_results,
    mark_scan_failed,
    get_scan,
    get_scan_with_findings,
    get_all_scans,
    get_target_history,
    delete_scan,
)
from api.schemas import (
    ScanRequest,
    ScanStartedResponse,
    ScanDetailResponse,
    ScanSummaryResponse,
    HistoryResponse,
    StatsResponse,
    ErrorResponse,
)
from scanner.engine import run_scan
from reports.report_writer import save_report

router = APIRouter()


def _validate_scan_id(scan_id: str) -> None:
    """Raise 422 immediately if scan_id is not a valid UUID4, before hitting DB."""
    try:
        uuid.UUID(scan_id, version=4)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Invalid scan_id format. Must be a valid UUID4."
        )


# ── Background task ───────────────────────────────────────────────────────

def _run_scan_task(scan_id: str, target_url: str, enable_ai: bool, max_pages: int):
    """
    This function runs in a background thread after the API responds.
    It executes the full scan pipeline and saves results to SQLite.

    The try/except ensures that even if something crashes mid-scan,
    the scan record gets marked as 'failed' rather than stuck on 'running'.

    max_pages is passed directly to run_scan — we never mutate the global
    config value (which would be a thread-safety bug under concurrent scans).
    """
    try:
        scan_result, exec_summary = run_scan(
            target_url=target_url,
            run_ai=enable_ai,
            max_pages=max_pages,
        )

        # Persist to SQLite
        save_scan_results(scan_id, scan_result, exec_summary)

        # Also save file reports (JSON + TXT) as before
        save_report(scan_result, exec_summary)

    except Exception as e:
        mark_scan_failed(scan_id, str(e))


# ── POST /scan ────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    response_model=ScanStartedResponse,
    status_code=202,   # 202 Accepted = "request received, processing started"
    summary="Start a new security scan",
    description="Initiates a scan on the target URL. Returns a scan_id immediately. Poll /scan/{id}/status to check progress.",
)
def start_scan(request: Request, scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new scan. Rate limited to 10 requests/minute/IP (requires slowapi).
    The scan runs in the background — this endpoint returns in <1 second.
    """
    # ── SSRF guard ────────────────────────────────────────────────────────
    if not ALLOW_PRIVATE_TARGETS and not is_ssrf_safe(scan_request.target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Target URL resolves to a private or internal IP address. "
                "Set ALLOW_PRIVATE_TARGETS=true in .env to scan internal hosts."
            ),
        )

    # Create the DB record immediately (status: running)
    scan_id = create_scan(scan_request.target_url)

    # Queue the scan as a background task
    background_tasks.add_task(
        _run_scan_task,
        scan_id    = scan_id,
        target_url = scan_request.target_url,
        enable_ai  = scan_request.enable_ai,
        max_pages  = scan_request.max_pages,
    )

    return ScanStartedResponse(
        scan_id    = scan_id,
        target_url = scan_request.target_url,
        status     = "running",
        message    = f"Scan started. Poll GET /scan/{scan_id}/status to check progress.",
    )


# ── GET /scan/{scan_id} ───────────────────────────────────────────────────

@router.get(
    "/scan/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get full scan results",
    description="Returns complete scan data including all findings with AI analysis.",
)
def get_scan_results(scan_id: str):
    """
    Fetch full scan results including every finding.
    Returns 404 if scan_id doesn't exist.
    Returns 202 (still processing) if scan is still running.
    """
    _validate_scan_id(scan_id)
    data = get_scan_with_findings(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if data["status"] == "running":
        return JSONResponse(
            status_code=202,
            content={"scan_id": scan_id, "status": "running",
                     "message": "Scan still in progress. Try again shortly."}
        )

    # Convert findings rows to FindingResponse shape
    data["findings"] = [
        {**f, "id": f["id"] or "", "created_at": f.get("created_at", "")}
        for f in data.get("findings", [])
    ]

    return data


# ── GET /scan/{scan_id}/status ────────────────────────────────────────────

@router.get(
    "/scan/{scan_id}/status",
    summary="Check scan status",
    description="Lightweight status check. Use this for polling instead of /scan/{id}.",
)
def get_scan_status(scan_id: str):
    """
    Returns just the status and basic counts — no findings.
    Much lighter than fetching full results. Use this for polling.
    """
    _validate_scan_id(scan_id)
    data = get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    return {
        "scan_id":        scan_id,
        "status":         data["status"],
        "target_url":     data["target_url"],
        "total_findings": data.get("total_findings", 0),
        "risk_score":     data.get("risk_score"),
        "overall_risk":   data.get("overall_risk"),
        "duration_secs":  data.get("duration_secs"),
        "error":          data.get("error"),
    }


# ── GET /history ──────────────────────────────────────────────────────────

@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="List all past scans",
    description="Returns scan history sorted by most recent first. No findings included.",
)
def scan_history(limit: int = 50):
    """
    Returns a list of all past scans.
    Optional ?limit= query param (default 50, max 200).
    """
    limit = min(limit, 200)
    scans = get_all_scans(limit=limit)
    return HistoryResponse(total=len(scans), scans=scans)


# ── GET /history/{target} ─────────────────────────────────────────────────

@router.get(
    "/history/target/{target_url:path}",
    summary="Scan history for a specific target",
    description="Returns all scans for a specific URL — enables trend analysis over time.",
)
def target_history(target_url: str):
    """
    Trend view: all scans for one target, newest first.
    The :path converter allows URLs with slashes in the path parameter.
    """
    scans = get_target_history(target_url)
    if not scans:
        raise HTTPException(
            status_code=404,
            detail=f"No scan history found for '{target_url}'"
        )

    # Build a simple trend: is the risk score going up or down?
    scores = [s.get("risk_score") for s in scans if s.get("risk_score") is not None]
    trend  = None
    if len(scores) >= 2:
        trend = "improving" if scores[0] < scores[1] else "worsening" if scores[0] > scores[1] else "stable"

    return {
        "target_url":  target_url,
        "total_scans": len(scans),
        "trend":       trend,
        "scans":       scans,
    }


# ── GET /stats ────────────────────────────────────────────────────────────

@router.get(
    "/stats",
    summary="Aggregate statistics",
    description="Overview stats across all scans — total findings, most vulnerable targets, etc.",
)
def get_stats():
    """
    Aggregate statistics across all scans.
    This is the kind of data shown on the overview page of Detectify or Nessus.
    """
    from api.database import get_connection

    conn = get_connection()
    try:
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status='complete'"
        ).fetchone()[0]

        total_findings = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        critical = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
        ).fetchone()[0]

        high = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='HIGH'"
        ).fetchone()[0]

        most_scanned = conn.execute("""
            SELECT target_url, COUNT(*) as cnt
            FROM scans
            GROUP BY target_url
            ORDER BY cnt DESC
            LIMIT 1
        """).fetchone()

        avg_risk = conn.execute(
            "SELECT AVG(risk_score) FROM scans WHERE risk_score IS NOT NULL"
        ).fetchone()[0]
    finally:
        conn.close()

    return StatsResponse(
        total_scans          = total_scans,
        total_findings       = total_findings,
        critical_findings    = critical,
        high_findings        = high,
        most_scanned_target  = most_scanned["target_url"] if most_scanned else None,
        avg_risk_score       = round(avg_risk, 1) if avg_risk else None,
    )


# ── DELETE /scan/{scan_id} ────────────────────────────────────────────────

@router.delete(
    "/scan/{scan_id}",
    summary="Delete a scan record",
    description="Permanently deletes a scan and all its findings from the database.",
)
def delete_scan_record(scan_id: str):
    """Delete a scan and all associated findings."""
    _validate_scan_id(scan_id)
    deleted = delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return {"message": f"Scan '{scan_id}' deleted successfully"}
