"""
tui/backend.py
──────────────
Thin adapter between the Textual TUI and the existing scan pipeline.

The TUI never re-implements scanning. It calls the same deep module
everything else uses:

    scanner.engine.run_scan(target_url, on_progress, run_ai, max_pages)

Persistence goes through the same SQLite layer as the API
(api/database.py), and exports through reports/report_writer.py.

Two modes:
  - direct (default): run_scan() in-process in a worker thread.
  - artefacts: every completed direct scan is saved to DB + JSON/TXT,
    exactly like api/routes.py _run_scan_task does.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Optional

from config import (
    ALLOW_PRIVATE_TARGETS,
    ENABLE_AI_ANALYSIS,
    MAX_PAGES_TO_CRAWL,
    is_ssrf_safe,
)

ProgressCb = Optional[Callable[[str], None]]


def defaults() -> dict:
    """Form defaults — mirrors the ScanRequest seam (.env values)."""
    return {"enable_ai": ENABLE_AI_ANALYSIS, "max_pages": MAX_PAGES_TO_CRAWL}


def validate_target(target: str) -> tuple[str, str]:
    """Normalise + SSRF-check a target. Returns (url, error)."""
    url = (target or "").strip()
    if not url:
        return "", "Enter a target URL first."
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not ALLOW_PRIVATE_TARGETS and not is_ssrf_safe(url):
        return "", (
            "Target resolves to a private/internal address. "
            "Set ALLOW_PRIVATE_TARGETS=true in .env to scan it."
        )
    return url, ""


def run_scan_direct(
    target_url: str,
    run_ai: bool,
    max_pages: int,
    on_progress: ProgressCb = None,
) -> tuple[object, dict]:
    """Run the full pipeline synchronously. Call from a worker thread."""
    from scanner.engine import run_scan

    return run_scan(
        target_url=target_url,
        on_progress=on_progress,
        run_ai=run_ai,
        max_pages=max_pages,
    )


def persist(scan_id: str, scan_result, exec_summary: dict) -> dict:
    """Save results to SQLite + JSON/TXT files. Returns {'json','text'}."""
    from api.database import save_scan_results
    from reports.report_writer import save_report

    save_scan_results(scan_id, scan_result, exec_summary)
    return save_report(scan_result, exec_summary)


def create_scan_record(target_url: str) -> str:
    from api.database import create_scan, init_db

    init_db()
    return create_scan(target_url)


def list_scans(limit: int = 50) -> list[dict]:
    from api.database import get_all_scans, init_db

    init_db()
    return get_all_scans(limit=limit)


def get_scan(scan_id: str) -> dict | None:
    from api.database import get_scan_with_findings, init_db

    init_db()
    return get_scan_with_findings(scan_id)


def delete_scan_record(scan_id: str) -> bool:
    from api.database import delete_scan, init_db

    init_db()
    return delete_scan(scan_id)


def stats() -> dict:
    from api.database import get_connection, init_db

    init_db()
    conn = get_connection()
    try:
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status='complete'"
        ).fetchone()[0]
        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
        ).fetchone()[0]
        high = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE severity='HIGH'"
        ).fetchone()[0]
    finally:
        conn.close()
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical": critical,
        "high": high,
    }


def finding_to_row(f: dict) -> tuple:
    """DataTable row: (SEV, TYPE, URL, CVSS, AI). Mono text, no colour."""
    sev = f.get("severity", "INFO")
    cvss = f.get("cvss_score")
    cvss_s = f"{cvss:.1f}" if cvss is not None else "-"
    ai = f.get("ai_verified")
    ai_s = "YES" if ai == 1 else ("NO" if ai == 0 else "-")
    url = (f.get("url") or "")[:60]
    return (sev, f.get("vuln_type", ""), url, cvss_s, ai_s)


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def severity_tag(sev: str) -> str:
    """ASCII severity marker — no emoji, no colour."""
    return {
        "CRITICAL": "[!!]",
        "HIGH": "[! ]",
        "MEDIUM": "[* ]",
        "LOW": "[. ]",
        "INFO": "[i ]",
    }.get(sev, "[? ]")


def finding_detail_text(f: dict) -> str:
    """Plain-text detail pane for one finding (B&W, monospace-safe)."""
    lines = [
        f"{severity_tag(f.get('severity', 'INFO'))} {f.get('vuln_type', '')}",
        f"Severity : {f.get('severity', '')}"
        + (f"  CVSS {f.get('cvss_score'):.1f}" if f.get("cvss_score") is not None else ""),
        f"URL      : {f.get('url', '')}",
    ]
    if f.get("detail"):
        lines += ["", "WHAT WAS FOUND", "-" * 40, f["detail"]]
    if f.get("evidence"):
        lines += ["", "EVIDENCE", "-" * 40, f["evidence"][:2000]]
    if f.get("remediation"):
        rem = f["remediation"].replace("\\n", "\n")
        lines += ["", "REMEDIATION", "-" * 40, rem[:4000]]
    return "\n".join(lines)


def summary_text(scan: dict) -> str:
    s = scan.get("summary_json") or {}
    by_sev = s.get("by_severity", {})
    es = scan.get("exec_summary") or {}
    if isinstance(es, str):
        try:
            es = json.loads(es)
        except (json.JSONDecodeError, TypeError):
            es = {}
    lines = [
        f"Target   : {scan.get('target_url', '')}",
        f"Status   : {scan.get('status', '')}   "
        f"Pages: {scan.get('pages_crawled', 0)}   "
        f"Duration: {(scan.get('duration_secs') or 0):.0f}s",
        f"Risk     : {scan.get('overall_risk') or 'N/A'} "
        f"({scan.get('risk_score', '?')}/100)   "
        f"Findings: {scan.get('total_findings', 0)}",
        "",
        "BY SEVERITY",
    ]
    total = max(scan.get("total_findings", 0), 1)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = by_sev.get(sev, 0)
        bar = "#" * min(n, 40)
        lines.append(f"  {severity_tag(sev)} {sev:<8} {n:>3}  {bar}")
    _ = total
    if es.get("executive_summary"):
        lines += ["", "EXECUTIVE SUMMARY", "-" * 40, es["executive_summary"][:2000]]
    if es.get("immediate_actions"):
        lines += ["", "IMMEDIATE ACTIONS"]
        for i, a in enumerate(es["immediate_actions"][:8], 1):
            lines.append(f"  {i}. {a}")
    return "\n".join(lines)
