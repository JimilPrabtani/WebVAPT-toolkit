"""
reports/report_writer.py
────────────────────────
Saves scan results in two formats:
  1. JSON  — machine-readable, used by the FastAPI layer (Sprint 4)
  2. TEXT  — human-readable terminal/file report

Usage:
    from reports.report_writer import save_report
    paths = save_report(scan_result, exec_summary)
    print(paths)  # {'json': '...', 'text': '...'}
"""

import json
import os
from datetime import datetime
from scanner.models import ScanResult
from config import SEVERITY_ORDER


# Save generated reports to data/reports/ at the project root.
# This separates generated output from the Python source files in reports/.
REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),  # reports/ source dir
    "..",                                         # project root
    "data",
    "reports",
)


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _filename_base(target_url: str) -> str:
    """Generate a safe filename from the target URL + timestamp."""
    safe = target_url.replace("https://", "").replace("http://", "")
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in safe)
    safe = safe[:40]
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe}_{ts}"


# ── JSON Report ───────────────────────────────────────────────────────────

def save_json_report(scan_result: ScanResult, exec_summary: dict) -> str:
    """Write full scan data to a .json file. Returns the file path."""
    _ensure_dir()
    base    = _filename_base(scan_result.target_url)
    path    = os.path.join(REPORTS_DIR, f"{base}.json")

    payload = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "tool": "WebPenTest AI Toolkit v1.0",
        },
        "executive_summary": exec_summary,
        "scan": scan_result.to_dict(),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return path


# ── Text Report ───────────────────────────────────────────────────────────

SEV_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


def save_text_report(scan_result: ScanResult, exec_summary: dict) -> str:
    """Write a human-readable .txt report. Returns the file path."""
    _ensure_dir()
    base  = _filename_base(scan_result.target_url)
    path  = os.path.join(REPORTS_DIR, f"{base}.txt")
    lines = []

    def h1(text):  lines.append(f"\n{'═'*60}\n  {text}\n{'═'*60}")
    def h2(text):  lines.append(f"\n{'─'*50}\n  {text}\n{'─'*50}")
    def ln(text=""):  lines.append(text)

    # ── Header ────────────────────────────────────────────────────────
    h1("WEB APPLICATION PENETRATION TEST REPORT")
    ln(f"  Tool       : WebPenTest AI Toolkit v1.0")
    ln(f"  Target     : {scan_result.target_url}")
    ln(f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    ln(f"  Duration   : {scan_result.scan_duration:.1f}s")
    ln(f"  Pages Scanned: {len(scan_result.pages_crawled)}")

    # ── Executive Summary ─────────────────────────────────────────────
    if exec_summary:
        h1("EXECUTIVE SUMMARY")
        risk = exec_summary.get("overall_risk", "UNKNOWN")
        score = exec_summary.get("risk_score", "N/A")
        ln(f"  Overall Risk  : {SEV_ICONS.get(risk, '⚪')} {risk}")
        ln(f"  Risk Score    : {score}/100")
        ln()
        ln(exec_summary.get("executive_summary", ""))

        if exec_summary.get("key_risks"):
            ln()
            ln("  KEY RISKS:")
            for r in exec_summary["key_risks"]:
                ln(f"    • {r}")

        if exec_summary.get("immediate_actions"):
            ln()
            ln("  IMMEDIATE ACTIONS REQUIRED:")
            for i, a in enumerate(exec_summary["immediate_actions"], 1):
                ln(f"    {i}. {a}")

        if exec_summary.get("positive_observations"):
            ln()
            ln(f"  POSITIVES: {exec_summary['positive_observations']}")

    # ── Findings Summary ──────────────────────────────────────────────
    h1("FINDINGS SUMMARY")
    summary = scan_result.summary()
    ln(f"  Total Findings: {summary['total_findings']}")
    ln()
    for sev in SEVERITY_ORDER:
        count = summary["by_severity"].get(sev, 0)
        icon  = SEV_ICONS.get(sev, "")
        bar   = "█" * count
        ln(f"  {icon} {sev:<10} {count:>3}  {bar}")

    # ── Detailed Findings ─────────────────────────────────────────────
    h1("DETAILED FINDINGS")

    findings = scan_result.sorted_findings()
    if not findings:
        ln("  No vulnerabilities detected.")
    else:
        for idx, f in enumerate(findings, 1):
            icon = SEV_ICONS.get(f.severity, "")
            h2(f"[{idx}] {icon} {f.vuln_type}")
            ln(f"  Severity  : {f.severity}" +
               (f" (CVSS {f.cvss_score:.1f})" if f.cvss_score else ""))
            ln(f"  URL       : {f.url}")
            if f.ai_verified is True:
                ln(f"  AI Status : ✅ Verified by Gemini")
            elif f.ai_verified is False:
                ln(f"  AI Status : ⚠️  Could not verify")
            ln()
            ln("  DETAIL:")
            for line in f.detail.split("\n"):
                ln(f"    {line}")
            ln()
            ln("  EVIDENCE:")
            ln(f"    {f.evidence}")

            if f.remediation:
                ln()
                ln("  REMEDIATION:")
                for line in f.remediation.split("\n"):
                    ln(f"    {line}")
            ln()

    # ── Pages Crawled ─────────────────────────────────────────────────
    h1("PAGES CRAWLED")
    for page in scan_result.pages_crawled:
        ln(f"  • {page}")

    # ── Footer ────────────────────────────────────────────────────────
    h1("END OF REPORT")
    ln("  DISCLAIMER: This tool is for authorized security testing only.")
    ln("  Always obtain written permission before scanning any target.")
    ln()

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return path


# ── Main entrypoint ───────────────────────────────────────────────────────

def save_report(scan_result: ScanResult, exec_summary: dict) -> dict:
    """
    Save both JSON and text reports.
    Returns dict with file paths: {'json': '...', 'text': '...'}
    """
    json_path = save_json_report(scan_result, exec_summary)
    text_path = save_text_report(scan_result, exec_summary)
    return {"json": json_path, "text": text_path}
