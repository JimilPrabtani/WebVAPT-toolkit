"""
api/schemas.py
──────────────
Pydantic models define the exact shape of every API request and response.

Why this matters:
  - FastAPI uses these to AUTO-VALIDATE incoming data
    (if someone sends an invalid URL, FastAPI rejects it before your code runs)
  - FastAPI uses these to AUTO-GENERATE the /docs UI
    (you get a full interactive API explorer for free)
  - They act as living documentation — anyone reading this file knows
    exactly what the API accepts and returns

Think of these as contracts between your API and whoever calls it.
"""

from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional
from datetime import datetime


# ── REQUEST schemas (what the API accepts) ────────────────────────────────

class ScanRequest(BaseModel):
    """
    Body of POST /scan
    The client sends this JSON to start a new scan.
    """
    target_url: str
    enable_ai:  bool = True    # Can disable AI for faster scans
    max_pages:  int  = 20      # Override MAX_PAGES_TO_CRAWL per-scan

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Auto-add http:// if scheme is missing."""
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        if not v or len(v) < 4:
            raise ValueError("Invalid URL")
        return v


# ── RESPONSE schemas (what the API returns) ───────────────────────────────

class ScanStartedResponse(BaseModel):
    """
    Returned immediately when POST /scan is called.
    The scan runs in the background — client uses scan_id to poll for results.
    This is the async pattern used by Nessus, Tenable, and Qualys.
    """
    scan_id:    str
    target_url: str
    status:     str   # always "running" at this point
    message:    str


class FindingResponse(BaseModel):
    """One vulnerability finding."""
    id:          str
    vuln_type:   str
    severity:    str
    url:         str
    detail:      Optional[str] = None
    evidence:    Optional[str] = None
    remediation: Optional[str] = None
    ai_verified: Optional[int] = None   # 1=verified, 0=not verified, None=not checked
    cvss_score:  Optional[float] = None
    created_at:  str


class ScanSummaryResponse(BaseModel):
    """
    Lightweight scan record — used in /history list.
    No findings included (would be too much data for a list view).
    """
    id:             str
    target_url:     str
    status:         str
    started_at:     str
    completed_at:   Optional[str]  = None
    duration_secs:  Optional[float]= None
    pages_crawled:  Optional[int]  = None
    total_findings: Optional[int]  = None
    risk_score:     Optional[int]  = None
    overall_risk:   Optional[str]  = None
    error:          Optional[str]  = None


class ScanDetailResponse(BaseModel):
    """
    Full scan record with all findings — returned by GET /scan/{id}
    """
    id:             str
    target_url:     str
    status:         str
    started_at:     str
    completed_at:   Optional[str]   = None
    duration_secs:  Optional[float] = None
    pages_crawled:  Optional[int]   = None
    total_findings: Optional[int]   = None
    risk_score:     Optional[int]   = None
    overall_risk:   Optional[str]   = None
    summary_json:   Optional[dict]  = None
    exec_summary:   Optional[dict]  = None
    findings:       list[FindingResponse] = []
    error:          Optional[str]   = None


class HistoryResponse(BaseModel):
    """List of past scans — returned by GET /history"""
    total:  int
    scans:  list[ScanSummaryResponse]


class StatsResponse(BaseModel):
    """
    Aggregate statistics across all scans.
    This is the kind of data Detectify shows on their overview dashboard.
    """
    total_scans:        int
    total_findings:     int
    critical_findings:  int
    high_findings:      int
    most_scanned_target: Optional[str]
    avg_risk_score:     Optional[float]


class ErrorResponse(BaseModel):
    """Standard error shape returned on 4xx/5xx responses."""
    error:   str
    detail:  Optional[str] = None
