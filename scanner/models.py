"""
scanner/models.py
─────────────────
Shared data structures used by every scanner module and the reporting layer.

WHY DATACLASSES?
  Using Python dataclasses keeps the core lightweight — no Pydantic or SQLAlchemy
  needed here. The API layer (api/schemas.py) handles validation separately.

HOW TO ADD A NEW FIELD:
  1. Add it to the Finding dataclass below with a type hint and default value
  2. Add it to the to_dict() method so it appears in JSON/API output
  3. Add it to the database schema in api/database.py if you want it persisted

SEVERITY LEVELS (highest → lowest):
  CRITICAL → confirmed, directly exploitable, immediate action needed
  HIGH     → likely exploitable, fix this week
  MEDIUM   → exploitable with conditions, fix this sprint
  LOW      → best practice violation, low impact
  INFO     → informational, no direct exploit
"""

from dataclasses import dataclass, field
from typing import Optional
from config import SEVERITY_ORDER


@dataclass
class Finding:
    """
    One detected vulnerability or security issue from any scanner module.

    Every scanner check (XSS, SQLi, headers, etc.) creates Finding objects
    and returns them as a list. The engine.py aggregates and deduplicates them.

    Fields filled by scanner modules:
      - vuln_type, severity, url, detail, evidence, remediation

    Fields filled by the AI layer (ai/AI_analyzer.py):
      - ai_verified, cvss_score, owasp_id, cwe_id, sans_rank

    Fields filled by the dashboard display (app.py):
      - These are read-only display fields, not set on the Finding itself
    """

    # ── Required fields (set by every scanner check) ──────────────────────
    vuln_type:   str   # Short name, e.g. "SQL Injection (Error-Based)"
    severity:    str   # One of: CRITICAL | HIGH | MEDIUM | LOW | INFO
    url:         str   # The affected URL (or hostname for site-wide findings)
    detail:      str   # Human-readable explanation of what was found and why it matters
    evidence:    str   # The exact header value, payload, or pattern that triggered this

    # ── Optional fields (filled by scanner or AI layer) ───────────────────
    remediation: str            = ""    # How to fix it (filled by AI for HIGH/CRITICAL)
    ai_verified: Optional[bool] = None  # True = AI confirmed | False = AI rejected | None = not sent to AI
    cvss_score:  Optional[float]= None  # CVSS 3.1 score (0.0–10.0), filled by AI layer

    # ── Framework classification fields (filled by AI layer) ──────────────
    # These let you filter/report findings by standard security frameworks.
    # Example values: owasp_id="A03:2021", cwe_id="CWE-89", sans_rank="CWE-89"
    owasp_id:    Optional[str]  = None  # OWASP Top 10 category, e.g. "A03:2021"
    cwe_id:      Optional[str]  = None  # CWE identifier, e.g. "CWE-89"
    sans_rank:   Optional[str]  = None  # SANS/CWE Top 25 rank, e.g. "#1 CWE-79"

    def to_dict(self) -> dict:
        """
        Serialize this finding to a plain dictionary.
        Used by: JSON reports, API responses, SQLite storage.

        If you add new fields above, add them here too so they appear in output.
        """
        return {
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "url":         self.url,
            "detail":      self.detail,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "ai_verified": self.ai_verified,
            "cvss_score":  self.cvss_score,
            "owasp_id":    self.owasp_id,
            "cwe_id":      self.cwe_id,
            "sans_rank":   self.sans_rank,
        }


@dataclass
class ScanResult:
    """
    Top-level container for a complete scan's output.

    Created by engine.run_scan() and passed through the pipeline:
      engine.py → AI_analyzer.py → database.py → reports/report_writer.py
    """

    target_url:    str
    pages_crawled: list[str]     = field(default_factory=list)  # All URLs visited
    findings:      list[Finding] = field(default_factory=list)  # All deduplicated findings
    scan_duration: float         = 0.0   # Total seconds from crawl start to AI done
    error:         Optional[str] = None  # Set if scan failed catastrophically

    # ── Convenience methods ────────────────────────────────────────────────

    def add(self, finding: Finding):
        """Add a single finding to this scan result."""
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """
        Return findings sorted from highest to lowest severity.
        Used by reports and the dashboard to show critical issues first.
        """
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity)
                          if f.severity in SEVERITY_ORDER else 99
        )

    def summary(self) -> dict:
        """
        Return a lightweight summary dict — used by the AI layer for the
        executive summary prompt, and by the dashboard for the stat cards.
        """
        # Count findings per severity level
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        return {
            "target":         self.target_url,
            "pages_crawled":  len(self.pages_crawled),
            "total_findings": len(self.findings),
            "by_severity":    counts,
            "scan_duration":  round(self.scan_duration, 2),
        }

    def to_dict(self) -> dict:
        """
        Full serialization for JSON reports and API responses.
        Includes all findings sorted by severity.
        """
        return {
            **self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
