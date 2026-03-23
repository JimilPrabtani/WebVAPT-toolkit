"""
scanner/models.py
─────────────────
Shared data structures used by every scanner module and the reporting layer.
Using dataclasses keeps things lightweight (no Pydantic needed in the core).
"""
from dataclasses import dataclass, field
from typing import Optional
from config import SEVERITY_ORDER


@dataclass
class Finding:
    """
    One detected vulnerability or security issue.
    """
    vuln_type:   str            # e.g. "SQL Injection", "Missing Header"
    severity:    str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url:         str            # affected URL
    detail:      str            # human-readable description of the finding
    evidence:    str            # the exact string / header / payload that triggered it
    remediation: str = ""       # filled in by the AI layer (Sprint 3)
    ai_verified: Optional[bool] = None   # True/False/None = not yet checked
    cvss_score:  Optional[float] = None  # optionally filled by AI layer

    def to_dict(self) -> dict:
        return {
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "url":         self.url,
            "detail":      self.detail,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "ai_verified": self.ai_verified,
            "cvss_score":  self.cvss_score,
        }


@dataclass
class ScanResult:
    """
    Top-level container for a complete scan.
    """
    target_url:    str
    pages_crawled: list[str]          = field(default_factory=list)
    findings:      list[Finding]      = field(default_factory=list)
    scan_duration: float              = 0.0   # seconds
    error:         Optional[str]      = None

    # ── convenience ──────────────────────────────────────────────────────

    def add(self, finding: Finding):
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted highest → lowest severity."""
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity)
                          if f.severity in SEVERITY_ORDER else 99
        )

    def summary(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return {
            "target":        self.target_url,
            "pages_crawled": len(self.pages_crawled),
            "total_findings": len(self.findings),
            "by_severity":   counts,
            "scan_duration": round(self.scan_duration, 2),
        }

    def to_dict(self) -> dict:
        return {
            **self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
