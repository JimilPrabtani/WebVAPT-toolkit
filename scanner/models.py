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
from collections import Counter
from config import SEVERITY_ORDER


# ── Finding category map ──────────────────────────────────────────────────
# Maps vuln_type prefixes → human-readable categories for grouped reporting.
# Centralized here so reports, the API, and the TUI all group identically
# without every scanner module needing to set a category field.

CATEGORY_MAP: list[tuple[str, str]] = [
    ("Cross-Site Scripting",        "Cross-Site Scripting (XSS)"),
    ("DOM Sink",                    "Cross-Site Scripting (XSS)"),
    ("XSS Attack Surface",          "Cross-Site Scripting (XSS)"),
    ("SQL Injection",               "Injection (SQLi)"),
    ("SQLi Attack Surface",         "Injection (SQLi)"),
    ("Server-Side Template Injection", "Injection (SSTI)"),
    ("Path Traversal",              "Injection (Path Traversal)"),
    ("Local File Inclusion",        "Injection (Path Traversal)"),
    ("Missing Header",              "Security Misconfiguration"),
    ("Weak Header",                 "Security Misconfiguration"),
    ("CORS Misconfiguration",       "Security Misconfiguration"),
    ("TLS:",                        "Security Misconfiguration"),
    ("Insecure Transport",          "Security Misconfiguration"),
    ("Sensitive Path",              "Sensitive Data Exposure"),
    ("Directory Listing",           "Sensitive Data Exposure"),
    ("Secret Exposure",             "Sensitive Data Exposure"),
    ("Information Disclosure",      "Sensitive Data Exposure"),
    ("Insecure Cookie",             "Session Management"),
    ("JWT Algorithm",               "Broken Authentication"),
    ("Missing CSRF",                "Broken Access Control"),
    ("Open Redirect",               "Open Redirect"),
    ("LLM Prompt Surface",          "LLM/AI Application Risk"),
    ("Exposed Model",               "LLM/AI Application Risk"),
    ("Prompt Injection",            "LLM/AI Application Risk"),
    ("Vulnerable Component",        "Vulnerable Components"),
]


def finding_category(vuln_type: str) -> str:
    """Return the report category for a vuln_type string."""
    for prefix, category in CATEGORY_MAP:
        if vuln_type.startswith(prefix):
            return category
    return "Other"


# ── OWASP Top 10 (2021) fallback map ───────────────────────────────────────
# Used when the AI layer hasn't classified a finding (AI disabled, LOW/INFO
# findings that are never sent to AI). AI-provided owasp_id always wins.

OWASP_FALLBACK: list[tuple[str, str]] = [
    ("Cross-Site Scripting (XSS)",  "A03:2021"),
    ("Injection (SQLi)",            "A03:2021"),
    ("Injection (SSTI)",            "A03:2021"),
    ("Injection (Path Traversal)",  "A03:2021"),
    ("Security Misconfiguration",   "A05:2021"),
    ("Sensitive Data Exposure",     "A05:2021"),
    ("Session Management",          "A07:2021"),
    ("Broken Authentication",       "A07:2021"),
    ("Broken Access Control",       "A01:2021"),
    ("Open Redirect",               "A01:2021"),
    ("LLM/AI Application Risk",     "LLM01:2025"),
    ("Vulnerable Components",       "A06:2021"),
]

OWASP_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable Components",
    "A07:2021": "Authentication Failures",
    "A08:2021": "Data/Software Integrity Failures",
    "A09:2021": "Logging/Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


def finding_owasp(vuln_type: str, owasp_id: Optional[str] = None) -> str:
    """Return the OWASP Top 10 id for a finding (AI value wins, else fallback)."""
    if owasp_id:
        return owasp_id
    category = finding_category(vuln_type)
    for cat, owasp in OWASP_FALLBACK:
        if category == cat:
            return owasp
    return "Unmapped"


# ── Systemic prevention guidance (future-proofing) ──────────────────────────
# Tells teams how to stop the whole BUG CLASS from recurring (process/tooling),
# not just how to fix this one instance. Engine appends this to findings the
# AI didn't already cover, so --no-ai reports still teach prevention.

PREVENTION_MAP = {
    "Cross-Site Scripting (XSS)":
        "Enforce auto-escaping templates everywhere and a nonce-based CSP; add a DAST "
        "scan plus a 'no innerHTML with variables' SAST rule to CI so new XSS can't merge.",
    "Injection (SQLi)":
        "Allow data access only through an ORM / parameterized queries; add a SAST rule "
        "that fails the build on string-concatenated SQL and review all raw-query call sites.",
    "Injection (SSTI)":
        "Ban rendering templates from user input; sandbox the template engine and add "
        "server-side validation rejecting template metacharacters ({{, ${, #{}).",
    "Injection (Path Traversal)":
        "Resolve all file access through an allowlist + canonical-path check helper; "
        "unit-test it with traversal payloads and run the app with least-privilege file rights.",
    "Security Misconfiguration":
        "Ship hardened security-header defaults in the base image / framework middleware "
        "and add a config-lint step (or this scanner) to the deploy pipeline.",
    "Sensitive Data Exposure":
        "Move secrets to a vault / env-only config above the webroot; add pre-commit "
        "secret scanning (gitleaks) and block sensitive paths at the reverse proxy.",
    "Session Management":
        "Set HttpOnly + Secure + SameSite=Lax cookie defaults in one session middleware; "
        "verify flags in an automated smoke test after every deploy.",
    "Broken Authentication":
        "Pin the JWT algorithm server-side and reject alg:none; require MFA on privileged "
        "roles and rate-limit + alert on authentication endpoints.",
    "Broken Access Control":
        "Add anti-CSRF tokens to every state-changing form and enforce server-side "
        "authorization checks on every object ID (test with two accounts in QA).",
    "Open Redirect":
        "Replace open redirect targets with an allowlist / ID-mapped destinations; "
        "add an automated test that rejects off-site redirect values.",
    "LLM/AI Application Risk":
        "Treat model output as untrusted: validate it, strip it of secrets, enforce "
        "least-privilege tool access, and log prompts/outputs for abuse review.",
    "Vulnerable Components":
        "Enable Dependabot/Renovate plus scheduled OSV scans; fail CI on known-critical "
        "dependency CVEs before they reach production.",
}


def prevention_for(vuln_type: str) -> str:
    """Return systemic prevention guidance for a finding's category."""
    return PREVENTION_MAP.get(finding_category(vuln_type), "")


# ── Attack-chain builder (exploitation chains for legal pentesting) ─────────
# Deterministic rules linking finding CATEGORIES into multi-step attack paths:
# recon → initial access → impact. Each rule fires only when ALL its steps are
# evidenced by real findings in this scan — no invented links.

CHAIN_RULES = [
    {
        "title": "XSS Session Hijack",
        "needs": ["Cross-Site Scripting (XSS)", "Session Management"],
        "impact": "Full account takeover of any victim who opens the crafted link.",
        "narrative": (
            "1. RECON: the scan confirms user input is reflected unescaped ({xss}). "
            "2. EXPLOIT: attacker crafts a link whose payload reads document.cookie — "
            "possible because session cookies lack HttpOnly ({sess}). "
            "3. IMPACT: stolen session token is replayed → victim account takeover "
            "without knowing any password."
        ),
    },
    {
        "title": "Missing CSP → Drive-By XSS",
        "needs": ["Security Misconfiguration", "Cross-Site Scripting (XSS)"],
        "impact": "Stored/reflected script execution with no browser-level safety net.",
        "narrative": (
            "1. RECON: no Content-Security-Policy ({misc}) removes the browser's last "
            "line of defence against injected scripts. "
            "2. EXPLOIT: the reflected XSS ({xss}) payload runs with full page privileges. "
            "3. IMPACT: keylogging, credential harvesting, or defacement in victims' browsers."
        ),
    },
    {
        "title": "Database Extraction",
        "needs": ["Sensitive Data Exposure", "Injection (SQLi)"],
        "impact": "Full database dump: credentials, PII, password hashes.",
        "narrative": (
            "1. RECON: version/secret exposure ({expo}) fingerprints the stack for tailored payloads. "
            "2. EXPLOIT: SQL injection ({sqli}) executes attacker SQL through the app. "
            "3. IMPACT: UNION-based or blind extraction of every reachable table; "
            "cracked hashes become valid logins."
        ),
    },
    {
        "title": "SQLi → Authentication Bypass",
        "needs": ["Injection (SQLi)", "Broken Authentication"],
        "impact": "Login as any user (often admin) with no password.",
        "narrative": (
            "1. EXPLOIT: SQL injection ({sqli}) dumps the users table or short-circuits "
            "the login query (' OR '1'='1). "
            "2. ESCALATE: weak auth controls ({auth}) — forged/unsigned tokens or missing "
            "checks — turn the dump into a working session. "
            "3. IMPACT: administrative access from an unauthenticated starting point."
        ),
    },
    {
        "title": "Phishing → Forged State-Changing Action",
        "needs": ["Open Redirect", "Broken Access Control"],
        "impact": "Victim performs attacker-chosen actions (email/password change, posts).",
        "narrative": (
            "1. LURE: open redirect ({redir}) makes evil.com look like the trusted site. "
            "2. EXPLOIT: victim clicks while logged in; CSRF-able forms ({csrf}) submit "
            "cross-site with the victim's cookies. "
            "3. IMPACT: account settings changed or content posted as the victim."
        ),
    },
    {
        "title": "Exposed Secret → Auth Bypass",
        "needs": ["Sensitive Data Exposure", "Broken Authentication"],
        "impact": "Attacker logs in with leaked credentials/tokens.",
        "narrative": (
            "1. RECON: hardcoded or exposed secret ({expo}) harvested from responses. "
            "2. EXPLOIT: the secret is replayed against weak auth ({auth}). "
            "3. IMPACT: authenticated access without brute force or phishing."
        ),
    },
    {
        "title": "AI App Prompt Abuse → Data Exfiltration",
        "needs": ["LLM/AI Application Risk", "Sensitive Data Exposure"],
        "impact": "Model tricked into leaking system prompts, secrets, or other users' data.",
        "narrative": (
            "1. RECON: exposed AI endpoint/model surface ({llm}). "
            "2. EXPLOIT: prompt-injection input ('ignore previous instructions…') abuses "
            "excessive agency or missing output filtering. "
            "3. IMPACT: exfiltrated secrets or poisoned downstream actions ({expo})."
        ),
    },
]

_CHAIN_SLOT = {
    "Cross-Site Scripting (XSS)": "xss",
    "Session Management": "sess",
    "Security Misconfiguration": "misc",
    "Sensitive Data Exposure": "expo",
    "Injection (SQLi)": "sqli",
    "Broken Authentication": "auth",
    "Open Redirect": "redir",
    "Broken Access Control": "csrf",
    "LLM/AI Application Risk": "llm",
}


def build_attack_chains(findings: list) -> list:
    """
    Link findings into evidenced exploitation chains (recon → exploit → impact).

    Returns at most 5 chains ordered by severity. Each chain cites the actual
    finding (type + URL) backing every step — pentesters can copy the chain
    into a report's narrative and reproduce each link during authorized testing.
    """
    by_cat: dict[str, list] = {}
    for f in findings:
        by_cat.setdefault(finding_category(f.vuln_type), []).append(f)

    chains = []
    for rule in CHAIN_RULES:
        if not all(c in by_cat for c in rule["needs"]):
            continue
        involved = [by_cat[c][0] for c in rule["needs"]]
        slots = {
            _CHAIN_SLOT.get(c, c): f"{by_cat[c][0].vuln_type} at {by_cat[c][0].url}"
            for c in rule["needs"]
        }
        worst = min(
            (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99
             for f in involved),
            default=99,
        )
        chains.append({
            "title":    rule["title"],
            "severity": SEVERITY_ORDER[worst] if worst < len(SEVERITY_ORDER) else "INFO",
            "steps":    [
                {"category": c, "finding": f.vuln_type, "url": f.url, "severity": f.severity}
                for c, f in zip(rule["needs"], involved)
            ],
            "narrative": rule["narrative"].format(**slots),
            "impact":    rule["impact"],
        })

    chains.sort(key=lambda c: SEVERITY_ORDER.index(c["severity"]))
    return chains[:5]


# ── Heuristic risk score (no-AI fallback) ───────────────────────────────────
# Weights chosen so a single CRITICAL already pushes HIGH territory,
# matching how the AI prompt describes overall_risk bands.

_RISK_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def heuristic_risk(by_severity: dict) -> tuple[int, str]:
    """
    Deterministic 0–100 risk score + overall risk band from severity counts.
    Used when AI analysis is disabled or fails, so --no-ai scans still
    produce a complete report instead of an empty executive summary.
    """
    score = min(100, sum(_RISK_WEIGHTS.get(s, 0) * n for s, n in by_severity.items()))
    if by_severity.get("CRITICAL"):
        band = "CRITICAL"
    elif by_severity.get("HIGH"):
        band = "HIGH"
    elif by_severity.get("MEDIUM"):
        band = "MEDIUM"
    else:
        band = "LOW"
    return score, band


@dataclass
class Finding:
    """
    One detected vulnerability or security issue from any scanner module.

    Every scanner check (XSS, SQLi, headers, etc.) creates Finding objects
    and returns them as a list. The engine.py aggregates and deduplicates them.

    Fields filled by scanner modules:
      - vuln_type, severity, url, detail, evidence, remediation

    Fields filled by the AI layer (ai/AI_analyzer.py):
      - ai_verified, cvss_score, owasp_id, cwe_id, sans_rank, cve_ids

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
    cve_ids:     list          = field(default_factory=list)  # AI-suggested CVE IDs, e.g. ["CVE-2023-1234"]

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
            "cve_ids":     self.cve_ids,
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
    # Scan coverage — filled by engine.py (what was actually tested, not just found)
    coverage:      dict          = field(default_factory=dict)

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
        Includes category breakdown, OWASP Top 10 mapping, top affected URLs,
        and scan coverage so reports are comprehensive even without AI.
        """
        # Count findings per severity level
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1

        by_category: Counter = Counter()
        by_owasp: Counter = Counter()
        by_url: Counter = Counter()
        for f in self.findings:
            by_category[finding_category(f.vuln_type)] += 1
            by_owasp[finding_owasp(f.vuln_type, f.owasp_id)] += 1
            by_url[f.url] += 1

        return {
            "target":         self.target_url,
            "pages_crawled":  len(self.pages_crawled),
            "total_findings": len(self.findings),
            "by_severity":    counts,
            "by_category":    dict(by_category),
            "by_owasp":       dict(by_owasp),
            "top_urls":       [
                {"url": url, "findings": n}
                for url, n in by_url.most_common(5)
            ],
            "attack_chains":  build_attack_chains(self.findings),
            "coverage":       self.coverage,
            "scan_duration":  round(self.scan_duration, 2),
        }

    def heuristic_summary(self) -> dict:
        """
        Build a deterministic executive-summary-shaped dict from severity
        counts + top findings. Same keys the AI summary uses (overall_risk,
        risk_score, executive_summary, key_risks, immediate_actions) plus
        source="heuristic" so consumers know no LLM was involved.
        """
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        score, band = heuristic_risk(counts)

        top = self.sorted_findings()[:3]
        key_risks = [f"{f.severity}: {f.vuln_type} at {f.url}" for f in top]
        actions = [
            f"Fix {f.vuln_type} at {f.url}"
            for f in top if f.severity in ("CRITICAL", "HIGH")
        ]

        if self.findings:
            overview = (
                f"Scan of {self.target_url} found {len(self.findings)} issue(s): "
                + ", ".join(f"{n} {s}" for s, n in counts.items() if n)
                + f". Overall risk: {band} ({score}/100, heuristic score)."
            )
        else:
            overview = (
                f"Scan of {self.target_url} found no issues across "
                f"{len(self.pages_crawled)} crawled page(s). "
                "This is a point-in-time automated result — manual testing is still recommended."
            )

        return {
            "overall_risk":      band,
            "risk_score":        score,
            "executive_summary": overview,
            "key_risks":         key_risks,
            "immediate_actions": actions,
            "source":            "heuristic",
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
