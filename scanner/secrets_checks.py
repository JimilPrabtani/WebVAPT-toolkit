"""
scanner/secrets_checks.py
──────────────────────────
Scans HTTP response bodies for hardcoded secrets, API keys, and credentials
that the target application accidentally leaks in its HTML, JS, or JSON output.

This is passive scanning — we inspect what the server already returns,
we don't inject anything. References:
  - Gitleaks rule patterns (https://github.com/gitleaks/gitleaks)
  - MITRE T1552.001 (Credentials in Files)
  - CWE-312 (Cleartext Storage of Sensitive Information)
  - OWASP A02:2021 (Cryptographic Failures)
"""

import re
import requests
from scanner.models import Finding

# ── Secret patterns ───────────────────────────────────────────────────────
# Each entry: (regex_pattern, label, severity, cwe)
SECRET_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}",                          "AWS Access Key ID",         "CRITICAL", "CWE-312"),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\"'\s:=]+([A-Za-z0-9/+]{40})",
                                                    "AWS Secret Access Key",     "CRITICAL", "CWE-312"),
    # Google / GCP
    (r"AIza[0-9A-Za-z\-_]{35}",                    "Google API Key",            "HIGH",     "CWE-312"),
    (r"(?i)gcp[_\-]?key[\"'\s:=]+([A-Za-z0-9\-_]{20,})",
                                                    "GCP Credential",            "HIGH",     "CWE-312"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}",                       "GitHub Personal Access Token", "CRITICAL", "CWE-312"),
    (r"github_pat_[A-Za-z0-9_]{82}",               "GitHub Fine-grained PAT",   "CRITICAL", "CWE-312"),
    # OpenAI
    (r"sk-[A-Za-z0-9]{48}",                        "OpenAI API Key",            "CRITICAL", "CWE-312"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}",                  "Stripe Live Secret Key",    "CRITICAL", "CWE-312"),
    (r"pk_live_[0-9a-zA-Z]{24,}",                  "Stripe Live Publishable Key","HIGH",    "CWE-312"),
    # Slack
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}",             "Slack Token",               "HIGH",     "CWE-312"),
    # Generic high-entropy tokens
    (r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"
     r"[\"'\s:=]+([A-Za-z0-9+/\-_]{32,})",         "Possible API Key/Token",    "HIGH",     "CWE-312"),
    # DB connection strings
    (r"(?i)(?:mysql|postgres|postgresql|mssql|mongodb)://[^\s\"'>]{10,}",
                                                    "Database Connection String", "CRITICAL", "CWE-312"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",  "Private Key",               "CRITICAL", "CWE-312"),
    # JWT (any JWT in a response body is suspicious)
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                                                    "JSON Web Token (JWT)",      "MEDIUM",   "CWE-312"),
]

COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), label, sev, cwe)
    for pattern, label, sev, cwe in SECRET_PATTERNS
]


def check_secrets_in_response(url: str, response: requests.Response) -> list[Finding]:
    """
    Scan the response body for secret patterns.
    Returns findings for each unique secret type discovered.
    """
    findings  = []
    body      = response.text
    seen_types: set[str] = set()

    for pattern, label, severity, cwe in COMPILED_PATTERNS:
        if label in seen_types:
            continue   # Report each type once per page

        match = pattern.search(body)
        if match:
            seen_types.add(label)
            # Extract a redacted snippet for evidence (never log full secret)
            matched_text  = match.group()
            redacted      = matched_text[:6] + "..." + matched_text[-4:] if len(matched_text) > 12 else matched_text[:4] + "..."
            findings.append(Finding(
                vuln_type  = f"Secret Exposure: {label}",
                severity   = severity,
                url        = url,
                detail     = (
                    f"A {label} was found in the HTTP response body of this page. "
                    f"({cwe}) Exposed credentials allow attackers to authenticate as the "
                    "service directly — no brute force required. Rotate immediately."
                ),
                evidence   = f"Pattern matched: {label} — redacted sample: {redacted}",
                remediation= (
                    f"1. Rotate the exposed {label} credential immediately. "
                    "2. Remove secrets from source code, HTML, and JS bundles. "
                    "3. Use environment variables or a secrets manager (Vault, AWS Secrets Manager). "
                    "4. Audit git history with Gitleaks/TruffleHog to check for prior exposure."
                ),
            ))

    return findings


def run_all_secrets_checks(url: str, response: requests.Response) -> list[Finding]:
    return check_secrets_in_response(url, response)
