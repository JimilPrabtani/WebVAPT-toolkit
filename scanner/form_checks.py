"""
scanner/form_checks.py
──────────────────────
Active HTML form testing — the engine's biggest previous blind spot.

Until now forms were only FLAGGED as INFO ("manual testing recommended").
This module actually SUBMITS them:

  1. Reflected input  — fill every text field with a unique probe marker and
     check whether it is echoed unescaped in the response (XSS).
  2. SQL errors       — submit a single-quote probe and look for database
     error signatures in the response (SQLi).
  3. Missing CSRF     — POST forms without a token field are flagged (MEDIUM).

SCOPE LIMITS (deliberate, to stay safe + fast):
  - Max 10 forms per page, max 5 testable fields per form.
  - One XSS probe + one SQLi probe per field (not the full probe lists —
    the URL-param checks already cover those exhaustively).
  - File-upload and multipart forms are skipped (no binary handling).
  - GET forms are tested via query string; POST forms via urlencoded body.

REFERENCES:
  - OWASP A03:2021 — Injection, A01:2021 — Broken Access Control (CSRF)
  - CWE-79 (XSS), CWE-89 (SQLi), CWE-352 (CSRF)
"""

from typing import List
from urllib.parse import urljoin
import threading
import requests
from bs4 import BeautifulSoup
from scanner.models import Finding
from scanner.sqli_checks import _find_db_error
from scanner.fetcher import _session
from config import SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS

# ── Submission counter (scan coverage) ──────────────────────────────────
# _scan_page runs in worker threads, so the counter is lock-guarded.
# engine.py resets it at scan start and reads it when the scan completes.

_submitted = 0
_lock = threading.Lock()


def reset_stats() -> None:
    """Zero the submission counter. Called once per scan by engine.py."""
    global _submitted
    with _lock:
        _submitted = 0


def submitted_count() -> int:
    """Return how many form submissions were attempted this scan."""
    with _lock:
        return _submitted


def _count_submission() -> None:
    global _submitted
    with _lock:
        _submitted += 1

MAX_FORMS_PER_PAGE = 10
MAX_FIELDS_PER_FORM = 5

# Distinctive marker — unlikely to appear in a page by coincidence.
XSS_MARKER = "xssprobe7x9"
XSS_PROBE = f'\"><svg onload=alert({XSS_MARKER})>'
SQLI_PROBE = "'"

# Input types we can safely fill with text probes.
TESTABLE_TYPES = (None, "text", "search", "email", "url", "number", "tel", "password", "hidden")

# Field names that indicate a CSRF / anti-forgery token is present.
CSRF_NAME_HINTS = ("csrf", "xsrf", "token", "nonce", "authenticity", "anti-forgery", "antiforgery")


def _testable_fields(form) -> list:
    """Return (name, kind) pairs for fields we can inject into."""
    fields = []
    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.get("name")
        if not name:
            continue
        if tag.name == "input" and tag.get("type", "text").lower() not in TESTABLE_TYPES:
            continue  # buttons, checkboxes, files, etc. — leave alone
        if tag.get("type", "").lower() == "hidden" and any(
            hint in name.lower() for hint in CSRF_NAME_HINTS
        ):
            continue  # don't clobber the CSRF token itself
        kind = tag.name if tag.name != "input" else "input"
        fields.append((name, kind))
        if len(fields) >= MAX_FIELDS_PER_FORM:
            break
    return fields


def _submit(action: str, method: str, data: dict) -> requests.Response | None:
    """Submit a form, returning the response or None on network error."""
    _count_submission()
    try:
        if method == "POST":
            return _session.post(action, data=data, timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)
        return _session.get(action, params=data, timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)
    except requests.RequestException:
        return None


def check_form_injection(url: str, response: requests.Response) -> List[Finding]:
    """
    Submit each discovered form with XSS + SQLi probes and inspect the reply.
    One finding per form+field at most (first confirmed issue wins).
    """
    findings = []
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")[:MAX_FORMS_PER_PAGE]

    for form in forms:
        raw_action = form.get("action", "") or url
        if raw_action.lower().startswith(("javascript:", "mailto:", "data:")):
            continue
        action = urljoin(url, raw_action)
        method = form.get("method", "GET").upper()
        if method not in ("GET", "POST"):
            continue
        if form.get("enctype") == "multipart/form-data":
            continue  # file uploads — out of scope

        fields = _testable_fields(form)
        if not fields:
            continue

        base_data = {name: "test" for name, _ in fields}

        for field_name, _ in fields:
            # ── Probe 1: reflected XSS ────────────────────────────────
            data = {**base_data, field_name: XSS_PROBE}
            resp = _submit(action, method, data)
            if resp is not None and XSS_PROBE.lower() in resp.text.lower():
                findings.append(Finding(
                    vuln_type="Cross-Site Scripting (Reflected via Form)",
                    severity="HIGH",
                    url=action,
                    detail=(
                        f"Form field '{field_name}' (action '{action}', method {method}) "
                        "reflects submitted input unescaped into the response. An attacker "
                        "can craft a malicious submission that executes JavaScript in victims' browsers."
                    ),
                    evidence=f"Probe marker '{XSS_MARKER}' echoed via field '{field_name}'",
                    remediation=(
                        "HTML-encode all user-supplied output and validate form input server-side. "
                        "Use a template engine with auto-escaping and a strict Content-Security-Policy."
                    ),
                ))
                break  # one finding per form is enough

            # ── Probe 2: SQL error ────────────────────────────────────
            data = {**base_data, field_name: SQLI_PROBE}
            resp = _submit(action, method, data)
            if resp is not None:
                matched = _find_db_error(resp.text)
                if matched:
                    findings.append(Finding(
                        vuln_type="SQL Injection (Error-Based via Form)",
                        severity="CRITICAL",
                        url=action,
                        detail=(
                            f"Form field '{field_name}' (action '{action}', method {method}) "
                            "triggers a raw database error when a SQL metacharacter is submitted. "
                            "The field value reaches a SQL query unsanitized — full database "
                            "extraction may be possible."
                        ),
                        evidence=(
                            f"Payload \"'\" in field '{field_name}' → "
                            f"DB error pattern '{matched}' in response"
                        ),
                        remediation=(
                            "Use parameterized queries (prepared statements) for all form input. "
                            "Never concatenate user input into SQL. Disable verbose DB errors in production."
                        ),
                    ))
                    break

    return findings


def check_form_csrf(url: str, response: requests.Response) -> List[Finding]:
    """
    Flag state-changing (POST) forms that carry no CSRF token field.
    A missing token means any third-party site can forge submissions
    from a logged-in victim's browser.
    """
    findings = []
    soup = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form")[:MAX_FORMS_PER_PAGE]:
        if form.get("method", "GET").upper() != "POST":
            continue
        names = [
            (tag.get("name") or "").lower()
            for tag in form.find_all(["input", "textarea"])
            if tag.get("name")
        ]
        if any(hint in n for n in names for hint in CSRF_NAME_HINTS):
            continue
        action = urljoin(url, form.get("action", "") or url)
        findings.append(Finding(
            vuln_type="Missing CSRF Token on Form",
            severity="MEDIUM",
            url=action,
            detail=(
                f"POST form targeting '{action}' has no anti-CSRF token field. "
                "An attacker site can submit this form on behalf of a logged-in victim "
                "(e.g. change email/password, post content) via a forged cross-site request."
            ),
            evidence=f"POST form action='{action}' with fields {names or ['(none named)']} — no token field",
            remediation=(
                "Add an unpredictable per-session CSRF token as a hidden field and validate it "
                "server-side on every POST. Set cookies with SameSite=Lax/Strict as defense in depth."
            ),
        ))

    return findings


def run_all_form_checks(url: str, response: requests.Response) -> List[Finding]:
    """Run all form checks for a page. Called by engine.py."""
    results: List[Finding] = []
    results.extend(check_form_injection(url, response))
    results.extend(check_form_csrf(url, response))
    return results
