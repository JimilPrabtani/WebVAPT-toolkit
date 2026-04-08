"""
scanner/sqli_checks.py
──────────────────────
Detects SQL Injection (SQLi) vulnerabilities.

WHAT IS SQL INJECTION?
  SQL Injection happens when user-supplied input is placed directly into a SQL query
  without sanitization. An attacker can manipulate the query to:
    - Dump the entire database (usernames, passwords, credit cards)
    - Bypass login authentication
    - Delete or modify data
    - In some cases, execute OS commands on the server

THREE DETECTION METHODS:
  1. Error-based  — inject SQL metacharacters, look for database error messages
  2. Boolean-blind — compare responses: TRUE condition ≈ baseline, FALSE condition ≠ baseline
  3. Form surface — flag forms with text inputs as SQLi attack surface (INFO level)

REFERENCES:
  - OWASP A03:2021 — Injection (https://owasp.org/Top10/A03_2021-Injection/)
  - CWE-89 — Improper Neutralization of Special Elements in SQL Command
  - MITRE T1190 — Exploit Public-Facing Application

HOW TO ADD NEW DB ERROR PATTERNS:
  Add a regex string to DB_ERROR_PATTERNS below. Use re.IGNORECASE safe patterns.
  Example: r"your error message here"
"""

from typing import List, Optional
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS


# ── 1. Error-based SQLi ───────────────────────────────────────────────────

# Simple payloads that trigger SQL syntax errors in vulnerable databases.
# We don't need complex payloads here — just enough to break a raw SQL query.
ERROR_PAYLOADS = [
    "'",              # Single quote — breaks string context in most SQL dialects
    '"',              # Double quote — for databases that use double quotes
    "' OR '1'='1",   # Classic always-true condition
    '" OR "1"="1',   # Same but double-quoted
    "' OR 1=1--",    # MySQL/MSSQL comment variant
    "1' ORDER BY 1--",  # ORDER BY injection to test column count
]

# Error message patterns from common database systems.
# If any of these appear in the HTTP response after injection → SQLi confirmed.
#
# HOW TO ADD NEW PATTERNS:
#   Add a raw string regex below. Keep it specific to avoid false positives.
#   Always test against a known-vulnerable app (e.g. DVWA, Juice Shop) after adding.
DB_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    # PostgreSQL
    r"pg_query\(\)",
    r"postgresql.*error",
    r"unterminated quoted string",
    # Microsoft SQL Server
    r"microsoft.*odbc.*sql server",
    r"unclosed quotation mark",
    r"syntax error.*converting",
    # Oracle
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    # Generic / framework-level
    r"sql syntax.*error",
    r"db_query failed",
    r"odbc.*error",
    r"jdbc.*error",
]

# Pre-compile patterns for performance (avoids re-compiling on every check)
COMPILED_ERRORS = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]


def _find_db_error(text: str) -> str:
    """
    Scan response text for database error signatures.

    Returns the matched error pattern string if found, or empty string.
    Used by check_error_based_sqli() to confirm injection.
    """
    for pattern in COMPILED_ERRORS:
        m = pattern.search(text)
        if m:
            return m.group()
    return ""


def check_error_based_sqli(url: str) -> List[Finding]:
    """
    Inject SQL metacharacters into each URL query parameter.
    If the response contains a database error message → confirmed SQLi.

    This is the most reliable detection method because:
      - Database error messages are highly specific, not easily confused
      - False positive rate is very low (error must contain exact DB patterns)
      - Finds injection even if the query uses different quoting styles

    Args:
        url: The page URL to test (only tests if URL has query parameters)

    Returns:
        List of Finding objects — typically 0 or 1 per vulnerable parameter
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    # Skip pages with no URL parameters — nothing to inject into
    if not params:
        return []

    for param_name in params:
        for payload in ERROR_PAYLOADS:
            # Build a test URL with the current payload in the target parameter
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

            try:
                resp = requests.get(
                    test_url,
                    headers=DEFAULT_HEADERS,
                    timeout=SCAN_TIMEOUT,
                    verify=_TLS_VERIFY,
                    allow_redirects=True,
                )
                matched = _find_db_error(resp.text)
                if matched:
                    findings.append(Finding(
                        vuln_type   = "SQL Injection (Error-Based)",
                        severity    = "CRITICAL",
                        url         = url,
                        detail      = (
                            f"Parameter '{param_name}' triggers a raw database error when "
                            "a SQL metacharacter is injected. This confirms the parameter is "
                            "passed directly into a SQL query without sanitization. "
                            "An attacker can use this to extract the entire database."
                        ),
                        evidence    = (
                            f"Payload: '{payload}' in param '{param_name}' → "
                            f"DB error pattern '{matched}' found in response"
                        ),
                        remediation = (
                            "Use parameterized queries (prepared statements) — NEVER build SQL "
                            "by concatenating user input. Example (Python): "
                            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))  "
                            "Also disable verbose DB error messages in production."
                        ),
                    ))
                    break   # One confirmed finding per parameter is enough

            except requests.RequestException:
                continue    # Network error — move on to next payload

    return findings


# ── 2. Boolean-based blind SQLi ───────────────────────────────────────────

def _normalized_len(text: str) -> int:
    """
    Strip digits and whitespace before measuring response length.

    WHY IS THIS NEEDED?
      Modern web pages embed dynamic content that changes every request:
        - Timestamps, session tokens, CSRF tokens, ad IDs, counters
      Raw byte-length comparison would give false positives on virtually
      every dynamic site because these values change between requests.

      Stripping digits removes most of this noise while preserving
      the structural differences caused by SQL injection (e.g. missing
      rows of content when a FALSE condition hides results).

    Example:
      Normal page: "Welcome John, last login: 2024-01-15 12:34:56" = 47 chars
      After strip : "Welcome John, last login:  " = 27 chars (digits removed)
      Both requests produce very similar normalized lengths → no false positive
    """
    import re as _re
    return len(_re.sub(r'\d+|\s+', '', text))


def check_boolean_sqli(url: str) -> List[Finding]:
    """
    Detect blind SQL injection by comparing TRUE vs FALSE condition responses.

    STRATEGY:
      1. Fetch baseline (original URL)
      2. Inject TRUE condition: param' AND '1'='1  (always evaluates to TRUE)
      3. Inject FALSE condition: param' AND '1'='2  (always evaluates to FALSE)

      If TRUE ≈ baseline AND FALSE is significantly different → blind SQLi confirmed
      (The database is executing our condition and changing the output based on it)

    THRESHOLDS (tuned to reduce false positives):
      - TRUE must match baseline within 5% normalized length
      - FALSE must differ from baseline by MORE than 25% normalized length
      - Baseline must be at least 150 normalized chars (avoids tiny static pages)

    WHY 25% NOT 15%?
      Original threshold was 15%, which caused false positives on dynamic sites
      with A/B testing, personalization, or changing ad banners.
      25% requires a meaningful structural change — content appearing/disappearing.

    Args:
        url: The page URL to test

    Returns:
        List of Finding objects (0 or 1 per vulnerable parameter)
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    for param_name in params:
        original_val = params[param_name][0]

        try:
            # ── Fetch baseline (original param value) ─────────────────────
            base_params = {k: v[0] for k, v in params.items()}
            base_url    = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(base_params)}"
            base_resp   = requests.get(base_url, headers=DEFAULT_HEADERS,
                                       timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            # ── TRUE condition (should return same content as baseline) ────
            true_params                = {**base_params}
            true_params[param_name]    = original_val + "' AND '1'='1"
            true_url                   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(true_params)}"
            true_resp                  = requests.get(true_url, headers=DEFAULT_HEADERS,
                                                      timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            # ── FALSE condition (should return different/empty content) ────
            false_params               = {**base_params}
            false_params[param_name]   = original_val + "' AND '1'='2"
            false_url                  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(false_params)}"
            false_resp                 = requests.get(false_url, headers=DEFAULT_HEADERS,
                                                      timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            # ── Compare normalized lengths ─────────────────────────────────
            norm_base  = _normalized_len(base_resp.text)
            norm_true  = _normalized_len(true_resp.text)
            norm_false = _normalized_len(false_resp.text)

            # Skip pages that are too small to draw meaningful conclusions
            # (very small pages might differ by 1-2 chars = large percentage swing)
            if norm_base < 150:
                continue

            true_delta  = abs(norm_true  - norm_base) / norm_base
            false_delta = abs(norm_false - norm_base) / norm_base

            # Confirmed: TRUE ≈ baseline (within 5%) AND FALSE differs by >25%
            if true_delta < 0.05 and false_delta > 0.25:
                findings.append(Finding(
                    vuln_type   = "SQL Injection (Boolean-Based Blind)",
                    severity    = "CRITICAL",
                    url         = url,
                    detail      = (
                        f"Parameter '{param_name}' responds differently to TRUE vs FALSE SQL conditions. "
                        f"TRUE response ({norm_true} chars) ≈ baseline ({norm_base} chars, {true_delta:.1%} delta). "
                        f"FALSE response ({norm_false} chars) differs by {false_delta:.1%}. "
                        "This indicates the parameter is used in a SQL query. "
                        "Even without visible errors, an attacker can extract the full database."
                    ),
                    evidence    = (
                        f"baseline={norm_base} chars  |  "
                        f"true_cond={norm_true} ({true_delta:.1%} delta)  |  "
                        f"false_cond={norm_false} ({false_delta:.1%} delta)"
                    ),
                    remediation = (
                        "Use parameterized queries. Even with errors suppressed, "
                        "boolean-blind SQLi allows full database extraction using tools like sqlmap. "
                        "Validate and whitelist all parameter types (e.g. only allow integers for ID params)."
                    ),
                ))

        except requests.RequestException:
            continue    # Network error — move on

    return findings


# ── 3. Form-based injection surface ──────────────────────────────────────

def check_forms_for_sqli(url: str, response: requests.Response) -> List[Finding]:
    """
    Identify HTML forms with text inputs — flag them as potential SQLi surfaces.

    This is an INFO-level finding, not a confirmed vulnerability.
    It tells the tester "there are input fields here worth testing manually."

    WHY NOT ACTIVELY TEST FORMS?
      Injecting SQL into POST forms requires stateful interaction that's
      outside scope for a passive scan (login sessions, CSRF tokens, etc.).
      Active form testing is on the roadmap using Playwright (Phase 2).

    Args:
        url:      The page URL
        response: The already-fetched HTTP response

    Returns:
        One INFO-level finding per form with text inputs
    """
    findings = []
    soup     = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        # Find text-style inputs (text, search, number, email — all accept user input)
        inputs = form.find_all(
            "input",
            {"type": lambda t: t in (None, "text", "search", "number", "email")}
        )
        if not inputs:
            continue

        action = urljoin(url, form.get("action", url))
        method = form.get("method", "GET").upper()

        findings.append(Finding(
            vuln_type   = "SQLi Attack Surface: Form with User Input",
            severity    = "INFO",
            url         = url,
            detail      = (
                f"Form at '{action}' (method: {method}) contains "
                f"{len(inputs)} input field(s). These are potential SQL injection entry points. "
                "Manual testing or deeper automated testing recommended."
            ),
            evidence    = f"Form fields: {[i.get('name', '?') for i in inputs]}",
            remediation = (
                "Ensure all form inputs are handled with parameterized queries on the server. "
                "Never use string formatting or concatenation to build SQL from user input."
            ),
        ))

    return findings


# ── Entrypoint ─────────────────────────────────────────────────────────────

def run_all_sqli_checks(url: str, response: requests.Response) -> List[Finding]:
    """
    Run all SQL injection checks for a given URL.
    Called by engine.py for every crawled page.

    To disable a check: comment out the relevant line below.
    To add a new check: create a function above and add it here.
    """
    results = []
    results.extend(check_error_based_sqli(url))   # Inject → look for DB error messages
    results.extend(check_boolean_sqli(url))        # Compare TRUE vs FALSE responses
    results.extend(check_forms_for_sqli(url, response))  # Flag form input surfaces
    return results
