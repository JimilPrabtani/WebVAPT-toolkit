"""
scanner/sqli_checks.py
──────────────────────
Detects SQL Injection vulnerabilities:
  1. Error-based SQLi  — inject payloads, look for DB error messages in response
  2. Boolean-based SQLi — compare responses for true/false conditions
  3. Form-based injection surface detection
"""
from typing import List, Optional
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS


# ── Error-based SQLi ─────────────────────────────────────────────────────

# Payloads that commonly trigger DB error messages
ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "1' ORDER BY 1--"]

# DB error signatures across MySQL, PostgreSQL, MSSQL, Oracle, SQLite
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
    # MSSQL
    r"microsoft.*odbc.*sql server",
    r"unclosed quotation mark",
    r"syntax error.*converting",
    # Oracle
    r"oracle.*driver",
    r"quoted string not properly terminated",
    # SQLite
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    # Generic
    r"sql syntax.*error",
    r"db_query failed",
    r"odbc.*error",
    r"jdbc.*error",
]

COMPILED_ERRORS = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]


def check_error_based_sqli(url: str) -> List[Finding]:
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    for param_name in params:
        for payload in ERROR_PAYLOADS:
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
                        vuln_type  = "SQL Injection (Error-Based)",
                        severity   = "CRITICAL",
                        url        = url,
                        detail     = (
                            f"Parameter '{param_name}' triggers a raw database error when "
                            "a SQL metacharacter is injected. This confirms the parameter is "
                            "passed directly into a SQL query without sanitization."
                        ),
                        evidence   = (
                            f"Payload: '{payload}' in param '{param_name}' → "
                            f"DB error pattern '{matched}' found in response"
                        ),
                        remediation= (
                            "Use parameterized queries / prepared statements — NEVER string-concatenate "
                            "user input into SQL. Example (Python): "
                            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))  "
                            "Also suppress verbose DB errors in production."
                        ),
                    ))
                    break   # One confirmed finding per param
            except requests.RequestException:
                continue

    return findings


def _find_db_error(text: str) -> str:
    """Return the matched error pattern string or empty string."""
    for pattern in COMPILED_ERRORS:
        m = pattern.search(text)
        if m:
            return m.group()
    return ""


# ── Boolean-based SQLi ───────────────────────────────────────────────────

def _normalized_len(text: str) -> int:
    """
    Strip digits and runs of whitespace before measuring response length.

    Why: modern pages embed timestamps, session tokens, counters, and ad IDs
    that change on every request, causing raw byte-length comparisons to
    produce false positives on virtually every dynamic site.
    Stripping digits removes most of this noise while preserving structural
    differences caused by SQL injection (row counts, missing content, etc.).
    """
    import re as _re
    return len(_re.sub(r'\d+|\s+', '', text))


def check_boolean_sqli(url: str) -> List[Finding]:
    """
    Compare normalised response lengths for TRUE vs FALSE SQL conditions.
    Uses percentage-based thresholds relative to the baseline response size
    to avoid the false positives that absolute byte-count thresholds cause
    on dynamic applications (dashboards, counters, ad-injected pages).

    Signals injection when:
      - TRUE condition matches baseline within 5 %  (structurally identical)
      - FALSE condition differs from baseline by >15 %  (content changed)
      - Baseline is large enough (>100 norm-chars) to draw conclusions
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    for param_name in params:
        original_val = params[param_name][0]

        try:
            # Baseline (original value)
            base_params = {k: v[0] for k, v in params.items()}
            base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(base_params)}"
            base_resp = requests.get(base_url, headers=DEFAULT_HEADERS,
                                     timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            # TRUE condition
            true_params = {**base_params}
            true_params[param_name] = original_val + "' AND '1'='1"
            true_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(true_params)}"
            true_resp = requests.get(true_url, headers=DEFAULT_HEADERS,
                                     timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            # FALSE condition
            false_params = {**base_params}
            false_params[param_name] = original_val + "' AND '1'='2"
            false_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(false_params)}"
            false_resp = requests.get(false_url, headers=DEFAULT_HEADERS,
                                      timeout=SCAN_TIMEOUT, verify=_TLS_VERIFY)

            norm_base  = _normalized_len(base_resp.text)
            norm_true  = _normalized_len(true_resp.text)
            norm_false = _normalized_len(false_resp.text)

            # Skip if the baseline response is too small to be meaningful
            if norm_base < 100:
                continue

            true_delta  = abs(norm_true  - norm_base) / norm_base
            false_delta = abs(norm_false - norm_base) / norm_base

            # TRUE ≈ baseline (within 5%) AND FALSE diverges (>15%)
            if true_delta < 0.05 and false_delta > 0.15:
                findings.append(Finding(
                    vuln_type  = "SQL Injection (Boolean-Based Blind)",
                    severity   = "CRITICAL",
                    url        = url,
                    detail     = (
                        f"Parameter '{param_name}' responds differently to TRUE vs FALSE SQL conditions "
                        f"(TRUE response: {norm_true} norm-chars ≈ baseline {norm_base}; "
                        f"FALSE response: {norm_false} norm-chars, {false_delta:.0%} deviation). "
                        "This strongly indicates blind SQL injection."
                    ),
                    evidence   = (
                        f"baseline={norm_base} norm-chars  "
                        f"true_cond={norm_true} ({true_delta:.1%} delta)  "
                        f"false_cond={norm_false} ({false_delta:.1%} delta)"
                    ),
                    remediation= (
                        "Use parameterized queries. Even if errors are suppressed, "
                        "boolean-blind SQLi allows full database extraction. "
                        "Validate and whitelist all query parameter types."
                    ),
                ))
        except requests.RequestException:
            continue

    return findings


# ── Form-based injection surface ─────────────────────────────────────────

def check_forms_for_sqli(url: str, response: requests.Response) -> List[Finding]:
    """
    Identify HTML forms with text inputs — flag them as SQLi attack surface.
    (Actual payload testing against forms would require a headless browser — Sprint 3 extension)
    """
    findings = []
    soup     = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        inputs = form.find_all("input", {"type": lambda t: t in (None, "text", "search", "number", "email")})
        if not inputs:
            continue

        action = urljoin(url, form.get("action", url))
        method = form.get("method", "GET").upper()

        findings.append(Finding(
            vuln_type  = "SQLi Attack Surface: Form with User Input",
            severity   = "INFO",
            url        = url,
            detail     = (
                f"Form at '{action}' (method: {method}) contains "
                f"{len(inputs)} input field(s). These are potential SQL injection entry points. "
                "Manual or deeper automated testing recommended."
            ),
            evidence   = f"Form fields: {[i.get('name','?') for i in inputs]}",
            remediation= (
                "Ensure all form inputs are handled with parameterized queries on the server. "
                "Never use string formatting or concatenation to build SQL from user input."
            ),
        ))

    return findings


# ── Entrypoint ────────────────────────────────────────────────────────────

def run_all_sqli_checks(url: str, response: requests.Response) -> List[Finding]:
    results = []
    results.extend(check_error_based_sqli(url))
    results.extend(check_boolean_sqli(url))
    results.extend(check_forms_for_sqli(url, response))
    return results
