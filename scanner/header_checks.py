"""
scanner/header_checks.py
────────────────────────
Checks HTTP response headers for:
  1. Missing security headers  (HIGH / MEDIUM)
  2. Weak/misconfigured present headers  (CSP wildcards, short HSTS max-age)
  3. Exposed server/technology version strings  (MEDIUM)
  4. Insecure cookie flags  (MEDIUM)
  5. CORS misconfiguration  (HIGH)
"""
from typing import List, Dict, Any
import re
import requests
from scanner.models import Finding


# ── 1. Required security headers ─────────────────────────────────────────

REQUIRED_HEADERS: list[dict] = [
    {
        "header":    "Content-Security-Policy",
        "severity":  "HIGH",
        "detail":    "No Content-Security-Policy (CSP) header detected. "
                     "This allows attackers to inject and execute arbitrary scripts (XSS).",
        "fix":       "Add a strict CSP, e.g.: "
                     "Content-Security-Policy: default-src 'self'; script-src 'self'"
    },
    {
        "header":    "X-Frame-Options",
        "severity":  "MEDIUM",
        "detail":    "No X-Frame-Options header. The page can be embedded in an iframe "
                     "enabling clickjacking attacks.",
        "fix":       "Add: X-Frame-Options: DENY  or  SAMEORIGIN"
    },
    {
        "header":    "X-Content-Type-Options",
        "severity":  "LOW",
        "detail":    "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff "
                     "responses, potentially executing uploaded files as scripts.",
        "fix":       "Add: X-Content-Type-Options: nosniff"
    },
    {
        "header":    "Strict-Transport-Security",
        "severity":  "MEDIUM",
        "detail":    "No HSTS header. The browser may downgrade HTTPS to HTTP, "
                     "enabling man-in-the-middle attacks.",
        "fix":       "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
        "header":    "Referrer-Policy",
        "severity":  "LOW",
        "detail":    "No Referrer-Policy header. Sensitive URL parameters may leak "
                     "via the Referer header to third-party sites.",
        "fix":       "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "header":    "Permissions-Policy",
        "severity":  "LOW",
        "detail":    "No Permissions-Policy header. Browser features (camera, mic, geolocation) "
                     "are not explicitly restricted.",
        "fix":       "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
]


# ── 2. Version-leaking headers ────────────────────────────────────────────

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                 "X-AspNetMvc-Version", "X-Generator"]


# ── Check functions ───────────────────────────────────────────────────────

def _csp_directive_sources(value: str) -> dict:
    """Parse a CSP header into {directive_name: [source, ...]} mappings."""
    result = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            result[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return result


def _validate_csp(url: str, value: str) -> list[Finding]:
    """
    Check that a present CSP header isn't trivially weak.
    A wildcard default-src or script-src completely negates XSS protection.
    'unsafe-inline' without a nonce/hash still allows inline script execution.
    """
    findings = []
    directives = _csp_directive_sources(value)

    # Check script-src and default-src for a bare * wildcard source
    for directive in ("script-src", "default-src"):
        sources = directives.get(directive, [])
        if "*" in sources:
            findings.append(Finding(
                vuln_type  = "Weak Header: Content-Security-Policy (Wildcard Source)",
                severity   = "HIGH",
                url        = url,
                detail     = (
                    f"A Content-Security-Policy header is present but '{directive}' "
                    "contains a '*' wildcard. This negates XSS protection entirely — "
                    "an attacker can still load scripts from any origin."
                ),
                evidence   = f"Content-Security-Policy: {value[:200]}",
                remediation= (
                    "Replace '*' with an explicit allowlist of trusted origins. "
                    "Example: Content-Security-Policy: default-src 'self'; "
                    "script-src 'self' https://trusted-cdn.example.com"
                ),
            ))
            return findings   # one finding per header is enough

    # Check for unsafe-inline without a nonce or hash
    for directive in ("script-src", "default-src"):
        sources = directives.get(directive, [])
        if "'unsafe-inline'" in sources:
            has_nonce = any(s.startswith("'nonce-") for s in sources)
            has_hash  = any(s.startswith(("'sha256-", "'sha384-", "'sha512-")) for s in sources)
            if not has_nonce and not has_hash:
                findings.append(Finding(
                    vuln_type  = "Weak Header: Content-Security-Policy (unsafe-inline)",
                    severity   = "MEDIUM",
                    url        = url,
                    detail     = (
                        f"CSP '{directive}' allows 'unsafe-inline' without a nonce or hash allowlist. "
                        "Inline scripts can still execute, which defeats XSS protection for "
                        "the most common injection pattern."
                    ),
                    evidence   = f"Content-Security-Policy: {value[:200]}",
                    remediation= (
                        "Remove 'unsafe-inline' from script-src. "
                        "Use per-request nonces: script-src 'nonce-<base64value>' "
                        "or precomputed integrity hashes instead."
                    ),
                ))
                return findings

    return findings


def _validate_hsts(url: str, value: str) -> list[Finding]:
    """
    Check that a present HSTS header has an adequate max-age.
    HSTS without max-age is silently ignored by browsers.
    """
    findings = []
    m = re.search(r'max-age\s*=\s*(\d+)', value, re.IGNORECASE)

    if not m:
        findings.append(Finding(
            vuln_type  = "Weak Header: Strict-Transport-Security (No max-age)",
            severity   = "HIGH",
            url        = url,
            detail     = (
                "An HSTS header is present but has no max-age directive. "
                "Browsers silently ignore HSTS headers without a valid max-age, "
                "leaving the site vulnerable to SSL-stripping attacks."
            ),
            evidence   = f"Strict-Transport-Security: {value[:200]}",
            remediation= (
                "Add max-age=31536000 (one year minimum): "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
        ))
    else:
        max_age = int(m.group(1))
        if max_age < 31536000:
            findings.append(Finding(
                vuln_type  = "Weak Header: Strict-Transport-Security (Short max-age)",
                severity   = "MEDIUM",
                url        = url,
                detail     = (
                    f"HSTS max-age={max_age}s is below the recommended minimum of "
                    "31536000s (one year). Short durations leave gaps where browsers "
                    "may fall back to accepting plain HTTP connections."
                ),
                evidence   = f"Strict-Transport-Security: {value[:200]}",
                remediation= (
                    "Increase max-age to at least 31536000. "
                    "Add includeSubDomains and consider submitting to the HSTS Preload list."
                ),
            ))
    return findings


def check_security_headers(url: str, response: requests.Response) -> list[Finding]:
    findings = []
    resp_headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for rule in REQUIRED_HEADERS:
        header_lower = rule["header"].lower()
        header_value = resp_headers_lower.get(header_lower)

        if header_value is None:
            findings.append(Finding(
                vuln_type  = f"Missing Header: {rule['header']}",
                severity   = rule["severity"],
                url        = url,
                detail     = rule["detail"],
                evidence   = f"Header '{rule['header']}' absent from response",
                remediation= rule["fix"],
            ))
        else:
            # Header is present \u2014 validate its value isn't trivially weak
            if rule["header"] == "Content-Security-Policy":
                findings.extend(_validate_csp(url, header_value))
            elif rule["header"] == "Strict-Transport-Security":
                findings.extend(_validate_hsts(url, header_value))

    return findings


def check_version_exposure(url: str, response: requests.Response) -> list[Finding]:
    """Flag headers that reveal software names or version numbers."""
    findings = []
    for header in LEAKY_HEADERS:
        value = response.headers.get(header)
        if value:
            findings.append(Finding(
                vuln_type  = "Information Disclosure: Server Version",
                severity   = "MEDIUM",
                url        = url,
                detail     = (
                    f"The '{header}' header exposes server/framework version info. "
                    "Attackers use this to look up known CVEs for the exact version."
                ),
                evidence   = f"{header}: {value}",
                remediation= (
                    f"Remove or mask the '{header}' header in your server config. "
                    "In Nginx: server_tokens off;  Apache: ServerTokens Prod;"
                ),
            ))
    return findings


def check_cookie_flags(url: str, response: requests.Response) -> list[Finding]:
    """Check Set-Cookie headers for missing HttpOnly / Secure / SameSite flags."""
    findings = []
    set_cookies = response.headers.getlist("Set-Cookie") \
                  if hasattr(response.headers, "getlist") \
                  else [v for k, v in response.headers.items()
                        if k.lower() == "set-cookie"]

    for cookie in set_cookies:
        cookie_lower = cookie.lower()
        cookie_name  = cookie.split("=")[0].strip()

        if "httponly" not in cookie_lower:
            findings.append(Finding(
                vuln_type  = "Insecure Cookie: Missing HttpOnly",
                severity   = "MEDIUM",
                url        = url,
                detail     = (
                    f"Cookie '{cookie_name}' lacks the HttpOnly flag. "
                    "JavaScript can read this cookie — enabling session theft via XSS."
                ),
                evidence   = cookie[:120],
                remediation= f"Set the HttpOnly flag on cookie '{cookie_name}'.",
            ))

        if url.startswith("https://") and "secure" not in cookie_lower:
            findings.append(Finding(
                vuln_type  = "Insecure Cookie: Missing Secure Flag",
                severity   = "MEDIUM",
                url        = url,
                detail     = (
                    f"Cookie '{cookie_name}' on an HTTPS page lacks the Secure flag. "
                    "It may be sent over plain HTTP if the user visits the HTTP version."
                ),
                evidence   = cookie[:120],
                remediation= f"Set the Secure flag on cookie '{cookie_name}'.",
            ))

        if "samesite" not in cookie_lower:
            findings.append(Finding(
                vuln_type  = "Insecure Cookie: Missing SameSite",
                severity   = "LOW",
                url        = url,
                detail     = (
                    f"Cookie '{cookie_name}' has no SameSite attribute, "
                    "increasing CSRF risk."
                ),
                evidence   = cookie[:120],
                remediation= f"Add SameSite=Lax or SameSite=Strict to cookie '{cookie_name}'.",
            ))

    return findings


def check_cors(url: str, response: requests.Response) -> list[Finding]:
    """Detect wildcard or overly permissive CORS policies."""
    findings = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        findings.append(Finding(
            vuln_type  = "CORS Misconfiguration: Wildcard Origin",
            severity   = "HIGH",
            url        = url,
            detail     = (
                "Access-Control-Allow-Origin: * allows any external website "
                "to read responses from this API via cross-origin requests."
            ),
            evidence   = f"Access-Control-Allow-Origin: {acao}",
            remediation= (
                "Replace '*' with an explicit allowlist of trusted origins. "
                "Never combine '*' with Allow-Credentials: true."
            ),
        ))

    if acao == "*" and acac.lower() == "true":
        # Upgrade severity — this is exploitable for credential theft
        findings[-1].severity = "CRITICAL"
        findings[-1].detail  += (
            " CRITICAL: Credentials are also allowed (Allow-Credentials: true). "
            "This combination is exploitable to steal authenticated session data."
        )

    return findings


# ── Entrypoint ────────────────────────────────────────────────────────────

def run_all_header_checks(url: str, response: requests.Response) -> list[Finding]:
    results = []
    results.extend(check_security_headers(url, response))
    results.extend(check_version_exposure(url, response))
    results.extend(check_cookie_flags(url, response))
    results.extend(check_cors(url, response))
    return results
