"""
scanner/misc_checks.py
──────────────────────
Miscellaneous vulnerability checks that don't fit a single category:

  1. Open Redirect      — redirect params pointing to external attacker URLs
  2. Sensitive Paths    — exposed .env, .git, wp-config.php, backups, admin panels
  3. HTTPS check        — plain HTTP usage detected
  4. Directory listing  — web server listing files in a directory
  5. JWT alg:none check — JWT tokens with algorithm set to "none" (auth bypass)

REFERENCES:
  - OWASP A01:2021 (Broken Access Control) — open redirect
  - OWASP A05:2021 (Security Misconfiguration) — sensitive paths, dir listing
  - OWASP A02:2021 (Cryptographic Failures) — no HTTPS, JWT alg:none
  - CWE-601 (Open Redirect), CWE-548 (Dir Listing), CWE-319 (No HTTPS)
  - MITRE T1566 (Phishing), T1083 (File Discovery), T1552 (Unsecured Credentials)

HOW TO ADD A NEW SENSITIVE PATH:
  Add an entry to SENSITIVE_PATHS as: ("/path", "SEVERITY", "Description")
  Severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS


# ── 1. Open Redirect ──────────────────────────────────────────────────────

# Common URL parameter names used for redirect destinations.
# If any of these are in the URL and point to an attacker domain → open redirect.
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "return", "returnUrl",
    "next", "goto", "target", "dest", "destination", "r", "to"
]

# The external URL we try to redirect to — must be clearly external and harmless
REDIRECT_PAYLOAD = "https://evil-attacker.com"


def check_open_redirect(url: str) -> list[Finding]:
    """
    Test URL parameters that commonly control redirect destinations.

    HOW IT WORKS:
      1. Look for redirect-related parameter names in the URL (url=, next=, return=, etc.)
      2. Replace the value with our external test URL
      3. Make the request WITHOUT following redirects (allow_redirects=False)
      4. If the Location header points to our test URL → open redirect confirmed

    IMPACT:
      Attackers craft phishing URLs like: https://trusted-site.com/login?next=https://evil.com
      The URL looks legitimate (trusted domain) but bounces victims to the attacker's site.

    Args:
        url: The page URL to test

    Returns:
        List of Finding objects (one per vulnerable redirect parameter)
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    # Only test parameters that match known redirect param names
    candidate_params = [
        p for p in params
        if p.lower() in [r.lower() for r in REDIRECT_PARAMS]
    ]

    for param in candidate_params:
        test_params       = {k: v[0] for k, v in params.items()}
        test_params[param] = REDIRECT_PAYLOAD
        test_url          = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

        try:
            resp     = requests.get(
                test_url,
                headers        = DEFAULT_HEADERS,
                timeout        = SCAN_TIMEOUT,
                verify         = _TLS_VERIFY,
                allow_redirects= False,  # We catch the redirect before it happens
            )
            location = resp.headers.get("Location", "")

            # Confirmed if the Location header contains our injected external URL
            if REDIRECT_PAYLOAD in location or "evil-attacker" in location:
                findings.append(Finding(
                    vuln_type   = "Open Redirect",
                    severity    = "HIGH",
                    url         = url,
                    detail      = (
                        f"Parameter '{param}' controls a server-side redirect without validation. "
                        "Attackers use this in phishing: a URL that looks like your trusted domain "
                        "can silently redirect victims to a malicious site."
                    ),
                    evidence    = f"GET {test_url} → Location: {location}",
                    remediation = (
                        "Validate redirect destinations against an allowlist of trusted URLs/domains. "
                        "Never redirect to user-supplied URLs directly. "
                        "Use relative paths only, or map numeric codes to allowed absolute URLs server-side."
                    ),
                ))

        except requests.RequestException:
            continue

    return findings


# ── 2. Sensitive file/path exposure ──────────────────────────────────────

# Each entry: ("/path", "SEVERITY", "Human-readable description")
#
# HOW TO ADD NEW PATHS:
#   Add a tuple below. Description should explain WHAT the file is and WHY it matters.
#   CRITICAL = contains credentials or source code
#   HIGH     = reveals server internals or allows exploitation
#   MEDIUM   = informational but security-relevant
#   INFO     = present but not directly dangerous
SENSITIVE_PATHS = [
    # ── Configuration / Secret files ──────────────────────────────────────
    ("/.env",              "CRITICAL", "Environment file (.env) exposed — may contain API keys, DB passwords"),
    ("/.env.production",   "CRITICAL", "Production env file exposed — highest risk, contains live credentials"),
    ("/.env.local",        "CRITICAL", "Local env file exposed"),
    ("/config.php",        "HIGH",     "PHP config file accessible — may contain DB credentials"),
    ("/wp-config.php",     "CRITICAL", "WordPress config file exposed — contains database login credentials"),
    ("/config.yml",        "HIGH",     "YAML config file accessible"),
    ("/config.json",       "HIGH",     "JSON config file accessible — check for secrets or internal URLs"),
    # ── Version Control ───────────────────────────────────────────────────
    ("/.git/config",       "HIGH",     "Git repository config exposed — may allow full source code reconstruction"),
    ("/.git/HEAD",         "HIGH",     "Git HEAD file exposed — confirms git repo is accessible"),
    ("/.svn/entries",      "HIGH",     "SVN repository data exposed"),
    # ── Backup / Archive files ────────────────────────────────────────────
    ("/backup.zip",        "HIGH",     "Backup archive accessible — may contain source code or DB dumps"),
    ("/backup.tar.gz",     "HIGH",     "Backup tarball accessible"),
    ("/db.sql",            "CRITICAL", "SQL database dump accessible — contains all database data"),
    ("/dump.sql",          "CRITICAL", "SQL dump accessible"),
    ("/database.sql",      "CRITICAL", "Database SQL file accessible"),
    # ── Admin Panels ──────────────────────────────────────────────────────
    ("/admin",             "MEDIUM",   "Admin panel endpoint reachable — verify authentication is enforced"),
    ("/admin/",            "MEDIUM",   "Admin panel directory reachable"),
    ("/phpmyadmin/",       "HIGH",     "phpMyAdmin database interface exposed — should not be public"),
    ("/wp-admin/",         "MEDIUM",   "WordPress admin login page exposed"),
    # ── Log files ─────────────────────────────────────────────────────────
    ("/logs/",             "HIGH",     "Log directory browsable — may expose error details/user data"),
    ("/error.log",         "HIGH",     "Error log file directly accessible — reveals stack traces and paths"),
    ("/access.log",        "HIGH",     "Access log exposed — reveals all visitor IPs and request history"),
    # ── Information files ─────────────────────────────────────────────────
    ("/robots.txt",        "INFO",     "robots.txt exists — review for sensitive path disclosures"),
    ("/sitemap.xml",       "INFO",     "Sitemap found — useful for complete endpoint enumeration"),
    ("/.well-known/security.txt", "INFO", "security.txt found (good security practice)"),
    ("/server-status",     "HIGH",     "Apache server-status page accessible — exposes real-time server internals"),
    ("/server-info",       "HIGH",     "Apache server-info page accessible — reveals module configuration"),
]


def _get_homepage_fingerprint(origin: str) -> tuple[int, str]:
    """
    Fetch the homepage to get its size and content-type for SPA detection.

    WHY IS THIS NEEDED?
      SPAs (React, Angular, Vue) use a catch-all route — every unknown URL
      returns 200 + the same index.html ("Sorry, page not found" rendered in JS).
      Without this fingerprint, we'd flag every sensitive path as found
      because they all return 200 with the SPA's index.html content.

      We compare each probed path's response size against the homepage size.
      If they match → it's the SPA's 404 fallback, not a real file.
      This is the same technique used by Burp Suite's active scanner.

    Returns:
        Tuple of (response_size_bytes, content_type_string)
    """
    try:
        resp = requests.get(
            origin,
            headers       = DEFAULT_HEADERS,
            timeout       = SCAN_TIMEOUT,
            verify        = _TLS_VERIFY,
            allow_redirects=True,
        )
        return len(resp.content), resp.headers.get("Content-Type", "")
    except requests.RequestException:
        return 0, ""


# File content types that indicate a REAL file (not an HTML error/SPA page)
PLAINTEXT_TYPES = (
    "text/plain", "application/octet-stream", "application/zip",
    "application/sql", "application/x-tar", "application/json",
    "application/x-php", "text/x-php"
)

# For these paths, a 403 response alone is enough to confirm the file exists
# (server is blocking access but the file is there)
EXISTENCE_BY_403 = {"/wp-config.php", "/.env", "/.git/config", "/.git/HEAD"}

# These info paths are always reported regardless of SPA detection
# (robots.txt and sitemap.xml existing is always noteworthy)
INFO_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}


def check_sensitive_paths(base_url: str) -> list[Finding]:
    """
    Probe a list of well-known sensitive paths on the target domain.

    Runs ONCE per scan (only on the target homepage URL, not every crawled page).
    Uses SPA fingerprinting to avoid false positives from catch-all routes.

    Args:
        base_url: The target domain root (e.g. "https://example.com")

    Returns:
        List of Finding objects for each accessible sensitive path
    """
    findings = []
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"

    # Get homepage size for SPA false-positive filtering
    homepage_size, _ = _get_homepage_fingerprint(origin)

    for path, severity, description in SENSITIVE_PATHS:
        test_url = origin + path

        try:
            resp = requests.get(
                test_url,
                headers       = DEFAULT_HEADERS,
                timeout       = SCAN_TIMEOUT,
                verify        = _TLS_VERIFY,
                allow_redirects=False,  # Don't follow redirects — we want the direct status
            )

            # Skip responses that aren't interesting
            interesting_codes = {200}
            if severity in ("CRITICAL", "HIGH"):
                interesting_codes.add(403)  # 403 = exists but protected

            if resp.status_code not in interesting_codes:
                continue

            # Skip empty responses (nothing useful there)
            if resp.status_code == 200 and len(resp.content) < 10:
                continue

            # ── SPA false-positive filter ──────────────────────────────────
            # If the response is 200 AND the exact same size as the homepage,
            # it's almost certainly the SPA's catch-all "not found" response.
            if (
                resp.status_code == 200
                and homepage_size > 0
                and path not in INFO_PATHS
                and abs(len(resp.content) - homepage_size) <= 50
            ):
                content_type = resp.headers.get("Content-Type", "")
                # Unless the Content-Type is clearly a file (not HTML)
                if not any(t in content_type for t in PLAINTEXT_TYPES):
                    continue  # SPA catch-all — skip this false positive

            # ── 403 handling ───────────────────────────────────────────────
            # A 403 on a high-value path means: file EXISTS but access is blocked.
            # Still worth flagging — the file shouldn't exist at that path at all.
            if resp.status_code == 403:
                if path not in EXISTENCE_BY_403:
                    continue
                description = description + " (access blocked — file exists on server)"

            findings.append(Finding(
                vuln_type   = f"Sensitive Path Exposure: {path}",
                severity    = severity,
                url         = test_url,
                detail      = description,
                evidence    = f"HTTP {resp.status_code} from {test_url} ({len(resp.content)} bytes)",
                remediation = (
                    f"Block public access to '{path}' via your web server configuration. "
                    "For .env and config files: move them above the webroot. "
                    "Nginx: deny all; in a location block. "
                    "Apache: add 'Deny from all' in .htaccess for sensitive paths."
                ),
            ))

        except requests.RequestException:
            continue

    return findings


# ── 3. HTTPS check ────────────────────────────────────────────────────────

def check_https(url: str, response: requests.Response) -> list[Finding]:
    """
    Check if the site is served over plain HTTP (no encryption).

    HTTP means ALL data is transmitted in cleartext:
      - Login credentials
      - Session cookies (can be stolen → account takeover)
      - Form data (health info, payment details, etc.)
      - API tokens

    This is OWASP A02:2021 (Cryptographic Failures).
    """
    findings = []
    if url.startswith("http://"):
        findings.append(Finding(
            vuln_type   = "Insecure Transport: No HTTPS",
            severity    = "HIGH",
            url         = url,
            detail      = (
                "The site is served over plain HTTP. All traffic — including credentials, "
                "cookies, and form data — is transmitted in cleartext and can be intercepted "
                "by anyone on the same network (coffee shop WiFi, ISN, employer, etc.)."
            ),
            evidence    = "URL scheme: http://",
            remediation = (
                "1. Obtain a free TLS certificate from Let's Encrypt (https://letsencrypt.org). "
                "2. Redirect all HTTP traffic to HTTPS using a 301 redirect. "
                "3. Add the HSTS header once HTTPS is stable: "
                "   Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
        ))
    return findings


# ── 4. Directory listing ──────────────────────────────────────────────────

# HTML patterns that appear in Apache/Nginx directory listing pages
DIRECTORY_LISTING_INDICATORS = [
    r"<title>Index of /",
    r"<h1>Index of /",
    r"Parent Directory</a>",
    r"Directory listing for /",
]

COMPILED_DIR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DIRECTORY_LISTING_INDICATORS]


def check_directory_listing(url: str, response: requests.Response) -> list[Finding]:
    """
    Detect web server directory listing on the current page.

    Directory listing exposes:
      - Full file structure of the web server
      - Source code files, config files, backup files
      - Internal path structure useful for further attacks

    This check works by looking for the characteristic HTML patterns
    that Apache and Nginx include in auto-generated directory index pages.
    """
    findings = []
    for pattern in COMPILED_DIR_PATTERNS:
        if pattern.search(response.text):
            findings.append(Finding(
                vuln_type   = "Directory Listing Enabled",
                severity    = "MEDIUM",
                url         = url,
                detail      = (
                    "The web server is returning a directory listing for this path. "
                    "This exposes the full file structure and may reveal sensitive files, "
                    "backups, configuration files, or source code to any visitor."
                ),
                evidence    = f"Directory index pattern matched at {url}",
                remediation = (
                    "Disable directory listing in your server configuration:\n"
                    "  Nginx:  add 'autoindex off;' in the server block\n"
                    "  Apache: add 'Options -Indexes' in .htaccess or httpd.conf"
                ),
            ))
            break   # One finding per page is enough

    return findings


# ── 5. JWT algorithm:none bypass ─────────────────────────────────────────

def check_jwt_alg_none(url: str, response: requests.Response) -> list[Finding]:
    """
    Detect JWT tokens in the response body or headers that use algorithm:none.

    WHAT IS JWT ALG:NONE?
      JSON Web Tokens (JWTs) have a header containing the signing algorithm.
      If the algorithm is set to "none", no signature verification is needed.
      An attacker can:
        1. Take any valid JWT
        2. Change the payload (e.g. set "role":"admin" or "user_id":"1")
        3. Set "alg":"none" and strip the signature
        4. Send the modified token — vulnerable servers accept it as valid!

      This completely bypasses authentication.

    DETECTION:
      We look for JWT-like patterns in:
        - The response body (sometimes APIs return tokens inline)
        - Authorization/Set-Cookie response headers
      Then decode the header (base64) and check if alg=none.

    OWASP Juice Shop: This is a known Juice Shop challenge.
    MITRE ATT&CK: T1552.001 — Credentials in Files
    CWE-347 — Improper Verification of Cryptographic Signature

    Args:
        url:      The page URL
        response: The already-fetched HTTP response

    Returns:
        List of Finding objects (one per alg:none JWT found)
    """
    import base64
    import json as json_module

    findings = []

    # JWT pattern: three base64url-encoded segments separated by dots
    jwt_pattern = re.compile(
        r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*',
        re.IGNORECASE
    )

    # Collect all text to search: response body + selected headers
    search_targets = [response.text]
    for header_name in ("Authorization", "Set-Cookie", "X-Auth-Token", "X-Access-Token"):
        val = response.headers.get(header_name, "")
        if val:
            search_targets.append(val)

    full_text = "\n".join(search_targets)
    jwt_matches = jwt_pattern.findall(full_text)

    for jwt_token in set(jwt_matches):  # deduplicate identical tokens
        try:
            # JWT header is the first segment — base64url decode it
            header_segment = jwt_token.split(".")[0]
            # Add padding for base64 decode (JWT strips trailing = padding)
            padding = 4 - len(header_segment) % 4
            header_bytes = base64.urlsafe_b64decode(header_segment + "=" * padding)
            header_data  = json_module.loads(header_bytes)

            # Check for algorithm:none (case-insensitive)
            alg = str(header_data.get("alg", "")).lower()
            if alg == "none" or alg == "":
                findings.append(Finding(
                    vuln_type   = "JWT Algorithm:None Bypass",
                    severity    = "CRITICAL",
                    url         = url,
                    detail      = (
                        "A JWT token with 'alg:none' was found in the response. "
                        "This means the server may accept unsigned tokens — "
                        "an attacker can forge any identity by removing the signature "
                        "and setting alg:none. "
                        "This completely bypasses JWT-based authentication."
                    ),
                    evidence    = f"JWT header: {header_data} | Token prefix: {jwt_token[:40]}...",
                    remediation = (
                        "1. Always validate the 'alg' field against an explicit allowlist "
                        "   (e.g. only allow RS256 or HS256). "
                        "2. Reject any token with alg:none or no algorithm. "
                        "3. Use a well-maintained JWT library with this protection built-in "
                        "   (e.g. python-jose, PyJWT with algorithms parameter). "
                        "4. Never trust the algorithm from the token itself — "
                        "   always specify the expected algorithm server-side."
                    ),
                ))

        except Exception:
            # Skip tokens we can't decode (binary data, encoding issues, etc.)
            continue

    return findings


# ── Entrypoint ─────────────────────────────────────────────────────────────

def run_all_misc_checks(url: str, response: requests.Response, base_url: str) -> list[Finding]:
    """
    Run all miscellaneous checks for a given page.
    Called by engine.py for every crawled page.

    Notes:
      - check_sensitive_paths() only runs on the base URL (not every page)
        because it probes fixed paths from the domain root, not per-page paths.
      - check_jwt_alg_none() runs on every page — tokens can appear anywhere.

    To disable a check: comment out the relevant line below.
    To add a new check: create a function above and add it here.
    """
    results = []
    results.extend(check_https(url, response))           # Plain HTTP usage
    results.extend(check_open_redirect(url))              # Redirect param injection
    results.extend(check_directory_listing(url, response))# Dir listing in response
    results.extend(check_jwt_alg_none(url, response))     # JWT alg:none in response

    # Sensitive paths: only probe from the domain root, once per scan
    # (probing /wp-config.php from every page would just hit the same URL repeatedly)
    if url == base_url:
        results.extend(check_sensitive_paths(base_url))

    return results