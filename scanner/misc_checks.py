"""
scanner/misc_checks.py
──────────────────────
Additional vulnerability checks:
  1. Open Redirect
  2. Sensitive file/path exposure (robots.txt, .env, .git, backups)
  3. Insecure HTTP usage (no HTTPS)
  4. Directory listing detection
  5. Clickjacking (X-Frame-Options covered in header_checks — this checks meta tags)
"""
import re
import requests
from urllib.parse import urlparse, urlencode, urljoin
from bs4 import BeautifulSoup
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS


# ── 1. Open Redirect ─────────────────────────────────────────────────────

REDIRECT_PARAMS = ["url", "redirect", "redirect_url", "return", "returnUrl",
                   "next", "goto", "target", "dest", "destination", "r", "to"]

REDIRECT_PAYLOAD = "https://evil-attacker.com"


def check_open_redirect(url: str) -> list[Finding]:
    findings = []
    parsed   = urlparse(url)

    # Check query params for known redirect param names
    from urllib.parse import parse_qs
    params = parse_qs(parsed.query, keep_blank_values=True)
    candidate_params = [p for p in params if p.lower() in
                        [r.lower() for r in REDIRECT_PARAMS]]

    for param in candidate_params:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = REDIRECT_PAYLOAD
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

        try:
            resp = requests.get(
                test_url,
                headers=DEFAULT_HEADERS,
                timeout=SCAN_TIMEOUT,
                verify=_TLS_VERIFY,
                allow_redirects=False,   # We want to catch the redirect, not follow it
            )
            location = resp.headers.get("Location", "")
            if REDIRECT_PAYLOAD in location or "evil-attacker" in location:
                findings.append(Finding(
                    vuln_type  = "Open Redirect",
                    severity   = "HIGH",
                    url        = url,
                    detail     = (
                        f"Parameter '{param}' controls a server-side redirect without validation. "
                        "Attackers use open redirects in phishing URLs that appear to link to "
                        "a trusted domain but bounce users to a malicious site."
                    ),
                    evidence   = f"GET {test_url} → Location: {location}",
                    remediation= (
                        "Validate redirect destinations against an allowlist of trusted URLs/domains. "
                        "Never redirect to user-supplied URLs directly. "
                        "Use relative paths or map codes to absolute URLs server-side."
                    ),
                ))
        except requests.RequestException:
            continue

    return findings


# ── 2. Sensitive file / path exposure ────────────────────────────────────

SENSITIVE_PATHS = [
    # Config / secrets
    ("/.env",              "CRITICAL", "Environment file (.env) exposed — may contain API keys, DB passwords"),
    ("/.env.production",   "CRITICAL", "Production env file exposed"),
    ("/.env.local",        "CRITICAL", "Local env file exposed"),
    ("/config.php",        "HIGH",     "PHP config file accessible"),
    ("/wp-config.php",     "CRITICAL", "WordPress config file exposed — contains DB credentials"),
    ("/config.yml",        "HIGH",     "YAML config file accessible"),
    ("/config.json",       "HIGH",     "JSON config file accessible"),
    # Version control
    ("/.git/config",       "HIGH",     "Git repository config exposed — may allow full source code download"),
    ("/.git/HEAD",         "HIGH",     "Git HEAD file exposed"),
    ("/.svn/entries",      "HIGH",     "SVN repository data exposed"),
    # Backup / old files
    ("/backup.zip",        "HIGH",     "Backup archive accessible"),
    ("/backup.tar.gz",     "HIGH",     "Backup tarball accessible"),
    ("/db.sql",            "CRITICAL", "SQL database dump accessible"),
    ("/dump.sql",          "CRITICAL", "SQL dump accessible"),
    ("/database.sql",      "CRITICAL", "Database SQL file accessible"),
    # Admin panels
    ("/admin",             "MEDIUM",   "Admin panel endpoint reachable — check if auth is enforced"),
    ("/admin/",            "MEDIUM",   "Admin panel directory reachable"),
    ("/phpmyadmin/",       "HIGH",     "phpMyAdmin interface exposed"),
    ("/wp-admin/",         "MEDIUM",   "WordPress admin login page exposed"),
    # Logs
    ("/logs/",             "HIGH",     "Log directory browsable"),
    ("/error.log",         "HIGH",     "Error log file directly accessible"),
    ("/access.log",        "HIGH",     "Access log exposed"),
    # Info files
    ("/robots.txt",        "INFO",     "robots.txt exists — review for sensitive path disclosures"),
    ("/sitemap.xml",       "INFO",     "Sitemap found — useful for full endpoint enumeration"),
    ("/.well-known/security.txt", "INFO", "security.txt found (good practice)"),
    ("/server-status",     "HIGH",     "Apache server-status page accessible — exposes server internals"),
    ("/server-info",       "HIGH",     "Apache server-info page accessible"),
]


def _get_homepage_fingerprint(origin: str) -> tuple[int, str]:
    """
    Fetch the homepage and return (content_length, content_type).

    Why we need this:
    SPAs (React, Angular, Vue) use a catch-all route — every unknown URL
    returns 200 + the same index.html instead of a real 404.
    Example: GET /wp-config.php → 200, 75002 bytes (the Angular index.html)

    By comparing a probed path's response size against the homepage size,
    we can tell whether we got a real file or just the SPA fallback.
    This is the same technique used by Burp Suite's active scanner.
    """
    try:
        resp = requests.get(
            origin,
            headers=DEFAULT_HEADERS,
            timeout=SCAN_TIMEOUT,
            verify=_TLS_VERIFY,
            allow_redirects=True,
        )
        content_type = resp.headers.get("Content-Type", "")
        return len(resp.content), content_type
    except requests.RequestException:
        return 0, ""


# Content-Type patterns that indicate a real sensitive file vs an HTML page
PLAINTEXT_TYPES = ("text/plain", "application/octet-stream", "application/zip",
                   "application/sql", "application/x-tar", "application/json",
                   "application/x-php", "text/x-php")

# Paths where 403 alone confirms existence even without reading content
EXISTENCE_BY_403 = {"/wp-config.php", "/.env", "/.git/config", "/.git/HEAD"}

# Paths that are genuinely informational — don't apply SPA filter
INFO_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}


def check_sensitive_paths(base_url: str) -> list[Finding]:
    findings = []
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"

    # ── Step 1: fingerprint the homepage ─────────────────────────────────
    # We fetch this ONCE before probing any paths.
    # homepage_size is the "SPA baseline" — any 200 response with this exact
    # size is the catch-all fallback, not a real file.
    homepage_size, _ = _get_homepage_fingerprint(origin)

    for path, severity, description in SENSITIVE_PATHS:
        test_url = origin + path
        try:
            resp = requests.get(
                test_url,
                headers=DEFAULT_HEADERS,
                timeout=SCAN_TIMEOUT,
                verify=_TLS_VERIFY,
                allow_redirects=False,
            )

            # ── Step 2: decide if this is interesting ─────────────────────
            interesting_codes = {200}
            if severity in ("CRITICAL", "HIGH"):
                interesting_codes.add(403)

            if resp.status_code not in interesting_codes:
                continue

            # ── Step 3: skip empty responses ──────────────────────────────
            if resp.status_code == 200 and len(resp.content) < 10:
                continue

            # ── Step 4: SPA catch-all detection ───────────────────────────
            # If the response is 200 AND the same size as homepage AND the
            # path isn't an info-only path we always want to report → skip.
            # Allow a ±50 byte tolerance for minor dynamic content variation.
            if (
                resp.status_code == 200
                and homepage_size > 0
                and path not in INFO_PATHS
                and abs(len(resp.content) - homepage_size) <= 50
            ):
                # Double-check: if Content-Type is clearly a file type
                # (not text/html), it's a real file even if size matches.
                content_type = resp.headers.get("Content-Type", "")
                if not any(t in content_type for t in PLAINTEXT_TYPES):
                    # SPA false positive — this is just the index.html fallback
                    continue

            # ── Step 5: 403 special handling ──────────────────────────────
            # A 403 on a high-value path confirms the file EXISTS but is
            # access-controlled. Flag it but note it's protected.
            if resp.status_code == 403:
                if path not in EXISTENCE_BY_403:
                    continue   # 403 on generic paths isn't meaningful
                description = description + " (access blocked — file exists on server)"

            findings.append(Finding(
                vuln_type  = f"Sensitive Path Exposure: {path}",
                severity   = severity,
                url        = test_url,
                detail     = description,
                evidence   = f"HTTP {resp.status_code} from {test_url} ({len(resp.content)} bytes)",
                remediation= (
                    f"Block public access to '{path}' via your web server config. "
                    "For .env and config files, move them above the webroot. "
                    "Use .htaccess or Nginx deny rules for sensitive paths."
                ),
            ))

        except requests.RequestException:
            continue

    return findings


# ── 3. HTTPS check ────────────────────────────────────────────────────────

def check_https(url: str, response: requests.Response) -> list[Finding]:
    findings = []
    if url.startswith("http://"):
        findings.append(Finding(
            vuln_type  = "Insecure Transport: No HTTPS",
            severity   = "HIGH",
            url        = url,
            detail     = (
                "The site is served over plain HTTP. All traffic — including credentials, "
                "cookies, and form data — is transmitted in cleartext and can be intercepted."
            ),
            evidence   = f"URL scheme: http://",
            remediation= (
                "Obtain a TLS certificate (free via Let's Encrypt) and redirect all HTTP "
                "traffic to HTTPS. Add the HSTS header once HTTPS is stable."
            ),
        ))
    return findings


# ── 4. Directory listing ──────────────────────────────────────────────────

DIRECTORY_LISTING_INDICATORS = [
    r"<title>Index of /",
    r"<h1>Index of /",
    r"Parent Directory</a>",
    r"Directory listing for /",
]

COMPILED_DIR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DIRECTORY_LISTING_INDICATORS]


def check_directory_listing(url: str, response: requests.Response) -> list[Finding]:
    findings = []
    for pattern in COMPILED_DIR_PATTERNS:
        if pattern.search(response.text):
            findings.append(Finding(
                vuln_type  = "Directory Listing Enabled",
                severity   = "MEDIUM",
                url        = url,
                detail     = (
                    "The web server is returning a directory listing for this path. "
                    "This exposes the full file structure and may reveal sensitive files, "
                    "backups, or source code."
                ),
                evidence   = f"Directory index pattern matched at {url}",
                remediation= (
                    "Disable directory listing in your server config. "
                    "Nginx: add 'autoindex off;'  Apache: add 'Options -Indexes' in .htaccess."
                ),
            ))
            break
    return findings


# ── Entrypoint ────────────────────────────────────────────────────────────

def run_all_misc_checks(url: str, response: requests.Response, base_url: str) -> list[Finding]:
    results = []
    results.extend(check_https(url, response))
    results.extend(check_open_redirect(url))
    results.extend(check_directory_listing(url, response))
    # Sensitive path check runs once per domain, not per page
    if url == base_url:
        results.extend(check_sensitive_paths(base_url))
    return results