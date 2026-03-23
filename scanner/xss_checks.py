"""
scanner/xss_checks.py
─────────────────────
Detects Cross-Site Scripting (XSS) vulnerabilities:
  1. Reflected XSS — inject a payload into URL params and check if it echoes in response
  2. Stored XSS indicators — scan page source for dangerous sink patterns
  3. DOM-based XSS patterns — look for unsafe JS patterns in inline scripts
"""
from typing import List
import re
import requests
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS


# ── Reflected XSS ────────────────────────────────────────────────────────

# Simple, detectable payloads (not meant to bypass WAFs — just to detect echo)
XSS_PROBES = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    '<marquee onstart=alert(1)>',
]


def check_reflected_xss(url: str) -> List[Finding]:
    """
    For each query parameter in the URL, inject each XSS probe and
    check if the raw string appears unencoded in the response.
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []   # No query params → nothing to inject

    for param_name in params:
        for probe in XSS_PROBES:
            # Build a test URL with the injected param
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = probe
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

            try:
                resp = requests.get(
                    test_url,
                    headers=DEFAULT_HEADERS,
                    timeout=SCAN_TIMEOUT,
                    verify=_TLS_VERIFY,
                    allow_redirects=True,
                )
                # If the raw probe appears verbatim in the response — it's reflected
                if probe.lower() in resp.text.lower():
                    findings.append(Finding(
                        vuln_type  = "Cross-Site Scripting (Reflected XSS)",
                        severity   = "HIGH",
                        url        = url,
                        detail     = (
                            f"Parameter '{param_name}' reflects user input unescaped into the HTML response. "
                            "An attacker can craft a malicious URL that executes JavaScript in victims' browsers."
                        ),
                        evidence   = f"Payload '{probe}' echoed in response via param '{param_name}'",
                        remediation= (
                            "HTML-encode all user-supplied output. "
                            "Use a template engine with auto-escaping (e.g., Jinja2, React). "
                            "Implement a strict Content-Security-Policy header."
                        ),
                    ))
                    break   # One confirmed finding per param is enough
            except requests.RequestException:
                continue

    return findings


# ── Stored / DOM XSS indicators ──────────────────────────────────────────

# Patterns in page source suggesting dangerous HTML sinks
DANGEROUS_SINK_PATTERNS = [
    (r'document\.write\s*\(', "document.write()"),
    (r'innerHTML\s*=',         "innerHTML assignment"),
    (r'outerHTML\s*=',         "outerHTML assignment"),
    (r'eval\s*\(',             "eval() call"),
    (r'setTimeout\s*\(\s*["\']', "setTimeout with string arg"),
    (r'setInterval\s*\(\s*["\']', "setInterval with string arg"),
    (r'\.html\s*\(',           "jQuery .html() call"),
]

# Patterns suggesting input is fed into a sink
INPUT_SOURCE_PATTERNS = [
    r'location\.search',
    r'location\.hash',
    r'document\.referrer',
    r'window\.name',
    r'URLSearchParams',
]


def check_dom_xss(url: str, response: requests.Response) -> List[Finding]:
    """
    Scan inline <script> blocks and external script references
    for dangerous DOM manipulation patterns.
    """
    findings = []
    soup     = BeautifulSoup(response.text, "html.parser")

    for script_tag in soup.find_all("script"):
        script_content = script_tag.string or ""
        if not script_content.strip():
            continue

        for pattern, sink_name in DANGEROUS_SINK_PATTERNS:
            if re.search(pattern, script_content, re.IGNORECASE):
                # Check if any known input source is also present — raises confidence
                has_source = any(
                    re.search(src, script_content, re.IGNORECASE)
                    for src in INPUT_SOURCE_PATTERNS
                )

                findings.append(Finding(
                    vuln_type  = "Cross-Site Scripting (DOM-based Indicator)",
                    severity   = "MEDIUM" if has_source else "LOW",
                    url        = url,
                    detail     = (
                        f"Potentially unsafe DOM sink '{sink_name}' detected in inline script"
                        + (" with a user-controlled source — elevated XSS risk." if has_source
                           else ". Manual review recommended.")
                    ),
                    evidence   = _extract_context(script_content, pattern),
                    remediation= (
                        f"Avoid {sink_name} with user-controlled data. "
                        "Use textContent instead of innerHTML. "
                        "Sanitize inputs with DOMPurify before inserting into the DOM."
                    ),
                ))
                break   # One finding per <script> block

    return findings


def check_forms_for_xss(url: str, response: requests.Response) -> List[Finding]:
    """
    Look for forms with text inputs that post to the same page —
    a common attack surface for stored/reflected XSS.
    """
    findings = []
    soup = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        text_inputs = form.find_all("input", {"type": lambda t: t in (None, "text", "search", "email", "url")})
        textareas   = form.find_all("textarea")

        if text_inputs or textareas:
            action  = form.get("action", url)
            full_action = urljoin(url, action)

            findings.append(Finding(
                vuln_type  = "XSS Attack Surface: Unvalidated Form Input",
                severity   = "INFO",
                url        = url,
                detail     = (
                    f"Form targeting '{full_action}' contains "
                    f"{len(text_inputs)} text input(s) and {len(textareas)} textarea(s). "
                    "These are common XSS injection points — manual testing recommended."
                ),
                evidence   = f"Form action='{full_action}', method='{form.get('method','GET').upper()}'",
                remediation= (
                    "Validate and escape all form input server-side. "
                    "Use CSRF tokens on all POST forms."
                ),
            ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────

def _extract_context(text: str, pattern: str, context: int = 80) -> str:
    """Return a snippet of text around the first regex match."""
    m = re.search(pattern, text, re.IGNORECASE)
    if not m:
        return ""
    start = max(0, m.start() - context // 2)
    end   = min(len(text), m.end() + context // 2)
    return "..." + text[start:end].strip().replace("\n", " ") + "..."


# ── Entrypoint ────────────────────────────────────────────────────────────

def run_all_xss_checks(url: str, response: requests.Response) -> List[Finding]:
    results = []
    results.extend(check_reflected_xss(url))
    results.extend(check_dom_xss(url, response))
    results.extend(check_forms_for_xss(url, response))
    return results
