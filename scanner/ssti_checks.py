"""
scanner/ssti_checks.py
──────────────────────
Detects Server-Side Template Injection (SSTI) vulnerabilities.

Strategy: inject math payloads that evaluate differently in template engines
vs. plain string contexts. If `{{7*7}}` returns `49`, a template engine is
executing our input — SSTI is confirmed (OWASP A03:2021, CWE-94, MITRE T1059).

Engines detected: Jinja2/Twig ({{}}), FreeMarker/Smarty (${}), Mako/Cheetah.
"""

import re
import requests
from urllib.parse import urlencode, urlparse, parse_qs
from scanner.models import Finding
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS

# Each probe is (payload, expected_result_pattern, engine_hint)
SSTI_PROBES = [
    # Jinja2 / Twig / Django (Python, PHP)
    ("{{7*7}}",           r"\b49\b",   "Jinja2/Twig"),
    ("{{7*'7'}}",         r"49|7777777", "Jinja2 (Python)"),
    # FreeMarker (Java)
    ("${7*7}",            r"\b49\b",   "FreeMarker"),
    # Smarty (PHP)
    ("{7*7}",             r"\b49\b",   "Smarty"),
    # Mako / Cheetah (Python)
    ("${7*7}",            r"\b49\b",   "Mako/Cheetah"),
    # Pebble / Velocity (Java)
    ("#{7*7}",            r"\b49\b",   "Velocity/Pebble"),
]


def check_ssti(url: str) -> list[Finding]:
    """
    Test each URL query parameter for SSTI by injecting math probes.
    A finding is raised only when the arithmetic result (49) appears
    in the response — not just the payload string itself.
    """
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    for param_name in params:
        for payload, result_pattern, engine in SSTI_PROBES:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = (
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                f"?{urlencode(test_params)}"
            )

            try:
                resp = requests.get(
                    test_url,
                    headers        = DEFAULT_HEADERS,
                    timeout        = SCAN_TIMEOUT,
                    verify         = _TLS_VERIFY,
                    allow_redirects= True,
                )
                # Confirm arithmetic result appears in response (not just raw payload)
                if re.search(result_pattern, resp.text):
                    findings.append(Finding(
                        vuln_type  = "Server-Side Template Injection (SSTI)",
                        severity   = "CRITICAL",
                        url        = url,
                        detail     = (
                            f"Parameter '{param_name}' is evaluated by a server-side template engine "
                            f"({engine}). Injecting `{payload}` returned `{re.search(result_pattern, resp.text).group()}` "
                            "in the response. SSTI allows Remote Code Execution — an attacker can "
                            "read files, exfiltrate environment variables, or execute OS commands."
                        ),
                        evidence   = (
                            f"Payload: {payload}  →  Result pattern '{result_pattern}' "
                            f"matched in response from param '{param_name}'"
                        ),
                        remediation= (
                            "Never pass user input into a template rendering function. "
                            "Use sandboxed rendering environments (Jinja2 SandboxedEnvironment). "
                            "Validate and reject inputs containing template metacharacters: {{ ${ # }}"
                        ),
                    ))
                    break   # One confirmed finding per param
            except requests.RequestException:
                continue

    return findings


def run_all_ssti_checks(url: str, response) -> list[Finding]:
    return check_ssti(url)
