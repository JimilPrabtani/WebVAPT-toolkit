"""
scanner/traversal_checks.py
───────────────────────────
Detects Path Traversal / Local File Inclusion (LFI) vulnerabilities.

STRATEGY:
  For each URL query parameter, substitute directory-traversal payloads that
  attempt to read well-known OS files, then look for their unmistakable
  content markers in the response:
    - Unix:  ../../../../etc/passwd  →  "root:x:0:0:"
    - Windows: ..\\..\\windows\\win.ini → "[fonts]" / "[extensions]"

A finding is raised ONLY when file content markers appear — a 200 status
alone is not enough (avoids SPA catch-all false positives).

BOUNDS: max 4 payloads per parameter, first confirmed hit per param wins.

REFERENCES:
  - OWASP A03:2021 — Injection (https://owasp.org/Top10/A03_2021-Injection/)
  - CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
  - MITRE T1083 — File and Directory Discovery
"""

from typing import List
import requests
from urllib.parse import urlencode, urlparse, parse_qs
from scanner.models import Finding
from scanner.fetcher import _session
from config import SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS

# (payload, content_marker, description)
TRAVERSAL_PROBES = [
    ("../../../../etc/passwd", "root:x:0:0:", "Unix /etc/passwd"),
    ("....//....//etc/passwd", "root:x:0:0:", "Unix /etc/passwd (filtered dots)"),
    ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0:", "Unix /etc/passwd (encoded)"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"),
]


def check_path_traversal(url: str) -> List[Finding]:
    """
    Inject traversal payloads into each URL query parameter.
    Confirmed only when OS file content markers appear in the response.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    for param_name in params:
        for payload, marker, target in TRAVERSAL_PROBES:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param_name] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

            try:
                resp = _session.get(
                    test_url,
                    timeout=SCAN_TIMEOUT,
                    verify=_TLS_VERIFY,
                    allow_redirects=True,
                )
                if marker in resp.text:
                    findings.append(Finding(
                        vuln_type="Path Traversal (Local File Inclusion)",
                        severity="HIGH",
                        url=url,
                        detail=(
                            f"Parameter '{param_name}' allows reading arbitrary server files: "
                            f"injecting a traversal sequence returned the contents of {target}. "
                            "An attacker can read configuration files, credentials, and source code."
                        ),
                        evidence=(
                            f"Payload '{payload}' in param '{param_name}' → "
                            f"marker '{marker}' found in response"
                        ),
                        remediation=(
                            "Never build file paths from user input. Map inputs to an allowlist of "
                            "permitted files, canonicalize with os.path.realpath and verify the result "
                            "stays inside the intended directory. Run the app with least-privilege file access."
                        ),
                    ))
                    break  # one confirmed finding per parameter is enough
            except requests.RequestException:
                continue

    return findings


def run_all_traversal_checks(url: str, response) -> List[Finding]:
    """Run all traversal checks for a page. Called by engine.py."""
    return check_path_traversal(url)
