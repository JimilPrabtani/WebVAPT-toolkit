"""
scanner/osv_checks.py
─────────────────────
Software-supply-chain scanning, OSV-Scanner style: extract client-side
JavaScript library name + version from <script src> URLs, then ask the
public OSV database (https://api.osv.dev) whether that exact version has
known vulnerabilities.

HOW IT WORKS (per page):
  1. Collect script src values (e.g. /js/jquery-3.4.1.min.js,
     https://cdn…/bootstrap@5.3.2/…, /static/react-18.2.0/…).
  2. Map the filename token to an npm package (KNOWN_LIBS).
  3. POST {package:{name, ecosystem:npm}, version} to OSV v1/query.
  4. One finding per vulnerable library: aliases (real CVE IDs where the
     OSV record carries them), severity from the highest CVSS in the record.

NETWORK FAILURE = SILENT SKIP. OSV is best-effort enrichment: offline labs,
proxied networks, or API downtime must never fail or slow a scan (15s cap
per lookup, results cached per name@version for the process lifetime).

REFERENCES:
  - OSV schema — https://ossf.github.io/osv-schema/
  - OWASP A06:2021 — Vulnerable and Outdated Components
  - CWE-1104 — Use of Unmaintained Third-Party Components
"""

import re
from typing import List
import requests
from bs4 import BeautifulSoup
from scanner.models import Finding

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 15

# filename token → npm package name (unscoped packages only)
KNOWN_LIBS = {
    "jquery": "jquery",
    "angular": "angular",
    "bootstrap": "bootstrap",
    "react": "react",
    "react-dom": "react-dom",
    "vue": "vue",
    "lodash": "lodash",
    "moment": "moment",
    "axios": "axios",
    "d3": "d3",
    "chart": "chart.js",
    "three": "three",
    "popper": "popper.js",
    "backbone": "backbone",
    "ember": "ember-source",
    "handlebars": "handlebars",
    "mustache": "mustache",
    "underscore": "underscore",
    "socket.io": "socket.io",
}

_VERSION_RE = re.compile(r"[-@/](\d+\.\d+\.\d+(?:[-+][\w.]+)?)")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# name@version → list of OSV vuln dicts (process-lifetime cache)
_osv_cache: dict = {}


def _extract_libs(page_url: str, html: str) -> list:
    """Return [(npm_name, version)] pairs found in script src attributes."""
    found = []
    seen = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip().lower()
        for token, npm_name in KNOWN_LIBS.items():
            if token not in src:
                continue
            m = _VERSION_RE.search(src)
            if not m:
                continue
            key = (npm_name, m.group(1))
            if key not in seen:
                seen.add(key)
                found.append(key)
    return found


def _query_osv(npm_name: str, version: str) -> list:
    """Return OSV vuln records for name@version ([] on any failure)."""
    key = f"{npm_name}@{version}"
    if key in _osv_cache:
        return _osv_cache[key]
    try:
        resp = requests.post(
            OSV_QUERY_URL,
            json={"package": {"name": npm_name, "ecosystem": "npm"}, "version": version},
            timeout=OSV_TIMEOUT,
        )
        vulns = resp.json().get("vulns", []) if resp.status_code == 200 else []
    except requests.RequestException:
        vulns = []
    _osv_cache[key] = vulns if isinstance(vulns, list) else []
    return _osv_cache[key]


# OSV severity words (database_specific.severity) → scanner severity.
_OSV_SEV = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM",
            "medium": "MEDIUM", "low": "LOW"}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _worst_osv_severity(vulns: list) -> str:
    """Worst database_specific severity across records (HIGH when unrated)."""
    worst = "HIGH"
    for v in vulns:
        word = str(v.get("database_specific", {}).get("severity", "")).lower()
        sev = _OSV_SEV.get(word)
        if sev and _SEV_RANK[sev] < _SEV_RANK[worst]:
            worst = sev
    return worst


def _cvss_vectors(vulns: list) -> list:
    """Collect CVSS vector strings for evidence (no fake numeric scores)."""
    out = []
    for v in vulns:
        for sev in v.get("severity", []):
            if sev.get("type") in ("CVSS_V3", "CVSS_V4") and sev.get("score"):
                out.append(f"{v.get('id')}: {sev['score']}")
    return out


def check_js_libraries(url: str, response: requests.Response) -> List[Finding]:
    """Flag client-side libraries with known OSV-recorded vulnerabilities."""
    findings = []
    for npm_name, version in _extract_libs(url, response.text):
        vulns = _query_osv(npm_name, version)
        if not vulns:
            continue
        cves = sorted({
            a.upper() for v in vulns for a in v.get("aliases", [])
            if isinstance(a, str) and _CVE_RE.match(a.upper())
        })
        ids = [v.get("id", "?") for v in vulns]
        severity = _worst_osv_severity(vulns)
        vectors = _cvss_vectors(vulns)
        findings.append(Finding(
            vuln_type=f"Vulnerable Component: {npm_name}@{version}",
            severity=severity,
            url=url,
            detail=(
                f"JavaScript library {npm_name}@{version} has {len(vulns)} known "
                f"vulnerabilit{'y' if len(vulns) == 1 else 'ies'} in the OSV database: "
                + "; ".join(f"{v.get('id')} — {v.get('summary', 'no summary')}" for v in vulns[:5])
                + (f" (+{len(vulns) - 5} more)" if len(vulns) > 5 else "")
            ),
            evidence=(f"Script src references {npm_name}@{version}; OSV records: "
                      f"{', '.join(ids[:5])}"
                      + (f"; CVSS: {' | '.join(vectors[:3])}" if vectors else "")),
            remediation=(
                f"Upgrade {npm_name} to the latest patched release and re-scan. "
                "Long term: enable Dependabot/Renovate and fail CI on known-critical "
                "dependency CVEs (this scanner's OSV check does exactly that lookup)."
            ),
            owasp_id="A06:2021",
            cve_ids=cves[:10],
        ))
    return findings


def run_all_osv_checks(url: str, response: requests.Response) -> List[Finding]:
    """Run all supply-chain checks for a page. Called by engine.py."""
    ctype = response.headers.get("Content-Type", "")
    if "text/html" not in ctype:
        return []
    return check_js_libraries(url, response)
