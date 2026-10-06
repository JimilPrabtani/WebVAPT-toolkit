"""
scanner/template_checks.py
──────────────────────────
Nuclei-inspired declarative checks: vulnerability probes defined as DATA
(JSON files in scanner/templates/), not code. Adding a new probe means
dropping in a JSON template — no Python changes, no redeploy of logic.

TEMPLATE SCHEMA (scanner/templates/*.json — a list of template objects):
  {
    "id":          "unique-id (e.g. exposed-git-config)",
    "name":        "Finding title (use an existing prefix like 'Sensitive Path Exposure:'",
    "severity":    "CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "owasp":       "A05:2021 (optional — explicit OWASP id)",
    "cwe":         "CWE-541 (optional)",
    "description": "Human-readable detail of what was found and why it matters",
    "remediation": "How to fix it",
    "requests": [
      {
        "method":  "GET",
        "path":    "/.git/config",
        "match_status": [200],
        "match_body": ["[core]", "repositoryformatversion"],
        "match_body_any": ["alternate phrasing"],
        "match_content_type": ["text/plain"],
        "min_bytes": 10
      }
    ]
  }

MATCH SEMANTICS: every specified condition must hold (AND). Within
match_body ALL snippets must appear; within match_body_any / match_status /
match_content_type at least one must match. The first matching request wins
(one finding per template max). Body markers are the SPA guard: a catch-all
index.html won't contain "[core]" or "repositoryformatversion".

Runs once per scan from the domain root (base URL only) — templates probe
fixed paths, so per-page execution would just repeat the same requests.
"""

import glob
import json
import os
from typing import List
import requests
from scanner.models import Finding
from scanner.fetcher import _session
from config import SCAN_TIMEOUT, ALLOW_INSECURE_TLS

_TLS_VERIFY = not ALLOW_INSECURE_TLS

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

_templates_cache: list | None = None


def _load_templates() -> list:
    """Load + validate all JSON templates once per process."""
    global _templates_cache
    if _templates_cache is not None:
        return _templates_cache
    loaded = []
    for path in sorted(glob.glob(os.path.join(TEMPLATES_DIR, "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] Skipping bad template file {path}: {e}")
            continue
        for t in data if isinstance(data, list) else []:
            if (isinstance(t, dict) and t.get("id") and t.get("name")
                    and t.get("severity") in _VALID_SEVERITIES
                    and isinstance(t.get("requests"), list) and t["requests"]):
                loaded.append(t)
            else:
                print(f"[!] Skipping invalid template in {path}: {t.get('id') if isinstance(t, dict) else t!r}")
    _templates_cache = loaded
    return loaded


def _request_matches(spec: dict, resp: requests.Response) -> str:
    """
    Evaluate one request spec against a response.
    Returns a human-readable match summary, or "" when it doesn't match.
    """
    hits = []
    if "match_status" in spec:
        if resp.status_code not in spec["match_status"]:
            return ""
        hits.append(f"status {resp.status_code}")
    body = resp.text
    if "match_body" in spec:
        missing = [s for s in spec["match_body"] if s not in body]
        if missing:
            return ""
        hits.append(f"body markers {spec['match_body']}")
    if "match_body_any" in spec:
        found = [s for s in spec["match_body_any"] if s in body]
        if not found:
            return ""
        hits.append(f"body marker '{found[0]}'")
    if "match_content_type" in spec:
        ctype = resp.headers.get("Content-Type", "")
        if not any(s in ctype for s in spec["match_content_type"]):
            return ""
        hits.append(f"content-type {ctype}")
    if "min_bytes" in spec:
        if len(resp.content) < spec["min_bytes"]:
            return ""
    return ", ".join(hits) if hits else "response received"


def check_templates(base_url: str) -> List[Finding]:
    """Run every loaded template against the domain root. One hit per template max."""
    from urllib.parse import urlparse  # local import: keeps module import-light for tests
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for t in _load_templates():
        for spec in t["requests"]:
            method = (spec.get("method") or "GET").upper()
            if method != "GET":
                continue  # only safe, idempotent probes — never mutate the target
            test_url = origin + spec.get("path", "/")
            try:
                resp = _session.get(test_url, timeout=SCAN_TIMEOUT,
                                    verify=_TLS_VERIFY, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp is None:
                continue
            matched = _request_matches(spec, resp)
            if matched:
                findings.append(Finding(
                    vuln_type=t["name"],
                    severity=t["severity"],
                    url=test_url,
                    detail=t.get("description", ""),
                    evidence=f"Template '{t['id']}': {test_url} → {matched} ({len(resp.content)} bytes)",
                    remediation=t.get("remediation", ""),
                    owasp_id=t.get("owasp"),
                    cwe_id=t.get("cwe"),
                ))
                break  # one finding per template is enough
    return findings


def run_all_template_checks(url: str, response, base_url: str) -> List[Finding]:
    """Entrypoint for engine.py — fires once (base URL only)."""
    if url != base_url:
        return []
    return check_templates(base_url)
