"""
scanner/engine.py
─────────────────
The scan orchestrator — coordinates the full pipeline from crawl to AI analysis.

PIPELINE OVERVIEW:
  1. CRAWL   — BFS crawl discovers all pages on the target domain
  2. SCAN    — All check modules run concurrently across every page (thread pool)
  3. DEDUP   — Identical findings are dropped (MD5 fingerprint per vuln+url+evidence)
               Site-wide findings (headers, TLS) dedup by hostname, not per-page URL
  4. AI      — HIGH/CRITICAL/MEDIUM findings sent to AI for CVSS + remediation
  5. REPORT  — report_writer.py saves JSON + TXT files

HOW TO CUSTOMIZE:
  - Add a new check module: import it here, call it in _scan_page()
  - Change thread count: max_workers parameter in run_scan()
  - Skip AI: pass run_ai=False to run_scan(), or set ENABLE_AI_ANALYSIS=false in .env
"""

import time
import hashlib
from typing import List, Tuple, Optional, Callable, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.fetcher        import fetch, crawl, _cache_clear
from scanner.models         import Finding, ScanResult
from scanner.header_checks  import run_all_header_checks
from scanner.xss_checks     import run_all_xss_checks
from scanner.sqli_checks    import run_all_sqli_checks
from scanner.misc_checks    import run_all_misc_checks
from scanner.ssti_checks    import run_all_ssti_checks
from scanner.secrets_checks import run_all_secrets_checks
from scanner.tls_checks     import run_all_tls_checks
from config                 import ENABLE_AI_ANALYSIS


# ── Site-wide finding categories ───────────────────────────────────────────
# These vuln types affect the entire site, not just one page.
# We deduplicate them by HOSTNAME (not per-page URL) to avoid 20x repetition
# of the same "Missing Content-Security-Policy" finding across 20 pages.
#
# To add a new site-wide check: add its vuln_type prefix to this set.
SITE_WIDE_VULN_PREFIXES = (
    "Missing Header:",          # Security headers apply to the whole site
    "Weak Header:",             # Weak header config is also site-wide
    "CORS Misconfiguration:",   # CORS policy is set server-wide
    "TLS:",                     # TLS cert / protocol is per-host, not per-page
    "Insecure Transport:",      # HTTP vs HTTPS is a site-level issue
    "Information Disclosure:",  # Server version leaks are consistent site-wide
)


def _is_site_wide(vuln_type: str) -> bool:
    """
    Return True if this vuln type is a site-wide issue (not page-specific).
    Site-wide findings are deduplicated by hostname to prevent noise.
    """
    return any(vuln_type.startswith(prefix) for prefix in SITE_WIDE_VULN_PREFIXES)


def _scan_page(
    url: str,
    response,
    target_url: str,
    tls_checked: bool,
) -> List[Finding]:
    """
    Run ALL security check modules against a single page.

    This function runs in a worker thread (called by the ThreadPoolExecutor).
    Each page gets all 7 check modules applied to it in sequence.

    Args:
        url:         The page URL being scanned
        response:    The HTTP response object (already fetched by crawl phase)
        target_url:  The original scan start URL (used for base comparisons)
        tls_checked: If True, skip TLS checks (they already ran for this host)

    Returns:
        List of Finding objects from all applicable checks

    HOW TO ADD A NEW CHECK MODULE:
        1. Create scanner/my_new_checks.py with a run_all_my_new_checks() function
        2. Import it at the top of this file
        3. Add: all_findings.extend(run_all_my_new_checks(url, response))
    """
    all_findings = []

    # ── Header checks (site-wide — will be deduped by hostname later) ──────
    all_findings.extend(run_all_header_checks(url, response))

    # ── XSS checks (per-page — URL params + DOM sinks) ─────────────────────
    all_findings.extend(run_all_xss_checks(url, response))

    # ── SQL injection checks (per-page — URL params + form surfaces) ────────
    all_findings.extend(run_all_sqli_checks(url, response))

    # ── Misc checks (HTTPS, open redirect, directory listing, sensitive paths)
    all_findings.extend(run_all_misc_checks(url, response, target_url))

    # ── SSTI checks (per-page — URL params injected with template payloads) ─
    all_findings.extend(run_all_ssti_checks(url, response))

    # ── Secrets checks (per-page — scans response body for leaked credentials)
    all_findings.extend(run_all_secrets_checks(url, response))

    # ── TLS checks (per-host — only runs once for the first page) ──────────
    # The TLS cert and protocol are the same for all pages on the same host.
    # Running this once prevents 20 identical "TLS 1.0 detected" findings.
    if not tls_checked:
        all_findings.extend(run_all_tls_checks(url, response))

    return all_findings


def run_scan(
    target_url: str,
    on_progress: Optional[Callable[[str], None]] = None,
    run_ai: Optional[bool] = None,
    max_pages: Optional[int] = None,
    max_workers: int = 4,
) -> Tuple[ScanResult, Dict]:
    """
    Run the full scan pipeline: crawl → scan → dedup → AI → summary.

    Args:
        target_url:   The website to scan (e.g. "https://example.com")
        on_progress:  Optional callback function for live status messages.
                      Called with a string message. Used by the dashboard
                      to show progress during scanning.
        run_ai:       Override AI setting from config.
                      None  = use ENABLE_AI_ANALYSIS from .env
                      True  = force AI on
                      False = skip AI (useful for quick scans without API key)
        max_pages:    Override MAX_PAGES_TO_CRAWL from .env (None = use config)
        max_workers:  Number of concurrent scan threads (default: 4).
                      Increase for faster scanning, decrease to reduce load.

    Returns:
        Tuple of (ScanResult, exec_summary_dict):
          - ScanResult contains all findings
          - exec_summary_dict is the AI executive summary (empty if AI disabled)

    TROUBLESHOOTING:
      - "Could not reach target" → Check URL, firewall, ALLOW_PRIVATE_TARGETS in .env
      - AI errors → Check AI_PROVIDER and matching API key in .env
      - Too many findings → Reduce MAX_PAGES_TO_CRAWL or use severity filter in dashboard
      - Too few findings → Increase MAX_PAGES_TO_CRAWL in .env
    """
    def log(msg: str):
        """Send progress message to callback or print to console."""
        if on_progress:
            on_progress(msg)
        else:
            print(msg)

    # Clear the per-scan response cache so each scan starts fresh
    _cache_clear()

    use_ai     = ENABLE_AI_ANALYSIS if run_ai is None else run_ai
    result     = ScanResult(target_url=target_url)
    start_time = time.time()

    # ── Step 1: Crawl ─────────────────────────────────────────────────────
    log(f"[*] Starting scan: {target_url}")
    log(f"[*] Crawling site...")

    pages = crawl(target_url, max_pages=max_pages)
    result.pages_crawled = [url for url, _ in pages]
    log(f"[*] Discovered {len(pages)} page(s)")

    if not pages:
        result.error = "Could not reach target. Check the URL and your connection."
        return result, {}

    # ── Step 2: Concurrent scanning  ──────────────────────────────────────
    # Each page is scanned in a separate thread for speed.
    # The deduplication step below handles any collisions from concurrent threads.
    log(f"[*] Scanning pages concurrently ({max_workers} workers)...")

    # Track which hostname already had TLS checks run
    tls_checked_hosts: set = set()

    # Track deduplicated findings:
    #   key = "vuln_type::dedup_url::evidence_hash"
    #   For site-wide findings, dedup_url = hostname (not the full page URL)
    #   This means "Missing CSP" only appears ONCE per scan, not 20× per page
    seen: Dict[str, bool] = {}

    hostname = urlparse(target_url).hostname or target_url

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all pages for concurrent scanning
        # tls_checked=True for all pages except the first of each host
        future_to_url = {}
        for i, (url, response) in enumerate(pages):
            page_host    = urlparse(url).hostname or url
            tls_done     = page_host in tls_checked_hosts
            if not tls_done:
                tls_checked_hosts.add(page_host)
            future = executor.submit(_scan_page, url, response, target_url, tls_done)
            future_to_url[future] = url

        # Collect results as each page finishes
        completed = 0
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            completed += 1
            log(f"[{completed}/{len(pages)}] Completed: {url}")

            try:
                all_findings = future.result()

                for finding in all_findings:
                    # ── Deduplication ────────────────────────────────────
                    # Site-wide findings (headers, TLS, CORS) → dedup by hostname
                    # Per-page findings (XSS, SQLi, secrets) → dedup by full URL
                    if _is_site_wide(finding.vuln_type):
                        # Normalize URL to just hostname for site-wide issues
                        # This prevents 20 identical "Missing CSP" findings
                        finding.url = hostname
                        dedup_url   = hostname
                    else:
                        dedup_url = finding.url

                    # Create a unique fingerprint for this finding
                    evidence_hash = hashlib.md5(finding.evidence.encode()).hexdigest()
                    key = f"{finding.vuln_type}::{dedup_url}::{evidence_hash}"

                    if key not in seen:
                        seen[key] = True
                        result.add(finding)

            except Exception as e:
                log(f"[!] Error scanning {url}: {e}")

    result.scan_duration = time.time() - start_time

    # ── Step 3: AI Analysis ────────────────────────────────────────────────
    # Sends HIGH/CRITICAL/MEDIUM findings to the configured AI provider.
    # AI adds CVSS score, attack scenario, and detailed fix instructions.
    exec_summary = {}
    if use_ai:
        from ai.AI_analyzer import analyze_scan
        exec_summary = analyze_scan(result, on_progress=on_progress)
    else:
        log("[*] AI analysis skipped (disabled in config or --no-ai flag used)")

    # ── Step 4: Final summary ─────────────────────────────────────────────
    s = result.summary()
    log(f"\n{'='*50}")
    log(f"SCAN COMPLETE: {s['target']}")
    log(f"  Pages   : {s['pages_crawled']}")
    log(f"  Findings: {s['total_findings']} total")
    for sev, count in s["by_severity"].items():
        if count:
            log(f"    {sev}: {count}")
    log(f"  Duration: {s['scan_duration']:.1f}s")

    return result, exec_summary
