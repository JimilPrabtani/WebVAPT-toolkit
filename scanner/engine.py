import time
import hashlib
from typing import List, Tuple, Optional, Callable, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _scan_page(
    url: str, 
    response,
    target_url: str,
    tls_checked: bool,
) -> List[Finding]:
    """
    Run all security checks on a single page (used for concurrent scanning).
    
    Args:
        url: Page URL
        response: HTTP response object
        target_url: Original target URL for comparison
        tls_checked: Whether TLS checks have already been run
        
    Returns:
        List of findings for this page
    """
    all_findings = []
    all_findings.extend(run_all_header_checks(url, response))
    all_findings.extend(run_all_xss_checks(url, response))
    all_findings.extend(run_all_sqli_checks(url, response))
    all_findings.extend(run_all_misc_checks(url, response, target_url))
    all_findings.extend(run_all_ssti_checks(url, response))
    all_findings.extend(run_all_secrets_checks(url, response))
    
    # TLS checks only need to run once per host (same cert for all pages)
    if not tls_checked:
        all_findings.extend(run_all_tls_checks(url, response))
    
    return all_findings


def run_scan(
    target_url: str,
    on_progress: Optional[Callable[[str], None]] = None,
    run_ai: Optional[bool] = None,
    max_pages: Optional[int] = None,
    max_workers: int = 4,  # Number of concurrent scan threads for checks
) -> Tuple[ScanResult, Dict]:
    """
    Full pipeline scan with concurrent page checking.

    Returns:
        (ScanResult, exec_summary_dict)
        exec_summary is empty dict if AI is disabled.

    Args:
        target_url: Target website URL
        on_progress: Optional callback for live status updates
        run_ai: Override ENABLE_AI_ANALYSIS from config (None = use config)
        max_pages: Override MAX_PAGES_TO_CRAWL from config (None = use config)
        max_workers: Number of threads for concurrent page scanning (default: 4)
    """
    def log(msg: str):
        if on_progress:
            on_progress(msg)
        else:
            print(msg)

    # Clear the response cache at the start of each scan
    _cache_clear()
    
    use_ai     = ENABLE_AI_ANALYSIS if run_ai is None else run_ai
    result     = ScanResult(target_url=target_url)
    start_time = time.time()

    log(f"[*] Starting scan: {target_url}")
    log(f"[*] Crawling site...")
    
    # Crawl phase: discover all internal links (with caching to avoid re-fetching)
    pages = crawl(target_url, max_pages=max_pages)
    result.pages_crawled = [url for url, _ in pages]
    log(f"[*] Discovered {len(pages)} page(s)")

    if not pages:
        result.error = "Could not reach target. Check the URL and your connection."
        return result, {}

    seen: Dict[str, bool] = {}

    # ── Concurrent scanning phase ────────────────────────────────────────
    log(f"[*] Scanning pages concurrently ({max_workers} workers)...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks — pass tls_already_checked=True for every page
        # except the very first one (index 0), so TLS only runs once per scan.
        future_to_url = {
            executor.submit(_scan_page, url, response, target_url, i > 0): url
            for i, (url, response) in enumerate(pages)
        }

        # Process results as they complete
        completed = 0
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            completed += 1
            log(f"[{completed}/{len(pages)}] Completed: {url}")
            
            try:
                all_findings = future.result()
                
                # Deduplicate findings
                for finding in all_findings:
                    key = (
                        f"{finding.vuln_type}::{finding.url}::"
                        f"{hashlib.md5(finding.evidence.encode()).hexdigest()}"
                    )
                    if key not in seen:
                        seen[key] = True
                        result.add(finding)
                        
            except Exception as e:
                log(f"[!] Error scanning {url}: {e}")

    result.scan_duration = time.time() - start_time

    # ──────────────────────────────────────────────────
    exec_summary = {}
    if use_ai:
        from ai.AI_analyzer import analyze_scan
        exec_summary = analyze_scan(result, on_progress=on_progress)
    else:
        log("[*] AI analysis skipped (disabled in config)")

    # ── Summary ──────────────────────────────────────────────────────────
    s = result.summary()
    log(f"\n{'='*50}")
    log(f"SCAN COMPLETE: {s['target']}")
    log(f"  Pages  : {s['pages_crawled']}")
    log(f"  Findings: {s['total_findings']} total")
    for sev, count in s["by_severity"].items():
        if count:
            log(f"    {sev}: {count}")
    log(f"  Duration: {s['scan_duration']:.1f}s")

    return result, exec_summary
