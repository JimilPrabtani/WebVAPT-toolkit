"""
scanner/fetcher.py
──────────────────
HTTP client, BFS web crawler, and SPA path discovery for the scanner.

TWO MAIN FUNCTIONS:
  1. fetch(url)  — GET a single URL with caching and SSRF protection
  2. crawl(url)  — BFS crawl from a start URL, staying within the same domain
                   + falls back to path discovery when a SPA is detected

RESPONSE CACHING:
  Each URL is fetched only ONCE per scan and cached in _response_cache.
  This is important because:
    - The crawl phase fetches pages to discover links
    - The scan phase reads those same pages for security checks
    - Without caching, every page would be fetched twice (or more)
  Cache is cleared at the start of each scan (engine.py calls _cache_clear())

SSRF PROTECTION (important for public deployments):
  SSRF (Server-Side Request Forgery) is when an attacker tricks the scanner
  into fetching internal URLs (e.g. http://192.168.1.1/admin).
  We protect against this with two checks:
    1. config.is_ssrf_safe() at the API level validates the target before scan starts
    2. _is_resolved_ip_safe() re-validates at each request (catches DNS rebinding attacks)
  Set ALLOW_PRIVATE_TARGETS=true in .env ONLY when scanning internal/private hosts.

HOW THE BFS CRAWLER WORKS:
  1. Start with the target URL in a queue
  2. Fetch the page, parse all <a href=> links
  3. Add same-domain links to the queue
  4. Continue until the queue is empty or MAX_PAGES_TO_CRAWL is reached
  5. Fragment URLs (#anchor) are stripped before comparing (avoids duplicate fetches)

SPA DETECTION + PATH DISCOVERY:
  Single Page Applications (React, Angular, Vue, etc.) route entirely via JavaScript.
  Their links are NOT in HTML <a href=> tags — they're rendered by JS at runtime.
  Example: OWASP Juice Shop (Angular) only shows its homepage to a static crawler.

  When the BFS crawl finds ONLY 1 page (the homepage), the crawler automatically
  tries a curated list of common web app paths to discover more scan surface.
  This is controlled by KNOWN_WEBAPP_PATHS below.

  To add Juice Shop-specific paths: add them to JUICESHOP_PATHS.
  To add paths for any other app: add them to COMMON_API_PATHS or ADMIN_PATHS.
"""

import requests
import urllib3
import ipaddress
import socket
from collections import deque
from typing import List, Tuple, Optional, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, MAX_PAGES_TO_CRAWL, ALLOW_INSECURE_TLS, ALLOW_PRIVATE_TARGETS

# Suppress TLS warnings only when the user has explicitly opted into insecure mode.
if ALLOW_INSECURE_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TLS_VERIFY = not ALLOW_INSECURE_TLS

# ── Per-scan cache (prevents re-fetching same URL within a single scan) ──────
_response_cache: Dict[str, Optional[requests.Response]] = {}


def _cache_clear() -> None:
    """Clear the response cache. Called at the start of each scan."""
    global _response_cache
    _response_cache.clear()


def _is_resolved_ip_safe(hostname: str) -> bool:
    """
    Re-validate the resolved IP(s) of a hostname at request time.
    Guards against DNS rebinding: the SSRF check in config.is_ssrf_safe()
    resolves the hostname once at scan-start validation time; an attacker
    can return a public IP then, and a private IP when the actual request
    fires. This per-request check catches that second resolution.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        for result in results:
            addr = ipaddress.ip_address(result[4][0])
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
            ):
                return False
        return True
    except Exception:
        return False


def fetch(url: str, allow_redirects: bool = True, _use_cache: bool = True) -> Optional[requests.Response]:
    """
    GET a URL with automatic caching within a single scan run.

    Args:
        url:             Target URL to fetch
        allow_redirects: Whether to follow HTTP redirects
        _use_cache:      Internal flag to enable/disable caching (for testing)

    Returns:
        Response object or None on network error

    Benefits of caching:
      - Crawl phase already fetches all pages → scan phase reuses responses
      - If a page is referenced from multiple scan contexts, fetch once
      - Significant speedup on sites with high link density
    """
    if _use_cache and url in _response_cache:
        return _response_cache[url]

    # Per-request SSRF guard: re-validate resolved IP when private targets are
    # disallowed. This catches DNS rebinding attacks.
    if not ALLOW_PRIVATE_TARGETS:
        hostname = urlparse(url).hostname
        if hostname and not _is_resolved_ip_safe(hostname):
            if _use_cache:
                _response_cache[url] = None
            return None

    try:
        response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=SCAN_TIMEOUT,
            allow_redirects=allow_redirects,
            verify=_TLS_VERIFY,
        )
        if _use_cache:
            _response_cache[url] = response
        return response
    except requests.exceptions.RequestException:
        if _use_cache:
            _response_cache[url] = None
        return None


def parse_html(response: requests.Response) -> BeautifulSoup:
    """Parse HTML response body into BeautifulSoup object."""
    return BeautifulSoup(response.text, "html.parser")


# ── SPA Path Discovery ────────────────────────────────────────────────────
#
# When a BFS crawl only finds 1 page (typical of React/Angular/Vue SPAs),
# we probe a curated list of paths to discover more pages to scan.
#
# HOW TO EXTEND:
#   - Add new paths to the lists below
#   - Paths are probed against the domain root (e.g. https://example.com/api/users)
#   - Only paths that return 200 with non-trivial content are added to the scan queue
#
# IMPORTANT: These are PASSIVE probes (GET requests only, no mutation)

# ── OWASP Juice Shop specific paths ─────────────────────────────────────
# Juice Shop is built with Angular and exposes these REST API endpoints.
# All return JSON that can be scanned for secrets, injection surfaces, etc.
JUICESHOP_PATHS = [
    "/rest/products/search?q=test",   # Search endpoint — XSS + SQLi surface
    "/rest/user/login",               # Login endpoint — SQLi + auth bypass surface
    "/rest/basket/1",                 # BOLA/IDOR surface (try different IDs)
    "/rest/basket/2",
    "/rest/user/whoami",              # JWT authentication status
    "/api/Challenges",                # Challenge list (info disclosure)
    "/api/Products",                  # Product catalog
    "/api/Users",                     # User list — BOLA/privilege escalation
    "/api/Feedbacks",                 # Feedback endpoint
    "/#/login",                       # Angular login page (static)
    "/#/register",                    # Registration page
    "/#/search?q=xss",                # Search with XSS probe
    "/ftp",                           # FTP directory (often accessible in Juice Shop)
    "/ftp/acquisitions.md",           # Exposed acquisition document
    "/assets/i18n/en.json",           # i18n file — info disclosure
]

# ── Common web app paths for generic SPAs ────────────────────────────────
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/users",
    "/api/products",
    "/api/orders",
    "/api/health",
    "/api/status",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/actuator",
    "/actuator/health",
    "/metrics",
]

ADMIN_PATHS = [
    "/admin",
    "/dashboard",
    "/login",
    "/register",
    "/profile",
    "/account",
    "/settings",
]

STATIC_PATHS = [
    "/about",
    "/contact",
    "/help",
    "/faq",
    "/privacy",
    "/terms",
    "/sitemap.xml",
    "/robots.txt",
]

# All paths to probe when SPA is detected (order matters — most valuable first)
SPA_DISCOVERY_PATHS = JUICESHOP_PATHS + COMMON_API_PATHS + ADMIN_PATHS + STATIC_PATHS


def _discover_spa_paths(origin: str, existing_urls: set, limit: int) -> List[Tuple[str, requests.Response]]:
    """
    Probe common paths when a SPA is detected (crawl found only 1 page).

    This acts as a fallback for React/Angular/Vue applications where the BFS
    crawler can't find routes because they're rendered by JavaScript at runtime.

    How it works:
      1. Try each path in SPA_DISCOVERY_PATHS
      2. Add the URL to the scan list if:
         - HTTP status is 200 or 206 (content served)
         - Response body is non-trivial (>50 bytes)
         - Not a duplicate of an already-found page
      3. Stop once we reach the scan limit

    Args:
        origin:       The domain root (e.g. "http://localhost:3000")
        existing_urls: Already-found URLs (to avoid duplicates)
        limit:        Max number of additional pages to add

    Returns:
        List of (url, response) tuples for discovered pages
    """
    print(f"[*] SPA detected — probing {len(SPA_DISCOVERY_PATHS)} common paths...")
    discovered = []

    for path in SPA_DISCOVERY_PATHS:
        if len(discovered) >= limit:
            break

        # Handle hash-fragment Angular routes: Angular SPAs use /#/route
        # These are client-side only — we can't fetch them separately.
        # Instead we record them as found but use the homepage response.
        if path.startswith("/#"):
            url = origin + path
            if url not in existing_urls:
                base_resp = _response_cache.get(origin)
                if base_resp is not None:
                    existing_urls.add(url)
                    discovered.append((url, base_resp))
            continue

        url  = origin + path
        if url in existing_urls:
            continue

        resp = fetch(url, _use_cache=True)
        if resp is None:
            continue
        if resp.status_code not in (200, 206):
            continue
        if len(resp.content) < 50:
            continue

        existing_urls.add(url)
        discovered.append((url, resp))

    print(f"[*] SPA discovery: found {len(discovered)} additional page(s)")
    return discovered


def crawl(start_url: str, max_pages: int = None) -> List[Tuple[str, requests.Response]]:
    """
    BFS crawl from start_url, staying within the same domain.
    Falls back to path discovery when a SPA is detected.

    Returns a list of (url, response) tuples for each successfully visited page,
    capped at max_pages or MAX_PAGES_TO_CRAWL.

    SPA DETECTION:
      If after the BFS crawl only 1 page was found (the homepage), it's very
      likely a SPA with JS-rendered routing. We automatically run _discover_spa_paths()
      to find additional scan surface (API endpoints, known routes, etc.).

    Args:
        start_url: Entry point for the crawl
        max_pages: Override MAX_PAGES_TO_CRAWL limit (None = use config)

    Returns:
        List of (url, response) tuples already fetched
    """
    limit        = max_pages if max_pages is not None else MAX_PAGES_TO_CRAWL
    parsed_start = urlparse(start_url)
    base_domain  = parsed_start.netloc
    origin       = f"{parsed_start.scheme}://{parsed_start.netloc}"

    visited: set[str]                            = set()
    queue:   deque[str]                          = deque([start_url])
    ordered: List[Tuple[str, requests.Response]] = []

    # ── Phase 1: BFS crawl using static <a href> link discovery ──────────
    while queue and len(visited) < limit:
        url = queue.popleft()
        url = url.split("#")[0]   # Strip fragment (avoids duplicate fetches)
        if url in visited:
            continue

        resp = fetch(url)
        if resp is None:
            continue

        visited.add(url)
        ordered.append((url, resp))

        # Only parse HTML pages for links — skip JSON APIs, binary files, etc.
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = parse_html(resp)

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            full = urljoin(url, href).split("#")[0]   # Strip fragment from discovered links
            parsed = urlparse(full)

            if (
                parsed.netloc == base_domain
                and parsed.scheme in ("http", "https")
                and full not in visited
                and full not in queue
            ):
                queue.append(full)

    # ── Phase 2: SPA fallback path discovery ─────────────────────────────
    # If we only found 1 page (the homepage), it's almost certainly a SPA.
    # Run path discovery to find API endpoints and known routes.
    #
    # We only do this when BFS found ≤1 pages because:
    #   - Traditional sites already expose their links in HTML
    #   - We don't want to probe paths on traditional sites that are already crawled
    #   - SPAs specifically need this — their links aren't discoverable from HTML
    if len(ordered) <= 1 and limit > 1:
        remaining = limit - len(ordered)
        spa_pages = _discover_spa_paths(origin, visited, remaining)
        ordered.extend(spa_pages)

    return ordered
