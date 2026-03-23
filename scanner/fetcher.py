import requests
import urllib3
from collections import deque
from typing import List, Tuple,Optional, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import DEFAULT_HEADERS, SCAN_TIMEOUT, MAX_PAGES_TO_CRAWL, ALLOW_INSECURE_TLS

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


def fetch(url: str, allow_redirects: bool = True, _use_cache: bool = True) -> Optional[requests.Response]:
    """
    GET a URL with automatic caching within a single scan run.
    
    Args:
        url: Target URL to fetch
        allow_redirects: Whether to follow HTTP redirects
        _use_cache: Internal flag to enable/disable caching (for testing)
        
    Returns:
        Response object or None on network error
        
    Benefits of caching:
      - Crawl phase already fetches all pages → scan phase reuses responses
      - If a page is referenced from multiple scan contexts, fetch once
      - Significant speedup on sites with high link density
    """
    if _use_cache and url in _response_cache:
        return _response_cache[url]
    
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


def crawl(start_url: str, max_pages: int = None) -> List[Tuple[str, requests.Response]]:
    """
    BFS crawl from start_url, staying within the same domain.
    
    Returns a list of (url, response) tuples for each successfully visited page,
    capped at max_pages or MAX_PAGES_TO_CRAWL.

    Caching greatly benefits this function:
      - Returning the response alongside the URL means the scan engine can reuse
        the already-fetched content instead of issuing a second HTTP request per page.
      - Additionally, responses are cached per-scan, so any URL fetched here is
        never re-requested during the check phase.

    Example:
        pages = crawl("https://example.com", max_pages=50)
        # pages = [("https://example.com", response_obj), ...]
        
    Args:
        start_url: Entry point for crawl
        max_pages: Override MAX_PAGES_TO_CRAWL limit (None = use config)
        
    Returns:
        List of (url, response) tuples already fetched
    """
    limit        = max_pages if max_pages is not None else MAX_PAGES_TO_CRAWL
    parsed_start = urlparse(start_url)
    base_domain  = parsed_start.netloc

    visited: set[str]                            = set()
    queue:   deque[str]                          = deque([start_url])
    ordered: List[Tuple[str, requests.Response]] = []

    while queue and len(visited) < limit:
        url = queue.popleft()
        url = url.split("#")[0]
        if url in visited:
            continue

        resp = fetch(url)
        if resp is None:
            continue

        visited.add(url)
        ordered.append((url, resp))

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = parse_html(resp)

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            full = urljoin(url, href).split("#")[0]
            parsed = urlparse(full)

            if (
                parsed.netloc == base_domain
                and parsed.scheme in ("http", "https")
                and full not in visited
                and full not in queue
            ):
                queue.append(full)

    return ordered
