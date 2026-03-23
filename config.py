import os
import ipaddress
import socket
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
ENABLE_AI_ANALYSIS: bool = os.getenv("ENABLE_AI_ANALYSIS", "true").lower() == "true"

# Set ALLOW_PRIVATE_TARGETS=false in .env when the API is internet-facing
# to prevent callers from using the scanner to probe internal infrastructure (SSRF).
ALLOW_PRIVATE_TARGETS: bool = os.getenv("ALLOW_PRIVATE_TARGETS", "true").lower() == "true"

# Set ALLOW_INSECURE_TLS=true only when intentionally scanning targets with
# self-signed certificates. Default is False (TLS verification enabled).
ALLOW_INSECURE_TLS: bool = os.getenv("ALLOW_INSECURE_TLS", "false").lower() == "true"


def _int_env(name: str, default: int) -> int:
    val = os.getenv(name, str(default))
    try:
        return int(val)
    except ValueError:
        print(f"[!] Invalid value for {name} in .env (got '{val}') -- using default {default}")
        return default


SCAN_TIMEOUT: int = _int_env("SCAN_TIMEOUT", 10)
MAX_PAGES_TO_CRAWL: int = _int_env("MAX_PAGES_TO_CRAWL", 20)

DEFAULT_HEADERS: dict = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; WebPenTestBot/1.0; "
        "+https://github.com/you/webpentest)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── SSRF guard ────────────────────────────────────────────────────────────

def is_ssrf_safe(url: str) -> bool:
    """
    Returns True if the URL resolves to a routable public IP address.
    Returns False if it resolves to a private, loopback, link-local, or
    reserved address — all of which are SSRF attack vectors.

    Used by both the API (routes.py) and CLI (scan.py) before scanning starts.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        ip_str = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except Exception:
        # If we cannot resolve the hostname, treat as unsafe
        return False