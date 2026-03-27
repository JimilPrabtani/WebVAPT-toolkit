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
ALLOW_PRIVATE_TARGETS: bool = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"

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
        "+https://github.com/JimilPrabtani/WebVAPT-toolkit)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── SSRF guard ────────────────────────────────────────────────────────────

def is_ssrf_safe(url: str) -> bool:
    """
    Returns True if the URL resolves to a routable public IP address.
    Returns False if any resolved address is private, loopback, link-local,
    reserved, or multicast — all of which are SSRF attack vectors.

    Uses getaddrinfo to resolve all A/AAAA records (handles both IPv4 and IPv6)
    and blocks if ANY of them resolve to a non-public range, guarding against
    DNS rebinding attacks.

    Used by both the API (routes.py) and CLI (scan.py) before scanning starts.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # getaddrinfo returns all A/AAAA records — check every one
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
        # If we cannot resolve the hostname, treat as unsafe
        return False


# ── Startup configuration validation ─────────────────────────────────────

def validate_config() -> None:
    """Validate .env configuration at startup and print actionable warnings."""
    provider = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    key_map = {
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }
    if ENABLE_AI_ANALYSIS and provider in key_map:
        key_name = key_map[provider]
        if not os.getenv(key_name, "").strip():
            print(f"[!] CONFIG ERROR: AI_PROVIDER={provider} but {key_name} is not set in .env.")
            print(f"    → AI analysis will fail. Set {key_name}=your_key in .env.")
    if not os.getenv("API_KEY", "").strip():
        print("[!] SECURITY WARNING: API_KEY is not set. The API is unprotected.")
        print("    → Set API_KEY=$(openssl rand -hex 32) in .env for production.")
    if ALLOW_PRIVATE_TARGETS:
        print("[!] SECURITY WARNING: ALLOW_PRIVATE_TARGETS=true.")
        print("    → The scanner can probe internal network ranges. Set ALLOW_PRIVATE_TARGETS=false on public servers.")