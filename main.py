import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

from api.routes import router
from api.database import init_db
from config import validate_config

# Read once at startup — never re-read mid-request.
_API_KEY: str = os.getenv("API_KEY", "")

# Paths that are always public (health check / root)
_OPEN_PATHS = {"/"}

# Expose Swagger UI only when EXPOSE_DOCS=true (default: false for security)
_EXPOSE_DOCS = os.getenv("EXPOSE_DOCS", "false").lower() == "true"
if _EXPOSE_DOCS:
    _OPEN_PATHS |= {"/docs", "/redoc", "/openapi.json"}

# ── Rate limiting ─────────────────────────────────────────────────────────
# Uses slowapi (pip install slowapi) — a thin Starlette wrapper around limits.
# 10 scan requests per minute per IP prevents resource exhaustion from
# unauthenticated callers hammering POST /scan.
try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from api.limiter import limiter as _limiter, RATE_LIMITING_AVAILABLE as _rate_limiting_available

except ImportError:
    _limiter = None
    _rate_limiting_available = False
    print("[!] slowapi not installed — rate limiting disabled. Run: pip install slowapi")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    validate_config()
    if _API_KEY:
        print("[*] API key authentication ENABLED (X-API-Key header required).")
    else:
        print("[!] WARNING: API_KEY not set — API is unprotected. Set API_KEY in .env for production.")
    if _rate_limiting_available:
        print("[*] Rate limiting ENABLED — 10 scan requests/minute/IP.")
    print("[*] Database ready. API at http://localhost:8000 | Docs at http://localhost:8000/docs")
    yield
    print("[*] Shutting down.")


app = FastAPI(
    title    = "WebPenTest AI Toolkit",
    version  = "1.0.0",
    lifespan = lifespan,
)

# Attach rate limiter state if available
if _rate_limiting_available:
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── API key middleware ───────────────────────────────────────────────────────
@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Enforce API key authentication when API_KEY is configured in .env."""
    if _API_KEY and request.url.path not in _OPEN_PATHS:
        provided = request.headers.get("X-API-Key", "")
        if provided != _API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: provide a valid X-API-Key header."},
            )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["http://localhost:8501", "http://127.0.0.1:8501"],
    # Explicit lists follow least-privilege — update if new endpoint methods are added.
    allow_methods  = ["GET", "POST", "DELETE"],
    allow_headers  = ["Content-Type", "X-API-Key"],
)

app.include_router(router, prefix="/api/v1", tags=["Scanning"])