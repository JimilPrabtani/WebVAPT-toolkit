import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    validate_config()
    if _API_KEY:
        print("[*] API key authentication ENABLED (X-API-Key header required).")
    else:
        print("[!] WARNING: API_KEY not set — API is unprotected. Set API_KEY in .env for production.")
    print("[*] Database ready. API at http://localhost:8000 | Docs at http://localhost:8000/docs")
    yield
    print("[*] Shutting down.")


app = FastAPI(
    title    = "WebPenTest AI Toolkit",
    version  = "1.0.0",
    lifespan = lifespan,
)

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


def _cors_origins() -> list[str]:
    """Origins allowed to call the API from a different URL (e.g. a hosted TUI).

    The terminaltui TUI (Node, `npx webvapt-tui`) calls this API over HTTP
    from *outside the browser*, so CORS is not enforced for it. Set
    CORS_ORIGINS (comma-separated) only if a browser-hosted frontend is added.
    """
    raw = os.getenv("CORS_ORIGINS", "")
    return [o.strip() for o in raw.split(",") if o.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins  = _cors_origins(),
    # Explicit lists follow least-privilege — update if new endpoint methods are added.
    allow_methods  = ["GET", "POST", "DELETE"],
    allow_headers  = ["Content-Type", "X-API-Key"],
)

app.include_router(router, prefix="/api/v1", tags=["Scanning"])