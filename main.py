import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from api.routes import router
from api.terminal import router as terminal_router
from api.database import init_db
from config import validate_config

# Read once at startup — never re-read mid-request.
_API_KEY: str = os.getenv("API_KEY", "")

# Paths that are always public (health check / root)
_OPEN_PATHS = {"/"}

# The web terminal is intentionally public like a local terminal session:
# browsers cannot send the X-API-Key header on page loads, and each
# connection only gets the TUI (never a shell). Do NOT expose this server
# to a network without reverse-proxy authentication in front of it.
_OPEN_PATHS |= {"/terminal", "/ws/terminal"}

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
    if _API_KEY and request.url.path not in _OPEN_PATHS \
            and not request.url.path.startswith("/static/"):
        provided = request.headers.get("X-API-Key", "")
        if provided != _API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: provide a valid X-API-Key header."},
            )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    # No browser client ships with the project (the TUI and CLI call the
    # scan engine in-process), so no cross-origin access is granted.
    # Add an origin here only if you build a browser frontend for the API.
    allow_origins  = [],
    # Explicit lists follow least-privilege — update if new endpoint methods are added.
    allow_methods  = ["GET", "POST", "DELETE"],
    allow_headers  = ["Content-Type", "X-API-Key"],
)

app.include_router(router, prefix="/api/v1", tags=["Scanning"])
app.include_router(terminal_router, tags=["Web Terminal"])

# Vendored xterm.js for /terminal — no CDN, works offline.
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")), name="static")