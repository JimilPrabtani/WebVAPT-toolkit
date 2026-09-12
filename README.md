# WebPenTest AI Toolkit

Automated web security scanner: crawl a target → run 30+ checks across 7 categories (OWASP Top 10) → AI grades HIGH/CRITICAL findings with CVSS + fixes → save to SQLite → read it in the terminal UI.

> Authorized testing only. Scan targets you own or have written permission to test.

## Latest changes

- **TUI is now terminaltui** (`terminal-tui/`, Node): the old Textual TUI, xterm.js web terminal, and their Python deps are deleted.
- **Split URLs**: API on `http://127.0.0.1:8000/api/v1`, TUI runs separately and calls it over HTTP. No API key config needed locally — the TUI falls back to `API_KEY` in the root `.env` (401s name the fix on-screen).
- **Scan form has a START SCAN button** and navigates to a live status page on submit.
- **Repo cleaned**: `__pycache__`, `.pytest_cache`, `.ruff_cache`, draft review files, and stale `DESIGN.md` removed.

## Quick start

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # Windows  |  source .venv/bin/activate  # macOS/Linux
.\.venv\Scripts\python -m pip install -r requirements.txt
# create .env in the root (gitignored): OPENAI_API_KEY, API_KEY, MAX_PAGES_TO_CRAWL=20, ...
```

Terminal 1 — API (the scan engine):

```bash
uvicorn main:app --port 8000
```

Terminal 2 — TUI (thin client over the API):

```bash
cd terminal-tui && npm install && npm run dev
```

Or skip the servers — one-off CLI scan:

```bash
python scan.py https://target.com --no-ai
```

## Folder map

```
.
├── main.py            # FastAPI server (the scan engine API)
├── scan.py            # CLI entry point
├── config.py          # env vars, SSRF guard, timeouts
├── scanner/           # crawl + 7 check modules + engine (run_scan)
├── ai/                # batched AI analysis (CVSS, fixes, risk score)
├── api/               # routes, SQLite layer, request/response schemas
├── reports/           # JSON + TXT report writer
├── data/              # scans.db + generated reports (gitignored)
├── tests/             # pytest suite
└── terminal-tui/      # terminal UI (Node, terminaltui)
    ├── config.ts      # monochrome theme (black ground, white ink)
    ├── lib/api.ts     # API client + report formatting
    ├── pages/         # home, scan, scan/[id], results, history, help
    └── tests/         # node:test suite
```

## How the tool works

```
Target URL
  │  POST /scan {target_url, enable_ai, max_pages}
  ▼
CRAWL ── BFS walk of the target domain (up to MAX_PAGES_TO_CRAWL), responses cached
  │
  ▼
SCAN ── 4 workers run all check modules per page:
│  headers · xss · sqli · sensitive-paths · ssti · secrets · tls/open-redirect
  │
  ▼
DEDUP ── MD5 fingerprint per finding, drops duplicates
  │
  ▼
AI ── CRITICAL/HIGH/MEDIUM in ONE batched call (CVSS + attack scenario + fix),
│     plus one executive-summary call (risk score 0–100). Skipped with --no-ai.
  │
  ▼
SAVE ── SQLite (data/scans.db) + JSON/TXT (data/reports/)
  │
  ▼
READ ── TUI pages (live status poll → results), API, or CLI output
```

Severity is ASCII text (`[!!] [!] [*] [.] [i]`), never color. SSRF guard blocks private/internal targets unless `ALLOW_PRIVATE_TARGETS=true`.

## API

Base URL: `http://localhost:8000/api/v1` (send `X-API-Key` when `API_KEY` is set in `.env`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Start a scan — returns `scan_id` immediately |
| `GET` | `/scan/{id}/status` | Lightweight poll while running |
| `GET` | `/scan/{id}` | Full results + findings |
| `GET` | `/history` | Past scans |
| `GET` | `/stats` | Aggregate statistics |
| `DELETE` | `/scan/{id}` | Delete a scan + findings |

## Testing

```bash
pytest tests/ -v
cd terminal-tui && npm test && npm run typecheck && npm run build
```

Live check: `docker run -d -p 3000:3000 bkimminich/juice-shop`, then `python scan.py http://localhost:3000`.

## Docs (all at repo root)

- [PRODUCT.md](PRODUCT.md) — what the tool is for
- [CONTEXT.md](CONTEXT.md) — domain vocabulary
- [terminal-tui/README.md](terminal-tui/README.md) — TUI setup + split-URL config
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — conduct rules

## Legal

Authorized security testing only. Unauthorized scanning may violate CFAA, the UK Computer Misuse Act, or equivalent laws. MIT License — see [LICENSE](LICENSE).

*Built by Team Web-Sentinels · Karnavati University · Hackathon 2026*
