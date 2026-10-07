# WebPenTest AI Toolkit

Automated web security scanner: crawl a target → run 40+ checks across 12 categories (OWASP Top 10 + LLM Top 10) → AI grades HIGH/CRITICAL findings with CVSS + fixes + prevention → link findings into evidenced attack chains → save to SQLite → read it in the terminal UI.

> Authorized testing only. Scan targets you own or have written permission to test.

## Features

- **40 checks across 12 categories** (OWASP Top 10 + LLM Top 10): headers, XSS, SQLi (error/boolean/time-based), path traversal, active form testing + CSRF, LLM endpoint/model/key exposure, Nuclei-style JSON templates, OSV supply-chain lookup, sensitive paths, SSTI, secrets, TLS, open redirect, JWT.
- **AI enrichment with free-model failover**: chunked calls grade CRITICAL/HIGH/MEDIUM (CVSS, attack scenario, fix, systemic prevention); `AI_MODEL` is a fallback chain, dead models are skipped automatically.
- **Evidenced attack chains**: findings linked into recon → exploit → impact paths for pentest reports.
- **Three ways to run**: terminal UI, REST API, one-off CLI. `--no-ai` scans still get heuristic risk scores + static prevention guidance.
- **ASCII severity** (`[!!] [!] [*] [.] [i]`), SSRF guard, SQLite + JSON/TXT reports.

Prerequisites: Python 3.11+, Node 22+. Docker only needed for the Juice Shop test target below.

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
python scan.py http://localhost:3000 --all   # crawl up to CRAWL_HARD_CAP (200) pages
```

## Folder map

```
.
├── main.py            # FastAPI server (the scan engine API)
├── scan.py            # CLI entry point
├── config.py          # env vars, SSRF guard, timeouts
├── scanner/           # crawl + 12 check modules + engine (run_scan)
│   └── templates/     # Nuclei-style declarative JSON probes (no code needed)
├── scripts/           # helper scripts (benchmark_free_models.py)
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
SCAN ── workers run all check modules per page (site-wide ones run once):
│  headers · xss · sqli (error/boolean/time) · traversal · forms+csrf ·
│  llm (OWASP LLM Top 10) · templates (Nuclei-style JSON) · osv (JS supply chain) ·
│  sensitive-paths · ssti · secrets · tls/open-redirect
  │
  ▼
DEDUP ── MD5 fingerprint per finding, drops duplicates
  │
  ▼
AI ── CRITICAL/HIGH/MEDIUM in chunked batch calls (CVSS + attack scenario + fix +
│     systemic prevention), plus one executive-summary call (risk score 0–100).
│     Granularity is yours: AI_BATCH_SIZE=25 (default) or 1 for one call per finding.
│     Skipped with --no-ai (deterministic heuristic score + static prevention instead).
│     AI_MODEL is a comma-separated fallback chain of OpenRouter free models —
│     dead/rate-limited models are skipped automatically.
│     Re-benchmark with `python scripts/benchmark_free_models.py`.
   │
   ▼
CHAINS ── findings linked into evidenced exploitation paths
│     (recon → exploit → impact, e.g. XSS + missing HttpOnly → session hijack)
   │
  ▼
SAVE ── SQLite (data/scans.db) + JSON/TXT (data/reports/)
  │
  ▼
READ ── TUI pages (live status poll → results), API, or CLI output
```

Severity is ASCII text (`[!!] [!] [*] [.] [i]`), never color. SSRF guard blocks private/internal targets unless `ALLOW_PRIVATE_TARGETS=true`.

## Reference-tool parity

Capabilities adopted from industry scanners (web-applicable ones implemented;
host/container/infra auditing stays out of scope for a web VAPT tool):

| Reference | Adopted as |
|---|---|
| Nuclei (templates) | `scanner/templates/*.json` declarative probes — add detections without code (`scanner/template_checks.py`) |
| OSV-Scanner (supply chain) | `scanner/osv_checks.py` — JS lib versions resolved against api.osv.dev |
| OWASP ZAP (spider + active + passive) | BFS crawler + SPA discovery, active injection probes, passive header/secret/JWT analysis |
| OpenVAS / Trivy / Lynis | Out of scope (network-infra, container/image, host-hardening domains) |

## API

Base URL: `http://localhost:8000/api/v1` (send `X-API-Key` when `API_KEY` is set in `.env`)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Start a scan — returns `scan_id` immediately |
| `GET` | `/scan/{id}/status` | Lightweight poll while running |
| `GET` | `/scan/{id}` | Full results + findings |
| `GET` | `/history` | Past scans |
| `GET` | `/history/target/{url}` | All scans for one target (trend) |
| `GET` | `/stats` | Aggregate statistics |
| `DELETE` | `/scan/{id}` | Delete a scan + findings |

## Testing

```bash
pytest tests/ -v
cd terminal-tui && npm test && npm run typecheck && npm run build
```

Live check: `docker run -d -p 3000:3000 bkimminich/juice-shop`, then `python scan.py http://localhost:3000`.
Local/docker targets need `ALLOW_PRIVATE_TARGETS=true` in `.env` (SSRF guard blocks them otherwise).

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
