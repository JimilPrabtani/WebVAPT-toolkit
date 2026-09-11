# 🔐 WebPenTest AI Toolkit

> Automated web application penetration testing with AI-powered vulnerability analysis.  
> Built for OWASP Top 10 coverage. Single AI provider. Production-ready API. Black-and-white terminal UI, in your terminal or in a browser.

![Version](https://img.shields.io/badge/Version-1.3-blue)
![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Textual](https://img.shields.io/badge/Textual-TUI-lightgrey)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 What It Does

**WebPenTest AI Toolkit** is an automated web application security scanner that:

1. **Crawls** a target web application and builds a complete map of its pages
2. **Scans** every page concurrently across 7 vulnerability categories (30+ checks)
3. **Sends** HIGH/CRITICAL findings to an AI provider for deep analysis, CVSS scoring, and fix generation
4. **Stores** everything in a local SQLite database and presents it through the terminal UI

```
Target URL → Crawl → Concurrent Checks → AI Analysis → SQLite → TUI / API / Report
```

You can use it three ways:

| Mode | Entry Point | Best For |
|---|---|---|
| **Terminal** | `python tui.py` (Textual, black-and-white) | Interactive use, labs, demos over SSH |
| **Web terminal** | `uvicorn main:app` → open `/terminal` | Hosted use — same TUI in a browser tab |
| **API** | `main.py` (FastAPI) | CI/CD pipelines, automation, integrations |
| **CLI** | `scan.py` | Quick terminal scans, scripting |

> ⚠️ **Authorized testing only.** Only scan applications you own or have written permission to test.

---

## 🆕 What's New

- **Terminal UI is the interface** — the Streamlit dashboard (`app.py` + `ui/`) is deleted. `python tui.py` (Textual, black-and-white) is the primary UI: Scan / Results / History / Help tabs, keys `1-4`, `Q` quits.
- **Web terminal** — `uvicorn main:app` → open `/terminal`: the same TUI in a browser tab (xterm.js, vendored locally, works offline). One private `tui.py` session per tab over WebSocket.
- **Single AI provider** — the multi-provider factory (Gemini/Anthropic/Ollama adapters) is deleted. One OpenAI-compatible endpoint (`OPENAI_API_KEY` + `CUSTOM_AI_BASE_URL` + `AI_MODEL`), batched into 2 calls per scan.
- **Dead weight removed** — `slowapi`, `google-generativeai`, `anthropic`, `streamlit` gone from requirements; stale tests repointed so the suite is fully green.
- **Typing-safe shortcuts** — `1-4`/`Q` yield while focus is in an input field, so typing a URL never switches tabs or quits.

---

## ✨ Feature Overview

### Vulnerability Categories

| Category | Checks |
|---|---|
| **Security Headers** | CSP · HSTS · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy · CORS wildcard |
| **Injection** | Reflected XSS (URL params) · DOM-based XSS sinks · Form surfaces · SQL injection (error-based + boolean-blind) · SSTI (Jinja2, FreeMarker, Mako, Velocity) |
| **Sensitive Exposure** | 25+ paths: `.env` · `wp-config.php` · `.git` · `db.sql` · backup archives · admin panels · log files |
| **Transport Security** | HTTPS enforcement · TLS cert expiry · Weak protocols (TLS 1.0/1.1) · Self-signed cert detection |
| **Secrets in Responses** | AWS keys · GitHub PATs · OpenAI keys · Stripe keys · Slack tokens · DB connection strings · JWTs · Private keys |
| **Open Redirect** | URL parameter redirect hijacking (11 common param names checked) |
| **Misconfiguration** | Directory listing · Cookie flags (HttpOnly, Secure, SameSite) · Server version disclosure |

### AI Layer

- **Single provider**: any OpenAI-compatible endpoint (`OPENAI_API_KEY` + `CUSTOM_AI_BASE_URL` + `AI_MODEL` in `.env`)
- **Batched calls**: all priority findings in ONE call + one executive-summary call (2 total per scan, no rate-limit storms)
- **Per-finding**: CVSS 3.1 score · confidence · attack scenario · remediation steps · secure code example · references
- **Executive summary**: risk score 0–100 · key risks · immediate actions · positive observations
- **Quota-aware**: only CRITICAL/HIGH/MEDIUM go to AI — INFO/LOW stay local

### Performance

- **Response caching**: pages fetched once, reused across all check modules (~50% fewer HTTP requests)
- **Concurrent scanning**: 4 worker threads run all check modules in parallel (~4x faster)
- **Deduplication**: MD5-fingerprinted findings — no duplicate alerts

---

## 🏗️ Architecture

```
webpentest/
├── scan.py                    # CLI entry point
├── tui.py                     # Terminal UI entry point (Textual, black-and-white)
├── main.py                    # FastAPI server entry point
├── config.py                  # Central config (env vars, SSRF guard, timeouts)
├── requirements.txt
│
├── tui/
│   ├── app.py                 # Textual app — Scan / Results / History / Help tabs
│   ├── backend.py             # Adapter: run_scan() + SQLite + report writer
│   └── theme.tcss             # Monochrome theme (black ground, white ink)
│
├── scanner/
│   ├── engine.py              # Scan orchestrator — pipeline + thread pool controller
│   ├── fetcher.py             # HTTP client + BFS crawler + response cache
│   ├── models.py              # Finding and ScanResult dataclasses
│   ├── header_checks.py       # HTTP security header analysis
│   ├── xss_checks.py          # XSS: reflected, DOM sinks, form surfaces
│   ├── sqli_checks.py         # SQLi: error-based, boolean-blind, form surfaces
│   ├── misc_checks.py         # Sensitive paths, HTTPS, open redirect, dir listing
│   ├── ssti_checks.py         # Server-Side Template Injection (6 engine probes)
│   ├── secrets_checks.py      # Secret / credential leak detection (14 patterns)
│   └── tls_checks.py          # TLS certificate and protocol checks
│
├── ai/
│   ├── AI_analyzer.py         # AI orchestration (batched analysis + executive summary)
│   ├── prompts.py             # Prompt templates
│   └── providers/
│       ├── base.py            # AIProvider interface + error types
│       └── openai_provider.py # Single OpenAI-compatible provider
│
├── api/
│   ├── routes.py              # All FastAPI HTTP endpoints (7 routes)
│   ├── terminal.py            # Web terminal: /terminal page + /ws/terminal sessions
│   ├── database.py            # SQLite persistence layer
│   └── schemas.py             # Pydantic v2 request/response models
│
├── web/
│   ├── terminal.html          # xterm.js page hosting the TUI in a browser
│   └── static/                # Vendored xterm.js (no CDN, works offline)
│
├── reports/
│   └── report_writer.py       # JSON + TXT report generation
│
├── data/
│   ├── scans.db               # SQLite database (auto-created)
│   └── reports/               # Generated .json and .txt reports
│
└── tests/
    ├── test_refactored.py     # Scanner + AI + integration tests
    ├── test_tui.py            # Headless Textual Pilot tests
    └── test_web_terminal.py   # /terminal page + live WebSocket TUI boot
```

### Scan Pipeline — Step by Step

```
Step 1: CRAWL
  fetcher.crawl() — BFS from start URL, stays within same domain
  Collects (url, response) pairs up to MAX_PAGES_TO_CRAWL
  All responses cached in _response_cache

Step 2: CONCURRENT SCAN  (ThreadPoolExecutor, 4 workers default)
  engine._scan_page() runs per URL simultaneously:
  ├─ header_checks    → analyses security response headers
  ├─ xss_checks       → injects XSS probes into URL params; scans DOM sinks
  ├─ sqli_checks      → injects SQL metacharacters; compares boolean responses
  ├─ misc_checks      → probes 25+ sensitive paths; checks HTTPS; open redirects
  ├─ ssti_checks      → injects math payloads ({{7*7}} → 49 = confirmed SSTI)
  ├─ secrets_checks   → regex-scans response body for 14 credential patterns
  └─ tls_checks       → SSL cert expiry + protocol check (runs once per host only)

Step 3: DEDUPLICATE
  MD5-fingerprint each finding (vuln_type + url + evidence hash)
  Identical findings from concurrent threads are dropped

Step 4: AI ANALYSIS
  analyze_scan() sends CRITICAL/HIGH/MEDIUM findings to the AI in ONE batched call
  Per finding: CVSS, confidence, attack scenario, fix steps, code example
  Then one executive-summary call: risk score, key risks, immediate actions

Step 5: PERSIST
  SQLite — saves scan record + all findings to scans.db

Step 6: REPORT
  Generates .json + .txt files in data/reports/
```

---

## 🚀 Quick Start

### 1. Install

```bash
git clone <repo-url>
cd webpentest

python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate           # Linux/macOS

.\.venv\Scripts\python -m pip install -r requirements.txt
```

### 2. Configure

Create a `.env` file in the project root (never commit it — it's gitignored):

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_key_here
CUSTOM_AI_BASE_URL=https://openrouter.ai/api/v1/
AI_MODEL=thinkingmachines/inkling-small:free
ENABLE_AI_ANALYSIS=true
SCAN_TIMEOUT=10
MAX_PAGES_TO_CRAWL=20
ALLOW_PRIVATE_TARGETS=true
ALLOW_INSECURE_TLS=true
API_KEY=any_random_string_for_api_auth
EXPOSE_DOCS=false
```

### 3. Run

**Terminal TUI (no server needed):**
```bash
python tui.py           # black-and-white TUI — keys 1-4 switch tabs, Q quits
python tui.py --check   # headless smoke check (no TTY needed)
```

**Web terminal (same TUI in a browser):**
```bash
uvicorn main:app --port 8000
# Open: http://localhost:8000/terminal
```
Each browser tab gets a private TUI session running `tui.py` server-side.
Bind to `127.0.0.1` by default; put authentication (reverse proxy / VPN)
in front before exposing to a network — a visitor gets a working scanner.

**CLI:**
```bash
python scan.py https://target.com
python scan.py https://target.com --no-ai   # skip AI (no API key needed)
```

**API only:**
```bash
uvicorn main:app --reload --port 8000
# Interactive docs only when EXPOSE_DOCS=true in .env
```

---

## 🌐 API Reference

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Start a scan — returns `scan_id` immediately |
| `GET` | `/scan/{id}` | Full results + findings |
| `GET` | `/scan/{id}/status` | Lightweight poll (use while scan is running) |
| `GET` | `/history` | All past scans |
| `GET` | `/history/target/{url}` | Trend analysis for one target |
| `GET` | `/stats` | Aggregate statistics |
| `DELETE` | `/scan/{id}` | Delete a scan + all its findings |

```bash
# Start scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://target.com", "enable_ai": true, "max_pages": 20}'

# Poll status
curl http://localhost:8000/api/v1/scan/{scan_id}/status

# With API key auth
curl -H "X-API-Key: your_key" http://localhost:8000/api/v1/history
```

---

## 🖥️ TUI Guide

Keys `1-4` switch tabs, `Tab` moves focus, `Enter` activates, `Q` quits.
Shortcuts yield while you're typing in a field, so entering a URL never
switches tabs or quits. In the browser terminal, `Ctrl +` / `Ctrl -` zoom
the text, `Ctrl 0` resets it.

### Scan Tab
Enter a URL, toggle AI on/off, set page depth, hit **START SCAN**. The live
log streams progress; results open automatically on completion.

### History Tab
- **Open** — load a past scan into Results
- **Delete** — two-step confirmation
- Reports are also saved as JSON + TXT under `data/reports/`

### Results Tab
Summary (risk score, severity counts, executive summary) plus a findings
table with category and AI-verified filters. Select a row for full detail:
evidence plus AI-generated remediation with code examples.

---

## 🧪 Testing

```bash
pytest tests/ -v
pytest tests/test_refactored.py --cov=scanner --cov=ai --cov-report=html
```

### OWASP Juice Shop Scorecard

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python scan.py http://localhost:3000
```

| Vulnerability | Status |
|---|---|
| CORS wildcard | ✅ |
| Missing CSP | ✅ |
| Missing HSTS | ✅ |
| Missing Referrer-Policy | ✅ |
| Missing Permissions-Policy | ✅ |
| Insecure HTTP | ✅ |
| `robots.txt` disclosure | ✅ |
| Exposed `/admin` | ✅ |
| Cookie flag issues | ✅ |
| DOM XSS (JS rendering) | ⚠️ Partial — Playwright planned |
| JWT alg:none bypass | ❌ Roadmap |

---

## 🔒 Security Design

| Concern | Implementation |
|---|---|
| SSRF prevention | Resolves hostnames and blocks private/loopback IPs before scanning |
| API authentication | `X-API-Key` header middleware |
| Input validation | Pydantic v2 on all API bodies; UUID4 validation on scan IDs |
| Secret redaction | Evidence shows only first 6 + last 4 chars of matched secrets |

---

## 🗺️ Roadmap

| Priority | Feature |
|---|---|
| P1 | PDF report export |
| P1 | Playwright-based JS/SPA crawling |
| P2 | Authenticated scanning (session cookie / Bearer token) |
| P2 | CVE correlation via NVD API |
| P3 | PostgreSQL migration + Docker |
| P4 | React + TypeScript frontend |

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| HTTP scanning | `requests` · `BeautifulSoup4` |
| API server | FastAPI 0.111 + Uvicorn |
| Database | SQLite (`sqlite3`) |
| Data validation | Pydantic v2 |
| Terminal UI | Textual |
| AI provider | OpenAI-compatible endpoint (`openai` package) |
| Web terminal backend | pywinpty (ConPTY, Windows) |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Testing | Pytest + pytest-asyncio |

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**.  
Always obtain **written permission** before scanning any target.  
Unauthorized scanning may violate CFAA, the UK Computer Misuse Act, or equivalent laws in your jurisdiction.  
The authors accept no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built by Team Web-Sentinels · Karnavati University · Hackathon 2026*  
*Jimil Prabtani (ProSec India) + 4 team members*
