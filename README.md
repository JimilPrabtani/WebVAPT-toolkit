# 🔐 WebPenTest AI Toolkit

> Automated web application penetration testing with AI-powered vulnerability analysis.  
> Built for OWASP Top 10 coverage. Multi-provider AI. Production-ready API. Real-time dashboard.

![Version](https://img.shields.io/badge/Version-1.3-blue)
![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35-red?logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 What It Does

**WebPenTest AI Toolkit** is an automated web application security scanner that:

1. **Crawls** a target web application and builds a complete map of its pages
2. **Scans** every page concurrently across 7 vulnerability categories (30+ checks)
3. **Sends** HIGH/CRITICAL findings to an AI provider for deep analysis, CVSS scoring, and fix generation
4. **Stores** everything in a local SQLite database and presents it through a real-time dashboard

```
Target URL → Crawl → Concurrent Checks → AI Analysis → SQLite → Dashboard / API / Report
```

You can use it three ways:

| Mode | Entry Point | Best For |
|---|---|---|
| **Dashboard** | `app.py` (Streamlit) | Interactive use, demos, presentations |
| **API** | `main.py` (FastAPI) | CI/CD pipelines, automation, integrations |
| **CLI** | `scan.py` | Quick terminal scans, scripting |

> ⚠️ **Authorized testing only.** Only scan applications you own or have written permission to test.

---

## 🆕 What's New in v1.3

- **Bug fix: Critical syntax error in scan engine** — garbled function call in `engine.py` that crashed AI analysis on every scan
- **Bug fix: TLS race condition** — TLS checks were running on every page in parallel instead of once per host, causing duplicate findings
- **Bug fix: Fake AI model names** — corrected `provider_factory.py` defaults to real model IDs (`gemini-2.0-flash`, `gpt-4o`, `claude-sonnet-4-6`)
- **History tab rebuilt** — full inline report viewer, read every finding directly in the dashboard without downloading anything
- **Delete scans** — two-step confirmation delete with automatic sidebar stat refresh
- **Provider-agnostic UI** — all user-facing text now says "AI Analysis" instead of hardcoding Gemini
- **XSS safety in History tab** — target URLs HTML-escaped before rendering

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

- **Multi-provider**: Gemini · OpenAI · Anthropic · Ollama · any OpenAI-compatible endpoint
- **Fallback chain**: if primary fails, automatically tries the next provider
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
├── main.py                    # FastAPI server entry point
├── app.py                     # Streamlit dashboard
├── config.py                  # Central config (env vars, SSRF guard, timeouts)
├── requirements.txt
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
│   ├── AI_analyzer.py         # AI orchestration (per-finding + executive summary)
│   ├── provider_factory.py    # Provider selection + fallback chain builder
│   ├── prompts.py             # Prompt templates
│   └── providers/
│       ├── base.py            # Abstract AIProvider interface
│       ├── gemini_provider.py
│       ├── openai_provider.py
│       ├── anthropic_provider.py
│       └── ollama_provider.py
│
├── api/
│   ├── routes.py              # All FastAPI HTTP endpoints (7 routes)
│   ├── database.py            # SQLite persistence layer
│   ├── schemas.py             # Pydantic v2 request/response models
│   └── limiter.py             # Rate limiter (10 scans/min/IP)
│
├── reports/
│   └── report_writer.py       # JSON + TXT report generation
│
├── data/
│   ├── scans.db               # SQLite database (auto-created)
│   └── reports/               # Generated .json and .txt reports
│
└── tests/
    └── test_refactored.py     # Pytest suite (30+ tests)
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
  analyze_scan() sends CRITICAL/HIGH/MEDIUM findings to AI provider
  Per finding: CVSS, confidence, attack scenario, fix steps, code example
  Falls back to next provider automatically if primary fails
  Generates executive summary: risk score, key risks, immediate actions

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

python -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\Activate.ps1       # Windows PowerShell

pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
```

Minimum `.env`:

```env
AI_PROVIDER=gemini
GEMINI_API_KEY=your_key_here
ENABLE_AI_ANALYSIS=true
SCAN_TIMEOUT=10
MAX_PAGES_TO_CRAWL=20
ALLOW_PRIVATE_TARGETS=true
```

### 3. Run

**Dashboard:**
```bash
# Terminal 1
uvicorn main:app --reload --port 8000

# Terminal 2
streamlit run app.py
# Open: http://localhost:8501
```

**CLI:**
```bash
python scan.py https://target.com
python scan.py https://target.com --no-ai   # skip AI (no API key needed)
```

**API only:**
```bash
uvicorn main:app --reload --port 8000
# Swagger UI: http://localhost:8000/docs
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

## 🖥️ Dashboard Guide

### New Scan Tab
Enter a URL, toggle AI on/off, set page depth, hit **⚡ Scan**. Results appear inline.

### History Tab
- **📄 View** — full report inline, no download needed
- **⬇ JSON** — optional export
- **🗑 Delete** — two-step confirmation
- **← Back** — return to the list

### Finding Cards
Each finding shows: severity badge · CVSS score · CWE + OWASP + MITRE ATT&CK badges · evidence · full AI-generated remediation with code examples.

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
| Rate limiting | `slowapi` — 10 scan requests/min/IP |
| XSS in dashboard | All user-controlled strings `html.escape()`'d before rendering |
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
| Rate limiting | slowapi |
| Database | SQLite (`sqlite3`) |
| Data validation | Pydantic v2 |
| Dashboard | Streamlit 1.35 |
| AI providers | Gemini · OpenAI · Anthropic · Ollama |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| Testing | Pytest 8.2 |

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
