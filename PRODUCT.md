# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Students learning web security and practitioners running authorized scans. Both run scans in terminal/lab environments and need guided, low-friction operation.

## Product Purpose

WebVAPT-toolkit is an automated web application security scanner: crawl target → run 30+ checks across 7 categories (OWASP Top 10) → AI-enrich HIGH/CRITICAL findings with CVSS, attack scenarios, and fixes → persist to SQLite → present via dashboard/API/reports. Success is a complete, understandable scan a beginner can run and act on.

## Positioning

Single-command scan pipeline with built-in AI remediation (CVSS + fix code + executive risk score 0-100), response caching, concurrent checks, and MD5 dedup — aimed at learning and quick assessments, not enterprise continuous monitoring.

## Operating Context

Terminal-first workflows: API server (`uvicorn main:app`) plus terminaltui TUI (`cd terminal-tui && npm run dev`) on a separate URL, and `python scan.py` for quick CLI scans. Local SQLite (`data/scans.db`), JSON/TXT reports (`data/reports/`). Authorized testing only.

## Capabilities and Constraints

Confirmed: `scanner/engine.py run_scan(target_url, on_progress, run_ai, max_pages, max_workers)` deep module; `ScanRequest` seam (`enable_ai`, `max_pages`) shared by UI/backend with `.env` defaults (`ENABLE_AI_ANALYSIS`, `MAX_PAGES_TO_CRAWL`); 7 check modules; site-wide dedup by hostname; AI via single OpenAI provider (`ai/providers/openai_provider.py`); SSRF guard (`config.is_ssrf_safe`, `ALLOW_PRIVATE_TARGETS`); severity order CRITICAL→INFO.
Undecided: none material for TUI scope.

## Brand Commitments

Name: WebVAPT-toolkit / WebPenTest AI. Binding visual constraint volunteered by user: black-and-white terminal TUI. Keep existing severity semantics and finding data (vuln_type, severity, CVSS, evidence, remediation, CWE/OWASP/MITRE refs).

## Evidence on Hand

Runnable code: `scanner/`, `ai/`, `api/database.py`, `reports/report_writer.py`, `config.py`, `scan.py`, `app.py` + `ui/`. No invented testimonials, benchmarks, or pricing.

## Product Principles

1. Easy over exhaustive: a beginner completes a scan without docs.
2. Truth in terminal: findings, evidence, and risk are always inspectable as plain text.
3. One pipeline, many surfaces: TUI calls the same `run_scan()` engine through the API (`ScanRequest` seam), no parallel logic.
4. Safe by default: SSRF guard and authorized-use warning are never hidden.
5. Monochrome clarity: hierarchy from layout and weight, not hue.
