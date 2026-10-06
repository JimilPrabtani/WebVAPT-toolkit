// Shared client for the Python FastAPI scan engine.
// API lives on its own URL (default http://127.0.0.1:8000/api/v1),
// separate from the terminaltui local server. Override with:
//   WEBVAPT_API_URL=http://host:8000/api/v1
//   WEBVAPT_API_KEY=...  (matches API_KEY in .env when set)
//
// Auth resolution order (first hit wins):
//   1. process.env.WEBVAPT_API_KEY (shell export, or terminal-tui/.env which
//      the terminaltui runtime auto-loads when cwd is terminal-tui/)
//   2. WEBVAPT_API_KEY inside terminal-tui/.env (found via module path,
//      so `npx webvapt-tui` works from any cwd)
//   3. API_KEY inside the project-root .env (same repo, zero-config locally)

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

let _envCache: Record<string, string> | null = null;

function parseEnvFile(content: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#") || !t.includes("=")) continue;
    const eq = t.indexOf("=");
    let v = t.slice(eq + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[t.slice(0, eq).trim()] = v;
  }
  return out;
}

function localEnv(): Record<string, string> {
  if (_envCache) return _envCache;
  _envCache = {};
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // lib/api.ts -> terminal-tui/.env ; dist/cli.js -> terminal-tui/.env
    // lib/api.ts -> project-root .env ; dist/cli.js -> project-root .env
    // Least-specific first so terminal-tui/.env overrides the root .env.
    for (const p of [resolve(here, "../../.env"), resolve(here, "../.env")]) {
      if (!existsSync(p)) continue;
      Object.assign(_envCache, parseEnvFile(readFileSync(p, "utf-8")));
    }
  } catch {
    // Filesystem unavailable — fall back to process.env only.
  }
  return _envCache;
}

export function apiBase(): string {
  const raw =
    (typeof process !== "undefined" && process.env?.WEBVAPT_API_URL) ||
    localEnv().WEBVAPT_API_URL ||
    "http://127.0.0.1:8000/api/v1";
  return raw.replace(/\/+$/, "");
}

export function apiKey(): string {
  if (typeof process !== "undefined" && process.env?.WEBVAPT_API_KEY) {
    return process.env.WEBVAPT_API_KEY;
  }
  const local = localEnv();
  return local.WEBVAPT_API_KEY || local.API_KEY || "";
}

export function apiHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json", ...extra };
  const key = apiKey();
  if (key) h["X-API-Key"] = key;
  return h;
}

export interface ScanSummary {
  id: string;
  target_url: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
  duration_secs?: number | null;
  pages_crawled?: number | null;
  total_findings?: number | null;
  risk_score?: number | null;
  overall_risk?: string | null;
  error?: string | null;
}

export interface Finding {
  id: string;
  vuln_type: string;
  severity: string;
  url: string;
  detail?: string | null;
  evidence?: string | null;
  remediation?: string | null;
  ai_verified?: number | null;
  cvss_score?: number | null;
  owasp_id?: string | null;
  cwe_id?: string | null;
  sans_rank?: string | null;
  cve_ids?: string[] | null;
  created_at: string;
}

export interface ScanDetail extends ScanSummary {
  summary_json?: Record<string, unknown> | null;
  exec_summary?: Record<string, unknown> | null;
  findings: Finding[];
}

export function severityTag(sev: string): string {
  // ASCII markers — port of tui/backend.py::severity_tag (no colour, no emoji).
  const m: Record<string, string> = {
    CRITICAL: "[!!]",
    HIGH: "[! ]",
    MEDIUM: "[* ]",
    LOW: "[. ]",
    INFO: "[i ]",
  };
  return m[sev] ?? "[? ]";
}

export function findingRow(f: Finding): string[] {
  const cvss = f.cvss_score == null ? "-" : Number(f.cvss_score).toFixed(1);
  const ai = f.ai_verified === 1 ? "YES" : f.ai_verified === 0 ? "NO" : "-";
  return [severityTag(f.severity) + " " + f.severity, f.vuln_type, (f.url || "").slice(0, 60), cvss, ai];
}

export function summaryText(scan: ScanDetail): string {
  const s = (scan.summary_json ?? {}) as {
    by_severity?: Record<string, number>;
    by_category?: Record<string, number>;
    by_owasp?: Record<string, number>;
    top_urls?: { url: string; findings: number }[];
    coverage?: {
      params_tested?: number;
      forms_found?: number;
      forms_submitted?: number;
      api_endpoints_probed?: number;
    };
  };
  const bySev = s.by_severity ?? {};
  const es = (scan.exec_summary ?? {}) as { executive_summary?: string; immediate_actions?: string[]; source?: string; ai_error?: string };
  const lines = [
    `Target   : ${scan.target_url}`,
    `Status   : ${scan.status}   Pages: ${scan.pages_crawled ?? 0}   Duration: ${Math.round(scan.duration_secs ?? 0)}s`,
    `Risk     : ${scan.overall_risk ?? "N/A"} (${scan.risk_score ?? "?"}//100)${es.source === "heuristic" ? " [heuristic]" : ""}   Findings: ${scan.total_findings ?? 0}`,
    "",
    "BY SEVERITY",
  ];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
    const n = bySev[sev] ?? 0;
    lines.push(`  ${severityTag(sev)} ${sev.padEnd(8)} ${String(n).padStart(3)}  ${"#".repeat(Math.min(n, 40))}`);
  }
  if (s.by_category && Object.keys(s.by_category).length) {
    lines.push("", "BY CATEGORY");
    for (const [cat, n] of Object.entries(s.by_category).sort((a, b) => b[1] - a[1])) {
      lines.push(`  ${cat} : ${n}`);
    }
  }
  if (s.by_owasp && Object.keys(s.by_owasp).length) {
    lines.push("", "OWASP TOP 10");
    for (const [id, n] of Object.entries(s.by_owasp).sort()) {
      lines.push(`  ${id} : ${n}`);
    }
  }
  if (s.top_urls?.length) {
    lines.push("", "TOP AFFECTED URLS");
    s.top_urls.slice(0, 5).forEach((t, i) => lines.push(`  ${i + 1}. [${t.findings}] ${(t.url || "").slice(0, 80)}`));
  }
  const chains = (s as { attack_chains?: { title: string; severity: string; impact: string }[] }).attack_chains ?? [];
  if (chains.length) {
    lines.push("", "ATTACK CHAINS");
    chains.slice(0, 3).forEach((c, i) => lines.push(`  ${i + 1}. [${c.severity}] ${c.title} — ${c.impact}`));
  }
  if (s.coverage && (s.coverage.params_tested != null || s.coverage.forms_found != null)) {
    const c = s.coverage;
    lines.push(
      "",
      "COVERAGE",
      `  Params tested: ${c.params_tested ?? "?"}   Forms: ${c.forms_found ?? "?"} found / ${c.forms_submitted ?? "?"} submitted   API endpoints: ${c.api_endpoints_probed ?? "?"}`
    );
  }
  if (es.ai_error) lines.push("", "AI ANALYSIS FAILED", "-".repeat(40), String(es.ai_error).slice(0, 300), "Fix AI_MODEL / key in .env, then re-run the scan.");
  if (es.executive_summary) lines.push("", "EXECUTIVE SUMMARY", "-".repeat(40), String(es.executive_summary).slice(0, 2000));
  if (es.immediate_actions?.length) {
    lines.push("", "IMMEDIATE ACTIONS");
    es.immediate_actions.slice(0, 8).forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
  }
  return lines.join("\n");
}

export function findingDetailText(f: Finding): string {
  const lines = [
    `${severityTag(f.severity)} ${f.vuln_type}`,
    `Severity : ${f.severity}` + (f.cvss_score != null ? `  CVSS ${Number(f.cvss_score).toFixed(1)}` : ""),
    `URL      : ${f.url}`,
  ];
  if (f.detail) lines.push("", "WHAT WAS FOUND", "-".repeat(40), f.detail);
  if (f.evidence) lines.push("", "EVIDENCE", "-".repeat(40), String(f.evidence).slice(0, 2000));
  const mapping = [
    f.owasp_id ? `OWASP: ${f.owasp_id}` : null,
    f.cwe_id ? `CWE: ${f.cwe_id}` : null,
    f.sans_rank ? `SANS: ${f.sans_rank}` : null,
  ].filter(Boolean);
  if (mapping.length) lines.push("", "CLASSIFICATION", "-".repeat(40), mapping.join("   "));
  if (f.cve_ids && f.cve_ids.length) {
    lines.push("", "CVEs", "-".repeat(40));
    for (const c of f.cve_ids.slice(0, 10)) lines.push(`  - ${c}  (https://nvd.nist.gov/vuln/detail/${c})`);
  }
  if (f.remediation) lines.push("", "REMEDIATION", "-".repeat(40), String(f.remediation).replace(/\\n/g, "\n").slice(0, 4000));
  return lines.join("\n");
}

export function normalizeTarget(target: string): { url: string; error: string } {
  const t = (target || "").trim();
  if (!t) return { url: "", error: "Enter a target URL first." };
  const url = /^https?:\/\//i.test(t) ? t : `http://${t}`;
  if (url.length < 8) return { url: "", error: "Invalid URL." };
  return { url, error: "" };
}
