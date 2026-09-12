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
  const s = (scan.summary_json ?? {}) as { by_severity?: Record<string, number> };
  const bySev = s.by_severity ?? {};
  const es = (scan.exec_summary ?? {}) as { executive_summary?: string; immediate_actions?: string[] };
  const lines = [
    `Target   : ${scan.target_url}`,
    `Status   : ${scan.status}   Pages: ${scan.pages_crawled ?? 0}   Duration: ${Math.round(scan.duration_secs ?? 0)}s`,
    `Risk     : ${scan.overall_risk ?? "N/A"} (${scan.risk_score ?? "?"}//100)   Findings: ${scan.total_findings ?? 0}`,
    "",
    "BY SEVERITY",
  ];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
    const n = bySev[sev] ?? 0;
    lines.push(`  ${severityTag(sev)} ${sev.padEnd(8)} ${String(n).padStart(3)}  ${"#".repeat(Math.min(n, 40))}`);
  }
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
  if (f.remediation) lines.push("", "REMEDIATION", "-".repeat(40), String(f.remediation).replace(/\\n/g, "\n").slice(0, 4000));
  return lines.join("\n");
}

export function normalizeTarget(target: string): { url: string; error: string } {
  const t = (target || "").trim();
  if (!t) return { url: "", error: "Enter a target URL first." };
  const url = /^https?:\/\//i.test(t) ? t : `https://${t}`;
  if (url.length < 8) return { url: "", error: "Invalid URL." };
  return { url, error: "" };
}
