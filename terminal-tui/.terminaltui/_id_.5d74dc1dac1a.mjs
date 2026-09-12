// pages/scan/[id].ts
import { asyncContent, card, divider, dynamic, fetcher, markdown, progressBar } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";

// lib/api.ts
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
var _envCache = null;
function parseEnvFile(content) {
  const out = {};
  for (const line of content.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#") || !t.includes("=")) continue;
    const eq = t.indexOf("=");
    let v = t.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"') || v.startsWith("'") && v.endsWith("'")) {
      v = v.slice(1, -1);
    }
    out[t.slice(0, eq).trim()] = v;
  }
  return out;
}
function localEnv() {
  if (_envCache) return _envCache;
  _envCache = {};
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const p of [resolve(here, "../../.env"), resolve(here, "../.env")]) {
      if (!existsSync(p)) continue;
      Object.assign(_envCache, parseEnvFile(readFileSync(p, "utf-8")));
    }
  } catch {
  }
  return _envCache;
}
function apiBase() {
  const raw = typeof process !== "undefined" && process.env?.WEBVAPT_API_URL || localEnv().WEBVAPT_API_URL || "http://127.0.0.1:8000/api/v1";
  return raw.replace(/\/+$/, "");
}
function apiKey() {
  if (typeof process !== "undefined" && process.env?.WEBVAPT_API_KEY) {
    return process.env.WEBVAPT_API_KEY;
  }
  const local = localEnv();
  return local.WEBVAPT_API_KEY || local.API_KEY || "";
}
function apiHeaders(extra = {}) {
  const h = { "Content-Type": "application/json", ...extra };
  const key = apiKey();
  if (key) h["X-API-Key"] = key;
  return h;
}
function severityTag(sev) {
  const m = {
    CRITICAL: "[!!]",
    HIGH: "[! ]",
    MEDIUM: "[* ]",
    LOW: "[. ]",
    INFO: "[i ]"
  };
  return m[sev] ?? "[? ]";
}
function findingRow(f) {
  const cvss = f.cvss_score == null ? "-" : Number(f.cvss_score).toFixed(1);
  const ai = f.ai_verified === 1 ? "YES" : f.ai_verified === 0 ? "NO" : "-";
  return [severityTag(f.severity) + " " + f.severity, f.vuln_type, (f.url || "").slice(0, 60), cvss, ai];
}
function summaryText(scan) {
  const s = scan.summary_json ?? {};
  const bySev = s.by_severity ?? {};
  const es = scan.exec_summary ?? {};
  const lines = [
    `Target   : ${scan.target_url}`,
    `Status   : ${scan.status}   Pages: ${scan.pages_crawled ?? 0}   Duration: ${Math.round(scan.duration_secs ?? 0)}s`,
    `Risk     : ${scan.overall_risk ?? "N/A"} (${scan.risk_score ?? "?"}//100)   Findings: ${scan.total_findings ?? 0}`,
    "",
    "BY SEVERITY"
  ];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
    const n = bySev[sev] ?? 0;
    lines.push(`  ${severityTag(sev)} ${sev.padEnd(8)} ${String(n).padStart(3)}  ${"#".repeat(Math.min(n, 40))}`);
  }
  if (es.executive_summary) lines.push("", "EXECUTIVE SUMMARY", "-".repeat(40), String(es.executive_summary).slice(0, 2e3));
  if (es.immediate_actions?.length) {
    lines.push("", "IMMEDIATE ACTIONS");
    es.immediate_actions.slice(0, 8).forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
  }
  return lines.join("\n");
}

// pages/scan/[id].ts
var metadata = {
  hidden: true,
  label: (p) => `Scan ${String(p.id).slice(0, 8)}`,
  loading: (p) => `Loading scan ${String(p.id).slice(0, 8)}...`
};
async function fetchJson(url) {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(
        "HTTP 401 \u2014 API key rejected. Set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env."
      );
    }
    throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  return await res.json();
}
function ScanDetailPage({ params }) {
  const id = params.id;
  const statusUrl = `${apiBase()}/scan/${encodeURIComponent(id)}/status`;
  const detailUrl = `${apiBase()}/scan/${encodeURIComponent(id)}`;
  return [
    markdown(`SCAN ${id.slice(0, 8)} \u2014 polling ${statusUrl}`),
    divider(),
    dynamic(() => {
      const s = fetcher({ url: statusUrl, refreshInterval: 3e3, headers: apiHeaders() });
      if (s.loading) return markdown("Checking status...");
      const d = s.data;
      if (s.error) {
        const msg = String(s.error).slice(0, 300);
        const hint = /401/.test(msg) ? " Set WEBVAPT_API_KEY to match the root .env API_KEY." : "";
        return markdown(`Status error: ${msg}.${hint}`);
      }
      if (!d) return markdown("No status yet.");
      const bar = d.status === "complete" ? 100 : d.status === "running" ? 50 : 0;
      return [
        progressBar(`Status: ${d.status}`, bar),
        markdown(`Findings: ${d.total_findings ?? 0}   Risk: ${d.overall_risk ?? "-"} (${d.risk_score ?? "-"})${d.error ? `   Error: ${d.error}` : ""}`)
      ];
    }),
    asyncContent({
      load: async () => {
        const detail = await fetchJson(detailUrl);
        const rows = detail.findings.map(findingRow);
        const { table } = await import("file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js");
        return [
          markdown(summaryText(detail)),
          divider("FINDINGS (SEV, TYPE, URL, CVSS, AI)"),
          table(["SEV", "TYPE", "URL", "CVSS", "AI"], rows.length ? rows : [["-", "No findings", "-", "-", "-"]]),
          card({ title: "Open in Results", body: "Filter by category / severity.", action: { navigate: "results" } })
        ];
      },
      loading: "Loading full results (available when status=complete)...",
      fallback: [markdown("Could not load full results yet. Wait for status=complete, then re-open this page.")]
    })
  ];
}
export {
  ScanDetailPage as default,
  metadata
};
