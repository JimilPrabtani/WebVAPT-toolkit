// pages/results.ts
import { accordion, asyncContent, divider, markdown, table } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";

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
function findingDetailText(f) {
  const lines = [
    `${severityTag(f.severity)} ${f.vuln_type}`,
    `Severity : ${f.severity}` + (f.cvss_score != null ? `  CVSS ${Number(f.cvss_score).toFixed(1)}` : ""),
    `URL      : ${f.url}`
  ];
  if (f.detail) lines.push("", "WHAT WAS FOUND", "-".repeat(40), f.detail);
  if (f.evidence) lines.push("", "EVIDENCE", "-".repeat(40), String(f.evidence).slice(0, 2e3));
  if (f.remediation) lines.push("", "REMEDIATION", "-".repeat(40), String(f.remediation).replace(/\\n/g, "\n").slice(0, 4e3));
  return lines.join("\n");
}

// pages/results.ts
var metadata = { label: "Results", icon: "=", order: 3 };
async function fetchJson(url) {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(
        "HTTP 401 \u2014 API key rejected. Set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env."
      );
    }
    throw new Error(`HTTP ${res.status}`);
  }
  return await res.json();
}
function Results() {
  return [
    markdown("RESULTS"),
    divider(),
    asyncContent({
      load: async () => {
        const h = await fetchJson(`${apiBase()}/history?limit=1`);
        const latest = h.scans?.[0];
        if (!latest) return [markdown("No scan loaded yet. Run a scan or wait for history.")];
        const detail = await fetchJson(`${apiBase()}/scan/${encodeURIComponent(latest.id)}`);
        const rows = detail.findings.map(findingRow);
        return [
          markdown(summaryText(detail)),
          divider(`LATEST: ${latest.target_url} (${latest.id.slice(0, 8)})`),
          table(
            ["SEV", "TYPE", "URL", "CVSS", "AI"],
            rows.length ? rows.slice(0, 50) : [["-", "No findings", "-", "-", "-"]]
          ),
          accordion(
            detail.findings.slice(0, 10).map((f) => ({
              label: `${f.severity} \u2014 ${f.vuln_type}`,
              content: [markdown("```\n" + findingDetailText(f).slice(0, 3e3) + "\n```")]
            }))
          )
        ];
      },
      loading: "Loading latest scan...",
      fallback: [markdown("Results unavailable. Check the API is running at the configured URL, and the API key if you see 401.")]
    })
  ];
}
export {
  Results as default,
  metadata
};
