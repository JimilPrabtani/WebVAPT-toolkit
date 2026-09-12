// pages/history.ts
import { card, divider, dynamic, fetcher, markdown, table } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";

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

// pages/history.ts
var metadata = { label: "History", icon: "#", order: 4 };
function History() {
  const url = `${apiBase()}/history?limit=50`;
  return [
    markdown("HISTORY"),
    markdown("Every completed scan is stored locally (SQLite). Reports also saved as JSON + TXT under data/reports/."),
    divider(),
    dynamic(() => {
      const h = fetcher({ url, refreshInterval: 1e4, headers: apiHeaders() });
      if (h.loading) return markdown("Loading history...");
      if (h.error) {
        const msg = String(h.error).slice(0, 300);
        const hint = /401/.test(msg) ? " API key rejected: set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env." : ` Is the API running at ${apiBase()}?`;
        return markdown(`History error: ${msg}.${hint}`);
      }
      const data = h.data;
      const scans = data?.scans ?? [];
      if (!scans.length) return markdown("No scans yet. Start one from New Scan.");
      const rows = scans.map((s) => [
        s.id.slice(0, 8),
        (s.target_url || "").slice(0, 40),
        s.status,
        s.overall_risk ?? "-",
        s.risk_score != null ? String(s.risk_score) : "-",
        String(s.total_findings ?? 0),
        (s.started_at || "").slice(0, 16).replace("T", " ")
      ]);
      return table(["ID", "TARGET", "STATUS", "RISK", "SCORE", "N", "STARTED"], rows);
    }),
    markdown("Open a scan by ID: use search below, or go to Results for the latest detail view."),
    card({ title: "Results", body: "Summary + findings table + filters.", action: { navigate: "results" } })
  ];
}
export {
  History as default,
  metadata
};
