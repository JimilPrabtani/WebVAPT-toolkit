// pages/scan.ts
import { button, divider, form, markdown, numberInput, textInput, toggle } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";

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
function normalizeTarget(target) {
  const t = (target || "").trim();
  if (!t) return { url: "", error: "Enter a target URL first." };
  const url = /^https?:\/\//i.test(t) ? t : `https://${t}`;
  if (url.length < 8) return { url: "", error: "Invalid URL." };
  return { url, error: "" };
}

// pages/scan.ts
var metadata = { label: "New Scan", icon: "+", order: 2 };
function Scan() {
  return [
    markdown("NEW SCAN"),
    markdown("Enter a target. The tool crawls it, runs all checks, optionally asks AI for fixes, then saves everything."),
    divider(),
    form({
      id: "new-scan",
      onSubmit: async (data) => {
        const target = String(data.target ?? "");
        const { url, error } = normalizeTarget(target);
        if (error) return { error };
        let pages = parseInt(String(data.pages ?? "20"), 10);
        if (!Number.isFinite(pages)) pages = 20;
        pages = Math.max(1, Math.min(50, pages));
        const enableAi = Boolean(data.ai ?? true);
        try {
          const res = await fetch(`${apiBase()}/scan`, {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ target_url: url, enable_ai: enableAi, max_pages: pages })
          });
          if (!res.ok) {
            const body = await res.text();
            if (res.status === 401) {
              return {
                error: "API rejected the request (401 Unauthorized). The API needs X-API-Key: set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the project-root .env, then re-open this page."
              };
            }
            return { error: `Scan rejected (${res.status}): ${body.slice(0, 300)}` };
          }
          const started = await res.json();
          const { navigate } = await import("file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js");
          navigate("scan/[id]", { id: started.scan_id });
          return { success: `Scan started: ${url} (pages=${pages}, ai=${enableAi ? "on" : "off"})` };
        } catch (e) {
          return { error: `API unreachable at ${apiBase()}: ${String(e)}` };
        }
      },
      fields: [
        textInput({ id: "target", label: "TARGET URL", placeholder: "https://example.com", maxLength: 2048 }),
        toggle({ id: "ai", label: "AI analysis (fixes + risk score)", onLabel: "ON", offLabel: "OFF", defaultValue: true }),
        numberInput({ id: "pages", label: "PAGES TO CRAWL (1-50)", defaultValue: 20, min: 1, max: 50, step: 1 }),
        button({ label: "START SCAN", style: "primary" })
      ]
    }),
    divider("Live progress appears on the scan page after START")
  ];
}
export {
  Scan as default,
  metadata
};
