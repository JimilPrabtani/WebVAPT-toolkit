import { accordion, asyncContent, divider, markdown, table } from "terminaltui";
import { apiBase, apiHeaders, findingDetailText, findingRow, summaryText, type ScanDetail, type ScanSummary } from "../lib/api.js";

export const metadata = { label: "Results", icon: "=", order: 3 };

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(
        "HTTP 401 — API key rejected. Set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env."
      );
    }
    throw new Error(`HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

export default function Results() {
  return [
    markdown("RESULTS"),
    divider(),
    asyncContent({
      load: async () => {
        const h = await fetchJson<{ scans?: ScanSummary[] }>(`${apiBase()}/history?limit=1`);
        const latest = h.scans?.[0];
        if (!latest) return [markdown("No scan loaded yet. Run a scan or wait for history.")];
        const detail = await fetchJson<ScanDetail>(`${apiBase()}/scan/${encodeURIComponent(latest.id)}`);
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
              label: `${f.severity} — ${f.vuln_type}`,
              content: [markdown("```\n" + findingDetailText(f).slice(0, 3000) + "\n```")],
            }))
          ),
        ];
      },
      loading: "Loading latest scan...",
      fallback: [markdown("Results unavailable. Check the API is running at the configured URL, and the API key if you see 401.")],
    }),
  ];
}
