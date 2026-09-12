import { asyncContent, card, divider, dynamic, fetcher, markdown, progressBar } from "terminaltui";
import { apiBase, apiHeaders, findingRow, summaryText, type ScanDetail } from "../../lib/api.js";

export const metadata = {
  hidden: true,
  label: (p: { id: string }) => `Scan ${String(p.id).slice(0, 8)}`,
  loading: (p: { id: string }) => `Loading scan ${String(p.id).slice(0, 8)}...`,
};

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(
        "HTTP 401 — API key rejected. Set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env."
      );
    }
    throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  }
  return (await res.json()) as T;
}

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const id = params.id;
  const statusUrl = `${apiBase()}/scan/${encodeURIComponent(id)}/status`;
  const detailUrl = `${apiBase()}/scan/${encodeURIComponent(id)}`;

  return [
    markdown(`SCAN ${id.slice(0, 8)} — polling ${statusUrl}`),
    divider(),
    dynamic(() => {
      const s = fetcher({ url: statusUrl, refreshInterval: 3000, headers: apiHeaders() });
      if (s.loading) return markdown("Checking status...");
      const d = s.data as { status?: string; total_findings?: number; risk_score?: number | null; overall_risk?: string | null; error?: string } | null;
      if (s.error) {
        const msg = String(s.error).slice(0, 300);
        const hint = /401/.test(msg) ? " Set WEBVAPT_API_KEY to match the root .env API_KEY." : "";
        return markdown(`Status error: ${msg}.${hint}`);
      }
      if (!d) return markdown("No status yet.");
      const bar = d.status === "complete" ? 100 : d.status === "running" ? 50 : 0;
      return [
        progressBar(`Status: ${d.status}`, bar),
        markdown(`Findings: ${d.total_findings ?? 0}   Risk: ${d.overall_risk ?? "-"} (${d.risk_score ?? "-"})${d.error ? `   Error: ${d.error}` : ""}`),
      ] as unknown as ReturnType<typeof markdown>;
    }),
    asyncContent({
      load: async () => {
        const detail = await fetchJson<ScanDetail>(detailUrl);
        const rows = detail.findings.map(findingRow);
        const { table } = await import("terminaltui");
        return [
          markdown(summaryText(detail)),
          divider("FINDINGS (SEV, TYPE, URL, CVSS, AI)"),
          table(["SEV", "TYPE", "URL", "CVSS", "AI"], rows.length ? rows : [["-", "No findings", "-", "-", "-"]]),
          card({ title: "Open in Results", body: "Filter by category / severity.", action: { navigate: "results" } }),
        ];
      },
      loading: "Loading full results (available when status=complete)...",
      fallback: [markdown("Could not load full results yet. Wait for status=complete, then re-open this page.")],
    }),
  ];
}
