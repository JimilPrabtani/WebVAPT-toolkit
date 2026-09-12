import { card, divider, dynamic, fetcher, markdown, table } from "terminaltui";
import { apiBase, apiHeaders, type ScanSummary } from "../lib/api.js";

export const metadata = { label: "History", icon: "#", order: 4 };

export default function History() {
  const url = `${apiBase()}/history?limit=50`;
  return [
    markdown("HISTORY"),
    markdown("Every completed scan is stored locally (SQLite). Reports also saved as JSON + TXT under data/reports/."),
    divider(),
    dynamic(() => {
      const h = fetcher({ url, refreshInterval: 10000, headers: apiHeaders() });
      if (h.loading) return markdown("Loading history...");
      if (h.error) {
        const msg = String(h.error).slice(0, 300);
        const hint = /401/.test(msg)
          ? " API key rejected: set WEBVAPT_API_KEY in terminal-tui/.env to match API_KEY in the root .env."
          : ` Is the API running at ${apiBase()}?`;
        return markdown(`History error: ${msg}.${hint}`);
      }
      const data = h.data as { total?: number; scans?: ScanSummary[] } | null;
      const scans = data?.scans ?? [];
      if (!scans.length) return markdown("No scans yet. Start one from New Scan.");
      const rows = scans.map((s) => [
        s.id.slice(0, 8),
        (s.target_url || "").slice(0, 40),
        s.status,
        s.overall_risk ?? "-",
        s.risk_score != null ? String(s.risk_score) : "-",
        String(s.total_findings ?? 0),
        (s.started_at || "").slice(0, 16).replace("T", " "),
      ]);
      return table(["ID", "TARGET", "STATUS", "RISK", "SCORE", "N", "STARTED"], rows);
    }),
    markdown("Open a scan by ID: use search below, or go to Results for the latest detail view."),
    card({ title: "Results", body: "Summary + findings table + filters.", action: { navigate: "results" } }),
  ];
}
