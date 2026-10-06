import { accordion, card, divider, dynamic, fetcher, markdown, progressBar, table } from "terminaltui";
import { apiBase, apiHeaders, findingRow, summaryText, type ScanDetail } from "../../lib/api.js";
import { findingDetailBlocks } from "../../lib/finding_detail.js";

export const metadata = {
  hidden: true,
  label: (p: { id: string }) => `Scan ${String(p.id).slice(0, 8)}`,
  loading: (p: { id: string }) => `Loading scan ${String(p.id).slice(0, 8)}...`,
};

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const id = params.id;

  return [
    markdown(`SCAN ${id.slice(0, 8)}`),
    divider(),
    dynamic(() => {
      const s = fetcher({
        url: `${apiBase()}/scan/${encodeURIComponent(id)}`,
        headers: apiHeaders(),
        refreshInterval: 3000,
        key: `scan-detail-${id}`,
      });
      if (s.loading) return markdown("Contacting API...");
      if (s.error) {
        const msg = String(s.error).slice(0, 300);
        const hint = /401/.test(msg) ? " Set WEBVAPT_API_KEY to match the root .env API_KEY." : "";
        return markdown(`Status error: ${msg}.${hint}`);
      }
      const d = s.data as Record<string, any> | null;
      if (!d) return markdown("No data yet.");

      // While the scan runs, the API answers 202 with {scan_id, status, message}
      if (!Array.isArray(d.findings)) {
        return [
          progressBar(`Status: ${d.status ?? "running"}`, 50),
          markdown(d.message ?? "Scan in progress — results will appear here when it completes."),
        ] as unknown as ReturnType<typeof markdown>;
      }

      // Scan finished — render everything inline, no need to leave this page.
      const detail = d as unknown as ScanDetail;
      const rows = detail.findings.map(findingRow);
      return [
        progressBar(`Status: ${detail.status}`, 100),
        markdown(summaryText(detail)),
        divider("FINDINGS (SEV, TYPE, URL, CVSS, AI)"),
        table(["SEV", "TYPE", "URL", "CVSS", "AI"], rows.length ? rows : [["-", "No findings", "-", "-", "-"]]),
        divider("FINDING DETAILS (expand one with Enter)"),
        accordion(
          detail.findings.map((f) => ({
            label: `${f.severity} — ${f.vuln_type}`,
            content: findingDetailBlocks(f),
          }))
        ),
        card({ title: "Done", body: "Full history lives on the Results page.", action: { navigate: "results" } }),
      ] as unknown as ReturnType<typeof markdown>;
    }),
  ];
}
