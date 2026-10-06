import { button, divider, form, markdown, numberInput, textInput, toggle } from "terminaltui";
import { apiBase, apiHeaders, normalizeTarget } from "../lib/api.js";

export const metadata = { label: "New Scan", icon: "+", order: 2 };

export default function Scan() {
  return [
    markdown("NEW SCAN"),
    markdown("Enter a target. The tool crawls it, runs all checks, optionally asks AI for fixes, then saves everything."),
    divider(),
    form({
      id: "new-scan",
      onSubmit: async (data) => {
        const target = String((data as Record<string, unknown>).target ?? "");
        const { url, error } = normalizeTarget(target);
        if (error) return { error };
        let allPages = Boolean((data as Record<string, unknown>).all ?? false);
        let pages = parseInt(String((data as Record<string, unknown>).pages ?? "20"), 10);
        if (!Number.isFinite(pages)) pages = 20;
        pages = Math.max(1, pages);
        const enableAi = Boolean((data as Record<string, unknown>).ai ?? true);
        try {
          const res = await fetch(`${apiBase()}/scan`, {
            method: "POST",
            headers: apiHeaders(),
            body: JSON.stringify({ target_url: url, enable_ai: enableAi, max_pages: allPages ? 0 : pages }),
          });
          if (!res.ok) {
            const body = await res.text();
            if (res.status === 401) {
              return {
                error:
                  "API rejected the request (401 Unauthorized). The API needs " +
                  "X-API-Key: set WEBVAPT_API_KEY in terminal-tui/.env to match " +
                  "API_KEY in the project-root .env, then re-open this page.",
              };
            }
            return { error: `Scan rejected (${res.status}): ${body.slice(0, 300)}` };
          }
          const started = (await res.json()) as { scan_id: string };
          const { navigate } = await import("terminaltui");
          navigate("scan/[id]", { id: started.scan_id });
          return { success: `Scan started: ${url} (${allPages ? "all pages (cap 200)" : `pages=${pages}`}, ai=${enableAi ? "on" : "off"})` };
        } catch (e) {
          return { error: `API unreachable at ${apiBase()}: ${String(e)}` };
        }
      },
      fields: [
        textInput({ id: "target", label: "TARGET URL (paste with Ctrl+Shift+V / right-click)", placeholder: "http://localhost:3000", maxLength: 2048 }),
        toggle({ id: "ai", label: "AI analysis (fixes + risk score)", onLabel: "ON", offLabel: "OFF", defaultValue: true }),
        toggle({ id: "all", label: "Scan entire site (up to 200 pages)", onLabel: "ON", offLabel: "OFF", defaultValue: false }),
        numberInput({ id: "pages", label: "PAGES TO CRAWL (ignored when ENTIRE SITE is ON)", defaultValue: 20, min: 1, step: 1 }),
        button({ label: "START SCAN", style: "primary" }),
      ],
    }),
    divider("Live progress appears on the scan page after START"),
  ];
}
