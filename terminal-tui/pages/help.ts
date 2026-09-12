import { divider, list, markdown } from "terminaltui";

export const metadata = { label: "Help", icon: "?", order: 5 };

export default function Help() {
  return [
    markdown("HOW IT WORKS"),
    divider(),
    list(
      [
        "CRAWL — breadth-first walk of the target domain.",
        "SCAN — 30+ checks in 7 groups: headers, injection, XSS, secrets, TLS, open redirect, misconfiguration.",
        "DEDUP — identical findings collapse to one.",
        "AI — HIGH/CRITICAL/MEDIUM go to AI for CVSS, attack scenario, and fix steps.",
        "SAVE — SQLite record plus JSON + TXT in data/reports/.",
      ],
      "number"
    ),
    divider("RUNNING"),
    markdown(
      "API (terminal 1): `uvicorn main:app --port 8000`\n" +
        "TUI (terminal 2): `cd terminal-tui && npm run dev`\n" +
        "Set WEBVAPT_API_URL if the API is not on http://127.0.0.1:8000/api/v1.\n" +
        "Set WEBVAPT_API_KEY when API_KEY is configured in .env."
    ),
    divider("LEGAL"),
    markdown("Authorized testing only. Get written permission before scanning a target you do not own."),
  ];
}
