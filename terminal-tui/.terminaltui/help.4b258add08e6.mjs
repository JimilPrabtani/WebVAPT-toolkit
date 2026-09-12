// pages/help.ts
import { divider, list, markdown } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";
var metadata = { label: "Help", icon: "?", order: 5 };
function Help() {
  return [
    markdown("HOW IT WORKS"),
    divider(),
    list(
      [
        "CRAWL \u2014 breadth-first walk of the target domain.",
        "SCAN \u2014 30+ checks in 7 groups: headers, injection, XSS, secrets, TLS, open redirect, misconfiguration.",
        "DEDUP \u2014 identical findings collapse to one.",
        "AI \u2014 HIGH/CRITICAL/MEDIUM go to AI for CVSS, attack scenario, and fix steps.",
        "SAVE \u2014 SQLite record plus JSON + TXT in data/reports/."
      ],
      "number"
    ),
    divider("RUNNING"),
    markdown(
      "API (terminal 1): `uvicorn main:app --port 8000`\nTUI (terminal 2): `cd terminal-tui && npm run dev`\nSet WEBVAPT_API_URL if the API is not on http://127.0.0.1:8000/api/v1.\nSet WEBVAPT_API_KEY when API_KEY is configured in .env."
    ),
    divider("LEGAL"),
    markdown("Authorized testing only. Get written permission before scanning a target you do not own.")
  ];
}
export {
  Help as default,
  metadata
};
