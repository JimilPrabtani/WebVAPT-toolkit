// pages/home.ts
import { card, divider, markdown } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";
var metadata = { label: "Home", icon: "\u25C6", order: 1 };
function Home() {
  return [
    markdown("WEBVAPT // TERMINAL  \u2014  authorized testing only"),
    divider(),
    markdown(
      "Automated web security scanner: crawl, 30+ checks in 7 groups, AI fixes for HIGH/CRITICAL/MEDIUM, SQLite + JSON/TXT reports."
    ),
    card({
      title: "New Scan",
      body: "Enter a target. Crawl it, run all checks, optionally ask AI for fixes.",
      action: { navigate: "scan" }
    }),
    card({
      title: "History",
      body: "Every completed scan is stored locally (SQLite). Open, delete, trend.",
      action: { navigate: "history" }
    }),
    card({
      title: "Help / Legal",
      body: "Workflow, keys, and authorized-testing-only notice.",
      action: { navigate: "help" }
    })
  ];
}
export {
  Home as default,
  metadata
};
