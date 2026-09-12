// config.ts
import { defineConfig } from "file:///C:/Users/Deepali's%20laptop/Desktop/Cybersecurity/Projects/WebVAPT-toolkit/terminal-tui/node_modules/terminaltui/dist/index.js";
var config_default = defineConfig({
  name: "WEBVAPT",
  theme: {
    accent: "#ffffff",
    accentDim: "#9a9a9a",
    text: "#ffffff",
    muted: "#9a9a9a",
    subtle: "#3a3a3a",
    success: "#ffffff",
    warning: "#ffffff",
    error: "#ffffff",
    border: "#6e6e6e",
    bg: "#000000"
  },
  borders: "single",
  menu: {
    items: [
      { label: "Home", page: "home", icon: "\u25C6" },
      { label: "New Scan", page: "scan", icon: "+" },
      { label: "Results", page: "results", icon: "=" },
      { label: "History", page: "history", icon: "#" },
      { label: "Help", page: "help", icon: "?" }
    ]
  }
});
export {
  config_default as default
};
