import { defineConfig } from "terminaltui";

// WEBVAPT // TERMINAL — authorized testing only.
// Monochrome incident-report theme: black ground, white ink, gray secondary.
// Severity is ASCII text ([!!]/[!]/[*]/[.]/[i]), never hue.
export default defineConfig({
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
    bg: "#000000",
  },
  borders: "single",
  menu: {
    items: [
      { label: "Home", page: "home", icon: "\u25C6" },
      { label: "New Scan", page: "scan", icon: "+" },
      { label: "Results", page: "results", icon: "=" },
      { label: "History", page: "history", icon: "#" },
      { label: "Help", page: "help", icon: "?" },
    ],
  },
});
