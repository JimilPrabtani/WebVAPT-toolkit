import { divider, markdown } from "terminaltui";
import type { Finding } from "./api.js";

// Flat detail sections for one finding. Deliberately NO nested tabs():
// an accordion item consumes Enter to toggle itself, so interactive blocks
// nested inside it can never receive keypresses. Sequential sections render
// everything inline on expand — no hidden tabs, nothing to cycle.
export function findingDetailBlocks(f: Finding) {
  const cvss = f.cvss_score == null ? "-" : Number(f.cvss_score).toFixed(1);
  const ai = f.ai_verified === 1 ? "YES" : f.ai_verified === 0 ? "NO" : "not checked";
  const mapping = [
    f.owasp_id ? `OWASP: ${f.owasp_id}` : null,
    f.cwe_id ? `CWE: ${f.cwe_id}` : null,
    f.sans_rank ? `SANS: ${f.sans_rank}` : null,
  ].filter(Boolean).join("   ") || "none reported";
  const cves = (f.cve_ids ?? []).length
    ? (f.cve_ids ?? []).slice(0, 15).map((c) => `  - ${c}  https://nvd.nist.gov/vuln/detail/${c}`).join("\n")
    : "  (none reported by scanner/AI)";
  return [
    markdown(
      `${f.vuln_type}\n\nSeverity: ${f.severity}   CVSS: ${cvss}   AI verified: ${ai}\n\nURL: ${f.url}\n\n${(f.detail ?? "").slice(0, 1500)}`
    ),
    divider("EVIDENCE"),
    markdown("```\n" + String(f.evidence ?? "none").slice(0, 2000) + "\n```"),
    divider("CVEs & MAPPING"),
    markdown(`Classification: ${mapping}\n\nCVEs:\n${cves}`),
    divider("MITIGATION"),
    markdown(String(f.remediation ?? "No remediation provided.").replace(/\\n/g, "\n").slice(0, 4000)),
    divider("AI VERDICT"),
    markdown(`AI verified: ${ai}   CVSS: ${cvss}`),
  ];
}
