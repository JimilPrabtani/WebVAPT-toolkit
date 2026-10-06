import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { findingDetailBlocks } from "../lib/finding_detail.ts";

const finding = {
  id: "94ad4c9a-7e77-4e80-be53-addf0e38a24c",
  vuln_type: "Missing Header: Content-Security-Policy",
  severity: "HIGH",
  url: "pentest-ground.com",
  detail: "No CSP header detected.",
  evidence: "Header absent from response",
  remediation: "WHY IT MATTERS:\nX\n\nPREVENTION (STOP IT RECURRING):\nY",
  ai_verified: 1,
  cvss_score: 7.5,
  owasp_id: "A03:2021",
  cwe_id: "CWE-693",
  sans_rank: null,
  cve_ids: [],
  created_at: "2026-10-06T13:32:40",
};

describe("finding detail view (flat sections, no nested tabs)", () => {
  it("returns renderable text/divider blocks only (no nested tabs)", () => {
    const blocks = findingDetailBlocks(finding) as { type: string }[];
    assert.ok(blocks.length >= 9);
    for (const b of blocks) {
      assert.ok(b.type === "text" || b.type === "divider", `unexpected block type: ${b.type}`);
    }
    assert.ok(!blocks.some((b) => b.type === "tabs" || b.type === "accordion"));
  });

  it("overview carries severity, CVSS, URL and AI verdict", () => {
    const blocks = findingDetailBlocks(finding) as { type: string; content?: string }[];
    const first = JSON.stringify(blocks[0]);
    assert.match(first, /Missing Header/);
    assert.match(first, /HIGH/);
    assert.match(first, /7\.5/);
    assert.match(first, /pentest-ground\.com/);
    assert.match(first, /YES/);
  });

  it("exposes evidence, CVE mapping incl. NVD links, mitigation and prevention", () => {
    const text = JSON.stringify(findingDetailBlocks(finding));
    assert.match(text, /EVIDENCE/);
    assert.match(text, /Header absent/);
    assert.match(text, /CVEs & MAPPING/);
    assert.match(text, /CWE-693/);
    assert.match(text, /MITIGATION/);
    assert.match(text, /PREVENTION \(STOP IT RECURRING\)/);
    assert.match(text, /AI VERDICT/);
  });

  it("survives null fields and stringifies CVE links", () => {
    const blocks = findingDetailBlocks({
      ...finding,
      detail: null,
      evidence: null,
      remediation: null,
      cvss_score: null,
      ai_verified: null,
      owasp_id: null,
      cwe_id: null,
      cve_ids: ["CVE-2020-11022"],
    }) as unknown[];
    const text = JSON.stringify(blocks);
    assert.match(text, /nvd\.nist\.gov\/vuln\/detail\/CVE-2020-11022/);
    assert.match(text, /not checked/);
  });
});
