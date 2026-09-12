import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { apiBase, findingDetailText, findingRow, normalizeTarget, severityTag, summaryText } from "../lib/api.ts";

describe("webvapt lib (port of tui/backend.py)", () => {
  it("severity markers are ASCII-only", () => {
    assert.equal(severityTag("CRITICAL"), "[!!]");
    assert.equal(severityTag("HIGH"), "[! ]");
    assert.equal(severityTag("MEDIUM"), "[* ]");
    assert.equal(severityTag("LOW"), "[. ]");
    assert.equal(severityTag("INFO"), "[i ]");
  });

  it("findingRow mirrors finding_to_row (SEV, TYPE, URL, CVSS, AI)", () => {
    const row = findingRow({
      id: "1",
      vuln_type: "XSS",
      severity: "HIGH",
      url: "https://example.com/?q=1",
      cvss_score: 7.55,
      ai_verified: 1,
      created_at: "2026-01-01",
    });
    assert.deepEqual(row, ["[! ] HIGH", "XSS", "https://example.com/?q=1", "7.5", "YES"]);
  });

  it("normalizeTarget requires input and adds https", () => {
    assert.equal(normalizeTarget("").error.length > 0, true);
    assert.deepEqual(normalizeTarget("example.com"), { url: "https://example.com", error: "" });
    assert.deepEqual(normalizeTarget("http://x.com"), { url: "http://x.com", error: "" });
  });

  it("summaryText renders incident-report sections", () => {
    const text = summaryText({
      id: "abc",
      target_url: "https://example.com",
      status: "complete",
      started_at: "2026-01-01",
      pages_crawled: 5,
      duration_secs: 12,
      total_findings: 2,
      risk_score: 80,
      overall_risk: "HIGH",
      summary_json: { by_severity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 } },
      exec_summary: { executive_summary: "fix now", immediate_actions: ["patch"] },
      findings: [],
    });
    assert.match(text, /Target\s+: https:\/\/example\.com/);
    assert.match(text, /BY SEVERITY/);
    assert.match(text, /EXECUTIVE SUMMARY/);
  });

  it("findingDetailText keeps WHAT/EVIDENCE/REMEDIATION blocks", () => {
    const text = findingDetailText({
      id: "1",
      vuln_type: "SQLi",
      severity: "CRITICAL",
      url: "https://example.com/s",
      detail: "d",
      evidence: "e",
      remediation: "r",
      created_at: "2026-01-01",
    });
    assert.match(text, /WHAT WAS FOUND/);
    assert.match(text, /EVIDENCE/);
    assert.match(text, /REMEDIATION/);
  });

  it("apiBase defaults to the split Python URL", () => {
    delete process.env.WEBVAPT_API_URL;
    assert.equal(apiBase(), "http://127.0.0.1:8000/api/v1");
    process.env.WEBVAPT_API_URL = "http://api:9000/api/v1/";
    assert.equal(apiBase(), "http://api:9000/api/v1");
    delete process.env.WEBVAPT_API_URL;
  });
});
