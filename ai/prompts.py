"""
ai/prompts.py
─────────────
All AI prompt templates for the analysis pipeline.

IMPORTANT CHANGE — BATCHED ANALYSIS:
  The per-finding prompt (FINDING_ANALYSIS_PROMPT) has been replaced by
  BATCH_ANALYSIS_PROMPT, which sends ALL findings in ONE API call.
  This reduces API calls from N (one per finding) to 2 (batch + summary).
  This prevents rate-limit errors even on free-tier API keys.

HOW TO CUSTOMIZE:
  - Change tone: edit the system prompt strings
  - Change output fields: edit the JSON schema in BATCH_ANALYSIS_PROMPT
    (also update _apply_ai_data_to_finding in AI_analyzer.py)
  - Add new output fields to the Finding model in scanner/models.py

STANDARDS COVERED:
  OWASP Top 10 2021 — https://owasp.org/Top10/
  CWE (Common Weakness Enumeration) — https://cwe.mitre.org/
  MITRE ATT&CK — https://attack.mitre.org/
  SANS/CWE Top 25 — https://www.sans.org/top25-software-errors/
"""


# ── Batched finding analysis (replaces per-finding approach) ──────────────
# This prompt receives ALL findings at once and returns a JSON array.
# API calls per scan: 1 (was N calls, one per finding)

BATCH_ANALYSIS_SYSTEM = """You are a senior web application penetration tester \
and security engineer with deep expertise in OWASP Top 10, SANS Top 25, \
MITRE ATT&CK, and CVSS 3.1 scoring.

Your job is to analyze a list of vulnerability findings from an automated security scan \
and return a structured JSON response with analysis for ALL of them.

Rules:
  1. Respond with ONLY valid JSON — no markdown, no code fences, no text outside JSON.
  2. Your response must contain an "analyses" array with exactly one object per finding.
  3. Keep each analysis focused and practical — developers need to understand and act on this.
  4. Be specific about attack scenarios — reference the actual URL and evidence given."""


BATCH_ANALYSIS_PROMPT = """Analyze these {count} security findings and return a JSON object.

FINDINGS:
{findings_text}

Return EXACTLY this JSON structure:
{{
  "analyses": [
    {{
      "finding_number": 1,
      "verified": true or false,
      "confidence": "HIGH" or "MEDIUM" or "LOW",
      "severity": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "INFO",
      "cvss_score": number between 0.0 and 10.0,
      "owasp_id": "e.g. A03:2021 — Injection (use null if not applicable)",
      "cwe_id": "e.g. CWE-89 (always include)",
      "sans_rank": "e.g. #1 CWE-79 (use null if not in SANS Top 25)",
      "why_it_matters": "2 sentences: what can an attacker DO with this? Focus on real impact.",
      "attack_scenario": "1 sentence: how would an attacker exploit THIS specific finding? Be specific to the URL/evidence.",
      "remediation_steps": [
        "Specific step 1 — not generic advice, reference the actual context",
        "Specific step 2",
        "Specific step 3"
      ],
      "code_example": "5-15 lines of secure code showing the fix. Use the most likely server language.",
      "references": [
        "https://owasp.org/... (OWASP)",
        "https://cwe.mitre.org/... (CWE)"
      ]
    }},
    ... one object per finding in the same order they were given ...
  ]
}}

IMPORTANT: The "analyses" array must contain exactly {count} objects, one per finding, in the same order."""


# ── Executive summary (whole scan) ────────────────────────────────────────
# Generated once per scan after the batched finding analysis.
# This is what shows in the dashboard header and report cover page.

SUMMARY_SYSTEM = """You are a senior penetration tester writing an executive summary \
for a security assessment report.

Audience:
  - Non-technical managers who approve remediation budgets (needs plain English)
  - Developers who will fix the issues (needs specific, actionable steps)

Rules:
  - Be clear and jargon-free in executive_summary
  - Be specific and technical in immediate_actions
  - Be honest — if critical issues exist, say so clearly
  - Respond with ONLY valid JSON — no markdown, no code fences"""


SUMMARY_PROMPT = """Write an executive summary for this web application security scan.

SCAN RESULTS:
- Target: {target_url}
- Pages scanned: {pages_crawled}
- Scan duration: {duration}s
- Total findings: {total_findings}
  - Critical: {critical}
  - High: {high}
  - Medium: {medium}
  - Low: {low}
  - Info: {info}

TOP FINDINGS:
{top_findings}

Return EXACTLY this JSON structure:
{{
  "overall_risk": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW",
  "risk_score": number 0-100 (0 = no risk, 100 = maximum risk),
  "executive_summary": "3-4 sentences for a manager. No jargon. Explain: what was found, what an attacker could do, and what needs to happen next.",
  "key_risks": [
    "Most critical risk in one clear sentence",
    "Second most important risk",
    "Third most important risk"
  ],
  "immediate_actions": [
    "Most urgent fix — be specific (e.g. 'Add Content-Security-Policy header to all responses')",
    "Second priority",
    "Third priority"
  ],
  "positive_observations": "1-2 sentences about anything done well security-wise. If nothing positive found, say so briefly."
}}"""
