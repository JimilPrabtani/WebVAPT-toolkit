"""
ai/AI_analyzer.py
─────────────────
Connects scanner findings to the AI provider chain.

HOW IT WORKS:
  1. analyze_scan() is called by engine.py after all checks complete
  2. It sends ALL priority findings (HIGH/CRITICAL/MEDIUM) to the AI in ONE batched call
     → This drastically reduces API calls: 10 findings = 1 call, not 10 calls
  3. Then it generates one executive summary call
  4. LOW/INFO findings are NOT sent to AI — they have consistent, well-understood fixes

WHY BATCH INSTEAD OF PER-FINDING?
  - The original per-finding approach sent one API call per finding:
      4 findings → 4 calls in 2 seconds → rate limit hit
  - The batched approach sends all findings in ONE call:
      4 findings → 1 call → no rate limit hit
  - Even with many findings, 2 API calls total (batch + summary) is very fast

RATE LIMIT NOTES:
  - OpenRouter free tier: ~15 requests per minute (RPM)
  - AI_MODEL accepts a comma-separated fallback chain; dead/rate-limited
    models are skipped automatically (see openai_provider.py).

AI PROVIDER (configure in .env — single OpenAI-compatible endpoint):
  - OPENAI_API_KEY=sk-or-v1-... (OpenRouter key)
  - CUSTOM_AI_BASE_URL=https://openrouter.ai/api/v1 (OpenRouter endpoint)
  - AI_MODEL=openai/gpt-4o-mini (any OpenRouter model id)

TROUBLESHOOTING:
  - "No AI provider configured" → Check OPENAI_API_KEY and CUSTOM_AI_BASE_URL in .env
  - "AI provider error" → Key, endpoint, or model is wrong; check .env
  - "non-JSON response" → AI returned unexpected format; scan still completes
"""

import json
import re
from typing import Optional, Callable

from config import ENABLE_AI_ANALYSIS
from scanner.models import Finding, ScanResult
from ai.prompts import (
    BATCH_ANALYSIS_SYSTEM,
    BATCH_ANALYSIS_PROMPT,
    SUMMARY_SYSTEM,
    SUMMARY_PROMPT,
)
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.base import ProviderError


# Last AI failure message (reset at the start of every analyze_scan call).
# Lets engine.py put the reason into the report instead of silently marking
# every finding unverified with no explanation.
_last_ai_error: str = ""


def get_last_ai_error() -> str:
    """Return the last AI failure message ('' if the last run was clean)."""
    return _last_ai_error


def _record_ai_error(msg: str) -> None:
    """Keep the FIRST error — it is usually the root cause (e.g. bad model)."""
    global _last_ai_error
    if not _last_ai_error:
        _last_ai_error = msg


def _parse_ai_response(response_text: str) -> dict:
    """
    Parse the JSON response from any AI provider.

    AI models sometimes wrap their output in markdown code fences like:
      ```json
      { ... }
      ```
    This function strips those fences before parsing.

    Returns empty dict on failure — callers handle the missing-data case gracefully.
    The scan will still complete; the finding just won't have AI enrichment.
    """
    raw_text = response_text.strip()

    # Strip markdown code fences if the model added them
    if raw_text.startswith("```"):
        lines    = raw_text.split("\n")
        raw_text = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"  [!] AI returned non-JSON response: {e}")
        print(f"      First 200 chars: {raw_text[:200]}")
        return {}


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

def _validate_cve_ids(raw) -> list:
    """
    Keep only well-formed CVE identifiers (CVE-YYYY-NNNN).

    LLMs sometimes hallucinate CVE numbers, so we drop anything that doesn't
    match the official format. A fabricated CVE is worse than no CVE at all.
    """
    if not isinstance(raw, list):
        return []
    return [
        c.strip().upper()
        for c in raw
        if isinstance(c, str) and _CVE_RE.match(c.strip().upper())
    ]


def _apply_ai_data_to_finding(finding: Finding, ai_data: dict) -> None:
    """
    Apply the AI's analysis results to a Finding object in-place.

    Called after the batch analysis response is parsed.
    Each key in ai_data should correspond to a field on the Finding model.

    Args:
        finding: The Finding object to enrich (modified in-place)
        ai_data:  Dict from AI response for this specific finding
    """
    finding.ai_verified = ai_data.get("verified", False)
    finding.cvss_score  = ai_data.get("cvss_score")
    # Normalize "A05:2021 - Security Misconfiguration" → "A05:2021"
    # so report grouping doesn't split on the model's free-text suffix.
    _owasp = ai_data.get("owasp_id")
    _m = re.match(r"\s*(A\d{2}:\d{4})", str(_owasp or ""))
    finding.owasp_id    = _m.group(1) if _m else (_owasp or None)
    finding.cwe_id      = ai_data.get("cwe_id")
    finding.sans_rank   = ai_data.get("sans_rank")
    finding.cve_ids     = _validate_cve_ids(ai_data.get("cve_ids"))

    # Only override severity when AI has high confidence
    if ai_data.get("confidence") == "HIGH" and ai_data.get("severity"):
        finding.severity = ai_data["severity"]

    # Build rich remediation text from AI sections
    steps  = ai_data.get("remediation_steps", [])
    code   = ai_data.get("code_example", "")
    why    = ai_data.get("why_it_matters", "")
    attack = ai_data.get("attack_scenario", "")
    prev   = ai_data.get("prevention", "")
    refs   = ai_data.get("references", [])

    remediation_parts = []
    if why:
        remediation_parts.append(f"WHY IT MATTERS:\n{why}")
    if attack:
        remediation_parts.append(f"ATTACK SCENARIO:\n{attack}")
    if steps:
        remediation_parts.append(
            "HOW TO FIX:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps))
        )
    if code:
        remediation_parts.append(f"SECURE CODE EXAMPLE:\n{code}")
    if prev:
        remediation_parts.append(f"PREVENTION (STOP IT RECURRING):\n{prev}")
    if refs:
        remediation_parts.append(
            "REFERENCES:\n" + "\n".join(f"  - {r}" for r in refs)
        )

    if remediation_parts:
        finding.remediation = "\n\n".join(remediation_parts)


def analyze_scan(
    scan_result: ScanResult,
    on_progress: Optional[Callable[[str], None]] = None
) -> dict:
    """
    Run AI analysis for an entire scan using a BATCHED approach.

    BATCHED APPROACH (2 API calls total, regardless of finding count):
      Call 1 → Send ALL priority findings at once, get back a JSON array of analyses
      Call 2 → Executive summary for the whole scan

    This replaces the old per-finding approach (N calls for N findings) which hit
    rate limits even on paid API keys when scanning sites with multiple issues.

    Args:
        scan_result:  The ScanResult from engine.run_scan()
        on_progress:  Optional callback for live progress messages (used by dashboard)

    Returns:
        Executive summary dict with:
          - overall_risk (CRITICAL/HIGH/MEDIUM/LOW)
          - risk_score (0–100)
          - executive_summary (plain English for managers)
          - key_risks, immediate_actions, positive_observations

        Returns empty dict if AI is disabled or all providers fail.

    API CALL COUNT:
      - Old: 1 call per finding → prone to rate limits
      - New: 2 calls total (batch + summary) → fast, safe on any tier
      - If you have 0 priority findings → 1 call (summary only)
    """
    def log(msg: str):
        if on_progress:
            on_progress(msg)
        else:
            print(msg)

    # Fresh error state for this run — engine.py reads it via get_last_ai_error()
    global _last_ai_error
    _last_ai_error = ""

    # Skip if AI is globally disabled in .env
    if not ENABLE_AI_ANALYSIS:
        log("[!] AI analysis disabled (ENABLE_AI_ANALYSIS=false in .env)")
        return {}

    # Initialize dynamically from .env — works with any endpoint/model/key
    try:
        provider = OpenAIProvider()
    except Exception as e:
        log(f"[!] AI provider error: {e}")
        log("    → Check OPENAI_API_KEY / CUSTOM_AI_BASE_URL / AI_MODEL in .env.")
        _record_ai_error(f"AI provider init failed: {e}")
        return {}

    # ── Sort findings by severity ──────────────────────────────────────────
    findings         = scan_result.sorted_findings()
    priority_findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    lower_findings    = [f for f in findings if f.severity in ("LOW", "INFO")]

    # Mark lower-severity findings as "not sent to AI" — null means not attempted
    for f in lower_findings:
        f.ai_verified = None

    # ── Step 1: Batched finding analysis ──────────────────────────────────
    # Send ALL priority findings in ONE API call.
    # The AI returns a JSON array with one analysis object per finding.
    if priority_findings:
        log(f"\n[AI] Batch-analyzing {len(priority_findings)} findings in 1 API call ({provider.name})...")

        # Build a numbered list of findings for the prompt
        findings_text = "\n\n".join(
            f"Finding #{i+1}:\n"
            f"  Type:     {f.vuln_type}\n"
            f"  Severity: {f.severity}\n"
            f"  URL:      {f.url}\n"
            f"  Detail:   {f.detail}\n"
            f"  Evidence: {f.evidence}"
            for i, f in enumerate(priority_findings)
        )

        prompt = BATCH_ANALYSIS_PROMPT.format(
            count          = len(priority_findings),
            findings_text  = findings_text,
        )

        try:
            response      = provider.complete(BATCH_ANALYSIS_SYSTEM, prompt)
            batch_data    = _parse_ai_response(response.content)

            # AI returns: {"analyses": [{...finding 1...}, {...finding 2...}, ...]}
            analyses = batch_data.get("analyses", [])

            if not analyses:
                log("[!] AI returned empty analyses array — findings will not have AI enrichment")
            else:
                log(f"[AI] Received {len(analyses)} analysis results (model: {response.model_used})")
                for i, (finding, ai_data) in enumerate(zip(priority_findings, analyses)):
                    _apply_ai_data_to_finding(finding, ai_data)
                    log(f"[AI]   [ok] {finding.vuln_type} (CVSS: {finding.cvss_score}, verified: {finding.ai_verified})")

        except ProviderError as e:
            log(f"[!] AI provider error during batch analysis: {e}")
            log("    → Findings below are NOT AI-verified. Check AI_MODEL / key / endpoint in .env.")
            _record_ai_error(f"Batch analysis failed: {e}")
            for f in priority_findings:
                f.ai_verified = False
    else:
        log("[AI] No HIGH/CRITICAL/MEDIUM findings — skipping per-finding analysis")

    # ── Step 2: Executive summary ──────────────────────────────────────────
    log("[AI] Generating executive summary...")
    summary_data = scan_result.summary()
    top_5 = [
        f"- [{f.severity}] {f.vuln_type} at {f.url}"
        for f in findings[:5]
    ]

    prompt = SUMMARY_PROMPT.format(
        target_url     = scan_result.target_url,
        pages_crawled  = summary_data["pages_crawled"],
        duration       = summary_data["scan_duration"],
        total_findings = summary_data["total_findings"],
        critical       = summary_data["by_severity"].get("CRITICAL", 0),
        high           = summary_data["by_severity"].get("HIGH", 0),
        medium         = summary_data["by_severity"].get("MEDIUM", 0),
        low            = summary_data["by_severity"].get("LOW", 0),
        info           = summary_data["by_severity"].get("INFO", 0),
        top_findings   = "\n".join(top_5) if top_5 else "No significant findings.",
    )

    try:
        response     = provider.complete(SUMMARY_SYSTEM, prompt)
        exec_summary = _parse_ai_response(response.content)
        log("[AI] Analysis complete [ok]")
    except ProviderError as e:
        log(f"[!] AI executive summary failed: {e}")
        _record_ai_error(f"Executive summary failed: {e}")
        exec_summary = {}

    return exec_summary
