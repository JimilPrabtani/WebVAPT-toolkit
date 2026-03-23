"""
ai/AI_analyzer.py
─────────────────
Connects scanner findings to the AI provider chain.

This module uses the multi-provider abstraction (provider_factory.py).
Supported providers: Gemini, OpenAI, Anthropic, Ollama, and any
OpenAI-compatible endpoint. Configure via AI_PROVIDER in .env.

Two public functions:
  - analyze_finding(finding)  → enriches one Finding in-place
  - analyze_scan(scan_result) → enriches all findings + generates executive summary
"""

import json
import time
from typing import Optional, Callable

from config import ENABLE_AI_ANALYSIS
from scanner.models import Finding, ScanResult
from ai.prompts import (
    FINDING_ANALYSIS_SYSTEM,
    FINDING_ANALYSIS_PROMPT,
    SUMMARY_SYSTEM,
    SUMMARY_PROMPT,
)
from ai.provider_factory import get_provider
from ai.providers.base import AIProvider, ProviderError


def _parse_ai_response(response_text: str) -> dict:
    """
    Parse JSON response from any AI provider.
    Strips markdown code fences if needed.
    Returns empty dict on parse failure.
    """
    raw_text = response_text.strip()

    # Strip markdown code fences if the model added them
    if raw_text.startswith("```"):
        lines = raw_text.split("\n")
        raw_text = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"  [!] AI provider returned non-JSON: {e}")
        print(f"      Raw response: {raw_text[:200]}")
        return {}


def analyze_finding(finding: Finding) -> Finding:
    """
    Send one finding to the configured AI provider for deep analysis.
    Enriches the Finding object in-place and also returns it.

    Fields populated:
      - remediation   (replaces heuristic placeholder)
      - ai_verified   (True/False)
      - cvss_score    (0.0 – 10.0)
      - why_it_matters, attack_scenario, steps, code_example (stored in remediation)
    
    Args:
        finding: Finding object to analyze
        
    Returns:
        Enriched Finding object
    """
    if not ENABLE_AI_ANALYSIS:
        return finding

    try:
        provider: AIProvider = get_provider()
    except RuntimeError as e:
        print(f"  [!] No AI provider configured: {e}")
        finding.ai_verified = False
        return finding

    prompt = FINDING_ANALYSIS_PROMPT.format(
        vuln_type = finding.vuln_type,
        severity  = finding.severity,
        url       = finding.url,
        detail    = finding.detail,
        evidence  = finding.evidence,
    )

    try:
        response = provider.complete(FINDING_ANALYSIS_SYSTEM, prompt)
        data = _parse_ai_response(response.content)
    except ProviderError as e:
        print(f"  [!] AI provider error: {e}")
        finding.ai_verified = False
        return finding

    if not data:
        finding.ai_verified = False
        return finding

    # ── Populate Finding fields from AI response ──────────────────
    finding.ai_verified = data.get("verified", False)
    finding.cvss_score  = data.get("cvss_score")

    # Override severity only if AI has high confidence
    if data.get("confidence") == "HIGH" and data.get("severity"):
        finding.severity = data["severity"]

    # Build a rich remediation string from all AI fields
    steps   = data.get("remediation_steps", [])
    code    = data.get("code_example", "")
    why     = data.get("why_it_matters", "")
    attack  = data.get("attack_scenario", "")
    refs    = data.get("references", [])

    remediation_parts = []
    if why:
        remediation_parts.append(f"WHY IT MATTERS:\n{why}")
    if attack:
        remediation_parts.append(f"ATTACK SCENARIO:\n{attack}")
    if steps:
        remediation_parts.append("HOW TO FIX:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps)))
    if code:
        remediation_parts.append(f"SECURE CODE EXAMPLE:\n{code}")
    if refs:
        remediation_parts.append("REFERENCES:\n" + "\n".join(f"  - {r}" for r in refs))

    finding.remediation = "\n\n".join(remediation_parts) if remediation_parts else finding.remediation

    return finding


def analyze_scan(
    scan_result: ScanResult,
    on_progress: Optional[Callable[[str], None]] = None
) -> dict:
    """
    1. Enrich every finding in scan_result with AI analysis
    2. Generate an executive summary for the whole scan
    3. Return the executive summary dict

    Args:
        scan_result: ScanResult object containing all findings
        on_progress: Optional callback for live UI updates (msg: str)
        
    Returns:
        Executive summary dict with insights, remediation priorities, etc.
    """
    def log(msg: str):
        if on_progress:
            on_progress(msg)
        else:
            print(msg)

    if not ENABLE_AI_ANALYSIS:
        log("[!] AI analysis disabled (ENABLE_AI_ANALYSIS=false in .env)")
        return {}

    try:
        provider: AIProvider = get_provider()
    except RuntimeError as e:
        log(f"[!] No AI provider configured: {e}")
        return {}

    # ── Step 1: Enrich each finding ───────────────────────────────────
    findings = scan_result.sorted_findings()
    # Only send HIGH and above to the API to save quota on INFO/LOW noise
    priority_findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    lower_findings    = [f for f in findings if f.severity in ("LOW", "INFO")]

    log(f"\n[AI] Analyzing {len(priority_findings)} priority findings with {provider.name}...")

    for idx, finding in enumerate(priority_findings, 1):
        log(f"[AI] ({idx}/{len(priority_findings)}) Analyzing: {finding.vuln_type}")
        analyze_finding(finding)
        time.sleep(0.5)   # gentle rate limiting

    # Mark lower findings as not needing AI (still useful in report)
    for finding in lower_findings:
        finding.ai_verified = None   # None = "not sent to AI"

    # ── Step 2: Executive summary ────────────────────────────────────
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
        response = provider.complete(SUMMARY_SYSTEM, prompt)
        exec_summary = _parse_ai_response(response.content)
        log("[AI] Analysis complete ✓")
    except ProviderError as e:
        log(f"[!] AI provider error during summary: {e}")
        exec_summary = {}

    return exec_summary
