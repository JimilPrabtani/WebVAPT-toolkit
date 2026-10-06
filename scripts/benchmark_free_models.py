"""
scripts/benchmark_free_models.py
────────────────────────────────
Re-benchmark OpenRouter :free models against this tool's real workload
(a mini batched-analysis prompt requiring strict JSON with the exact keys
ai/AI_analyzer.py consumes) and print a recommended AI_MODEL fallback chain.

Usage:
    python scripts/benchmark_free_models.py                       # curated shortlist
    python scripts/benchmark_free_models.py model/a:free model/b:free
    python scripts/benchmark_free_models.py --list                 # show live :free list

Free-model pools rotate and rate-limit, so re-run this whenever AI verdicts
start failing — then paste the recommended line into .env as AI_MODEL.
"""

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CURATED = [
    "nvidia/nemotron-3-super-120b-a12b:free",
    "cohere/north-mini-code:free",
    "liquid/lfm-2.5-2.6b:free",
    "google/gemma-4-26b-a4b-it:free",
]

SYSTEM = "You are a senior web application penetration tester. Respond with ONLY valid JSON."

MINI_PROMPT = """Analyze these 2 security findings and return a JSON object.
FINDINGS:
Finding #1:
  Type:     Missing Header: Content-Security-Policy
  Severity: HIGH
  URL:      localhost
  Detail:   No CSP header detected.
  Evidence: Header absent from response
Finding #2:
  Type:     SQL Injection (Error-Based)
  Severity: CRITICAL
  URL:      http://x/s?q=1
  Detail:   DB error on quote injection.
  Evidence: DB error pattern found
Return EXACTLY this JSON structure:
{"analyses": [{"finding_number": 1, "verified": true, "confidence": "HIGH",
"severity": "HIGH", "cvss_score": 7.5, "owasp_id": "A05:2021", "cwe_id": "CWE-693",
"sans_rank": null, "why_it_matters": "x", "attack_scenario": "y",
"remediation_steps": ["a"], "code_example": "", "prevention": "z",
"references": [], "cve_ids": []},
{"finding_number": 2, "verified": true, "confidence": "HIGH",
"severity": "CRITICAL", "cvss_score": 9.0, "owasp_id": "A03:2021", "cwe_id": "CWE-89",
"sans_rank": null, "why_it_matters": "x", "attack_scenario": "y",
"remediation_steps": ["a"], "code_example": "", "prevention": "z",
"references": [], "cve_ids": []}]}
IMPORTANT: The "analyses" array must contain exactly 2 objects."""

REQUIRED = {"verified", "confidence", "severity", "cvss_score", "owasp_id",
            "cwe_id", "remediation_steps", "prevention", "cve_ids"}


def list_free_models() -> list:
    req = urllib.request.Request("https://openrouter.ai/api/v1/models")
    data = json.load(urllib.request.urlopen(req, timeout=30))
    return [m["id"] for m in data["data"] if m.get("id", "").endswith(":free")]


def strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = "\n".join(t.split("\n")[1:])
    if t.endswith("```"):
        t = t[: -3]
    return t.strip()


def benchmark(model: str) -> tuple:
    """Return (model, verdict, seconds)."""
    from dotenv import load_dotenv  # local import: script also runs without .env
    load_dotenv()
    os.environ["AI_MODEL"] = model
    # Re-import after env override so the provider picks up this model.
    from ai.providers import openai_provider as provider_mod
    import importlib
    importlib.reload(provider_mod)
    try:
        p = provider_mod.OpenAIProvider()
        start = time.monotonic()
        resp = p.complete(SYSTEM, MINI_PROMPT)
        dt = time.monotonic() - start
        try:
            analyses = json.loads(strip_fences(resp.content)).get("analyses", [])
            ok = len(analyses) == 2 and all(REQUIRED <= set(a.keys()) for a in analyses)
            return model, ("PASS" if ok else "SHAPE-FAIL"), round(dt, 1)
        except Exception as e:
            return model, f"JSON-FAIL({e})", round(dt, 1)
    except Exception as e:
        return model, f"ERROR({str(e)[:120]})", -1


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--list" in sys.argv:
        print(f"{len(list_free_models())} free models:")
        for fid in list_free_models():
            print(" -", fid)
        return
    models = args or CURATED
    passed = []
    for model in models:
        name, verdict, secs = benchmark(model)
        print(f"{name} -> {verdict} in {secs}s", flush=True)
        if verdict == "PASS":
            passed.append((name, secs))
        time.sleep(3)
    print("\nRecommended AI_MODEL chain (fastest passing first):")
    if passed:
        passed.sort(key=lambda x: x[1])
        print("AI_MODEL=" + ",".join(m for m, _ in passed))
    else:
        print("(none passed — check key, endpoint, and rate limits)")


if __name__ == "__main__":
    main()
