import sys
import argparse

# Load .env FIRST — before any other import reads os.getenv().
# Without this, provider_factory.py may read empty env vars if config.py
# hasn't been imported yet when AI_analyzer.py calls get_provider().
from dotenv import load_dotenv
load_dotenv()

from scanner.engine        import run_scan
from reports.report_writer import save_report
from config                import ALLOW_PRIVATE_TARGETS, is_ssrf_safe



def parse_args():
    parser = argparse.ArgumentParser(
        description="WebPenTest AI Toolkit -- Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py https://example.com
  python scan.py http://localhost:3000 --no-ai

IMPORTANT: Only scan applications you own or have written
           permission to test. Unauthorized scanning is illegal.
        """
    )
    parser.add_argument("url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument(
        "--no-ai",
        action="store_true",
        default=False,
        help="Skip Gemini AI analysis (faster, no API calls)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    target = args.url
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    if not ALLOW_PRIVATE_TARGETS and not is_ssrf_safe(target):
        print(f"[!] Target '{target}' resolves to a private or internal IP address.")
        print("    Set ALLOW_PRIVATE_TARGETS=true in .env to scan internal hosts.")
        sys.exit(1)

    use_ai = not args.no_ai

    print(f"\n  Target : {target}")
    print(f"  AI Mode: {'Gemini enabled' if use_ai else 'Skipped (--no-ai)'}")
    print()

    try:
        scan_result, exec_summary = run_scan(target_url=target, run_ai=use_ai)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    if scan_result.error:
        print(f"\n[!] Scan failed: {scan_result.error}")
        sys.exit(1)

    print("\n[*] Saving reports...")
    paths = save_report(scan_result, exec_summary)
    print(f"  JSON: {paths['json']}")
    print(f"  TXT : {paths['text']}")
    print()

    findings = scan_result.sorted_findings()
    if findings:
        icons = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]",
                 "LOW": "[LOW]", "INFO": "[INFO]"}
        print("TOP FINDINGS:")
        for f in findings[:5]:
            icon = icons.get(f.severity, "[?]")
            print(f"  {icon} {f.vuln_type}")
            print(f"       {f.url}")
        if len(findings) > 5:
            print(f"  ... and {len(findings) - 5} more in the report.")


if __name__ == "__main__":
    main()