#!/usr/bin/env python3
"""
Fray CLI — Unified command-line interface

Usage:
    fray detect <url>           Detect WAF vendor
    fray test <url>             Test WAF with payloads
    fray test <url> -c xss      Test specific category
    fray test <url> --webhook <url>  Notify on completion
    fray report                 Generate HTML report
    fray payloads               List available payload categories
    fray doctor                 Check environment + auto-fix issues
    fray submit-payload          Submit payload to community (auto GitHub PR)
    fray version                Show version
"""

import argparse
import json
import sys
from pathlib import Path

from fray import __version__, PAYLOADS_DIR


def cmd_detect(args):
    """Detect WAF vendor on target"""
    from fray.detector import WAFDetector
    detector = WAFDetector()
    results = detector.detect_waf(args.target)
    detector.print_results(results)


def cmd_test(args):
    """Run WAF tests against target"""
    from fray.tester import WAFTester
    tester = WAFTester(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay
    )

    all_payloads = []

    if args.category:
        category_dir = PAYLOADS_DIR / args.category
        if not category_dir.exists():
            print(f"Error: Category '{args.category}' not found.")
            print(f"Available: {', '.join(list_categories())}")
            sys.exit(1)
        for pf in sorted(category_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))
    elif args.payload_file:
        all_payloads.extend(tester.load_payloads(args.payload_file))
    else:
        # Load all payloads
        for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
            if cat_dir.is_dir():
                for pf in sorted(cat_dir.glob("*.json")):
                    all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print("No payloads loaded. Check category name or payload file path.")
        sys.exit(1)

    print(f"\nLoaded {len(all_payloads)} payloads")
    results = tester.test_payloads(all_payloads, max_payloads=args.max)

    # Save results
    output = args.output or "fray_results.json"
    tester.generate_report(results, output=output)
    print(f"\nResults saved to {output}")

    # Send webhook notification if requested
    if args.webhook:
        from fray.webhook import send_webhook
        report = {
            "target": args.target,
            "duration": tester.start_time and str(tester.start_time) or "N/A",
            "summary": {
                "total": len(results),
                "blocked": sum(1 for r in results if r.get("blocked")),
                "passed": sum(1 for r in results if not r.get("blocked")),
                "block_rate": f"{sum(1 for r in results if r.get('blocked')) / len(results) * 100:.1f}%" if results else "0%",
            }
        }
        # Calculate duration properly
        if tester.start_time:
            from datetime import datetime
            elapsed = datetime.now() - tester.start_time
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            report["duration"] = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        send_webhook(args.webhook, report)


def cmd_report(args):
    """Generate HTML report from results"""
    if args.sample:
        from fray.reporter import generate_sample_report
        generate_sample_report()
        return

    from fray.reporter import SecurityReportGenerator
    if not args.input:
        print("Error: provide --input results.json or use --sample for a demo report")
        sys.exit(1)
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    generator = SecurityReportGenerator()
    output = args.output
    generator.generate_html_report(data, output)
    print(f"Report generated: {output}")


def cmd_payloads(args):
    """List available payload categories"""
    categories = list_categories()
    print(f"\nFray v{__version__} — Payload Categories\n")
    print(f"{'Category':<30} {'Files':<8} {'Location'}")
    print("-" * 70)
    total_files = 0
    for cat in categories:
        cat_dir = PAYLOADS_DIR / cat
        files = list(cat_dir.glob("*.json")) + list(cat_dir.glob("*.txt"))
        count = len(files)
        total_files += count
        print(f"  {cat:<28} {count:<8} payloads/{cat}/")
    print("-" * 70)
    print(f"  {'TOTAL':<28} {total_files}")
    print(f"\nUsage: fray test <url> -c <category>")


def cmd_version(args):
    """Show version"""
    print(f"Fray v{__version__}")


def cmd_doctor(args):
    """Run environment diagnostics and auto-fix issues"""
    from fray.doctor import run_doctor
    run_doctor(auto_fix=args.fix, verbose=args.verbose)


def cmd_submit_payload(args):
    """Submit a payload to the Fray community database via GitHub PR"""
    from fray.submit import run_submit_payload
    run_submit_payload(
        payload=args.payload,
        category=args.category,
        subcategory=args.subcategory,
        description=args.description,
        technique=args.technique,
        contributor_name=args.name,
        contributor_github=args.github,
        file=args.file,
        dry_run=args.dry_run,
    )


def cmd_mcp(args):
    """Start MCP server for AI assistant integration"""
    try:
        from fray.mcp_server import main as mcp_main
        mcp_main()
    except ImportError:
        print("Error: MCP SDK not installed. Install with:")
        print("  pip install 'mcp[cli]'")
        sys.exit(1)


def list_categories():
    """Get sorted list of payload category names"""
    return sorted([
        d.name for d in PAYLOADS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])


def main():
    parser = argparse.ArgumentParser(
        prog="fray",
        description=f"Fray v{__version__} — AI-Powered WAF Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fray detect https://example.com
  fray test https://example.com --category xss
  fray test https://example.com --all
  fray test https://example.com --webhook https://hooks.slack.com/xxx
  fray doctor
  fray doctor --fix
  fray submit-payload
  fray submit-payload --payload '<svg/onload=alert(1)>' --category xss
  fray submit-payload --file my_payloads.json
  fray payloads
  fray report --output report.html

Documentation: https://github.com/dalisecurity/fray
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # detect
    p_detect = subparsers.add_parser("detect", help="Detect WAF vendor on target URL")
    p_detect.add_argument("target", help="Target URL (e.g. https://example.com)")
    p_detect.set_defaults(func=cmd_detect)

    # test
    p_test = subparsers.add_parser("test", help="Test WAF with attack payloads")
    p_test.add_argument("target", help="Target URL")
    p_test.add_argument("-c", "--category", help="Payload category (e.g. xss, sqli, ssrf)")
    p_test.add_argument("-p", "--payload-file", help="Specific payload file to use")
    p_test.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    p_test.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    p_test.add_argument("--all", action="store_true", help="Test all payload categories")
    p_test.add_argument("-m", "--max", type=int, default=None, help="Maximum number of payloads to test")
    p_test.add_argument("-o", "--output", default=None, help="Output results JSON file")
    p_test.add_argument("--webhook", default=None, help="Webhook URL for notifications (Slack/Discord/Teams)")
    p_test.set_defaults(func=cmd_test)

    # report
    p_report = subparsers.add_parser("report", help="Generate HTML security report")
    p_report.add_argument("-i", "--input", help="Input results JSON file")
    p_report.add_argument("-o", "--output", default="fray_report.html", help="Output HTML file")
    p_report.add_argument("--sample", action="store_true", help="Generate a sample demo report")
    p_report.set_defaults(func=cmd_report)

    # payloads
    p_payloads = subparsers.add_parser("payloads", help="List available payload categories")
    p_payloads.set_defaults(func=cmd_payloads)

    # version
    p_version = subparsers.add_parser("version", help="Show version")
    p_version.set_defaults(func=cmd_version)

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check environment and auto-fix common issues")
    p_doctor.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")
    p_doctor.add_argument("-v", "--verbose", action="store_true", help="Show detailed fix suggestions")
    p_doctor.set_defaults(func=cmd_doctor)

    # submit-payload
    p_submit = subparsers.add_parser("submit-payload", help="Submit payload to community database via GitHub PR")
    p_submit.add_argument("--payload", default=None, help="Payload string to submit")
    p_submit.add_argument("-c", "--category", default=None, help="Payload category (e.g. xss, sqli)")
    p_submit.add_argument("--subcategory", default=None, help="Subcategory / target file (default: community)")
    p_submit.add_argument("--description", default=None, help="What the payload does")
    p_submit.add_argument("--technique", default=None, help="Technique (e.g. direct_injection, waf_bypass)")
    p_submit.add_argument("--name", default=None, help="Contributor name")
    p_submit.add_argument("--github", default=None, help="Contributor GitHub username")
    p_submit.add_argument("--file", default=None, help="JSON file with payloads for bulk submission")
    p_submit.add_argument("--dry-run", action="store_true", help="Preview without creating PR")
    p_submit.set_defaults(func=cmd_submit_payload)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Start MCP server for AI assistant integration")
    p_mcp.set_defaults(func=cmd_mcp)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
