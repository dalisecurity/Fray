#!/usr/bin/env python3
"""
SecurityForge CLI — Unified command-line interface

Usage:
    securityforge detect <url>           Detect WAF vendor
    securityforge test <url>             Test WAF with payloads
    securityforge test <url> -c xss      Test specific category
    securityforge report                 Generate HTML report
    securityforge payloads               List available payload categories
    securityforge version                Show version
"""

import argparse
import json
import sys
from pathlib import Path

from securityforge import __version__, PAYLOADS_DIR


def cmd_detect(args):
    """Detect WAF vendor on target"""
    from securityforge.detector import WAFDetector
    detector = WAFDetector()
    results = detector.detect_waf(args.target)
    detector.print_results(results)


def cmd_test(args):
    """Run WAF tests against target"""
    from securityforge.tester import WAFTester
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
    output = args.output or "securityforge_results.json"
    tester.generate_report(results, output=output)
    print(f"\nResults saved to {output}")


def cmd_report(args):
    """Generate HTML report from results"""
    if args.sample:
        from securityforge.reporter import generate_sample_report
        generate_sample_report()
        return

    from securityforge.reporter import SecurityReportGenerator
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
    print(f"\nSecurityForge v{__version__} — Payload Categories\n")
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
    print(f"\nUsage: securityforge test <url> -c <category>")


def cmd_version(args):
    """Show version"""
    print(f"SecurityForge v{__version__}")


def cmd_mcp(args):
    """Start MCP server for AI assistant integration"""
    try:
        from securityforge.mcp_server import main as mcp_main
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
        prog="securityforge",
        description=f"SecurityForge v{__version__} — AI-Powered WAF Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  securityforge detect https://example.com
  securityforge test https://example.com --category xss
  securityforge test https://example.com --all
  securityforge payloads
  securityforge report --output report.html

Documentation: https://github.com/dalisecurity/securityforge
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
    p_test.set_defaults(func=cmd_test)

    # report
    p_report = subparsers.add_parser("report", help="Generate HTML security report")
    p_report.add_argument("-i", "--input", help="Input results JSON file")
    p_report.add_argument("-o", "--output", default="securityforge_report.html", help="Output HTML file")
    p_report.add_argument("--sample", action="store_true", help="Generate a sample demo report")
    p_report.set_defaults(func=cmd_report)

    # payloads
    p_payloads = subparsers.add_parser("payloads", help="List available payload categories")
    p_payloads.set_defaults(func=cmd_payloads)

    # version
    p_version = subparsers.add_parser("version", help="Show version")
    p_version.set_defaults(func=cmd_version)

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
