#!/usr/bin/env python3
"""
Fray CLI — Unified command-line interface

Usage:
    fray detect <url>           Detect WAF vendor
    fray test <url>             Test WAF with payloads
    fray test <url> -c xss      Test specific category
    fray test <url> --smart      Adaptive payload evolution (fewer requests, more impact)
    fray test <url> --webhook <url>  Notify on completion
    fray report                 Generate HTML report
    fray payloads               List available payload categories
    fray doctor                 Check environment + auto-fix issues
    fray submit-payload          Submit payload to community (auto GitHub PR)
    fray ci init                 Generate GitHub Actions WAF test workflow
    fray learn xss               Interactive CTF-style security tutorial
    fray validate <url>          Blue team WAF config validation report
    fray bounty --platform h1    Bug bounty scope auto-fetch + batch test
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
    verify = not getattr(args, 'insecure', False)
    results = detector.detect_waf(args.target, verify_ssl=verify)
    detector.print_results(results)


def cmd_test(args):
    """Run WAF tests against target"""
    from fray.tester import WAFTester
    tester = WAFTester(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not getattr(args, 'insecure', False),
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

    # Adaptive mode: probe → score → test → mutate
    if args.smart:
        from fray.evolve import adaptive_test
        results, stats, profile = adaptive_test(
            tester, all_payloads, max_payloads=args.max or 50
        )
    else:
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


def cmd_validate(args):
    """Validate WAF configuration and generate report"""
    from fray.validate import run_validate
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_validate(
        target=args.target,
        waf=args.waf,
        categories=categories,
        max_payloads=args.max,
        output=args.output,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
    )


def cmd_bounty(args):
    """Run bug bounty scope fetch and batch WAF testing"""
    from fray.bounty import run_bounty
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_bounty(
        platform=args.platform,
        program=args.program,
        urls_file=args.urls,
        categories=categories,
        max_payloads=args.max,
        timeout=args.timeout,
        delay=args.delay,
        output=args.output,
        scope_only=args.scope_only,
        force=args.force,
        smart=not args.no_smart,
    )


def cmd_ci(args):
    """Generate GitHub Actions workflow for automated WAF testing"""
    from fray.ci import run_ci
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_ci(
        action=args.action,
        target=args.target,
        categories=categories,
        max_payloads=args.max,
        webhook=args.webhook,
        fail_on_bypass=args.fail_on_bypass,
        no_comment=args.no_comment,
        minimal=args.minimal,
        output_dir=args.output_dir,
    )


def cmd_learn(args):
    """Start interactive CTF-style security tutorial"""
    from fray.learn import run_learn
    run_learn(
        topic=args.topic,
        level=args.level,
        list_all=args.list,
        reset=args.reset,
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
  fray test https://example.com --category xss --smart
  fray test https://example.com --all
  fray test https://example.com --webhook https://hooks.slack.com/xxx
  fray doctor
  fray doctor --fix
  fray submit-payload
  fray submit-payload --payload '<svg/onload=alert(1)>' --category xss
  fray submit-payload --file my_payloads.json
  fray ci init
  fray ci init --target https://example.com
  fray ci show --minimal
  fray learn
  fray learn xss
  fray learn sqli --level 3
  fray validate https://example.com
  fray validate https://example.com --waf cloudflare -v
  fray bounty --platform hackerone --program github
  fray bounty --urls targets.txt --categories xss,sqli
  fray payloads
  fray report --output report.html

Documentation: https://github.com/dalisecurity/fray
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # detect
    p_detect = subparsers.add_parser("detect", help="Detect WAF vendor on target URL")
    p_detect.add_argument("target", help="Target URL (e.g. https://example.com)")
    p_detect.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
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
    p_test.add_argument("--smart", action="store_true",
                         help="Adaptive payload evolution: probe WAF, skip redundant payloads, mutate bypasses")
    p_test.add_argument("--webhook", default=None, help="Webhook URL for notifications (Slack/Discord/Teams)")
    p_test.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
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

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate WAF configuration (blue team report)")
    p_validate.add_argument("target", help="Target URL to validate")
    p_validate.add_argument("--waf", default=None, help="Expected WAF vendor (e.g. cloudflare, aws_waf, imperva)")
    p_validate.add_argument("--categories", default=None, help="Comma-separated payload categories to test")
    p_validate.add_argument("-m", "--max", type=int, default=10, help="Max payloads per category (default: 10)")
    p_validate.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_validate.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_validate.add_argument("-d", "--delay", type=float, default=0.3, help="Delay between requests (default: 0.3)")
    p_validate.add_argument("-v", "--verbose", action="store_true", help="Show detailed header and bypass info")
    p_validate.set_defaults(func=cmd_validate)

    # bounty
    p_bounty = subparsers.add_parser("bounty", help="Bug bounty platform integration (HackerOne/Bugcrowd)")
    p_bounty.add_argument("--platform", default=None, help="Platform: hackerone or bugcrowd")
    p_bounty.add_argument("--program", default=None, help="Program handle (e.g. github, tesla)")
    p_bounty.add_argument("--urls", default=None, help="Text file with URLs (one per line)")
    p_bounty.add_argument("--categories", default=None, help="Comma-separated payload categories (default: xss,sqli)")
    p_bounty.add_argument("-m", "--max", type=int, default=10, help="Max payloads per category per target (default: 10)")
    p_bounty.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_bounty.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    p_bounty.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_bounty.add_argument("--scope-only", action="store_true", help="Show scope URLs only, don't run tests")
    p_bounty.add_argument("--force", action="store_true", help="Test ALL URLs including shared platforms (dangerous)")
    p_bounty.add_argument("--no-smart", action="store_true",
                          help="Disable adaptive payload evolution (use brute-force instead)")
    p_bounty.set_defaults(func=cmd_bounty)

    # ci
    p_ci = subparsers.add_parser("ci", help="Generate GitHub Actions workflow for WAF testing on PRs")
    p_ci.add_argument("action", nargs="?", default="init", choices=["init", "show"],
                      help="Action: init (write file) or show (print to stdout)")
    p_ci.add_argument("--target", default=None, help="Default target URL for WAF tests")
    p_ci.add_argument("--categories", default=None, help="Comma-separated payload categories (e.g. xss,sqli)")
    p_ci.add_argument("-m", "--max", type=int, default=50, help="Max payloads per run (default: 50)")
    p_ci.add_argument("--webhook", default=None, help="Webhook URL for notifications")
    p_ci.add_argument("--fail-on-bypass", action="store_true", help="Fail CI if any payload bypasses WAF")
    p_ci.add_argument("--no-comment", action="store_true", help="Disable PR comment with results")
    p_ci.add_argument("--minimal", action="store_true", help="Generate minimal workflow")
    p_ci.add_argument("--output-dir", default=None, help="Output directory (default: current dir)")
    p_ci.set_defaults(func=cmd_ci)

    # learn
    p_learn = subparsers.add_parser("learn", help="Interactive CTF-style security tutorial")
    p_learn.add_argument("topic", nargs="?", default=None, help="Topic to learn (xss, sqli, ssrf, cmdi)")
    p_learn.add_argument("--level", type=int, default=None, help="Jump to specific level")
    p_learn.add_argument("--list", action="store_true", help="List all topics and progress")
    p_learn.add_argument("--reset", action="store_true", help="Reset all progress")
    p_learn.set_defaults(func=cmd_learn)

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
