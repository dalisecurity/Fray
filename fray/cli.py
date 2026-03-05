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
    fray stats                  Show payload database statistics
    fray doctor                 Check environment + auto-fix issues
    fray submit-payload          Submit payload to community (auto GitHub PR)
    fray ci init                 Generate GitHub Actions WAF test workflow
    fray learn xss               Interactive CTF-style security tutorial
    fray scan <url>              Auto crawl → param discovery → payload injection
    fray bypass <url> --waf cloudflare -c xss   WAF bypass scoring with evasion scorecard
    fray diff before.json after.json              Compare scans — surface regressions
    fray smuggle <url>           HTTP request smuggling detection (CL.TE / TE.CL)
    fray validate <url>          Blue team WAF config validation report
    fray bounty --platform h1    Bug bounty scope auto-fetch + batch test
    fray explain <CVE-ID>       Explain a CVE — payloads, severity, what to test
    fray demo [url]             Quick showcase: detect WAF + XSS scan (great for GIFs)
    fray version                Show version
"""

import argparse
import json
import sys
from pathlib import Path

from fray import __version__, PAYLOADS_DIR


def _validate_output_path(output: str) -> None:
    """Ensure output path is within the current working directory subtree."""
    resolved = Path(output).resolve()
    cwd = Path.cwd().resolve()
    if not str(resolved).startswith(str(cwd)):
        print(f"Error: Output path '{output}' is outside the current working directory.")
        print(f"  Resolved to: {resolved}")
        print(f"  CWD:         {cwd}")
        print("Use a relative path or a path under your working directory.")
        sys.exit(1)


def build_auth_headers(args) -> dict:
    """Build auth headers from CLI flags: --cookie, --bearer, --header, --login-flow"""
    headers = {}
    if getattr(args, 'cookie', None):
        headers['Cookie'] = args.cookie
    if getattr(args, 'bearer', None):
        headers['Authorization'] = f'Bearer {args.bearer}'
    for h in getattr(args, 'header', None) or []:
        if ':' in h:
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
    if getattr(args, 'login_flow', None):
        session_cookie = _do_login_flow(args.login_flow)
        if session_cookie:
            # Merge with existing cookies
            existing = headers.get('Cookie', '')
            if existing:
                headers['Cookie'] = f"{existing}; {session_cookie}"
            else:
                headers['Cookie'] = session_cookie
    return headers


def _do_login_flow(login_spec: str) -> str:
    """Perform form-based login and return session cookies.

    Format: URL,field=value,field=value
    Example: https://example.com/login,username=admin,password=secret
    """
    import http.client
    import urllib.parse

    parts = login_spec.split(',')
    if len(parts) < 2:
        print("  ⚠️  --login-flow format: URL,field=value,field=value")
        print("     Example: https://example.com/login,username=admin,password=secret")
        return ""

    login_url = parts[0].strip()
    form_data = {}
    for part in parts[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            form_data[k.strip()] = v.strip()

    parsed = urllib.parse.urlparse(login_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/login'
    use_ssl = parsed.scheme == 'https'

    body = urllib.parse.urlencode(form_data)
    req_headers = {
        'Host': host,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(body)),
        'User-Agent': 'Fray Auth',
    }

    try:
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)

        conn.request('POST', path, body=body, headers=req_headers)
        resp = conn.getresponse()
        resp.read()  # consume body

        # Extract Set-Cookie headers
        cookies = []
        for header_name, header_val in resp.getheaders():
            if header_name.lower() == 'set-cookie':
                # Extract cookie name=value (before ;)
                cookie_part = header_val.split(';')[0].strip()
                cookies.append(cookie_part)

        conn.close()

        if cookies:
            cookie_str = '; '.join(cookies)
            print(f"  🔑 Login successful — captured {len(cookies)} session cookie(s)")
            return cookie_str
        else:
            status = resp.status
            print(f"  ⚠️  Login returned HTTP {status} but no Set-Cookie headers")
            print(f"     Try using --cookie directly if you have a session token")
            return ""

    except Exception as e:
        print(f"  ❌ Login flow failed: {e}")
        return ""


def cmd_detect(args):
    """Detect WAF vendor on target"""
    from fray.detector import WAFDetector
    detector = WAFDetector()
    verify = not getattr(args, 'insecure', False)
    results = detector.detect_waf(args.target, verify_ssl=verify)
    detector.print_results(results)


def cmd_test(args):
    """Run WAF tests against target"""
    # Scope validation — block testing if target is out of scope
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  ⛔ Target is OUT OF SCOPE")
            print(f"  {reason}")
            print(f"  Scope file: {scope_file}")
            print(f"\n  Fray will not test targets outside your scope file.")
            sys.exit(1)
        else:
            print(f"  ✅ Target in scope — {reason}")

    from fray.tester import WAFTester
    # Build custom headers from auth flags
    custom_headers = build_auth_headers(args)
    # Redirect policy
    if getattr(args, 'no_follow_redirects', False):
        max_redirects = 0
    else:
        max_redirects = getattr(args, 'redirect_limit', 5) or 5
    tester = WAFTester(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        verbose=getattr(args, 'verbose', False),
        max_redirects=max_redirects,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
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
    elif args.smart:
        # Smart mode: run recon, show results, prompt user before testing
        from fray.recon import run_recon
        print(f"\n🔍 Running reconnaissance on {args.target}...")
        recon = run_recon(args.target, timeout=args.timeout,
                          headers=custom_headers or None)
        fp = recon.get("fingerprint", {})
        techs = fp.get("technologies", {})
        recommended = recon.get("recommended_categories", [])
        hdr = recon.get("headers", {})
        tls = recon.get("tls", {})

        # Show recon summary
        print(f"\n{'─' * 55}")
        print(f"  Target:  {args.target}")
        tls_ver = tls.get("tls_version") or "?"
        print(f"  TLS:     {tls_ver}")
        print(f"  Headers: {hdr.get('score', 0)}%")
        if techs:
            tech_list = ", ".join(f"{t} ({c:.0%})" for t, c in techs.items())
            print(f"  Stack:   {tech_list}")
        else:
            print(f"  Stack:   (not detected)")
        print(f"{'─' * 55}")

        # Build category list with payload counts
        all_categories = sorted([
            d.name for d in PAYLOADS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ])

        def _count_payloads_in_cat(cat_name):
            cat_dir = PAYLOADS_DIR / cat_name
            count = 0
            for pf in cat_dir.glob("*.json"):
                try:
                    data = json.loads(pf.read_text(encoding="utf-8"))
                    plist = data.get("payloads", data) if isinstance(data, dict) else data
                    count += len(plist) if isinstance(plist, list) else 0
                except Exception:
                    pass
            return count

        auto_yes = getattr(args, 'yes', False)

        if recommended:
            print(f"\n  Recommended categories (based on detected stack):\n")
            for i, cat in enumerate(recommended, 1):
                count = _count_payloads_in_cat(cat)
                print(f"    {i}. {cat:<25} ({count} payloads)")
            total_rec = sum(_count_payloads_in_cat(c) for c in recommended)
            total_all = sum(_count_payloads_in_cat(c) for c in all_categories)
            print(f"\n    Total: {total_rec} payloads (vs {total_all} if all categories)")
            print()
            if auto_yes:
                choice = 'y'
                print("  → Auto-accepting recommended categories (-y)")
            else:
                choice = input("  [Y] Run recommended  [A] Run all  [N] Cancel  [1,3,5] Pick: ").strip().lower()
        else:
            print(f"\n  No specific tech detected. All categories available:\n")
            for i, cat in enumerate(all_categories, 1):
                count = _count_payloads_in_cat(cat)
                print(f"    {i}. {cat:<25} ({count} payloads)")
            print()
            if auto_yes:
                choice = 'y'
                print("  → Auto-accepting all categories (-y)")
            else:
                choice = input("  [Y] Run all  [N] Cancel  [1,3,5] Pick specific: ").strip().lower()
            recommended = all_categories  # treat "y" as all for this path

        if choice == 'n' or choice == '':
            print("  Cancelled.")
            sys.exit(0)

        selected_cats = []
        if choice == 'y':
            selected_cats = recommended
        elif choice == 'a':
            selected_cats = all_categories
        else:
            # Parse comma-separated numbers
            try:
                indices = [int(x.strip()) for x in choice.split(",")]
                source = recommended if recommended != all_categories else all_categories
                for idx in indices:
                    if 1 <= idx <= len(source):
                        selected_cats.append(source[idx - 1])
                if not selected_cats:
                    print("  Invalid selection. Cancelled.")
                    sys.exit(1)
            except ValueError:
                print("  Invalid input. Cancelled.")
                sys.exit(1)

        print(f"\n  Loading: {', '.join(selected_cats)}")
        for cat in selected_cats:
            cat_dir = PAYLOADS_DIR / cat
            if cat_dir.is_dir():
                for pf in sorted(cat_dir.glob("*.json")):
                    all_payloads.extend(tester.load_payloads(str(pf)))
    else:
        # Load all payloads
        for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
            if cat_dir.is_dir():
                for pf in sorted(cat_dir.glob("*.json")):
                    all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print("No payloads loaded. Check category name or payload file path.", file=sys.stderr)
        sys.exit(1)

    json_mode = getattr(args, 'json', False)
    if not json_mode:
        print(f"\nLoaded {len(all_payloads)} payloads")

    # Adaptive mode: probe → score → test → mutate
    if args.smart:
        from fray.evolve import adaptive_test
        results, stats, profile = adaptive_test(
            tester, all_payloads, max_payloads=args.max or 50
        )
    else:
        results = tester.test_payloads(all_payloads, max_payloads=args.max,
                                       quiet=json_mode)

    # Build report dict
    from datetime import datetime as _dt
    total = len(results)
    blocked = sum(1 for r in results if r.get('blocked'))
    passed = total - blocked
    duration = "N/A"
    if tester.start_time:
        elapsed = _dt.now() - tester.start_time
        minutes = int(elapsed.total_seconds() // 60)
        seconds = int(elapsed.total_seconds() % 60)
        duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    report = {
        'target': args.target,
        'timestamp': _dt.now().isoformat(),
        'duration': duration,
        'summary': {
            'total': total,
            'blocked': blocked,
            'passed': passed,
            'block_rate': f"{(blocked/total*100):.2f}%" if total > 0 else "0%",
        },
        'results': results,
    }

    # JSON output to stdout
    if getattr(args, 'json', False):
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        # Save results file + rich summary
        output = args.output or "fray_results.json"
        _validate_output_path(output)
        tester.generate_report(results, output=output)
        print(f"\nResults saved to {output}")

    # Also save to file if -o given explicitly (even with --json)
    if getattr(args, 'json', False) and args.output:
        _validate_output_path(args.output)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    # Auto-generate formatted report if requested
    report_fmt = getattr(args, 'report_format', None)
    if report_fmt:
        from fray.reporter import SecurityReportGenerator
        gen = SecurityReportGenerator()
        # Build full result dict for the reporter
        report_data = {
            "target": args.target,
            "results": results,
        }
        if report_fmt == 'markdown':
            report_file = output.replace('.json', '.md')
            gen.generate_markdown_report(report_data, report_file)
        else:
            report_file = output.replace('.json', '.html')
            gen.generate_html_report(report_data, report_file)
        print(f"Report generated: {report_file}")

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
    """Generate HTML or Markdown report from results"""
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
    fmt = getattr(args, 'format', 'html') or 'html'
    if fmt == 'markdown':
        output = args.output.replace('.html', '.md') if args.output.endswith('.html') else args.output
    else:
        output = args.output
    _validate_output_path(output)
    if fmt == 'markdown':
        generator.generate_markdown_report(data, output)
    else:
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


def cmd_scan(args):
    """Auto scan: crawl → param discovery → payload injection."""
    from fray.scanner import run_scan, print_scan_result

    custom_headers = build_auth_headers(args)
    json_mode = getattr(args, 'json', False)

    scan = run_scan(
        target=args.target,
        category=getattr(args, 'category', None) or 'xss',
        max_payloads=args.max,
        max_depth=args.depth,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        quiet=json_mode,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
        scope_file=getattr(args, 'scope', None),
        workers=getattr(args, 'workers', 1),
    )

    if json_mode:
        print(json.dumps(scan.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_scan_result(scan)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(scan.to_dict(), f, indent=2, ensure_ascii=False)
        if not json_mode:
            print(f"\n  Results saved to {args.output}")


def cmd_stats(args):
    """Show payload database statistics"""
    from fray.stats import collect_stats, print_stats
    stats = collect_stats()
    if args.json:
        print(json.dumps(stats.to_dict(), indent=2))
    else:
        print_stats(stats)


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
    if args.output:
        _validate_output_path(args.output)
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
    if args.output:
        _validate_output_path(args.output)
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
        workers=getattr(args, 'workers', 1) or 1,
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


def cmd_recon(args):
    """Run target reconnaissance and fingerprinting"""
    auth_headers = build_auth_headers(args) or None

    # --params mode: standalone parameter mining (brute-force)
    if getattr(args, 'params', False):
        from fray.recon import mine_params, print_mined_params
        result = mine_params(args.target, timeout=getattr(args, 'timeout', 8),
                             extra_headers=auth_headers)
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_mined_params(args.target, result)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    # --history mode: standalone historical URL discovery
    if getattr(args, 'history', False):
        from fray.recon import discover_historical_urls, print_historical_urls
        result = discover_historical_urls(args.target, timeout=getattr(args, 'timeout', 8),
                                          extra_headers=auth_headers)
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_historical_urls(args.target, result)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    # --js mode: standalone JS endpoint extraction
    if getattr(args, 'js', False):
        from fray.recon import discover_js_endpoints, print_js_endpoints
        result = discover_js_endpoints(args.target, timeout=getattr(args, 'timeout', 8),
                                       extra_headers=auth_headers)
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_js_endpoints(args.target, result)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    from fray.recon import run_recon, print_recon
    result = run_recon(args.target, timeout=getattr(args, 'timeout', 8),
                       headers=auth_headers)
    if getattr(args, 'json', False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_recon(result)
    # Save output if requested
    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"  Recon saved to {args.output}")


def cmd_smuggle(args):
    """HTTP request smuggling detection."""
    from fray.smuggling import run_smuggling_detection, print_smuggle_report
    from dataclasses import asdict

    if not args.target:
        print("Error: target URL required. Usage: fray smuggle <url>")
        sys.exit(1)

    report = run_smuggling_detection(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not getattr(args, 'insecure', False),
        verbose=True,
    )

    if getattr(args, 'json', False):
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print_smuggle_report(report)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        print(f"\n  Results saved to {args.output}")

    # Exit code: 1 if vulnerable (CI integration)
    if report.vulnerable:
        sys.exit(1)


def cmd_diff(args):
    """Compare two scan results and surface regressions."""
    from fray.diff import run_diff, print_diff
    from dataclasses import asdict

    diff = run_diff(args.before, args.after)

    if getattr(args, 'json', False):
        print(json.dumps(asdict(diff), indent=2, ensure_ascii=False))
    else:
        print_diff(diff)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(diff), f, indent=2, ensure_ascii=False)
        print(f"\n  Diff saved to {args.output}")

    # Exit code: 1 if regressions found (useful for CI)
    if diff.verdict == "REGRESSED":
        sys.exit(1)


def cmd_bypass(args):
    """WAF bypass scoring — evasion-optimized testing"""
    from fray.tester import WAFTester
    from fray.bypass import run_bypass, resolve_waf_name, WAF_EVASION_HINTS

    # If --list-wafs, just show supported vendors
    if getattr(args, 'list_wafs', False):
        print(f"\nFray v{__version__} — Supported WAF Targets\n")
        for key, info in sorted(WAF_EVASION_HINTS.items()):
            print(f"  {info['label']:<30} --waf {key}")
        print(f"\n  Use: fray bypass <url> --waf <name> -c xss")
        return

    # Scope validation
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  ⛔ Target is OUT OF SCOPE")
            print(f"  {reason}")
            print(f"  Scope file: {scope_file}")
            print(f"\n  Fray will not test targets outside your scope file.")
            sys.exit(1)
        else:
            print(f"  ✅ Target in scope — {reason}")

    # Build tester
    custom_headers = build_auth_headers(args)
    tester = WAFTester(
        target=args.target,
        timeout=getattr(args, 'timeout', 8),
        delay=getattr(args, 'delay', 0.5),
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        verbose=getattr(args, 'verbose', False),
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
    )

    # Load payloads
    all_payloads = []
    if args.category:
        category_dir = PAYLOADS_DIR / args.category
        if not category_dir.exists():
            print(f"Error: Category '{args.category}' not found.")
            print(f"Available: {', '.join(list_categories())}")
            sys.exit(1)
        for pf in sorted(category_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))
    else:
        # Default: load xss payloads (most common bypass target)
        xss_dir = PAYLOADS_DIR / "xss"
        if xss_dir.exists():
            for pf in sorted(xss_dir.glob("*.json")):
                all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print("Error: No payloads loaded. Use -c <category> to specify.")
        sys.exit(1)

    # Auto-inject CSP bypass payloads when weak CSP detected
    csp_injected = 0
    if args.category != "csp_bypass":
        try:
            from fray.csp import get_csp_from_headers, analyze_csp
            import http.client, urllib.parse as _urlparse
            _parsed = _urlparse.urlparse(args.target if args.target.startswith("http") else f"https://{args.target}")
            _host = _parsed.hostname
            _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
            _use_ssl = _parsed.scheme == "https"
            try:
                if _use_ssl:
                    import ssl as _ssl
                    _ctx = _ssl.create_default_context()
                    if getattr(args, 'insecure', False):
                        _ctx.check_hostname = False
                        _ctx.verify_mode = _ssl.CERT_NONE
                    _conn = http.client.HTTPSConnection(_host, _port, context=_ctx, timeout=5)
                else:
                    _conn = http.client.HTTPConnection(_host, _port, timeout=5)
                _conn.request("GET", _parsed.path or "/", headers={"Host": _host})
                _resp = _conn.getresponse()
                _resp.read()
                _hdrs = {k.lower(): v for k, v in _resp.getheaders()}
                _conn.close()
                csp_val, csp_ro = get_csp_from_headers(_hdrs)
                csp_analysis = analyze_csp(csp_val, report_only=csp_ro)
                if csp_analysis.bypass_techniques:
                    csp_dir = PAYLOADS_DIR / "csp_bypass"
                    if csp_dir.exists():
                        technique_set = set(csp_analysis.bypass_techniques)
                        for pf in sorted(csp_dir.glob("*.json")):
                            # Only load payload files matching detected techniques
                            if pf.stem in technique_set:
                                loaded = tester.load_payloads(str(pf))
                                all_payloads.extend(loaded)
                                csp_injected += len(loaded)
            except Exception:
                pass  # CSP probe failed — continue with normal payloads
        except ImportError:
            pass

    loaded_msg = f"\n  Loaded {len(all_payloads)} payloads"
    if csp_injected:
        loaded_msg += f" (including {csp_injected} CSP bypass payloads)"
    print(loaded_msg)

    # Run bypass assessment
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)

    run_bypass(
        tester=tester,
        payloads=all_payloads,
        waf_name=getattr(args, 'waf', None),
        max_payloads=getattr(args, 'max', 50),
        max_mutations=getattr(args, 'mutations', 5),
        mutation_budget=getattr(args, 'mutation_budget', 20),
        param=getattr(args, 'param', 'input'),
        verbose=True,
        output_file=output_file,
        json_output=getattr(args, 'json', False),
        category=getattr(args, 'category', 'xss') or 'xss',
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


def cmd_scope(args):
    """Inspect, validate, or check a target against a scope file"""
    from fray.scope import parse_scope_file, is_target_in_scope, print_scope

    scope = parse_scope_file(args.scope_file)

    if args.check:
        # Check a specific target against scope
        in_scope, reason = is_target_in_scope(args.check, scope)
        if in_scope:
            print(f"\n  ✅ {args.check} is IN SCOPE")
            print(f"  {reason}")
        else:
            print(f"\n  ⛔ {args.check} is OUT OF SCOPE")
            print(f"  {reason}")
        sys.exit(0 if in_scope else 1)

    if args.json:
        print(json.dumps(scope, indent=2, ensure_ascii=False))
    else:
        print_scope(scope, filepath=args.scope_file)


def cmd_explain(args):
    """Explain a CVE — show payloads, affected versions, severity, and what to test"""
    import glob

    query = args.cve_id.upper().strip()
    # Also support partial matches like "log4shell", "react2shell"
    query_lower = args.cve_id.lower().strip()

    matches = []
    for fpath in glob.glob(str(PAYLOADS_DIR / "**" / "*.json"), recursive=True):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for p in data.get("payloads", []):
            cve_field = p.get("cve", "")
            desc = p.get("description", "")
            subcat = p.get("subcategory", "")
            source = p.get("source", "")
            # Match CVE ID, description, subcategory, or source
            if (query in cve_field.upper()
                    or query in desc.upper()
                    or query_lower in subcat.lower()
                    or query_lower in source.lower()
                    or query_lower in desc.lower()):
                matches.append((p, fpath))

    if not matches:
        print(f"\n  No payloads found for '{args.cve_id}'")
        print(f"  Try: fray explain CVE-2021-44228")
        print(f"        fray explain log4shell")
        print(f"        fray explain react2shell")
        sys.exit(1)

    # Group by CVE ID
    by_cve = {}
    for p, fpath in matches:
        key = p.get("cve", p.get("subcategory", "unknown"))
        by_cve.setdefault(key, []).append((p, fpath))

    # Severity colors
    sev_colors = {
        "critical": "\033[91m",  # red
        "high": "\033[93m",      # yellow
        "medium": "\033[33m",    # orange
        "low": "\033[92m",       # green
    }
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"

    print(f"\n{bold}Fray Explain — CVE Intelligence{reset}")
    print("━" * 60)

    for cve_id, items in by_cve.items():
        first = items[0][0]
        severity = first.get("severity", "unknown")
        cvss = first.get("cvss", "N/A")
        affected = first.get("affected_versions", "N/A")
        disclosure = first.get("disclosure_date", "N/A")
        desc = first.get("description", "")
        source_file = str(Path(items[0][1]).relative_to(PAYLOADS_DIR.parent))

        sev_color = sev_colors.get(severity, "")

        print(f"\n  {bold}{cve_id}{reset}")
        print(f"  {desc}")
        print()
        print(f"  {bold}Severity:{reset}     {sev_color}{severity.upper()}{reset} (CVSS {cvss})")
        print(f"  {bold}Affected:{reset}     {affected}")
        print(f"  {bold}Disclosed:{reset}    {disclosure}")
        print(f"  {bold}Payloads:{reset}     {len(items)} available")
        print(f"  {bold}Source:{reset}       {source_file}")

        # Show payloads
        print(f"\n  {bold}Payloads:{reset}")
        show_count = min(len(items), args.max)
        for i, (p, _) in enumerate(items[:show_count]):
            payload_text = p.get("payload", "")
            # Truncate long payloads
            if len(payload_text) > 120:
                payload_text = payload_text[:117] + "..."
            print(f"\n  {dim}#{i+1}{reset} {p.get('description', '')}")
            print(f"     {payload_text}")

        if len(items) > show_count:
            print(f"\n  {dim}... and {len(items) - show_count} more (use --max {len(items)} to see all){reset}")

        # How to run against a target
        cat = first.get("category", "")
        subcat = first.get("subcategory", "")
        cve_str = cve_id if cve_id.startswith("CVE") else ""

        print(f"\n  {bold}How to run against a target:{reset}")
        if "rce" in cat.lower() or "rce" in desc.lower() or "command" in desc.lower():
            print(f"    → Test command execution endpoints, check input sanitization")
        elif "xss" in cat.lower():
            print(f"    → Test reflected/stored XSS vectors in user input fields")
        elif "sqli" in cat.lower() or "sql" in desc.lower():
            print(f"    → Test SQL injection in query parameters and form fields")
        elif "ssrf" in cat.lower():
            print(f"    → Test SSRF in URL parameters, redirects, and webhooks")

        print()
        print(f"    {dim}# Test this CVE's payloads against your target:{reset}")
        print(f"    fray test https://target.com -c {cat} --max {len(items)}")
        print()
        print(f"    {dim}# Smart mode — recon first, then test recommended categories:{reset}")
        print(f"    fray test https://target.com --smart")
        print()
        print(f"    {dim}# Full recon + test workflow:{reset}")
        print(f"    fray recon https://target.com")
        print(f"    fray test https://target.com -c {cat} --max {len(items)} -o results.json")
        print(f"    fray report -i results.json -o report.html")

    total = sum(len(v) for v in by_cve.values())
    print(f"\n{'━' * 60}")
    print(f"  {bold}{total} payload(s){reset} across {bold}{len(by_cve)} CVE(s){reset}")

    if args.json:
        output = []
        for cve_id, items in by_cve.items():
            for p, fpath in items:
                entry = dict(p)
                entry["file"] = str(Path(fpath).relative_to(PAYLOADS_DIR.parent))
                output.append(entry)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            print(f"\n  JSON saved to {args.output}")
        else:
            print(json.dumps(output, indent=2, ensure_ascii=False))


def cmd_demo(args):
    """Quick showcase: detect WAF + XSS scan on a target (great for GIFs/READMEs)."""
    import time
    from fray.detector import WAFDetector
    from fray.scanner import run_scan, print_scan_result

    DEFAULT_TARGET = "http://testphp.vulnweb.com"
    target = getattr(args, 'target', None) or DEFAULT_TARGET

    print(f"\n  ⚔️  Fray v{__version__} — Demo Mode")
    print(f"  {'─' * 50}")
    print(f"  Target: {target}\n")

    # Phase 1: WAF Detection
    print(f"  [1/2] Detecting WAF...")
    detector = WAFDetector()
    try:
        waf = detector.detect_waf(target, verify_ssl=False)
        if waf.get('waf_detected'):
            vendor = waf['waf_vendor']
            conf = waf['confidence']
            print(f"  ✓ WAF Detected: {vendor} ({conf}% confidence)")
            sigs = waf.get('signatures_found', [])
            for sig in sigs[:3]:
                print(f"    • {sig}")
        else:
            print(f"  ✓ WAF: None detected")
    except Exception as e:
        print(f"  ⚠ WAF detection failed: {e}")

    # Phase 2: Quick XSS Scan
    print(f"\n  [2/2] Scanning for XSS bypasses...")
    print()

    scan = run_scan(
        target=target,
        category='xss',
        max_payloads=3,
        max_depth=2,
        max_pages=8,
        delay=0.2,
        timeout=8,
        verify_ssl=False,
        quiet=False,
    )
    print_scan_result(scan)

    # One-line verdict
    r = scan.total_reflected if hasattr(scan, 'total_reflected') else 0
    b = scan.total_blocked if hasattr(scan, 'total_blocked') else 0
    t = scan.total_tested if hasattr(scan, 'total_tested') else 0
    if r > 0:
        print(f"\n  🎯 Found {r} confirmed XSS bypass{'es' if r != 1 else ''} ({b}/{t} blocked)")
    elif b > 0:
        print(f"\n  🛡️  WAF blocked {b}/{t} payloads — no bypasses found")
    else:
        print(f"\n  ✓ Scan complete — {t} payloads tested")

    print(f"\n  Run 'fray scan {target}' for a full assessment.\n")


def cmd_help(args):
    """Friendly high-level guide to every fray command."""
    print(f"""
  ⚔️  Fray v{__version__} — WAF Security Testing Toolkit
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔍 RECON — Know your target
  ─────────────────────────────
  fray recon <url>              Full recon: TLS, headers, DNS, cookies, fingerprint,
                                GraphQL, exposed files, subdomains (19 checks)
  fray recon <url> --js         Extract hidden API endpoints from JavaScript files
  fray recon <url> --history    Discover old URLs via Wayback Machine / sitemap / robots
  fray recon <url> --params     Brute-force 136 common parameter names (?id= ?file= ?redirect=)

  🛡️  DETECT — Identify the WAF
  ─────────────────────────────
  fray detect <url>             Fingerprint WAF vendor (Cloudflare, AWS, Akamai, etc.)

  🎯 SCAN — Automated vulnerability scan
  ─────────────────────────────
  fray scan <url>               Auto crawl → param discovery → payload injection
  fray scan <url> -c sqli       Scan with specific payload category
  fray scan <url> --depth 5     Control crawl depth and scope

  ⚡ TEST — Payload injection
  ─────────────────────────────
  fray test <url> -c xss        Test a specific payload category
  fray test <url> --all         Test ALL 23 payload categories
  fray test <url> --smart       Adaptive mode: probe WAF first, skip redundant payloads

  🔓 BYPASS — WAF evasion scoring
  ─────────────────────────────
  fray bypass <url>             Evasion-optimized testing with bypass scorecard
  fray bypass <url> --waf cloudflare   Target a specific WAF vendor

  🕵️  SMUGGLE — HTTP request smuggling
  ─────────────────────────────
  fray smuggle <url>            Detect CL.TE / TE.CL / TE.TE smuggling vulns

  📊 REPORT — Generate reports
  ─────────────────────────────
  fray report -i results.json   Generate HTML security report
  fray report --sample          Generate a sample demo report

  🔎 OTHER TOOLS
  ─────────────────────────────
  fray payloads                 List all {len(list_categories())} payload categories with counts
  fray validate <url>           Blue team: validate WAF config (defense report)
  fray bounty --platform hackerone   Bug bounty integration
  fray diff before.json after.json   Compare scan results (regression testing)
  fray explain CVE-2021-44228   Explain a CVE with payloads and severity
  fray demo                     Quick showcase: detect WAF + XSS scan
  fray learn xss                Interactive CTF-style security tutorial
  fray ci init                  Generate GitHub Actions workflow for CI/CD
  fray stats                    Payload database statistics
  fray doctor                   Check environment, auto-fix issues

  🔑 AUTHENTICATION (works with any command)
  ─────────────────────────────
  --cookie "session=abc"        Cookie header
  --bearer "eyJ..."             Bearer token
  -H "X-Api-Key: secret"       Custom header (repeatable)
  --login-flow "url,user=x,pass=y"   Auto-login and capture session

  📖 Docs: https://github.com/dalisecurity/fray
  ⚠️  Only test systems you own or have written permission to test.
""")


def cmd_update(args):
    """Update payloads from GitHub"""
    from fray.update import run_update
    run_update(check_only=getattr(args, 'check', False))


def cmd_init_config(args):
    """Create a sample .fray.toml in the current directory"""
    target = Path.cwd() / ".fray.toml"
    if target.exists():
        print(f".fray.toml already exists at {target}")
        sys.exit(1)
    sample = '''\
# Fray configuration file
# CLI arguments always override these defaults.

[test]
timeout = 8
delay = 0.5
# category = "xss"
# insecure = false
# verbose = false
redirect_limit = 5

[test.auth]
# cookie = "session=abc123"
# bearer = "eyJ..."

[bounty]
max = 10
workers = 1
delay = 0.5

[webhook]
# url = "https://hooks.slack.com/services/..."
'''
    target.write_text(sample, encoding="utf-8")
    print(f"Created {target}")
    print("Edit the file to set your defaults, then run fray commands as usual.")


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
  fray explain CVE-2021-44228
  fray explain log4shell
  fray explain react2shell --max 10
  fray recon https://example.com
  fray payloads
  fray report --output report.html

Documentation: https://github.com/dalisecurity/fray
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # recon
    p_recon = subparsers.add_parser("recon", help="Reconnaissance: HTTP, TLS, headers, app fingerprinting")
    p_recon.add_argument("target", help="Target URL (e.g. https://example.com)")
    p_recon.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_recon.add_argument("--json", action="store_true", help="Output raw JSON instead of pretty-print")
    p_recon.add_argument("-o", "--output", default=None, help="Save recon JSON to file")
    p_recon.add_argument("--cookie", default=None, help="Cookie header for authenticated recon")
    p_recon.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_recon.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_recon.add_argument("--login-flow", default=None,
                          help="Form login: 'URL,field=value,field=value' — captures session cookies")
    p_recon.add_argument("--js", action="store_true",
                          help="JS endpoint extraction: find hidden API routes in JavaScript files")
    p_recon.add_argument("--history", action="store_true",
                          help="Historical URL discovery: Wayback Machine, sitemap.xml, robots.txt")
    p_recon.add_argument("--params", action="store_true",
                          help="Parameter mining: brute-force hidden URL parameters (not dir fuzzing)")
    p_recon.set_defaults(func=cmd_recon)

    # detect
    p_detect = subparsers.add_parser("detect", help="Detect WAF vendor on target URL")
    p_detect.add_argument("target", help="Target URL (e.g. https://example.com)")
    p_detect.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    p_detect.add_argument("--cookie", default=None, help="Cookie header for authenticated detection")
    p_detect.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_detect.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_detect.add_argument("--login-flow", default=None,
                           help="Form login: 'URL,field=value,field=value' — captures session cookies")
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
    p_test.add_argument("--cookie", default=None, help="Cookie header value for authenticated scanning")
    p_test.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_test.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_test.add_argument("--login-flow", default=None,
                         help="Form login: 'URL,field=value,field=value' — captures session cookies")
    p_test.add_argument("-v", "--verbose", action="store_true", help="Show raw HTTP request/response for debugging")
    p_test.add_argument("--no-follow-redirects", action="store_true", help="Do not follow HTTP redirects")
    p_test.add_argument("--redirect-limit", type=int, default=5, help="Max redirects to follow (default: 5, 0 = none)")
    p_test.add_argument("--report-format", choices=["html", "markdown"], default=None,
                         help="Auto-generate report in this format after testing")
    p_test.add_argument("-y", "--yes", action="store_true",
                         help="Skip interactive prompt in --smart mode (auto-accept recommendations)")
    p_test.add_argument("--scope", default=None,
                         help="Scope file — only test targets listed in this file (one domain/IP/CIDR per line)")
    p_test.add_argument("--jitter", type=float, default=0.0,
                         help="Random delay variance in seconds added to --delay (e.g. --jitter 1.0)")
    p_test.add_argument("--stealth", action="store_true",
                         help="Stealth mode: randomize User-Agent, add jitter, throttle requests — evade rate limiting")
    p_test.add_argument("--rate-limit", type=float, default=0.0,
                         help="Max requests per second (e.g. --rate-limit 2 = max 2 req/s)")
    p_test.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    p_test.set_defaults(func=cmd_test)

    # bypass
    p_bypass = subparsers.add_parser("bypass",
        help="WAF bypass scoring — evasion-optimized payload testing with scorecard")
    p_bypass.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_bypass.add_argument("--waf", default=None,
                          help="WAF vendor (cloudflare, akamai, aws_waf, imperva, f5, fastly, modsecurity)")
    p_bypass.add_argument("-c", "--category", default=None, help="Payload category (default: xss)")
    p_bypass.add_argument("-m", "--max", type=int, default=50, help="Max payloads to test (default: 50)")
    p_bypass.add_argument("--mutations", type=int, default=5, help="Max mutations per bypass (default: 5)")
    p_bypass.add_argument("--mutation-budget", type=int, default=20,
                          help="Total mutation test budget (default: 20)")
    p_bypass.add_argument("--param", default="input", help="URL parameter to inject into (default: input)")
    p_bypass.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_bypass.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    p_bypass.add_argument("-o", "--output", default=None, help="Save bypass scorecard JSON to file")
    p_bypass.add_argument("--json", action="store_true", help="Output scorecard as JSON to stdout")
    p_bypass.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification")
    p_bypass.add_argument("-v", "--verbose", action="store_true", help="Show raw HTTP requests")
    p_bypass.add_argument("--list-wafs", action="store_true", help="List supported WAF targets and exit")
    p_bypass.add_argument("--scope", default=None,
                          help="Scope file — only test targets in this file")
    p_bypass.add_argument("--cookie", default=None, help="Cookie header for authenticated scanning")
    p_bypass.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_bypass.add_argument("-H", "--header", action="append",
                          help="Custom header (repeatable, format: 'Name: Value')")
    p_bypass.add_argument("--login-flow", default=None,
                          help="Form login: 'URL,field=value,field=value'")
    p_bypass.add_argument("--jitter", type=float, default=0.0,
                          help="Random delay variance in seconds")
    p_bypass.add_argument("--stealth", action="store_true",
                          help="Stealth mode: UA rotation + jitter + throttle")
    p_bypass.add_argument("--rate-limit", type=float, default=0.0,
                          help="Max requests per second")
    p_bypass.set_defaults(func=cmd_bypass)

    # diff
    p_diff = subparsers.add_parser("diff",
        help="Compare two scan results — surface regressions and improvements")
    p_diff.add_argument("before", help="Baseline scan results JSON (before WAF change)")
    p_diff.add_argument("after", help="New scan results JSON (after WAF change)")
    p_diff.add_argument("-o", "--output", default=None, help="Save diff report JSON to file")
    p_diff.add_argument("--json", action="store_true", help="Output diff as JSON to stdout")
    p_diff.set_defaults(func=cmd_diff)

    # smuggle
    p_smuggle = subparsers.add_parser("smuggle",
        help="HTTP request smuggling detection (CL.TE / TE.CL / TE.TE)")
    p_smuggle.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_smuggle.add_argument("-t", "--timeout", type=int, default=10,
                           help="Request timeout in seconds (default: 10)")
    p_smuggle.add_argument("-d", "--delay", type=float, default=1.0,
                           help="Delay between probes (default: 1.0)")
    p_smuggle.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_smuggle.add_argument("--json", action="store_true", help="Output report as JSON")
    p_smuggle.add_argument("--insecure", action="store_true", help="Skip SSL verification")
    p_smuggle.set_defaults(func=cmd_smuggle)

    # report
    p_report = subparsers.add_parser("report", help="Generate HTML security report")
    p_report.add_argument("-i", "--input", help="Input results JSON file")
    p_report.add_argument("-o", "--output", default="fray_report.html", help="Output HTML file")
    p_report.add_argument("--sample", action="store_true", help="Generate a sample demo report")
    p_report.add_argument("--format", choices=["html", "markdown"], default="html", help="Report format (default: html)")
    p_report.set_defaults(func=cmd_report)

    # payloads
    p_payloads = subparsers.add_parser("payloads", help="List available payload categories")
    p_payloads.set_defaults(func=cmd_payloads)

    # scan
    p_scan = subparsers.add_parser("scan",
        help="Auto scan: crawl → param discovery → payload injection")
    p_scan.add_argument("target", help="Target URL to scan")
    p_scan.add_argument("-c", "--category", default="xss",
                         help="Payload category for injection (default: xss)")
    p_scan.add_argument("-m", "--max", type=int, default=5,
                         help="Max payloads per injection point (default: 5)")
    p_scan.add_argument("--depth", type=int, default=3,
                         help="Max crawl depth (default: 3)")
    p_scan.add_argument("--max-pages", type=int, default=30,
                         help="Max pages to crawl (default: 30)")
    p_scan.add_argument("-t", "--timeout", type=int, default=8,
                         help="Request timeout (default: 8)")
    p_scan.add_argument("-d", "--delay", type=float, default=0.3,
                         help="Delay between requests (default: 0.3)")
    p_scan.add_argument("-o", "--output", default=None,
                         help="Save scan results JSON to file")
    p_scan.add_argument("--json", action="store_true",
                         help="Output results as JSON to stdout")
    p_scan.add_argument("--insecure", action="store_true",
                         help="Skip SSL certificate verification")
    p_scan.add_argument("--cookie", default=None,
                         help="Cookie header for authenticated scanning")
    p_scan.add_argument("--bearer", default=None,
                         help="Bearer token for Authorization header")
    p_scan.add_argument("-H", "--header", action="append",
                         help="Custom header (repeatable, format: 'Name: Value')")
    p_scan.add_argument("--jitter", type=float, default=0.0,
                         help="Random delay variance (default: 0)")
    p_scan.add_argument("--stealth", action="store_true",
                         help="Stealth mode: randomize UA, add jitter, throttle")
    p_scan.add_argument("--rate-limit", type=float, default=0.0,
                         help="Max requests per second (default: unlimited)")
    p_scan.add_argument("--scope", default=None,
                         help="Scope file: one domain/IP/CIDR per line (restricts crawl)")
    p_scan.add_argument("-w", "--workers", type=int, default=1,
                         help="Concurrent workers for crawl + injection (default: 1)")
    p_scan.set_defaults(func=cmd_scan)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show payload database statistics")
    p_stats.add_argument("--json", action="store_true", help="Output as JSON")
    p_stats.set_defaults(func=cmd_stats)

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
    p_bounty.add_argument("-w", "--workers", type=int, default=1,
                          help="Parallel workers for multi-target scanning (default: 1)")
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

    # update
    p_update = subparsers.add_parser("update", help="Update payloads from GitHub without reinstalling")
    p_update.add_argument("--check", action="store_true", help="Check for updates without applying")
    p_update.set_defaults(func=cmd_update)

    # init-config
    p_init_config = subparsers.add_parser("init-config", help="Create a sample .fray.toml config file in the current directory")
    p_init_config.set_defaults(func=cmd_init_config)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain a CVE — payloads, severity, affected versions, what to test")
    p_explain.add_argument("cve_id", help="CVE ID or name (e.g. CVE-2021-44228, log4shell, react2shell)")
    p_explain.add_argument("--max", type=int, default=5, help="Max payloads to show per CVE (default: 5)")
    p_explain.add_argument("--json", action="store_true", help="Output as JSON")
    p_explain.add_argument("-o", "--output", help="Save JSON output to file")
    p_explain.set_defaults(func=cmd_explain)

    # scope
    p_scope = subparsers.add_parser("scope", help="Inspect or validate a scope file for bug bounty testing")
    p_scope.add_argument("scope_file", help="Path to scope file (one domain/IP/CIDR per line)")
    p_scope.add_argument("--check", default=None, help="Check if a specific URL is in scope")
    p_scope.add_argument("--json", action="store_true", help="Output parsed scope as JSON")
    p_scope.set_defaults(func=cmd_scope)

    # demo
    p_demo = subparsers.add_parser("demo",
        help="Quick showcase: detect WAF + XSS scan (great for GIFs)")
    p_demo.add_argument("target", nargs="?", default=None,
                         help="Target URL (default: http://testphp.vulnweb.com)")
    p_demo.set_defaults(func=cmd_demo)

    # help
    p_help = subparsers.add_parser("help",
        help="Show friendly guide to all fray commands")
    p_help.set_defaults(func=cmd_help)

    args = parser.parse_args()

    if not args.command:
        cmd_help(None)
        sys.exit(0)

    # Load .fray.toml and apply defaults for the active subcommand
    from fray.config import load_config, apply_config_defaults
    config = load_config()
    if config:
        apply_config_defaults(args, config, args.command)

    args.func(args)


if __name__ == "__main__":
    main()
