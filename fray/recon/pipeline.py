"""Recon pipeline — run_recon orchestrator, attack surface summary, and
pretty-print output."""

import random
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fray.recon.http import _parse_url, _http_get, check_http, check_tls
from fray.recon.fingerprint import (
    check_security_headers,
    check_cookies,
    fingerprint_app,
    recommend_categories,
)
from fray.recon.supply_chain import check_frontend_libs
from fray.recon.history import _save_recon_history
from fray.recon.dns import (
    _SUBDOMAIN_WORDLIST_DEEP,
    check_dns,
    check_subdomains_crt,
    check_subdomains_bruteforce,
    discover_origin_ip,
)
from fray.recon.checks import (
    check_robots_sitemap,
    check_cors,
    check_exposed_files,
    check_http_methods,
    check_error_page,
    check_graphql_introspection,
    check_api_discovery,
    check_host_header_injection,
    check_admin_panels,
    check_rate_limits,
    check_differential_responses,
    waf_gap_analysis,
)
from fray.recon.discovery import (
    discover_historical_urls,
    discover_params,
)


# ── Full recon pipeline ──────────────────────────────────────────────────

def run_recon(url: str, timeout: int = 8,
              headers: Optional[Dict[str, str]] = None,
              mode: str = "default",
              stealth: bool = False,
              retirejs: bool = False) -> Dict[str, Any]:
    """Run full reconnaissance on a target URL.

    Args:
        url: Target URL
        timeout: Request timeout in seconds
        headers: Extra HTTP headers for authenticated scanning (Cookie, Authorization, etc.)
        mode: Scan depth — 'fast' (~15s, core checks only),
              'default' (~30s, full scan), or 'deep' (~45s, extended DNS/subdomain/history)
        stealth: If True, limit parallel workers to 3 and add random jitter
                 between requests to avoid triggering WAF rate limits.
    """
    host, path, port, use_ssl = _parse_url(url)

    is_fast = mode == "fast"
    is_deep = mode == "deep"

    result: Dict[str, Any] = {
        "target": url,
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "stealth": stealth,
        "authenticated": bool(headers),
        "http": {},
        "tls": {},
        "headers": {},
        "csp": {},
        "cookies": {},
        "fingerprint": {},
        "dns": {},
        "robots": {},
        "cors": {},
        "exposed_files": {},
        "http_methods": {},
        "error_page": {},
        "subdomains": {},
        "recommended_categories": [],
    }

    # ── Phase 1: Parallel initial network I/O (steps 1-3, 8a, 8b, 9) ──
    # These are independent network calls; running them concurrently saves ~12-15s.
    import concurrent.futures

    phase1_workers = 3 if stealth else 6

    def _p1_http():
        return check_http(host, timeout=timeout)

    def _p1_tls():
        if use_ssl or port == 443:
            return check_tls(host, port=port, timeout=timeout)
        return {}

    def _p1_page():
        return _http_get(host, port, path, use_ssl, timeout=timeout,
                         extra_headers=headers)

    def _p1_dns():
        return check_dns(host, deep=is_deep)

    def _p1_robots():
        return check_robots_sitemap(host, port, use_ssl, timeout=timeout)

    def _p1_cors():
        return check_cors(host, port, use_ssl, timeout=timeout)

    phase1_tasks = {
        "http": _p1_http,
        "tls": _p1_tls,
        "page": _p1_page,
        "dns": _p1_dns,
        "robots": _p1_robots,
        "cors": _p1_cors,
    }

    phase1_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=phase1_workers) as pool:
        futures = {pool.submit(fn): key for key, fn in phase1_tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                phase1_results[key] = future.result()
            except Exception:
                phase1_results[key] = {} if key != "page" else (0, {}, "")

    # Unpack phase 1 results
    result["http"] = phase1_results.get("http", {})
    result["tls"] = phase1_results.get("tls", {})

    page_result = phase1_results.get("page", (0, {}, ""))
    status, resp_headers, body = page_result if isinstance(page_result, tuple) else (0, {}, "")
    result["page_status"] = status

    result["dns"] = phase1_results.get("dns", {})
    result["robots"] = phase1_results.get("robots", {})
    result["cors"] = phase1_results.get("cors", {})

    # ── Phase 1b: CPU-only analysis derived from page fetch (no network) ──

    # 4. Security headers
    result["headers"] = check_security_headers(resp_headers)

    # 5. CSP analysis
    from fray.csp import get_csp_from_headers, analyze_csp
    csp_value, csp_report_only = get_csp_from_headers(resp_headers)
    csp_analysis = analyze_csp(csp_value, report_only=csp_report_only)
    result["csp"] = {
        "present": csp_analysis.present,
        "report_only": csp_analysis.report_only,
        "score": csp_analysis.score,
        "weaknesses": [{"id": w.id, "severity": w.severity, "directive": w.directive,
                        "description": w.description} for w in csp_analysis.weaknesses],
        "bypass_techniques": csp_analysis.bypass_techniques,
        "recommendations": csp_analysis.recommendations,
    }

    # 6. Cookie security audit
    result["cookies"] = check_cookies(resp_headers)

    # 7. App fingerprinting
    result["fingerprint"] = fingerprint_app(resp_headers, body)

    # 7b. Frontend library supply chain check (CPU-only, no network)
    result["frontend_libs"] = check_frontend_libs(body, retirejs=retirejs)

    # ── Phase 2: Parallel network checks (steps 10-22) ──
    # These checks are independent and can safely run concurrently.

    # Stealth mode: fewer workers + jitter to avoid WAF rate-limit triggers
    max_workers = 3 if stealth else 13

    def _stealth_wrap(fn):
        """Wrap a task function to add random jitter in stealth mode."""
        if not stealth:
            return fn
        def wrapped():
            time.sleep(random.uniform(0.5, 1.5))
            return fn()
        return wrapped

    dns_data = result.get("dns", {})
    parent_cdn = dns_data.get("cdn_detected")
    parent_ips = dns_data.get("a", [])
    verify = use_ssl

    # Core tasks — always run
    parallel_tasks = {
        "exposed_files": lambda: check_exposed_files(host, port, use_ssl, timeout=timeout),
        "http_methods": lambda: check_http_methods(host, port, use_ssl, timeout=timeout),
        "error_page": lambda: check_error_page(host, port, use_ssl, timeout=timeout),
        "subdomains": lambda: check_subdomains_crt(host, timeout=timeout),
        "subdomains_active": lambda: check_subdomains_bruteforce(
            host, timeout=3.0, parent_ips=parent_ips or None, parent_cdn=parent_cdn,
            wordlist=_SUBDOMAIN_WORDLIST_DEEP if is_deep else None),
        "origin_ip": lambda: discover_origin_ip(
            host, timeout=4.0 if is_deep else 3.0, dns_data=dns_data,
            tls_data=result.get("tls"), parent_cdn=parent_cdn),
        "params": lambda: discover_params(url, max_depth=2, max_pages=10,
                                           timeout=timeout, verify_ssl=verify,
                                           extra_headers=headers),
        "api_discovery": lambda: check_api_discovery(host, port, use_ssl,
                                                      timeout=timeout,
                                                      extra_headers=headers),
        "host_header_injection": lambda: check_host_header_injection(
            host, port, use_ssl, timeout=timeout, extra_headers=headers),
    }

    # Skipped in fast mode — slow external APIs and large path lists
    if not is_fast:
        parallel_tasks["historical_urls"] = lambda: discover_historical_urls(
            url, timeout=timeout, verify_ssl=verify, extra_headers=headers,
            wayback_limit=500 if is_deep else 200)
        parallel_tasks["admin_panels"] = lambda: check_admin_panels(
            host, port, use_ssl, timeout=timeout, extra_headers=headers)
        parallel_tasks["rate_limits"] = lambda: check_rate_limits(
            host, port, use_ssl, timeout=timeout, extra_headers=headers)
        parallel_tasks["graphql"] = lambda: check_graphql_introspection(
            host, port, use_ssl, timeout=timeout, extra_headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_stealth_wrap(fn)): key for key, fn in parallel_tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                result[key] = future.result()
            except Exception:
                result[key] = {}

    # Merge active subdomain discoveries into passive list (dedup)
    passive_subs = set(result["subdomains"].get("subdomains", []))
    active_subs = {e["subdomain"] for e in result["subdomains_active"].get("discovered", [])}
    merged = sorted(passive_subs | active_subs)
    result["subdomains"]["subdomains"] = merged[:200]
    result["subdomains"]["count"] = len(passive_subs | active_subs)
    result["subdomains"]["passive_count"] = len(passive_subs)
    result["subdomains"]["active_count"] = len(active_subs)

    # 14. Smart payload recommendation
    result["recommended_categories"] = recommend_categories(result["fingerprint"])

    # 15. Add csp_bypass to recommendations if weak CSP detected
    if csp_analysis.bypass_techniques:
        if "csp_bypass" not in result["recommended_categories"]:
            result["recommended_categories"].insert(0, "csp_bypass")

    # 23. Differential response analysis (WAF detection mode) — sequential, sends attack probes
    if stealth:
        time.sleep(random.uniform(1.0, 2.0))
    result["differential"] = check_differential_responses(host, port, use_ssl,
                                                           timeout=timeout,
                                                           extra_headers=headers)

    # 24. WAF rule gap analysis (cross-reference vendor against waf_intel)
    result["gap_analysis"] = waf_gap_analysis(recon_result=result)

    # Merge gap analysis recommended categories into main recommendations
    gap_cats = result.get("gap_analysis", {}).get("recommended_categories", [])
    for cat in gap_cats:
        if cat not in result["recommended_categories"]:
            result["recommended_categories"].append(cat)

    # Add prototype_pollution to recommendations if Node.js detected
    fp_techs = result.get("fingerprint", {}).get("technologies", {})
    if any(t in fp_techs for t in ("node.js", "express")):
        if "prototype_pollution" not in result["recommended_categories"]:
            result["recommended_categories"].append("prototype_pollution")

    # 25. Attack surface summary
    result["attack_surface"] = _build_attack_surface_summary(result)

    # Auto-save for --compare history
    _save_recon_history(result)

    return result


def _build_attack_surface_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate all recon findings into a compact attack surface overview."""
    host = r.get("host", "")

    # ── Subdomains ──
    subs = r.get("subdomains", {})
    subdomain_list = subs.get("subdomains", [])
    n_subdomains = len(subdomain_list) if isinstance(subdomain_list, list) else 0

    # Detect staging / dev / internal environments
    staging_keywords = ("dev", "staging", "stage", "test", "qa", "uat", "sandbox",
                        "beta", "alpha", "preprod", "pre-prod", "demo", "internal",
                        "admin", "debug", "canary", "preview")
    staging_envs = []
    for sub in subdomain_list:
        name = sub if isinstance(sub, str) else sub.get("name", "") if isinstance(sub, dict) else ""
        name_lower = name.lower()
        for kw in staging_keywords:
            if kw in name_lower:
                staging_envs.append(name)
                break

    # ── Admin panels ──
    panels = r.get("admin_panels", {})
    panel_list = panels.get("panels", []) if isinstance(panels, dict) else []
    n_panels = len(panel_list)
    open_panels = [p for p in panel_list if isinstance(p, dict) and p.get("protected") is False]

    # ── GraphQL ──
    gql = r.get("graphql", {})
    gql_endpoints = gql.get("endpoints_found", [])
    gql_introspection = gql.get("introspection_enabled", False)

    # ── API endpoints ──
    api = r.get("api_discovery", {})
    api_specs = api.get("specs_found", []) if isinstance(api, dict) else []
    api_endpoints = api.get("endpoints_found", []) if isinstance(api, dict) else []

    # ── Exposed files ──
    exposed = r.get("exposed_files", {})
    exposed_list = exposed.get("found", []) if isinstance(exposed, dict) else []
    n_exposed = len(exposed_list)

    # ── Parameters ──
    params = r.get("params", {})
    param_list = params.get("params", []) if isinstance(params, dict) else []
    n_params = len(param_list)
    high_risk_params = [p for p in param_list if isinstance(p, dict) and p.get("risk") == "HIGH"]

    # ── Historical URLs ──
    hist = r.get("historical_urls", {})
    hist_urls = hist.get("urls", []) if isinstance(hist, dict) else []
    n_historical = len(hist_urls)
    interesting_hist = [u for u in hist_urls if isinstance(u, dict) and u.get("interesting")]

    # ── Technologies ──
    fp = r.get("fingerprint", {})
    techs = fp.get("technologies", {}) if isinstance(fp, dict) else {}
    tech_names = sorted(techs.keys()) if techs else []

    # ── WAF ──
    gap = r.get("gap_analysis", {})
    waf_vendor = gap.get("waf_vendor") if isinstance(gap, dict) else None
    diff = r.get("differential", {})
    detection_mode = diff.get("detection_mode") if isinstance(diff, dict) else None

    # ── DNS / CDN ──
    dns_info = r.get("dns", {})
    cdn = dns_info.get("cdn_detected") if isinstance(dns_info, dict) else None

    # ── TLS ──
    tls = r.get("tls", {})
    tls_version = tls.get("tls_version") if isinstance(tls, dict) else None
    cert_days = tls.get("cert_days_left") if isinstance(tls, dict) else None

    # ── Security headers score ──
    hdrs = r.get("headers", {})
    hdr_score = hdrs.get("score") if isinstance(hdrs, dict) else None

    # ── CSP ──
    csp = r.get("csp", {})
    csp_present = csp.get("present", False) if isinstance(csp, dict) else False
    csp_score = csp.get("score") if isinstance(csp, dict) else None

    # ── CORS ──
    cors = r.get("cors", {})
    cors_vuln = cors.get("vulnerable", False) if isinstance(cors, dict) else False

    # ── Host header injection ──
    hhi = r.get("host_header_injection", {})
    hhi_vuln = hhi.get("vulnerable", False) if isinstance(hhi, dict) else False

    # ── Robots interesting paths ──
    robots = r.get("robots", {})
    interesting_paths = robots.get("interesting_paths", []) if isinstance(robots, dict) else []

    # ── HTTP methods ──
    methods = r.get("http_methods", {})
    dangerous_methods = methods.get("dangerous", []) if isinstance(methods, dict) else []

    # ── WAF bypass subdomains ──
    active_subs = r.get("subdomains_active", {})
    waf_bypass_subs = active_subs.get("waf_bypass", []) if isinstance(active_subs, dict) else []
    n_waf_bypass = len(waf_bypass_subs)

    # ── Origin IP discovery ──
    origin_data = r.get("origin_ip", {})
    origin_exposed = origin_data.get("origin_exposed", False) if isinstance(origin_data, dict) else False
    n_origin_candidates = len(origin_data.get("candidates", [])) if isinstance(origin_data, dict) else 0
    n_origin_verified = len(origin_data.get("verified", [])) if isinstance(origin_data, dict) else 0

    # ── Frontend library vulnerabilities ──
    fl = r.get("frontend_libs", {})
    fl_vulns = fl.get("vulnerabilities", []) if isinstance(fl, dict) else []
    n_vuln_libs = fl.get("vulnerable_libs", 0) if isinstance(fl, dict) else 0
    critical_cves = [v for v in fl_vulns if v.get("severity") in ("critical", "high")]
    n_sri_missing = fl.get("sri_missing", 0) if isinstance(fl, dict) else 0

    # ── Build findings list (for quick scan) ──
    findings = []
    if critical_cves:
        cve_ids = [v["id"] for v in critical_cves[:3]]
        findings.append({"severity": "high", "finding": f"{len(critical_cves)} high/critical CVE(s) in frontend libs: {', '.join(cve_ids)}"})
    elif n_vuln_libs > 0:
        findings.append({"severity": "medium", "finding": f"{n_vuln_libs} frontend lib(s) with known CVEs"})
    if origin_exposed:
        verified_ips = [v["ip"] for v in origin_data.get("verified", [])[:3]]
        findings.append({"severity": "critical", "finding": f"Origin IP exposed \u2014 WAF completely bypassable via {', '.join(verified_ips)}"})
    elif n_origin_candidates > 0:
        findings.append({"severity": "high", "finding": f"{n_origin_candidates} origin IP candidate(s) found (unverified)"})
    if n_waf_bypass > 0:
        bypass_names = [e["subdomain"] for e in waf_bypass_subs[:3]]
        findings.append({"severity": "critical", "finding": f"{n_waf_bypass} subdomain(s) bypass WAF (direct origin IP): {', '.join(bypass_names)}"})
    if open_panels:
        findings.append({"severity": "critical", "finding": f"{len(open_panels)} admin panel(s) OPEN (no auth)"})
    if hhi_vuln:
        findings.append({"severity": "high", "finding": "Host header injection detected"})
    if cors_vuln:
        findings.append({"severity": "high", "finding": "CORS misconfiguration"})
    if gql_introspection:
        findings.append({"severity": "high", "finding": "GraphQL introspection enabled"})
    if dangerous_methods:
        findings.append({"severity": "medium", "finding": f"Dangerous HTTP methods: {', '.join(dangerous_methods)}"})
    if n_exposed > 0:
        findings.append({"severity": "medium", "finding": f"{n_exposed} exposed sensitive file(s)"})
    if high_risk_params:
        findings.append({"severity": "medium", "finding": f"{len(high_risk_params)} HIGH-risk injectable parameter(s)"})
    if staging_envs:
        envs_str = ", ".join(staging_envs[:5])
        findings.append({"severity": "medium", "finding": f"Staging/dev environment(s): {envs_str}"})
    if not csp_present:
        findings.append({"severity": "low", "finding": "No Content-Security-Policy header"})
    if cert_days is not None and cert_days < 30:
        findings.append({"severity": "medium", "finding": f"TLS certificate expires in {cert_days} days"})
    if n_sri_missing > 0:
        findings.append({"severity": "medium", "finding": f"{n_sri_missing} CDN-loaded script(s) missing Subresource Integrity (SRI)"})
    if interesting_paths:
        findings.append({"severity": "low", "finding": f"{len(interesting_paths)} interesting paths in robots.txt"})

    # ── Risk score (0-100) ──
    risk_score = 0
    for f in findings:
        if f["severity"] == "critical": risk_score += 25
        elif f["severity"] == "high": risk_score += 15
        elif f["severity"] == "medium": risk_score += 8
        elif f["severity"] == "low": risk_score += 3
    risk_score = min(risk_score, 100)

    # Factor in WAF presence
    if waf_vendor:
        risk_score = max(0, risk_score - 10)
    else:
        risk_score = min(100, risk_score + 15)

    # Risk level
    if risk_score >= 60:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "subdomains": n_subdomains,
        "staging_envs": staging_envs,
        "admin_panels": n_panels,
        "open_admin_panels": len(open_panels),
        "graphql_endpoints": len(gql_endpoints),
        "graphql_introspection": gql_introspection,
        "api_specs": len(api_specs),
        "api_endpoints": len(api_endpoints),
        "exposed_files": n_exposed,
        "injectable_params": n_params,
        "high_risk_params": len(high_risk_params),
        "historical_urls": n_historical,
        "interesting_historical": len(interesting_hist),
        "technologies": tech_names,
        "waf_vendor": waf_vendor,
        "waf_detection_mode": detection_mode,
        "cdn": cdn,
        "tls_version": tls_version,
        "cert_days_left": cert_days,
        "security_headers_score": hdr_score,
        "csp_present": csp_present,
        "csp_score": csp_score,
        "cors_vulnerable": cors_vuln,
        "host_header_injection": hhi_vuln,
        "dangerous_http_methods": dangerous_methods,
        "robots_interesting_paths": len(interesting_paths),
        "waf_bypass_subdomains": n_waf_bypass,
        "origin_ip_exposed": origin_exposed,
        "origin_ip_candidates": n_origin_candidates,
        "origin_ip_verified": n_origin_verified,
        "vulnerable_frontend_libs": n_vuln_libs,
        "frontend_cves": len(fl_vulns),
        "frontend_critical_cves": len(critical_cves),
        "sri_missing": n_sri_missing,
        "findings": findings,
    }


def print_recon(result: Dict[str, Any]) -> None:
    """Pretty-print recon results to terminal with rich formatting."""
    from fray.output import console, print_header, severity_style
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    def _score_color(score, max_val=100):
        pct = score / max_val * 100 if max_val else 0
        if pct >= 70: return "green"
        if pct >= 40: return "yellow"
        return "red"

    print_header("Fray Recon \u2014 Target Reconnaissance", target=result['target'])
    scan_mode = result.get("mode", "default")
    mode_labels = {"fast": "[yellow]fast[/yellow]", "deep": "[cyan]deep[/cyan]", "default": "[dim]default[/dim]"}
    stealth_tag = "  [red]stealth[/red]" if result.get("stealth") else ""
    console.print(f"  Host: {result['host']}    Mode: {mode_labels.get(scan_mode, scan_mode)}{stealth_tag}")
    console.print()

    # ── Attack Surface Summary ──
    atk = result.get("attack_surface", {})
    if atk:
        risk_level = atk.get("risk_level", "?")
        risk_score = atk.get("risk_score", 0)
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        rc = risk_colors.get(risk_level, "dim")

        console.print(f"  [bold]Attack Surface Summary[/bold]  [{rc}]{risk_level} ({risk_score}/100)[/{rc}]")
        console.print()

        # Row 1: Infrastructure
        waf = atk.get("waf_vendor")
        cdn = atk.get("cdn")
        tls_v = atk.get("tls_version", "?")
        waf_s = f"[green]{waf}[/green]" if waf else "[red]None[/red]"
        cdn_s = f"[cyan]{cdn}[/cyan]" if cdn else "[dim]none[/dim]"
        console.print(f"    WAF: {waf_s}    CDN: {cdn_s}    TLS: {tls_v}")

        # Row 2: Technologies
        techs = atk.get("technologies", [])
        if techs:
            tech_str = ", ".join(techs[:8])
            suffix = "..." if len(techs) > 8 else ""
            console.print(f"    Stack: [dim]{tech_str}{suffix}[/dim]")

        console.print()

        # Row 3: Surface area counts (table-style)
        counts = []
        n_subs = atk.get("subdomains", 0)
        if n_subs:
            counts.append(f"[cyan]{n_subs}[/cyan] subdomains")
        n_panels = atk.get("admin_panels", 0)
        n_open = atk.get("open_admin_panels", 0)
        if n_panels:
            panel_s = f"[red]{n_panels} ({n_open} OPEN)[/red]" if n_open else f"[cyan]{n_panels}[/cyan]"
            counts.append(f"{panel_s} admin panels")
        n_gql = atk.get("graphql_endpoints", 0)
        if n_gql:
            intro = " [red](introspection ON)[/red]" if atk.get("graphql_introspection") else ""
            counts.append(f"[cyan]{n_gql}[/cyan] GraphQL endpoints{intro}")
        n_api_specs = atk.get("api_specs", 0)
        n_api_ep = atk.get("api_endpoints", 0)
        if n_api_specs or n_api_ep:
            counts.append(f"[cyan]{n_api_specs}[/cyan] API specs \u00b7 [cyan]{n_api_ep}[/cyan] endpoints")
        n_exposed = atk.get("exposed_files", 0)
        if n_exposed:
            counts.append(f"[yellow]{n_exposed}[/yellow] exposed files")
        n_params = atk.get("injectable_params", 0)
        n_hi = atk.get("high_risk_params", 0)
        if n_params:
            param_s = f"[red]{n_params} ({n_hi} HIGH)[/red]" if n_hi else f"[cyan]{n_params}[/cyan]"
            counts.append(f"{param_s} injectable params")
        n_hist = atk.get("historical_urls", 0)
        n_int = atk.get("interesting_historical", 0)
        if n_hist:
            counts.append(f"[dim]{n_hist}[/dim] historical URLs ({n_int} interesting)")

        if counts:
            for c in counts:
                console.print(f"    {c}")
            console.print()

        # Row 4: Staging / dev environments
        staging = atk.get("staging_envs", [])
        if staging:
            console.print(f"    [yellow]Staging/dev environments:[/yellow]")
            for s in staging[:10]:
                console.print(f"      [yellow]\u2192 {s}[/yellow]")
            if len(staging) > 10:
                console.print(f"      [dim]... and {len(staging) - 10} more[/dim]")
            console.print()

        # Row 5: Key findings (severity-ordered)
        findings = atk.get("findings", [])
        if findings:
            console.print("    [bold]Key Findings[/bold]")
            sev_icons = {"critical": "[bold red]\u2298 CRITICAL[/bold red]",
                         "high": "[red]\u25b2 HIGH[/red]",
                         "medium": "[yellow]\u25cf MEDIUM[/yellow]",
                         "low": "[dim]\u25cb LOW[/dim]"}
            for f in findings:
                icon = sev_icons.get(f["severity"], "[dim]?[/dim]")
                console.print(f"      {icon}  {f['finding']}")
            console.print()

        console.print("  " + "\u2500" * 60)
        console.print()

    # ── HTTP ──
    http = result.get("http", {})
    port80 = http.get("port_80_open", False)
    redir = http.get("redirects_to_https", False)
    console.print("  [bold]HTTP[/bold]")
    p80 = "[yellow]\u26a0 OPEN[/yellow]" if port80 else "[dim]closed[/dim]"
    redir_s = "[green]\u2705[/green]" if redir else ("[red]\u274c[/red]" if port80 else "[dim]N/A[/dim]")
    console.print(f"    Port 80:            {p80}")
    console.print(f"    Redirects to HTTPS: {redir_s}")
    if port80 and not redir:
        console.print("    [red]\u26a0 HTTP traffic is not redirected to HTTPS![/red]")
    console.print()

    # ── TLS ──
    tls = result.get("tls", {})
    if tls and not tls.get("error"):
        v = str(tls.get("tls_version", "?"))
        vc = "green" if "1.3" in v else ("yellow" if "1.2" in v else "red")
        console.print("  [bold]TLS[/bold]")
        console.print(f"    Version:  [{vc}]{v}[/{vc}]")
        console.print(f"    Cipher:   {tls.get('cipher', '?')} ({tls.get('cipher_bits', '?')} bits)")
        console.print(f"    Subject:  {tls.get('cert_subject', '?')}")
        console.print(f"    Issuer:   {tls.get('cert_issuer', '?')}")
        days = tls.get("cert_days_remaining")
        if days is not None:
            if days < 0:
                console.print(f"    Expiry:   [red]EXPIRED ({abs(days)} days ago)[/red]")
            elif days < 30:
                console.print(f"    Expiry:   [yellow]{days} days remaining[/yellow]")
            else:
                console.print(f"    Expiry:   [green]{days} days remaining[/green]")
        if tls.get("supports_tls_1_0"):
            console.print("    [red]\u26a0 TLS 1.0 supported (insecure)[/red]")
        if tls.get("supports_tls_1_1"):
            console.print("    [red]\u26a0 TLS 1.1 supported (deprecated)[/red]")
        console.print()
    elif tls and tls.get("error"):
        console.print("  [bold]TLS[/bold]")
        console.print(f"    [red]Error: {tls['error']}[/red]")
        console.print()

    # ── Security Headers ──
    hdr = result.get("headers", {})
    score = hdr.get("score", 0)
    sc = _score_color(score)
    console.print(f"  [bold]Security Headers[/bold] ([{sc}]{score}%[/{sc}])")

    hdr_table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    hdr_table.add_column("Icon", width=4)
    hdr_table.add_column("Header", min_width=30)
    hdr_table.add_column("Detail", min_width=20)

    for name, info in hdr.get("present", {}).items():
        hdr_table.add_row("[green]\u2705[/green]", name, f"[dim]{info['value'][:55]}[/dim]")
    for name, info in hdr.get("missing", {}).items():
        sev = info.get("severity", "low")
        hdr_table.add_row("[red]\u274c[/red]", name, f"[{severity_style(sev)}]({sev})[/{severity_style(sev)}]")

    console.print(hdr_table)
    console.print()

    # ── CSP Analysis ──
    csp = result.get("csp", {})
    if csp:
        csp_score = csp.get("score", 0)
        cc = _score_color(csp_score)
        label = "CSP Analysis"
        if csp.get("report_only"):
            label += " [yellow](report-only \u2014 NOT enforced)[/yellow]"
        console.print(f"  [bold]{label}[/bold] ([{cc}]{csp_score}/100[/{cc}])")
        if not csp.get("present"):
            console.print("    [red]\u274c No Content-Security-Policy header[/red]")
        else:
            for w in csp.get("weaknesses", []):
                sev = w.get("severity", "low")
                ss = severity_style(sev)
                console.print(f"    [{ss}]\u26a0 \\[{w['directive']}] {w['description']}[/{ss}]")
            if csp.get("bypass_techniques"):
                bt_str = ", ".join(csp["bypass_techniques"])
                console.print(f"    [cyan]Testable bypass techniques: {bt_str}[/cyan]")
            for rec in csp.get("recommendations", []):
                console.print(f"    [dim]\U0001f4a1 {rec}[/dim]")
        console.print()

    # ── Cookies ──
    ck = result.get("cookies", {})
    cookies = ck.get("cookies", [])
    issues = ck.get("issues", [])
    if cookies:
        ck_score = ck.get("score", 100)
        ckc = _score_color(ck_score)
        console.print(f"  [bold]Cookies[/bold] ([{ckc}]{ck_score}%[/{ckc}])")

        cookie_table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
        cookie_table.add_column("Name", min_width=25)
        cookie_table.add_column("Flags", min_width=30)

        for c in cookies:
            flags = []
            flags.append("[green]HttpOnly[/green]" if c.get("httponly") else "[red]HttpOnly[/red]")
            flags.append("[green]Secure[/green]" if c.get("secure") else "[red]Secure[/red]")
            ss = c.get("samesite")
            if ss and ss is not True:
                flags.append(f"[green]SameSite={ss}[/green]")
            elif ss is True:
                flags.append("[green]SameSite[/green]")
            else:
                flags.append("[red]SameSite[/red]")
            cookie_table.add_row(f"    {c['name']}", " \u2502 ".join(flags))

        console.print(cookie_table)
        if issues:
            console.print()
            for iss in issues:
                sev = iss["severity"]
                ss = severity_style(sev)
                console.print(f"    [{ss}]\u26a0 {iss['cookie']}: {iss['issue']}[/{ss}]")
                console.print(f"      [dim]{iss['risk']}[/dim]")
        console.print()

    # ── Fingerprint ──
    fp = result.get("fingerprint", {})
    techs = fp.get("technologies", {})
    console.print("  [bold]Detected Technologies[/bold]")
    if techs:
        for tech, conf in techs.items():
            bar_len = int(conf * 20)
            bar = "\u2588" * bar_len + "\u2591" * (20 - bar_len)
            bc = "green" if conf >= 0.7 else ("yellow" if conf >= 0.4 else "dim")
            console.print(f"    {tech:<16} [{bc}]{bar} {conf:.0%}[/{bc}]")
    else:
        console.print("    [dim]No technologies identified[/dim]")
    console.print()

    # ── Frontend Libraries (Supply Chain) ──
    fl = result.get("frontend_libs", {})
    fl_libs = fl.get("libraries", [])
    fl_vulns = fl.get("vulnerabilities", [])
    if fl_libs:
        vuln_count = fl.get("vulnerable_libs", 0)
        sri_missing = fl.get("sri_missing", 0)
        label = f"  [bold]Frontend Libraries[/bold] ({len(fl_libs)} detected"
        if vuln_count:
            label += f", [red]{vuln_count} vulnerable[/red]"
        if sri_missing:
            label += f", [yellow]{sri_missing} missing SRI[/yellow]"
        label += ")"
        console.print(label)
        for lib in fl_libs:
            cves = lib.get("cves", [])
            sri_tag = ""
            if lib.get("source") == "cdn_url":
                sri_tag = " [green]SRI[/green]" if lib.get("has_sri") else " [yellow]no SRI[/yellow]"
            if cves:
                console.print(f"    [red]\u26a0 {lib['name']} {lib['version']}[/red]  ({len(cves)} CVE{'s' if len(cves) > 1 else ''}){sri_tag}")
            else:
                console.print(f"    [green]\u2713[/green] {lib['name']} [dim]{lib['version']}[/dim]{sri_tag}")
        if fl_vulns:
            console.print()
            console.print("    [bold red]Known Vulnerabilities[/bold red]")
            for v in fl_vulns:
                sev = v["severity"]
                sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
                sc = sev_colors.get(sev, "dim")
                console.print(f"      [{sc}]{sev.upper():>8}[/{sc}]  {v['id']}  {v['library']} < {v['fix_below']}")
                console.print(f"               [dim]{v['summary']}[/dim]")
        sri_issues = fl.get("sri_issues", [])
        if sri_issues:
            console.print()
            console.print(f"    [bold yellow]Missing SRI ({len(sri_issues)} CDN resources)[/bold yellow]")
            for si in sri_issues:
                console.print(f"      [yellow]\u26a0[/yellow] {si['library']} {si['version']}")
                console.print(f"        [dim]{si['risk']}[/dim]")
        console.print()

    # ── DNS ──
    dns = result.get("dns", {})
    if dns and (dns.get("a") or dns.get("cname") or dns.get("ns")):
        console.print("  [bold]DNS[/bold]")
        if dns.get("a"):
            console.print(f"    A:     {', '.join(dns['a'][:5])}")
        if dns.get("aaaa"):
            console.print(f"    AAAA:  {', '.join(dns['aaaa'][:3])}")
        if dns.get("cname"):
            console.print(f"    CNAME: {', '.join(dns['cname'][:3])}")
        if dns.get("ns"):
            console.print(f"    NS:    {', '.join(dns['ns'][:4])}")
        if dns.get("mx"):
            console.print(f"    MX:    {', '.join(dns['mx'][:3])}")
        cdn = dns.get("cdn_detected")
        if cdn:
            console.print(f"    CDN:   [cyan]{cdn}[/cyan]")
        spf = dns.get("has_spf", False)
        dmarc = dns.get("has_dmarc", False)
        spf_i = "[green]\u2705[/green]" if spf else "[red]\u274c[/red]"
        dmarc_i = "[green]\u2705[/green]" if dmarc else "[red]\u274c[/red]"
        console.print(f"    SPF:   {spf_i}  DMARC: {dmarc_i}")
        # Deep mode: extra record types
        if dns.get("soa"):
            console.print(f"    SOA:   [dim]{', '.join(dns['soa'][:2])}[/dim]")
        if dns.get("caa"):
            console.print(f"    CAA:   [dim]{', '.join(dns['caa'][:3])}[/dim]")
        if dns.get("ptr"):
            console.print("    PTR:")
            for ip, hostname in dns["ptr"].items():
                console.print(f"      {ip} \u2192 [dim]{hostname}[/dim]")
        if dns.get("srv"):
            console.print("    SRV:")
            for entry in dns["srv"][:5]:
                console.print(f"      {entry['service']} \u2192 [dim]{entry['record']}[/dim]")
        console.print()

    # ── robots.txt ──
    robots = result.get("robots", {})
    if robots.get("robots_txt"):
        disallowed = robots.get("disallowed_paths", [])
        interesting = robots.get("interesting_paths", [])
        sitemaps = robots.get("sitemaps", [])
        console.print(f"  [bold]robots.txt[/bold] ({len(disallowed)} disallowed paths)")
        if interesting:
            console.print("    [yellow]Interesting paths:[/yellow]")
            for p in interesting[:10]:
                console.print(f"      [yellow]{p}[/yellow]")
        if sitemaps:
            console.print(f"    Sitemaps: {', '.join(sitemaps[:3])}")
        console.print()

    # ── CORS ──
    cors = result.get("cors", {})
    if cors.get("cors_enabled"):
        misc = cors.get("misconfigured", False)
        mc = "red" if misc else "green"
        ml = "MISCONFIGURED" if misc else "OK"
        console.print(f"  [bold]CORS[/bold] ([{mc}]{ml}[/{mc}])")
        console.print(f"    Allow-Origin: {cors.get('allow_origin', '?')}")
        if cors.get("allow_credentials"):
            console.print("    [yellow]Credentials: allowed[/yellow]")
        for iss in cors.get("issues", []):
            ss = severity_style(iss["severity"])
            console.print(f"    [{ss}]\u26a0 {iss['issue']}[/{ss}]")
            console.print(f"      [dim]{iss['risk']}[/dim]")
        console.print()

    # ── Exposed Files ──
    exposed = result.get("exposed_files", {})
    exposed_list = exposed.get("exposed", [])
    if exposed_list:
        crit_count = sum(1 for e in exposed_list if e["severity"] == "critical")
        ec = "red" if crit_count else "yellow"
        console.print(f"  [bold]Exposed Files[/bold] ([{ec}]{len(exposed_list)} found[/{ec}], {exposed.get('checked', 0)} checked)")
        for ef in exposed_list:
            sev = ef["severity"]
            ss = severity_style(sev)
            icon = "\U0001f6a8" if sev == "critical" else "\u26a0"
            console.print(f"    [{ss}]{icon} {ef['path']}[/{ss}] \u2014 {ef['description']} ({ef['size']}b)")
        console.print()

    # ── HTTP Methods ──
    methods = result.get("http_methods", {})
    allowed = methods.get("allowed_methods", [])
    dangerous = methods.get("dangerous_methods", [])
    if allowed:
        console.print("  [bold]HTTP Methods[/bold]")
        safe_m = [m for m in allowed if m not in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
        line = f"    Allowed: [green]{', '.join(safe_m)}[/green]"
        if dangerous:
            line += f" [red]{', '.join(dangerous)}[/red]"
        console.print(line)
        for iss in methods.get("issues", []):
            ss = severity_style(iss["severity"])
            console.print(f"    [{ss}]\u26a0 {iss['method']}: {iss['risk']}[/{ss}]")
        console.print()

    # ── Error Page ──
    err = result.get("error_page", {})
    hints = err.get("framework_hints", [])
    leaks = err.get("version_leaks", [])
    has_trace = err.get("stack_trace", False)
    if hints or leaks or has_trace:
        console.print("  [bold]Error Page Analysis[/bold] (404)")
        if has_trace:
            console.print("    [red]\U0001f6a8 Stack trace exposed in error page![/red]")
        for leak in leaks:
            console.print(f"    [yellow]\u26a0 Version leak: {leak['software']} {leak['version']}[/yellow]")
        for hint in hints:
            console.print(f"    Framework: [cyan]{hint}[/cyan]")
        if err.get("server_header"):
            console.print(f"    Server: [dim]{err['server_header']}[/dim]")
        console.print()

    # ── Subdomains ──
    subs = result.get("subdomains", {})
    sub_list = subs.get("subdomains", [])
    sub_count = subs.get("count", 0)
    passive_count = subs.get("passive_count", sub_count)
    active_count = subs.get("active_count", 0)
    active_data = result.get("subdomains_active", {})
    waf_bypass_list = active_data.get("waf_bypass", [])
    waf_bypass_count = active_data.get("waf_bypass_count", 0)

    if sub_list or waf_bypass_list:
        src_parts = []
        if passive_count:
            src_parts.append(f"[green]{passive_count}[/green] passive (crt.sh)")
        if active_count:
            src_parts.append(f"[cyan]{active_count}[/cyan] active (DNS brute)")
        src_str = " \u00b7 ".join(src_parts) if src_parts else ""
        console.print(f"  [bold]Subdomains[/bold] ([cyan]{sub_count} unique[/cyan] \u2014 {src_str})")

        # WAF bypass subdomains — show first (critical finding)
        if waf_bypass_list:
            console.print()
            parent_cdn = active_data.get("parent_cdn", "CDN")
            console.print(f"    [bold red]\u26a0 WAF Bypass \u2014 {waf_bypass_count} subdomain(s) skip {parent_cdn}[/bold red]")
            for entry in waf_bypass_list[:10]:
                ips = ", ".join(entry.get("ips", [])[:3])
                reason = entry.get("bypass_reason", "")
                console.print(f"      [red]\u2192 {entry['subdomain']}[/red]  [{ips}]")
                if reason:
                    console.print(f"        [dim]{reason}[/dim]")
            if waf_bypass_count > 10:
                console.print(f"      [dim]... and {waf_bypass_count - 10} more[/dim]")
            console.print()

        # Regular subdomain list
        for s in sub_list[:15]:
            # Mark WAF-bypassing ones
            is_bypass = any(e["subdomain"] == s for e in waf_bypass_list)
            if is_bypass:
                console.print(f"    [red]{s}[/red]  [red]\u26a0 WAF bypass[/red]")
            else:
                console.print(f"    [dim]{s}[/dim]")
        if sub_count > 15:
            console.print(f"    [dim]... and {sub_count - 15} more[/dim]")
        console.print()

    # ── Origin IP Discovery ──
    origin = result.get("origin_ip", {})
    if origin and not origin.get("skip_reason"):
        candidates = origin.get("candidates", [])
        verified = origin.get("verified", [])
        techniques = origin.get("techniques_used", [])
        exposed = origin.get("origin_exposed", False)

        if candidates:
            status_color = "bold red" if exposed else "yellow"
            status_label = "ORIGIN EXPOSED" if exposed else f"{len(candidates)} candidate(s)"
            console.print(f"  [bold]Origin IP Discovery[/bold]  [{status_color}]{status_label}[/{status_color}]")
            console.print(f"    Parent CDN: [cyan]{origin.get('parent_cdn', '?')}[/cyan]")
            tech_str = ", ".join(techniques)
            console.print(f"    Techniques: [dim]{tech_str}[/dim]")
            console.print()

            if verified:
                console.print("    [bold red]\u26a0 VERIFIED ORIGIN \u2014 WAF completely bypassable[/bold red]")
                for v in verified:
                    proto = "https" if v.get("ssl") else "http"
                    server = f" ({v['server']})" if v.get("server") else ""
                    title = f' \u2014 "{v["title"]}"' if v.get("title") else ""
                    console.print(f"      [red]\u2192 {v['ip']}:{v['port']}[/red]  "
                                  f"HTTP {v.get('status_code', '?')}{server}{title}")
                    console.print(f"        [dim]curl -k -H 'Host: {result.get('host', '')}' "
                                  f"{proto}://{v['ip']}/[/dim]")
                console.print()

            # All candidates table
            for c in candidates[:10]:
                verified_s = " [bold red]\u2713 VERIFIED[/bold red]" if c.get("verified") else ""
                host_s = f" ({c['hostname']})" if c.get("hostname") else ""
                console.print(f"    {c['ip']:<18} [dim]{c['source']}[/dim]{host_s}{verified_s}")
            if len(candidates) > 10:
                console.print(f"    [dim]... and {len(candidates) - 10} more[/dim]")
            console.print()

    # ── Parameter Discovery ──
    params_data = result.get("params", {})
    params_list = params_data.get("params", [])
    if params_list:
        src = params_data.get("sources", {})
        console.print(f"  [bold]Discovered Parameters[/bold] ([cyan]{len(params_list)} found[/cyan] across {params_data.get('pages_crawled', 0)} pages)")
        console.print(f"    Sources: [green]{src.get('query', 0)}[/green] query \u00b7 [green]{src.get('form', 0)}[/green] form \u00b7 [green]{src.get('js', 0)}[/green] JS")

        param_table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        param_table.add_column("#", width=4, style="dim")
        param_table.add_column("Method", width=6)
        param_table.add_column("URL", min_width=35)
        param_table.add_column("Param", min_width=12, style="cyan")
        param_table.add_column("Source", width=6, style="dim")

        for i, p in enumerate(params_list[:20], 1):
            # Shorten URL for display
            disp_url = urllib.parse.urlparse(p["url"]).path or "/"
            param_table.add_row(str(i), p["method"], disp_url, p["param"], p["source"])
        console.print(param_table)
        if len(params_list) > 20:
            console.print(f"    [dim]... and {len(params_list) - 20} more[/dim]")
        console.print()
        console.print("  [dim]Test these: fray scan <target> -c xss -m 3[/dim]")
        console.print()
    elif params_data:
        console.print("  [bold]Discovered Parameters[/bold]")
        console.print(f"    [dim]No injectable parameters found ({params_data.get('pages_crawled', 0)} pages crawled)[/dim]")
        console.print()

    # ── Historical URLs ──
    hist = result.get("historical_urls", {})
    hist_urls = hist.get("urls", [])
    if hist_urls:
        hist_src = hist.get("sources", {})
        console.print(f"  [bold]Historical URLs[/bold] ([cyan]{len(hist_urls)} found[/cyan], "
                      f"[yellow]{hist.get('interesting', 0)} interesting[/yellow])")
        console.print(f"    Sources: [green]{hist_src.get('wayback', 0)}[/green] Wayback \u00b7 "
                      f"[green]{hist_src.get('sitemap', 0)}[/green] sitemap \u00b7 "
                      f"[green]{hist_src.get('robots', 0)}[/green] robots.txt")
        # Show only interesting paths in full recon (keep it compact)
        interesting_paths = [u for u in hist_urls if u["interesting"]]
        if interesting_paths:
            for u in interesting_paths[:10]:
                console.print(f"    [yellow]\u26a0 {u['path']}[/yellow]  [dim]({', '.join(u['sources'])})[/dim]")
            if len(interesting_paths) > 10:
                console.print(f"    [dim]... and {len(interesting_paths) - 10} more interesting paths[/dim]")
        console.print("    [dim]Full list: fray recon <target> --history[/dim]")
        console.print()
    elif hist:
        console.print("  [bold]Historical URLs[/bold]")
        console.print("    [dim]No historical URLs found[/dim]")
        console.print()

    # ── GraphQL Introspection ──
    gql = result.get("graphql", {})
    gql_endpoints = gql.get("endpoints_found", [])
    gql_introspection = gql.get("introspection_enabled", [])
    if gql_endpoints:
        if gql_introspection:
            console.print(f"  [bold red]GraphQL Introspection[/bold red] \u2014 [red]ENABLED[/red] \u26a0")
            for ep in gql_introspection:
                console.print(f"    [red]\u26a0 {ep} \u2014 full schema exposed[/red]")
            total_t = gql.get("total_types", 0)
            total_f = gql.get("total_fields", 0)
            if total_t:
                console.print(f"    Schema: [cyan]{total_t} types[/cyan], [cyan]{total_f} fields[/cyan]")
                for t in gql.get("types_found", [])[:8]:
                    fields_str = ", ".join(t["fields"][:5])
                    if t["field_count"] > 5:
                        fields_str += f" (+{t['field_count'] - 5} more)"
                    console.print(f"    [yellow]{t['name']}[/yellow]: {fields_str}")
        else:
            console.print("  [bold]GraphQL[/bold] \u2014 endpoints found, introspection disabled")
            for ep in gql_endpoints:
                console.print(f"    [green]\u2713[/green] {ep} (introspection blocked)")
        console.print()

    # ── API Discovery ──
    api = result.get("api_discovery", {})
    api_found = api.get("endpoints_found", [])
    api_specs = api.get("specs_found", [])
    if api_found or api_specs:
        has_spec = api.get("has_spec", False)
        if has_spec:
            console.print(f"  [bold red]API Discovery[/bold red] \u2014 [red]OpenAPI/Swagger spec EXPOSED[/red] \u26a0")
        else:
            console.print(f"  [bold]API Discovery[/bold] \u2014 [cyan]{len(api_found)} endpoints found[/cyan]")
        for spec in api_specs:
            title = spec.get("title", "Untitled")
            ver = spec.get("version", "")
            eps = spec.get("endpoints", 0)
            console.print(f"    [red]\u26a0 {spec['path']}[/red] \u2014 {title} v{ver} ({eps} endpoints)")
            for m in spec.get("methods", [])[:8]:
                console.print(f"      [dim]{m}[/dim]")
            if len(spec.get("methods", [])) > 8:
                console.print(f"      [dim]... and {len(spec['methods']) - 8} more[/dim]")
        for ep in api_found:
            if ep.get("spec"):
                continue  # Already shown above
            cat = ep.get("category", "")
            path = ep["path"]
            if ep.get("docs_page"):
                console.print(f"    [yellow]\u26a0 {path}[/yellow] \u2014 API docs page [dim]({cat})[/dim]")
            else:
                console.print(f"    [green]\u2192[/green] {path} [dim]({cat})[/dim]")
        console.print()

    # ── Host Header Injection ──
    hhi = result.get("host_header_injection", {})
    if hhi.get("reflected"):
        console.print(f"  [bold red]Host Header Injection[/bold red] \u2014 [red]VULNERABLE[/red] \u26a0")
        for v in hhi.get("vulnerable_headers", []):
            console.print(f"    [red]\u26a0 {v} \u2014 reflected in response (password reset poisoning / cache poisoning)[/red]")
        for d in hhi.get("details", []):
            if d.get("redirect"):
                console.print(f"    [red]\u26a0 {d['header']} \u2192 redirect to {d['redirect']}[/red]")
        console.print()
    elif hhi.get("details"):
        console.print(f"  [bold yellow]Host Header Injection[/bold yellow] \u2014 status changes detected")
        for d in hhi.get("details", []):
            console.print(f"    [yellow]\u26a0 {d['header']} \u2192 status {d['status']}[/yellow]")
        console.print()

    # ── Admin Panel Discovery ──
    admin = result.get("admin_panels", {})
    panels = admin.get("panels_found", [])
    if panels:
        open_panels = [p for p in panels if p.get("protected") is False]
        protected = [p for p in panels if p.get("protected") is True]
        redirects = [p for p in panels if "redirect" in p]
        if open_panels:
            console.print(f"  [bold red]Admin Panels[/bold red] \u2014 [red]{len(open_panels)} OPEN (no auth)[/red] \u26a0")
        else:
            console.print(f"  [bold]Admin Panels[/bold] \u2014 [cyan]{len(panels)} found[/cyan]")
        for p in panels:
            path = p["path"]
            status = p["status"]
            cat = p["category"]
            if p.get("protected") is False:
                console.print(f"    [red]\u26a0 {path}[/red] \u2014 [red]200 OPEN[/red] [dim]({cat})[/dim]")
            elif p.get("protected") is True:
                console.print(f"    [yellow]\U0001f512 {path}[/yellow] \u2014 {status} auth required [dim]({cat})[/dim]")
            elif p.get("redirect"):
                console.print(f"    [green]\u2192[/green] {path} \u2014 {status} \u2192 {p['redirect']} [dim]({cat})[/dim]")
            else:
                console.print(f"    [green]\u2192[/green] {path} \u2014 {status} [dim]({cat})[/dim]")
        console.print()

    # ── Rate Limits ──
    rl = result.get("rate_limits", {})
    if rl and not rl.get("error"):
        console.print("  [bold]Rate Limit Fingerprint[/bold]")
        det_type = rl.get("detection_type", "unknown")
        if det_type == "none":
            console.print("    [green]No rate limiting detected[/green] \u2014 fast testing safe")
        else:
            type_style = {"fixed-window": "yellow", "sliding-window": "yellow",
                          "token-bucket": "red", "declared-only": "cyan"}.get(det_type, "yellow")
            console.print(f"    Type:            [{type_style}]{det_type}[/{type_style}]")
            if rl.get("threshold_rps"):
                console.print(f"    Threshold:       [bold]{rl['threshold_rps']} req/s[/bold]")
            if rl.get("burst_limit"):
                console.print(f"    Burst limit:     {rl['burst_limit']} requests")
            if rl.get("lockout_duration"):
                console.print(f"    Lockout:         {rl['lockout_duration']}s")
            if rl.get("retry_after_policy"):
                console.print(f"    Retry-After:     {rl['retry_after_policy']}")
            console.print(f"    Safe delay:      [green]{rl['recommended_delay']}s[/green] between requests")
        if rl.get("rate_limit_headers"):
            hdrs_str = ", ".join(f"{k}={v}" for k, v in rl["rate_limit_headers"].items())
            console.print(f"    Headers:         [dim]{hdrs_str}[/dim]")
        console.print()

    # ── Differential Response Analysis ──
    diff = result.get("differential", {})
    if diff and not diff.get("error"):
        console.print("  [bold]WAF Detection Mode[/bold]")
        mode = diff.get("detection_mode", "unknown")
        mode_styles = {"signature": "yellow", "anomaly": "red", "hybrid": "bold red", "none": "green"}
        ms = mode_styles.get(mode, "dim")
        console.print(f"    Mode:            [{ms}]{mode}[/{ms}]")

        baseline = diff.get("baseline", {})
        blocked = diff.get("blocked_fingerprint", {})
        if baseline:
            console.print(f"    Baseline:        {baseline.get('status', '?')} \u00b7 {baseline.get('body_length', '?')} bytes \u00b7 {baseline.get('response_time_ms', '?')}ms")
        if blocked:
            console.print(f"    Blocked:         {blocked.get('status', '?')} \u00b7 {blocked.get('body_length', '?')} bytes \u00b7 {blocked.get('response_time_ms', '?')}ms")

        if diff.get("status_code_pattern"):
            console.print(f"    Status pattern:  {diff['status_code_pattern']}")
        if diff.get("timing_delta_ms") is not None:
            delta = diff["timing_delta_ms"]
            t_style = "red" if abs(delta) > 100 else "yellow" if abs(delta) > 30 else "dim"
            console.print(f"    Timing delta:    [{t_style}]{delta:+.1f}ms[/{t_style}]")
        if diff.get("body_length_delta") is not None:
            console.print(f"    Body \u0394:          {diff['body_length_delta']:+d} bytes")
        if diff.get("extra_headers_on_block"):
            console.print(f"    Extra headers:   {', '.join(diff['extra_headers_on_block'])}")
        if diff.get("block_page_signatures"):
            console.print(f"    Block sigs:      {', '.join(diff['block_page_signatures'])}")

        sig_count = len(diff.get("signature_detection", []))
        anom_count = len(diff.get("anomaly_detection", []))
        if sig_count or anom_count:
            console.print(f"    Triggered:       {sig_count} signature \u00b7 {anom_count} anomaly")
            for s in diff.get("signature_detection", []):
                console.print(f"      [yellow]SIG[/yellow]  {s['label']}: {s['status']} \u00b7 {s['response_time_ms']}ms \u00b7 {s['body_length']}B")
            for a in diff.get("anomaly_detection", []):
                console.print(f"      [red]ANOM[/red] {a['label']}: {a['status']} \u00b7 {a['response_time_ms']}ms \u00b7 {a['body_length']}B")

        # WAF intel-based recommendations
        if diff.get("waf_vendor"):
            console.print()
            console.print(f"  [bold]WAF Intel \u2014 {diff['waf_vendor']}[/bold]")
            for bp in diff.get("recommended_bypasses", [])[:5]:
                conf_style = {"high": "green", "medium": "yellow", "low": "red"}.get(bp["confidence"], "dim")
                console.print(f"    [{conf_style}]{bp['confidence'].upper():6s}[/{conf_style}] {bp['technique']}: {bp['description']}")
            ineff = diff.get("ineffective_techniques", [])
            if ineff:
                console.print(f"    [dim]Skip: {', '.join(ineff)}[/dim]")
            gaps = diff.get("detection_gaps", {})
            sig_misses = gaps.get("signature_misses", [])
            anom_misses = gaps.get("anomaly_misses", [])
            if sig_misses:
                console.print(f"    [green]Sig gaps:[/green]  {', '.join(sig_misses)}")
            if anom_misses:
                console.print(f"    [green]Anom gaps:[/green] {', '.join(anom_misses)}")
            rec_cats = diff.get("recommended_categories", [])
            if rec_cats:
                console.print(f"    [cyan]Try:[/cyan]       fray test <url> -c {rec_cats[0]} --smart")
        console.print()

    # ── WAF Rule Gap Analysis ──
    gap = result.get("gap_analysis", {})
    if gap and gap.get("waf_vendor"):
        risk = gap.get("risk_summary", "")
        risk_style = "red" if "HIGH" in risk else ("yellow" if "MEDIUM" in risk else "green")
        console.print(f"  [bold]WAF Rule Gap Analysis \u2014 {gap['waf_vendor']}[/bold]")
        console.print(f"    Risk:            [{risk_style}]{risk}[/{risk_style}]")
        console.print(f"    Detection mode:  {gap.get('detection_mode', '?')}")

        block = gap.get("block_behavior", {})
        if block.get("status_codes"):
            codes_str = ", ".join(str(c) for c in block["status_codes"])
            console.print(f"    Block codes:     {codes_str}")
        if block.get("timing_signature"):
            console.print(f"    Timing sig:      [dim]{block['timing_signature']}[/dim]")

        strategies = gap.get("bypass_strategies", [])
        if strategies:
            console.print()
            console.print("    [bold]Bypass Strategies[/bold] (prioritised)")
            for s in strategies:
                conf = s.get("confidence", "?")
                conf_style = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "dim")
                live = " [green]\u2605 live-confirmed[/green]" if s.get("live_confirmed") else ""
                console.print(f"      [{conf_style}]{conf.upper():6s}[/{conf_style}] {s['technique']}: {s['description']}{live}")
                if s.get("payload_example"):
                    example = s["payload_example"][:80]
                    console.print(f"             [dim]e.g. {example}[/dim]")

        ineff = gap.get("ineffective_techniques", [])
        if ineff:
            console.print()
            console.print("    [bold]Skip These[/bold] (known ineffective)")
            for t in ineff:
                reason = t["reason"][:80]
                console.print(f"      [dim]\u2717 {t['technique']}: {reason}[/dim]")

        det_gaps = gap.get("detection_gaps", {})
        sig_misses = det_gaps.get("signature_misses", [])
        anom_misses = det_gaps.get("anomaly_misses", [])
        config_gaps = det_gaps.get("config_gaps", [])
        if sig_misses or anom_misses or config_gaps:
            console.print()
            console.print("    [bold]Detection Gaps[/bold]")
            if sig_misses:
                console.print(f"      [green]Sig misses:[/green]   {', '.join(sig_misses)}")
            if anom_misses:
                console.print(f"      [green]Anom misses:[/green]  {', '.join(anom_misses)}")
            if config_gaps:
                console.print("      [yellow]Config issues:[/yellow]")
                for cg in config_gaps:
                    console.print(f"        [yellow]\u26a0 {cg}[/yellow]")

        # Technique matrix summary (compact)
        matrix = gap.get("technique_matrix", [])
        if matrix:
            eff_techs = [t["technique"] for t in matrix if t["status"] == "effective"]
            blk_techs = [t["technique"] for t in matrix if t["status"] == "blocked"]
            console.print()
            console.print("    [bold]Technique Matrix[/bold]")
            if eff_techs:
                console.print(f"      [green]\u2705 Effective:[/green] {', '.join(eff_techs)}")
            if blk_techs:
                console.print(f"      [red]\u274c Blocked:[/red]   {', '.join(blk_techs)}")

        console.print()

    # ── Recommended Categories ──
    cats = result.get("recommended_categories", [])
    if cats:
        console.print("  [bold]Recommended Payload Categories[/bold] (priority order)")
        for i, cat in enumerate(cats, 1):
            console.print(f"    {i}. [cyan]{cat}[/cyan]")
        console.print()
        console.print(f"  [dim]Usage: fray test <target> -c {cats[0]} --smart[/dim]")
    else:
        console.print("  [bold]Recommended Payload Categories[/bold]")
        console.print("    [dim]No specific recommendations \u2014 use --smart for adaptive testing[/dim]")
    console.print()
