"""Recon pipeline — run_recon orchestrator, attack surface summary, and
pretty-print output."""

import asyncio
import random
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ── Progress tracker ──────────────────────────────────────────────────

class _ReconProgress:
    """Real-time progress output for recon pipeline."""

    def __init__(self, total: int, quiet: bool = False):
        self._total = total
        self._done = 0
        self._start = time.time()
        self._quiet = quiet
        self._active: set = set()
        self._lock = __import__("threading").Lock()

    def _bar(self) -> str:
        bar_len = 20
        filled = int(bar_len * self._done / self._total) if self._total else 0
        return "█" * filled + "░" * (bar_len - filled)

    def _render(self, last_done: str = "") -> None:
        elapsed = time.time() - self._start
        pct = int(self._done / self._total * 100) if self._total else 0
        # Show what's currently running
        with self._lock:
            running = sorted(self._active)
        run_str = ", ".join(running[:3])
        if len(running) > 3:
            run_str += f" +{len(running)-3}"
        done_mark = f"✓ {last_done}" if last_done else ""
        line = (f"\r  [{self._bar()}] {pct:3d}% ({self._done}/{self._total}) "
                f"{elapsed:5.1f}s  {done_mark:<30}")
        if run_str and self._done < self._total:
            line += f"\n  → {run_str:<60}"
        # Clear previous line + write
        sys.stderr.write(f"\033[2K\033[A\033[2K{line}")
        sys.stderr.flush()

    def start(self, label: str) -> None:
        if self._quiet:
            return
        with self._lock:
            self._active.add(label)
        self._render()

    def done(self, label: str) -> None:
        if self._quiet:
            return
        with self._lock:
            self._active.discard(label)
        self._done += 1
        self._render(last_done=label)
        if self._done >= self._total:
            sys.stderr.write("\n")
            sys.stderr.flush()

    def status(self, msg: str) -> None:
        if self._quiet:
            return
        elapsed = time.time() - self._start
        sys.stderr.write(f"\033[2K\r  ⏳ {elapsed:5.1f}s  {msg}")
        sys.stderr.flush()

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
    check_subdomain_takeover,
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
              retirejs: bool = False,
              leak: bool = False,
              quiet: bool = False) -> Dict[str, Any]:
    """Run full reconnaissance on a target URL.

    Args:
        url: Target URL
        timeout: Request timeout in seconds
        headers: Extra HTTP headers for authenticated scanning (Cookie, Authorization, etc.)
        mode: Scan depth — 'fast' (~15s, core checks only),
              'default' (~30s, full scan), or 'deep' (~45s, extended DNS/subdomain/history)
        stealth: If True, limit parallel workers to 3 and add random jitter
                 between requests to avoid triggering WAF rate limits.
        leak: If True, run GitHub + HIBP leak search for the target domain.
        quiet: If True, suppress progress output (for JSON/AI mode).
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

    # ── Async pipeline: all network checks run concurrently with semaphore ──
    # Eliminates the phase-1/phase-2 barrier — tasks overlap freely within
    # the concurrency limit, cutting total recon time by 3-5x.

    concurrency = 3 if stealth else 10
    verify = use_ssl

    # Count total checks for progress bar
    n_checks = 13  # tier-1 core checks
    if not is_fast:
        n_checks += 4  # hist, admin, rate, gql
    n_checks += 2  # tier-2: subdomain brute + origin
    n_checks += 1  # CPU analysis (headers/csp/cookies/fingerprint)
    if leak:
        n_checks += 1

    prog = _ReconProgress(n_checks, quiet=quiet)
    if not quiet:
        checks_label = f"{n_checks} checks"
        mode_label = f"mode={mode}"
        if stealth:
            mode_label += " stealth"
        sys.stderr.write(f"\n  🔍 Recon: {host} ({checks_label}, {mode_label})\n\n\n")
        sys.stderr.flush()

    async def _run_all():
        sem = asyncio.Semaphore(concurrency)

        async def _run(fn, label: str = ""):
            """Run a sync function in a thread, respecting the semaphore."""
            async with sem:
                if stealth:
                    await asyncio.sleep(random.uniform(0.3, 1.0))
                if label:
                    prog.start(label)
                r = await asyncio.to_thread(fn)
                if label:
                    prog.done(label)
                return r

        # ── Tier 1: Independent network I/O (no dependencies) ──
        t_http    = asyncio.create_task(_run(
            lambda: check_http(host, timeout=timeout), "HTTP probe"))
        t_tls     = asyncio.create_task(_run(
            lambda: check_tls(host, port=port, timeout=timeout) if (use_ssl or port == 443) else {},
            "TLS/certificate"))
        t_page    = asyncio.create_task(_run(
            lambda: _http_get(host, port, path, use_ssl, timeout=timeout, extra_headers=headers),
            "Page fetch"))
        t_dns     = asyncio.create_task(_run(
            lambda: check_dns(host, deep=is_deep), "DNS records"))
        t_robots  = asyncio.create_task(_run(
            lambda: check_robots_sitemap(host, port, use_ssl, timeout=timeout),
            "Robots & sitemap"))
        t_cors    = asyncio.create_task(_run(
            lambda: check_cors(host, port, use_ssl, timeout=timeout), "CORS policy"))
        t_subs    = asyncio.create_task(_run(
            lambda: check_subdomains_crt(host, timeout=timeout),
            "Subdomains (CT logs)"))
        t_exposed = asyncio.create_task(_run(
            lambda: check_exposed_files(host, port, use_ssl, timeout=timeout),
            "Exposed files"))
        t_methods = asyncio.create_task(_run(
            lambda: check_http_methods(host, port, use_ssl, timeout=timeout),
            "HTTP methods"))
        t_error   = asyncio.create_task(_run(
            lambda: check_error_page(host, port, use_ssl, timeout=timeout),
            "Error pages"))
        t_params  = asyncio.create_task(_run(
            lambda: discover_params(url, max_depth=2, max_pages=10,
                                    timeout=timeout, verify_ssl=verify,
                                    extra_headers=headers),
            "Parameter discovery"))
        t_api     = asyncio.create_task(_run(
            lambda: check_api_discovery(host, port, use_ssl, timeout=timeout,
                                        extra_headers=headers),
            "API endpoints"))
        t_hhi     = asyncio.create_task(_run(
            lambda: check_host_header_injection(host, port, use_ssl,
                                                timeout=timeout, extra_headers=headers),
            "Host header injection"))

        # Non-fast tasks
        t_hist = t_admin = t_rate = t_gql = t_leak = None
        if not is_fast:
            t_hist  = asyncio.create_task(_run(
                lambda: discover_historical_urls(url, timeout=timeout, verify_ssl=verify,
                                                 extra_headers=headers,
                                                 wayback_limit=500 if is_deep else 200),
                "Wayback history"))
            t_admin = asyncio.create_task(_run(
                lambda: check_admin_panels(host, port, use_ssl, timeout=timeout,
                                           extra_headers=headers),
                "Admin panels"))
            t_rate  = asyncio.create_task(_run(
                lambda: check_rate_limits(host, port, use_ssl, timeout=timeout,
                                          extra_headers=headers),
                "Rate limits"))
            t_gql   = asyncio.create_task(_run(
                lambda: check_graphql_introspection(host, port, use_ssl, timeout=timeout,
                                                    extra_headers=headers),
                "GraphQL introspection"))

        # Leak check (--leak flag, runs concurrently with other checks)
        if leak:
            from fray.leak import run_leak_check
            t_leak = asyncio.create_task(_run(
                lambda: run_leak_check(host, timeout=timeout),
                "Leak search (GitHub+HIBP)"))

        # ── Await DNS + page first (needed for tier 2 tasks) ──
        dns_data = await _safe(t_dns, {})
        result["dns"] = dns_data
        parent_cdn = dns_data.get("cdn_detected")
        parent_ips = dns_data.get("a", [])

        page_result = await _safe(t_page, (0, {}, ""))
        if not isinstance(page_result, tuple):
            page_result = (0, {}, "")
        page_status, resp_headers, body = page_result
        result["page_status"] = page_status
        result["page_headers"] = resp_headers  # raw headers for WAF vendor inference
        tls_data = await _safe(t_tls, {})
        result["tls"] = tls_data

        # ── Tier 2: Tasks that depend on DNS/TLS results ──
        t_subs_active = asyncio.create_task(_run(
            lambda: check_subdomains_bruteforce(
                host, timeout=3.0, parent_ips=parent_ips or None,
                parent_cdn=parent_cdn,
                wordlist=_SUBDOMAIN_WORDLIST_DEEP if is_deep else None),
            "Subdomains (brute-force)"))
        t_origin = asyncio.create_task(_run(
            lambda: discover_origin_ip(
                host, timeout=4.0 if is_deep else 3.0, dns_data=dns_data,
                tls_data=tls_data, parent_cdn=parent_cdn),
            "Origin IP discovery"))

        # ── CPU-only analysis (derived from page fetch, no network) ──
        result["headers"] = check_security_headers(resp_headers)

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
        result["cookies"] = check_cookies(resp_headers)
        result["fingerprint"] = fingerprint_app(resp_headers, body)
        result["frontend_libs"] = check_frontend_libs(body, retirejs=retirejs)
        prog.done("Headers/CSP/fingerprint")

        # ── Collect remaining tier 1 results ──
        result["http"]          = await _safe(t_http, {})
        result["robots"]        = await _safe(t_robots, {})
        result["cors"]          = await _safe(t_cors, {})
        result["subdomains"]    = await _safe(t_subs, {})
        result["exposed_files"] = await _safe(t_exposed, {})
        result["http_methods"]  = await _safe(t_methods, {})
        result["error_page"]    = await _safe(t_error, {})
        result["params"]        = await _safe(t_params, {})
        result["api_discovery"] = await _safe(t_api, {})
        result["host_header_injection"] = await _safe(t_hhi, {})

        if t_hist:
            result["historical_urls"] = await _safe(t_hist, {})
        if t_admin:
            result["admin_panels"] = await _safe(t_admin, {})
        if t_rate:
            result["rate_limits"] = await _safe(t_rate, {})
        if t_gql:
            result["graphql"] = await _safe(t_gql, {})
        if t_leak:
            result["leak_check"] = await _safe(t_leak, {})

        # ── Collect tier 2 results ──
        result["subdomains_active"] = await _safe(t_subs_active, {})
        result["origin_ip"]         = await _safe(t_origin, {})

        return csp_analysis

    async def _safe(task, default):
        """Await a task, returning *default* on any exception."""
        try:
            return await task
        except Exception:
            return default

    # Run the async pipeline (works whether or not a loop is already running)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop (e.g. Jupyter) — use thread executor
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _pool:
            csp_analysis = _pool.submit(asyncio.run, _run_all()).result()
    else:
        csp_analysis = asyncio.run(_run_all())

    # ── Post-processing (sequential, depends on all results) ──

    # Merge active subdomain discoveries into passive list (dedup)
    passive_subs = set(result["subdomains"].get("subdomains", []))
    active_subs = {e["subdomain"] for e in result["subdomains_active"].get("discovered", [])}
    merged = sorted(passive_subs | active_subs)
    result["subdomains"]["subdomains"] = merged[:500]
    result["subdomains"]["count"] = len(passive_subs | active_subs)
    result["subdomains"]["passive_count"] = len(passive_subs)
    result["subdomains"]["active_count"] = len(active_subs)
    # Preserve per-source counts from multi-source enumeration
    if "sources" not in result["subdomains"]:
        result["subdomains"]["sources"] = {}
    result["subdomains"]["sources"]["dns_brute"] = len(active_subs)

    # Subdomain takeover detection (runs on merged subdomain list)
    all_subs = result["subdomains"].get("subdomains", [])
    if all_subs and not is_fast:
        if not quiet:
            sys.stderr.write(f"\r  ⏳ Checking {len(all_subs)} subdomain(s) for takeover...          \n")
            sys.stderr.flush()
        result["subdomain_takeover"] = check_subdomain_takeover(all_subs, timeout=4.0)
    else:
        result["subdomain_takeover"] = {"vulnerable": [], "checked": 0, "count": 0}

    # 14. Smart payload recommendation
    result["recommended_categories"] = recommend_categories(result["fingerprint"])

    # 15. Add csp_bypass to recommendations if weak CSP detected
    if csp_analysis.bypass_techniques:
        if "csp_bypass" not in result["recommended_categories"]:
            result["recommended_categories"].insert(0, "csp_bypass")

    # 23. Differential response analysis (WAF detection mode) — sequential, sends attack probes
    if not quiet:
        sys.stderr.write(f"\r  ⏳ WAF detection (differential response analysis)...          \n")
        sys.stderr.flush()
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
    # ── Subdomain takeover ──
    takeover = r.get("subdomain_takeover", {})
    takeover_vulns = takeover.get("vulnerable", []) if isinstance(takeover, dict) else []
    n_takeover = len(takeover_vulns)
    if n_takeover > 0:
        names = [f"{v['subdomain']} → {v['service']}" for v in takeover_vulns[:3]]
        findings.append({"severity": "critical", "finding": f"{n_takeover} subdomain(s) vulnerable to takeover: {'; '.join(names)}"})

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

    # ── Leak check findings ──
    leak_data = r.get("leak_check", {})
    n_leak_secrets = leak_data.get("confirmed_secrets", 0) if isinstance(leak_data, dict) else 0
    n_leak_repos = leak_data.get("github_repos", 0) if isinstance(leak_data, dict) else 0
    n_leak_breaches = leak_data.get("hibp_breaches", 0) if isinstance(leak_data, dict) else 0
    leak_pwn = leak_data.get("hibp_pwn_count", 0) if isinstance(leak_data, dict) else 0

    if n_leak_secrets > 0:
        findings.append({"severity": "critical", "finding": f"{n_leak_secrets} confirmed secret(s) leaked on GitHub (regex-verified)"})
    elif n_leak_repos > 0:
        findings.append({"severity": "high", "finding": f"{n_leak_repos} GitHub repo(s) with credential keywords for this domain"})
    if n_leak_breaches > 0:
        findings.append({"severity": "high", "finding": f"Domain in {n_leak_breaches} HIBP breach(es) ({leak_pwn:,} accounts)"})

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
        "subdomain_takeover": n_takeover,
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


def export_recon_dir(result: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    """Export recon results as structured text files to a directory.

    Creates:
      subdomains.txt     — one subdomain per line
      endpoints.txt      — discovered API/admin/historical endpoints
      params.txt         — injectable parameters (method url param source)
      technologies.txt   — detected technologies
      high-value.txt     — high-value targets + suggested tests
      summary.json       — attack surface summary JSON

    Returns dict of {filename: path} for all created files.
    """
    import json as _json
    import os
    os.makedirs(output_dir, exist_ok=True)
    created = {}

    def _write(name: str, lines: list) -> None:
        if not lines:
            return
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        created[name] = path

    # subdomains.txt
    subs = result.get("subdomains", {}).get("subdomains", [])
    _write("subdomains.txt", [s if isinstance(s, str) else s.get("name", "") for s in subs])

    # endpoints.txt
    endpoints = []
    for ep in result.get("api_discovery", {}).get("endpoints_found", []):
        endpoints.append(ep.get("path", ""))
    for spec in result.get("api_discovery", {}).get("specs_found", []):
        for m in spec.get("methods", []):
            endpoints.append(m)
    for p in result.get("admin_panels", {}).get("panels_found", []):
        endpoints.append(p.get("path", ""))
    for u in result.get("historical_urls", {}).get("urls", []):
        endpoints.append(u.get("path", "") if isinstance(u, dict) else str(u))
    for ef in result.get("exposed_files", {}).get("exposed", []):
        endpoints.append(ef.get("path", ""))
    for rp in result.get("robots", {}).get("interesting_paths", []):
        endpoints.append(rp)
    _write("endpoints.txt", sorted(set(e for e in endpoints if e)))

    # params.txt
    param_lines = []
    for p in result.get("params", {}).get("params", []):
        param_lines.append(f"{p.get('method','?')}\t{p.get('url','?')}\t{p.get('param','?')}\t{p.get('source','?')}")
    _write("params.txt", param_lines)

    # technologies.txt
    techs = result.get("fingerprint", {}).get("technologies", {})
    tech_lines = [f"{t}\t{c:.0%}" for t, c in sorted(techs.items(), key=lambda x: -x[1])]
    _write("technologies.txt", tech_lines)

    # high-value.txt
    hv_lines = _build_high_value_text(result)
    _write("high-value.txt", hv_lines)

    # subdomain-map.json (graph format for visualization)
    sub_count = result.get("subdomains", {}).get("count", 0)
    if sub_count > 0:
        map_path = os.path.join(output_dir, "subdomain-map.json")
        export_subdomain_map(result, map_path)
        created["subdomain-map.json"] = map_path

    # summary.json
    atk = result.get("attack_surface", {})
    path = os.path.join(output_dir, "summary.json")
    with open(path, "w", encoding="utf-8") as f:
        _json.dump(atk, f, indent=2, ensure_ascii=False)
    created["summary.json"] = path

    return created


def _build_high_value_text(result: Dict[str, Any]) -> list:
    """Build plain-text lines for high-value targets + suggested tests."""
    lines = []
    host = result.get("host", "?")
    targets = []
    tests = []

    # Staging/dev subdomains
    atk = result.get("attack_surface", {})
    staging = atk.get("staging_envs", [])
    for s in staging:
        targets.append(s)
        tests.append(f"Authentication bypass on {s}")

    # Admin panels
    panels = result.get("admin_panels", {}).get("panels_found", [])
    for p in panels:
        path = p.get("path", "")
        if p.get("protected") is False:
            targets.append(f"{host}{path}")
            tests.append(f"Unauthenticated access on {path} (OPEN)")
        else:
            tests.append(f"Authentication bypass on {path}")

    # API endpoints
    api = result.get("api_discovery", {})
    for spec in api.get("specs_found", []):
        targets.append(f"{host}{spec.get('path', '')}")
        tests.append(f"API enumeration on {spec.get('path', '')} ({spec.get('endpoints', 0)} endpoints)")
    for ep in api.get("endpoints_found", []):
        if ep.get("docs_page"):
            targets.append(f"{host}{ep['path']}")

    # GraphQL
    gql = result.get("graphql", {})
    for ep in gql.get("endpoints_found", []):
        targets.append(f"{host}{ep}")
        tests.append(f"GraphQL introspection + query fuzzing on {ep}")

    # High-risk params
    params = result.get("params", {}).get("params", [])
    hr_params = [p for p in params if isinstance(p, dict) and p.get("risk") == "HIGH"]
    for p in hr_params[:5]:
        tests.append(f"Injection testing on {p.get('param','')} ({p.get('url','')[:60]})")

    # Exposed files
    exposed = result.get("exposed_files", {}).get("exposed", [])
    for ef in exposed:
        if ef.get("severity") in ("critical", "high"):
            targets.append(f"{host}{ef['path']}")
            tests.append(f"Sensitive file access: {ef['path']} ({ef.get('description', '')})")

    # Origin IP bypass
    origin = result.get("origin_ip", {})
    for v in origin.get("verified", []):
        targets.append(f"{v['ip']}:{v.get('port', 443)}")
        tests.append(f"Direct origin access: curl -k -H 'Host: {host}' https://{v['ip']}/")

    # WAF bypass subdomains
    active = result.get("subdomains_active", {})
    for wb in active.get("waf_bypass", []):
        targets.append(wb.get("subdomain", ""))
        tests.append(f"WAF bypass via {wb.get('subdomain', '')} (direct origin)")

    # Host header injection
    hhi = result.get("host_header_injection", {})
    if hhi.get("reflected"):
        tests.append(f"Host header poisoning (password reset / cache poisoning)")

    # CORS
    cors = result.get("cors", {})
    if cors.get("misconfigured"):
        tests.append(f"CORS exploitation (misconfigured origin reflection)")

    # Subdomain takeover
    takeover = result.get("subdomain_takeover", {})
    for v in takeover.get("vulnerable", []):
        targets.append(v.get("subdomain", ""))
        tests.append(f"Subdomain takeover: {v.get('subdomain', '')} -> {v.get('service', '?')}")

    if targets:
        lines.append("High Value Targets")
        lines.append("-" * 40)
        for t in sorted(set(targets)):
            if t:
                lines.append(t)
        lines.append("")

    if tests:
        lines.append("Suggested Tests")
        lines.append("-" * 40)
        for t in tests:
            lines.append(f"  * {t}")
    elif not targets:
        lines.append("No high-value targets identified.")

    return lines


def _print_subdomain_tree(result: Dict[str, Any], sub_list: list,
                          waf_bypass_list: list, console) -> None:
    """Print a tree-map of subdomains grouped by role, with endpoints.

    Prioritizes critical/interesting subdomains:
      1. WAF bypass subdomains
      2. Staging/dev/test environments
      3. API/admin/auth subdomains
      4. Remaining (sorted alpha)
    Shows max 20 entries.
    """
    host = result.get("host", "")
    base = host.lstrip("www.") if host.startswith("www.") else host

    # Collect endpoints per subdomain from API/admin/historical data
    sub_endpoints: Dict[str, list] = {}
    for ep in result.get("api_discovery", {}).get("endpoints_found", []):
        sub_endpoints.setdefault(host, []).append(ep.get("path", ""))
    for spec in result.get("api_discovery", {}).get("specs_found", []):
        for m in spec.get("methods", []):
            sub_endpoints.setdefault(host, []).append(m)
    for p in result.get("admin_panels", {}).get("panels_found", []):
        sub_endpoints.setdefault(host, []).append(p.get("path", ""))
    for ef in result.get("exposed_files", {}).get("exposed", []):
        sub_endpoints.setdefault(host, []).append(ef.get("path", ""))

    # Categorize subdomains
    bypass_set = {e["subdomain"] for e in waf_bypass_list}
    staging_kw = ("dev", "staging", "stage", "test", "qa", "uat", "sandbox",
                  "beta", "alpha", "preprod", "demo", "internal", "debug", "canary")
    critical_kw = ("api", "admin", "auth", "sso", "login", "pay", "payment",
                   "gateway", "graphql", "grpc", "backend")

    priority_subs = []  # (subdomain, tag, color)
    normal_subs = []

    for s in sub_list:
        name_part = s.replace(f".{base}", "").lower() if s.endswith(base) else s.lower()
        if s in bypass_set:
            priority_subs.append((s, "WAF bypass", "red"))
        elif any(kw in name_part for kw in staging_kw):
            priority_subs.append((s, "staging/dev", "yellow"))
        elif any(kw in name_part for kw in critical_kw):
            priority_subs.append((s, "critical", "cyan"))
        else:
            normal_subs.append(s)

    # Build display list: priority first, then fill up to 20
    display = priority_subs[:15]
    remaining_slots = 20 - len(display)
    if remaining_slots > 0:
        for s in normal_subs[:remaining_slots]:
            display.append((s, "", "dim"))

    # Render tree
    console.print()
    for i, (sub, tag, color) in enumerate(display):
        is_last = i == len(display) - 1 and len(sub_list) <= 20
        prefix = "└── " if is_last else "├── "
        tag_str = f"  [{color}]({tag})[/{color}]" if tag else ""
        console.print(f"    {prefix}[{color}]{sub}[/{color}]{tag_str}")

        # Show endpoints for this subdomain (max 3)
        endpoints = sub_endpoints.get(sub, [])
        if not endpoints and sub == host:
            endpoints = sub_endpoints.get(host, [])
        for j, ep in enumerate(endpoints[:3]):
            ep_last = j == len(endpoints[:3]) - 1
            ep_prefix = "    └── " if ep_last else "    ├── "
            if is_last:
                ep_prefix = "    " + ep_prefix.lstrip()
            else:
                ep_prefix = "│   " + ep_prefix.lstrip()
            console.print(f"    {ep_prefix}[dim]{ep}[/dim]")
        if len(endpoints) > 3:
            connector = "    " if is_last else "│   "
            console.print(f"    {connector}    [dim]... +{len(endpoints) - 3} more[/dim]")


def export_subdomain_map(result: Dict[str, Any], output_file: str) -> str:
    """Export subdomain tree as JSON graph for visualization.

    Structure:
    {
      "domain": "example.com",
      "total": 42,
      "nodes": [
        {"id": "api.example.com", "type": "api", "endpoints": [...], "waf_bypass": false},
        ...
      ],
      "edges": [
        {"from": "example.com", "to": "api.example.com"},
        ...
      ]
    }
    """
    import json as _json

    host = result.get("host", "")
    base = host.lstrip("www.") if host.startswith("www.") else host
    sub_list = result.get("subdomains", {}).get("subdomains", [])
    active_data = result.get("subdomains_active", {})
    bypass_set = {e["subdomain"] for e in active_data.get("waf_bypass", [])}

    type_kw = {
        "api": ("api", "graphql", "grpc", "gateway"),
        "admin": ("admin", "dashboard", "panel", "cms"),
        "auth": ("auth", "sso", "login", "oauth", "accounts"),
        "staging": ("dev", "staging", "stage", "test", "qa", "uat", "sandbox", "beta"),
        "infra": ("vpn", "bastion", "jenkins", "gitlab", "ci", "cd", "monitor"),
        "mail": ("mail", "smtp", "imap", "exchange", "webmail"),
        "storage": ("cdn", "static", "assets", "media", "s3", "upload", "storage"),
        "database": ("db", "redis", "mongo", "elastic", "mysql", "postgres"),
    }

    nodes = []
    edges = []
    for s in sub_list:
        name_part = s.replace(f".{base}", "").lower() if s.endswith(base) else s.lower()
        node_type = "other"
        for t, keywords in type_kw.items():
            if any(kw in name_part for kw in keywords):
                node_type = t
                break
        nodes.append({
            "id": s,
            "type": node_type,
            "waf_bypass": s in bypass_set,
        })
        edges.append({"from": base, "to": s})

    graph = {
        "domain": base,
        "total": result.get("subdomains", {}).get("count", len(sub_list)),
        "sources": result.get("subdomains", {}).get("sources", {}),
        "nodes": nodes,
        "edges": edges,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        _json.dump(graph, f, indent=2, ensure_ascii=False)
    return output_file


def _print_high_value_targets(result: Dict[str, Any], console) -> None:
    """Print High Value Targets + Suggested Tests section."""
    lines = _build_high_value_text(result)
    if not lines:
        return

    console.print("  [bold]High Value Targets[/bold]")
    in_targets = False
    in_tests = False
    for line in lines:
        if line.startswith("High Value Targets"):
            in_targets = True
            in_tests = False
            continue
        elif line.startswith("Suggested Tests"):
            in_targets = False
            in_tests = True
            console.print()
            console.print("  [bold]Suggested Tests[/bold]")
            continue
        elif line.startswith("---") or line.startswith("-" * 10):
            continue
        elif line.strip() == "":
            continue
        elif line.startswith("No high-value"):
            console.print(f"    [dim]{line}[/dim]")
            continue

        if in_targets:
            console.print(f"    [cyan]{line}[/cyan]")
        elif in_tests:
            # Strip the "  * " prefix
            test = line.lstrip(" *").strip()
            console.print(f"    [yellow]\u2022[/yellow] {test}")

    console.print()


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

    # Show fix snippets if any headers are missing
    fix_snippets = hdr.get("fix_snippets", {})
    if fix_snippets and hdr.get("missing"):
        console.print()
        console.print("    [bold dim]Quick Fix — copy-paste config:[/bold dim]")
        # Show nginx by default (most common), hint at others
        if "nginx" in fix_snippets:
            for line in fix_snippets["nginx"].splitlines():
                console.print(f"      [dim]{line}[/dim]")
        platforms = [p for p in fix_snippets if p != "nginx"]
        if platforms:
            console.print(f"      [dim italic]Also available: {', '.join(platforms)} (in JSON output)[/dim italic]")

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
        # Per-source breakdown
        src_detail = subs.get("sources", {})
        src_parts = []
        for src_name, cnt in sorted(src_detail.items(), key=lambda x: -x[1]):
            src_parts.append(f"{src_name}:{cnt}")
        src_summary = " \u00b7 ".join(src_parts) if src_parts else f"{passive_count} passive \u00b7 {active_count} active"
        console.print(f"  [bold]Subdomains[/bold] ([cyan]{sub_count} unique[/cyan] \u2014 {src_summary})")

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

        # Smart subdomain display: prioritize interesting ones, show tree map
        _print_subdomain_tree(result, sub_list, waf_bypass_list, console)

        if sub_count > 20:
            console.print(f"    [dim]... and {sub_count - 20} more (use --export-dir to get full list)[/dim]")
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

        # Show redirect follow info
        redir = diff.get("redirect_followed")
        if redir:
            console.print(f"    Redirect:        [dim]{redir}[/dim]")

        baseline = diff.get("baseline", {})
        blocked = diff.get("blocked_fingerprint", {})
        if baseline:
            redir_note = f" [dim]({baseline['redirect_target']})[/dim]" if baseline.get("redirect_target") else ""
            console.print(f"    Baseline:        {baseline.get('status', '?')} \u00b7 {baseline.get('body_length', '?')} bytes \u00b7 {baseline.get('response_time_ms', '?')}ms{redir_note}")
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

    # ── High Value Targets + Suggested Tests ──
    _print_high_value_targets(result, console)

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
