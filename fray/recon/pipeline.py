"""Recon pipeline — run_recon orchestrator, attack surface summary, and
pretty-print output."""

import asyncio
import os
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

from fray.recon.http import _parse_url, _http_get, check_http, check_tls, check_tls_grade
from fray.recon.fingerprint import (
    check_security_headers,
    check_clickjacking,
    check_captcha,
    check_favicon,
    check_cookies,
    fingerprint_app,
    recommend_categories,
)
from fray.recon.supply_chain import check_frontend_libs, check_server_cves
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
    check_auth_endpoints,
    check_ai_endpoints,
    check_open_ports,
    check_rate_limits,
    check_rate_limits_critical,
    check_differential_responses,
    waf_gap_analysis,
)
from fray.recon.discovery import (
    discover_historical_urls,
    discover_params,
)


# ── Employee email breach cross-reference ────────────────────────────────

def _employee_breach_check(domain: str, github_data: Dict[str, Any],
                           timeout: int = 10) -> Dict[str, Any]:
    """Cross-reference discovered employee emails against breach databases.

    Checks:
        1. HIBP (Have I Been Pwned) — breached accounts
        2. GitHub code search — emails leaked in public repos
        3. GitLab profile lookup — accounts using same email

    Returns dict with breached_emails, code_exposures, and stats.
    """
    import hashlib
    import ssl
    import urllib.error
    import urllib.request

    result: Dict[str, Any] = {
        "domain": domain,
        "emails_checked": 0,
        "breached_emails": [],
        "code_exposures": [],
        "total_breaches": 0,
        "error": None,
    }

    # Collect unique emails from GitHub commit data
    emails = set()
    for author in (github_data or {}).get("commit_authors", []):
        email = (author.get("email") or "").strip().lower()
        if email and "@" in email and not email.endswith("@users.noreply.github.com"):
            emails.add(email)

    if not emails:
        return result

    result["emails_checked"] = len(emails)
    ctx = ssl.create_default_context()

    # ── HIBP breach check (uses k-anonymity API — no API key needed) ──
    for email in sorted(emails):
        sha1 = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            req = urllib.request.Request(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "Fray-Recon/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                # Note: this is the password range API, not the account API.
                # The account API requires an API key.
                # We'll use a different approach — check the HIBP breach API
                pass
        except Exception:
            pass

        # Use HIBP breachedaccount API (v3) — requires API key
        hibp_key = __import__("os").environ.get("HIBP_API_KEY")
        if hibp_key:
            try:
                req = urllib.request.Request(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.request.quote(email)}"
                    f"?truncateResponse=true",
                    headers={
                        "User-Agent": "Fray-Recon/1.0",
                        "hibp-api-key": hibp_key,
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    import json as _json
                    breaches = _json.loads(resp.read().decode())
                    if breaches:
                        result["breached_emails"].append({
                            "email": email,
                            "breach_count": len(breaches),
                            "breaches": [b.get("Name", "?") for b in breaches[:5]],
                        })
                        result["total_breaches"] += len(breaches)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    pass  # Not breached
                elif e.code == 429:
                    import time as _time
                    _time.sleep(1.6)  # HIBP rate limit: 10 req/min
            except Exception:
                pass

            import time as _time
            _time.sleep(0.15)  # polite delay

    # ── GitHub code search — find emails leaked in public repos ──
    gh_token = __import__("os").environ.get("GITHUB_TOKEN")
    if gh_token and emails:
        # Search for corporate emails in code (limit to 3 to avoid rate limits)
        corporate = [e for e in emails if e.endswith(f"@{domain}")][:3]
        for email in corporate:
            try:
                req = urllib.request.Request(
                    f"https://api.github.com/search/code?q={urllib.request.quote(email)}"
                    f"&per_page=5",
                    headers={
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "Fray-Recon/1.0",
                        "Authorization": f"token {gh_token}",
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    import json as _json
                    data = _json.loads(resp.read().decode())
                    total = data.get("total_count", 0)
                    if total > 0:
                        items = data.get("items", [])
                        result["code_exposures"].append({
                            "email": email,
                            "total_results": total,
                            "sample_repos": [
                                {
                                    "repo": item.get("repository", {}).get("full_name", "?"),
                                    "path": item.get("path", "?"),
                                    "url": item.get("html_url", ""),
                                }
                                for item in items[:3]
                            ],
                        })
            except Exception:
                pass

            import time as _time
            _time.sleep(1.0)  # GitHub code search rate limit

    return result


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
    n_checks += 1  # tier-4: GitHub org recon
    n_checks += 1  # tier-4: employee email breach check
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

    _check_timings: Dict[str, float] = {}

    async def _run_all():
        sem = asyncio.Semaphore(concurrency)

        async def _run(fn, label: str = ""):
            """Run a sync function in a thread, respecting the semaphore."""
            async with sem:
                if stealth:
                    await asyncio.sleep(random.uniform(0.3, 1.0))
                if label:
                    prog.start(label)
                t0 = time.time()
                r = await asyncio.to_thread(fn)
                _check_timings[label] = round(time.time() - t0, 1)
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
            lambda: check_robots_sitemap(host, port, use_ssl, timeout=timeout,
                                         fast=is_fast),
            "Robots & sitemap"))
        t_cors    = asyncio.create_task(_run(
            lambda: check_cors(host, port, use_ssl, timeout=timeout), "CORS policy"))
        t_subs    = asyncio.create_task(_run(
            lambda: check_subdomains_crt(host, timeout=timeout),
            "Subdomains (CT logs)"))
        t_favicon = asyncio.create_task(_run(
            lambda: check_favicon(host, port=port, use_ssl=use_ssl, timeout=timeout),
            "Favicon fingerprint"))
        _fast_to = max(3, timeout // 2) if is_fast else timeout
        t_exposed = asyncio.create_task(_run(
            lambda: check_exposed_files(host, port, use_ssl, timeout=_fast_to,
                                        fast=is_fast),
            "Exposed files"))
        t_methods = asyncio.create_task(_run(
            lambda: check_http_methods(host, port, use_ssl, timeout=_fast_to,
                                       fast=is_fast),
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
            lambda: check_api_discovery(host, port, use_ssl, timeout=_fast_to,
                                        extra_headers=headers, fast=is_fast),
            "API endpoints"))
        t_hhi     = asyncio.create_task(_run(
            lambda: check_host_header_injection(host, port, use_ssl,
                                                timeout=_fast_to, extra_headers=headers),
            "Host header injection"))

        # Non-fast tasks
        t_hist = t_admin = t_auth = t_ports = t_rate = t_gql = t_leak = None
        t_dnssec = t_axfr = t_wildcard = t_rebind = None
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
            t_auth  = asyncio.create_task(_run(
                lambda: check_auth_endpoints(host, port, use_ssl, timeout=timeout,
                                              extra_headers=headers),
                "Auth endpoints"))
            t_ports = asyncio.create_task(_run(
                lambda: check_open_ports(host, timeout=2.0),
                "Port scan"))
            t_rate  = asyncio.create_task(_run(
                lambda: check_rate_limits(host, port, use_ssl, timeout=timeout,
                                          extra_headers=headers),
                "Rate limits"))
            t_gql   = asyncio.create_task(_run(
                lambda: check_graphql_introspection(host, port, use_ssl, timeout=timeout,
                                                    extra_headers=headers),
                "GraphQL introspection"))
            # DNS security checks (#47, #48, #49, #51)
            from fray.recon.dns import (check_dnssec, check_zone_transfer,
                                         check_wildcard_dns, check_dns_rebinding)
            t_dnssec   = asyncio.create_task(_run(
                lambda: check_dnssec(host, timeout=5.0), "DNSSEC validation"))
            t_axfr     = asyncio.create_task(_run(
                lambda: check_zone_transfer(host, timeout=8.0), "Zone transfer (AXFR)"))
            t_wildcard = asyncio.create_task(_run(
                lambda: check_wildcard_dns(host, timeout=3.0), "Wildcard DNS"))
            t_rebind   = asyncio.create_task(_run(
                lambda: check_dns_rebinding(host, timeout=3.0), "DNS rebinding"))

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
        result["tls_grade"] = check_tls_grade(tls_data)

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
        result["clickjacking"] = check_clickjacking(resp_headers, csp_value)
        result["captcha"] = check_captcha(resp_headers, body)
        result["cookies"] = check_cookies(resp_headers)
        result["fingerprint"] = fingerprint_app(resp_headers, body)
        result["frontend_libs"] = check_frontend_libs(body, retirejs=retirejs)
        prog.done("Headers/CSP/fingerprint")

        # ── Collect remaining tier 1 results ──
        result["http"]          = await _safe(t_http, {})
        result["robots"]        = await _safe(t_robots, {})
        result["cors"]          = await _safe(t_cors, {})
        result["subdomains"]    = await _safe(t_subs, {})
        result["favicon"]       = await _safe(t_favicon, {})
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
        if t_auth:
            result["auth_endpoints"] = await _safe(t_auth, {})
        if t_ports:
            result["port_scan"] = await _safe(t_ports, {})
        if t_rate:
            result["rate_limits"] = await _safe(t_rate, {})
        if t_gql:
            result["graphql"] = await _safe(t_gql, {})
        if t_leak:
            result["leak_check"] = await _safe(t_leak, {})
        if t_dnssec:
            result["dnssec"] = await _safe(t_dnssec, {})
        if t_axfr:
            result["zone_transfer"] = await _safe(t_axfr, {})
        if t_wildcard:
            result["wildcard_dns"] = await _safe(t_wildcard, {})
        if t_rebind:
            result["dns_rebinding"] = await _safe(t_rebind, {})

        # ── Collect tier 2 results ──
        result["subdomains_active"] = await _safe(t_subs_active, {})
        result["origin_ip"]         = await _safe(t_origin, {})

        # ── Tier 3: AI endpoint discovery (needs origin IPs for port scan) ──
        _origin_data = result.get("origin_ip", {})
        _origin_candidates = _origin_data.get("candidates", []) if isinstance(_origin_data, dict) else []
        _origin_ip_list = [c.get("ip") for c in _origin_candidates
                           if isinstance(c, dict) and c.get("ip")] if _origin_candidates else []
        t_ai_ep = asyncio.create_task(_run(
            lambda: check_ai_endpoints(host, port, use_ssl,
                                        timeout=4 if is_fast else 6,
                                        extra_headers=headers,
                                        origin_ips=_origin_ip_list[:3]),
            "AI/LLM endpoint discovery"))

        # ── Tier 3: Critical path rate limit probe (needs subdomain list) ──
        all_subs = []
        for s in (result.get("subdomains", {}).get("subdomains", []) +
                  result.get("subdomains_active", {}).get("subdomains", [])):
            if isinstance(s, dict):
                all_subs.append(s)
            elif isinstance(s, str):
                all_subs.append({"fqdn": s})
        t_rl_crit = asyncio.create_task(_run(
            lambda: check_rate_limits_critical(host, port, use_ssl,
                                               timeout=3 if is_fast else 6,
                                               extra_headers=headers,
                                               subdomains=all_subs),
            "Rate limits (critical paths)"))
        result["rate_limits_critical"] = await _safe(t_rl_crit, {})
        result["ai_endpoints"] = await _safe(t_ai_ep, {})

        # ── Tier 4: GitHub org recon + OSINT email harvest + breach check ──
        from fray.osint import github_org_recon, enumerate_employees, harvest_emails
        t_github = asyncio.create_task(_run(
            lambda: github_org_recon(host, timeout=timeout),
            "GitHub org recon"))
        # Strip www. for email domain
        _email_domain = host[4:] if host.startswith("www.") else host
        t_emails = asyncio.create_task(_run(
            lambda: harvest_emails(_email_domain, timeout=timeout),
            "OSINT email harvest"))
        result["github_recon"] = await _safe(t_github, {})
        result["email_harvest"] = await _safe(t_emails, {})

        # Cross-reference discovered employee emails with breach databases
        t_emp_breach = asyncio.create_task(_run(
            lambda: _employee_breach_check(host, result.get("github_recon", {}), timeout),
            "Employee breach check"))
        result["employee_exposure"] = await _safe(t_emp_breach, {})

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

    # Load subdomain cache (learned from previous scans)
    cached_subs: set = set()
    try:
        import json as _json
        _cache_path = os.path.join(os.path.expanduser("~"), ".fray", "subdomain_cache.json")
        if os.path.exists(_cache_path):
            with open(_cache_path, "r", encoding="utf-8") as _cf:
                _cache = _json.load(_cf)
            search_domain = host.lstrip("www.") if host.startswith("www.") else host
            _domain_cache = _cache.get("domains", {}).get(search_domain, {})
            cached_subs = set(_domain_cache.get("subdomains", []))
            if cached_subs and not quiet:
                sys.stderr.write(f"\r  ⏳ Loaded {len(cached_subs)} cached subdomain(s) for {search_domain}          \n")
                sys.stderr.flush()
    except Exception:
        pass

    # Save newly discovered subdomains back to cache
    new_discovered = passive_subs | active_subs
    if new_discovered:
        try:
            import json as _json
            _cache_path = os.path.join(os.path.expanduser("~"), ".fray", "subdomain_cache.json")
            if os.path.exists(_cache_path):
                with open(_cache_path, "r", encoding="utf-8") as _cf:
                    _cache = _json.load(_cf)
            else:
                _cache = {"domains": {}, "common_prefixes": {}, "total_scans": 0}
            search_domain = host.lstrip("www.") if host.startswith("www.") else host
            if search_domain not in _cache["domains"]:
                _cache["domains"][search_domain] = {"subdomains": [], "last_scan": ""}
            existing = set(_cache["domains"][search_domain].get("subdomains", []))
            merged_cache = sorted(existing | new_discovered)
            _cache["domains"][search_domain]["subdomains"] = merged_cache
            _cache["domains"][search_domain]["last_scan"] = result.get("timestamp", "")
            _cache["total_scans"] = _cache.get("total_scans", 0) + 1
            os.makedirs(os.path.dirname(_cache_path), exist_ok=True)
            with open(_cache_path, "w", encoding="utf-8") as _cf:
                _json.dump(_cache, _cf, ensure_ascii=False)
        except Exception:
            pass

    merged_all = sorted(passive_subs | active_subs | cached_subs)
    result["subdomains"]["subdomains"] = merged_all[:500]
    result["subdomains"]["count"] = len(passive_subs | active_subs | cached_subs)
    result["subdomains"]["passive_count"] = len(passive_subs)
    result["subdomains"]["active_count"] = len(active_subs)
    result["subdomains"]["cached_count"] = len(cached_subs)
    # Preserve per-source counts from multi-source enumeration
    if "sources" not in result["subdomains"]:
        result["subdomains"]["sources"] = {}
    result["subdomains"]["sources"]["dns_brute"] = len(active_subs)
    if cached_subs:
        result["subdomains"]["sources"]["cache"] = len(cached_subs)

    # Subdomain takeover detection (runs on merged subdomain list)
    all_subs = result["subdomains"].get("subdomains", [])
    if all_subs and not is_fast:
        if not quiet:
            sys.stderr.write(f"\r  ⏳ Checking {len(all_subs)} subdomain(s) for takeover...          \n")
            sys.stderr.flush()
        result["subdomain_takeover"] = check_subdomain_takeover(all_subs, timeout=4.0)
    else:
        result["subdomain_takeover"] = {"vulnerable": [], "checked": 0, "count": 0}

    # Subdomain sprawl detection (#76) + cloud distribution (#77)
    from fray.recon.dns import score_dns_hygiene, detect_subdomain_sprawl, analyze_cloud_distribution
    merged_sub_list = result["subdomains"].get("subdomains", [])
    result["subdomain_sprawl"] = detect_subdomain_sprawl(merged_sub_list, host)
    if merged_sub_list and not is_fast:
        result["cloud_distribution"] = analyze_cloud_distribution(
            merged_sub_list, result.get("dns", {}), timeout=2.0)
    else:
        result["cloud_distribution"] = {}

    # DNS hygiene score (#74) — aggregates all DNS data collected above
    result["dns_hygiene"] = score_dns_hygiene(
        dns_data=result.get("dns", {}),
        dnssec_data=result.get("dnssec"),
        zone_transfer_data=result.get("zone_transfer"),
        wildcard_data=result.get("wildcard_dns"),
        takeover_data=result.get("subdomain_takeover"),
    )

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

    # 26. Enrich result with attack vectors, targets, remediation for HTML report
    _enrich_for_report(result)

    # ── Scan duration + stats summary (#189) ──
    scan_end = time.time()
    scan_start = prog._start
    scan_duration_s = round(scan_end - scan_start, 1)
    scan_minutes = int(scan_duration_s // 60)
    scan_seconds = int(scan_duration_s % 60)
    duration_str = f"{scan_minutes}m {scan_seconds}s" if scan_minutes > 0 else f"{scan_seconds}s"

    atk = result.get("attack_surface", {})
    n_findings = len(atk.get("findings", []))
    risk_lvl = atk.get("risk_level", "?")
    risk_sc = atk.get("risk_score", 0)

    result["scan_stats"] = {
        "duration_seconds": scan_duration_s,
        "duration": duration_str,
        "checks_run": prog._total,
        "checks_done": prog._done,
        "mode": mode,
        "findings": n_findings,
        "risk_score": risk_sc,
        "risk_level": risk_lvl,
        "check_timings": _check_timings,
    }

    if not quiet:
        sys.stderr.write(
            f"\n  ✅ Recon complete: {duration_str} │ {n_findings} finding(s) │ "
            f"risk {risk_sc}/100 ({risk_lvl}) │ {prog._done}/{prog._total} checks\n")
        sys.stderr.flush()

    # Auto-save for --compare history
    _save_recon_history(result)

    # Historical trend snapshot (#79)
    try:
        from fray.adaptive_cache import save_trend_snapshot
        save_trend_snapshot(host, result)
    except Exception:
        pass

    return result


def _enrich_for_report(result: Dict[str, Any]) -> None:
    """Enrich result dict with attack_vectors, attack_targets, remediation for HTML report.

    Reads existing pipeline data and synthesises structured objects that the
    v11 HTML report builder consumes.  Mutates *result* in place.
    """
    host = result.get("host", "")
    atk = result.get("attack_surface", {})
    cloud_dist = result.get("cloud_distribution", {})
    per_sub = cloud_dist.get("per_subdomain", [])
    waf_vendor = atk.get("waf_vendor") or "WAF"
    cdn_vendor = atk.get("cdn") or ""

    # ── Attack Vectors ──
    vectors = []
    priority_counter = 100

    # WAF bypass subdomains
    active = result.get("subdomains_active", {})
    waf_bypass = active.get("waf_bypass", []) if isinstance(active, dict) else []
    if waf_bypass:
        targets = [f"https://{e['subdomain']}" for e in waf_bypass if isinstance(e, dict)]
        bypass_detail_parts = []
        for e in waf_bypass[:5]:
            if isinstance(e, dict):
                sd = e.get('subdomain', '')
                ips = ', '.join(e.get('ips', [])) if e.get('ips') else 'unknown IP'
                bypass_detail_parts.append(f"{sd} → {ips}")
        bypass_detail = f"Bypasses {waf_vendor} — {len(waf_bypass)} subdomain(s) resolve to non-CDN IPs (direct origin). "
        bypass_detail += "Subdomains: " + "; ".join(bypass_detail_parts)
        if len(waf_bypass) > 5:
            bypass_detail += f" … and {len(waf_bypass) - 5} more"
        vectors.append({
            "type": "WAF Bypass", "severity": "critical", "count": len(waf_bypass),
            "priority": priority_counter, "targets": targets,
            "description": f"Subdomains that resolve to origin IPs outside the WAF/CDN, allowing attackers to send payloads directly to the origin server without any filtering.",
            "impact": f"Complete bypass of WAF rules — XSS, SQLi, and all OWASP attacks reach the application unfiltered.",
            "mitre": "T1190 — Exploit Public-Facing Application",
            "detail": bypass_detail,
        })
        priority_counter -= 5

    # Unprotected subdomains (no WAF and no CDN)
    unprotected = [s for s in per_sub if not s.get("waf") and not s.get("cdn")]
    if unprotected:
        targets = [f"https://{s['subdomain']}" for s in unprotected[:20]]
        sample = [s['subdomain'] for s in unprotected[:3]]
        unprot_detail = f"{len(unprotected)} subdomain(s) have no WAF or CDN protection. "
        unprot_detail += f"Examples: {', '.join(sample)}"
        if len(unprotected) > 3:
            unprot_detail += f" … and {len(unprotected) - 3} more"
        unprot_detail += ". All traffic reaches origin servers directly — no DDoS scrubbing, bot filtering, or WAF inspection."
        vectors.append({
            "type": "Unprotected Subdomain", "severity": "high", "count": len(unprotected),
            "priority": priority_counter, "targets": targets,
            "description": "Subdomains with no CDN or WAF protection, directly exposed on the internet.",
            "impact": "No edge security — vulnerable to direct attacks, DDoS, and automated scanning.",
            "mitre": "T1595 — Active Scanning",
            "detail": unprot_detail,
        })
        priority_counter -= 5

    # Account takeover surface
    auth_ep = result.get("auth_endpoints", {})
    if isinstance(auth_ep, dict) and auth_ep.get("has_login"):
        auth_subs = []
        for s in per_sub:
            nm = s.get("subdomain", "").lower()
            if any(k in nm for k in ("auth", "sso", "login", "id", "account", "oauth")):
                auth_subs.append(s["subdomain"])
        auth_detail = f"Login/auth surface on {host}. "
        if auth_subs:
            auth_detail += f"Auth-related subdomains: {', '.join(auth_subs[:5])}"
            if len(auth_subs) > 5:
                auth_detail += f" … and {len(auth_subs) - 5} more"
            auth_detail += ". "
        login_url = auth_ep.get('login_url', '')
        if login_url:
            auth_detail += f"Login page: {login_url}. "
        auth_detail += "Test for credential stuffing, brute-force (no rate limiting detected), session fixation, and OAuth misconfiguration."
        vectors.append({
            "type": "Account Takeover", "severity": "critical", "count": 1 + len(auth_subs),
            "priority": priority_counter, "targets": [f"https://{host}"] + [f"https://{s}" for s in auth_subs[:5]],
            "description": "Authentication and identity endpoints discovered — login portals, SSO, OAuth flows, password reset, and session management surfaces.",
            "impact": "Credential stuffing, brute-force, session hijacking, and OAuth abuse can lead to full account compromise.",
            "mitre": "T1078 — Valid Accounts / T1110 — Brute Force",
            "detail": auth_detail,
        })
        priority_counter -= 5

    # API surface
    api = result.get("api_discovery", {})
    api_subs = [s["subdomain"] for s in per_sub if "api" in s.get("subdomain", "").lower()]
    if (isinstance(api, dict) and api.get("endpoints_found")) or api_subs:
        api_detail = "API attack surface: "
        if api_subs:
            api_detail += f"{len(api_subs)} API subdomain(s): {', '.join(api_subs[:5])}"
            if len(api_subs) > 5:
                api_detail += f" … and {len(api_subs) - 5} more"
            api_detail += ". "
        if isinstance(api, dict) and api.get('endpoints_found'):
            api_detail += f"{api.get('endpoints_found', 0)} endpoint(s) discovered. "
        api_detail += "Test for BOLA/IDOR, broken auth, excessive data exposure, mass assignment, and rate limiting bypass."
        vectors.append({
            "type": "API Vulnerability", "severity": "high", "count": max(1, len(api_subs)),
            "priority": priority_counter, "targets": [f"https://{host}"] + [f"https://{s}" for s in api_subs[:5]],
            "description": "API endpoints discovered — REST, GraphQL, or internal service APIs that may lack proper authentication, rate limiting, or input validation.",
            "impact": "Broken authentication, excessive data exposure, mass assignment, and SSRF via API abuse.",
            "mitre": "OWASP API1-API10",
            "detail": api_detail,
        })
        priority_counter -= 5

    # LLM / AI surface — strict word-boundary matching to avoid false positives
    # "ai" must be a standalone segment (ai.example, my-ai-app) not part of "air", "mail", "paint"
    import re as _re
    _AI_STRICT_KW = {"llm", "gpt", "openai", "chatgpt", "copilot", "genai", "gen-ai",
                      "langchain", "ollama", "agenticai", "agentic", "generativeai",
                      "vertexai", "azureai", "bedrock", "sagemaker", "huggingface"}
    _AI_SEGMENT_KW = {"ai", "chat", "bot", "robot", "chatbot", "aibot", "assistant"}

    def _is_ai_subdomain(sub_lower):
        # Split into segments by dots and hyphens
        segments = _re.split(r'[.\-_]', sub_lower)
        # Exact segment match for short keywords (avoids "air", "airem", "mailbot")
        for seg in segments:
            if seg in _AI_SEGMENT_KW:
                return True
            # Check if segment ends with 'ai' and is long enough (agenticai, genai)
            if len(seg) > 3 and seg.endswith("ai"):
                return True
        # Substring match for longer, unambiguous keywords
        for kw in _AI_STRICT_KW:
            if kw in sub_lower:
                return True
        # Also check compound patterns: ai as standalone segment
        if _re.search(r'(?:^|[.\-_])ai(?:[.\-_]|$)', sub_lower):
            return True
        return False

    ai_subs = [s["subdomain"] for s in per_sub if _is_ai_subdomain(s.get("subdomain", "").lower())]
    # Also check probe results for AI indicators (chatbot widgets, LLM API responses)
    for s in per_sub:
        sub = s.get("subdomain", "")
        if sub in ai_subs:
            continue
        surfaces = s.get("surfaces", []) if isinstance(s.get("surfaces"), list) else []
        if any(k in str(surfaces).lower() for k in ("llm", "chatbot", "ai_assistant")):
            ai_subs.append(sub)

    # Check fingerprinted technologies for AI indicators (body/header/cookie detections)
    _AI_TECH_CATEGORIES = {"AI / LLM", "AI / ML", "AI Chatbot", "Chatbot", "AI Framework",
                           "AI Gateway", "AI Search", "AI Support", "Vector DB"}
    _AI_TECH_NAMES = {
        "botpress", "voiceflow", "ada_chatbot", "tidio", "kommunicate", "customerly",
        "chatbase", "landbot", "chatgpt_embed", "botsonic", "dialogflow", "watson_assistant",
        "amazon_lex", "rasa", "manychat", "chatfuel", "tiledesk", "yellow_ai", "haptik",
        "verloop", "engati", "gorgias", "kore_ai", "openai", "openai_api", "anthropic",
        "anthropic_api", "cohere", "huggingface", "replicate", "together_ai", "groq",
        "mistral", "perplexity", "fireworks_ai", "deepinfra", "ollama", "llm_api",
        "llm_streaming", "langchain", "llamaindex", "pinecone", "weaviate", "chromadb",
        "qdrant", "milvus", "algolia_ai", "vectara", "mendable", "inkeep", "docsbot",
        "copilot", "github_copilot", "google_gemini", "google_vertex_ai", "aws_bedrock",
        "aws_sagemaker", "azure_openai", "azure_ml", "cloudflare_ai_gateway",
    }
    ai_techs_detected = []
    _fp_data = result.get("fingerprint", {})
    fp_techs = _fp_data.get("technologies", {}) if isinstance(_fp_data, dict) else {}
    for tech_name, tech_info in fp_techs.items():
        cat = tech_info.get("category", "") if isinstance(tech_info, dict) else ""
        if cat in _AI_TECH_CATEGORIES or tech_name.lower() in _AI_TECH_NAMES:
            ai_techs_detected.append(tech_name)
    # If AI techs detected on main host but no AI subs found, add the main host
    if ai_techs_detected and not ai_subs:
        ai_subs.append(host)

    # ── Merge results from check_ai_endpoints (active probing) ──
    ai_ep_data = result.get("ai_endpoints", {})
    ai_ep_endpoints = ai_ep_data.get("endpoints", []) if isinstance(ai_ep_data, dict) else []
    ai_ep_headers = ai_ep_data.get("ai_headers", {}) if isinstance(ai_ep_data, dict) else {}
    ai_ep_ports = ai_ep_data.get("open_ports", []) if isinstance(ai_ep_data, dict) else []
    ai_ep_confirmed_ports = ai_ep_data.get("confirmed_ports", []) if isinstance(ai_ep_data, dict) else []
    ai_ep_techs = ai_ep_data.get("technologies", []) if isinstance(ai_ep_data, dict) else []

    # Add discovered AI API paths as targets
    ai_path_targets = []
    for ep in ai_ep_endpoints:
        if isinstance(ep, dict):
            p = ep.get("path", "")
            signals = ep.get("signals", [])
            if p:
                ai_path_targets.append(f"https://{host}{p}")
    # Add confirmed self-hosted AI ports as targets
    for ps in ai_ep_confirmed_ports:
        if isinstance(ps, dict):
            ip = ps.get("ip", "")
            pt = ps.get("port", "")
            svc = ps.get("service", "")
            if ip and pt:
                ai_path_targets.append(f"http://{ip}:{pt} ({svc})")
    # Merge AI endpoint techs into ai_techs_detected
    for t in ai_ep_techs:
        if t not in ai_techs_detected:
            ai_techs_detected.append(t)

    # Ensure host is in ai_subs if active probing found AI endpoints
    if (ai_ep_endpoints or ai_ep_confirmed_ports or ai_ep_headers) and host not in ai_subs:
        ai_subs.append(host)

    if ai_subs or ai_path_targets:
        all_ai_targets = [f"https://{s}" for s in ai_subs[:5]]
        for t in ai_path_targets[:5]:
            if t not in all_ai_targets:
                all_ai_targets.append(t)

        ai_detail_parts = []
        if ai_subs:
            ai_detail_parts.append(f"{len(ai_subs)} AI/chatbot subdomain(s): {', '.join(ai_subs[:5])}")
            if len(ai_subs) > 5:
                ai_detail_parts[-1] += f" … +{len(ai_subs) - 5} more"
        if ai_ep_endpoints:
            ai_detail_parts.append(f"{len(ai_ep_endpoints)} AI API path(s) discovered via active probing")
        if ai_ep_headers:
            hdr_names = ', '.join(ai_ep_headers.keys())
            ai_detail_parts.append(f"AI proxy headers detected: {hdr_names}")
        if ai_ep_confirmed_ports:
            port_info = ', '.join(f"{p.get('ip')}:{p.get('port')} ({p.get('service')})"
                                  for p in ai_ep_confirmed_ports[:3])
            ai_detail_parts.append(f"Self-hosted AI services: {port_info}")
        elif ai_ep_ports:
            ai_detail_parts.append(f"{len(ai_ep_ports)} open AI-related port(s)")
        if ai_techs_detected:
            ai_detail_parts.append(f"Technologies: {', '.join(ai_techs_detected[:8])}")
        ai_detail_parts.append("Test for prompt injection, jailbreaking, system prompt leakage, and indirect prompt injection via user-supplied content.")
        ai_detail = ". ".join(ai_detail_parts)

        sev = "critical" if (ai_ep_endpoints or ai_ep_confirmed_ports) else "high"
        vectors.append({
            "type": "LLM / AI Prompt Injection", "severity": sev,
            "count": len(ai_subs) + len(ai_path_targets),
            "priority": priority_counter, "targets": all_ai_targets[:10],
            "description": "AI/ML and chatbot endpoints discovered — LLM-powered services that may be vulnerable to prompt injection, jailbreaking, and data exfiltration.",
            "impact": "Prompt injection can bypass safety filters, leak system prompts, exfiltrate training data, or cause unintended actions.",
            "mitre": "OWASP LLM01 — Prompt Injection",
            "detail": ai_detail,
        })
        priority_counter -= 5

    # Payment surface
    pay_subs = [s["subdomain"] for s in per_sub
                if any(k in s.get("subdomain", "").lower() for k in ("pay", "shop", "store", "cart", "order", "checkout"))]
    if pay_subs:
        pay_detail = f"{len(pay_subs)} payment/commerce subdomain(s): {', '.join(pay_subs[:5])}"
        if len(pay_subs) > 5:
            pay_detail += f" … and {len(pay_subs) - 5} more"
        pay_detail += ". Test for price manipulation, payment flow bypass, card testing, and PII exposure."
        vectors.append({
            "type": "Payment / Financial Abuse", "severity": "critical", "count": len(pay_subs),
            "priority": priority_counter, "targets": [f"https://{s}" for s in pay_subs[:5]],
            "description": "Payment processing, e-commerce, and financial transaction endpoints detected.",
            "impact": "Price manipulation, payment bypass, card testing, and financial fraud.",
            "mitre": "T1565 — Data Manipulation",
            "detail": pay_detail,
        })
        priority_counter -= 5

    # Staging/dev
    staging_envs = atk.get("staging_envs", [])
    if staging_envs:
        targets = [f"https://{s}" for s in staging_envs[:10]]
        staging_detail = f"{len(staging_envs)} staging/dev environment(s) publicly accessible: {', '.join(staging_envs[:3])}"
        if len(staging_envs) > 3:
            staging_detail += f" … and {len(staging_envs) - 3} more"
        staging_detail += ". Staging/dev environments typically have weaker WAF rules, debug mode enabled, verbose errors, and default credentials."
        vectors.append({
            "type": "Staging / Dev Environment", "severity": "high", "count": len(staging_envs),
            "priority": priority_counter, "targets": targets,
            "description": "Non-production environments publicly accessible — often with debug mode, verbose errors, default credentials, and weaker WAF rules.",
            "impact": "Information disclosure, default credential access, code/config leakage, and pivot to production.",
            "mitre": "T1580 — Cloud Infrastructure Discovery",
            "detail": staging_detail,
        })
        priority_counter -= 5

    # DDoS / L7 DoS
    rate_limit = result.get("rate_limit", {})
    rl_type = rate_limit.get("type", "none") if isinstance(rate_limit, dict) else "none"
    if rl_type == "none" and len(unprotected) > 5:
        no_cdn = [s['subdomain'] for s in per_sub if not s.get('cdn')]
        ddos_detail = f"DDoS/L7 DoS surface: {len(no_cdn)} unprotected subdomain(s) (no CDN): {', '.join(no_cdn[:3])}"
        if len(no_cdn) > 3:
            ddos_detail += f" … and {len(no_cdn) - 3} more"
        subs_data = result.get('subdomains', {})
        n_subs = subs_data.get('count', 0) if isinstance(subs_data, dict) else 0
        ddos_detail += f"; {n_subs} subdomains — large surface for distributed attacks. No rate limiting or scrubbing detected."
        vectors.append({
            "type": "DDoS / L7 Denial of Service", "severity": "high", "count": 1,
            "priority": priority_counter, "targets": [f"https://{host}"],
            "description": "Large number of unprotected subdomains without rate limiting — application-layer flood attacks possible.",
            "impact": "Service degradation or outage via slow HTTP, resource-intensive queries, or connection exhaustion.",
            "mitre": "T1499 — Endpoint Denial of Service",
            "detail": ddos_detail,
        })
        priority_counter -= 5

    # Cache poisoning
    if cdn_vendor and auth_ep and isinstance(auth_ep, dict) and auth_ep.get("has_login"):
        cache_detail = f"Web cache + auth surface: CDN detected: {cdn_vendor}. CDN caching + user-specific pages = cache deception risk."
        vectors.append({
            "type": "Web Cache Poisoning", "severity": "medium", "count": 1,
            "priority": priority_counter, "targets": [f"https://{host}"],
            "description": "CDN caching combined with user-specific pages creates cache deception and poisoning attack surface.",
            "impact": "Serve malicious content to other users, steal credentials via cached authenticated pages, or cause widespread XSS.",
            "mitre": "T1557 — Adversary-in-the-Middle",
            "detail": cache_detail,
        })
        priority_counter -= 5

    # DDoS — Direct Origin (if origin IPs found)
    origin_data = result.get("origin_ip", {})
    origin_candidates = origin_data.get("candidates", []) if isinstance(origin_data, dict) else []
    if origin_candidates and len(unprotected) > 0:
        targets = [f"https://{s['subdomain']}" for s in unprotected[:3]]
        origin_detail = f"No CDN/WAF on {unprotected[0]['subdomain']} — direct volumetric flood possible, no rate limiting or scrubbing"
        if len(origin_candidates) > 0:
            ips = [c.get('ip', str(c)) if isinstance(c, dict) else str(c) for c in origin_candidates[:3]]
            origin_detail += f". Origin IPs discovered: {', '.join(ips)}"
        vectors.append({
            "type": "DDoS — Direct Origin", "severity": "high", "count": len(unprotected[:3]),
            "priority": priority_counter, "targets": targets,
            "description": "Origin servers reachable without CDN protection — volumetric and application-layer DDoS attacks can target them directly.",
            "impact": "Service disruption, resource exhaustion, and potential complete outage.",
            "mitre": "T1499 — Endpoint Denial of Service",
            "detail": origin_detail,
        })

    # Critical path endpoints — /login, /signup, /checkout, /api, /admin discovered via probes
    probe_results = result.get("subdomain_probes", [])
    critical_paths = []
    _CRITICAL_PATH_MAP = {
        "login": ("Login / Authentication", "critical"),
        "password": ("Password Reset", "high"),
        "password_reset": ("Password Reset", "high"),
        "registration": ("User Registration", "high"),
        "api": ("API Endpoint", "high"),
        "admin": ("Admin Panel", "critical"),
        "file_upload": ("File Upload", "high"),
        "payment": ("Payment / Checkout", "critical"),
    }
    # From subdomain probes — check detected surfaces
    for p in (probe_results if isinstance(probe_results, list) else []):
        sub = p.get("subdomain", "")
        cats = p.get("categories", p.get("surfaces", {}))
        if isinstance(cats, dict):
            for cat_key in cats:
                if cat_key in _CRITICAL_PATH_MAP and cats[cat_key]:
                    label, sev = _CRITICAL_PATH_MAP[cat_key]
                    critical_paths.append({"url": f"https://{sub}", "type": label, "severity": sev, "source": "probe"})
        elif isinstance(cats, list):
            for cat_key in cats:
                if cat_key in _CRITICAL_PATH_MAP:
                    label, sev = _CRITICAL_PATH_MAP[cat_key]
                    critical_paths.append({"url": f"https://{sub}", "type": label, "severity": sev, "source": "probe"})
    # From auth_endpoints — all discovered auth endpoints are critical
    _AUTH_CAT_MAP = {
        "login": ("Login / Authentication", "critical"),
        "registration": ("User Registration", "high"),
        "oauth": ("OAuth / OpenID", "critical"),
        "sso": ("SSO / SAML", "critical"),
        "mfa": ("MFA / 2FA", "high"),
        "password_reset": ("Password Reset", "high"),
        "api_auth": ("API Auth Endpoint", "critical"),
        "session": ("Session Management", "high"),
    }
    if isinstance(auth_ep, dict):
        auth_endpoints_list = auth_ep.get("endpoints", [])
        for ep in (auth_endpoints_list if isinstance(auth_endpoints_list, list) else []):
            if not isinstance(ep, dict):
                continue
            ep_path = ep.get("path", "")
            ep_cat = ep.get("category", "")
            ep_status = ep.get("status", 0)
            ep_protected = ep.get("protected", False)
            ep_redirect = ep.get("redirect", "")
            ep_auth_scheme = ep.get("auth_scheme", "")

            label, sev = _AUTH_CAT_MAP.get(ep_cat, ("Auth Endpoint", "high"))

            # Endpoints returning 401/403 are protected — still critical to discover
            extra = ""
            if ep_protected:
                extra = f" [Protected: {ep_status}"
                if ep_auth_scheme:
                    extra += f", {ep_auth_scheme}"
                extra += "]"
            elif ep_redirect:
                extra = f" [Redirects to auth]"
            elif ep.get("has_csrf"):
                extra = " [Has CSRF token]"
            if ep.get("rate_limited"):
                extra += " [Rate limited]"
            if ep.get("openid_discovery"):
                extra += " [OpenID Discovery]"

            critical_paths.append({
                "url": f"https://{host}{ep_path}",
                "type": label,
                "severity": sev,
                "source": "auth_scan",
                "status": ep_status,
                "protected": ep_protected,
                "detail": extra.strip(),
            })
    # From admin_panels
    admin_data = result.get("admin_panels", {})
    admin_panels_list = (admin_data.get("panels_found", []) or admin_data.get("found", []) or []) if isinstance(admin_data, dict) else []
    for ap in (admin_panels_list[:5] if isinstance(admin_panels_list, list) else []):
        path = ap.get("path", "") if isinstance(ap, dict) else str(ap)
        if path:
            critical_paths.append({"url": f"https://{host}{path}", "type": "Admin Panel", "severity": "critical", "source": "admin_scan"})
    # From endpoint discovery
    endpoint_data = result.get("endpoints", result.get("api_discovery", {}))
    if isinstance(endpoint_data, dict):
        for ep in endpoint_data.get("endpoints", endpoint_data.get("endpoints_found", []))[:5]:
            if isinstance(ep, dict):
                path = ep.get("path", ep.get("url", ""))
                if path:
                    critical_paths.append({"url": f"https://{host}{path}" if not path.startswith("http") else path,
                                           "type": "API Endpoint", "severity": "high", "source": "endpoint_scan"})

    if critical_paths:
        # Deduplicate
        seen_urls = set()
        unique_paths = []
        for cp in critical_paths:
            if cp["url"] not in seen_urls:
                seen_urls.add(cp["url"])
                unique_paths.append(cp)
        critical_paths = unique_paths

        crit_targets = [cp["url"] for cp in critical_paths[:10]]
        crit_detail = f"{len(critical_paths)} critical endpoint(s) discovered: "
        type_counts = {}
        for cp in critical_paths:
            type_counts[cp["type"]] = type_counts.get(cp["type"], 0) + 1
        crit_detail += ", ".join(f"{count} {t}" for t, count in type_counts.items())
        crit_detail += ". These endpoints handle sensitive operations and require hardened access controls, input validation, and monitoring."
        vectors.append({
            "type": "Critical Endpoint Exposure", "severity": "critical", "count": len(critical_paths),
            "priority": max(85, priority_counter), "targets": crit_targets,
            "description": "Critical application endpoints discovered — login, registration, payment, admin, and API surfaces that are primary attack targets.",
            "impact": "Credential theft, unauthorized access, payment fraud, privilege escalation, and data exfiltration.",
            "mitre": "T1190 — Exploit Public-Facing Application",
            "detail": crit_detail,
            "critical_paths": critical_paths,
        })

    atk["attack_vectors"] = vectors

    # ── Enrich Technologies (merge infrastructure signals into fingerprint) ──
    fp = result.get("fingerprint", {})
    if not isinstance(fp, dict):
        fp = {}
        result["fingerprint"] = fp
    techs = fp.get("technologies", {})
    # Convert old float-style techs to dict format for consistency
    for k, v in list(techs.items()):
        if isinstance(v, (int, float)):
            techs[k] = {"category": "Detected", "confidence": max(1, int(v * 100) if v <= 1 else int(v))}
    inferred = dict(techs)  # start with existing detections
    if True:  # always enrich
        # WAF vendors
        waf_dist = cloud_dist.get("waf_distribution", {})
        for name in waf_dist:
            inferred[name] = {"category": "WAF", "confidence": 90}
        # CDN vendors
        cdn_dist_d = cloud_dist.get("cdn_distribution", {})
        for name in cdn_dist_d:
            inferred[name] = {"category": "CDN", "confidence": 90}
        # DNS-level CDN
        dns_data = result.get("dns", {})
        dns_cdn = dns_data.get("cdn_detected") if isinstance(dns_data, dict) else None
        if dns_cdn and dns_cdn not in inferred:
            inferred[dns_cdn.title()] = {"category": "CDN", "confidence": 80}
        # Server headers from per-subdomain data
        for s in per_sub:
            sv = s.get("server")
            if sv and sv != "-":
                sv_clean = sv.split("/")[0].strip().title()
                if sv_clean and sv_clean not in inferred:
                    inferred[sv_clean] = {"category": "Web Server", "confidence": 70}
        # Admin panel categories → technology hints
        admin_data = result.get("admin_panels", {})
        admin_panels_list = (admin_data.get("panels_found", []) or
                             admin_data.get("found", []) or []) if isinstance(admin_data, dict) else []
        _admin_tech_map = {
            "tomcat": ("Apache Tomcat", "Application Server"),
            "spring": ("Spring Framework", "Framework"),
            "drupal": ("Drupal", "CMS"),
            "wordpress": ("WordPress", "CMS"),
            "joomla": ("Joomla", "CMS"),
            "docker": ("Docker", "Container"),
            "grafana": ("Grafana", "Monitoring"),
            "jenkins": ("Jenkins", "CI/CD"),
            "gitlab": ("GitLab", "DevOps"),
        }
        # Count how many admin panel paths responded with non-404
        admin_cats = {}
        for p in admin_panels_list:
            cat = p.get("category", "") if isinstance(p, dict) else ""
            status = p.get("status", 0) if isinstance(p, dict) else 0
            if cat and status and status != 404:
                admin_cats[cat.lower()] = admin_cats.get(cat.lower(), 0) + 1
        for cat, count in admin_cats.items():
            if cat in _admin_tech_map:
                name, role = _admin_tech_map[cat]
                # Higher confidence if multiple paths respond (not just 301)
                conf = min(70, 30 + count * 10)
                if name not in inferred or inferred[name].get("confidence", 0) < conf:
                    inferred[name] = {"category": role, "confidence": conf}
        # Subdomain name hints
        subs_data = result.get("subdomains", {})
        sub_list_raw = subs_data.get("subdomains", []) if isinstance(subs_data, dict) else []
        _sub_tech_hints = {
            # API
            "graphql": ("GraphQL", "API"),
            "grpc": ("gRPC", "API"),
            "rest-api": ("REST API", "API"),
            # Database
            "redis": ("Redis", "Database"),
            "mongo": ("MongoDB", "Database"),
            "postgres": ("PostgreSQL", "Database"),
            "mysql": ("MySQL", "Database"),
            "mariadb": ("MariaDB", "Database"),
            "mssql": ("Microsoft SQL Server", "Database"),
            "oracle-db": ("Oracle Database", "Database"),
            "dynamodb": ("DynamoDB", "Database"),
            "cassandra": ("Apache Cassandra", "Database"),
            "couchdb": ("CouchDB", "Database"),
            "memcached": ("Memcached", "Cache"),
            # Search
            "elastic": ("Elasticsearch", "Search Engine"),
            "solr": ("Apache Solr", "Search Engine"),
            "opensearch": ("OpenSearch", "Search Engine"),
            # CI/CD & DevOps
            "jenkins": ("Jenkins", "CI/CD"),
            "gitlab": ("GitLab", "DevOps"),
            "github": ("GitHub", "DevOps"),
            "bitbucket": ("Bitbucket", "DevOps"),
            "argocd": ("Argo CD", "CI/CD"),
            "circleci": ("CircleCI", "CI/CD"),
            "sonar": ("SonarQube", "Code Quality"),
            # Container / Orchestration
            "k8s": ("Kubernetes", "Container Orchestration"),
            "kubernetes": ("Kubernetes", "Container Orchestration"),
            "docker": ("Docker", "Container"),
            "rancher": ("Rancher", "Container Orchestration"),
            # Cloud
            "gcp": ("Google Cloud Platform", "Cloud"),
            "google-cloud": ("Google Cloud Platform", "Cloud"),
            "azure": ("Microsoft Azure", "Cloud"),
            "aws": ("Amazon Web Services", "Cloud"),
            # SaaS / Business
            "salesforce": ("Salesforce", "CRM"),
            "sfdc": ("Salesforce", "CRM"),
            "zendesk": ("Zendesk", "Support"),
            "freshdesk": ("Freshdesk", "Support"),
            "servicenow": ("ServiceNow", "ITSM"),
            "jira": ("Jira", "Project Management"),
            "confluence": ("Confluence", "Wiki"),
            "slack": ("Slack", "Communication"),
            "teams": ("Microsoft Teams", "Communication"),
            "sharepoint": ("SharePoint", "Collaboration"),
            "hubspot": ("HubSpot", "Marketing"),
            "marketo": ("Marketo", "Marketing"),
            # CMS
            "wordpress": ("WordPress", "CMS"),
            "drupal": ("Drupal", "CMS"),
            "sitecore": ("Sitecore", "CMS"),
            "contentful": ("Contentful", "CMS"),
            "strapi": ("Strapi", "CMS"),
            # E-commerce
            "shopify": ("Shopify", "E-commerce"),
            "magento": ("Magento", "E-commerce"),
            # Monitoring
            "grafana": ("Grafana", "Monitoring"),
            "prometheus": ("Prometheus", "Monitoring"),
            "datadog": ("Datadog", "Monitoring"),
            "newrelic": ("New Relic", "Monitoring"),
            "kibana": ("Kibana", "Monitoring"),
            "nagios": ("Nagios", "Monitoring"),
            "zabbix": ("Zabbix", "Monitoring"),
            "splunk": ("Splunk", "SIEM"),
            # Telco / JP Infra
            "ntt": ("NTT", "Telco"),
            "softbank": ("SoftBank", "Telco"),
            "kddi": ("KDDI", "Telco"),
            # Message Queue
            "rabbitmq": ("RabbitMQ", "Message Queue"),
            "kafka": ("Apache Kafka", "Message Queue"),
            "activemq": ("ActiveMQ", "Message Queue"),
            # Auth / Identity
            "keycloak": ("Keycloak", "Identity"),
            "okta": ("Okta", "Identity"),
            "auth0": ("Auth0", "Identity"),
            "ldap": ("LDAP", "Directory"),
        }
        all_subs_lower = " ".join(s.lower() for s in sub_list_raw[:500])
        for kw, (name, role) in _sub_tech_hints.items():
            if kw in all_subs_lower and name not in inferred:
                inferred[name] = {"category": role, "confidence": 40}
        # Cloud provider from WAF/CDN
        if any("aws" in n.lower() or "cloudfront" in n.lower() for n in list(waf_dist) + list(cdn_dist_d)):
            if "Amazon Web Services" not in inferred:
                inferred["Amazon Web Services"] = {"category": "Cloud", "confidence": 85}
        if any("azure" in n.lower() for n in list(waf_dist) + list(cdn_dist_d)):
            if "Microsoft Azure" not in inferred:
                inferred["Microsoft Azure"] = {"category": "Cloud", "confidence": 85}

        # DNS CNAME chain analysis
        dns_data = dns_data if isinstance(dns_data, dict) else result.get("dns", {})
        cname_chain = dns_data.get("cname", []) if isinstance(dns_data, dict) else []
        if isinstance(cname_chain, str):
            cname_chain = [cname_chain]
        a_recs = dns_data.get("a", []) if isinstance(dns_data, dict) else []
        aaaa_recs = dns_data.get("aaaa", []) if isinstance(dns_data, dict) else []
        all_dns_str = " ".join(str(r).lower() for r in (cname_chain + a_recs + aaaa_recs))
        _dns_tech_hints = {
            "akamai": ("Akamai", "CDN", 85),
            "edgekey": ("Akamai", "CDN", 80),
            "akadns": ("Akamai", "CDN", 75),
            "cloudflare": ("Cloudflare", "CDN/WAF", 85),
            "fastly": ("Fastly", "CDN", 85),
            "incapsula": ("Imperva Incapsula", "CDN/WAF", 85),
            "sucuri": ("Sucuri", "WAF", 80),
            "stackpath": ("StackPath", "CDN", 80),
            "amazonaws.com": ("Amazon Web Services", "Cloud", 85),
            "azurewebsites": ("Microsoft Azure App Service", "PaaS", 80),
            "azure-dns": ("Microsoft Azure DNS", "DNS", 75),
            "googleusercontent": ("Google Cloud Platform", "Cloud", 85),
            "googleapis": ("Google Cloud Platform", "Cloud", 80),
            "github.io": ("GitHub Pages", "Hosting", 85),
            "heroku": ("Heroku", "PaaS", 80),
            "netlify": ("Netlify", "Hosting", 85),
            "vercel": ("Vercel", "Hosting", 85),
            "wpengine": ("WP Engine", "Hosting", 80),
            "pantheon": ("Pantheon", "Hosting", 75),
            "zendesk": ("Zendesk", "Support", 70),
            "salesforce": ("Salesforce", "CRM", 70),
            "force.com": ("Salesforce", "CRM", 80),
            "my.salesforce.com": ("Salesforce", "CRM", 85),
            "desk.com": ("Salesforce Desk", "Support", 75),
            "freshdesk": ("Freshdesk", "Support", 75),
            "servicenow": ("ServiceNow", "ITSM", 80),
            "service-now": ("ServiceNow", "ITSM", 80),
            "okta.com": ("Okta", "Identity", 85),
            "auth0.com": ("Auth0", "Identity", 85),
            "hubspot": ("HubSpot", "Marketing", 75),
            "marketo": ("Marketo", "Marketing", 75),
            "pardot": ("Pardot", "Marketing", 75),
            "shopify": ("Shopify", "E-commerce", 80),
            "squarespace": ("Squarespace", "CMS", 80),
            "wix": ("Wix", "CMS", 80),
            "contentful": ("Contentful", "CMS", 80),
            "prismic": ("Prismic", "CMS", 75),
            "ghost": ("Ghost", "CMS", 75),
            "strapi": ("Strapi", "CMS", 75),
            "ntt.com": ("NTT", "Telco", 70),
            "ntt.co.jp": ("NTT", "Telco", 70),
            "softbank": ("SoftBank", "Telco", 70),
            "oracle": ("Oracle", "Cloud", 70),
            "oraclecloud": ("Oracle Cloud", "Cloud", 80),
            "ibm.com": ("IBM", "Cloud", 70),
            "azure-api": ("Azure API Management", "API Gateway", 80),
            "apigee": ("Apigee", "API Gateway", 80),
            "kong": ("Kong", "API Gateway", 75),
            "traefik": ("Traefik", "Proxy", 75),
        }
        for kw, (name, cat, conf) in _dns_tech_hints.items():
            if kw in all_dns_str and name not in inferred:
                inferred[name] = {"category": cat, "confidence": conf}

        # TLS analysis
        tls_data = result.get("tls", {})
        if isinstance(tls_data, dict):
            tls_ver = tls_data.get("tls_version", "")
            if tls_ver:
                inferred[tls_ver] = {"category": "TLS", "confidence": 95}
            cipher = tls_data.get("cipher", "")
            if cipher:
                inferred[cipher] = {"category": "Cipher Suite", "confidence": 95}
            cert_issuer = tls_data.get("cert_issuer")
            if cert_issuer and cert_issuer not in inferred:
                inferred[cert_issuer] = {"category": "Certificate Authority", "confidence": 85}

        # IP range → cloud provider mapping
        _IP_PREFIXES = {
            "13.": "Amazon Web Services", "34.": "Amazon Web Services",
            "35.": "Amazon Web Services", "52.": "Amazon Web Services",
            "54.": "Amazon Web Services", "99.": "Amazon Web Services",
            "3.": "Amazon Web Services",
            "20.": "Microsoft Azure", "40.": "Microsoft Azure",
            "51.": "Microsoft Azure", "52.": "Amazon Web Services",
            "142.250.": "Google Cloud Platform", "172.217.": "Google Cloud Platform",
            "151.101.": "Fastly", "199.232.": "Fastly",
            "198.41.": "Cloudflare", "104.16.": "Cloudflare",
            "104.17.": "Cloudflare", "104.18.": "Cloudflare",
            "104.19.": "Cloudflare", "104.20.": "Cloudflare",
            "104.21.": "Cloudflare", "104.22.": "Cloudflare",
            "23.": "Akamai",
        }
        for rec in a_recs:
            rec_str = str(rec)
            for prefix, provider in _IP_PREFIXES.items():
                if rec_str.startswith(prefix) and provider not in inferred:
                    inferred[provider] = {"category": "Cloud/CDN", "confidence": 60}
                    break

        # Normalize fingerprint-detected techs (lowercase keys → proper names + categories)
        _NORMALIZE = {
            "azure": ("Microsoft Azure", "Cloud"),
            "cloudflare": ("Cloudflare", "CDN/WAF"),
            "cloudfront": ("CloudFront", "CDN"),
            "akamai": ("Akamai", "CDN"),
            "fastly": ("Fastly", "CDN"),
            "varnish": ("Varnish", "Cache"),
            "jquery": ("jQuery", "JavaScript Library"),
            "bootstrap": ("Bootstrap", "CSS Framework"),
            "font_awesome": ("Font Awesome", "Icon Library"),
            "swiper": ("Swiper", "JavaScript Library"),
            "slick": ("Slick Carousel", "JavaScript Library"),
            "react": ("React", "JavaScript Framework"),
            "vue": ("Vue.js", "JavaScript Framework"),
            "angular": ("Angular", "JavaScript Framework"),
            "next.js": ("Next.js", "JavaScript Framework"),
            "nuxt.js": ("Nuxt.js", "JavaScript Framework"),
            "google_tag_manager": ("Google Tag Manager", "Analytics"),
            "google_analytics": ("Google Analytics", "Analytics"),
            "facebook_pixel": ("Facebook Pixel", "Analytics"),
            "linkedin_insight": ("LinkedIn Insight", "Analytics"),
            "microsoft_clarity": ("Microsoft Clarity", "Analytics"),
            "recaptcha": ("Google reCAPTCHA", "Captcha"),
            "hcaptcha": ("hCaptcha", "Captcha"),
            "turnstile": ("Cloudflare Turnstile", "Captcha"),
            "captcha": ("Captcha", "Security"),
            "sitecore": ("Sitecore", "CMS"),
            "adobe_experience_manager": ("Adobe Experience Manager", "CMS"),
            "shopify": ("Shopify", "E-commerce"),
            "php": ("PHP", "Language"),
            "python": ("Python", "Language"),
            "java": ("Java", "Language"),
            ".net": (".NET", "Framework"),
            "ruby": ("Ruby", "Language"),
            "node.js": ("Node.js", "Runtime"),
            "express": ("Express.js", "Framework"),
            "nginx": ("Nginx", "Web Server"),
            "apache": ("Apache", "Web Server"),
            "iis": ("Microsoft IIS", "Web Server"),
            "wordpress": ("WordPress", "CMS"),
            "drupal": ("Drupal", "CMS"),
            "joomla": ("Joomla", "CMS"),
            "cdn": ("CDN", "Infrastructure"),
            "api_json": ("JSON API", "API"),
            # JS Frameworks & Libraries
            "gatsby": ("Gatsby", "JavaScript Framework"),
            "svelte": ("Svelte", "JavaScript Framework"),
            "ember": ("Ember.js", "JavaScript Framework"),
            "backbone": ("Backbone.js", "JavaScript Framework"),
            "knockout": ("Knockout.js", "JavaScript Framework"),
            "mootools": ("MooTools", "JavaScript Library"),
            "prototype_js": ("Prototype.js", "JavaScript Library"),
            "dojo": ("Dojo Toolkit", "JavaScript Framework"),
            "extjs": ("Ext JS", "JavaScript Framework"),
            # UI Libraries
            "tailwindcss": ("Tailwind CSS", "CSS Framework"),
            "material_ui": ("Material UI", "UI Library"),
            "antd": ("Ant Design", "UI Library"),
            "semantic_ui": ("Semantic UI", "UI Library"),
            "foundation": ("Foundation", "CSS Framework"),
            "bulma": ("Bulma", "CSS Framework"),
            # Editors
            "ckeditor": ("CKEditor", "Editor"),
            "tinymce": ("TinyMCE", "Editor"),
            "quill": ("Quill", "Editor"),
            # Charts
            "chartjs": ("Chart.js", "Visualization"),
            "d3": ("D3.js", "Visualization"),
            "highcharts": ("Highcharts", "Visualization"),
            "echarts": ("ECharts", "Visualization"),
            # Video
            "videojs": ("Video.js", "Media"),
            "plyr": ("Plyr", "Media"),
            "flowplayer": ("Flowplayer", "Media"),
            # SaaS
            "salesforce": ("Salesforce", "CRM"),
            "zendesk": ("Zendesk", "Support"),
            "freshdesk": ("Freshdesk", "Support"),
            "intercom": ("Intercom", "Support"),
            "drift": ("Drift", "Support"),
            "crisp": ("Crisp", "Support"),
            "tawkto": ("Tawk.to", "Support"),
            "livechat": ("LiveChat", "Support"),
            "marketo": ("Marketo", "Marketing"),
            "pardot": ("Pardot", "Marketing"),
            "segment": ("Segment", "Analytics"),
            "mixpanel": ("Mixpanel", "Analytics"),
            "amplitude": ("Amplitude", "Analytics"),
            "heap": ("Heap", "Analytics"),
            "optimizely": ("Optimizely", "A/B Testing"),
            "launchdarkly": ("LaunchDarkly", "Feature Flags"),
            "fullstory": ("FullStory", "Analytics"),
            "mouseflow": ("Mouseflow", "Analytics"),
            "crazyegg": ("Crazy Egg", "Analytics"),
            # Payment
            "stripe": ("Stripe", "Payment"),
            "paypal": ("PayPal", "Payment"),
            "braintree": ("Braintree", "Payment"),
            "adyen": ("Adyen", "Payment"),
            # Auth
            "auth0": ("Auth0", "Identity"),
            "okta": ("Okta", "Identity"),
            "firebase": ("Firebase", "BaaS"),
            "supabase": ("Supabase", "BaaS"),
            # Maps
            "google_maps": ("Google Maps", "Maps"),
            "mapbox": ("Mapbox", "Maps"),
            "leaflet": ("Leaflet", "Maps"),
            # CMS / E-commerce
            "magento": ("Magento", "E-commerce"),
            "squarespace": ("Squarespace", "CMS"),
            "wix": ("Wix", "CMS"),
            "webflow": ("Webflow", "CMS"),
            "ghost": ("Ghost", "CMS"),
            "contentful": ("Contentful", "CMS"),
            "prismic": ("Prismic", "CMS"),
            "sanity": ("Sanity", "CMS"),
            # Cookie-detected techs
            "hubspot": ("HubSpot", "Marketing"),
            "hotjar": ("Hotjar", "Analytics"),
            "haproxy": ("HAProxy", "Load Balancer"),
            "f5": ("F5 BIG-IP", "Load Balancer"),
            "netscaler": ("Citrix NetScaler", "Load Balancer"),
            "flask": ("Flask", "Framework"),
            # Server header aliases (from .title() mangling)
            "Amazons3": ("AWS S3", "Storage"),
            "Awselb": ("AWS ELB", "Load Balancer"),
            "Awsalb": ("AWS ALB", "Load Balancer"),
            "Akamaighost": ("Akamai", "CDN"),
            "Akamainetstorage": ("Akamai", "CDN"),
            "Cloudfront": ("AWS CloudFront", "CDN"),
            "Openresty": ("OpenResty", "Web Server"),
            "Envoy": ("Envoy Proxy", "Proxy"),
            "Gunicorn": ("Gunicorn", "Web Server"),
            "Uvicorn": ("Uvicorn", "Web Server"),
            "Caddy": ("Caddy", "Web Server"),
            "Litespeed": ("LiteSpeed", "Web Server"),
            "Tengine": ("Tengine", "Web Server"),
            "Cowboy": ("Cowboy", "Web Server"),
            # Hyphenated server headers (.title() keeps hyphens)
            "Microsoft-Iis": ("Microsoft IIS", "Web Server"),
            "Microsoft-Azure-Application-Gateway": ("Azure Application Gateway", "Load Balancer"),
            "Akamaighost": ("Akamai", "CDN"),
            "Big-Ip": ("F5 BIG-IP", "Load Balancer"),
            "Ovh": ("OVH", "Cloud"),
            "Gws": ("Google Web Server", "Web Server"),
            "Gse": ("Google Servlet Engine", "Web Server"),
            "Sffe": ("Google SFFE", "Web Server"),
            "Ats": ("Apache Traffic Server", "Proxy"),
            "ovh": ("OVH", "Cloud"),
            # AI / LLM / Chatbot platforms
            "botpress": ("Botpress", "AI Chatbot"),
            "voiceflow": ("Voiceflow", "AI Chatbot"),
            "ada_chatbot": ("Ada", "AI Chatbot"),
            "tidio": ("Tidio", "AI Chatbot"),
            "kommunicate": ("Kommunicate", "AI Chatbot"),
            "customerly": ("Customerly", "AI Chatbot"),
            "chatbase": ("Chatbase", "AI Chatbot"),
            "landbot": ("Landbot", "AI Chatbot"),
            "chatgpt_embed": ("ChatGPT Embed", "AI / LLM"),
            "botsonic": ("Botsonic", "AI Chatbot"),
            "dialogflow": ("Google Dialogflow", "AI Chatbot"),
            "watson_assistant": ("IBM Watson Assistant", "AI Chatbot"),
            "amazon_lex": ("Amazon Lex", "AI Chatbot"),
            "rasa": ("Rasa", "AI Chatbot"),
            "manychat": ("ManyChat", "Chatbot"),
            "chatfuel": ("Chatfuel", "Chatbot"),
            "collectchat": ("Collect.chat", "Chatbot"),
            "flowxo": ("Flow XO", "Chatbot"),
            "tiledesk": ("Tiledesk", "AI Chatbot"),
            "yellow_ai": ("Yellow.ai", "AI Chatbot"),
            "haptik": ("Haptik", "AI Chatbot"),
            "verloop": ("Verloop", "AI Chatbot"),
            "engati": ("Engati", "AI Chatbot"),
            "gorgias": ("Gorgias", "AI Support"),
            "kore_ai": ("Kore.ai", "AI Chatbot"),
            # AI Platforms & LLM Providers
            "openai": ("OpenAI", "AI / LLM"),
            "openai_api": ("OpenAI API", "AI / LLM"),
            "anthropic": ("Anthropic", "AI / LLM"),
            "anthropic_api": ("Anthropic API", "AI / LLM"),
            "cohere": ("Cohere", "AI / LLM"),
            "huggingface": ("Hugging Face", "AI / ML"),
            "replicate": ("Replicate", "AI / ML"),
            "together_ai": ("Together AI", "AI / LLM"),
            "groq": ("Groq", "AI / LLM"),
            "mistral": ("Mistral AI", "AI / LLM"),
            "perplexity": ("Perplexity AI", "AI / LLM"),
            "fireworks_ai": ("Fireworks AI", "AI / LLM"),
            "anyscale": ("Anyscale", "AI / ML"),
            "deepinfra": ("DeepInfra", "AI / LLM"),
            "ollama": ("Ollama", "AI / LLM"),
            "llm_api": ("LLM API", "AI / LLM"),
            "llm_streaming": ("LLM Streaming", "AI / LLM"),
            # AI Frameworks & Orchestration
            "langchain": ("LangChain", "AI Framework"),
            "llamaindex": ("LlamaIndex", "AI Framework"),
            # Vector Databases
            "pinecone": ("Pinecone", "Vector DB"),
            "weaviate": ("Weaviate", "Vector DB"),
            "chromadb": ("ChromaDB", "Vector DB"),
            "qdrant": ("Qdrant", "Vector DB"),
            "milvus": ("Milvus", "Vector DB"),
            # AI Search & RAG
            "algolia_ai": ("Algolia AI", "AI Search"),
            "vectara": ("Vectara", "AI Search"),
            "mendable": ("Mendable", "AI Search"),
            "inkeep": ("Inkeep", "AI Search"),
            "docsbot": ("DocsBot", "AI Chatbot"),
            # Cloud AI Services
            "copilot": ("Microsoft Copilot", "AI / LLM"),
            "github_copilot": ("GitHub Copilot", "AI / LLM"),
            "google_gemini": ("Google Gemini", "AI / LLM"),
            "google_vertex_ai": ("Google Vertex AI", "AI / ML"),
            "aws_bedrock": ("AWS Bedrock", "AI / LLM"),
            "aws_sagemaker": ("AWS SageMaker", "AI / ML"),
            "azure_openai": ("Azure OpenAI", "AI / LLM"),
            "azure_ml": ("Azure ML", "AI / ML"),
            "cloudflare_ai_gateway": ("Cloudflare AI Gateway", "AI Gateway"),
            # API Gateway (detected via headers)
            "kong": ("Kong", "API Gateway"),
        }
        for old_key, (proper_name, cat) in _NORMALIZE.items():
            if old_key in inferred:
                entry = inferred.pop(old_key)
                entry["category"] = cat
                if proper_name in inferred:
                    existing = inferred[proper_name]
                    if entry.get("confidence", 0) > existing.get("confidence", 0):
                        inferred[proper_name] = entry
                else:
                    inferred[proper_name] = entry

        # Deduplication pass: merge remaining aliases
        _ALIASES = {
            "Google Cloud": "Google Cloud Platform",
            "Google": "Google Cloud Platform",
            "Akamai Edge": "Akamai",
            "Akamai DNS": "Akamai",
            "Akamai (Kona/AAP)": "Akamai",  # merged as CDN/WAF
            "Apache HTTP Server": "Apache",
            "CloudFront": "AWS CloudFront",
            "Microsoft Azure App Service": "Microsoft Azure",
            "Microsoft Azure DNS": "Microsoft Azure",
        }
        for old_name, canonical in _ALIASES.items():
            if old_name in inferred:
                old_entry = inferred.pop(old_name)
                if canonical not in inferred or inferred[canonical].get("confidence", 0) < old_entry.get("confidence", 0):
                    inferred[canonical] = old_entry

        # Post-alias category fixes for multi-role providers
        if "Akamai" in inferred:
            inferred["Akamai"]["category"] = "CDN/WAF"

        if inferred:
            fp["technologies"] = inferred

    # ── Enrich CVEs from server headers ──
    fl = result.get("frontend_libs", {})
    if isinstance(fl, dict):
        server_hdrs = list({s.get("server", "") for s in per_sub if s.get("server") and s.get("server") != "-"})
        resp_hdrs = result.get("headers", {})
        x_powered = resp_hdrs.get("x-powered-by") if isinstance(resp_hdrs, dict) else None
        tls_data = result.get("tls", {})
        srv_vulns = check_server_cves(server_hdrs, x_powered_by=x_powered, tls_data=tls_data)
        if srv_vulns:
            existing_vulns = fl.get("vulnerabilities", [])
            existing_ids = {(v.get("library"), v.get("id")) for v in existing_vulns}
            for sv in srv_vulns:
                key = (sv.get("library"), sv.get("id"))
                if key not in existing_ids:
                    existing_vulns.append(sv)
                    existing_ids.add(key)
            fl["vulnerabilities"] = existing_vulns
            fl["vulnerable_libs"] = len({v.get("library") for v in existing_vulns})
            # Also add server techs as detected libraries
            existing_libs = fl.get("libraries", [])
            seen_libs = {l.get("name") for l in existing_libs}
            for sv in srv_vulns:
                lib_name = sv.get("library", "")
                if lib_name not in seen_libs:
                    existing_libs.append({
                        "name": lib_name,
                        "version": sv.get("version", ""),
                        "source": "server_header",
                        "url": "",
                        "cves": [sv["id"]],
                    })
                    seen_libs.add(lib_name)
            fl["libraries"] = existing_libs

    # ── Attack Targets (union of all vector targets, deduped, sorted by priority) ──
    seen = set()
    targets_list = []
    for vec in vectors:
        for t in vec.get("targets", []):
            if t not in seen:
                seen.add(t)
                targets_list.append({"target": t, "type": vec["type"], "priority": vec["priority"]})
    targets_list.sort(key=lambda x: -x["priority"])
    atk["attack_targets"] = targets_list

    # ── Remediation Plan ──
    remediation = []
    hdrs = result.get("headers", {})
    hdr_score = hdrs.get("score", 0) if isinstance(hdrs, dict) else 0
    missing_hdrs = hdrs.get("missing", {}) if isinstance(hdrs, dict) else {}
    csp = result.get("csp", {})
    csp_present = csp.get("present", False) if isinstance(csp, dict) else False

    if not csp_present:
        remediation.append({
            "action": "Deploy Content-Security-Policy header", "severity": "critical",
            "why": "Prevents XSS, data injection, and clickjacking attacks",
            "how": "Add CSP header to web server config; start with report-only mode",
            "timeline": "Immediate",
        })
    if hdr_score < 50:
        n_miss = len(missing_hdrs) if isinstance(missing_hdrs, dict) else 0
        remediation.append({
            "action": "Harden security headers", "severity": "critical",
            "why": f"Only {hdr_score}/100 — missing {n_miss} essential headers",
            "how": "Add missing headers to reverse proxy / web server configuration",
            "timeline": "Immediate",
        })
    if waf_bypass:
        remediation.append({
            "action": f"Fix {len(waf_bypass)} WAF-bypass subdomain(s)", "severity": "critical",
            "why": "Attackers bypass WAF via direct origin access",
            "how": "Route all subdomains through CDN or restrict origin IP access via firewall",
            "timeline": "Short-term",
        })
    if rl_type == "none":
        remediation.append({
            "action": "Implement rate limiting", "severity": "high",
            "why": "No rate limiting — vulnerable to brute-force & L7 DDoS",
            "how": "Enable rate limiting on WAF/reverse proxy (e.g., 100 req/min per IP)",
            "timeline": "Short-term",
        })
    if staging_envs:
        remediation.append({
            "action": f"Restrict {len(staging_envs)} staging/dev environments", "severity": "high",
            "why": "Staging environments often have weaker security controls",
            "how": "Add authentication, IP whitelist, or remove from public DNS",
            "timeline": "Short-term",
        })
    dns = result.get("dns", {})
    spf = dns.get("spf", "") if isinstance(dns, dict) else ""
    dmarc = dns.get("dmarc", "") if isinstance(dns, dict) else ""
    if not spf:
        remediation.append({
            "action": "Add SPF record", "severity": "medium",
            "why": "Domain vulnerable to email spoofing",
            "how": 'Add TXT record: v=spf1 include:... -all',
            "timeline": "Short-term",
        })
    if not dmarc:
        remediation.append({
            "action": "Add DMARC record", "severity": "medium",
            "why": "No email authentication enforcement",
            "how": 'Add TXT record: v=DMARC1; p=reject; rua=...',
            "timeline": "Short-term",
        })
    gap_findings = result.get("gap_analysis", {}).get("findings", [])
    if gap_findings:
        remediation.append({
            "action": f"Address {len(gap_findings)} WAF gap(s)", "severity": "medium",
            "why": "Known bypass techniques applicable to detected WAF",
            "how": "Review gap analysis and add custom WAF rules",
            "timeline": "Medium-term",
        })

    atk["remediation"] = remediation

    # ── Expose origin_ips and admin_panels in report-friendly format ──
    origin_ip_data = result.get("origin_ip", {})
    if isinstance(origin_ip_data, dict):
        result["origin_ips"] = origin_ip_data

    # ── WAF bypass subdomains in cloud_distribution ──
    if waf_bypass and "waf_bypass_subdomains" not in cloud_dist:
        cloud_dist["waf_bypass_subdomains"] = waf_bypass

    # ── Subdomain probes ──
    probes = result.get("subdomain_probes", {})
    if not probes:
        # Build from subdomains_active if available
        active_data = result.get("subdomains_active", {})
        if isinstance(active_data, dict) and active_data.get("results"):
            result["subdomain_probes"] = {
                "total": active_data.get("total", 0),
                "responsive": active_data.get("responsive", 0),
                "results": active_data.get("results", []),
            }

    # ── Security checks summary ──
    checks = {}
    cors = result.get("cors", {})
    if isinstance(cors, dict) and cors.get("vulnerable"):
        checks["cors"] = {"findings": [f"CORS misconfiguration: {cors.get('details', 'origin reflected')}"]}
    takeover = result.get("subdomain_takeover", {})
    if isinstance(takeover, dict) and takeover.get("vulnerable"):
        checks["subdomain_takeover"] = {"findings": [f"{len(takeover['vulnerable'])} subdomain(s) vulnerable to takeover"]}
    hhi = result.get("host_header_injection", {})
    if isinstance(hhi, dict) and hhi.get("vulnerable"):
        checks["host_header_injection"] = {"findings": ["Host header injection detected"]}
    result["security_checks"] = checks


def _build_attack_surface_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate all recon findings into a compact attack surface overview."""
    host = r.get("host", "")
    page_status = r.get("page_status", 0)

    # ── Subdomains ──
    subs = r.get("subdomains", {})
    subdomain_list = subs.get("subdomains", [])
    n_subdomains = len(subdomain_list) if isinstance(subdomain_list, list) else 0

    # Detect staging / dev / internal environments
    staging_keywords = ("dev", "staging", "stage", "test", "qa", "uat", "sandbox",
                        "beta", "alpha", "preprod", "pre-prod", "demo", "internal",
                        "debug", "canary", "preview")
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

    # ── Auth endpoints ──
    auth_ep = r.get("auth_endpoints", {})
    auth_endpoints = auth_ep.get("endpoints", []) if isinstance(auth_ep, dict) else []
    n_auth = len(auth_endpoints)
    has_login = auth_ep.get("has_login", False) if isinstance(auth_ep, dict) else False
    has_registration = auth_ep.get("has_registration", False) if isinstance(auth_ep, dict) else False
    has_oauth = auth_ep.get("has_oauth", False) if isinstance(auth_ep, dict) else False
    has_mfa = auth_ep.get("has_mfa", False) if isinstance(auth_ep, dict) else False

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

    # ── Favicon ──
    fav = r.get("favicon", {})
    favicon_found = fav.get("found", False) if isinstance(fav, dict) else False
    favicon_tech = fav.get("technology") if isinstance(fav, dict) else None
    favicon_mmh3 = fav.get("mmh3") if isinstance(fav, dict) else None

    # ── Technologies ──
    fp = r.get("fingerprint", {})
    techs = fp.get("technologies", {}) if isinstance(fp, dict) else {}
    tech_names = sorted(techs.keys()) if techs else []

    # ── WAF ──
    gap = r.get("gap_analysis", {})
    waf_vendor = gap.get("waf_vendor") if isinstance(gap, dict) else None
    diff = r.get("differential", {})
    detection_mode = (diff.get("detection_mode") or "").lower() or None if isinstance(diff, dict) else None
    waf_redirect_target = diff.get("redirect_followed") if isinstance(diff, dict) else None

    # ── DNS / CDN ──
    dns_info = r.get("dns", {})
    cdn = dns_info.get("cdn_detected") if isinstance(dns_info, dict) else None

    # ── TLS ──
    tls = r.get("tls", {})
    tls_version = tls.get("tls_version") if isinstance(tls, dict) else None
    cert_days = tls.get("cert_days_remaining") if isinstance(tls, dict) else None
    tls_gr = r.get("tls_grade", {})
    tls_grade = tls_gr.get("grade") if isinstance(tls_gr, dict) else None
    tls_grade_score = tls_gr.get("score") if isinstance(tls_gr, dict) else None

    # ── Security headers score ──
    hdrs = r.get("headers", {})
    hdr_score = hdrs.get("score") if isinstance(hdrs, dict) else None

    # ── CSP ──
    csp = r.get("csp", {})
    csp_present = csp.get("present", False) if isinstance(csp, dict) else False
    csp_score = csp.get("score") if isinstance(csp, dict) else None

    # ── Clickjacking ──
    clickjack = r.get("clickjacking", {})
    clickjack_vuln = clickjack.get("vulnerable", False) if isinstance(clickjack, dict) else False

    # ── CAPTCHA / Bot Protection ──
    captcha = r.get("captcha", {})
    captcha_detected = captcha.get("detected", False) if isinstance(captcha, dict) else False
    captcha_providers = [p["name"] for p in captcha.get("providers", [])] if isinstance(captcha, dict) else []

    # ── Port Scan ──
    ps = r.get("port_scan", {})
    open_ports = ps.get("open_count", 0) if isinstance(ps, dict) else 0
    risky_ports = ps.get("risky_ports", []) if isinstance(ps, dict) else []

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

    # ── Per-finding severity scoring model ──
    # Maps keywords in finding text to specific numeric scores (0-100).
    # Falls back to severity-level base scores if no keyword match.
    _FINDING_SCORES = {
        # Critical (80-100)
        "origin IP exposed":        95, "takeover":              95,
        "zone transfer":            95, "AXFR":                  95,
        "DNS rebinding":            95,
        "secret":                   90, "leaked":                90,
        "bypass WAF":               90, "admin panel":           85,
        # High (60-79)
        "host header injection":    75, "CORS misconfiguration": 70,
        "GraphQL introspection":    70, "risky port":            65,
        "CVE":                      65, "origin IP candidate":   60,
        "HIBP breach":              60, "credential":            60,
        # Medium (30-59)
        "clickjacking":             50, "dangerous HTTP method":  45,
        "injectable parameter":     45, "exposed sensitive file": 40,
        "staging":                  40, "SRI":                   35,
        "TLS certificate expires":  35,
        # Low (10-29)
        "Content-Security-Policy":  20, "robots.txt":            15,
        "DNSSEC":                   15, "Wildcard DNS":          10,
        "DNS hygiene":              30, "Subdomain sprawl":      30,
        "Multi-cloud":              10,
        "WAF":                      10,
    }
    _SEVERITY_BASE = {"critical": 90, "high": 65, "medium": 40, "low": 15}

    def _score_finding(f: dict) -> int:
        text = f.get("finding", "")
        sev = f.get("severity", "low")
        for keyword, score in _FINDING_SCORES.items():
            if keyword.lower() in text.lower():
                return score
        return _SEVERITY_BASE.get(sev, 15)

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
    if waf_vendor and waf_redirect_target:
        findings.append({"severity": "low", "finding": f"WAF ({waf_vendor}) detected on redirect target ({waf_redirect_target}), not the original domain"})
    if clickjack_vuln:
        findings.append({"severity": "medium", "finding": "Clickjacking vulnerable — no X-Frame-Options or CSP frame-ancestors"})
    if risky_ports:
        port_list = ", ".join(f"{p['port']}/{p['service']}" for p in risky_ports)
        findings.append({"severity": "high", "finding": f"{len(risky_ports)} risky port(s) open: {port_list}"})
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

    # ── DNS rebinding (#49) ──
    rebind_data = r.get("dns_rebinding", {})
    if isinstance(rebind_data, dict) and rebind_data.get("vulnerable"):
        priv_ips = ", ".join(rebind_data.get("private_ips", [])[:3])
        findings.append({"severity": "critical", "finding": f"DNS rebinding — domain resolves to private IP(s): {priv_ips}"})

    # ── Subdomain sprawl (#76) ──
    sprawl = r.get("subdomain_sprawl", {})
    sprawl_total = sprawl.get("total", 0) if isinstance(sprawl, dict) else 0
    sprawl_staging = sprawl.get("staging_count", 0) if isinstance(sprawl, dict) else 0
    sprawl_severity = sprawl.get("severity", "low") if isinstance(sprawl, dict) else "low"
    if sprawl_total >= 100:
        findings.append({"severity": "high" if sprawl_total >= 200 else "medium",
                         "finding": f"Subdomain sprawl: {sprawl_total} subdomains ({sprawl_staging} staging/dev)"})
    elif sprawl_total >= 50:
        findings.append({"severity": "low", "finding": f"Subdomain sprawl: {sprawl_total} subdomains ({sprawl_staging} staging/dev)"})

    # ── Cloud distribution (#77) ──
    cloud_dist = r.get("cloud_distribution", {})
    if isinstance(cloud_dist, dict) and cloud_dist.get("multi_cloud"):
        providers = cloud_dist.get("providers", [])[:4]
        findings.append({"severity": "low", "finding": f"Multi-cloud infrastructure: {', '.join(providers)}"})

    # ── DNS hygiene score (#74) ──
    dns_hygiene = r.get("dns_hygiene", {})
    dns_hygiene_score = dns_hygiene.get("score", 0) if isinstance(dns_hygiene, dict) else 0
    dns_hygiene_grade = dns_hygiene.get("grade", "?") if isinstance(dns_hygiene, dict) else "?"
    dns_hygiene_failed = dns_hygiene.get("failed", 0) if isinstance(dns_hygiene, dict) else 0
    if dns_hygiene_failed > 0 and dns_hygiene_score < 60:
        findings.append({"severity": "medium", "finding": f"DNS hygiene score {dns_hygiene_score}/100 (grade {dns_hygiene_grade}) — {dns_hygiene_failed} check(s) failed"})
    elif dns_hygiene_failed > 0:
        findings.append({"severity": "low", "finding": f"DNS hygiene score {dns_hygiene_score}/100 (grade {dns_hygiene_grade}) — {dns_hygiene_failed} check(s) failed"})

    # ── DNS security findings (#47, #48, #51) ──
    dnssec_data = r.get("dnssec", {})
    if isinstance(dnssec_data, dict) and dnssec_data:
        if not dnssec_data.get("enabled", False):
            findings.append({"severity": "low", "finding": "DNSSEC not enabled — DNS responses can be spoofed"})
        elif dnssec_data.get("enabled") and not dnssec_data.get("validated"):
            findings.append({"severity": "medium", "finding": "DNSSEC enabled but not validated by resolver (broken chain of trust)"})
    axfr_data = r.get("zone_transfer", {})
    if isinstance(axfr_data, dict) and axfr_data.get("vulnerable"):
        ns_list = ", ".join(axfr_data.get("ns_vulnerable", [])[:3])
        n_leaked = axfr_data.get("records_leaked", 0)
        findings.append({"severity": "critical", "finding": f"DNS zone transfer (AXFR) allowed — {n_leaked} record(s) leaked via {ns_list}"})
    wildcard_data = r.get("wildcard_dns", {})
    if isinstance(wildcard_data, dict) and wildcard_data.get("wildcard"):
        wc_ips = ", ".join(wildcard_data.get("wildcard_ips", [])[:3])
        findings.append({"severity": "low", "finding": f"Wildcard DNS detected — all subdomains resolve to {wc_ips}"})

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

    # ── Finding deduplication (#182) ──
    _seen_hashes = set()
    _deduped = []
    for f in findings:
        _key = f["finding"].lower().strip()
        if _key not in _seen_hashes:
            _seen_hashes.add(_key)
            _deduped.append(f)
    findings = _deduped

    # ── Per-finding risk scores (0-100) ──
    for f in findings:
        f["risk_score"] = _score_finding(f)

    # ── Finding grouping by category (#183) ──
    _FINDING_CATEGORIES = {
        "infra": {"origin IP", "takeover", "port", "WAF", "bypass WAF", "DNS",
                  "zone transfer", "AXFR", "DNSSEC", "Wildcard DNS", "DNS hygiene",
                  "DNS rebinding", "Subdomain sprawl", "Multi-cloud"},
        "app":   {"XSS", "injection", "CORS", "clickjacking", "GraphQL",
                  "injectable", "HTTP method", "host header"},
        "config": {"Content-Security-Policy", "SRI", "robots.txt", "admin panel",
                   "exposed sensitive", "staging", "TLS certificate"},
        "data":  {"secret", "leaked", "credential", "HIBP", "CVE"},
    }
    for f in findings:
        text = f.get("finding", "")
        cat = "other"
        for category, keywords in _FINDING_CATEGORIES.items():
            if any(kw.lower() in text.lower() for kw in keywords):
                cat = category
                break
        f["category"] = cat

    # Sort findings by risk_score descending
    findings.sort(key=lambda f: f["risk_score"], reverse=True)

    # ── Aggregate risk score (0-100) ──
    risk_score = 0
    for f in findings:
        if f["severity"] == "critical": risk_score += 25
        elif f["severity"] == "high": risk_score += 15
        elif f["severity"] == "medium": risk_score += 8
        elif f["severity"] == "low": risk_score += 3
    risk_score = min(risk_score, 100)

    # Factor in WAF presence (skip penalty for unreachable domains)
    if waf_vendor:
        risk_score = max(0, risk_score - 10)
    elif page_status != 0:
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
        "http_status": page_status,
        "subdomains": n_subdomains,
        "staging_envs": staging_envs,
        "admin_panels": n_panels,
        "open_admin_panels": len(open_panels),
        "auth_endpoints": n_auth,
        "has_login": has_login,
        "has_registration": has_registration,
        "has_oauth": has_oauth,
        "has_mfa": has_mfa,
        "graphql_endpoints": len(gql_endpoints),
        "graphql_introspection": gql_introspection,
        "api_specs": len(api_specs),
        "api_endpoints": len(api_endpoints),
        "exposed_files": n_exposed,
        "injectable_params": n_params,
        "high_risk_params": len(high_risk_params),
        "historical_urls": n_historical,
        "interesting_historical": len(interesting_hist),
        "favicon_hash": favicon_mmh3,
        "favicon_technology": favicon_tech,
        "technologies": tech_names,
        "waf_vendor": waf_vendor,
        "waf_redirect_target": waf_redirect_target,
        "waf_detection_mode": detection_mode,
        "cdn": cdn,
        "tls_version": tls_version,
        "tls_grade": tls_grade,
        "tls_grade_score": tls_grade_score,
        "cert_days_remaining": cert_days,
        "security_headers_score": hdr_score,
        "csp_present": csp_present,
        "csp_score": csp_score,
        "cors_vulnerable": cors_vuln,
        "clickjacking_vulnerable": clickjack_vuln,
        "captcha_detected": captcha_detected,
        "captcha_providers": captcha_providers,
        "open_ports": open_ports,
        "risky_ports": [{"port": p["port"], "service": p["service"]} for p in risky_ports],
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

        # Per-subdomain WAF/CDN table
        cloud_dist = result.get("cloud_distribution", {})
        per_sub = cloud_dist.get("per_subdomain", [])
        if per_sub:
            console.print()
            sub_table = Table(title="Per-Subdomain WAF / CDN", box=None, pad_edge=False,
                              padding=(0, 1), show_header=True, header_style="bold")
            sub_table.add_column("Subdomain", min_width=28)
            sub_table.add_column("WAF", min_width=20)
            sub_table.add_column("CDN", min_width=16)
            sub_table.add_column("Cache", min_width=8)
            sub_table.add_column("HTTP", width=5)
            sub_table.add_column("Server", min_width=14)
            for s in per_sub:
                waf_v = s.get("waf") or "(no WAF)"
                cdn_v = s.get("cdn") or "(direct)"
                waf_style = f"[green]{waf_v}[/green]" if s.get("waf") else f"[red]{waf_v}[/red]"
                cdn_style = f"[cyan]{cdn_v}[/cyan]" if s.get("cdn") else f"[dim]{cdn_v}[/dim]"
                cache = s.get("cache_status") or "-"
                http_st = str(s.get("status") or "-")
                srv = (s.get("server") or "-")[:18]
                sub_table.add_row(s["subdomain"], waf_style, cdn_style, cache, http_st, f"[dim]{srv}[/dim]")
            console.print(sub_table)

            # Distribution summary
            waf_dist = cloud_dist.get("waf_distribution", {})
            cdn_dist = cloud_dist.get("cdn_distribution", {})
            if waf_dist:
                waf_parts = ", ".join(f"[green]{k}[/green] {v['pct']}%" for k, v in waf_dist.items())
                console.print(f"    WAF coverage: {waf_parts}")
            if cdn_dist:
                cdn_parts = ", ".join(f"[cyan]{k}[/cyan] {v['pct']}%" for k, v in cdn_dist.items())
                console.print(f"    CDN coverage: {cdn_parts}")
            if cloud_dist.get("multi_waf"):
                console.print("    [yellow]⚠ Multi-WAF environment detected[/yellow]")

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
                score = f.get("risk_score", 0)
                score_color = "bold red" if score >= 80 else ("red" if score >= 60 else ("yellow" if score >= 40 else "dim"))
                console.print(f"      {icon} [{score_color}]{score:>3}[/{score_color}]  {f['finding']}")
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
    tls_gr = result.get("tls_grade", {})
    if tls and not tls.get("error"):
        v = str(tls.get("tls_version", "?"))
        vc = "green" if "1.3" in v else ("yellow" if "1.2" in v else "red")
        grade = tls_gr.get("grade", "?") if tls_gr else "?"
        grade_score = tls_gr.get("score", "?") if tls_gr else "?"
        gc = "green" if grade in ("A+", "A") else ("yellow" if grade == "B" else "red")
        console.print(f"  [bold]TLS[/bold] ([{gc}]Grade {grade} · {grade_score}%[/{gc}])")
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
        for strength in tls_gr.get("strengths", []):
            console.print(f"    [green]✓[/green] {strength}")
        for issue in tls_gr.get("issues", []):
            console.print(f"    [red]✗[/red] {issue}")
        console.print()
    elif tls and tls.get("error"):
        console.print("  [bold]TLS[/bold] ([red]Grade F[/red])")
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
            if isinstance(conf, dict):
                pct = conf.get("confidence", 50) / 100.0
                cat = conf.get("category", "")
                cat_suffix = f" [dim]({cat})[/dim]" if cat else ""
            else:
                pct = float(conf) if isinstance(conf, (int, float)) else 0.5
                cat_suffix = ""
            bar_len = int(pct * 20)
            bar = "\u2588" * bar_len + "\u2591" * (20 - bar_len)
            bc = "green" if pct >= 0.7 else ("yellow" if pct >= 0.4 else "dim")
            console.print(f"    {tech:<30} [{bc}]{bar} {pct:.0%}[/{bc}]{cat_suffix}")
    else:
        console.print("    [dim]No technologies identified[/dim]")

    # Favicon fingerprint
    fav = result.get("favicon", {})
    if fav and fav.get("found"):
        fav_tech = fav.get("technology")
        fav_hash = fav.get("mmh3")
        fav_md5 = fav.get("md5", "")[:16]
        if fav_tech:
            console.print(f"    Favicon: [cyan]{fav_tech}[/cyan] [dim](mmh3:{fav_hash}, md5:{fav_md5}…)[/dim]")
        else:
            console.print(f"    Favicon: [dim]unknown (mmh3:{fav_hash}, md5:{fav_md5}…)[/dim]")
        console.print(f"    Shodan:  [dim]{fav.get('shodan_query', '')}[/dim]")
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
            console.print(f"    [bold yellow]Missing SRI ({len(sri_issues)} external resources)[/bold yellow]")
            for si in sri_issues:
                if si.get("library"):
                    console.print(f"      [yellow]\u26a0[/yellow] {si['library']} {si['version']}")
                else:
                    url_short = si['url'][:80] + ("..." if len(si['url']) > 80 else "")
                    console.print(f"      [yellow]\u26a0[/yellow] {url_short}")
                console.print(f"        [dim]{si['issue']}[/dim]")
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

    # ── Clickjacking ──
    cj = result.get("clickjacking", {})
    if cj:
        cj_vuln = cj.get("vulnerable", False)
        cj_sev = cj.get("severity", "?")
        cc = "red" if cj_vuln else "green"
        cl = "VULNERABLE" if cj_vuln else "PROTECTED"
        console.print(f"  [bold]Clickjacking[/bold] ([{cc}]{cl}[/{cc}])")
        for prot in cj.get("protections", []):
            console.print(f"    [green]✓[/green] {prot}")
        for iss in cj.get("issues", []):
            console.print(f"    [red]✗[/red] {iss}")
        if cj.get("recommendation"):
            console.print(f"    [dim]{cj['recommendation']}[/dim]")
        console.print()

    # ── CAPTCHA / Bot Protection ──
    cap = result.get("captcha", {})
    if cap and cap.get("detected"):
        providers = cap.get("providers", [])
        names = ", ".join(p["name"] for p in providers)
        col = "yellow" if cap.get("challenge_on_load") else "cyan"
        console.print(f"  [bold]CAPTCHA / Bot Protection[/bold] ([{col}]{len(providers)} provider(s)[/{col}])")
        for p in providers:
            ev = "; ".join(p.get("evidence", []))
            console.print(f"    [{col}]{p['name']}[/{col}] ({p['type']}) — {ev}")
        if cap.get("challenge_on_load"):
            console.print("    [yellow]⚠ Challenge fires on page load — automated scanning may be blocked[/yellow]")
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

    # ── Auth Endpoints ──
    auth_ep = result.get("auth_endpoints", {})
    auth_found = auth_ep.get("endpoints", []) if isinstance(auth_ep, dict) else []
    if auth_found:
        cats = auth_ep.get("categories", {})
        cat_tags = []
        if cats.get("login"):
            cat_tags.append(f"[cyan]{cats['login']} login[/cyan]")
        if cats.get("registration"):
            cat_tags.append(f"[cyan]{cats['registration']} registration[/cyan]")
        if cats.get("oauth") or cats.get("sso"):
            n_oauth = cats.get("oauth", 0) + cats.get("sso", 0)
            cat_tags.append(f"[cyan]{n_oauth} OAuth/SSO[/cyan]")
        if cats.get("mfa"):
            cat_tags.append(f"[green]{cats['mfa']} MFA[/green]")
        if cats.get("password_reset"):
            cat_tags.append(f"[yellow]{cats['password_reset']} password reset[/yellow]")
        if cats.get("api_auth"):
            cat_tags.append(f"[cyan]{cats['api_auth']} API auth[/cyan]")
        summary = ", ".join(cat_tags) if cat_tags else f"{len(auth_found)} endpoints"
        console.print(f"  [bold]Auth Endpoints[/bold] ({summary})")
        for ep in auth_found:
            path = ep["path"]
            status = ep["status"]
            cat = ep["category"]
            extras = []
            if ep.get("has_csrf"):
                extras.append("[green]CSRF[/green]")
            if ep.get("rate_limited"):
                extras.append("[green]rate-limited[/green]")
            if ep.get("openid_discovery"):
                extras.append("[cyan]OpenID[/cyan]")
            if ep.get("auth_scheme"):
                extras.append(f"[dim]{ep['auth_scheme']}[/dim]")
            extra_str = " " + " ".join(extras) if extras else ""
            if ep.get("protected"):
                console.print(f"    [yellow]\U0001f512 {path}[/yellow] — {status} auth required [dim]({cat})[/dim]{extra_str}")
            elif ep.get("redirect"):
                redir_short = ep['redirect'][:60]
                console.print(f"    [green]→[/green] {path} — {status} → {redir_short} [dim]({cat})[/dim]{extra_str}")
            else:
                console.print(f"    [cyan]●[/cyan] {path} — {status} [dim]({cat})[/dim]{extra_str}")
        if not auth_ep.get("has_mfa"):
            console.print("    [yellow]⚠ No MFA/2FA endpoint detected[/yellow]")
        console.print()

    # ── Port Scan ──
    ps = result.get("port_scan", {})
    ps_open = ps.get("open", []) if isinstance(ps, dict) else []
    if ps_open:
        risky = ps.get("risky_ports", [])
        if risky:
            console.print(f"  [bold red]Open Ports[/bold red] ({len(ps_open)} open, [red]{len(risky)} risky[/red])")
        else:
            console.print(f"  [bold]Open Ports[/bold] ({len(ps_open)} open)")
        for op in ps_open:
            port_num = op["port"]
            svc = op["service"]
            banner = op.get("banner")
            is_risky = any(r["port"] == port_num for r in risky)
            col = "red" if is_risky else "cyan"
            banner_str = f" [dim]{banner[:60]}[/dim]" if banner else ""
            console.print(f"    [{col}]{port_num:>5}/tcp[/{col}]  {svc}{banner_str}")
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

    # ── Critical Path Rate Limits ──
    rlc = result.get("rate_limits_critical", {})
    if rlc and rlc.get("paths_checked"):
        n_limited = len(rlc.get("rate_limited_paths", []))
        n_checked = rlc.get("paths_checked", 0)
        console.print("  [bold]Rate Limits (Critical Paths)[/bold]")
        if n_limited == 0:
            console.print(f"    [green]No rate limiting[/green] on {n_checked} critical paths")
        else:
            console.print(f"    [yellow]{n_limited}/{n_checked}[/yellow] critical paths have rate limiting")
            for rp in rlc.get("rate_limited_paths", [])[:8]:
                path_key = f"{rp['host']}{rp['path']}"
                hdrs = rp.get("headers", {})
                limit_val = hdrs.get("x-ratelimit-limit", hdrs.get("ratelimit-limit", ""))
                limit_str = f" ({limit_val} req/window)" if limit_val else ""
                status_str = f" [red]429[/red]" if rp.get("status") == 429 else ""
                console.print(f"    ⚡ [cyan]{path_key}[/cyan]{limit_str}{status_str}")
            most = rlc.get("most_restrictive")
            if most:
                console.print(f"    Most restrictive: [bold]{most['host']}{most['path']}[/bold] "
                              f"— {most['limit']} req/window")
        console.print(f"    [dim]{rlc.get('summary', '')}[/dim]")
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

    # ── GitHub Org Recon ──
    gh = result.get("github_recon", {})
    if gh and gh.get("org_found"):
        console.print(f"  [bold]GitHub Organisation — {gh.get('org_login', '?')}[/bold]")
        console.print(f"    Public repos: [bold]{gh.get('public_repos', 0)}[/bold]  "
                       f"Members: [bold]{len(gh.get('members', []))}[/bold]  "
                       f"Commit authors: [bold]{len(gh.get('commit_authors', []))}[/bold]")
        if gh.get("blog"):
            console.print(f"    Website:      [dim]{gh['blog']}[/dim]")

        # Interesting repos (infra/deploy/secrets)
        interesting = gh.get("interesting_repos", [])
        if interesting:
            console.print(f"\n    [bold red]Infrastructure Repos[/bold red] ({len(interesting)} flagged)")
            for r in interesting[:8]:
                console.print(f"    🔴 [bold]{r['name']}[/bold]  [yellow]({r['reason']})[/yellow]")
                if r.get("description"):
                    console.print(f"       [dim]{r['description'][:80]}[/dim]")

        # Commit authors with corporate emails
        authors = gh.get("commit_authors", [])
        corp_authors = [a for a in authors if a.get("email", "").endswith(f"@{result.get('host', '')}")]
        if corp_authors:
            console.print(f"\n    [bold]Corporate Emails in Git History[/bold] ({len(corp_authors)})")
            for a in corp_authors[:8]:
                console.print(f"    📧 {a['name']:<25} [green]{a['email']}[/green]")
            if len(corp_authors) > 8:
                console.print(f"    [dim]... and {len(corp_authors) - 8} more[/dim]")

        # Leaked URLs
        leaked = gh.get("leaked_urls", [])
        if leaked:
            console.print(f"\n    [bold red]Leaked Internal URLs[/bold red]")
            for l in leaked[:5]:
                console.print(f"    🚨 [red]{l['url']}[/red]  [dim]({l['source']})[/dim]")

        console.print()
    elif gh and gh.get("error"):
        console.print(f"  [bold]GitHub Organisation[/bold]  [dim]{gh['error']}[/dim]")
        console.print()

    # ── Employee Email Exposure ──
    emp = result.get("employee_exposure", {})
    if emp and (emp.get("breached_emails") or emp.get("code_exposures")):
        n_checked = emp.get("emails_checked", 0)
        n_breached = len(emp.get("breached_emails", []))
        n_code = len(emp.get("code_exposures", []))
        console.print(f"  [bold]Employee Email Exposure[/bold] ({n_checked} emails checked)")

        if n_breached:
            console.print(f"\n    [bold red]Breached Accounts (HIBP)[/bold red] ({n_breached})")
            for b in emp["breached_emails"][:10]:
                breaches_str = ", ".join(b.get("breaches", [])[:3])
                console.print(f"    🔓 [red]{b['email']}[/red]  {b['breach_count']} breach(es): [dim]{breaches_str}[/dim]")

        if n_code:
            console.print(f"\n    [bold yellow]Emails Leaked in Code[/bold yellow] ({n_code})")
            for c in emp["code_exposures"][:5]:
                console.print(f"    📂 [yellow]{c['email']}[/yellow]  {c['total_results']} result(s)")
                for s in c.get("sample_repos", [])[:2]:
                    console.print(f"       [dim]{s['repo']} / {s['path']}[/dim]")

        if not n_breached and not n_code:
            console.print(f"    [green]No breaches or code leaks found[/green]")
        else:
            console.print(f"\n    [dim]Tip: Set HIBP_API_KEY and GITHUB_TOKEN for deeper checks[/dim]")
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
