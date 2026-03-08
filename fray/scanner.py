#!/usr/bin/env python3
"""
Fray Scanner — Auto Recon → Crawl → Param Discovery → Payload Injection

Automated attack surface mapping:
  1. Crawl — spider target, follow same-origin links
  2. Parameter discovery — extract query params, form inputs, JS endpoints
  3. Endpoint map — deduplicate and classify injection points
  4. Payload injection — test each discovered parameter with WAFTester

Usage:
    fray scan https://example.com
    fray scan https://example.com --depth 3 --max-pages 50
    fray scan https://example.com --category xss --json
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class InjectionPoint:
    """A single parameter that can be tested for injection."""
    url: str
    param: str
    method: str = "GET"            # GET or POST
    source: str = "query"          # query | form | js | path
    context: str = ""              # e.g. "login form", "search box"

    def __hash__(self):
        return hash((self.url, self.param, self.method))

    def __eq__(self, other):
        return (self.url, self.param, self.method) == (other.url, other.param, other.method)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "source": self.source,
            "context": self.context,
        }


@dataclass
class CrawlResult:
    """Result of crawling + parameter discovery."""
    target: str
    pages_crawled: int = 0
    endpoints: List[str] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    forms_found: int = 0
    js_endpoints: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "pages_crawled": self.pages_crawled,
            "total_endpoints": len(self.endpoints),
            "total_injection_points": len(self.injection_points),
            "forms_found": self.forms_found,
            "js_endpoints": self.js_endpoints,
            "endpoints": self.endpoints,
            "injection_points": [ip.to_dict() for ip in self.injection_points],
            "errors": self.errors,
        }


@dataclass
class ScanResult:
    """Full scan result: crawl + test results."""
    target: str
    crawl: Optional[CrawlResult] = None
    test_results: List[dict] = field(default_factory=list)
    total_tested: int = 0
    total_blocked: int = 0
    total_passed: int = 0
    total_reflected: int = 0
    duration: str = "N/A"
    auto_throttle: Optional[Dict] = None

    def to_dict(self) -> dict:
        block_rate = f"{(self.total_blocked / self.total_tested * 100):.1f}%" if self.total_tested else "0%"
        d = {
            "target": self.target,
            "crawl": self.crawl.to_dict() if self.crawl else {},
            "summary": {
                "total_tested": self.total_tested,
                "blocked": self.total_blocked,
                "passed": self.total_passed,
                "reflected": self.total_reflected,
                "block_rate": block_rate,
            },
            "test_results": self.test_results,
            "duration": self.duration,
        }
        if self.auto_throttle:
            d["auto_throttle"] = self.auto_throttle
        return d


# ── HTTP fetcher (stdlib only) ───────────────────────────────────────────

# ── Rate limit backoff state ──────────────────────────────────────────

_backoff_delay: float = 0.0       # extra delay added on 429
_BACKOFF_MAX: float = 30.0        # cap


def auto_throttle(target: str, timeout: int = 8, verify_ssl: bool = True,
                  quiet: bool = False) -> Dict[str, any]:
    """Fingerprint target rate limits and return optimal scan parameters.

    Sends escalating probe bursts to detect the exact threshold where the
    target starts returning 429/503, then calculates a safe delay.

    Returns:
        Dict with recommended_delay, threshold_rps, burst_limit,
        detection_type, and rate_limit_headers.
    """
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    if not quiet:
        try:
            from fray.output import console
            console.print(f"\n  [bold]Auto-throttle[/bold]: fingerprinting rate limits on [cyan]{host}[/cyan]...")
        except ImportError:
            print(f"  Auto-throttle: fingerprinting rate limits on {host}...")

    from fray.recon.checks import check_rate_limits
    rl = check_rate_limits(host, port, use_ssl, timeout=timeout)

    result = {
        "recommended_delay": rl.get("recommended_delay", 0.5),
        "threshold_rps": rl.get("threshold_rps"),
        "burst_limit": rl.get("burst_limit"),
        "detection_type": rl.get("detection_type", "unknown"),
        "rate_limit_headers": rl.get("rate_limit_headers", {}),
        "lockout_duration": rl.get("lockout_duration"),
    }

    if not quiet:
        try:
            from fray.output import console
            det = result["detection_type"] or "none"
            rps = result["threshold_rps"]
            delay = result["recommended_delay"]
            burst = result["burst_limit"]

            if det == "none":
                console.print(f"  [green]No rate limiting detected[/green] — using fast delay ({delay}s)")
            else:
                console.print(f"  [yellow]Rate limit detected[/yellow]: type=[bold]{det}[/bold]"
                              f"  threshold=[bold]{rps} req/s[/bold]"
                              f"  burst=[bold]{burst}[/bold]")
                console.print(f"  [bold]Auto-set delay: {delay}s[/bold] (60% of threshold)")
                if result.get("lockout_duration"):
                    console.print(f"  [dim]Lockout duration: {result['lockout_duration']}s[/dim]")
            console.print()
        except ImportError:
            pass

    return result


def _fetch(url: str, timeout: int = 8, verify_ssl: bool = True,
           headers: Optional[Dict[str, str]] = None,
           _retry: int = 0) -> Tuple[int, str, Dict[str, str]]:
    """Fetch a URL and return (status, body, response_headers).

    Uses http.client for zero external dependencies.
    Automatically backs off on 429 (rate limit) responses.
    """
    global _backoff_delay

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        port = port or 443
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        req_headers.update(headers)

    # Apply backoff delay if we've been rate-limited previously
    if _backoff_delay > 0:
        time.sleep(_backoff_delay)

    try:
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read(500_000).decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}

        # Auto-backoff on 429
        if resp.status == 429 and _retry < 3:
            retry_after = resp_headers.get("retry-after", "")
            try:
                wait = min(int(retry_after), 30) if retry_after.isdigit() else 0
            except (ValueError, AttributeError):
                wait = 0
            _backoff_delay = max(wait, _backoff_delay * 2 if _backoff_delay > 0 else 2.0)
            _backoff_delay = min(_backoff_delay, _BACKOFF_MAX)
            time.sleep(_backoff_delay)
            conn.close()
            return _fetch(url, timeout=timeout, verify_ssl=verify_ssl,
                          headers=headers, _retry=_retry + 1)

        # Decay backoff on success
        if resp.status < 400 and _backoff_delay > 0:
            _backoff_delay = max(0.0, _backoff_delay * 0.5)
            if _backoff_delay < 0.1:
                _backoff_delay = 0.0

        return resp.status, body, resp_headers
    except Exception:
        return 0, "", {}
    finally:
        conn.close()


# ── Link extraction ──────────────────────────────────────────────────────

_HREF_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)', re.IGNORECASE)
_JS_URL_RE = re.compile(
    r"""(?:"""
    r"""fetch\s*\(\s*['"]([^'"]+)['"]"""        # fetch("url")
    r"""|\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""  # xhr.open("GET","url")
    r"""|axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]"""  # axios.get("url")
    r"""|['"](/api/[^'"]+)['"]"""               # "/api/..."
    r"""|['"](/v\d+/[^'"]+)['"]"""              # "/v1/..."
    r""")""",
    re.IGNORECASE,
)

_FORM_RE = re.compile(
    r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL
)
_FORM_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)', re.IGNORECASE)
_INPUT_RE = re.compile(
    r'<(?:input|textarea|select)[^>]*\bname\s*=\s*["\']([^"\']+)',
    re.IGNORECASE,
)


def _same_origin(base: str, url: str) -> bool:
    """Check if url is same origin as base."""
    bp = urlparse(base)
    up = urlparse(url)
    return up.scheme in ("", bp.scheme) and (up.netloc == "" or up.netloc == bp.netloc)


def _normalize_url(base: str, href: str) -> Optional[str]:
    """Resolve relative URL and normalize. Returns None if off-origin."""
    if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    full = urljoin(base, href)
    parsed = urlparse(full)
    # Strip fragment
    normalized = parsed._replace(fragment="").geturl()
    return normalized


def extract_links(base_url: str, html: str) -> Set[str]:
    """Extract same-origin links from HTML."""
    from html import unescape
    links = set()
    for match in _HREF_RE.finditer(html):
        href = unescape(match.group(1).strip())
        url = _normalize_url(base_url, href)
        if url and _same_origin(base_url, url):
            links.add(url)
    return links


def extract_query_params(url: str) -> List[InjectionPoint]:
    """Extract injection points from URL query parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    points = []
    # Base URL without query
    base = parsed._replace(query="", fragment="").geturl()
    for param_name in params:
        points.append(InjectionPoint(
            url=base,
            param=param_name,
            method="GET",
            source="query",
            context=f"query param in {parsed.path}",
        ))
    return points


def extract_forms(base_url: str, html: str) -> Tuple[List[InjectionPoint], int]:
    """Extract injection points from HTML forms. Returns (points, form_count)."""
    points = []
    form_count = 0
    for form_match in _FORM_RE.finditer(html):
        form_count += 1
        form_html = form_match.group(0)
        # Action
        action_match = _FORM_ACTION_RE.search(form_html)
        action = action_match.group(1) if action_match else ""
        form_url = _normalize_url(base_url, action) or base_url
        # Method
        method_match = _FORM_METHOD_RE.search(form_html)
        method = (method_match.group(1).upper() if method_match else "GET")
        if method not in ("GET", "POST"):
            method = "POST"
        # Input names
        for input_match in _INPUT_RE.finditer(form_html):
            param_name = input_match.group(1)
            # Skip common non-injectable fields
            if param_name.lower() in ("csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
                                       "submit", "button", "captcha", "g-recaptcha-response"):
                continue
            points.append(InjectionPoint(
                url=form_url,
                param=param_name,
                method=method,
                source="form",
                context=f"form → {urlparse(form_url).path}",
            ))
    return points, form_count


def extract_js_endpoints(base_url: str, html: str) -> Tuple[List[InjectionPoint], int]:
    """Extract API endpoints from inline/embedded JavaScript."""
    points = []
    js_count = 0
    seen = set()
    for match in _JS_URL_RE.finditer(html):
        # Pick first non-None group
        endpoint = next((g for g in match.groups() if g), None)
        if not endpoint:
            continue
        url = _normalize_url(base_url, endpoint)
        if not url or not _same_origin(base_url, url):
            continue
        if url in seen:
            continue
        seen.add(url)
        js_count += 1
        # Extract params if present
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base = parsed._replace(query="", fragment="").geturl()
        if params:
            for param_name in params:
                points.append(InjectionPoint(
                    url=base,
                    param=param_name,
                    method="GET",
                    source="js",
                    context=f"JS endpoint {parsed.path}",
                ))
        else:
            # API endpoint without params — try common param names
            for common_param in ("id", "q", "query", "search", "input", "name"):
                points.append(InjectionPoint(
                    url=base,
                    param=common_param,
                    method="GET",
                    source="js",
                    context=f"JS endpoint {parsed.path} (inferred param)",
                ))
    return points, js_count


# ── Scope checker ────────────────────────────────────────────────────

class ScopeChecker:
    """Check if a URL is within a permitted scope.

    Scope file format (one entry per line):
        example.com             — exact domain match
        *.example.com           — wildcard subdomain match
        192.168.1.0/24          — CIDR range
        10.0.0.5                — exact IP
        # comment               — ignored
    """

    def __init__(self, scope_file: Optional[str] = None, entries: Optional[List[str]] = None):
        self.domains: List[str] = []       # exact domain matches
        self.wildcards: List[str] = []     # *.example.com patterns
        self.networks: List[ipaddress.IPv4Network] = []
        self.ips: List[str] = []
        self._enabled = False

        lines = entries or []
        if scope_file:
            try:
                with open(scope_file, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
            except Exception:
                return

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self._enabled = True
            # CIDR
            if "/" in line:
                try:
                    self.networks.append(ipaddress.IPv4Network(line, strict=False))
                    continue
                except (ValueError, ipaddress.AddressValueError):
                    pass
            # Wildcard
            if line.startswith("*."):
                self.wildcards.append(line[2:].lower())
                continue
            # IP
            try:
                ipaddress.IPv4Address(line)
                self.ips.append(line)
                continue
            except (ValueError, ipaddress.AddressValueError):
                pass
            # Domain
            self.domains.append(line.lower())

    @property
    def enabled(self) -> bool:
        return self._enabled

    def in_scope(self, url: str) -> bool:
        """Check if url's host is within scope. Returns True if scope is disabled."""
        if not self._enabled:
            return True
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return True  # relative URL, allow

        # Exact domain
        if host in self.domains:
            return True

        # Wildcard: *.example.com matches sub.example.com and example.com
        for wc in self.wildcards:
            if host == wc or host.endswith("." + wc):
                return True

        # IP exact
        if host in self.ips:
            return True

        # CIDR
        try:
            addr = ipaddress.IPv4Address(host)
            for net in self.networks:
                if addr in net:
                    return True
        except (ValueError, ipaddress.AddressValueError):
            # host is a domain name, try resolving
            try:
                resolved = socket.gethostbyname(host)
                if resolved in self.ips:
                    return True
                addr = ipaddress.IPv4Address(resolved)
                for net in self.networks:
                    if addr in net:
                        return True
            except (socket.gaierror, ValueError):
                pass

        return False


# ── robots.txt / sitemap.xml seeding ─────────────────────────────────

def parse_robots_txt(base_url: str, body: str) -> List[str]:
    """Extract paths from robots.txt Disallow / Allow lines."""
    paths: List[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        for directive in ("Disallow:", "Allow:", "Sitemap:"):
            if line.startswith(directive):
                value = line[len(directive):].strip()
                if value and not value.startswith("#"):
                    if directive == "Sitemap:":
                        # Sitemap is a full URL
                        if _same_origin(base_url, value):
                            paths.append(value)
                    else:
                        # Disallow / Allow are paths
                        if value != "/" and "*" not in value:
                            url = _normalize_url(base_url, value)
                            if url:
                                paths.append(url)
                break
    return paths


def parse_sitemap_xml(base_url: str, body: str) -> List[str]:
    """Extract URLs from a sitemap.xml body."""
    urls: List[str] = []
    for match in re.finditer(r'<loc>\s*([^<]+?)\s*</loc>', body, re.IGNORECASE):
        url = match.group(1).strip()
        if _same_origin(base_url, url):
            urls.append(url)
    return urls


def _seed_from_robots_and_sitemap(
    base_url: str, timeout: int = 8, verify_ssl: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Fetch robots.txt and sitemap.xml to discover additional seed URLs."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    seeds: List[str] = []

    # robots.txt
    status, body, _ = _fetch(f"{origin}/robots.txt", timeout=timeout,
                              verify_ssl=verify_ssl, headers=headers)
    if status == 200 and body:
        seeds.extend(parse_robots_txt(origin, body))

    # sitemap.xml
    status, body, _ = _fetch(f"{origin}/sitemap.xml", timeout=timeout,
                              verify_ssl=verify_ssl, headers=headers)
    if status == 200 and body:
        seeds.extend(parse_sitemap_xml(origin, body))

    return seeds


# ── Crawler ──────────────────────────────────────────────────────────────

_STATIC_EXT = frozenset((
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
    "woff", "woff2", "ttf", "eot", "pdf", "zip", "mp4", "webp",
))


def _is_crawlable(url: str, visited: Set[str], target: str,
                   scope: Optional[ScopeChecker] = None) -> bool:
    """Check if URL should be crawled (same-origin or in-scope, not visited, not static)."""
    parsed = urlparse(url)
    canonical = parsed._replace(fragment="").geturl()
    if canonical in visited:
        return False
    ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
    if ext in _STATIC_EXT:
        return False
    # Scope check takes priority over same-origin
    if scope and scope.enabled:
        return scope.in_scope(url)
    return _same_origin(target, url)


def crawl(target: str, max_depth: int = 3, max_pages: int = 30,
          delay: float = 0.3, timeout: int = 8,
          verify_ssl: bool = True,
          headers: Optional[Dict[str, str]] = None,
          quiet: bool = False,
          scope: Optional[ScopeChecker] = None,
          workers: int = 1) -> CrawlResult:
    """Crawl target, discover endpoints and injection points.

    Automatically seeds crawl queue from robots.txt and sitemap.xml.

    Args:
        target: Base URL to crawl.
        max_depth: Maximum link depth to follow.
        max_pages: Maximum pages to fetch.
        delay: Delay between requests.
        timeout: Request timeout.
        verify_ssl: Verify SSL certificates.
        headers: Optional custom headers.
        quiet: Suppress progress output.
        scope: Optional ScopeChecker for domain/IP filtering.
        workers: Number of concurrent crawl workers (default: 1 = sequential).

    Returns:
        CrawlResult with discovered endpoints and injection points.
    """
    global _backoff_delay
    _backoff_delay = 0.0  # reset backoff state per scan

    result = CrawlResult(target=target)
    visited: Set[str] = set()
    injection_points: Set[InjectionPoint] = set()
    # (url, depth) queue
    queue: List[Tuple[str, int]] = [(target, 0)]

    # Seed from robots.txt and sitemap.xml
    seed_urls = _seed_from_robots_and_sitemap(target, timeout=timeout,
                                               verify_ssl=verify_ssl, headers=headers)
    for seed in seed_urls:
        if _is_crawlable(seed, visited, target, scope):
            queue.append((seed, 1))

    if not quiet:
        from fray.output import console
        console.print()
        console.rule(f"[bold]Crawling [cyan]{target}[/cyan][/bold]")
        if scope and scope.enabled:
            console.print("  [dim]Scope filter active[/dim]")

    # Thread-safe state for concurrent mode
    lock = threading.Lock()
    forms_found = [0]  # mutable container for thread-safe increment
    js_endpoints_found = [0]
    endpoints_list: List[str] = []
    errors_list: List[str] = []

    def _process_url(url: str, depth: int) -> List[Tuple[str, int]]:
        """Fetch one URL, extract params and links. Returns new (url, depth) pairs."""
        new_links: List[Tuple[str, int]] = []

        status, body, resp_headers = _fetch(url, timeout=timeout,
                                             verify_ssl=verify_ssl, headers=headers)
        if status == 0:
            with lock:
                errors_list.append(f"Failed to fetch {url}")
            return new_links

        # Follow redirects (301/302/307/308)
        if status in (301, 302, 307, 308):
            location = resp_headers.get("location", "")
            if location:
                redir_url = _normalize_url(url, location)
                if redir_url and _is_crawlable(redir_url, visited, target, scope):
                    new_links.append((redir_url, depth))
            return new_links

        if status >= 400:
            return new_links

        canonical = urlparse(url)._replace(fragment="").geturl()
        with lock:
            endpoints_list.append(canonical)

        # Extract query params from current URL
        for p in extract_query_params(canonical):
            with lock:
                injection_points.add(p)

        # Extract forms
        form_points, form_count = extract_forms(canonical, body)
        with lock:
            forms_found[0] += form_count
            for p in form_points:
                injection_points.add(p)

        # Extract JS endpoints
        js_points, js_count = extract_js_endpoints(canonical, body)
        with lock:
            js_endpoints_found[0] += js_count
            for p in js_points:
                injection_points.add(p)

        # Discover links for next depth
        if depth < max_depth:
            for link in extract_links(canonical, body):
                if _is_crawlable(link, visited, target, scope):
                    new_links.append((link, depth + 1))

        return new_links

    if workers <= 1:
        # Sequential crawl (original behavior)
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            parsed = urlparse(url)
            canonical = parsed._replace(fragment="").geturl()
            if canonical in visited:
                continue
            ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
            if ext in _STATIC_EXT:
                continue
            visited.add(canonical)

            if not quiet:
                from fray.output import console
                console.print(f"  [dim][{len(visited):>3}][/dim] {canonical[:80]}")

            new_links = _process_url(url, depth)
            for link in new_links:
                queue.append(link)

            if delay > 0:
                time.sleep(delay)
    else:
        # Concurrent crawl
        with ThreadPoolExecutor(max_workers=workers) as executor:
            in_flight: Dict = {}  # future -> (url, depth)

            def _submit_batch():
                while queue and len(visited) + len(in_flight) < max_pages:
                    url, depth = queue.pop(0)
                    parsed = urlparse(url)
                    canonical = parsed._replace(fragment="").geturl()
                    if canonical in visited:
                        continue
                    ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
                    if ext in _STATIC_EXT:
                        continue
                    visited.add(canonical)

                    if not quiet:
                        from fray.output import console
                        console.print(f"  [dim][{len(visited):>3}][/dim] {canonical[:80]}")

                    fut = executor.submit(_process_url, url, depth)
                    in_flight[fut] = (url, depth)

            _submit_batch()

            while in_flight:
                done_futures = [f for f in in_flight if f.done()]
                if not done_futures:
                    time.sleep(0.05)
                    continue

                for fut in done_futures:
                    del in_flight[fut]
                    try:
                        new_links = fut.result()
                        for link in new_links:
                            queue.append(link)
                    except Exception:
                        pass

                    if delay > 0:
                        time.sleep(delay / workers)  # spread delay across workers

                _submit_batch()

    result.pages_crawled = len(visited)
    result.endpoints = endpoints_list
    result.forms_found = forms_found[0]
    result.js_endpoints = js_endpoints_found[0]
    result.errors = errors_list
    result.injection_points = sorted(injection_points,
                                      key=lambda p: (p.url, p.param))

    if not quiet:
        from fray.output import console
        console.print(
            f"\n  [bold green]✓[/bold green] Crawled {result.pages_crawled} pages, "
            f"found {len(result.injection_points)} injection points "
            f"({result.forms_found} forms, {result.js_endpoints} JS endpoints)"
        )

    return result


# ── Full scan: crawl → inject ────────────────────────────────────────────

def run_scan(target: str, category: str = "xss", max_payloads: int = 5,
             max_depth: int = 3, max_pages: int = 30,
             delay: float = 0.5, timeout: int = 8,
             verify_ssl: bool = True,
             custom_headers: Optional[Dict[str, str]] = None,
             quiet: bool = False,
             jitter: float = 0.0,
             stealth: bool = False,
             rate_limit: float = 0.0,
             scope_file: Optional[str] = None,
             workers: int = 1,
             use_auto_throttle: bool = False) -> ScanResult:
    """Full automated scan: crawl → discover params → inject payloads.

    Args:
        target: Target URL.
        category: Payload category for injection testing.
        max_payloads: Max payloads to test per injection point.
        max_depth: Crawl depth.
        max_pages: Max pages to crawl.
        delay: Delay between requests.
        timeout: Request timeout.
        verify_ssl: Verify SSL certs.
        custom_headers: Optional custom headers.
        quiet: Suppress rich output.
        jitter: Random delay variance.
        stealth: Stealth mode.
        rate_limit: Max req/s.
        scope_file: Path to scope file for domain/IP filtering.
        workers: Concurrent workers for crawl + injection.

    Returns:
        ScanResult with crawl data and test results.
    """
    from datetime import datetime
    from fray import PAYLOADS_DIR
    from fray.tester import WAFTester

    start = datetime.now()
    scan = ScanResult(target=target)
    scope = ScopeChecker(scope_file=scope_file) if scope_file else None

    # Phase 0: Auto-throttle — fingerprint rate limits before scanning
    if use_auto_throttle:
        throttle_info = auto_throttle(target, timeout=timeout,
                                       verify_ssl=verify_ssl, quiet=quiet)
        rec_delay = throttle_info.get("recommended_delay", 0.5)
        # Only override if auto-throttle found a tighter limit
        if rec_delay > delay:
            delay = rec_delay
        rps = throttle_info.get("threshold_rps")
        if rps and (rate_limit == 0.0 or rps < rate_limit):
            rate_limit = rps * 0.6  # stay at 60% of threshold
        scan.auto_throttle = throttle_info

    # Phase 1: Crawl
    crawl_result = crawl(
        target, max_depth=max_depth, max_pages=max_pages,
        delay=delay, timeout=timeout, verify_ssl=verify_ssl,
        headers=custom_headers, quiet=quiet, scope=scope,
        workers=workers,
    )
    scan.crawl = crawl_result

    if not crawl_result.injection_points:
        if not quiet:
            from fray.output import console
            console.print("\n  [yellow]⚠ No injection points discovered.[/yellow]")
        elapsed = datetime.now() - start
        scan.duration = f"{int(elapsed.total_seconds())}s"
        return scan

    # Phase 2: Load payloads
    category_dir = PAYLOADS_DIR / category
    payloads = []
    if category_dir.is_dir():
        for pf in sorted(category_dir.glob("*.json")):
            try:
                data = json.loads(pf.read_text(encoding="utf-8"))
                plist = data.get("payloads", data) if isinstance(data, dict) else data
                if isinstance(plist, list):
                    payloads.extend(plist)
            except Exception:
                pass

    if not payloads:
        if not quiet:
            from fray.output import console
            console.print(f"\n  [yellow]⚠ No payloads found for category '{category}'[/yellow]")
        elapsed = datetime.now() - start
        scan.duration = f"{int(elapsed.total_seconds())}s"
        return scan

    # Limit payloads per injection point
    test_payloads = payloads[:max_payloads]

    if not quiet:
        from fray.output import console
        console.print()
        console.rule("[bold]Payload Injection[/bold]")
        console.print(
            f"  Testing {len(crawl_result.injection_points)} injection points "
            f"× {len(test_payloads)} {category} payloads"
        )
        console.print()

    # Phase 3: Test each injection point
    all_results = []
    print_lock = threading.Lock()

    def _test_injection_point(idx: int, ip: InjectionPoint) -> List[dict]:
        """Test a single injection point with all payloads. Thread-safe."""
        results = []
        tester = WAFTester(
            target=ip.url,
            timeout=timeout,
            delay=delay,
            verify_ssl=verify_ssl,
            custom_headers=custom_headers or None,
            jitter=jitter,
            stealth=stealth,
            rate_limit=rate_limit,
        )
        if not quiet:
            with print_lock:
                from fray.output import console
                console.print(
                    f"  [dim][{idx}/{len(crawl_result.injection_points)}][/dim] "
                    f"[bold]{ip.method}[/bold] {ip.url} "
                    f"[cyan]?{ip.param}=[/cyan] "
                    f"[dim]({ip.source})[/dim]"
                )

        for payload_data in test_payloads:
            payload = payload_data.get("payload", payload_data) if isinstance(payload_data, dict) else str(payload_data)
            result = tester.test_payload(payload, method=ip.method, param=ip.param)
            result["injection_point"] = ip.to_dict()
            result["category"] = category
            results.append(result)

            if not quiet:
                with print_lock:
                    from fray.output import blocked_text, passed_text
                    badge = blocked_text() if result["blocked"] else passed_text()
                    label = payload[:50] if isinstance(payload, str) else str(payload)[:50]
                    reflected_tag = " [bold magenta]↩ REFLECTED[/bold magenta]" if result.get("reflected") else ""
                    console.print(f"    ", badge, f" {result['status']} │ {label}{reflected_tag}", highlight=False)

            tester._stealth_delay()
        return results

    if workers <= 1:
        # Sequential injection (original behavior)
        for idx, ip in enumerate(crawl_result.injection_points, 1):
            all_results.extend(_test_injection_point(idx, ip))
    else:
        # Parallel injection
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_test_injection_point, idx, ip): ip
                for idx, ip in enumerate(crawl_result.injection_points, 1)
            }
            for fut in as_completed(futures):
                try:
                    all_results.extend(fut.result())
                except Exception:
                    pass

    scan.test_results = all_results
    scan.total_tested = len(all_results)
    scan.total_blocked = sum(1 for r in all_results if r.get("blocked"))
    scan.total_passed = scan.total_tested - scan.total_blocked
    scan.total_reflected = sum(1 for r in all_results if r.get("reflected"))

    elapsed = datetime.now() - start
    minutes = int(elapsed.total_seconds() // 60)
    seconds = int(elapsed.total_seconds() % 60)
    scan.duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    return scan


# ── Rich output ──────────────────────────────────────────────────────────

def print_scan_result(scan: ScanResult) -> None:
    """Print scan results using rich."""
    from fray.output import console, make_summary_table
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    # Crawl summary
    if scan.crawl:
        cr = scan.crawl
        tbl = make_summary_table()
        tbl.add_row("Target", scan.target)
        tbl.add_row("Pages Crawled", str(cr.pages_crawled))
        tbl.add_row("Endpoints", str(len(cr.endpoints)))
        tbl.add_row("Injection Points", Text(str(len(cr.injection_points)), style="bold cyan"))
        tbl.add_row("Forms", str(cr.forms_found))
        tbl.add_row("JS Endpoints", str(cr.js_endpoints))
        console.print()
        console.print(Panel(tbl, title="[bold]Crawl Results[/bold]",
                            border_style="bright_cyan", expand=False))

    # Injection point map
    if scan.crawl and scan.crawl.injection_points:
        ip_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        ip_table.add_column("#", style="dim", width=4)
        ip_table.add_column("Method", style="bold", width=6)
        ip_table.add_column("URL", style="cyan", max_width=50)
        ip_table.add_column("Param", style="bold yellow")
        ip_table.add_column("Source", style="dim")

        for i, ip in enumerate(scan.crawl.injection_points, 1):
            ip_table.add_row(
                str(i), ip.method,
                ip.url[:50] + ("…" if len(ip.url) > 50 else ""),
                ip.param, ip.source,
            )

        console.print()
        console.print(Panel(ip_table, title="[bold]Endpoint Map[/bold]",
                            border_style="yellow", expand=False))

    # Test summary
    if scan.total_tested > 0:
        block_rate = scan.total_blocked / scan.total_tested * 100
        tbl2 = make_summary_table()
        tbl2.add_row("Duration", scan.duration)
        tbl2.add_row("Total Tested", str(scan.total_tested))
        tbl2.add_row("Blocked", Text(str(scan.total_blocked), style="bold red"))
        tbl2.add_row("Passed", Text(str(scan.total_passed), style="bold green"))
        tbl2.add_row("Reflected", Text(str(scan.total_reflected), style="bold magenta"))
        tbl2.add_row("Block Rate", Text(f"{block_rate:.1f}%", style="bold"))
        console.print()
        console.print(Panel(tbl2, title="[bold]Scan Summary[/bold]",
                            border_style="bright_green", expand=False))

        # ── Next Steps ──
        _target = scan.target
        _cat = "xss"  # default category for recommendations
        console.print()
        console.print("  [bold]What This Means / Next Steps:[/bold]")
        if scan.total_passed == 0:
            console.print(f"    → [bold]All {scan.total_blocked} payloads blocked — WAF is actively protecting this target[/bold]")
            console.print(f"      Try bypass scorer:  fray bypass {_target} -c {_cat} -m 50")
            console.print(f"      Try smart mode:     fray test {_target} -c {_cat} --smart --max 100")
            console.print(f"      Try more payloads:  fray test {_target} -c sqli,rce,ssrf -m 20")
            console.print(f"      Run full recon:     fray recon {_target}")
        elif scan.total_reflected > 0:
            console.print(f"    → [bold]{scan.total_reflected} payload(s) REFLECTED — confirmed injection, likely exploitable[/bold]")
            console.print(f"      Run bypass scorer:  fray bypass {_target} -c {_cat} -m 50")
            console.print(f"      Export report:      fray scan {_target} -c {_cat} -o scan_report.json")
            console.print(f"      Generate report:    fray report -i scan_report.json --format html")
        else:
            console.print(f"    → [bold]{scan.total_passed} payload(s) not blocked ({block_rate:.0f}% block rate)[/bold]")
            console.print(f"      Verify bypasses:    fray bypass {_target} -c {_cat} -m 30")
            console.print(f"      Test more payloads: fray test {_target} -c {_cat} -m 50")
        console.print()

        # Show passed (bypassed) payloads if any
        # Show reflected payloads (confirmed XSS) first
        reflected = [r for r in scan.test_results if r.get("reflected") and not r.get("blocked")]
        if reflected:
            ref_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            ref_table.add_column("URL", style="cyan", max_width=40)
            ref_table.add_column("Param", style="yellow")
            ref_table.add_column("Status", style="bold")
            ref_table.add_column("Payload", style="red", max_width=40)
            ref_table.add_column("Context", style="dim", max_width=30)

            for r in reflected[:20]:
                ip_info = r.get("injection_point", {})
                ref_table.add_row(
                    ip_info.get("url", "")[:40],
                    ip_info.get("param", ""),
                    str(r.get("status", "")),
                    r.get("payload", "")[:40],
                    r.get("reflection_context", "")[:30],
                )

            console.print()
            console.print(Panel(ref_table,
                                title="[bold magenta]↩ Reflected (Confirmed Injection)[/bold magenta]",
                                border_style="magenta", expand=False))

        # Show passed (bypassed) payloads
        passed = [r for r in scan.test_results if not r.get("blocked")]
        if passed:
            bypass_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            bypass_table.add_column("URL", style="cyan", max_width=40)
            bypass_table.add_column("Param", style="yellow")
            bypass_table.add_column("Status", style="bold")
            bypass_table.add_column("Payload", style="red", max_width=50)

            for r in passed[:20]:
                ip_info = r.get("injection_point", {})
                bypass_table.add_row(
                    ip_info.get("url", "")[:40],
                    ip_info.get("param", ""),
                    str(r.get("status", "")),
                    r.get("payload", "")[:50],
                )

            console.print()
            console.print(Panel(bypass_table, title="[bold red]⚠ Bypassed (Not Blocked)[/bold red]",
                                border_style="red", expand=False))
    else:
        _target = scan.target
        _cat = "xss"
        console.print("\n  [dim]No payloads tested (no injection points found).[/dim]")
        console.print()
        console.print("  [bold]What This Means / Next Steps:[/bold]")
        console.print(f"    → [bold]No forms or injectable parameters found on crawled pages[/bold]")
        console.print(f"      This is common on JS-heavy SPAs (React, Angular, Vue)")
        console.print(f"      Try browser mode:   fray scan {_target} -c {_cat} --browser")
        console.print(f"      Test a specific URL: fray test {_target}/search?q=test -c {_cat}")
        console.print(f"      Run recon to find endpoints: fray recon {_target}")
        console.print(f"      Crawl deeper:       fray scan {_target} -c {_cat} --max-pages 20 --depth 3")
        console.print()
