#!/usr/bin/env python3
"""
Fray Crawler — Injection point discovery.

Discovers injectable parameters from:
  1. HTML forms (action, method, input names)
  2. URL query parameters (from links, redirects)
  3. JavaScript XHR/fetch calls (API routes, JSON keys)
  4. robots.txt / sitemap.xml paths
  5. GraphQL introspection endpoints

Usage:
    from fray.crawler import Crawler
    c = Crawler("https://target.com", max_pages=50)
    result = c.crawl()
    # result["endpoints"] = [{"url": ..., "params": [...], "method": ..., "source": ...}]

CLI:
    fray crawl https://target.com --max 50 --depth 3
"""

import json
import re
import ssl
import socket
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


class CrawlEndpoint:
    """A discovered injectable endpoint."""

    __slots__ = ("url", "method", "params", "source", "content_type", "depth")

    def __init__(self, url: str, method: str = "GET", params: List[str] = None,
                 source: str = "link", content_type: str = "", depth: int = 0):
        self.url = url
        self.method = method.upper()
        self.params = params or []
        self.source = source  # link, form, js_fetch, js_xhr, sitemap, robots, graphql
        self.content_type = content_type
        self.depth = depth

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "source": self.source,
            "content_type": self.content_type,
            "depth": self.depth,
        }

    def __hash__(self):
        return hash((self.url, self.method, tuple(sorted(self.params))))

    def __eq__(self, other):
        return (self.url == other.url and self.method == other.method
                and sorted(self.params) == sorted(other.params))


# ── Regex patterns for JS analysis ────────────────────────────────────────

# fetch("url") / fetch('url') / fetch(`url`)
_RE_FETCH = re.compile(
    r'''fetch\s*\(\s*['"`]([^'"`\s]{3,200})['"`]''', re.I
)
# XMLHttpRequest .open("METHOD", "url")
_RE_XHR = re.compile(
    r'''\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"`]([^'"`\s]{3,200})['"`]''', re.I
)
# axios.get/post/put/delete("url")
_RE_AXIOS = re.compile(
    r'''axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]''', re.I
)
# $.ajax({url: "...", ...})  /  $.get("url")  /  $.post("url")
_RE_JQUERY = re.compile(
    r'''\$\s*\.\s*(ajax|get|post|getJSON)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]''', re.I
)
# JSON keys that look like params: {"key": value}
_RE_JSON_KEY = re.compile(r'"(\w{2,30})"\s*:', re.I)
# API path patterns: /api/v1/users, /v2/data
_RE_API_PATH = re.compile(
    r'''['"`](/(?:api|v\d|graphql|rest|rpc|endpoint|service|data|auth|admin|internal)[/\w.-]{2,120})['"`]''', re.I
)
# WebSocket URLs
_RE_WEBSOCKET = re.compile(
    r'''['"`](wss?://[^'"`\s]{5,200})['"`]''', re.I
)
# window.postMessage target origins
_RE_POSTMESSAGE = re.compile(
    r'''\.postMessage\s*\([^,]+,\s*['"`]([^'"`\s]{5,200})['"`]''', re.I
)
# Additional API patterns: /users/123, /items?page=1
_RE_REST_CRUD = re.compile(
    r'''['"`](/(?:users?|items?|products?|orders?|accounts?|posts?|comments?|files?|uploads?|images?|settings?|profiles?|notifications?|messages?|search|login|logout|register|signup|signin|reset|verify|confirm|callback|webhook)[/\w.-]{0,80})['"`]''', re.I
)
# Form action
_RE_FORM_ACTION = re.compile(
    r'<form[^>]*action\s*=\s*["\']([^"\']{1,500})["\']', re.I
)
_RE_FORM_METHOD = re.compile(r'<form[^>]*method\s*=\s*["\'](\w+)["\']', re.I)
_RE_INPUT = re.compile(
    r'<input[^>]*name\s*=\s*["\']([^"\']{1,100})["\']', re.I
)
_RE_SELECT = re.compile(
    r'<select[^>]*name\s*=\s*["\']([^"\']{1,100})["\']', re.I
)
_RE_TEXTAREA = re.compile(
    r'<textarea[^>]*name\s*=\s*["\']([^"\']{1,100})["\']', re.I
)
# Links
_RE_HREF = re.compile(r'href\s*=\s*["\']([^"\']{1,500})["\']', re.I)
_RE_SRC = re.compile(r'src\s*=\s*["\']([^"\']{1,500})["\']', re.I)

# Form enctype
_RE_FORM_ENCTYPE = re.compile(
    r'<form[^>]*enctype\s*=\s*["\']([^"\']{1,60})["\']', re.I
)
# Hidden inputs (CSRF tokens, etc.)
_RE_HIDDEN_INPUT = re.compile(
    r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']{1,100})["\']', re.I
)
_RE_HIDDEN_INPUT_ALT = re.compile(
    r'<input[^>]*name\s*=\s*["\']([^"\']{1,100})["\'][^>]*type\s*=\s*["\']hidden["\']', re.I
)
# File upload inputs
_RE_FILE_INPUT = re.compile(
    r'<input[^>]*type\s*=\s*["\']file["\']', re.I
)

# OpenAPI / Swagger paths
_OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
    "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
    "/api/openapi.json", "/docs", "/redoc", "/api/docs",
    "/.well-known/openapi.json", "/swagger/v1/swagger.json",
]

# CSRF token field name patterns
_CSRF_NAMES = frozenset({
    "csrf", "csrf_token", "csrftoken", "_csrf", "_token", "token",
    "authenticity_token", "__requestverificationtoken", "anticsrf",
    "xsrf_token", "_xsrf", "csrfmiddlewaretoken",
})


class Crawler:
    """Injection point crawler — discovers forms, params, API routes, GraphQL."""

    def __init__(self, target: str, *, max_pages: int = 50, max_depth: int = 3,
                 timeout: int = 8, verify_ssl: bool = False,
                 delay: float = 0.2, headers: Dict[str, str] = None,
                 impersonate: str = None, verbose: bool = False,
                 browser: bool = False):
        if not target.startswith("http"):
            target = f"https://{target}"
        self.target = target
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.headers = headers or {}
        self.impersonate = impersonate
        self.verbose = verbose
        self.browser = browser

        parsed = urllib.parse.urlparse(target)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.base_url = f"{self.scheme}://{self.host}"
        if (self.scheme == "https" and self.port != 443) or \
           (self.scheme == "http" and self.port != 80):
            self.base_url += f":{self.port}"

        self._visited: Set[str] = set()
        self._endpoints: List[CrawlEndpoint] = []
        self._js_urls: Set[str] = set()
        self._session = None

    def _get_session(self):
        """Lazy-init impersonated or fallback session."""
        if self._session:
            return self._session
        if self.impersonate:
            try:
                from fray.impersonate import ImpersonatedSession, AVAILABLE
                if AVAILABLE:
                    self._session = ImpersonatedSession(
                        browser=self.impersonate, verify=self.verify_ssl,
                        timeout=self.timeout, headers=self.headers)
                    return self._session
            except ImportError:
                pass
        # Fallback session (no impersonation)
        from fray.impersonate import ImpersonatedSession
        self._session = ImpersonatedSession(
            browser="chrome", verify=self.verify_ssl,
            timeout=self.timeout, headers=self.headers)
        return self._session

    def _fetch(self, url: str) -> Tuple[int, str, Dict[str, str]]:
        """Fetch a URL and return (status, body, headers)."""
        s = self._get_session()
        try:
            r = s.get(url)
            hdrs = {k.lower(): v for k, v in r.headers.items()} if r.headers else {}
            return r.status_code, r.text, hdrs
        except Exception:
            return 0, "", {}

    def _normalize_url(self, href: str, base_url: str) -> Optional[str]:
        """Normalize a relative/absolute href to a full URL within scope."""
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
            return None
        full = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(full)
        if parsed.hostname != self.host:
            return None
        # Strip fragment
        return urllib.parse.urlunparse(parsed._replace(fragment=""))

    def _add_endpoint(self, ep: CrawlEndpoint):
        """Deduplicate and add endpoint."""
        if ep not in self._endpoints:
            self._endpoints.append(ep)

    def _browser_crawl(self):
        """Use Playwright to crawl JS-rendered SPAs (React/Angular/Vue).

        Intercepts network requests to discover API calls, extracts forms
        from rendered DOM, and follows client-side navigation.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "Playwright required for --browser mode. "
                "Install: pip install playwright && playwright install chromium"
            )

        _intercepted: List[Dict] = []

        def _on_request(request):
            """Capture XHR/fetch requests made by the page."""
            rtype = request.resource_type
            if rtype in ("xhr", "fetch"):
                _intercepted.append({
                    "url": request.url,
                    "method": request.method,
                    "post_data": request.post_data,
                })

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                ignore_https_errors=not self.verify_ssl,
                extra_http_headers=self.headers or {},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/125.0.0.0 Safari/537.36",
            )
            page = ctx.new_page()
            page.on("request", _on_request)

            visited_browser: Set[str] = set()
            queue = [self.target]

            for _ in range(min(self.max_pages, 20)):
                if not queue:
                    break
                url = queue.pop(0)
                if url in visited_browser:
                    continue
                visited_browser.add(url)

                try:
                    page.goto(url, wait_until="networkidle",
                              timeout=self.timeout * 1000)
                    page.wait_for_timeout(1500)  # Let JS settle
                except Exception:
                    continue

                if self.verbose:
                    print(f"  🌐 [{len(visited_browser)}] {url[:70]}")

                # Extract forms from rendered DOM
                try:
                    forms = page.query_selector_all("form")
                    for form in forms:
                        action = form.get_attribute("action") or url
                        method = (form.get_attribute("method") or "GET").upper()
                        full_url = self._normalize_url(action, url) or url

                        inputs = form.query_selector_all("input[name], select[name], textarea[name]")
                        params = []
                        for inp in inputs:
                            name = inp.get_attribute("name")
                            if name:
                                params.append(name)
                        if params:
                            self._add_endpoint(CrawlEndpoint(
                                url=full_url, method=method, params=list(dict.fromkeys(params)),
                                source="browser_form", depth=0))
                except Exception:
                    pass

                # Extract links from rendered DOM
                try:
                    links = page.query_selector_all("a[href]")
                    for link in links:
                        href = link.get_attribute("href")
                        norm = self._normalize_url(href, url)
                        if norm and norm not in visited_browser:
                            queue.append(norm)
                            self._extract_url_params(norm, 1)
                except Exception:
                    pass

                if self.delay > 0:
                    time.sleep(self.delay)

            browser.close()

        # Process intercepted XHR/fetch requests
        for req in _intercepted:
            norm = self._normalize_url(req["url"], self.target)
            if not norm:
                continue
            params = []
            # Extract POST body params
            if req.get("post_data"):
                try:
                    body = json.loads(req["post_data"])
                    if isinstance(body, dict):
                        params = list(body.keys())[:20]
                except (json.JSONDecodeError, ValueError):
                    # URL-encoded form data
                    try:
                        params = [k for k, _ in urllib.parse.parse_qsl(req["post_data"])]
                    except Exception:
                        pass
            # Extract URL query params
            parsed = urllib.parse.urlparse(norm)
            if parsed.query:
                params.extend(k for k, _ in urllib.parse.parse_qsl(parsed.query))
                norm = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

            self._add_endpoint(CrawlEndpoint(
                url=norm, method=req["method"],
                params=list(dict.fromkeys(params)) if params else [],
                source="browser_xhr", depth=0))

    def crawl(self) -> dict:
        """Execute the crawl. Returns result dict."""
        t0 = time.monotonic()

        # Phase 0: Browser crawl for SPAs (if enabled)
        if self.browser:
            try:
                self._browser_crawl()
            except ImportError as e:
                if self.verbose:
                    print(f"  ⚠ {e}")
            except Exception as e:
                if self.verbose:
                    print(f"  ⚠ Browser crawl error: {e}")

        # Phase 1: robots.txt + sitemap
        self._crawl_robots()
        self._crawl_sitemap()

        # Phase 2: BFS crawl from target
        queue: List[Tuple[str, int]] = [(self.target, 0)]
        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self._visited or depth > self.max_depth:
                continue
            self._visited.add(url)

            if self.verbose:
                print(f"  [{len(self._visited)}/{self.max_pages}] {url[:80]}")

            status, body, headers = self._fetch(url)
            if status == 0 or not body:
                continue
            if self.delay > 0:
                time.sleep(self.delay)

            ct = headers.get("content-type", "")

            # Extract from HTML
            if "html" in ct or body.strip().startswith("<"):
                self._extract_forms(url, body, depth)
                self._extract_links(url, body, depth, queue)
                self._extract_js_refs(url, body)

            # Extract query params from current URL
            self._extract_url_params(url, depth)

        # Phase 3: Analyze JS files
        self._analyze_js_files()

        # Phase 4: OpenAPI / Swagger discovery
        self._check_openapi()

        # Phase 5: GraphQL introspection
        self._check_graphql()

        elapsed = time.monotonic() - t0
        result = {
            "target": self.target,
            "pages_crawled": len(self._visited),
            "endpoints": [ep.to_dict() for ep in self._endpoints],
            "total_endpoints": len(self._endpoints),
            "total_params": sum(len(ep.params) for ep in self._endpoints),
            "js_files_analyzed": len(self._js_urls),
            "elapsed_s": round(elapsed, 1),
            "sources": {},
        }
        # Count by source
        for ep in self._endpoints:
            result["sources"][ep.source] = result["sources"].get(ep.source, 0) + 1

        # Form metadata (CSRF, file uploads, hidden fields)
        if hasattr(self, '_form_meta') and self._form_meta:
            result["forms"] = self._form_meta
            result["forms_with_upload"] = sum(1 for f in self._form_meta if f.get("file_upload"))
            result["forms_with_csrf"] = sum(1 for f in self._form_meta if f.get("csrf_fields"))

        # OpenAPI specs found
        if hasattr(self, '_openapi_specs') and self._openapi_specs:
            result["openapi_specs"] = self._openapi_specs

        # WebSocket URLs
        if hasattr(self, '_websockets') and self._websockets:
            result["websockets"] = list(set(self._websockets))

        # postMessage targets
        if hasattr(self, '_postmessage_targets') and self._postmessage_targets:
            result["postmessage_targets"] = self._postmessage_targets

        return result

    def _crawl_robots(self):
        """Parse robots.txt for paths."""
        url = f"{self.base_url}/robots.txt"
        status, body, _ = self._fetch(url)
        if status != 200 or not body:
            return
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and not path.startswith("#") and "*" not in path:
                    full = f"{self.base_url}{path}"
                    self._add_endpoint(CrawlEndpoint(
                        url=full, source="robots", depth=0))

    def _crawl_sitemap(self):
        """Parse sitemap.xml for URLs."""
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            url = f"{self.base_url}{path}"
            status, body, _ = self._fetch(url)
            if status != 200 or not body:
                continue
            locs = re.findall(r"<loc>(.*?)</loc>", body, re.I)
            for loc in locs[:100]:
                norm = self._normalize_url(loc, self.base_url)
                if norm:
                    self._add_endpoint(CrawlEndpoint(
                        url=norm, source="sitemap", depth=0))

    def _extract_forms(self, page_url: str, body: str, depth: int):
        """Extract form actions, input names, enctype, hidden fields, file uploads, CSRF tokens."""
        form_blocks = re.split(r"<form", body, flags=re.I)[1:]
        for block in form_blocks:
            # Find closing </form> or next <form
            end = block.find("</form")
            if end == -1:
                end = len(block)
            block = block[:end]
            full_tag = "<form" + block

            # Action
            action_m = _RE_FORM_ACTION.search(full_tag)
            action = action_m.group(1) if action_m else page_url
            full_url = self._normalize_url(action, page_url)
            if not full_url:
                full_url = page_url

            # Method
            method_m = _RE_FORM_METHOD.search(full_tag)
            method = method_m.group(1).upper() if method_m else "GET"

            # Enctype
            enctype_m = _RE_FORM_ENCTYPE.search(full_tag)
            enctype = enctype_m.group(1).lower() if enctype_m else ""
            content_type = enctype if enctype else ""

            # Params
            params = []
            for pattern in [_RE_INPUT, _RE_SELECT, _RE_TEXTAREA]:
                params.extend(pattern.findall(block))
            # Dedupe
            params = list(dict.fromkeys(params))

            # Hidden fields (CSRF tokens, etc.)
            hidden_names = set(_RE_HIDDEN_INPUT.findall(block))
            hidden_names.update(_RE_HIDDEN_INPUT_ALT.findall(block))
            csrf_fields = [n for n in hidden_names if n.lower() in _CSRF_NAMES]

            # File upload detection
            has_file_upload = bool(_RE_FILE_INPUT.search(block))

            if params or has_file_upload:
                ep = CrawlEndpoint(
                    url=full_url, method=method, params=params,
                    source="form", content_type=content_type, depth=depth)
                self._add_endpoint(ep)

                # Track form metadata for richer crawl output
                if not hasattr(self, '_form_meta'):
                    self._form_meta = []
                meta = {"url": full_url, "method": method, "params": params}
                if csrf_fields:
                    meta["csrf_fields"] = csrf_fields
                if has_file_upload:
                    meta["file_upload"] = True
                    if enctype != "multipart/form-data":
                        meta["missing_multipart"] = True
                if hidden_names:
                    meta["hidden_fields"] = list(hidden_names)
                if enctype:
                    meta["enctype"] = enctype
                self._form_meta.append(meta)

    def _extract_links(self, page_url: str, body: str, depth: int,
                       queue: List[Tuple[str, int]]):
        """Extract links and queue them for crawling."""
        hrefs = _RE_HREF.findall(body)
        for href in hrefs:
            norm = self._normalize_url(href, page_url)
            if norm and norm not in self._visited:
                queue.append((norm, depth + 1))
                # Extract query params
                self._extract_url_params(norm, depth + 1)

    def _extract_url_params(self, url: str, depth: int):
        """Extract query parameters from URL."""
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]
            if params:
                base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))
                self._add_endpoint(CrawlEndpoint(
                    url=base, method="GET", params=params,
                    source="link", depth=depth))

    def _extract_js_refs(self, page_url: str, body: str):
        """Extract JS file references for later analysis."""
        srcs = _RE_SRC.findall(body)
        for src in srcs:
            if src.endswith(".js") or ".js?" in src:
                norm = self._normalize_url(src, page_url)
                if norm:
                    self._js_urls.add(norm)

    def _analyze_js_files(self):
        """Fetch and analyze JS files for API routes, fetch/XHR calls."""
        for js_url in list(self._js_urls)[:20]:
            status, body, _ = self._fetch(js_url)
            if status != 200 or not body:
                continue
            if self.delay > 0:
                time.sleep(self.delay)

            # fetch() calls
            for m in _RE_FETCH.finditer(body):
                url = m.group(1)
                norm = self._normalize_url(url, js_url)
                if norm:
                    self._add_endpoint(CrawlEndpoint(
                        url=norm, source="js_fetch", depth=1))

            # XHR .open() calls
            for m in _RE_XHR.finditer(body):
                method, url = m.group(1), m.group(2)
                norm = self._normalize_url(url, js_url)
                if norm:
                    self._add_endpoint(CrawlEndpoint(
                        url=norm, method=method, source="js_xhr", depth=1))

            # axios calls
            for m in _RE_AXIOS.finditer(body):
                method, url = m.group(1), m.group(2)
                norm = self._normalize_url(url, js_url)
                if norm:
                    self._add_endpoint(CrawlEndpoint(
                        url=norm, method=method, source="js_fetch", depth=1))

            # jQuery ajax
            for m in _RE_JQUERY.finditer(body):
                jq_method, url = m.group(1), m.group(2)
                method_map = {"get": "GET", "post": "POST", "getJSON": "GET", "ajax": "GET"}
                norm = self._normalize_url(url, js_url)
                if norm:
                    self._add_endpoint(CrawlEndpoint(
                        url=norm, method=method_map.get(jq_method.lower(), "GET"),
                        source="js_fetch", depth=1))

            # API paths
            for m in _RE_API_PATH.finditer(body):
                path = m.group(1)
                full = f"{self.base_url}{path}"
                self._add_endpoint(CrawlEndpoint(
                    url=full, source="js_fetch", depth=1))

            # REST CRUD paths (/users, /items, /search, etc.)
            for m in _RE_REST_CRUD.finditer(body):
                path = m.group(1)
                full = f"{self.base_url}{path}"
                self._add_endpoint(CrawlEndpoint(
                    url=full, source="js_fetch", depth=1))

            # WebSocket URLs
            for m in _RE_WEBSOCKET.finditer(body):
                ws_url = m.group(1)
                if not hasattr(self, '_websockets'):
                    self._websockets = []
                self._websockets.append(ws_url)

            # postMessage targets
            for m in _RE_POSTMESSAGE.finditer(body):
                origin = m.group(1)
                if not hasattr(self, '_postmessage_targets'):
                    self._postmessage_targets = []
                if origin not in self._postmessage_targets:
                    self._postmessage_targets.append(origin)

            # JSON keys near API calls (potential body params)
            # Only extract if there's a nearby fetch/axios/xhr
            if _RE_FETCH.search(body) or _RE_XHR.search(body) or _RE_AXIOS.search(body):
                json_keys = _RE_JSON_KEY.findall(body)
                # Filter to likely param names
                _SKIP = {"type", "name", "value", "class", "style", "id", "key",
                         "default", "true", "false", "null", "undefined",
                         "length", "prototype", "constructor"}
                json_keys = [k for k in json_keys if k.lower() not in _SKIP
                             and not k.startswith("_") and len(k) > 2][:20]
                # These are potential POST body params — associate with discovered API endpoints
                # (stored as context, not standalone endpoints)

    def _check_openapi(self):
        """Probe for OpenAPI/Swagger spec endpoints and extract API routes."""
        for path in _OPENAPI_PATHS:
            url = f"{self.base_url}{path}"
            status, body, headers = self._fetch(url)
            if status != 200 or not body:
                continue
            ct = headers.get("content-type", "")

            # JSON spec (swagger.json / openapi.json)
            if "json" in ct or body.strip().startswith("{"):
                try:
                    spec = json.loads(body)
                    paths = spec.get("paths", {})
                    if not paths:
                        continue
                    if not hasattr(self, '_openapi_specs'):
                        self._openapi_specs = []
                    self._openapi_specs.append(url)

                    for api_path, methods in paths.items():
                        if not isinstance(methods, dict):
                            continue
                        for method_name, detail in methods.items():
                            if method_name.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                                continue
                            full = f"{self.base_url}{api_path}"
                            params = []
                            # Extract parameter names
                            for p in (detail.get("parameters", []) or []):
                                if isinstance(p, dict) and p.get("name"):
                                    params.append(p["name"])
                            # Extract request body keys (OpenAPI 3.x)
                            rb = detail.get("requestBody", {})
                            if isinstance(rb, dict):
                                content = rb.get("content", {})
                                for ct_key, ct_val in content.items():
                                    schema = ct_val.get("schema", {}) if isinstance(ct_val, dict) else {}
                                    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                                    if isinstance(props, dict):
                                        params.extend(list(props.keys())[:20])

                            self._add_endpoint(CrawlEndpoint(
                                url=full, method=method_name.upper(),
                                params=list(dict.fromkeys(params)),
                                source="openapi", content_type="application/json",
                                depth=0))
                    return  # Found a spec, stop probing
                except (json.JSONDecodeError, ValueError):
                    pass

            # HTML page (swagger-ui, redoc) — just note it exists
            if "html" in ct and any(kw in body.lower() for kw in ("swagger", "openapi", "redoc")):
                if not hasattr(self, '_openapi_specs'):
                    self._openapi_specs = []
                self._openapi_specs.append(url)

    def _check_graphql(self):
        """Probe for GraphQL introspection."""
        for path in _GRAPHQL_PATHS:
            url = f"{self.base_url}{path}"
            s = self._get_session()
            try:
                r = s.post(url, headers={"Content-Type": "application/json"},
                           data='{"query":"{ __schema { types { name } } }"}')
                if r.status_code == 200 and "__schema" in r.text:
                    # GraphQL found — extract type names
                    try:
                        data = json.loads(r.text)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t["name"] for t in types
                                      if not t["name"].startswith("__")][:20]
                    except Exception:
                        type_names = []
                    self._add_endpoint(CrawlEndpoint(
                        url=url, method="POST", params=type_names,
                        source="graphql", content_type="application/json",
                        depth=0))
                    break
            except Exception:
                continue

    def close(self):
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
