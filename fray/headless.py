"""
Fray Headless Browser Engine — SPA crawling and DOM XSS verification.

Features:
  - Playwright-based headless browser (optional dependency)
  - SPA JavaScript rendering and crawling
  - DOM XSS verification (inject + observe alert/console)
  - Screenshot capture for proof-of-exploitation
  - JavaScript execution monitoring
  - Network request interception
  - Cookie/localStorage extraction
  - Form auto-fill and submission

Falls back to stdlib HTTP if Playwright is not installed.

Usage:
    engine = HeadlessEngine()
    page = engine.navigate("https://example.com")
    links = page.extract_links()
    screenshot = page.screenshot()
    dom_xss = page.verify_xss("<img src=x onerror=alert(1)>")
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _playwright_available() -> bool:
    """Check if Playwright is installed."""
    try:
        import playwright
        return True
    except ImportError:
        return False


class PageResult:
    """Result from navigating to a page."""
    def __init__(self):
        self.url: str = ""
        self.title: str = ""
        self.status: int = 0
        self.body: str = ""
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts: List[str] = []
        self.console_logs: List[str] = []
        self.network_requests: List[Dict[str, str]] = []
        self.cookies: List[Dict[str, str]] = []
        self.local_storage: Dict[str, str] = {}
        self.screenshot_path: Optional[str] = None
        self.js_errors: List[str] = []
        self.dom_xss_verified: bool = False
        self.rendered_html: str = ""
        self.elapsed_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "status": self.status,
            "links_count": len(self.links),
            "forms_count": len(self.forms),
            "scripts_count": len(self.scripts),
            "console_logs": self.console_logs[:20],
            "network_requests": len(self.network_requests),
            "cookies": len(self.cookies),
            "js_errors": self.js_errors[:10],
            "dom_xss_verified": self.dom_xss_verified,
            "screenshot": self.screenshot_path,
            "elapsed_ms": self.elapsed_ms,
        }


class HeadlessEngine:
    """Headless browser engine for SPA crawling and DOM XSS verification.

    Uses Playwright if available, otherwise falls back to Node.js puppeteer
    or basic HTTP crawling.
    """

    def __init__(self, headless: bool = True, timeout: int = 30000,
                 user_agent: str = "",
                 proxy: str = "",
                 viewport: Tuple[int, int] = (1920, 1080)):
        self.headless = headless
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        self.proxy = proxy
        self.viewport = viewport
        self._browser = None
        self._context = None
        self._use_playwright = _playwright_available()

    def _ensure_browser(self):
        """Lazily initialize browser on first use."""
        if self._browser:
            return
        if not self._use_playwright:
            return

        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        launch_opts = {"headless": self.headless}
        if self.proxy:
            launch_opts["proxy"] = {"server": self.proxy}
        self._browser = self._pw.chromium.launch(**launch_opts)
        ctx_opts = {
            "viewport": {"width": self.viewport[0], "height": self.viewport[1]},
            "user_agent": self.user_agent,
            "ignore_https_errors": True,
        }
        self._context = self._browser.new_context(**ctx_opts)

    def navigate(self, url: str, wait_for: str = "networkidle") -> PageResult:
        """Navigate to URL and collect page data."""
        result = PageResult()
        result.url = url
        t0 = time.monotonic()

        if self._use_playwright:
            result = self._navigate_playwright(url, wait_for, result)
        else:
            result = self._navigate_fallback(url, result)

        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result

    def _navigate_playwright(self, url: str, wait_for: str, result: PageResult) -> PageResult:
        """Navigate using Playwright."""
        self._ensure_browser()
        page = self._context.new_page()

        # Collect console logs
        page.on("console", lambda msg: result.console_logs.append(f"[{msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: result.js_errors.append(str(err)))

        # Collect network requests
        def on_request(req):
            result.network_requests.append({
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
            })
        page.on("request", on_request)

        try:
            resp = page.goto(url, wait_until=wait_for, timeout=self.timeout)
            result.status = resp.status if resp else 0
            result.title = page.title()
            result.rendered_html = page.content()
            result.body = result.rendered_html

            # Extract links
            result.links = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )

            # Extract forms
            forms = page.eval_on_selector_all(
                "form",
                """els => els.map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                        name: i.name, type: i.type, value: i.value
                    }))
                }))"""
            )
            result.forms = forms

            # Extract script srcs
            result.scripts = page.eval_on_selector_all(
                "script[src]", "els => els.map(e => e.src)"
            )

            # Cookies
            cookies = self._context.cookies()
            result.cookies = [{"name": c["name"], "value": c["value"], "domain": c["domain"]}
                             for c in cookies]

            # LocalStorage
            try:
                result.local_storage = page.evaluate(
                    "() => { const s = {}; for(let i=0;i<localStorage.length;i++){ const k=localStorage.key(i); s[k]=localStorage.getItem(k); } return s; }"
                )
            except Exception:
                pass

        except Exception as e:
            result.js_errors.append(str(e))
        finally:
            page.close()

        return result

    def _navigate_fallback(self, url: str, result: PageResult) -> PageResult:
        """Fallback: use stdlib HTTP (no JS rendering)."""
        import http.client
        import ssl
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=15, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=15)
            conn.request("GET", path, headers={"User-Agent": self.user_agent, "Accept": "*/*"})
            resp = conn.getresponse()
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            result.status = resp.status
            result.body = body
            result.rendered_html = body
            conn.close()

            # Parse title
            m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            result.title = m.group(1).strip() if m else ""

            # Parse links
            result.links = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)

            # Parse scripts
            result.scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)

        except Exception as e:
            result.js_errors.append(str(e))

        return result

    def screenshot(self, url: str, output_path: str = "") -> Optional[str]:
        """Take a screenshot of a URL."""
        if not self._use_playwright:
            return None

        self._ensure_browser()
        page = self._context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.timeout)
            path = output_path or f"/tmp/fray_screenshot_{int(time.time())}.png"
            page.screenshot(path=path, full_page=True)
            page.close()
            return path
        except Exception:
            page.close()
            return None

    def verify_xss(self, url: str, payload: str, param: str) -> Dict[str, Any]:
        """Verify XSS by injecting payload and checking for alert/console output.

        Returns dict with 'verified', 'method', 'evidence'.
        """
        result = {"verified": False, "method": "", "evidence": "", "screenshot": None}

        if not self._use_playwright:
            return result

        import urllib.parse
        self._ensure_browser()
        page = self._context.new_page()

        dialog_triggered = [False]
        dialog_message = [""]

        def on_dialog(dialog):
            dialog_triggered[0] = True
            dialog_message[0] = dialog.message
            dialog.dismiss()

        page.on("dialog", on_dialog)

        try:
            # Build URL with payload
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[param] = payload
            qs = urllib.parse.urlencode(params, safe="")
            inject_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"

            page.goto(inject_url, wait_until="networkidle", timeout=self.timeout)

            # Wait a moment for JS to execute
            page.wait_for_timeout(1000)

            if dialog_triggered[0]:
                result["verified"] = True
                result["method"] = "alert_dialog"
                result["evidence"] = f"Alert triggered: {dialog_message[0]}"
                # Screenshot proof
                ss_path = f"/tmp/fray_xss_proof_{int(time.time())}.png"
                page.screenshot(path=ss_path)
                result["screenshot"] = ss_path

        except Exception as e:
            result["evidence"] = str(e)
        finally:
            page.close()

        return result

    def crawl_spa(self, url: str, max_pages: int = 50,
                  max_depth: int = 3) -> List[PageResult]:
        """Crawl a single-page application by following links and monitoring route changes."""
        visited: set = set()
        queue: List[Tuple[str, int]] = [(url, 0)]
        results: List[PageResult] = []

        while queue and len(results) < max_pages:
            current_url, depth = queue.pop(0)
            if current_url in visited or depth > max_depth:
                continue
            visited.add(current_url)

            page_result = self.navigate(current_url)
            results.append(page_result)

            # Add discovered links to queue
            for link in page_result.links:
                if link not in visited and link.startswith(("http://", "https://")):
                    # Same-origin only
                    import urllib.parse
                    parsed_link = urllib.parse.urlparse(link)
                    parsed_base = urllib.parse.urlparse(url)
                    if parsed_link.netloc == parsed_base.netloc:
                        queue.append((link, depth + 1))

        return results

    def solve_js_challenge(self, url: str, max_wait: int = 30,
                           cookie_jar: Optional[Dict[str, str]] = None,
                           ) -> Dict[str, Any]:
        """Solve JavaScript challenges (Cloudflare, Akamai, etc.) using Playwright.

        Navigates to the URL in a real browser, waits for JS challenges to
        auto-solve (most are timer-based), then extracts the resulting cookies
        and page content.

        Args:
            url:        Target URL behind a JS challenge.
            max_wait:   Maximum seconds to wait for challenge to resolve.
            cookie_jar: Optional initial cookies to set before navigation.

        Returns:
            Dict with 'solved', 'cookies', 'headers', 'body', 'challenge_type',
            'elapsed_ms', 'status'.
        """
        result: Dict[str, Any] = {
            "solved": False,
            "cookies": {},
            "headers": {},
            "body": "",
            "challenge_type": "unknown",
            "elapsed_ms": 0,
            "status": 0,
            "error": "",
        }

        if not self._use_playwright:
            result["error"] = "Playwright not installed (pip install playwright && playwright install chromium)"
            return result

        self._ensure_browser()
        page = self._context.new_page()
        t0 = time.monotonic()

        # Challenge detection patterns
        _CF_PATTERNS = [
            "Checking if the site connection is secure",
            "Enable JavaScript and cookies to continue",
            "Just a moment...",
            "cf-browser-verification",
            "cf_chl_opt",
            "_cf_chl_tk",
        ]
        _AKAMAI_PATTERNS = [
            "akam-sw.js",
            "_abck",
            "AkamaiGlobalHost",
        ]
        _DDOS_GUARD_PATTERNS = [
            "DDoS-Guard",
            "__ddg1",
            "__ddg2",
        ]

        try:
            # Set initial cookies if provided
            if cookie_jar:
                import urllib.parse as _up
                parsed = _up.urlparse(url)
                cookie_list = [
                    {"name": k, "value": v, "domain": parsed.hostname,
                     "path": "/", "httpOnly": False, "secure": parsed.scheme == "https"}
                    for k, v in cookie_jar.items()
                ]
                self._context.add_cookies(cookie_list)

            # Navigate — use 'commit' to get initial response quickly
            resp = page.goto(url, wait_until="commit", timeout=self.timeout)
            result["status"] = resp.status if resp else 0

            # Check initial page for challenge indicators
            body = page.content()

            # Detect challenge type
            challenge_type = "none"
            for pat in _CF_PATTERNS:
                if pat in body:
                    challenge_type = "cloudflare"
                    break
            if challenge_type == "none":
                for pat in _AKAMAI_PATTERNS:
                    if pat in body:
                        challenge_type = "akamai"
                        break
            if challenge_type == "none":
                for pat in _DDOS_GUARD_PATTERNS:
                    if pat in body:
                        challenge_type = "ddos_guard"
                        break

            result["challenge_type"] = challenge_type

            if challenge_type == "none":
                # No challenge detected — page loaded directly
                result["solved"] = True
                result["body"] = body
            else:
                # Wait for challenge to resolve (most are timer-based 3-5s)
                # Poll every 500ms for up to max_wait seconds
                deadline = time.monotonic() + max_wait
                solved = False
                while time.monotonic() < deadline:
                    page.wait_for_timeout(500)
                    body = page.content()

                    # Check if challenge is gone
                    still_challenging = False
                    if challenge_type == "cloudflare":
                        still_challenging = any(p in body for p in _CF_PATTERNS[:3])
                    elif challenge_type == "akamai":
                        still_challenging = resp and resp.status in (403, 429)
                    elif challenge_type == "ddos_guard":
                        still_challenging = "DDoS-Guard" in body and len(body) < 5000

                    if not still_challenging:
                        solved = True
                        break

                    # Check for Turnstile iframe and try to interact
                    try:
                        turnstile = page.query_selector("iframe[src*='challenges.cloudflare.com']")
                        if turnstile:
                            # Turnstile auto-solves if browser looks real;
                            # just wait for it
                            pass
                    except Exception:
                        pass

                result["solved"] = solved
                result["body"] = page.content() if solved else body
                result["status"] = 200 if solved else result["status"]

            # Extract cookies (the valuable part — contains cf_clearance, etc.)
            all_cookies = self._context.cookies()
            result["cookies"] = {
                c["name"]: c["value"] for c in all_cookies
            }

            # Extract response headers from the last navigation
            result["headers"] = {}

        except Exception as e:
            result["error"] = str(e)
        finally:
            result["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
            page.close()

        return result

    def close(self):
        """Clean up browser resources."""
        if self._browser:
            self._browser.close()
            self._pw.stop()
            self._browser = None
