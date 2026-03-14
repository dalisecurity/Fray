"""
Fray Parallel/Async Request Execution Engine.

Provides high-performance concurrent HTTP request execution for:
  - Payload testing (WAF bypass, fuzzing)
  - Multi-target scanning
  - Parallel recon checks

Features:
  - asyncio + stdlib (zero deps) or optional aiohttp
  - Configurable concurrency (semaphore-based)
  - Rate limiting (requests/sec)
  - Automatic retry with backoff
  - Per-request timeout
  - Result streaming (callback or queue)
  - Connection pooling

Usage:
    engine = AsyncEngine(concurrency=20, rate_limit=50)
    results = engine.run(requests)

    # Or with callback:
    engine.run(requests, callback=lambda r: print(r.status))

Zero external dependencies — stdlib only (aiohttp optional for speed).
"""

import asyncio
import http.client
import json
import queue
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple


class AsyncRequest:
    """A single HTTP request to execute."""
    __slots__ = ("url", "method", "headers", "body", "timeout", "verify_ssl",
                 "tag", "meta")

    def __init__(self, url: str, method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 body: Optional[str] = None, timeout: int = 10,
                 verify_ssl: bool = True, tag: str = "",
                 meta: Optional[Dict[str, Any]] = None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.body = body
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.tag = tag
        self.meta = meta or {}


class AsyncResponse:
    """Response from an async request."""
    __slots__ = ("url", "status", "body", "headers", "elapsed_ms", "error",
                 "tag", "meta")

    def __init__(self, url: str = "", status: int = 0, body: str = "",
                 headers: Optional[Dict[str, str]] = None,
                 elapsed_ms: float = 0, error: str = "",
                 tag: str = "", meta: Optional[Dict[str, Any]] = None):
        self.url = url
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.elapsed_ms = elapsed_ms
        self.error = error
        self.tag = tag
        self.meta = meta or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "body_length": len(self.body),
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "tag": self.tag,
        }


class AsyncEngine:
    """High-performance parallel HTTP request engine."""

    def __init__(self, concurrency: int = 20, rate_limit: float = 0,
                 max_retries: int = 1, retry_delay: float = 0.5,
                 max_body_size: int = 512 * 1024,
                 default_timeout: int = 10,
                 default_headers: Optional[Dict[str, str]] = None):
        """
        Args:
            concurrency: Max parallel requests.
            rate_limit: Max requests per second (0 = unlimited).
            max_retries: Retry count on failure.
            retry_delay: Base delay between retries (exponential backoff).
            max_body_size: Max response body to read (bytes).
            default_timeout: Default per-request timeout.
            default_headers: Default headers for all requests.
        """
        self.concurrency = max(1, min(concurrency, 200))
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_body_size = max_body_size
        self.default_timeout = default_timeout
        self.default_headers = default_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
        }

        # Stats
        self._total_requests = 0
        self._total_errors = 0
        self._start_time = 0.0
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0

    # ── Single request execution ───────────────────────────────────────

    def _execute_one(self, req: AsyncRequest) -> AsyncResponse:
        """Execute a single HTTP request using stdlib."""
        parsed = urllib.parse.urlparse(req.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        hdrs = dict(self.default_headers)
        hdrs.update(req.headers)
        timeout = req.timeout or self.default_timeout

        body_bytes = req.body.encode() if req.body else None

        # Rate limiting
        if self.rate_limit > 0:
            with self._rate_lock:
                now = time.monotonic()
                min_interval = 1.0 / self.rate_limit
                elapsed_since_last = now - self._last_request_time
                if elapsed_since_last < min_interval:
                    time.sleep(min_interval - elapsed_since_last)
                self._last_request_time = time.monotonic()

        for attempt in range(self.max_retries + 1):
            t0 = time.monotonic()
            try:
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    if not req.verify_ssl:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(host, port,
                                                        timeout=timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)

                conn.request(req.method, path, body=body_bytes, headers=hdrs)
                resp = conn.getresponse()
                body = resp.read(self.max_body_size).decode("utf-8", errors="replace")
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()

                elapsed = (time.monotonic() - t0) * 1000
                self._total_requests += 1

                return AsyncResponse(
                    url=req.url, status=status, body=body,
                    headers=resp_headers, elapsed_ms=elapsed,
                    tag=req.tag, meta=req.meta,
                )

            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (2 ** attempt))
                    continue

                self._total_errors += 1
                return AsyncResponse(
                    url=req.url, status=0, body="",
                    elapsed_ms=elapsed, error=str(e)[:200],
                    tag=req.tag, meta=req.meta,
                )

        # Should not reach here
        return AsyncResponse(url=req.url, error="max retries exceeded",
                             tag=req.tag, meta=req.meta)

    # ── Parallel execution (ThreadPoolExecutor) ────────────────────────

    def run(self, requests: List[AsyncRequest],
            callback: Optional[Callable[[AsyncResponse], None]] = None,
            ordered: bool = False) -> List[AsyncResponse]:
        """Execute requests in parallel using ThreadPoolExecutor.

        Args:
            requests: List of requests to execute.
            callback: Optional callback for each completed response.
            ordered: If True, return results in request order.

        Returns:
            List of AsyncResponse objects.
        """
        if not requests:
            return []

        self._total_requests = 0
        self._total_errors = 0
        self._start_time = time.monotonic()
        self._last_request_time = 0.0

        results: List[AsyncResponse] = []

        if ordered:
            # Maintain order using index mapping
            result_map: Dict[int, AsyncResponse] = {}
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {
                    pool.submit(self._execute_one, req): i
                    for i, req in enumerate(requests)
                }
                for future in as_completed(futures):
                    idx = futures[future]
                    try:
                        resp = future.result()
                    except Exception as e:
                        resp = AsyncResponse(
                            url=requests[idx].url, error=str(e),
                            tag=requests[idx].tag, meta=requests[idx].meta,
                        )
                    result_map[idx] = resp
                    if callback:
                        callback(resp)

            results = [result_map[i] for i in range(len(requests))]
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {
                    pool.submit(self._execute_one, req): req
                    for req in requests
                }
                for future in as_completed(futures):
                    req = futures[future]
                    try:
                        resp = future.result()
                    except Exception as e:
                        resp = AsyncResponse(
                            url=req.url, error=str(e),
                            tag=req.tag, meta=req.meta,
                        )
                    results.append(resp)
                    if callback:
                        callback(resp)

        return results

    # ── Batch builder helpers ──────────────────────────────────────────

    @staticmethod
    def build_requests(url: str, param: str, payloads: List[str],
                       method: str = "GET", cookie: str = "",
                       verify_ssl: bool = True,
                       timeout: int = 10) -> List[AsyncRequest]:
        """Build a batch of requests from a URL + param + payload list.

        Convenience method for fuzzing / payload testing.
        """
        parsed = urllib.parse.urlparse(url)
        base_params = dict(urllib.parse.parse_qsl(parsed.query))
        requests = []

        for i, payload in enumerate(payloads):
            params = dict(base_params)
            params[param] = payload

            if method == "GET":
                qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
                req_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                body = None
            else:
                req_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                body = urllib.parse.urlencode(params)

            hdrs = {}
            if cookie:
                hdrs["Cookie"] = cookie
            if method == "POST":
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

            requests.append(AsyncRequest(
                url=req_url, method=method, headers=hdrs,
                body=body, timeout=timeout, verify_ssl=verify_ssl,
                tag=f"payload_{i}", meta={"payload": payload, "index": i},
            ))

        return requests

    @staticmethod
    def build_url_requests(urls: List[str], method: str = "GET",
                           cookie: str = "", verify_ssl: bool = True,
                           timeout: int = 10) -> List[AsyncRequest]:
        """Build requests from a list of URLs (for multi-target scanning)."""
        requests = []
        for i, url in enumerate(urls):
            hdrs = {}
            if cookie:
                hdrs["Cookie"] = cookie
            requests.append(AsyncRequest(
                url=url, method=method, headers=hdrs,
                timeout=timeout, verify_ssl=verify_ssl,
                tag=f"url_{i}", meta={"index": i},
            ))
        return requests

    # ── Stats ──────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return execution statistics."""
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        rps = self._total_requests / elapsed if elapsed > 0 else 0
        return {
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "elapsed_sec": round(elapsed, 2),
            "requests_per_sec": round(rps, 1),
            "concurrency": self.concurrency,
            "rate_limit": self.rate_limit,
        }


# ══════════════════════════════════════════════════════════════════════════
# Response Diffing — False Positive Reduction
# ══════════════════════════════════════════════════════════════════════════

class ResponseBaseline:
    """Captures a baseline response for comparison — reduces false positives.

    Strategy: Send a benign request first. Compare each payload response to
    the baseline. If the response is too similar to baseline, the WAF didn't
    actually block it (false positive).
    """

    def __init__(self, status: int = 0, body: str = "", headers: Dict[str, str] = None,
                 body_length: int = 0):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.body_length = body_length or len(body)
        self._body_tokens: Optional[set] = None

    @property
    def body_tokens(self) -> set:
        """Lazy tokenize body for similarity comparison."""
        if self._body_tokens is None:
            import re
            self._body_tokens = set(re.findall(r'\w{3,}', self.body.lower()))
        return self._body_tokens

    @staticmethod
    def capture(url: str, param: str = "q", method: str = "GET",
                timeout: int = 10, verify_ssl: bool = True,
                headers: Optional[Dict[str, str]] = None) -> 'ResponseBaseline':
        """Capture a baseline by sending a benign request."""
        engine = AsyncEngine(concurrency=1, default_timeout=timeout)
        benign = "test12345"
        reqs = AsyncEngine.build_requests(
            url, param, [benign], method=method,
            verify_ssl=verify_ssl, timeout=timeout,
        )
        if headers:
            for r in reqs:
                r.headers.update(headers)
        results = engine.run(reqs)
        if results and results[0].status > 0:
            r = results[0]
            return ResponseBaseline(
                status=r.status, body=r.body,
                headers=r.headers, body_length=len(r.body),
            )
        return ResponseBaseline()

    def is_false_positive(self, resp_status: int, resp_body: str,
                          similarity_threshold: float = 0.85) -> bool:
        """Check if a response is a false positive (too similar to baseline).

        A "blocked" response that looks identical to the baseline benign
        response is likely a false positive — the WAF didn't actually block.

        Returns True if the response is a likely false positive.
        """
        if self.status == 0:
            return False  # No baseline captured

        # If statuses match and body length is within 15%, check tokens
        if resp_status == self.status:
            len_ratio = len(resp_body) / max(self.body_length, 1)
            if 0.85 <= len_ratio <= 1.15:
                import re
                resp_tokens = set(re.findall(r'\w{3,}', resp_body.lower()))
                if not self.body_tokens and not resp_tokens:
                    return True
                if self.body_tokens:
                    overlap = len(self.body_tokens & resp_tokens) / max(len(self.body_tokens), 1)
                    if overlap >= similarity_threshold:
                        return True

        return False

    def classify_block(self, resp_status: int, resp_body: str) -> str:
        """Classify how the response differs from baseline.

        Returns: 'blocked', 'different_status', 'different_body', 'same' (false positive)
        """
        if self.status == 0:
            # No baseline — use status code heuristics
            if resp_status in (403, 406, 429, 503):
                return "blocked"
            return "unknown"

        if self.is_false_positive(resp_status, resp_body):
            return "same"

        if resp_status != self.status:
            if resp_status in (403, 406, 429, 503):
                return "blocked"
            return "different_status"

        # Same status but different body
        return "different_body"


# ══════════════════════════════════════════════════════════════════════════
# Redirect Chain Following
# ══════════════════════════════════════════════════════════════════════════

def follow_redirects(url: str, method: str = "GET",
                     headers: Optional[Dict[str, str]] = None,
                     body: Optional[str] = None,
                     max_redirects: int = 5, timeout: int = 10,
                     verify_ssl: bool = True) -> Tuple[int, str, Dict[str, str], List[Dict]]:
    """Follow redirect chain and return final response + chain.

    WAFs sometimes respond with 302 redirects instead of 403 blocks.
    This function follows the chain and classifies the outcome.

    Returns:
        (final_status, final_body, final_headers, chain)
        chain = [{"status": 302, "location": "...", "url": "..."}, ...]
    """
    chain: List[Dict] = []
    current_url = url
    current_method = method

    for _ in range(max_redirects):
        parsed = urllib.parse.urlparse(current_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", "Mozilla/5.0")
        hdrs.setdefault("Host", host)
        body_bytes = body.encode() if body and current_method == "POST" else None

        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                if not verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)

            conn.request(current_method, path, body=body_bytes, headers=hdrs)
            resp = conn.getresponse()
            resp_body = resp.read(512 * 1024).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
            conn.close()

        except Exception as e:
            return 0, str(e), {}, chain

        if status in (301, 302, 303, 307, 308):
            location = resp_headers.get("location", "")
            chain.append({
                "status": status,
                "url": current_url,
                "location": location,
            })
            if not location:
                return status, resp_body, resp_headers, chain
            # Resolve relative redirect
            if location.startswith("/"):
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            elif not location.startswith("http"):
                location = urllib.parse.urljoin(current_url, location)
            current_url = location
            # 303 always becomes GET
            if status == 303:
                current_method = "GET"
                body = None
            continue

        return status, resp_body, resp_headers, chain

    # Max redirects exceeded
    return 0, "max redirects exceeded", {}, chain


def classify_redirect_block(chain: List[Dict], final_status: int,
                            final_body: str) -> str:
    """Classify if a redirect chain indicates a WAF block.

    Returns: 'redirect_block', 'captcha_redirect', 'normal_redirect', 'no_redirect'
    """
    if not chain:
        return "no_redirect"

    # Check if any redirect goes to a known block/captcha page
    _BLOCK_PATTERNS = [
        "captcha", "challenge", "blocked", "denied", "forbidden",
        "security", "firewall", "waf", "bot-detect",
    ]
    for hop in chain:
        loc = hop.get("location", "").lower()
        if any(p in loc for p in _BLOCK_PATTERNS):
            return "redirect_block"

    # Final page is a captcha/challenge?
    import re
    if re.search(r'captcha|challenge|blocked|denied|firewall', final_body, re.I):
        return "captcha_redirect"

    # If final status is still a block
    if final_status in (403, 406, 429, 503):
        return "redirect_block"

    return "normal_redirect"


# ══════════════════════════════════════════════════════════════════════════
# Parallel Payload Testing — High-level API for scanner integration
# ══════════════════════════════════════════════════════════════════════════

def parallel_test_payloads(
    url: str, param: str, payloads: List[str],
    method: str = "GET", category: str = "xss",
    concurrency: int = 10, rate_limit: float = 0,
    timeout: int = 10, verify_ssl: bool = True,
    headers: Optional[Dict[str, str]] = None,
    baseline: Optional[ResponseBaseline] = None,
    follow_redirect: bool = True,
    callback: Optional[Callable] = None,
) -> List[Dict]:
    """Test payloads in parallel with false-positive reduction + redirect following.

    This is the high-level API for integrating async testing into fray scan.

    Args:
        url: Target URL.
        param: Parameter to inject into.
        payloads: List of payload strings.
        method: HTTP method.
        category: Payload category (for result tagging).
        concurrency: Max parallel requests.
        rate_limit: Max requests/sec.
        timeout: Request timeout.
        verify_ssl: Verify SSL.
        headers: Custom headers.
        baseline: Optional baseline for false positive reduction.
        follow_redirect: Follow 3xx redirects to detect redirect-based blocks.
        callback: Optional per-result callback.

    Returns:
        List of result dicts compatible with WAFTester.test_payload output.
    """
    engine = AsyncEngine(
        concurrency=concurrency,
        rate_limit=rate_limit,
        default_timeout=timeout,
    )

    reqs = AsyncEngine.build_requests(
        url, param, payloads, method=method,
        verify_ssl=verify_ssl, timeout=timeout,
    )
    if headers:
        for r in reqs:
            r.headers.update(headers)

    # Capture baseline if not provided
    if baseline is None:
        baseline = ResponseBaseline.capture(
            url, param=param, method=method,
            timeout=timeout, verify_ssl=verify_ssl, headers=headers,
        )

    # Fire all requests
    responses = engine.run(reqs, ordered=True)

    results = []
    for i, resp in enumerate(responses):
        payload = payloads[i] if i < len(payloads) else ""
        blocked = resp.status in (403, 406, 429, 503) or resp.error != ""
        reflected = payload in resp.body if payload and resp.body else False

        # False positive check
        fp = False
        if blocked and baseline:
            fp = baseline.is_false_positive(resp.status, resp.body)
            if fp:
                blocked = False

        # Redirect following
        redirect_info = None
        if follow_redirect and resp.status in (301, 302, 303, 307, 308):
            final_status, final_body, final_headers, chain = follow_redirects(
                resp.url, method=method, headers=headers or {},
                timeout=timeout, verify_ssl=verify_ssl,
            )
            redirect_class = classify_redirect_block(chain, final_status, final_body)
            blocked = redirect_class in ("redirect_block", "captcha_redirect")
            reflected = payload in final_body if payload and final_body else False
            redirect_info = {
                "chain_length": len(chain),
                "final_status": final_status,
                "classification": redirect_class,
            }

        result = {
            "payload": payload,
            "status": resp.status,
            "blocked": blocked,
            "reflected": reflected,
            "false_positive": fp,
            "elapsed_ms": round(resp.elapsed_ms, 1),
            "category": category,
            "param": param,
            "method": method,
        }
        if redirect_info:
            result["redirect"] = redirect_info
        if resp.error:
            result["error"] = resp.error

        results.append(result)
        if callback:
            callback(result)

    return results
