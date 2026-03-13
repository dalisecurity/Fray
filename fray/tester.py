#!/usr/bin/env python3
"""
WAF Tester - Easy-to-use CLI tool for WAF testing
Simple command-line interface for testing WAFs with comprehensive payload database
"""

import argparse
import ipaddress
import json
import random
import socket
import ssl
import re
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import sys


# Realistic browser User-Agent pool (2025-2026 versions)
# Used by DEFAULT — not just stealth mode — to avoid bot detection before reaching WAF
_BROWSER_USER_AGENTS = [
    # Chrome 131-134 (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox 133-135
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari 18
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    # Edge 131-134
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
]

# Accept-Language variants
_BROWSER_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en,*;q=0.5",
]

# Browser-realistic Accept headers by content type
_BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
_BROWSER_ACCEPT_ENCODING = "gzip, deflate, br"

# Sec-Fetch headers that real browsers always send (absence flags bots)
_SEC_FETCH_HEADERS = {
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


def _is_private_host(hostname: str) -> bool:
    """Check if a hostname resolves to a private/internal IP address."""
    if not hostname:
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (socket.gaierror, ValueError):
        return False

# Import WAF detector if available
try:
    from waf_detector import WAFDetector
    WAF_DETECTOR_AVAILABLE = True
except ImportError:
    WAF_DETECTOR_AVAILABLE = False

class Colors:
    """Terminal colors for better output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class WAFTester:
    """Main WAF testing class"""
    
    def __init__(self, target: str, timeout: int = 8, delay: float = 0.5,
                 custom_headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True, verbose: bool = False,
                 max_redirects: int = 5, jitter: float = 0.0,
                 stealth: bool = False, rate_limit: float = 0.0):
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.jitter = jitter
        self.stealth = stealth
        self.rate_limit = rate_limit
        self.results = []
        self.start_time = None
        self.custom_headers = custom_headers or {}
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.max_redirects = max_redirects
        self._last_request_time = 0.0
        self._baseline = None  # Cached baseline for confidence scoring
        self._consecutive_429s = 0  # Adaptive throttle: consecutive 429 counter
        self._backoff_until = 0.0   # Adaptive throttle: don't send before this time

        # Stealth mode defaults: if --stealth is on, apply sane defaults
        if self.stealth:
            if self.delay < 1.0:
                self.delay = 1.5
            if self.jitter == 0.0:
                self.jitter = 1.0
            if self.rate_limit == 0.0:
                self.rate_limit = 2.0  # max 2 req/s
        
        # Parse target URL
        if not target.startswith('http'):
            target = f'https://{target}'
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = parsed.scheme == 'https'
        self.path = parsed.path or '/'
        self.query = parsed.query
    
    def _stealth_delay(self):
        """Apply delay + jitter + rate limit between requests."""
        # Adaptive backoff: respect 429 cooldown
        if self._backoff_until > 0:
            remaining = self._backoff_until - time.time()
            if remaining > 0:
                time.sleep(remaining)
            self._backoff_until = 0.0

        # Rate limit: enforce minimum interval between requests
        if self.rate_limit > 0:
            min_interval = 1.0 / self.rate_limit
            elapsed = time.time() - self._last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

        # Base delay + random jitter
        wait = self.delay
        if self.jitter > 0:
            wait += random.uniform(0, self.jitter)
        if wait > 0:
            time.sleep(wait)

        self._last_request_time = time.time()

    def _get_browser_headers(self) -> str:
        """Return browser-mimicking headers.

        ALWAYS used (not just stealth) because bot detectors check UA, Accept,
        Sec-Fetch-* etc. BEFORE traffic even reaches the WAF layer.
        Without these, the request gets blocked by bot detection, not the WAF,
        giving a false 'blocked' result.
        """
        ua = random.choice(_BROWSER_USER_AGENTS)
        lang = random.choice(_BROWSER_ACCEPT_LANGS)
        # Header ordering matters — Chrome sends them in this exact order
        lines = (f"User-Agent: {ua}\r\n"
                 f"Accept: {_BROWSER_ACCEPT}\r\n"
                 f"Accept-Language: {lang}\r\n"
                 f"Accept-Encoding: {_BROWSER_ACCEPT_ENCODING}\r\n")
        # Sec-Fetch-* headers — their absence is a strong bot signal
        for k, v in _SEC_FETCH_HEADERS.items():
            lines += f"{k}: {v}\r\n"
        if self.stealth:
            # Extra stealth: add DNT, Upgrade-Insecure-Requests, Cache-Control
            lines += "DNT: 1\r\n"
            lines += "Upgrade-Insecure-Requests: 1\r\n"
            lines += f"Cache-Control: max-age=0\r\n"
        return lines

    def _build_post_body(self, payload: str, param: str, enc: str,
                         content_type: str = None) -> tuple:
        """Build Content-Type header and body for POST requests.

        Returns (content_type_header, body_string).
        Supports content-type confusion: JSON, multipart, XML, text/plain.
        """
        if not content_type:
            return ('application/x-www-form-urlencoded', f"{param}={enc}")

        ct = content_type.lower()

        if 'json' in ct:
            # JSON body — WAFs that only inspect form-urlencoded miss this
            import json as _json
            body = _json.dumps({param: payload})
            return ('application/json', body)

        elif 'multipart' in ct:
            # Multipart form-data — boundary-based encoding confuses pattern matchers
            boundary = '----FrayBoundary' + str(random.randint(100000, 999999))
            body = (f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; name=\"{param}\"\r\n\r\n"
                    f"{payload}\r\n"
                    f"--{boundary}--\r\n")
            return (f'multipart/form-data; boundary={boundary}', body)

        elif 'xml' in ct:
            # XML body — WAFs may not parse XML param extraction
            body = (f'<?xml version="1.0"?>\n'
                    f'<request><{param}>{payload}</{param}></request>')
            return ('text/xml', body)

        elif 'plain' in ct:
            # text/plain — some WAFs skip body inspection entirely
            body = f"{param}={payload}"
            return ('text/plain', body)

        else:
            # Custom content-type — send raw payload
            return (content_type, f"{param}={payload}")

    def _build_extra_headers(self) -> str:
        """Build extra header lines from custom_headers dict."""
        lines = ""
        for k, v in self.custom_headers.items():
            # Sanitize CRLF to prevent header injection
            k = k.replace('\r', '').replace('\n', '')
            v = v.replace('\r', '').replace('\n', '')
            lines += f"{k}: {v}\r\n"
        return lines

    def _resolve_and_check(self, host: str) -> str:
        """Resolve hostname once and return the IP. Raises ValueError for private IPs."""
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(f"Resolved to private/internal IP: {ip_str}")
        return ip_str

    def _raw_request(self, host: str, port: int, use_ssl: bool,
                     request: str) -> tuple:
        """Send a raw HTTP request and return (status, response_str, headers_dict)."""
        # DNS rebinding protection: resolve once, pin IP, verify it's not private
        try:
            resolved_ip = self._resolve_and_check(host)
        except (socket.gaierror, ValueError) as e:
            if isinstance(e, ValueError):
                raise  # Propagate private-IP block
            resolved_ip = host  # Fallback for raw IPs or unresolvable hosts

        if use_ssl:
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((resolved_ip, port), timeout=self.timeout)
            conn = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = socket.create_connection((resolved_ip, port), timeout=self.timeout)

        if self.verbose:
            print(f"\n{Colors.HEADER}>>> RAW REQUEST >>>{Colors.END}")
            print(request[:500])
            print(f"{Colors.HEADER}>>> END REQUEST >>>{Colors.END}")

        conn.sendall(request.encode('utf-8', errors='replace'))

        t0 = time.monotonic()
        resp = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                resp += data
                if len(resp) > 100000:
                    break
            except (socket.error, socket.timeout, OSError):
                break
        elapsed_ms = (time.monotonic() - t0) * 1000
        conn.close()

        resp_str = resp.decode('utf-8', errors='replace')
        status_match = re.search(r'HTTP/[\d.]+ (\d+)', resp_str)
        status = int(status_match.group(1)) if status_match else 0

        # Parse Location header for redirects
        headers = {}
        header_section = resp_str.split('\r\n\r\n', 1)[0] if '\r\n\r\n' in resp_str else resp_str
        for line in header_section.split('\r\n')[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        if self.verbose:
            print(f"\n{Colors.HEADER}<<< RAW RESPONSE (status={status}, {len(resp_str)} bytes) <<<{Colors.END}")
            print(resp_str[:800])
            print(f"{Colors.HEADER}<<< END RESPONSE <<<{Colors.END}")

        return status, resp_str, headers, elapsed_ms

    def _measure_baseline(self, param: str = 'input') -> Dict:
        """Send multiple benign requests to establish stable baseline characteristics.

        Sends 3 different benign values to capture:
        - Average response length and timing (reduces noise)
        - Body hash for identity comparison (detect "param ignored" FPs)
        - Structural token count (HTML tag count for structural diffing)
        - Content-Type of the response
        """
        if self._baseline is not None:
            return self._baseline

        import hashlib

        benign_values = ['test123', 'hello', 'fray_baseline']
        samples = []

        for benign in benign_values:
            try:
                enc = urllib.parse.quote(benign, safe='')
                query_string = f"{self.query}&{param}={enc}" if self.query else f"{param}={enc}"
                req = (f"GET {self.path}?{query_string} HTTP/1.1\r\n"
                       f"Host: {self.host}\r\n"
                       f"Connection: close\r\n\r\n")
                status, resp_str, headers, elapsed_ms = self._raw_request(
                    self.host, self.port, self.use_ssl, req)
                resp_body = resp_str.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in resp_str else ''
                body_hash = hashlib.md5(resp_body.encode('utf-8', errors='replace')).hexdigest()
                ct = headers.get('content-type', '')
                # Count HTML structural tokens (rough tag count)
                tag_count = resp_body.count('<') if resp_body else 0
                samples.append({
                    'status': status,
                    'length': len(resp_body),
                    'elapsed_ms': elapsed_ms,
                    'body_hash': body_hash,
                    'content_type': ct,
                    'tag_count': tag_count,
                })
            except Exception:
                continue

        if not samples:
            self._baseline = {
                'status': 0, 'response_length': 0, 'elapsed_ms': 500.0,
                'body_hashes': set(), 'content_type': '', 'tag_count': 0,
                'length_min': 0, 'length_max': 0, 'stable_body': False,
            }
            return self._baseline

        lengths = [s['length'] for s in samples]
        timings = [s['elapsed_ms'] for s in samples]
        hashes = {s['body_hash'] for s in samples}
        statuses = [s['status'] for s in samples]
        tag_counts = [s['tag_count'] for s in samples]

        # Body is "stable" if all samples produced the same hash
        # (meaning the benign value doesn't affect response body)
        stable_body = len(hashes) == 1

        self._baseline = {
            'status': max(set(statuses), key=statuses.count),  # mode
            'response_length': int(sum(lengths) / len(lengths)),
            'elapsed_ms': sum(timings) / len(timings),
            'body_hashes': hashes,
            'content_type': samples[0]['content_type'],
            'tag_count': int(sum(tag_counts) / len(tag_counts)),
            'length_min': min(lengths),
            'length_max': max(lengths),
            'stable_body': stable_body,
        }
        return self._baseline

    @staticmethod
    def _compute_bypass_confidence(blocked: bool, reflected: bool,
                                   status: int, resp_length: int,
                                   elapsed_ms: float,
                                   baseline: Dict) -> int:
        """Compute a 0-100 bypass confidence score.

        Factors:
          - blocked flag (dominant: 0 if blocked)
          - status code match with baseline
          - response length similarity to baseline
          - payload reflection in response body
          - timing: WAF blocks are faster (negative delta = likely blocked)
        """
        if blocked:
            return 0

        score = 0.0

        # Status code (40 pts max)
        bl_status = baseline.get('status', 200)
        if status == bl_status:
            score += 40
        elif 200 <= status < 300:
            score += 30
        elif 300 <= status < 400:
            score += 15
        # 4xx/5xx with not-blocked is unusual but possible

        # Response length similarity (25 pts max)
        bl_len = baseline.get('response_length', 0)
        if bl_len > 0 and resp_length > 0:
            ratio = min(resp_length, bl_len) / max(resp_length, bl_len)
            score += 25 * ratio
        elif resp_length > 100:
            score += 10  # Some body present

        # Reflection (25 pts)
        if reflected:
            score += 25

        # Timing delta (10 pts max)
        # WAF blocks are typically faster (edge short-circuit).
        # If our response is slower or similar to baseline, it likely
        # passed through to origin → good sign.
        bl_time = baseline.get('elapsed_ms', 500.0)
        if bl_time > 0 and elapsed_ms > 0:
            delta = elapsed_ms - bl_time
            if delta >= 0:  # Same or slower than baseline → likely reached origin
                score += 10
            elif delta > -50:  # Slightly faster, inconclusive
                score += 5
            # Much faster than baseline → possible WAF fast-reject (0 pts)

        return max(0, min(100, int(round(score))))

    @staticmethod
    def _compute_fp_score(blocked: bool, reflected: bool,
                          status: int, resp_body: str,
                          elapsed_ms: float, baseline: Dict) -> Dict:
        """Compute false positive risk score for a finding.

        Returns:
            Dict with fp_score (0-100, higher = more likely FP),
            fp_reasons (list of flags explaining the score),
            and confidence_label ("confirmed", "likely", "possible", "noise").
        """
        if blocked:
            return {"fp_score": 0, "fp_reasons": [], "confidence_label": "confirmed_block"}

        import hashlib as _hl

        fp = 0.0
        reasons = []

        bl_status = baseline.get('status', 200)
        bl_len = baseline.get('response_length', 0)
        bl_time = baseline.get('elapsed_ms', 500.0)
        bl_hashes = baseline.get('body_hashes', set())
        bl_stable = baseline.get('stable_body', False)
        bl_tag_count = baseline.get('tag_count', 0)
        bl_len_min = baseline.get('length_min', 0)
        bl_len_max = baseline.get('length_max', 0)

        # 1. Generic error page masquerading as bypass (30 pts)
        body_lower = resp_body.lower() if resp_body else ""
        generic_error_sigs = [
            "page not found", "404 not found", "not found",
            "bad request", "400 bad request", "invalid request",
            "internal server error", "500 internal",
            "service unavailable", "502 bad gateway", "503 service",
            "default page", "welcome to nginx", "it works!",
            "apache2 default", "microsoft-iis",
        ]
        if any(sig in body_lower for sig in generic_error_sigs):
            fp += 30
            reasons.append("generic_error_page")

        # 2. Empty or near-empty response (20 pts)
        if len(resp_body) < 50:
            fp += 20
            reasons.append("empty_response")
        elif bl_len > 0 and len(resp_body) < bl_len * 0.1:
            fp += 15
            reasons.append("response_much_shorter_than_baseline")

        # 3. Status code mismatch with baseline (15 pts)
        if status != bl_status and status >= 400:
            fp += 15
            reasons.append(f"status_{status}_differs_from_baseline_{bl_status}")

        # 4. Body hash identity — response identical to a benign baseline (20 pts)
        #    If the body is stable (all benign probes got same hash) AND our payload
        #    response matches that hash, the param was ignored → likely FP.
        if bl_stable and bl_hashes and resp_body:
            resp_hash = _hl.md5(resp_body.encode('utf-8', errors='replace')).hexdigest()
            if resp_hash in bl_hashes:
                fp += 20
                reasons.append("body_identical_to_baseline_hash")
        elif bl_len > 100 and resp_body and abs(len(resp_body) - bl_len) < 10:
            # Fallback: length-based identity check
            fp += 15
            reasons.append("response_identical_to_baseline")

        # 5. Response length outside baseline range (10 pts)
        #    If body length is wildly different from any baseline sample,
        #    likely a different page (error, redirect, etc.)
        if bl_len_max > 0 and len(resp_body) > 0:
            margin = max(100, int(bl_len_max * 0.15))  # 15% tolerance
            if len(resp_body) < bl_len_min - margin or len(resp_body) > bl_len_max + margin:
                fp += 10
                reasons.append("response_length_outside_baseline_range")

        # 6. Structural divergence — HTML tag count differs significantly (10 pts)
        if bl_tag_count > 10 and resp_body:
            resp_tags = resp_body.count('<')
            tag_ratio = min(resp_tags, bl_tag_count) / max(resp_tags, bl_tag_count) if max(resp_tags, bl_tag_count) > 0 else 1.0
            if tag_ratio < 0.5:
                fp += 10
                reasons.append(f"structural_divergence_tags_{resp_tags}_vs_{bl_tag_count}")

        # 7. No reflection when payload should reflect (10 pts)
        if not reflected and status == 200 and bl_status == 200:
            fp += 10
            reasons.append("no_reflection")

        # 8. Suspiciously fast response (WAF fast-reject leaked through?) (10 pts)
        if bl_time > 0 and elapsed_ms > 0:
            if elapsed_ms < bl_time * 0.3:
                fp += 10
                reasons.append("suspiciously_fast_response")

        fp_score = max(0, min(100, int(round(fp))))

        if fp_score <= 15:
            label = "confirmed"
        elif fp_score <= 35:
            label = "likely"
        elif fp_score <= 60:
            label = "possible"
        else:
            label = "noise"

        return {
            "fp_score": fp_score,
            "fp_reasons": reasons,
            "confidence_label": label,
        }

    def test_payload(self, payload: str, method: str = 'GET', param: str = 'input',
                     content_type: str = None) -> Dict:
        """Test a single payload, following redirects up to max_redirects hops.

        Args:
            content_type: Override Content-Type for POST body (content-type confusion).
                          When set, method is forced to POST. Supported:
                          - 'application/json'
                          - 'multipart/form-data'
                          - 'text/xml' / 'application/xml'
                          - 'text/plain'
                          - Any custom value (payload sent as raw body)
        """
        # Content-type confusion forces POST
        if content_type:
            method = 'POST'

        max_redirects = self.max_redirects
        current_host = self.host
        current_port = self.port
        current_ssl = self.use_ssl
        current_path = self.path
        current_query = self.query
        extra_hdrs = self._build_extra_headers()
        redirect_chain = []  # Track full chain of URLs visited

        for hop in range(max_redirects + 1):
            try:
                enc = urllib.parse.quote(payload, safe='')

                stealth_hdrs = self._get_browser_headers()

                if method == 'GET' or hop > 0:
                    query_string = f"{current_query}&{param}={enc}" if current_query else f"{param}={enc}"
                    req = (f"GET {current_path}?{query_string} HTTP/1.1\r\n"
                           f"Host: {current_host}\r\n"
                           f"{stealth_hdrs}"
                           f"{extra_hdrs}"
                           f"Connection: close\r\n\r\n")
                else:
                    ct, body = self._build_post_body(payload, param, enc, content_type)
                    req = (f"POST {current_path} HTTP/1.1\r\n"
                           f"Host: {current_host}\r\n"
                           f"Content-Type: {ct}\r\n"
                           f"Content-Length: {len(body)}\r\n"
                           f"{stealth_hdrs}"
                           f"{extra_hdrs}"
                           f"Connection: close\r\n\r\n{body}")

                status, resp_str, headers, elapsed_ms = self._raw_request(
                    current_host, current_port, current_ssl, req)

                # Follow redirects
                if status in (301, 302, 303, 307, 308) and 'location' in headers:
                    location = headers['location']
                    # Record this hop in the chain
                    scheme = 'https' if current_ssl else 'http'
                    port_s = '' if (current_ssl and current_port == 443) or (not current_ssl and current_port == 80) else f':{current_port}'
                    chain_url = f"{scheme}://{current_host}{port_s}{current_path}"
                    redirect_chain.append({
                        'url': chain_url,
                        'status': status,
                        'location': location,
                    })
                    if location.startswith('/'):
                        current_path = location.split('?')[0]
                        current_query = location.split('?')[1] if '?' in location else ''
                    elif location.startswith('http'):
                        parsed = urllib.parse.urlparse(location)
                        redirect_host = parsed.hostname or current_host
                        # Block redirects to private/internal IPs (SSRF prevention)
                        if _is_private_host(redirect_host):
                            return {
                                'payload': payload,
                                'status': status,
                                'error': f'Redirect to private/internal host blocked: {redirect_host}',
                                'blocked': True,
                                'redirects': hop,
                                'redirect_chain': redirect_chain,
                                'timestamp': datetime.now().isoformat()
                            }
                        current_host = redirect_host
                        current_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                        current_ssl = parsed.scheme == 'https'
                        current_path = parsed.path or '/'
                        current_query = parsed.query or ''
                    continue  # Follow the redirect

                # Handle 429 rate-limiting with adaptive backoff
                if status == 429 and hop == 0:
                    self._consecutive_429s += 1
                    retry_after = headers.get('retry-after', '')
                    try:
                        base_wait = min(int(retry_after), 60) if retry_after.isdigit() else 5
                    except (ValueError, AttributeError):
                        base_wait = 5
                    # Exponential backoff: 5s, 10s, 20s, 40s (capped at 60s)
                    wait = min(base_wait * (2 ** (self._consecutive_429s - 1)), 60)
                    # Dynamically reduce rate limit to avoid future 429s
                    if self.rate_limit > 0:
                        self.rate_limit = max(0.5, self.rate_limit * 0.5)
                    elif self._consecutive_429s >= 2:
                        self.rate_limit = 1.0  # Auto-enable rate limiting
                    self._backoff_until = time.time() + wait
                    if not getattr(self, '_quiet_429', False):
                        sys.stderr.write(
                            f"  \033[33m429 rate-limited (×{self._consecutive_429s}), "
                            f"backing off {wait:.0f}s, rate→{self.rate_limit:.1f} req/s\033[0m\n")
                    time.sleep(wait)
                    continue  # Retry this hop
                elif status != 429:
                    self._consecutive_429s = 0  # Reset on success

                # Final response — determine if blocked
                error_code = None
                if 'error code:' in resp_str.lower():
                    error_match = re.search(r'error code:\s*(\d+)', resp_str, re.IGNORECASE)
                    if error_match:
                        error_code = error_match.group(1)

                blocked = status in (403, 406, 429, 500, 501, 503)

                # #220: Detect WAF-redirect blocks — WAFs often 302 to a
                # block/challenge page instead of returning 403 directly.
                # If we followed redirects and the final URL looks like a
                # known WAF block page path, mark as blocked.
                redirect_blocked = False
                if redirect_chain and not blocked:
                    final_path_lower = current_path.lower()
                    _WAF_BLOCK_PATHS = (
                        '/block', '/blocked', '/captcha', '/challenge',
                        '/access-denied', '/error', '/forbidden',
                        '/cdn-cgi/challenge', '/cdn-cgi/l/chk_jschl',
                        '/waf-block', '/security-check', '/bot-check',
                        '/firewall', '/request-blocked',
                    )
                    if any(bp in final_path_lower for bp in _WAF_BLOCK_PATHS):
                        blocked = True
                        redirect_blocked = True

                # Enhanced block detection: WAF body signatures
                # Modern WAFs and secure apps often return 200 with a block
                # page, challenge, CAPTCHA, or JSON error instead of 403.
                if not blocked and resp_str:
                    resp_lower = resp_str.lower()

                    # --- Vendor-specific block pages (even at 200) ---

                    # Cloudflare: challenge pages, turnstile, JS challenge
                    if any(sig in resp_lower for sig in (
                        'attention required', 'cf-error-details',
                        'cf-challenge-platform', 'cf-turnstile',
                        'just a moment', 'checking your browser',
                        'cf-chl-bypass', 'ray id:',
                    )):
                        blocked = True
                    # Akamai: block page with reference number
                    elif 'reference #' in resp_lower and ('akamai' in resp_lower or 'access denied' in resp_lower):
                        blocked = True
                    # Imperva / Incapsula: incident ID block
                    elif ('incident id' in resp_lower or 'support id' in resp_lower) and (
                        'incapsula' in resp_lower or 'imperva' in resp_lower
                    ):
                        blocked = True
                    # F5 BIG-IP: URL rejection
                    elif 'the requested url was rejected' in resp_lower:
                        blocked = True
                    # AWS WAF: request blocked by policy
                    elif 'request blocked' in resp_lower and (
                        'security policy' in resp_lower or 'aws' in resp_lower or 'waf' in resp_lower
                    ):
                        blocked = True
                    # ModSecurity
                    elif 'mod_security' in resp_lower or 'modsecurity' in resp_lower:
                        blocked = True
                    # Sucuri WAF
                    elif 'sucuri' in resp_lower and ('blocked' in resp_lower or 'firewall' in resp_lower):
                        blocked = True
                    # Barracuda WAF
                    elif 'barracuda' in resp_lower and 'blocked' in resp_lower:
                        blocked = True

                    # --- Generic soft-block indicators (any WAF / secure app) ---

                    elif 'web application firewall' in resp_lower:
                        blocked = True
                    elif 'access denied' in resp_lower and status in (200, 403, 406):
                        blocked = True
                    # CAPTCHA / challenge interstitials at 200
                    elif any(sig in resp_lower for sig in (
                        'captcha', 'recaptcha', 'hcaptcha',
                        'please verify you are human',
                        'bot detection', 'are you a robot',
                        'browser verification',
                    )):
                        blocked = True
                    # JSON error responses (REST APIs returning 200 with error body)
                    elif status == 200 and any(sig in resp_lower for sig in (
                        '"error":', '"blocked":', '"denied"',
                        '"status":"forbidden"', '"status":"denied"',
                        '"message":"forbidden"', '"message":"access denied"',
                        '"code":403', '"code":"403"',
                    )):
                        blocked = True
                    # Meta-refresh redirect to block/challenge page
                    elif 'meta http-equiv="refresh"' in resp_lower and (
                        'blocked' in resp_lower or 'denied' in resp_lower or 'challenge' in resp_lower
                    ):
                        blocked = True
                    # Forbidden / request denied in title or heading
                    elif status == 200 and any(sig in resp_lower for sig in (
                        '<title>403', '<title>forbidden',
                        '<title>access denied', '<title>blocked',
                        '<title>error', '<title>not acceptable',
                        '<h1>403', '<h1>forbidden', '<h1>access denied',
                        '<h1>blocked', '<h1>error</h1>',
                    )):
                        blocked = True
                    # Suspicious action / security violation
                    elif any(sig in resp_lower for sig in (
                        'suspicious activity', 'security violation',
                        'request has been blocked', 'this request was blocked',
                        'your request has been denied',
                        'automated request', 'bot detected',
                    )):
                        blocked = True

                # Extract response body for reflection analysis
                resp_body = ''
                if '\r\n\r\n' in resp_str:
                    resp_body = resp_str.split('\r\n\r\n', 1)[1]

                # Check if payload is reflected in response
                reflected = False
                reflection_context = ''
                if not blocked and resp_body:
                    # Check for raw payload reflection
                    if payload in resp_body:
                        reflected = True
                        idx = resp_body.index(payload)
                        start = max(0, idx - 40)
                        end = min(len(resp_body), idx + len(payload) + 40)
                        reflection_context = resp_body[start:end]
                    # Check for URL-decoded reflection
                    elif urllib.parse.unquote(payload) in resp_body:
                        reflected = True
                        decoded = urllib.parse.unquote(payload)
                        idx = resp_body.index(decoded)
                        start = max(0, idx - 40)
                        end = min(len(resp_body), idx + len(decoded) + 40)
                        reflection_context = resp_body[start:end]

                # Collect security headers
                sec_headers = {}
                for hdr_name in ('content-security-policy', 'x-xss-protection',
                                 'x-content-type-options', 'x-frame-options',
                                 'strict-transport-security', 'content-type',
                                 'server'):
                    if hdr_name in headers:
                        sec_headers[hdr_name] = headers[hdr_name]

                baseline = self._measure_baseline(param)
                confidence = self._compute_bypass_confidence(
                    blocked, reflected, status, len(resp_body),
                    elapsed_ms, baseline)
                fp_info = self._compute_fp_score(
                    blocked, reflected, status, resp_body,
                    elapsed_ms, baseline)

                return {
                    'payload': payload,
                    'status': status,
                    'error_code': error_code,
                    'blocked': blocked,
                    'redirect_blocked': redirect_blocked,
                    'redirects': hop,
                    'redirect_chain': redirect_chain,
                    'final_url': f"{'https' if current_ssl else 'http'}://{current_host}{current_path}",
                    'reflected': reflected,
                    'reflection_context': reflection_context[:200],
                    'response_length': len(resp_body),
                    'elapsed_ms': round(elapsed_ms, 1),
                    'bypass_confidence': confidence,
                    'fp_score': fp_info['fp_score'],
                    'fp_reasons': fp_info['fp_reasons'],
                    'confidence_label': fp_info['confidence_label'],
                    'security_headers': sec_headers,
                    'timestamp': datetime.now().isoformat()
                }

            except Exception as e:
                return {
                    'payload': payload,
                    'status': 0,
                    'error': str(e),
                    'blocked': True,
                    'bypass_confidence': 0,
                    'fp_score': 0,
                    'fp_reasons': [],
                    'confidence_label': 'error',
                    'elapsed_ms': 0,
                    'redirects': hop,
                    'redirect_chain': redirect_chain,
                    'timestamp': datetime.now().isoformat()
                }

        # Ran out of redirect hops
        return {
            'payload': payload,
            'status': 0,
            'error': f'Too many redirects ({max_redirects})',
            'blocked': True,
            'bypass_confidence': 0,
            'fp_score': 0,
            'fp_reasons': [],
            'confidence_label': 'error',
            'elapsed_ms': 0,
            'redirects': max_redirects,
            'redirect_chain': redirect_chain,
            'timestamp': datetime.now().isoformat()
        }
    
    def load_payloads(self, filepath: str) -> List[Dict]:
        """Load payloads from JSON or plain-text file.

        JSON: expects {"payloads": [...]} or a bare list.
        TXT:  one payload per line (blank lines and #comments are skipped).
        """
        if filepath.endswith('.txt'):
            payloads = []
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        payloads.append({'payload': stripped, 'category': 'custom', 'bypasses': []})
            return payloads

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'payloads' in data:
            return data['payloads']
        return data if isinstance(data, list) else []
    
    def probe_rate_limit(self, n_probes: int = 6, burst_delay: float = 0.1) -> Dict:
        """Proactively detect rate limiting before a full scan.

        Sends a quick burst of benign requests and watches for 429s.
        Returns dict with detected, threshold_rps, recommended_delay.
        """
        statuses = []
        t0 = time.monotonic()
        for i in range(n_probes):
            try:
                req = (f"GET {self.path}?_rl_probe={i} HTTP/1.1\r\n"
                       f"Host: {self.host}\r\n"
                       f"{self._get_browser_headers()}"
                       f"Connection: close\r\n\r\n")
                status, _, _, _ = self._raw_request(self.host, self.port, self.use_ssl, req)
                statuses.append(status)
            except Exception:
                statuses.append(0)
            if burst_delay > 0:
                time.sleep(burst_delay)
        elapsed = time.monotonic() - t0

        n_429 = statuses.count(429)
        n_ok = sum(1 for s in statuses if 200 <= s < 400)
        detected = n_429 > 0

        if detected and n_ok > 0:
            # Estimate threshold: how many OK before first 429
            first_429_idx = statuses.index(429)
            threshold_rps = max(1, first_429_idx) / max(0.1, elapsed * (first_429_idx / n_probes))
            rec_delay = max(0.5, 1.0 / threshold_rps * 1.5)  # 1.5× safety margin
        elif detected:
            threshold_rps = 1.0
            rec_delay = 2.0
        else:
            threshold_rps = n_probes / elapsed if elapsed > 0 else 10.0
            rec_delay = self.delay

        result = {
            "detected": detected,
            "threshold_rps": round(threshold_rps, 1),
            "recommended_delay": round(rec_delay, 2),
            "probes": n_probes,
            "ok": n_ok,
            "rate_limited": n_429,
        }

        if detected and not getattr(self, '_quiet_429', False):
            sys.stderr.write(
                f"  \033[33m⚡ Rate limit detected ({n_429}/{n_probes} probes → 429), "
                f"adjusting delay to {rec_delay:.1f}s\033[0m\n")
            # Auto-adjust delay
            if rec_delay > self.delay:
                self.delay = rec_delay
            if self.rate_limit == 0.0 or threshold_rps < self.rate_limit:
                self.rate_limit = max(0.5, threshold_rps * 0.6)

        return result

    def test_payloads(self, payloads: List[Dict], method: str = 'GET', param: str = 'input',
                     max_payloads: Optional[int] = None, quiet: bool = False,
                     smart_sort: bool = True, waf_vendor: str = '',
                     resume: bool = False) -> List[Dict]:
        """Test multiple payloads.

        Args:
            smart_sort:  If True, reorder payloads using the adaptive cache so
                         proven bypasses run first and known-blocked payloads
                         are deprioritised. Default: True.
            waf_vendor:  Detected WAF vendor — passed to smart_sort for future
                         cross-vendor filtering (Phase 2).
            resume:      If True, load checkpoint and skip already-tested payloads.
        """
        # ── Proactive rate limit detection (#192) ──
        if not quiet and len(payloads) >= 10:
            self.probe_rate_limit()

        # ── Adaptive sort: put proven bypasses first, known-blocked last ──
        if smart_sort:
            try:
                from fray.adaptive_cache import smart_sort_payloads
                payloads = smart_sort_payloads(payloads, domain=self.target,
                                               waf_vendor=waf_vendor)
            except Exception:
                pass  # Never break scans due to cache errors

        results = []
        total = min(len(payloads), max_payloads) if max_payloads else len(payloads)

        # ── Resume: load checkpoint and skip already-tested payloads ──
        tested_hashes: set = set()
        started_at = datetime.now().isoformat()
        if resume:
            try:
                from fray.checkpoint import (load_checkpoint, get_tested_set,
                                             _payload_hash as _cp_hash)
                cp = load_checkpoint(self.target)
                if cp:
                    tested_hashes = get_tested_set(cp)
                    results = cp.get('results', [])
                    started_at = cp.get('started_at', started_at)
                    n_skip = len(tested_hashes)
                    if not quiet:
                        sys.stderr.write(
                            f"  \033[36m↻ Resuming: {n_skip} payloads already tested, "
                            f"{total - n_skip} remaining\033[0m\n")
            except Exception:
                pass

        self.start_time = datetime.now()

        if quiet:
            # Silent mode for --json: no rich output
            for idx, payload_data in enumerate(payloads[:total], 1):
                payload = payload_data.get('payload', payload_data) if isinstance(payload_data, dict) else payload_data
                # Skip already-tested on resume
                if tested_hashes:
                    from fray.checkpoint import _payload_hash as _cp_hash
                    if _cp_hash(payload) in tested_hashes:
                        continue
                desc = payload_data.get('description', '') if isinstance(payload_data, dict) else ''
                category = payload_data.get('category', 'unknown') if isinstance(payload_data, dict) else 'unknown'
                result = self.test_payload(payload, method, param)
                result['category'] = category
                result['description'] = desc
                results.append(result)
                # Checkpoint after each payload
                if resume:
                    try:
                        from fray.checkpoint import save_checkpoint, _payload_hash as _cp_hash2
                        tested_hashes.add(_cp_hash2(payload))
                        save_checkpoint(self.target, method, param, waf_vendor,
                                        total, list(tested_hashes), results, started_at)
                    except Exception:
                        pass
                self._stealth_delay()

            # ── Filter noise via response diffing (#219) ──
            try:
                from fray.differ import ResponseDiffer
                _confirmed, _noise = ResponseDiffer().filter_noise(results, fp_threshold=60)
                for r in _noise:
                    r["filtered"] = "noise"
            except Exception:
                pass

            # ── Persist results to adaptive cache (async D1 share included) ──
            try:
                from fray.adaptive_cache import save_scan_results
                save_scan_results(results, domain=self.target, waf_vendor=waf_vendor)
            except Exception:
                pass
            # Clear checkpoint on successful completion
            if resume:
                try:
                    from fray.checkpoint import clear_checkpoint
                    clear_checkpoint(self.target)
                except Exception:
                    pass
            return results

        from fray.output import console, blocked_text, passed_text, make_progress

        console.print()
        console.rule(f"[bold]Testing {total} payloads against [cyan]{self.target}[/cyan][/bold]")
        console.print()

        skipped = 0
        with make_progress() as progress:
            task = progress.add_task("Testing", total=total)
            for idx, payload_data in enumerate(payloads[:total], 1):
                payload = payload_data.get('payload', payload_data) if isinstance(payload_data, dict) else payload_data
                # Skip already-tested on resume
                if tested_hashes:
                    from fray.checkpoint import _payload_hash as _cp_hash
                    if _cp_hash(payload) in tested_hashes:
                        progress.advance(task)
                        skipped += 1
                        continue
                desc = payload_data.get('description', '') if isinstance(payload_data, dict) else ''
                category = payload_data.get('category', 'unknown') if isinstance(payload_data, dict) else 'unknown'
                
                result = self.test_payload(payload, method, param)
                result['category'] = category
                result['description'] = desc
                results.append(result)
                
                # Print result with rich badge + confidence
                badge = blocked_text() if result['blocked'] else passed_text()
                label = desc[:40] if desc else payload[:40]
                conf = result.get('bypass_confidence', 0)
                ms = result.get('elapsed_ms', 0)
                if conf >= 75:
                    conf_style = f"[bold green]{conf:>3}%[/bold green]"
                elif conf >= 40:
                    conf_style = f"[yellow]{conf:>3}%[/yellow]"
                elif conf > 0:
                    conf_style = f"[dim]{conf:>3}%[/dim]"
                else:
                    conf_style = f"[dim red]  0%[/dim red]"
                # #220: Show redirect chain info when redirects occurred
                redir_info = ''
                if result.get('redirects', 0) > 0:
                    n_redir = result['redirects']
                    if result.get('redirect_blocked'):
                        redir_info = f' [dim red]→{n_redir} redirect(s) → block page[/dim red]'
                    else:
                        redir_info = f' [dim]→{n_redir} redirect(s)[/dim]'
                progress.console.print(
                    f"  [{idx:>{len(str(total))}}/{total}] ",
                    badge,
                    f" {result['status']} │ {conf_style} │ {ms:>6.0f}ms │ {label}{redir_info}",
                    highlight=False,
                )
                progress.advance(task)
                # Checkpoint after each payload
                if resume:
                    try:
                        from fray.checkpoint import save_checkpoint, _payload_hash as _cp_hash2
                        tested_hashes.add(_cp_hash2(payload))
                        save_checkpoint(self.target, method, param, waf_vendor,
                                        total, list(tested_hashes), results, started_at)
                    except Exception:
                        pass
                self._stealth_delay()

        # ── Filter noise via response diffing (#219) ──
        try:
            from fray.differ import ResponseDiffer
            _confirmed, _noise = ResponseDiffer().filter_noise(results, fp_threshold=60)
            for r in _noise:
                r["filtered"] = "noise"
        except Exception:
            pass

        # ── Persist results to adaptive cache (async D1 share included) ──
        try:
            from fray.adaptive_cache import save_scan_results
            save_scan_results(results, domain=self.target, waf_vendor=waf_vendor)
        except Exception:
            pass
        # Clear checkpoint on successful completion
        if resume:
            try:
                from fray.checkpoint import clear_checkpoint
                clear_checkpoint(self.target)
            except Exception:
                pass

        return results

    def generate_report(self, results: List[Dict], output: str = 'report.json', html: bool = False):
        """Generate test report"""
        total = len(results)
        blocked = sum(1 for r in results if r.get('blocked'))
        passed = total - blocked
        
        # Calculate duration
        duration = "N/A"
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            duration = f"{minutes} minutes {seconds} seconds" if minutes > 0 else f"{seconds} seconds"
        
        # Bypass confidence stats
        confidences = [r.get('bypass_confidence', 0) for r in results if not r.get('blocked')]
        avg_conf = round(sum(confidences) / len(confidences), 1) if confidences else 0
        high_conf = sum(1 for c in confidences if c >= 75)
        timings = [r.get('elapsed_ms', 0) for r in results if r.get('elapsed_ms', 0) > 0]
        avg_ms = round(sum(timings) / len(timings), 1) if timings else 0

        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'summary': {
                'total': total,
                'blocked': blocked,
                'passed': passed,
                'block_rate': f"{(blocked/total*100):.2f}%" if total > 0 else "0%",
                'avg_bypass_confidence': avg_conf,
                'high_confidence_bypasses': high_conf,
                'avg_response_ms': avg_ms,
            },
            'results': results
        }
        
        # Save JSON report
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report if requested
        if html:
            try:
                from report_generator import SecurityReportGenerator
                generator = SecurityReportGenerator()
                html_output = output.replace('.json', '.html')
                generator.generate_html_report(report, html_output)
                print(f"\n{Colors.GREEN}✅ HTML Report: {html_output}{Colors.END}")
            except Exception as e:
                print(f"\n{Colors.YELLOW}⚠️  HTML report generation failed: {e}{Colors.END}")
        
        # Print summary with rich
        from fray.output import console, make_summary_table
        from rich.panel import Panel
        from rich.text import Text

        tbl = make_summary_table()
        tbl.add_row("Target", self.target)
        tbl.add_row("Duration", duration)
        tbl.add_row("Total", str(total))
        tbl.add_row("Blocked", Text(str(blocked), style="bold red"))
        tbl.add_row("Passed", Text(str(passed), style="bold green"))
        tbl.add_row("Block Rate", Text(report['summary']['block_rate'], style="bold"))
        if high_conf > 0:
            tbl.add_row("High-Conf Bypasses", Text(str(high_conf), style="bold green"))
        tbl.add_row("Avg Bypass Conf", Text(f"{avg_conf}%", style="bold"))
        tbl.add_row("Avg Response", f"{avg_ms}ms")
        tbl.add_row("Report", output)

        console.print()
        console.print(Panel(tbl, title="[bold]Test Summary[/bold]", border_style="bright_cyan", expand=False))

        # ── Next Steps (actionable recommendations) ──
        console.print()
        console.print("  [bold]What This Means / Next Steps:[/bold]")
        if passed == 0:
            console.print(f"    → [bold]All {blocked} payloads blocked — WAF is actively filtering[/bold]")
            console.print(f"      Try bypass mode:     fray bypass {self.target} -c xss -m 50")
            console.print(f"      Try smart mode:      fray test {self.target} -c xss --smart --max 100")
            console.print(f"      Try mutation:         fray test {self.target} -c xss --mutate 20 -m 50")
            console.print(f"      Try different payloads: fray test {self.target} -c sqli -m 20")
            console.print(f"      Run recon:            fray recon {self.target}")
        elif blocked == 0:
            if avg_conf < 40:
                console.print(f"    → [bold]All {passed} payloads passed but avg confidence is low ({avg_conf}%)[/bold]")
                console.print(f"      This likely means no WAF is present, or the parameter is ignored")
                console.print(f"      Run scan to find real injection points: fray scan {self.target} -c xss")
                console.print(f"      Detect WAF:  fray detect {self.target}")
                console.print(f"      Run recon:   fray recon {self.target}")
            else:
                console.print(f"    → [bold]{passed} bypass(es) found — {high_conf} high-confidence[/bold]")
                console.print(f"      Run bypass scorer:    fray bypass {self.target} -c xss -m 30")
                console.print(f"      Export report:        fray report -i {output} --format html")
        else:
            bypass_rate = passed / total * 100
            if avg_conf >= 70:
                console.print(f"    → [bold]{passed} bypass(es) at {avg_conf}% avg confidence ({bypass_rate:.0f}% bypass rate)[/bold]")
                console.print(f"      Strong results — run bypass scorer: fray bypass {self.target} -c xss -m 50")
                console.print(f"      Export report: fray report -i {output} --format html")
            elif avg_conf >= 40:
                console.print(f"    → [bold]{passed} bypass(es) at {avg_conf}% avg confidence — needs verification[/bold]")
                console.print(f"      Amplify with mutations: fray test {self.target} -c xss --mutate 20")
                console.print(f"      Try bypass scorer:      fray bypass {self.target} -c xss -m 50")
            else:
                console.print(f"    → [bold]{passed} passed but low confidence ({avg_conf}%) — likely false positives[/bold]")
                console.print(f"      Find real injection points: fray scan {self.target} -c xss")
                console.print(f"      Run recon:                  fray recon {self.target}")
        console.print()

def interactive_mode():
    """Interactive mode for easy testing"""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}WAF Tester - Interactive Mode{Colors.END}")
    print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")
    
    # Get target
    target = input(f"{Colors.BLUE}Enter target URL (e.g., https://example.com): {Colors.END}").strip()
    if not target:
        print(f"{Colors.RED}Error: Target URL required{Colors.END}")
        return
    
    # Get payload category
    print(f"\n{Colors.BLUE}Available payload categories:{Colors.END}")
    print("1. XSS - Basic")
    print("2. XSS - SVG-based")
    print("3. XSS - Encoded")
    print("4. XSS - All")
    print("5. SQL Injection")
    print("6. SSRF")
    print("7. Custom payload file")
    
    choice = input(f"\n{Colors.BLUE}Select category (1-7): {Colors.END}").strip()
    
    payload_map = {
        '1': 'payloads/xss/basic.json',
        '2': 'payloads/xss/svg_based.json',
        '3': 'payloads/xss/encoded.json',
        '4': 'payloads/xss/',
        '5': 'payloads/sqli/general.json',
        '6': 'payloads/ssrf/general.json',
    }
    
    if choice == '7':
        payload_file = input(f"{Colors.BLUE}Enter payload file path: {Colors.END}").strip()
    elif choice in payload_map:
        payload_file = payload_map[choice]
    else:
        print(f"{Colors.RED}Invalid choice{Colors.END}")
        return
    
    # Get method
    method = input(f"\n{Colors.BLUE}HTTP method (GET/POST) [GET]: {Colors.END}").strip().upper() or 'GET'
    
    # Get max payloads
    max_input = input(f"{Colors.BLUE}Max payloads to test (blank for all): {Colors.END}").strip()
    max_payloads = int(max_input) if max_input else None
    
    # Run test
    tester = WAFTester(target)
    
    if Path(payload_file).is_dir():
        # Load all files in directory
        all_payloads = []
        for file in Path(payload_file).glob('*.json'):
            all_payloads.extend(tester.load_payloads(str(file)))
        payloads = all_payloads
    else:
        payloads = tester.load_payloads(payload_file)
    
    results = tester.test_payloads(payloads, method=method, max_payloads=max_payloads)
    tester.generate_report(results)

def main():
    parser = argparse.ArgumentParser(
        description='WAF Tester - Test Web Application Firewalls with comprehensive payload database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python waf_tester.py -i
  
  # Test single domain
  python waf_tester.py -t https://example.com -p payloads/xss/basic.json
  
  # Test specific endpoint/path
  python waf_tester.py -t https://example.com/api/search -p payloads/sqli/general.json
  
  # Test with POST method
  python waf_tester.py -t https://example.com/login -p payloads/sqli/general.json -m POST
  
  # Test multiple domains from file
  python waf_tester.py --targets-file targets.txt -p payloads/xss/ --html-report
  
  # Test with custom parameters
  python waf_tester.py -t https://api.example.com/v1/users -p payloads/ --param query --max 50
  
  # Generate HTML report
  python waf_tester.py -t https://example.com -p payloads/xss/basic.json --html-report
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL to test (supports full URLs with paths/endpoints)')
    parser.add_argument('--targets-file', help='File containing list of target URLs (one per line)')
    parser.add_argument('-p', '--payloads', help='Path to payload JSON file or directory')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--param', default='input', help='Parameter name (default: input)')
    parser.add_argument('--max', type=int, help='Maximum number of payloads to test')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (seconds)')
    parser.add_argument('-o', '--output', default='report.json', help='Output report file')
    parser.add_argument('--html-report', action='store_true', help='Generate HTML report with Dali Security branding')
    parser.add_argument('--detect-waf', action='store_true', help='Detect WAF vendor before testing')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
        return
    
    # Get list of targets
    targets = []
    if args.targets_file:
        # Load targets from file
        try:
            with open(args.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            print(f"\n{Colors.BLUE}Loaded {len(targets)} targets from {args.targets_file}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Error loading targets file: {e}{Colors.END}\n")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        print(f"\n{Colors.YELLOW}Tip: Use -i for interactive mode{Colors.END}\n")
        sys.exit(1)
    
    if not args.payloads:
        parser.print_help()
        print(f"\n{Colors.RED}Error: --payloads is required{Colors.END}\n")
        sys.exit(1)
    
    # Test each target
    all_results = []
    for idx, target in enumerate(targets, 1):
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Testing Target {idx}/{len(targets)}: {target}{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        # Detect WAF if requested
        waf_info = None
        if args.detect_waf and WAF_DETECTOR_AVAILABLE:
            print(f"\n{Colors.BLUE}🔍 Detecting WAF...{Colors.END}")
            detector = WAFDetector()
            waf_info = detector.detect_waf(target, timeout=args.timeout)
            
            if waf_info['waf_detected']:
                print(f"{Colors.GREEN}✓ WAF Detected: {waf_info['waf_vendor']} ({waf_info['confidence']}% confidence){Colors.END}")
            else:
                print(f"{Colors.YELLOW}✗ No WAF detected or unknown WAF{Colors.END}")
        elif args.detect_waf and not WAF_DETECTOR_AVAILABLE:
            print(f"{Colors.YELLOW}⚠️  WAF detection not available (waf_detector.py not found){Colors.END}")
        
        # Run test
        tester = WAFTester(target, timeout=args.timeout, delay=args.delay)
        
        # Load payloads
        payload_path = Path(args.payloads)
        if payload_path.is_dir():
            all_payloads = []
            for file in payload_path.glob('*.json'):
                all_payloads.extend(tester.load_payloads(str(file)))
            payloads = all_payloads
        else:
            payloads = tester.load_payloads(args.payloads)
        
        # Test payloads
        results = tester.test_payloads(payloads, method=args.method, param=args.param, max_payloads=args.max)
        
        # Generate report for this target
        if len(targets) > 1:
            # Multiple targets - create separate reports
            output_name = args.output.replace('.json', f'_{idx}.json')
            tester.generate_report(results, output=output_name, html=args.html_report)
            all_results.append({'target': target, 'results': results})
        else:
            # Single target - use specified output name
            tester.generate_report(results, output=args.output, html=args.html_report)
    
    # Generate combined report for multiple targets
    if len(targets) > 1:
        combined_output = args.output.replace('.json', '_combined.json')
        combined_report = {
            'targets': targets,
            'timestamp': datetime.now().isoformat(),
            'total_targets': len(targets),
            'results_by_target': all_results
        }
        with open(combined_output, 'w', encoding='utf-8') as f:
            json.dump(combined_report, f, indent=2, ensure_ascii=False)
        print(f"\n{Colors.GREEN}✅ Combined report saved to: {combined_output}{Colors.END}")

if __name__ == '__main__':
    main()
