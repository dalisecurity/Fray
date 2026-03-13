#!/usr/bin/env python3
"""
Fray — WAF Rule Reverse Engineering (#149)

Systematically probes a WAF to map its detection rules:
  1. Tag probing     — which HTML tags are blocked (<script>, <img>, <svg>, ...)
  2. Event probing   — which event handlers are blocked (onerror, onload, ...)
  3. Keyword probing — which JS keywords are blocked (alert, eval, fetch, ...)
  4. Encoding probing — which encodings bypass rules (hex, unicode, mixed-case)
  5. Context probing  — where rules apply (query, body, headers, path)
  6. Threshold probing — payload length limits, parameter count limits

Output: WAFProfile JSON with all blocked/allowed items per category.

CLI:
    fray waf-reverse https://example.com
    fray waf-reverse https://example.com --json
    fray waf-reverse https://example.com -o profile.json
"""

import http.client
import json
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"


# ── Probe sets ───────────────────────────────────────────────────────────────

_TAGS = [
    "script", "img", "svg", "iframe", "object", "embed", "video", "audio",
    "body", "input", "form", "a", "div", "span", "style", "link", "meta",
    "base", "details", "marquee", "math", "table", "textarea", "select",
    "button", "xss", "isindex", "keygen", "source", "track",
]

_EVENTS = [
    "onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur",
    "onsubmit", "onchange", "oninput", "onkeypress", "onkeydown", "onkeyup",
    "onmouseenter", "onmouseleave", "oncontextmenu", "ondblclick",
    "onanimationend", "ontransitionend", "onpointerover", "ontouchstart",
    "onbeforeinput", "onformdata", "onscroll", "onwheel", "onresize",
    "onpaste", "oncopy", "ondrag", "ondrop", "onhashchange", "onpopstate",
    "onsearch", "ontoggle", "onafterprint",
]

_KEYWORDS = [
    "alert", "confirm", "prompt", "eval", "Function", "constructor",
    "setTimeout", "setInterval", "fetch", "XMLHttpRequest",
    "document.cookie", "document.domain", "document.write",
    "window.location", "location.href", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "srcdoc", "javascript:", "data:",
    "import(", "require(", "child_process", "execSync",
    "__proto__", "constructor.prototype", "String.fromCharCode",
    "atob", "btoa", "decodeURI", "encodeURI",
]

_ENCODINGS = {
    "plain": lambda s: s,
    "hex_lower": lambda s: "".join(f"\\x{ord(c):02x}" for c in s),
    "hex_upper": lambda s: "".join(f"\\x{ord(c):02X}" for c in s),
    "unicode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "html_dec": lambda s: "".join(f"&#{ord(c)};" for c in s),
    "html_hex": lambda s: "".join(f"&#x{ord(c):x};" for c in s),
    "url_encode": lambda s: urllib.parse.quote(s, safe=""),
    "double_url": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    "mixed_case": lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
    "null_byte": lambda s: "%00".join(s),
    "tab_insert": lambda s: "%09".join(s) if len(s) > 1 else s,
    "newline_insert": lambda s: "%0a".join(s) if len(s) > 1 else s,
}

_CONTEXTS = [
    ("query", "GET parameter"),
    ("body", "POST body"),
    ("path", "URL path"),
    ("header_referer", "Referer header"),
    ("header_ua", "User-Agent header"),
]


@dataclass
class WAFProfile:
    """Complete WAF rule profile from reverse engineering."""
    target: str
    waf_vendor: str = ""
    blocked_tags: List[str] = field(default_factory=list)
    allowed_tags: List[str] = field(default_factory=list)
    blocked_events: List[str] = field(default_factory=list)
    allowed_events: List[str] = field(default_factory=list)
    blocked_keywords: List[str] = field(default_factory=list)
    allowed_keywords: List[str] = field(default_factory=list)
    encoding_bypasses: Dict[str, List[str]] = field(default_factory=dict)
    context_enforcement: Dict[str, bool] = field(default_factory=dict)
    total_probes: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "waf_vendor": self.waf_vendor,
            "blocked_tags": self.blocked_tags,
            "allowed_tags": self.allowed_tags,
            "blocked_events": self.blocked_events,
            "allowed_events": self.allowed_events,
            "blocked_keywords": self.blocked_keywords,
            "allowed_keywords": self.allowed_keywords,
            "encoding_bypasses": self.encoding_bypasses,
            "context_enforcement": self.context_enforcement,
            "total_probes": self.total_probes,
            "duration_s": round(self.duration_s, 2),
            "summary": {
                "tags": f"{len(self.blocked_tags)} blocked / {len(self.allowed_tags)} allowed",
                "events": f"{len(self.blocked_events)} blocked / {len(self.allowed_events)} allowed",
                "keywords": f"{len(self.blocked_keywords)} blocked / {len(self.allowed_keywords)} allowed",
                "bypass_encodings": list(self.encoding_bypasses.keys()),
            },
        }


# ── HTTP probe helper ────────────────────────────────────────────────────────

def _probe(url: str, payload: str, context: str = "query",
           timeout: int = 8, delay: float = 0.1) -> Tuple[bool, int]:
    """Send a probe and return (blocked, status_code).

    blocked = True if WAF intercepted (403, 406, 429, 503 with WAF body, etc.)
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    use_ssl = parsed.scheme == "https"
    base_path = parsed.path or "/"

    if not port:
        port = 443 if use_ssl else 80

    hdrs = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,*/*",
        "Connection": "close",
    }

    method = "GET"
    body = None
    path = base_path

    enc_payload = urllib.parse.quote(payload, safe="")

    if context == "query":
        path = f"{base_path}?fray={enc_payload}"
    elif context == "body":
        method = "POST"
        body = f"fray={enc_payload}"
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs["Content-Length"] = str(len(body))
    elif context == "path":
        path = f"{base_path}/{enc_payload}"
    elif context == "header_referer":
        hdrs["Referer"] = f"https://example.com/{payload}"
    elif context == "header_ua":
        hdrs["User-Agent"] = payload

    if delay > 0:
        time.sleep(delay)

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request(method, path, body=body.encode("utf-8") if body else None, headers=hdrs)
        resp = conn.getresponse()
        status = resp.status
        resp_body = resp.read(8192).decode("utf-8", "replace").lower()
        conn.close()

        # Detect WAF block
        blocked = False
        if status in (403, 406, 429, 503):
            blocked = True
        elif status >= 400:
            waf_sigs = ["blocked", "forbidden", "access denied", "waf", "firewall",
                        "security", "captcha", "challenge", "rate limit", "not acceptable"]
            if any(sig in resp_body for sig in waf_sigs):
                blocked = True

        return blocked, status
    except Exception:
        return False, 0


# ── Main reverse engineering routine ─────────────────────────────────────────

def reverse_engineer_waf(
    target: str,
    timeout: int = 8,
    delay: float = 0.15,
    skip_encodings: bool = False,
    skip_contexts: bool = False,
) -> WAFProfile:
    """Reverse engineer WAF rules for a target.

    Args:
        target:          Target URL.
        timeout:         HTTP timeout per probe.
        delay:           Delay between probes (be polite).
        skip_encodings:  Skip encoding bypass probing.
        skip_contexts:   Skip context enforcement probing.

    Returns:
        WAFProfile with all findings.
    """
    t0 = time.time()
    profile = WAFProfile(target=target)
    probes = 0

    # Detect WAF vendor
    try:
        from fray.tester import WAFTester
        tester = WAFTester(target, timeout=timeout)
        waf = tester.detect_waf()
        profile.waf_vendor = waf.get("waf_vendor", "") if isinstance(waf, dict) else ""
    except Exception:
        profile.waf_vendor = ""

    # Phase 1: Tag probing
    for tag in _TAGS:
        payload = f"<{tag}>"
        blocked, _ = _probe(target, payload, timeout=timeout, delay=delay)
        probes += 1
        if blocked:
            profile.blocked_tags.append(tag)
        else:
            profile.allowed_tags.append(tag)

    # Phase 2: Event probing
    for event in _EVENTS:
        payload = f"<img {event}=1>"
        blocked, _ = _probe(target, payload, timeout=timeout, delay=delay)
        probes += 1
        if blocked:
            profile.blocked_events.append(event)
        else:
            profile.allowed_events.append(event)

    # Phase 3: Keyword probing
    for kw in _KEYWORDS:
        blocked, _ = _probe(target, kw, timeout=timeout, delay=delay)
        probes += 1
        if blocked:
            profile.blocked_keywords.append(kw)
        else:
            profile.allowed_keywords.append(kw)

    # Phase 4: Encoding bypass probing (test blocked items with encodings)
    if not skip_encodings and profile.blocked_keywords:
        test_kw = profile.blocked_keywords[:3]  # Test top 3 blocked keywords
        for enc_name, enc_fn in _ENCODINGS.items():
            if enc_name == "plain":
                continue
            bypasses = []
            for kw in test_kw:
                try:
                    encoded = enc_fn(kw)
                except Exception:
                    continue
                blocked, _ = _probe(target, encoded, timeout=timeout, delay=delay)
                probes += 1
                if not blocked:
                    bypasses.append(kw)
            if bypasses:
                profile.encoding_bypasses[enc_name] = bypasses

    # Phase 5: Context enforcement
    if not skip_contexts:
        test_payload = "<script>alert(1)</script>"
        for ctx, desc in _CONTEXTS:
            blocked, _ = _probe(target, test_payload, context=ctx,
                                timeout=timeout, delay=delay)
            probes += 1
            profile.context_enforcement[ctx] = blocked

    profile.total_probes = probes
    profile.duration_s = time.time() - t0
    return profile


# ── CLI-friendly output ──────────────────────────────────────────────────────

def print_waf_profile(profile: WAFProfile):
    """Pretty-print WAF rule profile."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}WAF Rule Reverse Engineering{R}")
    print(f"  {D}{profile.target}{R}")
    if profile.waf_vendor:
        print(f"  {CYN}WAF: {profile.waf_vendor}{R}")
    print(f"  {D}Probes: {profile.total_probes} | Duration: {profile.duration_s:.1f}s{R}")
    print(f"{D}{'━' * 60}{R}")

    # Tags
    print(f"\n  {B}HTML Tags{R}")
    print(f"    {RED}Blocked ({len(profile.blocked_tags)}):{R} {', '.join(profile.blocked_tags[:15])}")
    if len(profile.blocked_tags) > 15:
        print(f"    {D}  ... and {len(profile.blocked_tags) - 15} more{R}")
    print(f"    {GRN}Allowed ({len(profile.allowed_tags)}):{R} {', '.join(profile.allowed_tags[:15])}")

    # Events
    print(f"\n  {B}Event Handlers{R}")
    print(f"    {RED}Blocked ({len(profile.blocked_events)}):{R} {', '.join(profile.blocked_events[:10])}")
    if len(profile.blocked_events) > 10:
        print(f"    {D}  ... and {len(profile.blocked_events) - 10} more{R}")
    print(f"    {GRN}Allowed ({len(profile.allowed_events)}):{R} {', '.join(profile.allowed_events[:10])}")

    # Keywords
    print(f"\n  {B}Keywords{R}")
    print(f"    {RED}Blocked ({len(profile.blocked_keywords)}):{R} {', '.join(profile.blocked_keywords[:10])}")
    print(f"    {GRN}Allowed ({len(profile.allowed_keywords)}):{R} {', '.join(profile.allowed_keywords[:10])}")

    # Encoding bypasses
    if profile.encoding_bypasses:
        print(f"\n  {YEL}{B}Encoding Bypasses Found!{R}")
        for enc, kws in profile.encoding_bypasses.items():
            print(f"    {YEL}●{R} {enc}: bypasses {', '.join(kws)}")
    else:
        print(f"\n  {D}No encoding bypasses found{R}")

    # Context enforcement
    if profile.context_enforcement:
        print(f"\n  {B}Context Enforcement{R}")
        for ctx, blocked in profile.context_enforcement.items():
            status = f"{RED}Blocked{R}" if blocked else f"{GRN}Not enforced{R}"
            print(f"    {ctx}: {status}")

    # Summary
    total_blocked = len(profile.blocked_tags) + len(profile.blocked_events) + len(profile.blocked_keywords)
    total_allowed = len(profile.allowed_tags) + len(profile.allowed_events) + len(profile.allowed_keywords)
    if total_blocked + total_allowed > 0:
        block_pct = total_blocked / (total_blocked + total_allowed) * 100
        print(f"\n  {B}Overall:{R} {block_pct:.0f}% of probes blocked ({total_blocked}/{total_blocked + total_allowed})")

    print(f"\n{D}{'━' * 60}{R}\n")
