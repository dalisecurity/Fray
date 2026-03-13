#!/usr/bin/env python3
"""
Fray — Client-Side Prototype Pollution Verification (#29)

Detects and verifies prototype pollution vulnerabilities via:
  1. Source analysis — scan JS for vulnerable sinks (merge, extend, clone, assign)
  2. Query-string probing — inject __proto__[fray_pp]=1 and check if it lands
  3. JSON body probing — POST {"__proto__": {"fray_pp": 1}} variants
  4. Gadget detection — check known gadgets (lodash, jQuery, ejs, pug, etc.)

Usage (programmatic):
    from fray.proto_pollution import scan_prototype_pollution
    results = scan_prototype_pollution("https://example.com", timeout=8)

CLI:
    fray test <url> -c prototype_pollution
"""

import http.client
import json
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Known vulnerable sinks ──────────────────────────────────────────────────

_VULNERABLE_SINKS = [
    # Pattern, description, severity
    (r"Object\.assign\s*\(", "Object.assign with user input", "medium"),
    (r"_\.merge\s*\(", "lodash _.merge (CVE-2018-16487)", "high"),
    (r"_\.defaultsDeep\s*\(", "lodash _.defaultsDeep (CVE-2019-10744)", "critical"),
    (r"_\.set\s*\(", "lodash _.set with user-controlled path", "high"),
    (r"_\.setWith\s*\(", "lodash _.setWith with user-controlled path", "high"),
    (r"\$\.extend\s*\(\s*true", "jQuery deep $.extend", "high"),
    (r"jQuery\.extend\s*\(\s*true", "jQuery deep extend", "high"),
    (r"\.extend\s*\(\s*true\s*,\s*\{", "Generic deep extend", "medium"),
    (r"JSON\.parse\s*\(", "JSON.parse of user input (potential sink)", "low"),
    (r"qs\.parse\s*\(", "qs.parse without prototype filtering", "medium"),
    (r"merge\s*\(\s*\{", "Custom merge function", "medium"),
    (r"deepMerge\s*\(", "Deep merge utility", "medium"),
    (r"deepExtend\s*\(", "Deep extend utility", "medium"),
    (r"defaultsDeep\s*\(", "defaultsDeep utility", "high"),
    (r"hoek\.merge\s*\(", "hoek.merge (CVE-2018-3728)", "critical"),
    (r"hoek\.applyToDefaults\s*\(", "hoek.applyToDefaults", "high"),
    (r"deap\.merge\s*\(", "deap.merge vulnerability", "high"),
    (r"deepmerge\s*\(", "deepmerge library", "medium"),
    (r"flat\s*\(", "flat() unflatten with __proto__", "medium"),
    (r"unflatten\s*\(", "unflatten with __proto__ keys", "high"),
]

# Known gadgets: library pattern → exploitation details
_KNOWN_GADGETS = {
    "lodash": {
        "pattern": r"lodash(?:\.min)?\.js|_\.(VERSION|templateSettings)",
        "cves": ["CVE-2018-16487", "CVE-2019-10744", "CVE-2020-8203"],
        "impact": "RCE via template injection or DoS",
        "sink": "__proto__[sourceURL]",
        "severity": "critical",
    },
    "jquery": {
        "pattern": r"jquery(?:\.min)?\.js|jQuery\.fn\.jquery",
        "cves": ["CVE-2019-11358"],
        "impact": "XSS via DOM manipulation gadgets",
        "sink": "__proto__[innerHTML]",
        "severity": "high",
    },
    "ejs": {
        "pattern": r"ejs(?:\.min)?\.js|\.render\s*\(",
        "cves": ["CVE-2022-29078"],
        "impact": "RCE via outputFunctionName pollution",
        "sink": "__proto__[outputFunctionName]",
        "severity": "critical",
    },
    "pug": {
        "pattern": r"pug(?:\.min)?\.js|jade(?:\.min)?\.js",
        "cves": [],
        "impact": "RCE via compileDebug + self pollution",
        "sink": "__proto__[compileDebug]",
        "severity": "critical",
    },
    "handlebars": {
        "pattern": r"handlebars(?:\.min)?\.js|Handlebars\.compile",
        "cves": ["CVE-2019-19919", "CVE-2021-23369"],
        "impact": "RCE via constructor prototype",
        "sink": "constructor.prototype",
        "severity": "critical",
    },
    "vue": {
        "pattern": r"vue(?:\.min)?\.js|Vue\.version",
        "cves": [],
        "impact": "XSS via template compilation gadgets",
        "sink": "__proto__[v-bind:class]",
        "severity": "high",
    },
    "express": {
        "pattern": r"express|X-Powered-By:\s*Express",
        "cves": [],
        "impact": "Status code override, header injection",
        "sink": "__proto__[status]",
        "severity": "medium",
    },
}

# Canary property for verification
_CANARY = "fray_pp_" + str(int(time.time()) % 10000)


@dataclass
class PPFinding:
    """A single prototype pollution finding."""
    url: str
    vector: str          # "query_string", "json_body", "source_sink", "gadget"
    payload: str
    description: str
    severity: str        # critical, high, medium, low
    verified: bool       # True if pollution was confirmed in response
    gadget: str = ""     # Library name if gadget-based
    cves: List[str] = field(default_factory=list)
    evidence: str = ""   # Response snippet showing pollution

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "vector": self.vector,
            "payload": self.payload,
            "description": self.description,
            "severity": self.severity,
            "verified": self.verified,
        }
        if self.gadget:
            d["gadget"] = self.gadget
        if self.cves:
            d["cves"] = self.cves
        if self.evidence:
            d["evidence"] = self.evidence[:500]
        return d


@dataclass
class PPResult:
    """Aggregate result of prototype pollution scan."""
    target: str
    findings: List[PPFinding] = field(default_factory=list)
    sinks_found: List[Dict] = field(default_factory=list)
    gadgets_found: List[Dict] = field(default_factory=list)
    total_probes: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "sinks_found": self.sinks_found,
            "gadgets_found": self.gadgets_found,
            "total_probes": self.total_probes,
            "duration_s": round(self.duration_s, 2),
            "vulnerable": any(f.verified for f in self.findings),
            "max_severity": _max_severity([f.severity for f in self.findings]),
        }


class PPScanner:
    """Wrapper class for prototype pollution scanning (compatible with _run_module interface)."""

    def __init__(self, target: str, timeout: int = 8, verify_ssl: bool = True, **kwargs):
        self.target = target
        self.timeout = timeout

    def scan(self) -> PPResult:
        return scan_prototype_pollution(self.target, timeout=self.timeout)


def _max_severity(sevs: List[str]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not sevs:
        return "none"
    return max(sevs, key=lambda s: order.get(s, 0))


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def _request(url: str, method: str = "GET", body: Optional[str] = None,
             headers: Optional[Dict] = None, timeout: int = 8
             ) -> Tuple[int, str, Dict[str, str]]:
    """Minimal HTTP request, returns (status, body, headers)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if not port:
        port = 443 if use_ssl else 80

    hdrs = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (compatible; FrayPP/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    if body and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/json"
    if body:
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))

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
        resp_body = resp.read(64 * 1024).decode("utf-8", "replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, resp_body, resp_headers
    except Exception:
        return 0, "", {}


# ── Phase 1: Source Analysis ─────────────────────────────────────────────────

def _analyze_js_sources(url: str, timeout: int = 8) -> Tuple[List[Dict], List[Dict]]:
    """Fetch page + linked JS, scan for vulnerable sinks and known gadgets."""
    sinks = []
    gadgets = []

    status, body, hdrs = _request(url, timeout=timeout)
    if status == 0:
        return sinks, gadgets

    # Check main page
    _scan_body_for_sinks(body, url, sinks)
    _scan_body_for_gadgets(body, url, gadgets)

    # Extract <script src="..."> links
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
    parsed_base = urllib.parse.urlparse(url)

    for src in script_srcs[:10]:  # Limit to 10 JS files
        js_url = urllib.parse.urljoin(url, src)
        js_parsed = urllib.parse.urlparse(js_url)
        # Only same-origin or CDN
        if js_parsed.hostname and js_parsed.hostname != parsed_base.hostname:
            if not any(cdn in js_parsed.hostname for cdn in
                       ("cdn", "jsdelivr", "unpkg", "cloudflare", "jquery", "googleapis")):
                continue

        _, js_body, _ = _request(js_url, timeout=timeout)
        if js_body:
            _scan_body_for_sinks(js_body, js_url, sinks)
            _scan_body_for_gadgets(js_body, js_url, gadgets)

    return sinks, gadgets


def _scan_body_for_sinks(body: str, source_url: str, sinks: List[Dict]):
    """Scan a JS/HTML body for vulnerable sinks."""
    for pattern, desc, sev in _VULNERABLE_SINKS:
        matches = re.findall(pattern, body)
        if matches:
            sinks.append({
                "source": source_url,
                "pattern": desc,
                "severity": sev,
                "count": len(matches),
            })


def _scan_body_for_gadgets(body: str, source_url: str, gadgets: List[Dict]):
    """Scan for known vulnerable library gadgets."""
    for lib_name, info in _KNOWN_GADGETS.items():
        if re.search(info["pattern"], body, re.I):
            gadgets.append({
                "library": lib_name,
                "source": source_url,
                "cves": info["cves"],
                "impact": info["impact"],
                "sink": info["sink"],
                "severity": info["severity"],
            })


# ── Phase 2: Query-String Probing ────────────────────────────────────────────

_QS_PROBES = [
    # (query suffix, description)
    (f"__proto__[{_CANARY}]=1", "Basic __proto__ bracket notation"),
    (f"__proto__.{_CANARY}=1", "Dot notation __proto__"),
    (f"constructor[prototype][{_CANARY}]=1", "constructor.prototype bracket"),
    (f"constructor.prototype.{_CANARY}=1", "constructor.prototype dot"),
    (f"__proto__[isAdmin]=true", "Privilege escalation probe"),
    (f"__proto__[innerHTML]=<img/src/onerror=alert(1)>", "DOM XSS gadget probe"),
    (f"__proto__[sourceURL]=%0aalert(1)//", "lodash sourceURL XSS probe"),
]


def _probe_query_string(url: str, timeout: int = 8) -> List[PPFinding]:
    """Probe for prototype pollution via query string parameters."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    for probe_qs, desc in _QS_PROBES:
        sep = "&" if parsed.query else "?"
        probe_url = f"{base}{sep}{probe_qs}" if not parsed.query else f"{base}?{parsed.query}&{probe_qs}"

        status, body, hdrs = _request(probe_url, timeout=timeout)
        if status == 0:
            continue

        # Check if our canary appears in response (verification)
        verified = _CANARY in body
        # Also check for common pollution indicators
        pollution_indicators = [
            _CANARY in body,
            '"polluted"' in body,
            '"isAdmin":true' in body.lower(),
            '"isadmin": true' in body.lower(),
        ]

        if any(pollution_indicators) or (status == 200 and "__proto__" not in body):
            # Only report as finding if canary verified or if known-dangerous probe
            if verified or "isAdmin" in probe_qs or "innerHTML" in probe_qs:
                evidence = ""
                if verified:
                    idx = body.find(_CANARY)
                    start = max(0, idx - 50)
                    end = min(len(body), idx + len(_CANARY) + 50)
                    evidence = body[start:end]

                findings.append(PPFinding(
                    url=probe_url,
                    vector="query_string",
                    payload=probe_qs,
                    description=desc,
                    severity="high" if verified else "medium",
                    verified=verified,
                    evidence=evidence,
                ))

    return findings


# ── Phase 3: JSON Body Probing ───────────────────────────────────────────────

_JSON_PROBES = [
    ({"__proto__": {_CANARY: "1"}}, "JSON __proto__ pollution"),
    ({"constructor": {"prototype": {_CANARY: "1"}}}, "JSON constructor.prototype"),
    ({"__proto__": {"isAdmin": True}}, "Privilege escalation via JSON body"),
    ({"__proto__": {"role": "admin"}}, "Role escalation via JSON body"),
    ({"__proto__": {"outputFunctionName": f"x;throw new Error('{_CANARY}')//"}},
     "EJS RCE probe via outputFunctionName"),
]


def _probe_json_body(url: str, timeout: int = 8) -> List[PPFinding]:
    """Probe for prototype pollution via JSON POST body."""
    findings = []

    for payload_obj, desc in _JSON_PROBES:
        payload_str = json.dumps(payload_obj)
        status, body, hdrs = _request(url, method="POST", body=payload_str, timeout=timeout)
        if status == 0:
            continue

        verified = _CANARY in body
        evidence = ""
        if verified:
            idx = body.find(_CANARY)
            start = max(0, idx - 50)
            end = min(len(body), idx + len(_CANARY) + 50)
            evidence = body[start:end]

        if verified:
            findings.append(PPFinding(
                url=url,
                vector="json_body",
                payload=payload_str,
                description=desc,
                severity="critical" if "outputFunctionName" in desc else "high",
                verified=True,
                evidence=evidence,
            ))

    return findings


# ── Phase 4: Gadget-based verification ───────────────────────────────────────

def _verify_gadgets(url: str, gadgets: List[Dict], timeout: int = 8) -> List[PPFinding]:
    """For each detected gadget, try the specific exploitation sink."""
    findings = []

    for g in gadgets:
        lib = g["library"]
        sink = g.get("sink", "")
        if not sink:
            continue

        # Build probe from sink
        if "sourceURL" in sink:
            probe = f"__proto__[sourceURL]=%0a{_CANARY}//"
        elif "innerHTML" in sink:
            probe = f"__proto__[innerHTML]={_CANARY}"
        elif "outputFunctionName" in sink:
            probe = f"__proto__[outputFunctionName]=x;{_CANARY}//x"
        elif "compileDebug" in sink:
            probe = f"__proto__[compileDebug]=true&__proto__[self]=1"
        else:
            # Generic probe using the sink name
            key = sink.split("[")[-1].rstrip("]") if "[" in sink else sink.split(".")[-1]
            probe = f"__proto__[{key}]={_CANARY}"

        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        probe_url = f"{base}?{probe}"

        status, body, _ = _request(probe_url, timeout=timeout)
        if status == 0:
            continue

        verified = _CANARY in body
        evidence = ""
        if verified:
            idx = body.find(_CANARY)
            start = max(0, idx - 50)
            end = min(len(body), idx + len(_CANARY) + 50)
            evidence = body[start:end]

        findings.append(PPFinding(
            url=probe_url,
            vector="gadget",
            payload=probe,
            description=f"{lib} gadget: {g['impact']}",
            severity=g["severity"] if verified else "medium",
            verified=verified,
            gadget=lib,
            cves=g.get("cves", []),
            evidence=evidence,
        ))

    return findings


# ── Main entry point ─────────────────────────────────────────────────────────

def scan_prototype_pollution(
    target: str,
    timeout: int = 8,
    skip_source: bool = False,
    skip_qs: bool = False,
    skip_json: bool = False,
    custom_headers: Optional[Dict] = None,
) -> PPResult:
    """Run full prototype pollution verification scan.

    Args:
        target:       Target URL.
        timeout:      HTTP timeout in seconds.
        skip_source:  Skip JS source analysis.
        skip_qs:      Skip query-string probing.
        skip_json:    Skip JSON body probing.
        custom_headers: Extra HTTP headers.

    Returns:
        PPResult with all findings.
    """
    start = time.time()
    result = PPResult(target=target)

    # Phase 1: Source analysis
    if not skip_source:
        sinks, gadgets = _analyze_js_sources(target, timeout=timeout)
        result.sinks_found = sinks
        result.gadgets_found = gadgets

        # Create findings for high-severity sinks
        for s in sinks:
            if s["severity"] in ("critical", "high"):
                result.findings.append(PPFinding(
                    url=s["source"],
                    vector="source_sink",
                    payload=s["pattern"],
                    description=f"Vulnerable sink detected: {s['pattern']}",
                    severity=s["severity"],
                    verified=False,  # Source analysis = not runtime verified
                ))

    # Phase 2: Query-string probing
    if not skip_qs:
        qs_findings = _probe_query_string(target, timeout=timeout)
        result.findings.extend(qs_findings)
        result.total_probes += len(_QS_PROBES)

    # Phase 3: JSON body probing
    if not skip_json:
        json_findings = _probe_json_body(target, timeout=timeout)
        result.findings.extend(json_findings)
        result.total_probes += len(_JSON_PROBES)

    # Phase 4: Gadget verification
    if result.gadgets_found:
        gadget_findings = _verify_gadgets(target, result.gadgets_found, timeout=timeout)
        result.findings.extend(gadget_findings)
        result.total_probes += len(result.gadgets_found)

    result.duration_s = time.time() - start
    return result


# ── CLI-friendly print ───────────────────────────────────────────────────────

def print_pp_result(result: PPResult):
    """Pretty-print prototype pollution scan results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    sev_color = {"critical": RED, "high": RED, "medium": YEL, "low": D}

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Prototype Pollution Scan{R}")
    print(f"  {D}{result.target}{R}")
    print(f"  {D}Probes: {result.total_probes} | Duration: {result.duration_s:.1f}s{R}")
    print(f"{D}{'━' * 60}{R}")

    if result.sinks_found:
        print(f"\n  {B}Vulnerable Sinks ({len(result.sinks_found)}){R}")
        for s in result.sinks_found:
            sc = sev_color.get(s["severity"], D)
            print(f"    {sc}●{R} {s['pattern']} {D}({s['count']}x in {s['source']}){R}")

    if result.gadgets_found:
        print(f"\n  {B}Known Gadgets ({len(result.gadgets_found)}){R}")
        for g in result.gadgets_found:
            sc = sev_color.get(g["severity"], D)
            cve_str = ", ".join(g["cves"]) if g["cves"] else "no CVE"
            print(f"    {sc}●{R} {g['library']} — {g['impact']} {D}({cve_str}){R}")

    verified = [f for f in result.findings if f.verified]
    unverified = [f for f in result.findings if not f.verified]

    if verified:
        print(f"\n  {RED}{B}Verified Findings ({len(verified)}){R}")
        for f in verified:
            sc = sev_color.get(f.severity, D)
            print(f"    {sc}● [{f.severity.upper()}]{R} {f.description}")
            print(f"      {CYN}{f.payload[:80]}{R}")
            if f.evidence:
                print(f"      {D}Evidence: {f.evidence[:100]}{R}")
            if f.cves:
                print(f"      {YEL}CVEs: {', '.join(f.cves)}{R}")

    if unverified:
        print(f"\n  {YEL}{B}Potential Findings ({len(unverified)}){R}")
        for f in unverified[:10]:
            sc = sev_color.get(f.severity, D)
            print(f"    {sc}●{R} {f.description}")

    if not result.findings:
        print(f"\n  {GRN}No prototype pollution indicators found.{R}")
    else:
        vuln = any(f.verified for f in result.findings)
        if vuln:
            print(f"\n  {RED}{B}VULNERABLE{R} — Prototype pollution confirmed")
        else:
            print(f"\n  {YEL}{B}POTENTIAL{R} — Sinks/gadgets found, manual verification recommended")

    print(f"\n{D}{'━' * 60}{R}\n")
