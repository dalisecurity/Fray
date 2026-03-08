"""
Fray Interop — Burp Suite, ZAP, and Nuclei integration.

Export Fray scan/bypass results to:
  - Burp Suite XML (base64-encoded request/response items)
  - ZAP alerts JSON
  - Nuclei YAML templates

Import from:
  - Burp Suite saved request files (raw HTTP)
  - Burp XML export (base64-decoded)

Zero dependencies — stdlib only.
"""

import base64
import json
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape


# ── Burp Suite Export ──────────────────────────────────────────────────

def export_burp_xml(results: List[Dict], target: str,
                    output_file: str = "fray_burp_export.xml") -> str:
    """Export Fray scan/bypass results as Burp Suite XML.

    Produces Burp-compatible <items> XML with base64-encoded
    request/response pairs that can be imported into Burp Suite
    via Extender > Import.

    Args:
        results: List of test result dicts from fray scan/test/bypass.
        target: Target URL.
        output_file: Output file path.

    Returns:
        Path to the generated XML file.
    """
    parsed = urllib.parse.urlparse(
        target if target.startswith("http") else f"https://{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    protocol = parsed.scheme or "https"
    path = parsed.path or "/"

    root = ET.Element("items", burpVersion="2024.0", exportTime=_iso_now())

    for i, r in enumerate(results):
        item = ET.SubElement(root, "item")

        ET.SubElement(item, "time").text = _iso_now()
        ET.SubElement(item, "url").text = r.get("url", target)
        ET.SubElement(item, "host", ip="").text = host
        ET.SubElement(item, "port").text = str(port)
        ET.SubElement(item, "protocol").text = protocol
        ET.SubElement(item, "method").text = r.get("method", "GET")
        ET.SubElement(item, "path").text = r.get("path", path)

        # Build raw HTTP request
        payload = r.get("payload", "")
        param = r.get("param", "input")
        method = r.get("method", "GET")

        if method == "GET":
            req_path = f"{path}?{param}={urllib.parse.quote(payload)}"
            raw_request = (
                f"{method} {req_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Fray-Scanner\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
        else:
            body = f"{param}={urllib.parse.quote(payload)}"
            raw_request = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Fray-Scanner\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )

        ET.SubElement(item, "request", base64="true").text = (
            base64.b64encode(raw_request.encode()).decode())

        # Build mock response
        status = r.get("status", 200)
        resp_len = r.get("response_length", 0)
        blocked = r.get("blocked", False)
        raw_response = (
            f"HTTP/1.1 {status} {'Forbidden' if blocked else 'OK'}\r\n"
            f"Content-Length: {resp_len}\r\n"
            f"X-Fray-Blocked: {'true' if blocked else 'false'}\r\n"
            f"X-Fray-Payload: {escape(payload[:100])}\r\n\r\n"
        )
        ET.SubElement(item, "response", base64="true").text = (
            base64.b64encode(raw_response.encode()).decode())

        ET.SubElement(item, "responselength").text = str(resp_len)
        ET.SubElement(item, "mimetype").text = "text/html"

        # Status code mapping
        status_code = str(status)
        ET.SubElement(item, "status").text = status_code

        # Comment with Fray metadata
        category = r.get("category", "")
        technique = r.get("technique", "")
        reflected = r.get("reflected", False)
        evasion = r.get("evasion_score", 0)
        comment_parts = [f"Fray: {category}"]
        if technique:
            comment_parts.append(f"technique={technique}")
        if reflected:
            comment_parts.append("REFLECTED")
        if not blocked:
            comment_parts.append(f"BYPASSED (evasion={evasion})")
        ET.SubElement(item, "comment").text = " | ".join(comment_parts)

        # Highlight bypasses
        if not blocked:
            ET.SubElement(item, "highlight").text = "red"
        elif reflected:
            ET.SubElement(item, "highlight").text = "orange"

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    return output_file


def import_burp_requests(file_path: str) -> List[Dict[str, Any]]:
    """Import Burp Suite saved request file(s).

    Supports:
      - Raw HTTP request files (one request per file)
      - Burp XML export (multiple items with base64 requests)

    Returns list of {method, url, headers, body, param, payload} dicts
    suitable for feeding into fray test/bypass.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Detect format
    if content.strip().startswith("<?xml") or content.strip().startswith("<items"):
        return _import_burp_xml(content)
    else:
        return [_parse_raw_http_request(content)]


def _import_burp_xml(xml_content: str) -> List[Dict[str, Any]]:
    """Parse Burp XML export with base64-encoded requests."""
    results = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return results

    for item in root.findall("item"):
        req_elem = item.find("request")
        if req_elem is None or not req_elem.text:
            continue

        is_base64 = req_elem.get("base64", "false") == "true"
        raw = base64.b64decode(req_elem.text).decode("utf-8", errors="replace") if is_base64 else req_elem.text

        parsed = _parse_raw_http_request(raw)
        url_elem = item.find("url")
        if url_elem is not None and url_elem.text:
            parsed["url"] = url_elem.text

        host_elem = item.find("host")
        if host_elem is not None and host_elem.text:
            parsed["host"] = host_elem.text

        results.append(parsed)

    return results


def _parse_raw_http_request(raw: str) -> Dict[str, Any]:
    """Parse a raw HTTP request string into structured dict."""
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        return {"method": "GET", "path": "/", "headers": {}, "body": ""}

    # Request line
    parts = lines[0].split(" ", 2)
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    # Headers
    headers = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    body = "\n".join(lines[body_start:]).strip()

    # Extract target URL from Host header
    host = headers.get("Host", "")
    scheme = "https"
    url = f"{scheme}://{host}{path}" if host else path

    # Try to extract payload param from URL or body
    param = ""
    payload = ""
    if "?" in path:
        qs = urllib.parse.urlparse(path).query
        params = urllib.parse.parse_qs(qs)
        if params:
            param = list(params.keys())[0]
            payload = params[param][0] if params[param] else ""
    elif body:
        try:
            params = urllib.parse.parse_qs(body)
            if params:
                param = list(params.keys())[0]
                payload = params[param][0] if params[param] else ""
        except Exception:
            pass

    return {
        "method": method,
        "url": url,
        "path": path,
        "host": host,
        "headers": headers,
        "body": body,
        "param": param,
        "payload": payload,
    }


# ── ZAP Export ────────────────────────────────────────────────────────

def export_zap_json(results: List[Dict], target: str,
                    output_file: str = "fray_zap_export.json") -> str:
    """Export Fray results as ZAP-compatible alerts JSON.

    Produces a JSON structure compatible with ZAP's alert format
    for import via ZAP API or scripting console.
    """
    alerts = []
    for r in results:
        blocked = r.get("blocked", False)
        category = r.get("category", "waf-bypass")
        payload = r.get("payload", "")

        risk_val = 0 if blocked else 2  # 0=Info, 1=Low, 2=Medium, 3=High
        confidence_val = 2  # Medium

        if not blocked and r.get("reflected"):
            risk_val = 3  # High — reflected bypass
            confidence_val = 3

        alert = {
            "sourceid": "fray",
            "pluginid": f"fray-{category}",
            "alertRef": f"fray-{category}-{hash(payload) & 0xFFFF:04x}",
            "alert": f"WAF Bypass: {category.upper()}" if not blocked else f"WAF Block: {category.upper()}",
            "name": f"Fray {category.upper()} {'bypass' if not blocked else 'blocked'}",
            "riskcode": str(risk_val),
            "confidence": str(confidence_val),
            "riskdesc": ["Informational", "Low", "Medium", "High"][risk_val],
            "desc": f"Fray detected {'a WAF bypass' if not blocked else 'WAF blocking'} "
                    f"for {category} payload.",
            "uri": r.get("url", target),
            "method": r.get("method", "GET"),
            "param": r.get("param", ""),
            "attack": payload,
            "evidence": f"Status: {r.get('status', '?')}, "
                       f"Blocked: {blocked}, "
                       f"Reflected: {r.get('reflected', False)}",
            "solution": "Review WAF rules for this payload pattern." if not blocked
                       else "WAF is correctly blocking this payload.",
            "reference": "https://github.com/dalisecurity/Fray",
            "tags": {
                "fray-category": category,
                "fray-blocked": str(blocked).lower(),
                "fray-evasion-score": str(r.get("evasion_score", 0)),
            },
        }
        alerts.append(alert)

    output = {
        "version": "1.0",
        "generated": _iso_now(),
        "site": [{
            "host": urllib.parse.urlparse(
                target if target.startswith("http") else f"https://{target}"
            ).hostname or target,
            "name": target,
            "alerts": alerts,
        }],
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    return output_file


# ── Nuclei Template Export ─────────────────────────────────────────────

def export_nuclei_templates(results: List[Dict], target: str,
                            output_dir: str = "fray_nuclei_templates") -> List[str]:
    """Convert Fray bypass findings into Nuclei YAML templates.

    Generates one template per unique bypass technique/payload.
    Only exports bypasses (not blocked results).

    Returns list of generated template file paths.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    # Filter to bypasses only
    bypasses = [r for r in results if not r.get("blocked", True)]
    if not bypasses:
        return []

    # Group by category + technique for dedup
    seen = set()
    templates = []

    for r in bypasses:
        category = r.get("category", "waf-bypass")
        payload = r.get("payload", "")
        technique = r.get("technique", "")
        param = r.get("param", "input")
        evasion = r.get("evasion_score", 0)

        # Dedup key
        key = f"{category}:{technique}:{payload[:50]}"
        if key in seen:
            continue
        seen.add(key)

        template_id = f"fray-{category}-{len(templates) + 1:03d}"
        safe_payload = payload.replace("'", "\\'").replace('"', '\\"')

        # Determine matchers based on what we know
        matchers = []
        if r.get("reflected"):
            matchers.append(f'      - type: word\n        words:\n          - "{_nuclei_escape(payload[:60])}"')
        matchers.append(f'      - type: status\n        status:\n          - {r.get("status", 200)}')

        matchers_yaml = "\n".join(matchers)

        template = f"""id: {template_id}

info:
  name: "Fray WAF Bypass - {category.upper()}{f' ({technique})' if technique else ''}"
  author: fray
  severity: medium
  description: |
    WAF bypass detected by Fray security scanner.
    Category: {category}
    Technique: {technique or 'direct'}
    Evasion Score: {evasion}%
  reference:
    - https://github.com/dalisecurity/Fray
  tags: fray,waf-bypass,{category}
  metadata:
    fray-evasion-score: "{evasion}"
    fray-technique: "{technique or 'direct'}"

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/?{param}={urllib.parse.quote(payload)}"
    matchers-condition: and
    matchers:
{matchers_yaml}
"""

        filename = f"{template_id}.yaml"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(template)
        templates.append(filepath)

    return templates


def _nuclei_escape(text: str) -> str:
    """Escape special chars for Nuclei YAML string."""
    return text.replace('"', '\\"').replace("\n", "\\n")


# ── Bypass Recipe Sharing ─────────────────────────────────────────────

def format_bypass_recipe(result: Dict, target: str = "",
                         anonymize: bool = True) -> Dict[str, Any]:
    """Format a bypass result as a shareable recipe.

    Anonymizes the target by default (strips hostname).
    Returns a dict suitable for JSON serialization.
    """
    recipe = {
        "schema_version": "1.0",
        "timestamp": _iso_now(),
        "category": result.get("category", ""),
        "technique": result.get("technique", ""),
        "payload": result.get("payload", ""),
        "parent_payload": result.get("parent", ""),
        "waf_vendor": result.get("waf_vendor", ""),
        "evasion_score": result.get("evasion_score", 0),
        "status_code": result.get("status", 0),
        "reflected": result.get("reflected", False),
        "reflection_context": result.get("reflection_context", ""),
        "response_length": result.get("response_length", 0),
    }

    if not anonymize and target:
        recipe["target"] = target
    else:
        recipe["target"] = "(anonymized)"

    return recipe


def export_bypass_recipes(bypasses: List[Dict], target: str = "",
                          output_file: str = "fray_bypass_recipes.json",
                          anonymize: bool = True) -> str:
    """Export all successful bypasses as shareable recipes."""
    recipes = []
    for b in bypasses:
        if not b.get("blocked", True):
            recipes.append(format_bypass_recipe(b, target, anonymize))

    output = {
        "schema_version": "1.0",
        "generated": _iso_now(),
        "tool": "Fray",
        "total_recipes": len(recipes),
        "recipes": recipes,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    return output_file


# ── Helpers ────────────────────────────────────────────────────────────

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
