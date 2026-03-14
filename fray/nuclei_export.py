#!/usr/bin/env python3
"""
Nuclei Template Export — generate .yaml templates from Fray bypass results.

Converts successful WAF bypass payloads from fray agent/bypass/test into
Nuclei-compatible YAML templates for reproducible scanning.

Usage:
    from fray.nuclei_export import export_templates
    templates = export_templates(bypass_results, output_dir="./nuclei")

CLI:
    fray bypass https://target.com --nuclei-export ./nuclei/
"""

import os
import re
import hashlib
from typing import Dict, List, Optional
from datetime import datetime


def _safe_id(payload: str) -> str:
    """Generate a safe template ID from a payload."""
    h = hashlib.md5(payload.encode()).hexdigest()[:8]
    return f"fray-bypass-{h}"


def _severity_from_category(category: str) -> str:
    """Map Fray category to Nuclei severity."""
    _MAP = {
        "xss": "medium",
        "sqli": "critical",
        "cmdi": "critical",
        "ssti": "high",
        "ssrf": "high",
        "lfi": "high",
        "rce": "critical",
        "xxe": "high",
        "cache_poison": "medium",
        "prototype_pollution": "medium",
        "deser": "critical",
        "massassign": "medium",
    }
    return _MAP.get(category, "medium")


def _escape_yaml(s: str) -> str:
    """Escape a string for safe YAML inclusion."""
    if not s:
        return '""'
    # If it contains special chars, quote it
    if any(c in s for c in ":{}\n\r\t[]&*#?|->!%@`\"'"):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def bypass_to_template(bypass: Dict, category: str = "xss",
                       target: str = "", waf_vendor: str = "") -> str:
    """Convert a single bypass result dict into a Nuclei YAML template.

    Args:
        bypass: Dict with keys: payload, param, status, endpoint, technique, etc.
        category: Payload category (xss, sqli, cmdi, etc.)
        target: Original target URL (for reference)
        waf_vendor: WAF vendor name

    Returns:
        YAML string for the Nuclei template.
    """
    payload = bypass.get("payload", "")
    param = bypass.get("param", "q")
    method = bypass.get("method", "GET").upper()
    endpoint = bypass.get("endpoint", target or "{{BaseURL}}")
    technique = bypass.get("technique", bypass.get("mutation", ""))
    status = bypass.get("status", 200)
    tid = _safe_id(payload)
    severity = _severity_from_category(category)
    now = datetime.utcnow().strftime("%Y-%m-%d")

    # Build matchers
    matchers = []
    if status and status != 0:
        matchers.append(f"""      - type: status
        status:
          - {status}""")
    # For XSS, check if payload reflected
    if category == "xss" and "<" in payload:
        # Extract a short snippet for word matching
        _snippet = payload[:40].replace('"', '\\"')
        matchers.append(f"""      - type: word
        words:
          - {_escape_yaml(_snippet)}
        part: body""")

    matchers_yaml = "\n".join(matchers) if matchers else ""
    matchers_block = f"""    matchers:
{matchers_yaml}""" if matchers_yaml else ""

    # Build request
    if method == "GET":
        path_line = f"{{{{BaseURL}}}}?{param}={payload}"
        request_block = f"""    - method: GET
      path:
        - {_escape_yaml(path_line)}
      headers:
        User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
{matchers_block}"""
    else:
        request_block = f"""    - method: {method}
      path:
        - "{{{{BaseURL}}}}"
      headers:
        User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        Content-Type: "application/x-www-form-urlencoded"
      body: "{param}={payload}"
{matchers_block}"""

    tags = [category]
    if waf_vendor:
        tags.append(waf_vendor.lower().replace(" ", "-"))
    if technique:
        tags.append(technique.lower().replace(" ", "-")[:20])
    tags_str = ",".join(tags)

    template = f"""id: {tid}

info:
  name: "Fray WAF Bypass - {category.upper()} ({tid})"
  author: fray
  severity: {severity}
  description: |
    WAF bypass payload discovered by Fray.
    Category: {category}
    Technique: {technique or 'generic'}
    WAF: {waf_vendor or 'unknown'}
    Original target: {target or 'N/A'}
  tags: {tags_str}
  metadata:
    fray_category: {category}
    fray_waf: {waf_vendor or 'unknown'}
    fray_technique: {technique or 'generic'}
    fray_date: {now}

http:
{request_block}
"""
    return template


def export_templates(bypasses: List[Dict], output_dir: str = "./nuclei",
                     category: str = "xss", target: str = "",
                     waf_vendor: str = "") -> List[str]:
    """Export multiple bypass results as Nuclei YAML templates.

    Args:
        bypasses: List of bypass result dicts.
        output_dir: Directory to write .yaml files.
        category: Payload category.
        target: Original target URL.
        waf_vendor: WAF vendor name.

    Returns:
        List of written file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    written = []

    for bypass in bypasses:
        payload = bypass.get("payload", "")
        if not payload:
            continue
        tid = _safe_id(payload)
        yaml_str = bypass_to_template(bypass, category=category,
                                       target=target, waf_vendor=waf_vendor)
        path = os.path.join(output_dir, f"{tid}.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(yaml_str)
        written.append(path)

    return written
