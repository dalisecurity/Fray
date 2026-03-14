#!/usr/bin/env python3
"""
Fray WAF Rule Generator — auto-generate WAF rules from bypass payloads.

For each successful bypass found by fray go/bypass/agent, generates
vendor-specific WAF rules to block that payload pattern.

Supports:
  - ModSecurity (Apache/Nginx)
  - Cloudflare WAF (Expression rules)
  - AWS WAF (regex pattern sets)

Usage:
    from fray.waf_rules import generate_rules
    rules = generate_rules(bypasses, waf_vendor="cloudflare")
"""

import re
import hashlib
from typing import Dict, List, Optional


def _escape_modsec(s: str) -> str:
    """Escape a string for ModSecurity SecRule."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")


def _escape_cf(s: str) -> str:
    """Escape for Cloudflare expression."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _extract_pattern(payload: str) -> str:
    """Extract the core attack pattern from a payload for regex matching."""
    # Strip common encoding wrappers
    p = payload.strip()

    # Extract key attack indicators
    patterns = []

    # Event handlers: onerror, onload, onfocus, etc.
    events = re.findall(r'on\w+\s*=', p, re.I)
    for e in events:
        patterns.append(e.strip())

    # Script tags
    if re.search(r'<\s*script', p, re.I):
        patterns.append("<script")

    # SVG/IMG/IFRAME tags with event handlers
    for tag in ["svg", "img", "iframe", "object", "embed", "video", "audio", "body", "details"]:
        if re.search(rf'<\s*{tag}', p, re.I):
            patterns.append(f"<{tag}")

    # JavaScript protocol
    if re.search(r'javascript\s*:', p, re.I):
        patterns.append("javascript:")

    # SQL injection patterns
    if re.search(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s+'|--\s*$|;\s*drop\s)", p, re.I):
        sql_m = re.search(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s+')", p, re.I)
        if sql_m:
            patterns.append(sql_m.group(0))

    # Template injection
    if re.search(r'\{\{.*\}\}|\$\{.*\}|<%.*%>', p):
        patterns.append("template_injection")

    # Command injection
    if re.search(r';\s*(ls|cat|id|whoami|curl|wget|nc)\b', p, re.I):
        cmd_m = re.search(r';\s*(ls|cat|id|whoami|curl|wget|nc)\b', p, re.I)
        if cmd_m:
            patterns.append(cmd_m.group(0))

    return "|".join(patterns) if patterns else payload[:60]


def _modsec_rule(payload: str, rule_id: int, category: str = "xss") -> str:
    """Generate a ModSecurity SecRule for a bypass payload."""
    pattern = _extract_pattern(payload)
    escaped = _escape_modsec(pattern)
    phase = "2" if category in ("sqli", "cmdi", "ssti") else "1"

    return (
        f'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx {escaped}" '
        f'"id:{rule_id},'
        f'phase:{phase},'
        f'deny,'
        f'status:403,'
        f'log,'
        f'msg:\'Fray bypass blocked: {_escape_modsec(category)}\','
        f'tag:\'fray/bypass/{category}\','
        f'severity:CRITICAL"'
    )


def _cloudflare_rule(payload: str, category: str = "xss") -> str:
    """Generate a Cloudflare WAF expression rule."""
    pattern = _extract_pattern(payload)
    escaped = _escape_cf(pattern)

    # Build expression matching query string and body
    parts = []
    for p in pattern.split("|"):
        p = p.strip()
        if p:
            ep = _escape_cf(p)
            parts.append(
                f'(http.request.uri.query contains "{ep}" or '
                f'http.request.body contains "{ep}")'
            )

    if not parts:
        parts = [f'(http.request.uri.query contains "{escaped}")']

    expr = " or ".join(parts)
    return f'({expr})'


def _aws_waf_pattern(payload: str, category: str = "xss") -> Dict:
    """Generate an AWS WAF regex pattern set entry."""
    pattern = _extract_pattern(payload)
    # AWS WAF uses Java regex
    regex = re.escape(pattern).replace(r"\|", "|")

    return {
        "RegexString": regex,
        "Description": f"Fray bypass: {category} pattern",
    }


def generate_rules(bypasses: List[Dict], waf_vendor: str = "modsecurity",
                   category: str = "xss", base_rule_id: int = 9500000) -> Dict:
    """Generate WAF rules from bypass payloads.

    Args:
        bypasses: List of bypass result dicts with 'payload' key.
        waf_vendor: Target WAF vendor (modsecurity, cloudflare, aws).
        category: Attack category.
        base_rule_id: Starting rule ID for ModSecurity.

    Returns:
        Dict with 'vendor', 'rules' (list of rule strings/dicts), 'count'.
    """
    vendor = waf_vendor.lower().replace(" ", "").replace("-", "")
    rules = []
    seen = set()

    for i, bypass in enumerate(bypasses):
        payload = bypass.get("payload", "")
        if not payload:
            continue

        # Deduplicate by pattern
        pattern = _extract_pattern(payload)
        if pattern in seen:
            continue
        seen.add(pattern)

        if "modsec" in vendor or "mod_security" in vendor or vendor == "apache" or vendor == "nginx":
            rules.append({
                "type": "modsecurity",
                "rule": _modsec_rule(payload, base_rule_id + i, category),
                "pattern": pattern,
                "payload": payload[:80],
            })
        elif "cloudflare" in vendor or vendor == "cf":
            rules.append({
                "type": "cloudflare",
                "expression": _cloudflare_rule(payload, category),
                "pattern": pattern,
                "payload": payload[:80],
            })
        elif "aws" in vendor:
            rules.append({
                "type": "aws_waf",
                "regex_pattern": _aws_waf_pattern(payload, category),
                "pattern": pattern,
                "payload": payload[:80],
            })
        else:
            # Generic: output all three formats
            rules.append({
                "type": "generic",
                "modsecurity": _modsec_rule(payload, base_rule_id + i, category),
                "cloudflare": _cloudflare_rule(payload, category),
                "aws_waf": _aws_waf_pattern(payload, category),
                "pattern": pattern,
                "payload": payload[:80],
            })

    return {
        "vendor": vendor or "generic",
        "category": category,
        "count": len(rules),
        "rules": rules,
    }


def rules_to_html(rules_data: Dict) -> str:
    """Render WAF rules as an HTML section for the report."""
    rules = rules_data.get("rules", [])
    if not rules:
        return ""

    vendor = rules_data.get("vendor", "generic")
    category = rules_data.get("category", "xss")

    rows = ""
    for r in rules[:15]:
        payload = r.get("payload", "")[:60]
        pattern = r.get("pattern", "")[:50]
        rtype = r.get("type", "generic")

        if rtype == "modsecurity":
            rule_text = r.get("rule", "")
        elif rtype == "cloudflare":
            rule_text = r.get("expression", "")
        elif rtype == "aws_waf":
            rule_text = r.get("regex_pattern", {}).get("RegexString", "")
        else:
            rule_text = r.get("modsecurity", "")

        # Escape HTML
        import html
        payload_esc = html.escape(payload)
        rule_esc = html.escape(str(rule_text))[:200]

        rows += (
            f'<tr>'
            f'<td style="font-family:monospace;font-size:0.8em;max-width:250px;'
            f'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{payload_esc}</td>'
            f'<td><code style="font-size:0.75em;word-break:break-all;">{rule_esc}</code></td>'
            f'</tr>'
        )

    return (
        f'<div style="margin-top:14px;border-top:1px solid var(--border);padding-top:14px;">'
        f'<p style="font-size:0.9em;font-weight:600;margin-bottom:8px;">'
        f'Suggested WAF Rules ({len(rules)} for {category.upper()}, {vendor}):</p>'
        f'<table style="font-size:0.85em;"><tr><th>Bypass Payload</th><th>Rule</th></tr>'
        f'{rows}</table>'
        f'</div>'
    )
