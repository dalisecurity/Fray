#!/usr/bin/env python3
"""
Fray CLI — Unified command-line interface

Usage:
    fray go <url>               Guided pipeline: recon → smart test → report (zero-knowledge)
    fray detect <url>           Detect WAF vendor
    fray test <url>             Test WAF with payloads
    fray test <url> -c xss      Test specific category
    fray test <url> --blind      Blind injection detection (time-based + OOB DNS)
    fray test <url> --auth-profile ~/.fray/auth/mysite.json   Authenticated scan
    fray test <url> --smart      Adaptive payload evolution (fewer requests, more impact)
    fray test <url> --webhook <url>  Notify on completion
    fray report                 Generate HTML report
    fray payloads               List available payload categories
    fray stats                  Show payload database statistics
    fray doctor                 Check environment + auto-fix issues
    fray submit-payload          Submit payload to community (auto GitHub PR)
    fray ci init                 Generate GitHub Actions WAF test workflow
    fray learn xss               Interactive CTF-style security tutorial
    fray scan <url>              Auto crawl → param discovery → payload injection
    fray bypass <url> --waf cloudflare -c xss   WAF bypass scoring with evasion scorecard
    fray diff before.json after.json              Compare scans — surface regressions
    fray smuggle <url>           HTTP request smuggling detection (CL.TE / TE.CL)
    fray validate <url>          Blue team WAF config validation report
    fray bounty --platform h1    Bug bounty scope auto-fetch + batch test
    fray explain <CVE-ID>       Explain a CVE — payloads, severity, what to test
    fray explain results.json    Explain scan findings — impact, remediation, next steps
    fray agent <url>             Self-improving payload agent: probe → mutate → learn
    fray feed                    Threat intel feed: auto-discover CVEs → translate to payloads
    fray update                  Pull latest payload database from cloud (R2 / GitHub)
    fray sync --push             Publish payload database to cloud (maintainer)
    fray demo [url]             Quick showcase: detect WAF + XSS scan (great for GIFs)
    fray version                Show version
"""

import argparse
import json
import sys
from pathlib import Path

from fray import __version__, PAYLOADS_DIR


def _json_print(obj, **kwargs):
    """Print JSON to stdout: compact JSONL when piped, pretty when interactive.

    Always uses ensure_ascii=False. Extra kwargs passed to json.dumps.
    When stdout is a TTY (interactive terminal), prints with indent=2.
    When piped (not a TTY), prints compact single-line JSONL for automation.
    """
    if sys.stdout.isatty():
        print(json.dumps(obj, indent=2, ensure_ascii=False, **kwargs))
    else:
        print(json.dumps(obj, ensure_ascii=False, **kwargs))


def _local_summarize_recon(target: str, recon: dict) -> str:
    """Generate a rule-based actionable summary when no LLM is available.

    Parses the recon results and produces prioritized findings + next commands.
    No API key required — works offline.
    """
    lines = []
    atk = recon.get("attack_surface", {})
    risk = atk.get("risk_level", "?")
    score = atk.get("risk_score", 0)
    waf = atk.get("waf_vendor") or "Unknown"
    findings = atk.get("findings", [])

    # TL;DR
    lines.append(f"**TL;DR** — {target} is behind {waf} WAF with a {risk} risk score ({score}/100).")
    if not findings:
        lines.append("No significant findings from reconnaissance.")
        lines.append("")
        lines.append(f"**Recommended Next Steps**")
        lines.append(f"  `fray test {target} --smart` — Run payload tests with auto-category selection")
        lines.append(f"  `fray detect {target}` — Confirm WAF vendor identification")
        return "\n".join(lines)

    lines.append("")

    # Top Findings — sorted by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity", "info"), 4))

    lines.append("**Top Findings**")
    for f in sorted_findings[:5]:
        sev = f.get("severity", "info")
        emoji = sev_emoji.get(sev, "⚪")
        lines.append(f"  {emoji} [{sev.upper()}] {f.get('finding', '?')}")
    lines.append("")

    # Recommended Next Steps
    lines.append("**Recommended Next Steps**")
    recs = recon.get("recommended_categories", [])
    top_cat = recs[0] if recs else "xss"

    # Always suggest test with top category
    lines.append(f"  `fray test {target} -c {top_cat} --smart` — Test top priority category")

    # If WAF found, suggest bypass
    if waf and waf != "Unknown":
        lines.append(f"  `fray bypass {target} -c {top_cat}` — Attempt WAF bypass ({waf})")

    # If critical/high findings exist, suggest deeper scan
    crit_high = [f for f in findings if f.get("severity") in ("critical", "high")]
    if crit_high:
        lines.append(f"  `fray scan {target} --deep` — Deep scan to enumerate all injection points")

    # If exposed files or admin panels found
    exposed = recon.get("exposed_files", {})
    if exposed and exposed.get("found"):
        lines.append(f"  `fray recon {target} --deep` — Deep recon on exposed files")

    # Always suggest hardening check
    lines.append(f"  `fray harden {target}` — Check security headers and configuration")
    lines.append("")

    # Quick Wins
    sec = recon.get("security_headers", {})
    missing = sec.get("missing", []) if sec else []
    if missing:
        lines.append("**Quick Wins**")
        lines.append(f"  Add missing headers: {', '.join(missing[:4])}")
        cookies = recon.get("cookies", {})
        if cookies and cookies.get("issues"):
            lines.append(f"  Fix cookie flags: {', '.join(str(i) for i in cookies['issues'][:2])}")

    return "\n".join(lines)


def _ai_summarize_recon(target: str, recon: dict) -> str:
    """Send recon results to LLM and get an actionable security summary.

    Returns a formatted string with prioritized findings and next commands.
    Falls back to rule-based summary if no API key is available.
    """
    from fray.ai_bypass import _call_llm, _llm_available

    provider = _llm_available()
    if not provider:
        return _local_summarize_recon(target, recon)

    # Build a compact summary to minimize tokens
    compact = {"target": target}
    atk = recon.get("attack_surface", {})
    if atk:
        compact["risk_score"] = atk.get("risk_score", 0)
        compact["risk_level"] = atk.get("risk_level", "?")
        compact["findings"] = atk.get("findings", [])
        compact["waf"] = atk.get("waf_vendor")
        compact["cdn"] = atk.get("cdn")
        compact["technologies"] = atk.get("technologies", [])

    sec = recon.get("security_headers", {})
    if sec:
        compact["header_score"] = sec.get("score")
        compact["missing_headers"] = sec.get("missing", [])

    tls = recon.get("tls", {})
    if tls:
        compact["tls_version"] = tls.get("version")
        compact["cert_expires_days"] = tls.get("expires_days")

    cors = recon.get("cors", {})
    if cors and cors.get("misconfigured"):
        compact["cors_issues"] = cors.get("issues", [])

    exposed = recon.get("exposed_files", {})
    if exposed and exposed.get("found"):
        compact["exposed_files"] = exposed["found"]

    cookies = recon.get("cookies", {})
    if cookies and cookies.get("issues"):
        compact["cookie_issues"] = cookies["issues"]

    graphql = recon.get("graphql", {})
    if graphql and graphql.get("introspection_enabled"):
        compact["graphql_introspection_open"] = True
        compact["graphql_endpoint"] = graphql.get("endpoint", "")

    api = recon.get("api_discovery", {})
    if api and api.get("endpoints_found"):
        compact["api_endpoints"] = api["endpoints_found"]

    admin = recon.get("admin_panels", {})
    if admin and admin.get("panels_found"):
        compact["admin_panels"] = [
            {"path": p["path"], "status": p["status"], "open": not p.get("protected", True)}
            for p in admin["panels_found"]
        ]

    host_inj = recon.get("host_header_injection", {})
    if host_inj and host_inj.get("vulnerable"):
        compact["host_header_injectable"] = True

    recs = recon.get("recommended_categories", [])
    if recs:
        compact["recommended_categories"] = recs

    fp = recon.get("fingerprint", {})
    if fp:
        compact["server"] = fp.get("server")
        compact["powered_by"] = fp.get("x_powered_by")

    system_prompt = """\
You are Fray, a senior penetration tester reviewing reconnaissance results.

Given the recon JSON below, produce a concise actionable summary:

1. **TL;DR** — One sentence: what is this target and its overall security posture?
2. **Top Findings** — Bullet list of the 3-5 most important findings, ranked by severity. Each bullet: severity emoji (🔴 critical, 🟠 high, 🟡 medium, 🔵 low), finding, and why it matters.
3. **Recommended Next Steps** — 3-5 exact fray commands the user should run next, with a one-line explanation each. Use the actual target URL.
4. **Quick Wins** — 1-3 things the target owner could fix immediately to improve security.

Rules:
- Be specific, not generic. Reference actual findings from the data.
- If no significant findings, say so clearly.
- Keep the entire response under 400 words.
- Do NOT use markdown headers (#). Use the bold labels shown above.
- Format commands as: `fray <command>` (with backtick code formatting)."""

    user_msg = json.dumps(compact, indent=2, ensure_ascii=False)

    try:
        response = _call_llm(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
            max_tokens=800,
        )
        return response.strip()
    except Exception:
        return ""


def _build_ai_output(target: str, results: list = None, recon: dict = None,
                     scan_summary: dict = None, crawl: dict = None) -> dict:
    """Build LLM-optimized JSON output for AI agent consumption.

    Structured for direct piping into Claude, GPT, or any AI workflow:
        fray scan target.com --ai | ai analyze
    """
    from datetime import datetime as _dt

    out = {
        "schema": "fray-ai/v1",
        "target": target,
        "timestamp": _dt.now().isoformat(),
    }

    # ── Technologies (from recon fingerprint) ──
    technologies = []
    if recon:
        fp = recon.get("fingerprint", {})
        for tech, conf in fp.get("technologies", {}).items():
            technologies.append({"name": tech, "confidence": conf})
        # WAF
        waf = recon.get("waf_detected")
        if waf:
            out["waf"] = waf

        # Security posture from recon
        headers = recon.get("headers", {})
        security_headers = recon.get("security_headers", {})
        tls = recon.get("tls", {})
        dns = recon.get("dns", {})
        cors = recon.get("cors", {})
        cookies = recon.get("cookies", {})
        exposed = recon.get("exposed_files", {})
        graphql = recon.get("graphql", {})
        api_discovery = recon.get("api_discovery", {})
        host_injection = recon.get("host_header_injection", {})
        admin_panels = recon.get("admin_panels", {})

        posture = {}
        # Header score
        if security_headers:
            score = security_headers.get("score")
            missing = security_headers.get("missing", [])
            if score is not None:
                posture["header_score"] = score
            if missing:
                posture["missing_headers"] = missing

        # TLS
        if tls and tls.get("version"):
            posture["tls_version"] = tls["version"]
            if tls.get("expires_days") is not None:
                posture["cert_expires_days"] = tls["expires_days"]

        # CORS
        if cors and cors.get("misconfigured"):
            posture["cors_misconfigured"] = True
            posture["cors_issues"] = cors.get("issues", [])

        # Exposed files
        if exposed and exposed.get("found"):
            posture["exposed_files"] = exposed["found"]

        # Cookies
        if cookies and cookies.get("issues"):
            posture["cookie_issues"] = cookies["issues"]

        # GraphQL
        if graphql and graphql.get("introspection_enabled"):
            posture["graphql_introspection_open"] = True
            posture["graphql_endpoint"] = graphql.get("endpoint", "")

        # API discovery
        if api_discovery and api_discovery.get("endpoints_found"):
            posture["api_endpoints_exposed"] = api_discovery["endpoints_found"]

        # Host header injection
        if host_injection and host_injection.get("vulnerable"):
            posture["host_header_injectable"] = True
            posture["host_injection_headers"] = host_injection.get("vulnerable_headers", [])

        # Admin panels
        if admin_panels and admin_panels.get("panels_found"):
            panels = []
            for p in admin_panels["panels_found"]:
                entry = {"path": p["path"], "status": p["status"]}
                if p.get("protected") is False:
                    entry["open"] = True
                panels.append(entry)
            posture["admin_panels"] = panels

        if posture:
            out["security_posture"] = posture

        # Recommended categories
        recs = recon.get("recommended_categories", [])
        if recs:
            out["recommended_categories"] = recs

    if technologies:
        out["technologies"] = technologies

    # ── Crawl summary (from scan) ──
    if crawl:
        out["crawl"] = {
            "pages": crawl.get("pages_crawled", 0),
            "endpoints": crawl.get("total_endpoints", 0),
            "injection_points": crawl.get("total_injection_points", 0),
        }

    # ── Vulnerabilities (from test/scan results) ──
    if results:
        reflected = [r for r in results if r.get("reflected") and not r.get("blocked")]
        bypassed = [r for r in results if not r.get("blocked") and not r.get("reflected")]
        blocked_count = sum(1 for r in results if r.get("blocked"))

        # CWE mapping
        cwe_map = {
            "xss": "CWE-79", "sqli": "CWE-89", "ssrf": "CWE-918",
            "ssti": "CWE-1336", "command_injection": "CWE-78", "xxe": "CWE-611",
            "path_traversal": "CWE-22", "open-redirect": "CWE-601",
            "crlf_injection": "CWE-113", "prototype_pollution": "CWE-1321",
            "host_header_injection": "CWE-644",
        }

        vulns = []
        # Group reflected by category
        by_cat = {}
        for r in reflected:
            cat = r.get("category", "unknown")
            by_cat.setdefault(cat, []).append(r)
        for cat, items in by_cat.items():
            vuln = {
                "type": cat,
                "cwe": cwe_map.get(cat, "CWE-20"),
                "confidence": "high",
                "confirmed": True,
                "count": len(items),
                "endpoints": [],
            }
            seen = set()
            for r in items:
                ep = r.get("url", r.get("endpoint", target))
                param = r.get("param", "")
                key = f"{ep}|{param}"
                if key not in seen:
                    seen.add(key)
                    entry = {"url": ep}
                    if param:
                        entry["parameter"] = param
                    entry["payload_sample"] = r.get("payload", "")[:120]
                    vuln["endpoints"].append(entry)
            vulns.append(vuln)

        # Group bypassed by category
        by_cat_b = {}
        for r in bypassed:
            cat = r.get("category", "unknown")
            by_cat_b.setdefault(cat, []).append(r)
        for cat, items in by_cat_b.items():
            vuln = {
                "type": cat,
                "cwe": cwe_map.get(cat, "CWE-20"),
                "confidence": "medium",
                "confirmed": False,
                "count": len(items),
                "endpoints": [],
            }
            seen = set()
            for r in items[:5]:
                ep = r.get("url", r.get("endpoint", target))
                param = r.get("param", "")
                key = f"{ep}|{param}"
                if key not in seen:
                    seen.add(key)
                    entry = {"url": ep}
                    if param:
                        entry["parameter"] = param
                    entry["payload_sample"] = r.get("payload", "")[:120]
                    vuln["endpoints"].append(entry)
            vulns.append(vuln)

        out["vulnerabilities"] = vulns
        out["summary"] = {
            "total_tested": len(results),
            "blocked": blocked_count,
            "bypassed": len(bypassed),
            "reflected": len(reflected),
            "block_rate": f"{(blocked_count / len(results) * 100):.1f}%" if results else "0%",
            "risk": "critical" if reflected else ("medium" if bypassed else "low"),
        }

    if scan_summary and "summary" not in out:
        out["summary"] = scan_summary

    # ── Suggested next actions ──
    actions = []
    if results:
        reflected = [r for r in results if r.get("reflected") and not r.get("blocked")]
        bypassed = [r for r in results if not r.get("blocked") and not r.get("reflected")]
        if reflected:
            actions.append({"action": "report", "reason": "Confirmed exploitable findings — generate report", "command": f"fray report -i results.json -o report.html"})
        if bypassed:
            cats = list({r.get("category", "xss") for r in bypassed})
            actions.append({"action": "deep_test", "reason": "WAF bypasses found — test with smart mode", "command": f"fray test {target} -c {','.join(cats)} --smart --max 100"})
        if not reflected and not bypassed:
            actions.append({"action": "expand", "reason": "All blocked — try more categories", "command": f"fray test {target} -c sqli,ssrf,ssti,command_injection --smart"})
    elif recon:
        recs = recon.get("recommended_categories", [])
        if recs:
            cats = ",".join(r["category"] for r in recs[:5]) if isinstance(recs[0], dict) else ",".join(recs[:5])
            actions.append({"action": "test", "reason": "Recon complete — test recommended categories", "command": f"fray test {target} -c {cats} --smart"})
    if actions:
        out["suggested_actions"] = actions

    return out


def _build_sarif_output(target: str, results: list, tool_version: str = "") -> dict:
    """Build SARIF 2.1.0 output for GitHub Security tab / CodeQL integration.

    Usage:
        fray scan target.com --sarif -o results.sarif
        fray test target.com -c xss --sarif -o results.sarif

    Upload to GitHub:
        gh code-scanning upload-sarif --sarif results.sarif
    """
    from datetime import datetime as _dt

    if not tool_version:
        tool_version = __version__

    cwe_map = {
        "xss": {"id": "CWE-79", "name": "Cross-Site Scripting (XSS)"},
        "sqli": {"id": "CWE-89", "name": "SQL Injection"},
        "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
        "ssti": {"id": "CWE-1336", "name": "Server-Side Template Injection"},
        "command_injection": {"id": "CWE-78", "name": "OS Command Injection"},
        "xxe": {"id": "CWE-611", "name": "XML External Entity"},
        "path_traversal": {"id": "CWE-22", "name": "Path Traversal"},
        "open-redirect": {"id": "CWE-601", "name": "Open Redirect"},
        "crlf_injection": {"id": "CWE-113", "name": "CRLF Injection"},
        "prototype_pollution": {"id": "CWE-1321", "name": "Prototype Pollution"},
        "host_header_injection": {"id": "CWE-644", "name": "Host Header Injection"},
        "ldap_injection": {"id": "CWE-90", "name": "LDAP Injection"},
        "xpath_injection": {"id": "CWE-643", "name": "XPath Injection"},
    }

    severity_map = {
        "xss": "error", "sqli": "error", "command_injection": "error",
        "ssti": "error", "xxe": "error", "ssrf": "error",
        "path_traversal": "error", "prototype_pollution": "warning",
        "host_header_injection": "warning", "open-redirect": "warning",
        "crlf_injection": "warning", "ldap_injection": "error",
        "xpath_injection": "error",
    }

    # Collect unique rules from results
    rules_seen = {}
    sarif_results = []

    for r in results:
        if r.get("blocked"):
            continue  # Only report bypasses and reflected

        cat = r.get("category", "unknown")
        payload = r.get("payload", "")
        status = r.get("status", 0)
        reflected = r.get("reflected", False)
        param = r.get("param", "input")
        endpoint = r.get("url", r.get("endpoint", target))

        cwe = cwe_map.get(cat, {"id": "CWE-20", "name": "Improper Input Validation"})
        rule_id = f"fray/{cat}"

        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": cwe["name"],
                "shortDescription": {"text": cwe["name"]},
                "fullDescription": {
                    "text": f"Fray detected a potential {cwe['name']} vulnerability. "
                            f"A payload bypassed the WAF and {'was reflected in the response (confirmed exploitable)' if reflected else 'was not blocked'}."
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe['id'].split('-')[1]}.html",
                "properties": {
                    "tags": ["security", cat, cwe["id"]],
                },
                "defaultConfiguration": {
                    "level": severity_map.get(cat, "warning"),
                },
            }

        # Determine level
        level = "error" if reflected else severity_map.get(cat, "warning")

        message_text = (
            f"{'Confirmed reflected ' if reflected else 'Potential '}"
            f"{cwe['name']} on {endpoint}"
            f"{' (parameter: ' + param + ')' if param else ''}"
            f". Payload: {payload[:100]}"
            f"{' — payload appeared in response (exploitable)' if reflected else ' — payload bypassed WAF'}"
        )

        result_entry = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": endpoint,
                        "uriBaseId": "TARGET",
                    },
                },
                "logicalLocations": [{
                    "name": param or "request",
                    "kind": "parameter",
                }],
            }],
            "properties": {
                "payload": payload[:200],
                "httpStatus": status,
                "reflected": reflected,
                "category": cat,
                "cwe": cwe["id"],
            },
        }
        sarif_results.append(result_entry)

    # Build SARIF envelope
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Fray",
                    "version": tool_version,
                    "informationUri": "https://github.com/dalisecurity/fray",
                    "semanticVersion": tool_version,
                    "rules": list(rules_seen.values()),
                },
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "toolExecutionNotifications": [],
            }],
            "originalUriBaseIds": {
                "TARGET": {
                    "uri": target if target.endswith("/") else target + "/",
                },
            },
        }],
    }

    return sarif


def _build_recon_sarif_output(target: str, recon_result: dict, tool_version: str = "") -> dict:
    """Build SARIF 2.1.0 output from recon findings for GitHub/GitLab Security tab.

    Usage:
        fray recon target.com --sarif -o recon.sarif
        gh code-scanning upload-sarif --sarif recon.sarif
    """
    from datetime import datetime as _dt

    if not tool_version:
        tool_version = __version__

    atk = recon_result.get("attack_surface", {})
    findings = atk.get("findings", [])

    severity_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    cwe_map = {
        "origin ip": "CWE-200",
        "cors": "CWE-942",
        "admin panel": "CWE-306",
        "host header": "CWE-644",
        "graphql": "CWE-200",
        "http method": "CWE-749",
        "cve": "CWE-1395",
        "takeover": "CWE-672",
        "bypass": "CWE-693",
        "exposed": "CWE-538",
        "injectable": "CWE-20",
        "staging": "CWE-489",
        "csp": "CWE-1021",
        "tls": "CWE-295",
        "sri": "CWE-353",
        "robots": "CWE-538",
    }

    rules_seen = {}
    sarif_results = []

    for f in findings:
        sev = f.get("severity", "medium")
        finding_text = f.get("finding", "")
        level = severity_to_level.get(sev, "warning")

        # Derive rule ID from finding text
        rule_id = "fray/recon-finding"
        cwe_id = "CWE-200"
        for keyword, cwe in cwe_map.items():
            if keyword in finding_text.lower():
                rule_id = f"fray/recon-{keyword.replace(' ', '-')}"
                cwe_id = cwe
                break

        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": finding_text[:80],
                "shortDescription": {"text": finding_text[:120]},
                "fullDescription": {
                    "text": f"Fray recon detected: {finding_text}"
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
                "properties": {"tags": ["security", "recon", sev, cwe_id]},
                "defaultConfiguration": {"level": level},
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": finding_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target,
                        "uriBaseId": "TARGET",
                    },
                },
            }],
            "properties": {
                "severity": sev,
                "riskScore": atk.get("risk_score", 0),
                "riskLevel": atk.get("risk_level", "?"),
                "cwe": cwe_id,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Fray",
                    "version": tool_version,
                    "informationUri": "https://github.com/dalisecurity/fray",
                    "semanticVersion": tool_version,
                    "rules": list(rules_seen.values()),
                },
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "toolExecutionNotifications": [],
            }],
            "originalUriBaseIds": {
                "TARGET": {
                    "uri": target if target.endswith("/") else target + "/",
                },
            },
        }],
    }

    return sarif


def _validate_output_path(output: str) -> None:
    """Ensure output path is within the current working directory subtree."""
    resolved = Path(output).resolve()
    cwd = Path.cwd().resolve()
    if not str(resolved).startswith(str(cwd)):
        print(f"Error: Output path '{output}' is outside the current working directory.")
        print(f"  Resolved to: {resolved}")
        print(f"  CWD:         {cwd}")
        print("Use a relative path or a path under your working directory.")
        sys.exit(1)


def build_auth_headers(args) -> dict:
    """Build auth headers from CLI flags: --cookie, --bearer, --header, --login-flow, --load-session"""
    headers = {}

    # 1. Load saved session first (can be overridden by explicit flags)
    _auth_profile = None
    load_name = getattr(args, 'load_session', None)
    if load_name:
        try:
            from fray.auth import AuthProfile
            _auth_profile = AuthProfile.load_session(load_name)
            sess_headers = _auth_profile.get_headers()
            headers.update(sess_headers)
            sys.stderr.write(f"  Session loaded: {load_name} ({_auth_profile.auth_type})\n")
        except FileNotFoundError:
            sys.stderr.write(f"  ⚠  Session not found: {load_name}\n")
        except Exception as e:
            sys.stderr.write(f"  ⚠  Failed to load session: {e}\n")

    # 2. Explicit flags override loaded session
    if getattr(args, 'cookie', None):
        headers['Cookie'] = args.cookie
    if getattr(args, 'bearer', None):
        headers['Authorization'] = f'Bearer {args.bearer}'
    for h in getattr(args, 'header', None) or []:
        if ':' in h:
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
    if getattr(args, 'login_flow', None):
        session_cookie = _do_login_flow(args.login_flow)
        if session_cookie:
            # Merge with existing cookies
            existing = headers.get('Cookie', '')
            if existing:
                headers['Cookie'] = f"{existing}; {session_cookie}"
            else:
                headers['Cookie'] = session_cookie

    # 3. Save session if --save-session was requested
    save_name = getattr(args, 'save_session', None)
    if save_name and headers:
        try:
            from fray.auth import AuthProfile
            profile = _auth_profile or AuthProfile(auth_type="custom")
            # Populate from current headers
            if 'Cookie' in headers and not profile.cookie and not profile._session_cookies:
                profile.cookie = headers['Cookie']
            if 'Authorization' in headers and headers['Authorization'].startswith('Bearer '):
                token = headers['Authorization'][7:]
                if not profile.bearer_token and not profile._access_token:
                    profile.bearer_token = token
            profile.custom_headers = {k: v for k, v in headers.items()
                                       if k.lower() not in ('cookie', 'authorization')}
            path = profile.save_session(save_name)
            sys.stderr.write(f"  Session saved: {path}\n")
        except Exception as e:
            sys.stderr.write(f"  ⚠  Failed to save session: {e}\n")

    return headers


def _do_login_flow(login_spec: str) -> str:
    """Perform form-based login and return session cookies.

    Format: URL,field=value,field=value
    Example: https://example.com/login,username=admin,password=secret
    """
    import http.client
    import urllib.parse

    parts = login_spec.split(',')
    if len(parts) < 2:
        print("  ⚠️  --login-flow format: URL,field=value,field=value")
        print("     Example: https://example.com/login,username=admin,password=secret")
        return ""

    login_url = parts[0].strip()
    form_data = {}
    for part in parts[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            form_data[k.strip()] = v.strip()

    parsed = urllib.parse.urlparse(login_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/login'
    use_ssl = parsed.scheme == 'https'

    body = urllib.parse.urlencode(form_data)
    req_headers = {
        'Host': host,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(body)),
        'User-Agent': 'Fray Auth',
    }

    try:
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)

        conn.request('POST', path, body=body, headers=req_headers)
        resp = conn.getresponse()
        resp.read()  # consume body

        # Extract Set-Cookie headers
        cookies = []
        for header_name, header_val in resp.getheaders():
            if header_name.lower() == 'set-cookie':
                # Extract cookie name=value (before ;)
                cookie_part = header_val.split(';')[0].strip()
                cookies.append(cookie_part)

        conn.close()

        if cookies:
            cookie_str = '; '.join(cookies)
            print(f"  🔑 Login successful — captured {len(cookies)} session cookie(s)")
            return cookie_str
        else:
            status = resp.status
            print(f"  ⚠️  Login returned HTTP {status} but no Set-Cookie headers")
            print(f"     Try using --cookie directly if you have a session token")
            return ""

    except Exception as e:
        print(f"  ❌ Login flow failed: {e}")
        return ""


def _is_piped():
    """True when stdin is a pipe (not a terminal)."""
    return not sys.stdin.isatty()


def _read_targets(args) -> list:
    """Read target(s) from args.target or stdin (pipe-friendly).

    Supports:
        fray recon https://example.com           # single target
        cat domains.txt | fray recon              # piped targets
        cat domains.txt | fray recon -            # explicit stdin marker
        echo https://example.com | fray detect    # single pipe
    """
    targets = []

    # 1. Explicit CLI argument ("-" means "read from stdin")
    target_arg = getattr(args, 'target', None)
    if target_arg and target_arg != '-':
        targets.append(target_arg)

    # 2. Stdin (piped, or "-" forces stdin read)
    if _is_piped() or target_arg == '-':
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            targets.append(line)

    if not targets:
        print("  Error: No target specified.")
        print("  Usage: fray <command> <url>")
        print("     or: cat domains.txt | fray <command>")
        sys.exit(1)

    # Normalize: ensure scheme
    normalized = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(('http://', 'https://')):
            t = f'https://{t}'
        normalized.append(t)

    return normalized


def cmd_detect(args):
    """Detect WAF vendor on target"""
    from fray.detector import WAFDetector
    targets = _read_targets(args)
    detector = WAFDetector()
    verify = not getattr(args, 'insecure', False)
    multi = len(targets) > 1

    for target in targets:
        results = detector.detect_waf(target, verify_ssl=verify)
        if multi:
            # Compact one-line output for pipe mode
            waf = results.get('waf_vendor', 'none') if isinstance(results, dict) else 'none'
            conf = results.get('confidence', 0) if isinstance(results, dict) else 0
            waf = waf or 'none'
            print(f"{target}\t{waf}\t{conf}%")
        else:
            detector.print_results(results)
            # Next-step hints (single target, TTY)
            if not getattr(args, 'json', False):
                try:
                    from fray.interactive import next_steps
                    waf_name = results.get('waf_vendor', '') if isinstance(results, dict) else ''
                    next_steps(target, "detect", waf=waf_name or '')
                except Exception:
                    pass


def _cmd_test_multi(args, targets):
    """Pipe mode: run WAF test on each target, output one JSONL line per target."""
    from fray.tester import WAFTester
    custom_headers = build_auth_headers(args)
    if getattr(args, 'no_follow_redirects', False):
        max_redirects = 0
    else:
        max_redirects = getattr(args, 'redirect_limit', 5) or 5

    for target in targets:
        try:
            tester = WAFTester(
                target=target,
                timeout=args.timeout,
                delay=args.delay,
                verify_ssl=not getattr(args, 'insecure', False),
                custom_headers=custom_headers or None,
                verbose=False,
                max_redirects=max_redirects,
                jitter=getattr(args, 'jitter', 0.0),
                stealth=getattr(args, 'stealth', False),
                rate_limit=getattr(args, 'rate_limit', 0.0),
            )

            all_payloads = []
            if args.category:
                cat_dir = PAYLOADS_DIR / args.category
                if cat_dir.exists():
                    for pf in sorted(cat_dir.glob("*.json")):
                        all_payloads.extend(tester.load_payloads(str(pf)))
            elif getattr(args, 'all', False):
                for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
                    if cat_dir.is_dir():
                        for pf in sorted(cat_dir.glob("*.json")):
                            all_payloads.extend(tester.load_payloads(str(pf)))

            if not all_payloads:
                print(json.dumps({"target": target, "error": "no payloads loaded"}))
                continue

            max_payloads = getattr(args, 'max', None)
            if max_payloads:
                all_payloads = all_payloads[:max_payloads]

            results = tester.test_payloads(all_payloads)
            total = len(results)
            bypassed = sum(1 for r in results if r.get("bypassed"))
            blocked = sum(1 for r in results if r.get("blocked"))
            errors = total - bypassed - blocked

            print(json.dumps({
                "target": target,
                "total": total,
                "bypassed": bypassed,
                "blocked": blocked,
                "errors": errors,
                "bypass_rate": f"{bypassed/total*100:.1f}%" if total else "0%",
            }, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"target": target, "error": str(e)}))

    sys.stderr.write(f"\n  Fray test complete: {len(targets)} targets\n")


def cmd_test(args):
    """Run WAF tests against target"""
    targets = _read_targets(args)
    multi = len(targets) > 1

    if multi:
        # Pipe mode: run each target sequentially, compact JSONL output
        _cmd_test_multi(args, targets)
        return

    # Single target: set args.target for the rest of the function
    args.target = targets[0]

    # Scope validation — block testing if target is out of scope
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  ⛔ Target is OUT OF SCOPE")
            print(f"  {reason}")
            print(f"  Scope file: {scope_file}")
            print(f"\n  Fray will not test targets outside your scope file.")
            sys.exit(1)
        else:
            print(f"  ✅ Target in scope — {reason}")

    from fray.tester import WAFTester

    # Auth profile support: --auth-profile overrides --cookie/--bearer
    auth_profile_path = getattr(args, 'auth_profile', None)
    if auth_profile_path:
        from fray.auth import AuthProfile
        auth_prof = AuthProfile.from_file(auth_profile_path)
        if not auth_prof.authenticate(verbose=not getattr(args, 'json', False)):
            print("Error: Authentication failed. Check your auth profile.", file=sys.stderr)
            sys.exit(1)
        custom_headers = auth_prof.get_headers()
    else:
        # Build custom headers from auth flags
        custom_headers = build_auth_headers(args)
    # Redirect policy
    if getattr(args, 'no_follow_redirects', False):
        max_redirects = 0
    else:
        max_redirects = getattr(args, 'redirect_limit', 5) or 5

    delay = args.delay
    rl = getattr(args, 'rate_limit', 0.0)

    # Auto-throttle: fingerprint rate limits before testing
    if getattr(args, 'auto_throttle', False):
        from fray.scanner import auto_throttle
        throttle_info = auto_throttle(
            args.target, timeout=args.timeout,
            verify_ssl=not getattr(args, 'insecure', False),
            quiet=getattr(args, 'json', False),
        )
        rec_delay = throttle_info.get("recommended_delay", 0.5)
        if rec_delay > delay:
            delay = rec_delay
        rps = throttle_info.get("threshold_rps")
        if rps and (rl == 0.0 or rps < rl):
            rl = rps * 0.6

    tester = WAFTester(
        target=args.target,
        timeout=args.timeout,
        delay=delay,
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        verbose=getattr(args, 'verbose', False),
        max_redirects=max_redirects,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=rl,
    )

    all_payloads = []

    if args.category:
        category_dir = PAYLOADS_DIR / args.category
        if not category_dir.exists():
            print(f"Error: Category '{args.category}' not found.")
            print(f"Available: {', '.join(list_categories())}")
            sys.exit(1)
        for pf in sorted(category_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))
    elif args.payload_file:
        all_payloads.extend(tester.load_payloads(args.payload_file))
    elif args.smart:
        # Smart mode: run recon, show results, prompt user before testing
        from fray.recon import run_recon
        print(f"\n🔍 Running reconnaissance on {args.target}...")
        recon = run_recon(args.target, timeout=args.timeout,
                          headers=custom_headers or None)
        fp = recon.get("fingerprint", {})
        techs = fp.get("technologies", {})
        recommended = recon.get("recommended_categories", [])
        hdr = recon.get("headers", {})
        tls = recon.get("tls", {})

        # Show recon summary
        print(f"\n{'─' * 55}")
        print(f"  Target:  {args.target}")
        tls_ver = tls.get("tls_version") or "?"
        print(f"  TLS:     {tls_ver}")
        print(f"  Headers: {hdr.get('score', 0)}%")
        if techs:
            tech_list = ", ".join(f"{t} ({c:.0%})" for t, c in techs.items())
            print(f"  Stack:   {tech_list}")
        else:
            print(f"  Stack:   (not detected)")
        print(f"{'─' * 55}")

        # Build category list with payload counts
        all_categories = sorted([
            d.name for d in PAYLOADS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ])

        def _count_payloads_in_cat(cat_name):
            cat_dir = PAYLOADS_DIR / cat_name
            count = 0
            for pf in cat_dir.glob("*.json"):
                try:
                    data = json.loads(pf.read_text(encoding="utf-8"))
                    plist = data.get("payloads", data) if isinstance(data, dict) else data
                    count += len(plist) if isinstance(plist, list) else 0
                except Exception:
                    pass
            return count

        auto_yes = getattr(args, 'yes', False)

        if recommended:
            print(f"\n  Recommended categories (based on detected stack):\n")
            for i, cat in enumerate(recommended, 1):
                count = _count_payloads_in_cat(cat)
                print(f"    {i}. {cat:<25} ({count} payloads)")
            total_rec = sum(_count_payloads_in_cat(c) for c in recommended)
            total_all = sum(_count_payloads_in_cat(c) for c in all_categories)
            print(f"\n    Total: {total_rec} payloads (vs {total_all} if all categories)")
            print()
            if auto_yes:
                choice = 'y'
                print("  → Auto-accepting recommended categories (-y)")
            else:
                choice = input("  [Y] Run recommended  [A] Run all  [N] Cancel  [1,3,5] Pick: ").strip().lower()
        else:
            print(f"\n  No specific tech detected. All categories available:\n")
            for i, cat in enumerate(all_categories, 1):
                count = _count_payloads_in_cat(cat)
                print(f"    {i}. {cat:<25} ({count} payloads)")
            print()
            if auto_yes:
                choice = 'y'
                print("  → Auto-accepting all categories (-y)")
            else:
                choice = input("  [Y] Run all  [N] Cancel  [1,3,5] Pick specific: ").strip().lower()
            recommended = all_categories  # treat "y" as all for this path

        if choice == 'n' or choice == '':
            print("  Cancelled.")
            sys.exit(0)

        selected_cats = []
        if choice == 'y':
            selected_cats = recommended
        elif choice == 'a':
            selected_cats = all_categories
        else:
            # Parse comma-separated numbers
            try:
                indices = [int(x.strip()) for x in choice.split(",")]
                source = recommended if recommended != all_categories else all_categories
                for idx in indices:
                    if 1 <= idx <= len(source):
                        selected_cats.append(source[idx - 1])
                if not selected_cats:
                    print("  Invalid selection. Cancelled.")
                    sys.exit(1)
            except ValueError:
                print("  Invalid input. Cancelled.")
                sys.exit(1)

        print(f"\n  Loading: {', '.join(selected_cats)}")
        for cat in selected_cats:
            cat_dir = PAYLOADS_DIR / cat
            if cat_dir.is_dir():
                for pf in sorted(cat_dir.glob("*.json")):
                    all_payloads.extend(tester.load_payloads(str(pf)))
    else:
        # Load all payloads
        for cat_dir in sorted(PAYLOADS_DIR.iterdir()):
            if cat_dir.is_dir():
                for pf in sorted(cat_dir.glob("*.json")):
                    all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print("No payloads loaded. Check category name or payload file path.", file=sys.stderr)
        sys.exit(1)

    json_mode = getattr(args, 'json', False)
    if not json_mode:
        print(f"\nLoaded {len(all_payloads)} payloads")

    # Adaptive mode: probe → score → test → mutate
    if args.smart:
        from fray.evolve import adaptive_test
        results, stats, profile = adaptive_test(
            tester, all_payloads, max_payloads=args.max or 50
        )
    else:
        # Detect WAF vendor for smart sort cross-domain intelligence
        _waf_vendor = ""
        try:
            from fray.adaptive_cache import _detect_vendor, _extract_domain
            _waf_vendor = _detect_vendor(_extract_domain(args.target))
        except Exception:
            pass
        results = tester.test_payloads(all_payloads, max_payloads=args.max,
                                       quiet=json_mode, waf_vendor=_waf_vendor,
                                       resume=getattr(args, 'resume', False))

    # --mutate: auto-mutate blocked payloads and re-test
    mutate_n = getattr(args, 'mutate', 0)
    if mutate_n:
        from fray.mutator import mutate_blocked_results
        blocked_count = sum(1 for r in results if r.get('blocked'))
        if blocked_count > 0 and not json_mode:
            sys.stderr.write(f"\n  Mutating {blocked_count} blocked payload(s) × {mutate_n} variants...\n")
        mutations = mutate_blocked_results(results, max_per_payload=mutate_n)
        if mutations:
            mutation_payloads = [m["payload"] for m in mutations]
            mutation_results = tester.test_payloads(mutation_payloads, max_payloads=len(mutation_payloads),
                                                     quiet=json_mode)
            # Tag mutation results with strategy info
            for mr, mi in zip(mutation_results, mutations):
                mr["mutation_strategy"] = mi["strategy"]
                mr["original_payload"] = mi["original"]
                mr["is_mutation"] = True
            mutation_bypassed = sum(1 for r in mutation_results if not r.get('blocked'))
            if not json_mode:
                sys.stderr.write(f"  Mutations: {len(mutation_results)} tested, {mutation_bypassed} bypassed\n")
            results.extend(mutation_results)

    # Blind injection detection (--blind)
    blind_findings = []
    if getattr(args, 'blind', False):
        from fray.blind import BlindDetector
        blind_cats = [args.category] if args.category else None
        oob_server = getattr(args, 'oob_server', '') or ''
        blind_det = BlindDetector(
            tester, param=args.param or 'input',
            oob_server=oob_server,
            verbose=not json_mode,
        )
        blind_findings = blind_det.detect_all(categories=blind_cats)
        # Add blind findings as result entries
        for bf in blind_findings:
            results.append({
                'payload': bf.payload,
                'status': 0,
                'blocked': False,
                'detection_method': bf.detection_method,
                'category': bf.category,
                'subcategory': bf.subcategory,
                'confidence': bf.confidence,
                'blind': True,
                'bypass_confidence': 95 if bf.confidence == 'confirmed' else 70,
                'fp_score': 5 if bf.confidence == 'confirmed' else 25,
                'confidence_label': bf.confidence,
                'evidence': bf.evidence,
                'baseline_ms': bf.baseline_ms,
                'actual_ms': bf.actual_ms,
                'timestamp': bf.timestamp or __import__('datetime').datetime.now().isoformat(),
            })

    # Build report dict
    from datetime import datetime as _dt
    total = len(results)
    blocked = sum(1 for r in results if r.get('blocked'))
    passed = total - blocked
    duration = "N/A"
    if tester.start_time:
        elapsed = _dt.now() - tester.start_time
        minutes = int(elapsed.total_seconds() // 60)
        seconds = int(elapsed.total_seconds() % 60)
        duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    report = {
        'target': args.target,
        'timestamp': _dt.now().isoformat(),
        'duration': duration,
        'summary': {
            'total': total,
            'blocked': blocked,
            'passed': passed,
            'block_rate': f"{(blocked/total*100):.2f}%" if total > 0 else "0%",
        },
        'results': results,
    }

    # SARIF output (GitHub Security tab / CodeQL compatible)
    if getattr(args, 'sarif', False):
        sarif = _build_sarif_output(target=args.target, results=results)
        sarif_str = json.dumps(sarif, indent=2, ensure_ascii=False)
        output_file = args.output or "fray_results.sarif"
        _validate_output_path(output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(sarif_str)
        findings = len(sarif["runs"][0]["results"])
        rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
        print(f"\n  SARIF 2.1.0 report generated: {output_file}")
        print(f"  {findings} finding(s) across {rules} rule(s)")
        print(f"\n  Upload to GitHub:")
        print(f"    gh code-scanning upload-sarif --sarif {output_file}")
        return

    # AI-optimized output
    ai_mode = getattr(args, 'ai', False)
    if ai_mode:
        from fray.recon import run_recon
        recon = run_recon(args.target, timeout=args.timeout,
                          headers=custom_headers or None)
        ai_out = _build_ai_output(target=args.target, results=results, recon=recon)
        _json_print(ai_out)
        if args.output:
            _validate_output_path(args.output)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(ai_out, f, indent=2, ensure_ascii=False)
        return

    # JSON output to stdout
    if getattr(args, 'json', False):
        _json_print(report)
    else:
        # Auto-detect output format from extension
        out = args.output or "fray_results.json"
        _validate_output_path(out)
        if out.endswith('.html') or out.endswith('.htm'):
            from fray.reporter import SecurityReportGenerator
            gen = SecurityReportGenerator()
            gen.generate_html_report(report, out)
            print(f"\n  HTML report saved to {out}")
        elif out.endswith('.md'):
            from fray.reporter import generate_markdown_report
            generate_markdown_report(report, out)
            print(f"\n  Markdown report saved to {out}")
        else:
            tester.generate_report(results, output=out)
            print(f"\nResults saved to {out}")

    # Also save to file if -o given explicitly (even with --json)
    if getattr(args, 'json', False) and args.output:
        _validate_output_path(args.output)
        out = args.output
        if out.endswith('.html') or out.endswith('.htm'):
            from fray.reporter import SecurityReportGenerator
            gen = SecurityReportGenerator()
            gen.generate_html_report(report, out)
            print(f"\n  HTML report saved to {out}")
        else:
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

    # Auto-generate formatted report if requested (legacy --report-format flag)
    report_fmt = getattr(args, 'report_format', None)
    if report_fmt:
        from fray.reporter import SecurityReportGenerator
        gen = SecurityReportGenerator()
        report_data = {
            "target": args.target,
            "results": results,
        }
        if report_fmt == 'markdown':
            report_file = (args.output or "fray_results.json").replace('.json', '.md')
            gen.generate_markdown_report(report_data, report_file)
        else:
            report_file = (args.output or "fray_results.json").replace('.json', '.html')
            gen.generate_html_report(report_data, report_file)
        print(f"Report generated: {report_file}")

    # Send webhook notification if requested
    if args.webhook:
        from fray.webhook import send_webhook
        report = {
            "target": args.target,
            "duration": tester.start_time and str(tester.start_time) or "N/A",
            "summary": {
                "total": len(results),
                "blocked": sum(1 for r in results if r.get("blocked")),
                "passed": sum(1 for r in results if not r.get("blocked")),
                "block_rate": f"{sum(1 for r in results if r.get('blocked')) / len(results) * 100:.1f}%" if results else "0%",
            }
        }
        # Calculate duration properly
        if tester.start_time:
            from datetime import datetime
            elapsed = datetime.now() - tester.start_time
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            report["duration"] = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        send_webhook(args.webhook, report)

    # --notify (generic notification)
    notify_url = getattr(args, 'notify', None)
    if notify_url:
        from fray.webhook import send_generic_notification
        passed = sum(1 for r in results if not r.get("blocked"))
        sev = "critical" if passed > 5 else "high" if passed > 0 else "low"
        summary = {
            "total_tested": len(results),
            "blocked": sum(1 for r in results if r.get("blocked")),
            "bypassed": passed,
            "block_rate": f"{sum(1 for r in results if r.get('blocked')) / len(results) * 100:.1f}%" if results else "0%",
            "_severity": sev,
        }
        send_generic_notification(notify_url, "test", args.target, summary)

    # Next-step hints (TTY only)
    if not getattr(args, 'json', False) and not getattr(args, 'quiet', False):
        try:
            from fray.interactive import next_steps
            _bypassed = sum(1 for r in results if not r.get("blocked"))
            _blocked = sum(1 for r in results if r.get("blocked"))
            _cats = [getattr(args, 'category', 'xss')]
            next_steps(args.target, "test", bypassed=_bypassed, blocked=_blocked,
                       categories=_cats)
        except Exception:
            pass


def cmd_report(args):
    """Generate HTML or Markdown report from results"""
    if args.sample:
        from fray.reporter import generate_sample_report
        generate_sample_report()
        return

    from fray.reporter import SecurityReportGenerator
    if not args.input:
        print("Error: provide --input results.json or use --sample for a demo report")
        sys.exit(1)
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    generator = SecurityReportGenerator()
    fmt = getattr(args, 'format', 'html') or 'html'
    if fmt == 'markdown':
        output = args.output.replace('.html', '.md') if args.output.endswith('.html') else args.output
    else:
        output = args.output
    _validate_output_path(output)
    if fmt == 'markdown':
        generator.generate_markdown_report(data, output)
    else:
        generator.generate_html_report(data, output)
    print(f"Report generated: {output}")


def cmd_payloads(args):
    """List available payload categories"""
    categories = list_categories()
    print(f"\nFray v{__version__} — Payload Categories\n")
    print(f"{'Category':<30} {'Files':<8} {'Location'}")
    print("-" * 70)
    total_files = 0
    for cat in categories:
        cat_dir = PAYLOADS_DIR / cat
        files = list(cat_dir.glob("*.json")) + list(cat_dir.glob("*.txt"))
        count = len(files)
        total_files += count
        print(f"  {cat:<28} {count:<8} payloads/{cat}/")
    print("-" * 70)
    print(f"  {'TOTAL':<28} {total_files}")
    print(f"\nUsage: fray test <url> -c <category>")


def cmd_scan(args):
    """Auto scan: crawl → param discovery → payload injection."""
    from fray.scanner import run_scan, print_scan_result, InjectionPoint

    custom_headers = build_auth_headers(args)
    json_mode = getattr(args, 'json', False)

    # Browser pre-crawl: discover JS-rendered endpoints before static scan
    browser_result = None
    if getattr(args, 'browser', False):
        from fray.browser import check_playwright, browser_crawl
        if not check_playwright():
            print("  Error: Playwright not installed.")
            print("  Install: pip install playwright && playwright install chromium")
            sys.exit(1)
        browser_result = browser_crawl(
            target=args.target,
            max_pages=getattr(args, 'max_pages', 20),
            max_depth=getattr(args, 'depth', 2),
            timeout=args.timeout,
            quiet=json_mode,
        )

    scan = run_scan(
        target=args.target,
        category=getattr(args, 'category', None) or 'xss',
        max_payloads=args.max,
        max_depth=args.depth,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        quiet=json_mode,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
        scope_file=getattr(args, 'scope', None),
        workers=getattr(args, 'workers', 1),
        use_auto_throttle=getattr(args, 'auto_throttle', False),
    )

    # Merge browser-discovered injection points into scan results
    if browser_result and not browser_result.get("error") and scan.crawl:
        existing = {(ip.url, ip.param, ip.method) for ip in scan.crawl.injection_points}
        added = 0
        for bip in browser_result.get("injection_points", []):
            key = (bip["url"], bip["param"], bip["method"])
            if key not in existing:
                scan.crawl.injection_points.append(
                    InjectionPoint(url=bip["url"], param=bip["param"],
                                   method=bip["method"], source=bip.get("source", "browser")))
                existing.add(key)
                added += 1
        if added > 0 and not json_mode:
            print(f"\n  🌐 Browser mode added {added} extra injection point(s)")

    # SARIF output (GitHub Security tab / CodeQL compatible)
    if getattr(args, 'sarif', False):
        scan_dict = scan.to_dict()
        test_results = scan_dict.get("test_results", [])
        sarif = _build_sarif_output(target=args.target, results=test_results)
        sarif_str = json.dumps(sarif, indent=2, ensure_ascii=False)
        output_file = getattr(args, 'output', None) or "fray_scan.sarif"
        _validate_output_path(output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(sarif_str)
        findings = len(sarif["runs"][0]["results"])
        rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
        print(f"\n  SARIF 2.1.0 report generated: {output_file}")
        print(f"  {findings} finding(s) across {rules} rule(s)")
        print(f"\n  Upload to GitHub:")
        print(f"    gh code-scanning upload-sarif --sarif {output_file}")
        return

    ai_mode = getattr(args, 'ai', False)

    if ai_mode:
        # Run quick recon for technology fingerprinting
        from fray.recon import run_recon
        recon = run_recon(args.target, timeout=getattr(args, 'timeout', 8),
                          headers=custom_headers or None)
        scan_dict = scan.to_dict()
        ai_out = _build_ai_output(
            target=args.target,
            results=scan_dict.get("test_results", []),
            recon=recon,
            crawl=scan_dict.get("crawl", {}),
        )
        _json_print(ai_out)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(ai_out, f, indent=2, ensure_ascii=False)
        return

    if json_mode:
        _json_print(scan.to_dict())
    else:
        print_scan_result(scan)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        out = args.output
        if out.endswith('.html') or out.endswith('.htm'):
            from fray.reporter import SecurityReportGenerator
            gen = SecurityReportGenerator()
            scan_dict = scan.to_dict()
            report_data = {
                "target": args.target,
                "results": scan_dict.get("test_results", []),
            }
            gen.generate_html_report(report_data, out)
            if not json_mode:
                print(f"\n  HTML report saved to {out}")
        else:
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(scan.to_dict(), f, indent=2, ensure_ascii=False)
            if not json_mode:
                print(f"\n  Results saved to {out}")

    # Interop exports: Burp / ZAP / Nuclei
    scan_dict = scan.to_dict()
    test_results = scan_dict.get("test_results", [])

    if getattr(args, 'burp', None):
        from fray.interop import export_burp_xml
        _validate_output_path(args.burp)
        export_burp_xml(test_results, args.target, args.burp)
        print(f"\n  Burp Suite XML exported: {args.burp}")

    if getattr(args, 'zap', None):
        from fray.interop import export_zap_json
        _validate_output_path(args.zap)
        export_zap_json(test_results, args.target, args.zap)
        print(f"\n  ZAP alerts JSON exported: {args.zap}")

    if getattr(args, 'nuclei_export', None):
        from fray.interop import export_nuclei_templates
        templates = export_nuclei_templates(test_results, args.target, args.nuclei_export)
        if templates:
            print(f"\n  Nuclei templates exported: {len(templates)} template(s) → {args.nuclei_export}/")
            print(f"  Run: nuclei -t {args.nuclei_export}/ -u {args.target}")
        else:
            print(f"\n  No bypasses found — no Nuclei templates generated.")

    # Webhook notification
    notify_url = getattr(args, 'notify', None)
    if notify_url:
        from fray.webhook import send_generic_notification
        sd = scan.to_dict()
        sm = sd.get("summary", {})
        passed = sm.get("passed", 0)
        sev = "critical" if passed > 5 else "high" if passed > 0 else "low"
        summary = {
            "total_tested": sm.get("total_tested", 0),
            "blocked": sm.get("blocked", 0),
            "bypassed": passed,
            "reflected": sm.get("reflected", 0),
            "block_rate": sm.get("block_rate", "N/A"),
            "duration": sd.get("duration", "N/A"),
            "_severity": sev,
        }
        send_generic_notification(notify_url, "scan", args.target, summary)

    # Next-step hints (TTY only)
    if not getattr(args, 'json', False):
        try:
            from fray.interactive import next_steps
            sd = scan.to_dict()
            sm = sd.get("summary", {})
            _bypassed = sm.get("passed", 0)
            next_steps(args.target, "scan", bypassed=_bypassed)
        except Exception:
            pass


def cmd_stats(args):
    """Show payload database statistics or WAF effectiveness leaderboard"""
    if getattr(args, 'waf', False):
        from fray.adaptive_cache import get_waf_leaderboard, print_waf_leaderboard
        if getattr(args, 'json', False):
            _json_print(get_waf_leaderboard())
        else:
            print_waf_leaderboard()
        return

    if getattr(args, 'waf_market', False):
        from fray.adaptive_cache import get_waf_market_share, print_waf_market_share
        if getattr(args, 'json', False):
            _json_print(get_waf_market_share())
        else:
            print_waf_market_share()
        return

    if getattr(args, 'trend', None):
        from fray.adaptive_cache import get_trend
        domain = args.trend
        data = get_trend(domain)
        if getattr(args, 'json', False):
            _json_print(data)
        else:
            print(f"\n  Trend for {data['domain']} ({data['snapshot_count']} snapshots): {data['trend']}")
            for s in data.get('snapshots', [])[-5:]:
                print(f"    {s['timestamp'][:10]}  risk={s.get('risk_score',0):>3}  "
                      f"hygiene={s.get('dns_hygiene_score',0):>3}/{s.get('dns_hygiene_grade','?')}  "
                      f"findings={s.get('findings_count',0)}")
            print()
        return

    from fray.stats import collect_stats, print_stats
    stats = collect_stats()
    if args.json:
        _json_print(stats.to_dict())
    else:
        print_stats(stats)


def cmd_version(args):
    """Show version"""
    print(f"Fray v{__version__}")


def cmd_completions(args):
    """Generate shell completion scripts (bash/zsh/fish)."""
    from fray.completions import generate_completion
    shell = getattr(args, "shell", None)
    if not shell:
        sys.stderr.write("Usage: fray completions {bash,zsh,fish}\n")
        return 1
    print(generate_completion(shell))


def cmd_doctor(args):
    """Run environment diagnostics and auto-fix issues"""
    from fray.doctor import run_doctor
    run_doctor(auto_fix=args.fix, verbose=args.verbose)


def cmd_submit_payload(args):
    """Submit a payload to the Fray community database via GitHub PR"""
    from fray.submit import run_submit_payload
    run_submit_payload(
        payload=args.payload,
        category=args.category,
        subcategory=args.subcategory,
        description=args.description,
        technique=args.technique,
        contributor_name=args.name,
        contributor_github=args.github,
        file=args.file,
        dry_run=args.dry_run,
    )


def cmd_validate(args):
    """Validate WAF configuration and generate report"""
    if args.output:
        _validate_output_path(args.output)
    from fray.validate import run_validate
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_validate(
        target=args.target,
        waf=args.waf,
        categories=categories,
        max_payloads=args.max,
        output=args.output,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
    )


def cmd_graph(args):
    """Visualize the attack surface of a target."""
    from fray.recon import run_recon
    from fray.graph import build_graph, print_graph

    custom_headers = build_auth_headers(args)

    # Run full recon
    recon = run_recon(args.target, timeout=getattr(args, 'timeout', 8),
                      headers=custom_headers or None)

    # Optional deep mode: also fetch JS endpoints + historical URLs
    js_endpoints = None
    historical = None
    if getattr(args, 'deep', False):
        from fray.recon import discover_js_endpoints, discover_historical_urls
        js_endpoints = discover_js_endpoints(args.target,
                                              timeout=getattr(args, 'timeout', 8),
                                              extra_headers=custom_headers or None)
        historical = discover_historical_urls(args.target,
                                              timeout=getattr(args, 'timeout', 8),
                                              extra_headers=custom_headers or None)

    graph = build_graph(args.target, recon,
                        js_endpoints=js_endpoints,
                        historical=historical)

    if getattr(args, 'json', False):
        _json_print(graph.to_dict())
    else:
        print_graph(graph)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(graph.to_dict(), f, indent=2, ensure_ascii=False)
        if not getattr(args, 'json', False):
            print(f"  Graph saved to {args.output}")

    # Next-step hints
    if not getattr(args, 'json', False):
        try:
            from fray.interactive import next_steps
            next_steps(args.target, "graph")
        except Exception:
            pass


def cmd_bounty(args):
    """Run bug bounty scope fetch and batch WAF testing"""
    if args.output:
        _validate_output_path(args.output)
    from fray.bounty import run_bounty
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_bounty(
        platform=args.platform,
        program=args.program,
        urls_file=args.urls,
        categories=categories,
        max_payloads=args.max,
        timeout=args.timeout,
        delay=args.delay,
        output=args.output,
        scope_only=args.scope_only,
        force=args.force,
        smart=not args.no_smart,
        workers=getattr(args, 'workers', 1) or 1,
    )


def cmd_ci(args):
    """Generate GitHub Actions workflow for automated WAF testing"""
    from fray.ci import run_ci
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    run_ci(
        action=args.action,
        target=args.target,
        categories=categories,
        max_payloads=args.max,
        webhook=args.webhook,
        fail_on_bypass=args.fail_on_bypass,
        no_comment=args.no_comment,
        minimal=args.minimal,
        output_dir=args.output_dir,
    )


def cmd_recon(args):
    """Run target reconnaissance and fingerprinting"""
    targets = _read_targets(args)
    auth_headers = build_auth_headers(args) or None
    multi = len(targets) > 1

    # --params mode: standalone parameter mining (brute-force)
    if getattr(args, 'params', False):
        from fray.recon import mine_params, print_mined_params
        for target in targets:
            result = mine_params(target, timeout=getattr(args, 'timeout', 8),
                                 extra_headers=auth_headers)
            if multi or getattr(args, 'json', False):
                print(json.dumps({"target": target, **result}, ensure_ascii=False))
            else:
                print_mined_params(target, result)
        if not multi and getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    # --history mode: standalone historical URL discovery
    if getattr(args, 'history', False):
        from fray.recon import discover_historical_urls, print_historical_urls
        for target in targets:
            result = discover_historical_urls(target, timeout=getattr(args, 'timeout', 8),
                                              extra_headers=auth_headers)
            if multi or getattr(args, 'json', False):
                print(json.dumps({"target": target, **result}, ensure_ascii=False))
            else:
                print_historical_urls(target, result)
        if not multi and getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    # --js mode: standalone JS endpoint extraction
    if getattr(args, 'js', False):
        from fray.recon import discover_js_endpoints, print_js_endpoints
        for target in targets:
            result = discover_js_endpoints(target, timeout=getattr(args, 'timeout', 8),
                                           extra_headers=auth_headers)
            if multi or getattr(args, 'json', False):
                print(json.dumps({"target": target, **result}, ensure_ascii=False))
            else:
                print_js_endpoints(target, result)
        if not multi and getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\n  Results saved to {args.output}")
        return

    from fray.recon import run_recon, print_recon

    # CI/CD mode: --fail-on implies --ci
    ci_mode = getattr(args, 'ci', False) or getattr(args, 'fail_on', None) is not None
    fail_on = getattr(args, 'fail_on', None)
    _SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    fail_threshold = _SEVERITY_RANK.get(fail_on, 0) if fail_on else 0

    # Determine scan mode
    if getattr(args, 'fast', False):
        scan_mode = "fast"
    elif getattr(args, 'deep', False):
        scan_mode = "deep"
    else:
        scan_mode = "default"

    stealth = getattr(args, 'stealth', False)
    retirejs = getattr(args, 'retirejs', False)

    all_results = []
    for target in targets:
        json_mode = getattr(args, 'json', False)
        ai_mode = getattr(args, 'ai', False)
        quiet_mode = getattr(args, 'quiet', False)
        suppress_progress = json_mode or ai_mode or ci_mode or quiet_mode
        result = run_recon(target, timeout=getattr(args, 'timeout', 8),
                           headers=auth_headers, mode=scan_mode,
                           stealth=stealth, retirejs=retirejs,
                           leak=getattr(args, 'leak', False),
                           quiet=suppress_progress)

        # SARIF output for recon
        if getattr(args, 'sarif', False):
            sarif = _build_recon_sarif_output(target=target, recon_result=result)
            sarif_str = json.dumps(sarif, indent=2, ensure_ascii=False)
            output_file = getattr(args, 'output', None) or "fray_recon.sarif"
            _validate_output_path(output_file)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(sarif_str)
            findings = len(sarif["runs"][0]["results"])
            rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
            print(f"\n  SARIF 2.1.0 recon report generated: {output_file}")
            print(f"  {findings} finding(s) across {rules} rule(s)")
            print(f"\n  Upload to GitHub:")
            print(f"    gh code-scanning upload-sarif --sarif {output_file}")
            return

        if multi:
            # Pipe mode: compact one-line JSONL per target (attack surface summary)
            atk = result.get("attack_surface", {})
            summary = {
                "target": target,
                "risk_score": atk.get("risk_score", 0),
                "risk_level": atk.get("risk_level", "?"),
                "subdomains": atk.get("subdomains", 0),
                "admin_panels": atk.get("admin_panels", 0),
                "open_admin_panels": atk.get("open_admin_panels", 0),
                "graphql_endpoints": atk.get("graphql_endpoints", 0),
                "api_endpoints": atk.get("api_endpoints", 0),
                "exposed_files": atk.get("exposed_files", 0),
                "injectable_params": atk.get("injectable_params", 0),
                "staging_envs": atk.get("staging_envs", []),
                "waf": atk.get("waf_vendor"),
                "cdn": atk.get("cdn"),
                "technologies": atk.get("technologies", []),
                "findings": len(atk.get("findings", [])),
                "per_subdomain_waf_cdn": result.get("cloud_distribution", {}).get("per_subdomain", []),
                "multi_waf": result.get("cloud_distribution", {}).get("multi_waf", False),
                "multi_cdn": result.get("cloud_distribution", {}).get("multi_cdn", False),
            }
            print(json.dumps(summary, ensure_ascii=False))
            all_results.append(result)
            continue

        # ── CI/CD mode: compact JSON, severity gate ──
        if ci_mode:
            atk = result.get("attack_surface", {})
            findings = atk.get("findings", [])
            ci_out = {
                "target": target,
                "risk_score": atk.get("risk_score", 0),
                "risk_level": atk.get("risk_level", "?"),
                "findings_count": len(findings),
                "findings": findings,
                "waf": atk.get("waf_vendor"),
                "per_subdomain_waf_cdn": result.get("cloud_distribution", {}).get("per_subdomain", []),
                "exit_code": 0,
            }
            # Check severity gate
            if fail_threshold:
                breaching = [f for f in findings
                             if _SEVERITY_RANK.get(f.get("severity"), 0) >= fail_threshold]
                if breaching:
                    ci_out["exit_code"] = 1
                    ci_out["gate_failed"] = True
                    ci_out["gate_threshold"] = fail_on
                    ci_out["breaching_findings"] = breaching

            # Save output if requested
            if getattr(args, 'output', None):
                _validate_output_path(args.output)
                out = args.output
                if out.endswith('.html') or out.endswith('.htm'):
                    from fray.reporter import SecurityReportGenerator
                    gen = SecurityReportGenerator()
                    gen.generate_recon_html_report(result, out)
                    sys.stderr.write(f"  Recon HTML report saved to {out}\n")
                else:
                    with open(out, "w", encoding="utf-8") as f:
                        json.dump(result, f, indent=2, ensure_ascii=False)
                    sys.stderr.write(f"  Recon saved to {out}\n")

            print(json.dumps(ci_out, ensure_ascii=False))
            sys.exit(ci_out["exit_code"])

        # Single target: full output
        ai_mode = getattr(args, 'ai', False)
        if ai_mode:
            ai_out = _build_ai_output(target=target, recon=result)
            _json_print(ai_out)
            if getattr(args, 'output', None):
                _validate_output_path(args.output)
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(ai_out, f, indent=2, ensure_ascii=False)
            return

        if getattr(args, 'json', False):
            _json_print(result)
        elif not quiet_mode:
            print_recon(result)

        # --ai-summary: LLM-powered (or local fallback) actionable summary
        if getattr(args, 'ai_summary', False):
            from fray.ai_bypass import _llm_available
            provider = _llm_available()
            if not getattr(args, 'json', False):
                if provider:
                    label = f"🤖 AI Summary (powered by {provider.capitalize()})"
                else:
                    label = "🤖 AI Summary"
                pad = max(0, 44 - len(label))
                print(f"\n  ┌{'─' * 46}┐")
                print(f"  │  {label}{' ' * pad}│")
                print(f"  └{'─' * 46}┘\n")
                sys.stdout.flush()
            summary = _ai_summarize_recon(target, result)
            if summary:
                for line in summary.split("\n"):
                    print(f"  {line}")
                if not provider:
                    print(f"\n  💡 Set OPENAI_API_KEY or ANTHROPIC_API_KEY for richer AI analysis")
                print()
            else:
                print("  ⚠ AI summary failed.\n")

        # --compare: diff against previous scan
        recon_diff = None
        compare = getattr(args, 'compare', None)
        if compare:
            from fray.recon import _load_previous_recon, diff_recon, print_recon_diff
            if compare == "last":
                previous = _load_previous_recon(result.get("host", ""))
            else:
                try:
                    with open(compare, "r", encoding="utf-8") as f:
                        previous = json.load(f)
                except Exception as e:
                    print(f"  Error loading compare file: {e}")
                    previous = None
            if previous and previous.get("timestamp") != result.get("timestamp"):
                recon_diff = diff_recon(result, previous)
                if getattr(args, 'json', False):
                    _json_print({"diff": recon_diff})
                else:
                    print_recon_diff(recon_diff)
            elif not previous:
                print("  No previous scan found for this host. Run recon again to compare.")

        # --notify: send Slack/Discord/Teams notification
        notify_url = getattr(args, 'notify', None)
        if notify_url:
            from fray.webhook import send_recon_notification
            send_recon_notification(notify_url, target, result, diff=recon_diff)

        # Save output if requested
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            out = args.output
            if out.endswith('.html') or out.endswith('.htm'):
                from fray.reporter import SecurityReportGenerator
                gen = SecurityReportGenerator()
                gen.generate_recon_html_report(result, out)
                print(f"  Recon HTML report saved to {out}")
            else:
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"  Recon saved to {out}")

        # Auto-export to ~/.fray/recon/{domain}/ (or --export-dir override)
        no_export = getattr(args, 'no_export', False)
        if not no_export and not ci_mode:
            import os as _os
            from fray.recon.pipeline import export_recon_dir
            export_dir = getattr(args, 'export_dir', None)
            if not export_dir:
                domain = result.get("host", "unknown")
                export_dir = _os.path.join(_os.path.expanduser("~"), ".fray", "recon", domain)
            created = export_recon_dir(result, export_dir)
            # Also save full JSON alongside structured files
            full_json_path = _os.path.join(export_dir, "recon.json")
            with open(full_json_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            created["recon.json"] = full_json_path
            n_files = len(created)
            total_bytes = sum(_os.path.getsize(p) for p in created.values())
            print(f"\n  📁 Saved to {export_dir}/  ({n_files} files, {total_bytes:,} bytes)")

        # ── Interactive menu (TTY only, single target, non-pipe) ──
        no_interactive = getattr(args, 'no_interactive', False)
        is_interactive = (sys.stdin.isatty() and sys.stdout.isatty()
                          and not json_mode and not ai_mode
                          and not ci_mode and not quiet_mode
                          and not no_interactive)
        if is_interactive:
            try:
                from fray.interactive import ReconInteractive
                menu = ReconInteractive(target, result,
                                        export_dir=export_dir if not no_export else "")
                menu.run()
            except Exception:
                pass  # Never break recon flow due to interactive menu

    # Multi-target summary
    if multi and all_results:
        total = len(all_results)
        crit = sum(1 for r in all_results if r.get("attack_surface", {}).get("risk_level") == "CRITICAL")
        high = sum(1 for r in all_results if r.get("attack_surface", {}).get("risk_level") == "HIGH")
        sys.stderr.write(f"\n  Fray recon complete: {total} targets — {crit} CRITICAL, {high} HIGH\n")
        # Return highest risk_score across all targets for exit code mapping
        max_rs = max(r.get("attack_surface", {}).get("risk_score", 0) for r in all_results)
        return {"risk_score": max_rs}

    # Single target: return risk_score for exit code mapping (#190)
    if not multi and result:
        rs = result.get("attack_surface", {}).get("risk_score", 0)
        return {"risk_score": rs}


def cmd_smuggle(args):
    """HTTP request smuggling detection."""
    from fray.smuggling import run_smuggling_detection, print_smuggle_report
    from dataclasses import asdict

    if not args.target:
        print("Error: target URL required. Usage: fray smuggle <url>")
        sys.exit(1)

    report = run_smuggling_detection(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not getattr(args, 'insecure', False),
        verbose=True,
    )

    if getattr(args, 'json', False):
        _json_print(asdict(report))
    else:
        print_smuggle_report(report)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        print(f"\n  Results saved to {args.output}")

    # Next-step hints
    if not getattr(args, 'json', False):
        try:
            from fray.interactive import next_steps
            next_steps(args.target, "smuggle")
        except Exception:
            pass

    # Exit code: 1 if vulnerable (CI integration)
    if report.vulnerable:
        sys.exit(1)


def cmd_diff(args):
    """Compare two scan results and surface regressions."""
    from fray.diff import run_diff, print_diff
    from dataclasses import asdict

    diff = run_diff(args.before, args.after)

    if getattr(args, 'json', False):
        _json_print(asdict(diff))
    else:
        print_diff(diff)

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(diff), f, indent=2, ensure_ascii=False)
        print(f"\n  Diff saved to {args.output}")

    # Exit code: 1 if regressions found (useful for CI)
    if diff.verdict == "REGRESSED":
        sys.exit(1)


def cmd_bypass(args):
    """WAF bypass scoring — evasion-optimized testing"""
    from fray.tester import WAFTester
    from fray.bypass import run_bypass, resolve_waf_name, WAF_EVASION_HINTS

    # If --list-wafs, just show supported vendors
    if getattr(args, 'list_wafs', False):
        print(f"\nFray v{__version__} — Supported WAF Targets\n")
        for key, info in sorted(WAF_EVASION_HINTS.items()):
            print(f"  {info['label']:<30} --waf {key}")
        print(f"\n  Use: fray bypass <url> --waf <name> -c xss")
        return

    # Scope validation
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  ⛔ Target is OUT OF SCOPE")
            print(f"  {reason}")
            print(f"  Scope file: {scope_file}")
            print(f"\n  Fray will not test targets outside your scope file.")
            sys.exit(1)
        else:
            print(f"  ✅ Target in scope — {reason}")

    # Build tester
    custom_headers = build_auth_headers(args)
    tester = WAFTester(
        target=args.target,
        timeout=getattr(args, 'timeout', 8),
        delay=getattr(args, 'delay', 0.5),
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        verbose=getattr(args, 'verbose', False),
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
    )

    # Load payloads
    all_payloads = []
    if args.category:
        category_dir = PAYLOADS_DIR / args.category
        if not category_dir.exists():
            print(f"Error: Category '{args.category}' not found.")
            print(f"Available: {', '.join(list_categories())}")
            sys.exit(1)
        for pf in sorted(category_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))
    else:
        # Default: load xss payloads (most common bypass target)
        xss_dir = PAYLOADS_DIR / "xss"
        if xss_dir.exists():
            for pf in sorted(xss_dir.glob("*.json")):
                all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print("Error: No payloads loaded. Use -c <category> to specify.")
        sys.exit(1)

    # Auto-inject CSP bypass payloads when weak CSP detected
    csp_injected = 0
    if args.category != "csp_bypass":
        try:
            from fray.csp import get_csp_from_headers, analyze_csp
            import http.client, urllib.parse as _urlparse
            _parsed = _urlparse.urlparse(args.target if args.target.startswith("http") else f"https://{args.target}")
            _host = _parsed.hostname
            _port = _parsed.port or (443 if _parsed.scheme == "https" else 80)
            _use_ssl = _parsed.scheme == "https"
            try:
                if _use_ssl:
                    import ssl as _ssl
                    _ctx = _ssl.create_default_context()
                    if getattr(args, 'insecure', False):
                        _ctx.check_hostname = False
                        _ctx.verify_mode = _ssl.CERT_NONE
                    _conn = http.client.HTTPSConnection(_host, _port, context=_ctx, timeout=5)
                else:
                    _conn = http.client.HTTPConnection(_host, _port, timeout=5)
                _conn.request("GET", _parsed.path or "/", headers={"Host": _host})
                _resp = _conn.getresponse()
                _resp.read()
                _hdrs = {k.lower(): v for k, v in _resp.getheaders()}
                _conn.close()
                csp_val, csp_ro = get_csp_from_headers(_hdrs)
                csp_analysis = analyze_csp(csp_val, report_only=csp_ro)
                if csp_analysis.bypass_techniques:
                    csp_dir = PAYLOADS_DIR / "csp_bypass"
                    if csp_dir.exists():
                        technique_set = set(csp_analysis.bypass_techniques)
                        for pf in sorted(csp_dir.glob("*.json")):
                            # Only load payload files matching detected techniques
                            if pf.stem in technique_set:
                                loaded = tester.load_payloads(str(pf))
                                all_payloads.extend(loaded)
                                csp_injected += len(loaded)
            except Exception:
                pass  # CSP probe failed — continue with normal payloads
        except ImportError:
            pass

    loaded_msg = f"\n  Loaded {len(all_payloads)} payloads"
    if csp_injected:
        loaded_msg += f" (including {csp_injected} CSP bypass payloads)"
    print(loaded_msg)

    # Run bypass assessment
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)

    scorecard = run_bypass(
        tester=tester,
        payloads=all_payloads,
        waf_name=getattr(args, 'waf', None),
        max_payloads=getattr(args, 'max', 50),
        max_mutations=getattr(args, 'mutations', 5),
        mutation_budget=getattr(args, 'mutation_budget', 30),
        param=getattr(args, 'param', 'input'),
        verbose=True,
        output_file=output_file,
        json_output=getattr(args, 'json', False),
        category=getattr(args, 'category', 'xss') or 'xss',
    )

    # Interop exports: Burp / ZAP / Nuclei / Share
    from dataclasses import asdict
    bypass_results = scorecard.bypasses if scorecard else []

    if getattr(args, 'burp', None) and bypass_results:
        from fray.interop import export_burp_xml
        _validate_output_path(args.burp)
        export_burp_xml(bypass_results, args.target, args.burp)
        print(f"\n  Burp Suite XML exported: {args.burp}")

    if getattr(args, 'zap', None) and bypass_results:
        from fray.interop import export_zap_json
        _validate_output_path(args.zap)
        export_zap_json(bypass_results, args.target, args.zap)
        print(f"\n  ZAP alerts JSON exported: {args.zap}")

    if getattr(args, 'nuclei_export', None):
        from fray.interop import export_nuclei_templates
        templates = export_nuclei_templates(bypass_results, args.target, args.nuclei_export)
        if templates:
            print(f"\n  Nuclei templates exported: {len(templates)} template(s) → {args.nuclei_export}/")
            print(f"  Run: nuclei -t {args.nuclei_export}/ -u {args.target}")
        else:
            print(f"\n  No bypasses found — no Nuclei templates generated.")

    if getattr(args, 'share', False) and bypass_results:
        from fray.interop import export_bypass_recipes
        recipe_file = f"fray_bypass_recipes_{int(time.time())}.json"
        export_bypass_recipes(bypass_results, args.target, recipe_file, anonymize=True)
        print(f"\n  🔄 Bypass recipes exported (anonymized): {recipe_file}")
        print(f"     {len([b for b in bypass_results if not b.get('blocked')])} recipe(s) ready for community sharing")

    # Next-step hints
    if not getattr(args, 'json', False):
        try:
            from fray.interactive import next_steps
            _bypassed = len([b for b in bypass_results if not b.get('blocked')]) if bypass_results else 0
            next_steps(args.target, "bypass", bypassed=_bypassed)
        except Exception:
            pass


def cmd_ai_bypass(args):
    """AI-assisted WAF bypass — LLM-generated payloads with adaptive feedback"""
    from fray.tester import WAFTester
    from fray.ai_bypass import run_ai_bypass
    from dataclasses import asdict

    # Scope validation
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  Target is OUT OF SCOPE: {reason}")
            sys.exit(1)

    if not args.target:
        print("Error: target URL is required.")
        sys.exit(1)

    custom_headers = build_auth_headers(args)
    tester = WAFTester(
        target=args.target,
        timeout=getattr(args, 'timeout', 8),
        delay=getattr(args, 'delay', 0.5),
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
    )

    json_mode = getattr(args, 'json', False)

    result = run_ai_bypass(
        tester=tester,
        category=getattr(args, 'category', 'xss'),
        param=getattr(args, 'param', 'input'),
        rounds=getattr(args, 'rounds', 3),
        max_per_round=getattr(args, 'max_per_round', 10),
        try_headers=not getattr(args, 'no_headers', False),
        verbose=True,
        json_output=json_mode,
    )

    # Save output
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(result), f, indent=2, ensure_ascii=False)
        if not json_mode:
            print(f"\n  Results saved to {output_file}")

    # Next-step hints
    if not json_mode:
        try:
            from fray.interactive import next_steps
            next_steps(args.target, "bypass", bypassed=result.total_bypassed)
        except Exception:
            pass


def cmd_agent(args):
    """Self-improving payload agent — iterative probe → test → mutate → learn loop"""
    from fray.tester import WAFTester
    from fray.agent import run_agent

    targets = _read_targets(args)
    args.target = targets[0]

    # Scope validation
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(args.target, scope)
        if not in_scope:
            print(f"\n  Target is OUT OF SCOPE: {reason}")
            sys.exit(1)

    custom_headers = build_auth_headers(args)
    tester = WAFTester(
        target=args.target,
        timeout=getattr(args, 'timeout', 8),
        delay=getattr(args, 'delay', 0.5),
        verify_ssl=not getattr(args, 'insecure', False),
        custom_headers=custom_headers or None,
        jitter=getattr(args, 'jitter', 0.0),
        stealth=getattr(args, 'stealth', False),
        rate_limit=getattr(args, 'rate_limit', 0.0),
    )

    # Load payloads
    all_payloads = []
    category = getattr(args, 'category', 'xss') or 'xss'
    for cat in category.split(','):
        cat = cat.strip()
        cat_dir = PAYLOADS_DIR / cat
        if cat_dir.exists():
            for pf in sorted(cat_dir.glob("*.json")):
                all_payloads.extend(tester.load_payloads(str(pf)))

    if not all_payloads:
        print(f"Error: No payloads loaded for category '{category}'.")
        print(f"Available: {', '.join(list_categories())}")
        sys.exit(1)

    json_mode = getattr(args, 'json', False)

    results, stats, profile = run_agent(
        tester=tester,
        payloads=all_payloads,
        max_rounds=getattr(args, 'rounds', 5),
        budget=getattr(args, 'budget', 100),
        param=getattr(args, 'param', 'input'),
        category=category,
        verbose=not json_mode,
        use_cache=not getattr(args, 'no_cache', False),
        use_ai=getattr(args, 'ai', False),
    )

    # JSON output
    if json_mode:
        output = {
            "target": args.target,
            "rounds": stats.rounds_completed,
            "total_requests": stats.total_requests,
            "bypasses": stats.total_bypasses,
            "bypass_rate": stats.bypass_rate,
            "techniques": sorted(stats.unique_bypass_techniques),
            "results": [r for r in results if not r.get("blocked")],
        }
        _json_print(output, default=str)

    # Save output
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)
        output = {
            "target": args.target,
            "rounds": stats.rounds_completed,
            "total_requests": stats.total_requests,
            "bypasses": stats.total_bypasses,
            "bypass_rate": stats.bypass_rate,
            "techniques": sorted(stats.unique_bypass_techniques),
            "results": results,
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)
        if not json_mode:
            print(f"\n  Results saved to {output_file}")

    # Webhook notification
    webhook_url = getattr(args, 'notify', None)
    if webhook_url:
        from fray.webhook import send_generic_notification
        send_generic_notification(
            webhook_url, "agent", args.target,
            {"Bypasses": stats.total_bypasses,
             "Rounds": stats.rounds_completed,
             "Requests": stats.total_requests,
             "Bypass Rate": stats.bypass_rate},
        )

    # Next-step hints
    if not json_mode:
        try:
            from fray.interactive import next_steps
            next_steps(args.target, "agent", bypassed=stats.total_bypasses)
        except Exception:
            pass


def cmd_feed(args):
    """Threat intelligence feed — auto-discover & ingest new attack vectors"""
    from fray.threat_intel import run_feed, _SOURCES

    # Parse sources
    sources = None
    if hasattr(args, 'sources') and args.sources:
        sources = [s.strip() for s in args.sources.split(',')]

    # Parse --since (e.g. "7d", "30d", "2w")
    since_days = 7
    if hasattr(args, 'since') and args.since:
        s = args.since.strip().lower()
        if s.endswith('d'):
            since_days = int(s[:-1])
        elif s.endswith('w'):
            since_days = int(s[:-1]) * 7
        elif s.endswith('m'):
            since_days = int(s[:-1]) * 30
        else:
            since_days = int(s)

    json_mode = getattr(args, 'json', False)

    # List available sources
    if getattr(args, 'list_sources', False):
        if json_mode:
            _json_print({"sources": list(_SOURCES.keys())})
        else:
            print("\n  Available threat intelligence sources:\n")
            for key, src in _SOURCES.items():
                print(f"    {key:12s}  {src['label']}")
            print(f"\n  Use: fray feed --sources nvd,cisa,github")
        return

    payloads, stats = run_feed(
        sources=sources,
        since_days=since_days,
        category_filter=getattr(args, 'category', '') or '',
        auto_add=getattr(args, 'auto_add', False),
        dry_run=getattr(args, 'dry_run', False),
        test_target=getattr(args, 'test_target', '') or '',
        test_delay=getattr(args, 'delay', 0.3),
        test_timeout=getattr(args, 'timeout', 8),
        test_verify_ssl=not getattr(args, 'insecure', False),
        verbose=not json_mode,
    )

    # JSON output
    if json_mode:
        output = {
            "sources_queried": stats.sources_queried,
            "items_fetched": stats.items_fetched,
            "payloads_new": stats.payloads_new,
            "payloads_duplicate": stats.payloads_duplicate,
            "payloads_added": stats.payloads_added,
            "payloads_tested": stats.payloads_tested,
            "payloads_bypassed": stats.payloads_bypassed,
            "payloads_blocked": stats.payloads_blocked,
            "test_target": stats.test_target,
            "errors": stats.errors,
            "payloads": [p.to_fray_format(i) for i, p in enumerate(payloads)],
        }
        _json_print(output, default=str)

    # Save output
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)
        output = {
            "sources_queried": stats.sources_queried,
            "items_fetched": stats.items_fetched,
            "payloads_new": stats.payloads_new,
            "payloads_added": stats.payloads_added,
            "payloads": [p.to_fray_format(i) for i, p in enumerate(payloads)],
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)
        if not json_mode:
            print(f"\n  Results saved to {output_file}")

    # Cache warming (#46)
    if getattr(args, 'warm_cache', False):
        from fray.adaptive_cache import warm_cache_from_threat_intel
        warm_result = warm_cache_from_threat_intel(verbose=not json_mode)
        if json_mode:
            _json_print({"cache_warm": warm_result}, default=str)
        elif warm_result["payloads_loaded"] > 0:
            print(f"\n  Cache warmed: {warm_result['payloads_loaded']} payloads"
                  f" ({len(warm_result['categories'])} categories)")

    # Webhook notification
    webhook_url = getattr(args, 'notify', None)
    if webhook_url:
        from fray.webhook import send_generic_notification
        send_generic_notification(
            webhook_url, "feed", "threat-intel",
            {"New Payloads": stats.payloads_new,
             "Added": stats.payloads_added,
             "Sources": stats.sources_queried,
             "Tested": stats.payloads_tested,
             "Bypassed": stats.payloads_bypassed},
        )


def cmd_update(args):
    """Pull latest payload database from cloud (R2 / GitHub Releases)."""
    from fray.cloud_sync import update_payloads

    json_mode = getattr(args, 'json', False)
    source = getattr(args, 'source', 'auto') or 'auto'

    manifest = update_payloads(source=source, verbose=not json_mode)

    if json_mode:
        output = manifest or {"status": "up_to_date"}
        _json_print(output, default=str)


def cmd_sync(args):
    """Publish or pull payload database to/from cloud."""
    from fray.cloud_sync import run_sync, load_config, save_config

    json_mode = getattr(args, 'json', False)
    push = getattr(args, 'push', False)
    pull = getattr(args, 'pull', False)
    source = getattr(args, 'source', 'auto') or 'auto'
    tag = getattr(args, 'tag', '') or ''

    # Handle --configure
    if getattr(args, 'configure', False):
        cfg = load_config()
        import sys as _sys
        print("\n  Fray Cloud Sync Configuration")
        print("  ─────────────────────────────")
        print(f"  Current config: ~/.fray/cloud.json\n")

        prompts = [
            ("github_repo", "GitHub repo", cfg.github_repo),
            ("r2_endpoint", "R2 endpoint URL", cfg.r2_endpoint or "(not set)"),
            ("r2_bucket", "R2 bucket name", cfg.r2_bucket),
            ("r2_access_key", "R2 access key", cfg.r2_access_key or "(not set)"),
            ("r2_secret_key", "R2 secret key", "(hidden)" if cfg.r2_secret_key else "(not set)"),
            ("d1_api_url", "D1 API URL", cfg.d1_api_url or "(not set)"),
            ("d1_api_token", "D1 API token", "(hidden)" if cfg.d1_api_token else "(not set)"),
        ]
        for attr, label, default in prompts:
            try:
                val = input(f"  {label} [{default}]: ").strip()
                if val:
                    setattr(cfg, attr, val)
            except (EOFError, KeyboardInterrupt):
                print()
                return

        save_config(cfg)
        print(f"\n  Config saved to ~/.fray/cloud.json")
        return

    # Handle --status
    if getattr(args, 'status', False):
        cfg = load_config()
        from fray.cloud_sync import r2_available, d1_available
        print(f"\n  Fray Cloud Sync Status")
        print(f"  ─────────────────────")
        print(f"  GitHub repo:  {cfg.github_repo}")
        print(f"  R2 storage:   {'configured' if r2_available(cfg) else 'not configured'}")
        print(f"  D1 database:  {'configured' if d1_available(cfg) else 'not configured'}")
        print(f"  Share learn:  {'enabled' if cfg.share_patterns else 'disabled'}")

        from pathlib import Path as _P
        last = _P.home() / ".fray" / "last_update.json"
        if last.exists():
            info = json.loads(last.read_text())
            print(f"\n  Last update:  {info.get('last_update', 'never')}")
            print(f"  Source:       {info.get('source', '?')}")
            print(f"  Payloads:     {info.get('total_payloads', '?')}")
        else:
            print(f"\n  Last update:  never")
        return

    result = run_sync(push=push, pull=pull, source=source, tag=tag,
                      verbose=not json_mode)

    if json_mode:
        _json_print(result, default=str)


def cmd_todo(args):
    """Internal TODO list — private, stored in ~/.fray/todo.json (never in repo)."""
    todo_path = Path.home() / ".fray" / "todo.json"
    todo_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing
    items = []
    if todo_path.exists():
        try:
            items = json.loads(todo_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            items = []

    json_mode = getattr(args, 'json', False)
    action = getattr(args, 'action', 'list')
    text = getattr(args, 'text', None)

    # --- add ---
    if action == 'add' and text:
        priority = getattr(args, 'priority', 'medium') or 'medium'
        new_id = max((i.get("id", 0) for i in items), default=0) + 1
        items.append({
            "id": new_id,
            "content": " ".join(text),
            "status": "pending",
            "priority": priority,
            "created": __import__('datetime').datetime.now().isoformat(),
        })
        todo_path.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
        if not json_mode:
            print(f"  Added #{new_id}: {' '.join(text)} [{priority}]")
        else:
            _json_print(items[-1])
        return

    # --- done ---
    if action == 'done':
        tid = getattr(args, 'id', None)
        if tid is not None:
            for item in items:
                if item.get("id") == tid:
                    item["status"] = "completed"
                    todo_path.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
                    if not json_mode:
                        print(f"  Completed #{tid}: {item['content']}")
                    return
            print(f"  Not found: #{tid}")
        return

    # --- rm ---
    if action == 'rm':
        tid = getattr(args, 'id', None)
        if tid is not None:
            before = len(items)
            items = [i for i in items if i.get("id") != tid]
            if len(items) < before:
                todo_path.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
                if not json_mode:
                    print(f"  Removed #{tid}")
            else:
                print(f"  Not found: #{tid}")
        return

    # --- list (default) ---
    if json_mode:
        _json_print(items)
        return

    show_all = getattr(args, 'all', False)
    pending = [i for i in items if i.get("status") != "completed"]
    completed = [i for i in items if i.get("status") == "completed"]
    display = items if show_all else pending

    if not display:
        print("  No TODO items. Add one with: fray todo add \"your task\"")
        return

    priority_sym = {"high": "\033[31m●\033[0m", "medium": "\033[33m●\033[0m", "low": "\033[2m●\033[0m"}
    status_sym = {"completed": "\033[32m✓\033[0m", "in_progress": "\033[94m→\033[0m", "pending": " "}

    print(f"\n  \033[1mFray Internal TODO\033[0m  \033[2m(~/.fray/todo.json)\033[0m\n")
    for item in display:
        sid = item.get("id", "?")
        st = status_sym.get(item.get("status", "pending"), " ")
        pr = priority_sym.get(item.get("priority", "medium"), "●")
        content = item.get("content", "")
        struck = f"\033[9m\033[2m{content}\033[0m" if item.get("status") == "completed" else content
        print(f"  {st} {pr} #{sid:<3d} {struck}")

    if not show_all and completed:
        print(f"\n  \033[2m({len(completed)} completed — use --all to show)\033[0m")
    print()


def cmd_harden(args):
    """OWASP Top 10 misconfiguration checks + security header hardening audit"""
    from fray.recon import run_recon
    from fray.recon.fingerprint import check_security_headers, generate_header_fix_snippets
    from fray.recon.http import fetch_headers

    if not args.target:
        print("Error: target URL is required.")
        sys.exit(1)

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    json_mode = getattr(args, 'json', False)

    # Phase 1: Headers audit
    if not json_mode:
        from fray.output import console, print_header, print_phase
        print_header(f"Fray Harden v{__version__}", target=target)
        print_phase(1, "Security headers audit...")

    headers = fetch_headers(target, timeout=8)
    if not headers:
        print(f"  Error: Could not fetch headers from {target}")
        sys.exit(1)

    hdr_result = check_security_headers(headers)

    # Rate-limit headers
    rl_headers = {
        "x-ratelimit-limit": "Rate limit ceiling",
        "x-ratelimit-remaining": "Remaining requests",
        "retry-after": "Retry-After",
        "ratelimit-limit": "Standard RateLimit",
        "ratelimit-policy": "RateLimit policy",
    }
    rl_present = {}
    for hk, desc in rl_headers.items():
        if hk in headers:
            rl_present[hk] = headers[hk]

    # Phase 2: Full recon for OWASP checks
    if not json_mode:
        print_phase(2, "OWASP Top 10 misconfiguration scan...")

    recon = run_recon(target, timeout=8, mode="fast")
    atk = recon.get("attack_surface", {})
    findings = atk.get("findings", [])
    tls = recon.get("tls", {})
    csp = recon.get("csp", {})
    cookies = recon.get("cookies", {})
    fl = recon.get("frontend_libs", {})

    # Build OWASP checks
    owasp = {}

    # A01: Broken Access Control
    a01_issues = []
    cors = recon.get("cors", {})
    if cors.get("allows_any_origin"):
        a01_issues.append(("high", "CORS allows any origin (*)"))
    if atk.get("open_admin_panels", 0) > 0:
        a01_issues.append(("critical", f"{atk['open_admin_panels']} open admin panel(s)"))
    owasp["A01_Access_Control"] = a01_issues

    # A02: Cryptographic Failures
    a02_issues = []
    tls_ver = str(tls.get("tls_version", ""))
    if "1.0" in tls_ver:
        a02_issues.append(("high", "TLS 1.0 detected — upgrade to 1.2+"))
    elif "1.1" in tls_ver:
        a02_issues.append(("medium", "TLS 1.1 detected — upgrade to 1.2+"))
    if "Strict-Transport-Security" not in [h.get("name", "") for h in hdr_result.get("present", {}).values()]:
        if "HSTS" not in str(hdr_result.get("present", {})):
            a02_issues.append(("high", "Missing HSTS header"))
    cert_days = tls.get("cert_days_remaining")
    if cert_days is not None and cert_days < 30:
        a02_issues.append(("medium", f"TLS certificate expires in {cert_days} day(s)"))
    owasp["A02_Crypto_Failures"] = a02_issues

    # A05: Security Misconfiguration
    a05_issues = []
    if not csp.get("present"):
        a05_issues.append(("high", "No Content-Security-Policy header"))
    elif csp.get("weaknesses"):
        for w in csp["weaknesses"][:3]:
            a05_issues.append(("medium", f"CSP: {w.get('description', '?')}"))
    if atk.get("exposed_files", 0) > 0:
        a05_issues.append(("medium", f"{atk['exposed_files']} exposed sensitive file(s)"))
    owasp["A05_Misconfiguration"] = a05_issues

    # A06: Vulnerable Components
    a06_issues = []
    vuln_libs = fl.get("vulnerable_libs", 0)
    if vuln_libs > 0:
        a06_issues.append(("high", f"{vuln_libs} vulnerable frontend lib(s)"))
        for v in fl.get("vulnerabilities", [])[:3]:
            a06_issues.append(("medium", f"{v.get('id', '?')}: {v.get('summary', '')}"))
    sri_missing = fl.get("sri_missing", 0)
    if sri_missing > 0:
        a06_issues.append(("medium", f"{sri_missing} external script(s) without SRI"))
    owasp["A06_Vulnerable_Components"] = a06_issues

    # A07: Auth Failures
    a07_issues = []
    for ci in cookies.get("issues", []):
        issue = ci.get("issue", "")
        if "HttpOnly" in issue:
            a07_issues.append(("medium", f"Cookie missing HttpOnly"))
        if "SameSite" in issue:
            a07_issues.append(("low", f"Cookie missing SameSite"))
        if "Secure" in issue:
            a07_issues.append(("medium", f"Cookie missing Secure flag"))
    owasp["A07_Auth_Failures"] = a07_issues

    # JSON output
    if json_mode:
        report = {
            "target": target,
            "headers": hdr_result,
            "rate_limit_headers": rl_present,
            "owasp_checks": {k: [{"severity": s, "issue": i} for s, i in v] for k, v in owasp.items()},
            "risk_score": atk.get("risk_score", 0),
            "risk_level": atk.get("risk_level", "?"),
        }
        _json_print(report)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        return

    # Rich terminal output
    from rich.table import Table
    from rich.panel import Panel

    # Security Headers table
    score = hdr_result.get("score", 0)
    grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"
    grade_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(f"\n  Security Headers: [{grade_color}]{grade}[/{grade_color}] ({score}/100)")

    htbl = Table(show_header=True, box=None, pad_edge=False)
    htbl.add_column("Header", min_width=30)
    htbl.add_column("Status", width=10, justify="center")
    htbl.add_column("Value / Issue", min_width=30)

    for name, info in sorted(hdr_result.get("present", {}).items()):
        htbl.add_row(name, "[green]PRESENT[/green]", f"[dim]{str(info.get('value', ''))[:60]}[/dim]")
    for name, info in sorted(hdr_result.get("missing", {}).items()):
        sev = info.get("severity", "medium")
        sev_color = "red" if sev == "high" else "yellow"
        htbl.add_row(name, f"[{sev_color}]MISSING[/{sev_color}]", f"[dim]{info.get('description', '')}[/dim]")

    console.print()
    console.print(htbl)

    # Rate-limit headers
    if rl_present:
        console.print(f"\n  Rate-Limit Headers: [green]PRESENT[/green]")
        for hk, hv in rl_present.items():
            console.print(f"    {hk}: [dim]{hv}[/dim]")
    else:
        console.print(f"\n  Rate-Limit Headers: [yellow]NONE DETECTED[/yellow]")

    # Fix snippets
    fix_snippets = hdr_result.get("fix_snippets")
    if fix_snippets:
        console.print(f"\n  [bold]Fix Snippets (copy-paste):[/bold]")
        for platform, snippet in fix_snippets.items():
            console.print(f"\n  [cyan]{platform}:[/cyan]")
            for line in snippet.strip().split("\n"):
                console.print(f"    [dim]{line}[/dim]")

    # OWASP checks
    console.print()
    print_phase(3, "OWASP Top 10 Results")

    total_issues = 0
    for category, issues in owasp.items():
        if issues:
            total_issues += len(issues)
            console.print(f"\n  [bold red]{category}[/bold red]  ({len(issues)} finding(s))")
            for sev, issue in issues:
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim"}.get(sev, "white")
                console.print(f"    [{sev_color}][{sev.upper()}][/{sev_color}] {issue}")
        else:
            console.print(f"\n  [bold green]{category}[/bold green]  PASS")

    # Summary
    passed = sum(1 for v in owasp.values() if not v)
    failed = sum(1 for v in owasp.values() if v)
    console.print(f"\n  [bold]Summary:[/bold] {passed} passed, {failed} failed, {total_issues} total finding(s)")
    console.print(f"  Risk: {atk.get('risk_level', '?')} ({atk.get('risk_score', 0)}/100)")
    console.print()

    if getattr(args, 'output', None):
        _validate_output_path(args.output)
        report = {
            "target": target,
            "headers": hdr_result,
            "rate_limit_headers": rl_present,
            "owasp_checks": {k: [{"severity": s, "issue": i} for s, i in v] for k, v in owasp.items()},
            "risk_score": atk.get("risk_score", 0),
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        console.print(f"  Report saved to {args.output}")

    # Next-step hints
    if not json_mode:
        try:
            from fray.interactive import next_steps
            next_steps(target, "harden")
        except Exception:
            pass


def cmd_go(args):
    """Zero-knowledge guided pipeline: recon → smart test → report.

    One command, no flags needed. Fray figures out what to test based on recon.
    """
    if not args.target:
        print("Usage: fray go <url>")
        print("  Example: fray go https://example.com")
        sys.exit(1)

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    from fray.interactive import GuidedPipeline

    auth_headers = build_auth_headers(args) or None
    json_mode = getattr(args, 'json', False)

    pipeline = GuidedPipeline(
        target,
        timeout=getattr(args, 'timeout', 8),
        deep=getattr(args, 'deep', False),
        output_dir=getattr(args, 'output_dir', "") or "",
        headers=auth_headers,
        stealth=getattr(args, 'stealth', False),
        quiet=json_mode,
    )

    summary = pipeline.run()

    if json_mode:
        _json_print(summary)

    # Save JSON output if requested
    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        if not json_mode:
            print(f"  Pipeline results saved to {output_file}")


def cmd_auto(args):
    """Full pipeline: recon → scan → ai-bypass in one command"""
    from fray.tester import WAFTester
    from fray.output import console, print_header, print_phase
    from rich.panel import Panel

    if not args.target:
        print("Error: target URL is required.")
        sys.exit(1)

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    # Scope validation
    scope_file = getattr(args, 'scope', None)
    if scope_file:
        from fray.scope import parse_scope_file, is_target_in_scope
        scope = parse_scope_file(scope_file)
        in_scope, reason = is_target_in_scope(target, scope)
        if not in_scope:
            print(f"\n  Target is OUT OF SCOPE: {reason}")
            sys.exit(1)

    json_mode = getattr(args, 'json', False)
    full_report = {"target": target, "phases": {}}
    start_time = __import__('time').time()

    if not json_mode:
        print_header(f"Fray Auto Pipeline v{__version__}", target=target)
        console.print(f"  Pipeline: recon → scan → ai-bypass")
        console.print(f"  Category: {args.category}")

    # ── Phase 1: Recon ────────────────────────────────────────────────
    recon_result = None
    recommended_cats = []
    waf_vendor = None

    if not getattr(args, 'skip_recon', False):
        if not json_mode:
            console.print()
            console.rule("[bold cyan]Phase 1: Reconnaissance[/bold cyan]", style="cyan")
            console.print()

        from fray.recon import run_recon
        recon_result = run_recon(target, timeout=getattr(args, 'timeout', 8), mode="default")
        atk = recon_result.get("attack_surface", {})

        # Extract useful info for next phases
        recommended_cats = recon_result.get("recommended_categories", [])
        waf_vendor = atk.get("waf_vendor") or ""
        risk_score = atk.get("risk_score", 0)
        risk_level = atk.get("risk_level", "?")
        findings = atk.get("findings", [])
        waf_mode = atk.get("waf_detection_mode", "")
        subdomains = atk.get("subdomains", 0)

        full_report["phases"]["recon"] = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "waf_vendor": waf_vendor,
            "waf_mode": waf_mode,
            "findings_count": len(findings),
            "subdomains": subdomains,
            "recommended_categories": recommended_cats,
        }

        if not json_mode:
            console.print()
            console.print(Panel(
                f"[bold]Risk:[/bold] {risk_level} ({risk_score}/100)\n"
                f"[bold]WAF:[/bold]  {waf_vendor or 'unknown'} ({waf_mode or 'none'})\n"
                f"[bold]Findings:[/bold] {len(findings)}\n"
                f"[bold]Subdomains:[/bold] {subdomains}",
                title="[bold]Recon Summary[/bold]",
                border_style="cyan", expand=False,
            ))

            # Recommendation
            if recommended_cats:
                cat_str = ", ".join(recommended_cats[:4])
                console.print(f"\n  [bold yellow]→ Recommended:[/bold yellow] fray test {target} -c {recommended_cats[0]}")
                console.print(f"    Categories: {cat_str}")
            if waf_vendor:
                console.print(f"  [bold yellow]→ WAF detected:[/bold yellow] {waf_vendor} — scan will use adaptive throttling")
    else:
        if not json_mode:
            console.print("\n  [dim]Phase 1: Recon skipped (--skip-recon)[/dim]")

    # ── Phase 2: WAF Scan ─────────────────────────────────────────────
    scan_results = None
    block_rate = 0

    if not getattr(args, 'skip_scan', False):
        if not json_mode:
            console.print()
            console.rule("[bold cyan]Phase 2: WAF Scan[/bold cyan]", style="cyan")
            console.print()

        # Use recommended category from recon if available
        category = args.category
        if recommended_cats and category == "xss" and recommended_cats[0] != "xss":
            if not json_mode:
                console.print(f"  [yellow]Recon suggests:[/yellow] {recommended_cats[0]} "
                              f"(using {category} as requested)")

        custom_headers = build_auth_headers(args)
        tester = WAFTester(
            target=target,
            timeout=getattr(args, 'timeout', 8),
            delay=getattr(args, 'delay', 0.5),
            verify_ssl=not getattr(args, 'insecure', False),
            custom_headers=custom_headers or None,
            stealth=getattr(args, 'stealth', False),
        )

        # Load payloads
        all_payloads = []
        category_dir = PAYLOADS_DIR / category
        if category_dir.exists():
            for pf in sorted(category_dir.glob("*.json")):
                all_payloads.extend(tester.load_payloads(str(pf)))

        max_test = getattr(args, 'max', 20)
        if all_payloads:
            test_payloads = all_payloads[:max_test]
            results = []
            for i, p in enumerate(test_payloads):
                payload_str = p.get("payload", p) if isinstance(p, dict) else str(p)
                desc = p.get("description", "") if isinstance(p, dict) else ""
                r = tester.test_payload(payload_str, param=getattr(args, 'param', 'input'))
                r["payload"] = payload_str
                r["description"] = desc
                results.append(r)

                if not json_mode:
                    blocked = r.get("blocked", True)
                    status = r.get("status", 0)
                    tag = "[red]BLOCKED[/red]" if blocked else "[green]BYPASS[/green]"
                    console.print(f"  [{i+1:>3}/{max_test}] {tag}  {status} │ {desc[:50]}")

                tester._stealth_delay()

            blocked_count = sum(1 for r in results if r.get("blocked", True))
            bypassed_count = len(results) - blocked_count
            block_rate = blocked_count / len(results) * 100 if results else 0

            scan_results = results
            full_report["phases"]["scan"] = {
                "category": category,
                "total": len(results),
                "blocked": blocked_count,
                "bypassed": bypassed_count,
                "block_rate": f"{block_rate:.1f}%",
            }

            if not json_mode:
                console.print()
                console.print(Panel(
                    f"[bold]Tested:[/bold]  {len(results)} payloads ({category})\n"
                    f"[bold]Blocked:[/bold] {blocked_count}\n"
                    f"[bold]Bypassed:[/bold] {bypassed_count}\n"
                    f"[bold]Block Rate:[/bold] {block_rate:.1f}%",
                    title="[bold]Scan Summary[/bold]",
                    border_style="cyan", expand=False,
                ))

                # Recommendation for next phase
                if block_rate == 100:
                    console.print(f"\n  [bold yellow]→ 100% blocked:[/bold yellow] AI bypass will try adaptive mutations + header tricks")
                elif block_rate > 50:
                    console.print(f"\n  [bold yellow]→ {block_rate:.0f}% blocked:[/bold yellow] AI bypass will focus on mutation of blocked payloads")
                else:
                    console.print(f"\n  [bold green]→ {100-block_rate:.0f}% bypassed:[/bold green] WAF is weak — AI bypass will amplify successful vectors")
        else:
            if not json_mode:
                console.print(f"  [dim]No payloads found for category '{category}'[/dim]")
    else:
        if not json_mode:
            console.print("\n  [dim]Phase 2: Scan skipped (--skip-scan)[/dim]")

    # ── Phase 3: AI Bypass ────────────────────────────────────────────
    ai_result = None

    if not getattr(args, 'skip_bypass', False):
        if not json_mode:
            console.print()
            console.rule("[bold cyan]Phase 3: AI Bypass[/bold cyan]", style="cyan")
            console.print()

        from fray.ai_bypass import run_ai_bypass
        from dataclasses import asdict

        custom_headers = build_auth_headers(args)
        tester = WAFTester(
            target=target,
            timeout=getattr(args, 'timeout', 8),
            delay=getattr(args, 'delay', 0.5),
            verify_ssl=not getattr(args, 'insecure', False),
            custom_headers=custom_headers or None,
            stealth=getattr(args, 'stealth', False),
        )

        ai_result = run_ai_bypass(
            tester=tester,
            category=args.category,
            param=getattr(args, 'param', 'input'),
            rounds=getattr(args, 'rounds', 2),
            max_per_round=8,
            try_headers=True,
            verbose=not json_mode,
            json_output=False,
        )

        full_report["phases"]["ai_bypass"] = {
            "provider": ai_result.provider,
            "rounds": ai_result.rounds,
            "generated": ai_result.total_generated,
            "tested": ai_result.total_tested,
            "bypassed": ai_result.total_bypassed,
            "reflected": ai_result.total_reflected,
            "header_bypasses": ai_result.header_bypasses,
            "bypass_rate": f"{ai_result.total_bypassed / max(ai_result.total_tested, 1) * 100:.1f}%",
        }
    else:
        if not json_mode:
            console.print("\n  [dim]Phase 3: AI bypass skipped (--skip-bypass)[/dim]")

    # ── Final Summary ─────────────────────────────────────────────────
    elapsed = __import__('time').time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
    full_report["duration"] = duration

    if not json_mode:
        console.print()
        console.rule("[bold bright_cyan]Pipeline Complete[/bold bright_cyan]", style="bright_cyan")

        # Final summary table
        from rich.table import Table
        tbl = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
        tbl.add_column("Key", style="dim", min_width=22)
        tbl.add_column("Value")

        tbl.add_row("Target", target)
        tbl.add_row("Duration", duration)
        tbl.add_row("", "")

        if recon_result:
            atk = recon_result.get("attack_surface", {})
            tbl.add_row("Recon Risk", f"{atk.get('risk_level', '?')} ({atk.get('risk_score', 0)}/100)")
            tbl.add_row("WAF", atk.get("waf_vendor", "unknown"))

        if scan_results:
            bypassed = sum(1 for r in scan_results if not r.get("blocked", True))
            tbl.add_row("Scan", f"{bypassed}/{len(scan_results)} bypassed ({100-block_rate:.0f}% bypass rate)")

        if ai_result:
            tbl.add_row("AI Bypass", f"{ai_result.total_bypassed}/{ai_result.total_tested} bypassed")
            tbl.add_row("Header Bypass", f"{ai_result.header_bypasses} found")
            tbl.add_row("Reflected", f"{ai_result.total_reflected}")

        console.print()
        console.print(Panel(tbl, title="[bold]Pipeline Summary[/bold]",
                            border_style="bright_cyan", expand=False))

        console.print()

    if json_mode:
        _json_print(full_report)

    output_file = getattr(args, 'output', None)
    if output_file:
        _validate_output_path(output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2, ensure_ascii=False)
        if not json_mode:
            print(f"  Report saved to {output_file}")

    # Next-step hints
    if not json_mode:
        try:
            from fray.interactive import next_steps
            next_steps(target, "auto")
        except Exception:
            pass


def cmd_learn(args):
    """Start interactive CTF-style security tutorial"""
    from fray.learn import run_learn
    run_learn(
        topic=args.topic,
        level=args.level,
        list_all=args.list,
        reset=args.reset,
    )


def cmd_mcp(args):
    """Start MCP server for AI assistant integration"""
    try:
        from fray.mcp_server import main as mcp_main
        mcp_main()
    except ImportError:
        print("Error: MCP SDK not installed. Install with:")
        print("  pip install 'mcp[cli]'")
        sys.exit(1)


def cmd_scope(args):
    """Inspect, validate, or check a target against a scope file"""
    from fray.scope import parse_scope_file, is_target_in_scope, print_scope

    scope = parse_scope_file(args.scope_file)

    if args.check:
        # Check a specific target against scope
        in_scope, reason = is_target_in_scope(args.check, scope)
        if in_scope:
            print(f"\n  ✅ {args.check} is IN SCOPE")
            print(f"  {reason}")
        else:
            print(f"\n  ⛔ {args.check} is OUT OF SCOPE")
            print(f"  {reason}")
        sys.exit(0 if in_scope else 1)

    if args.json:
        _json_print(scope)
    else:
        print_scope(scope, filepath=args.scope_file)


def _explain_findings(filepath: str, verbose: bool = False):
    """Explain scan/test results in human-readable format for bug bounty hunters."""
    import re as _re

    bold = "\033[1m"
    dim = "\033[2m"
    reset = "\033[0m"
    red = "\033[91m"
    yellow = "\033[93m"
    green = "\033[92m"
    magenta = "\033[95m"
    cyan = "\033[96m"

    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"\n  {red}Error:{reset} Cannot read '{filepath}': {exc}")
        sys.exit(1)

    # Normalise: support both cmd_test report and cmd_scan ScanResult formats
    target = data.get("target", "unknown")
    summary = data.get("summary", {})
    results = data.get("results", data.get("test_results", []))
    crawl = data.get("crawl", {})
    duration = data.get("duration", "N/A")

    # Separate findings by risk level
    reflected = [r for r in results if r.get("reflected") and not r.get("blocked")]
    bypassed = [r for r in results if not r.get("blocked") and not r.get("reflected")]
    blocked = [r for r in results if r.get("blocked")]

    # ── Vulnerability knowledge base ──
    vuln_info = {
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "icon": "\U0001f534",
            "severity": "HIGH",
            "why": "User input appears in the response without proper encoding. An attacker can inject JavaScript that runs in victims' browsers, stealing session cookies, credentials, or performing actions on their behalf.",
            "impact": ["Session hijacking via cookie theft", "Credential harvesting with fake login forms", "Keylogging user inputs", "Defacement or phishing redirect"],
            "fix": ["HTML-encode all user input before rendering", "Set Content-Security-Policy header", "Use HttpOnly + Secure cookie flags"],
            "cwe": "CWE-79",
        },
        "sqli": {
            "name": "SQL Injection",
            "icon": "\U0001f534",
            "severity": "CRITICAL",
            "why": "User input is incorporated into SQL queries without parameterization. An attacker can read, modify, or delete database contents, and potentially execute system commands.",
            "impact": ["Full database extraction (users, passwords, PII)", "Authentication bypass (login as admin)", "Data modification or deletion", "Remote code execution (via xp_cmdshell, INTO OUTFILE)"],
            "fix": ["Use parameterized queries / prepared statements", "Use an ORM layer", "Apply least-privilege database permissions"],
            "cwe": "CWE-89",
        },
        "ssrf": {
            "name": "Server-Side Request Forgery (SSRF)",
            "icon": "\U0001f7e0",
            "severity": "HIGH",
            "why": "The server can be tricked into making requests to internal resources. An attacker can access cloud metadata endpoints, internal APIs, and services not exposed to the internet.",
            "impact": ["Steal cloud credentials (AWS keys, GCP tokens)", "Access internal admin panels and databases", "Port scan internal network", "Pivot to deeper attacks"],
            "fix": ["Allowlist permitted destination hosts", "Block private IP ranges (10.x, 172.16.x, 169.254.x)", "Disable HTTP redirects in server-side clients"],
            "cwe": "CWE-918",
        },
        "ssti": {
            "name": "Server-Side Template Injection (SSTI)",
            "icon": "\U0001f534",
            "severity": "CRITICAL",
            "why": "User input is rendered inside a server-side template engine. An attacker can execute arbitrary code on the server, leading to full system compromise.",
            "impact": ["Remote code execution on the server", "Read sensitive files (/etc/passwd, config)", "Reverse shell access", "Lateral movement in the network"],
            "fix": ["Never pass user input directly to template engines", "Use sandboxed template environments", "Validate and sanitize all inputs"],
            "cwe": "CWE-1336",
        },
        "command_injection": {
            "name": "OS Command Injection",
            "icon": "\U0001f534",
            "severity": "CRITICAL",
            "why": "User input is passed to a system shell command. An attacker can execute arbitrary OS commands, taking full control of the server.",
            "impact": ["Full server compromise", "Data exfiltration", "Install backdoors or ransomware", "Pivot to internal network"],
            "fix": ["Never pass user input to shell commands", "Use language-level APIs instead of shell exec", "Allowlist expected input patterns"],
            "cwe": "CWE-78",
        },
        "xxe": {
            "name": "XML External Entity (XXE)",
            "icon": "\U0001f7e0",
            "severity": "HIGH",
            "why": "The XML parser processes external entity references. An attacker can read local files, perform SSRF, or cause denial of service.",
            "impact": ["Read server files (/etc/passwd, config)", "SSRF to internal services", "Denial of service (billion laughs)", "Port scanning"],
            "fix": ["Disable external entity processing in XML parser", "Use JSON instead of XML", "Validate and sanitize XML input"],
            "cwe": "CWE-611",
        },
        "path_traversal": {
            "name": "Path Traversal",
            "icon": "\U0001f7e0",
            "severity": "HIGH",
            "why": "User input controls file paths without proper validation. An attacker can read arbitrary files from the server filesystem.",
            "impact": ["Read source code and configuration files", "Access credentials and API keys", "Read /etc/passwd and /etc/shadow", "Access other users' data"],
            "fix": ["Validate file paths against an allowlist", "Use chroot or sandboxed file access", "Strip ../ sequences and null bytes"],
            "cwe": "CWE-22",
        },
        "open-redirect": {
            "name": "Open Redirect",
            "icon": "\U0001f7e1",
            "severity": "MEDIUM",
            "why": "The application redirects users to a URL controlled by attacker input. This enables phishing attacks that appear to originate from the trusted domain.",
            "impact": ["Phishing — redirect to fake login page", "OAuth token theft via redirect_uri", "Bypass domain-based security filters", "Chain with SSRF for internal access"],
            "fix": ["Allowlist permitted redirect destinations", "Use relative redirects only", "Validate redirect URL against same-origin"],
            "cwe": "CWE-601",
        },
        "crlf_injection": {
            "name": "CRLF Injection / HTTP Response Splitting",
            "icon": "\U0001f7e0",
            "severity": "MEDIUM",
            "why": "User input is included in HTTP headers without filtering newlines. An attacker can inject additional headers or split the response to perform XSS or cache poisoning.",
            "impact": ["HTTP response splitting", "Cache poisoning", "Session fixation", "XSS via injected headers"],
            "fix": ["Strip \\r\\n from all header values", "Use framework header-setting functions", "Validate header values"],
            "cwe": "CWE-113",
        },
        "prototype_pollution": {
            "name": "Prototype Pollution",
            "icon": "\U0001f7e0",
            "severity": "HIGH",
            "why": "User-controlled input modifies JavaScript object prototypes. An attacker can inject properties that affect all objects, leading to denial of service, privilege escalation, or remote code execution.",
            "impact": ["Denial of service", "Privilege escalation (isAdmin = true)", "Remote code execution via gadget chains", "Authentication bypass"],
            "fix": ["Freeze Object.prototype", "Use Map instead of plain objects", "Validate and sanitize recursive merge operations"],
            "cwe": "CWE-1321",
        },
        "host_header_injection": {
            "name": "Host Header Injection",
            "icon": "\U0001f7e0",
            "severity": "MEDIUM",
            "why": "The application trusts the Host header for generating URLs. An attacker can poison password reset links, cache entries, or trigger SSRF.",
            "impact": ["Password reset link poisoning", "Web cache poisoning", "SSRF via Host header", "Virtual host routing bypass"],
            "fix": ["Hardcode the server hostname in config", "Validate Host header against allowlist", "Ignore X-Forwarded-Host from untrusted sources"],
            "cwe": "CWE-644",
        },
    }

    default_info = {
        "name": "Security Finding",
        "icon": "\u26a0\ufe0f",
        "severity": "MEDIUM",
        "why": "A payload bypassed the WAF and was not blocked. This indicates a gap in the security configuration that could be exploited.",
        "impact": ["WAF bypass — attacker payloads reach the application", "Potential exploitation depending on application behavior"],
        "fix": ["Review WAF rules for this payload pattern", "Add application-level input validation"],
        "cwe": "CWE-693",
    }

    sev_colors = {"CRITICAL": red, "HIGH": red, "MEDIUM": yellow, "LOW": green}

    # ── Header ──
    print(f"\n{bold}Fray Findings Report{reset}")
    print("━" * 64)
    print(f"  {bold}Target:{reset}    {target}")
    print(f"  {bold}Duration:{reset}  {duration}")
    total = summary.get("total", summary.get("total_tested", len(results)))
    blk = summary.get("blocked", 0)
    psd = summary.get("passed", 0)
    refl = summary.get("reflected", 0)
    br = summary.get("block_rate", "N/A")
    print(f"  {bold}Tested:{reset}    {total} payloads")
    print(f"  {bold}Blocked:{reset}   {blk}  |  {bold}Passed:{reset} {psd}  |  {bold}Reflected:{reset} {refl}")
    print(f"  {bold}Block Rate:{reset} {br}")

    # ── Crawl info (from fray scan) ──
    if crawl:
        pages = crawl.get("pages_crawled", 0)
        eps = crawl.get("total_endpoints", 0)
        ips = crawl.get("total_injection_points", 0)
        if pages:
            print(f"  {bold}Crawled:{reset}   {pages} pages, {eps} endpoints, {ips} injection points")

    # ── Critical: Reflected findings ──
    if reflected:
        print(f"\n{'━' * 64}")
        print(f"  {red}{bold}\U0001f6a8 CRITICAL — {len(reflected)} Reflected Finding(s){reset}")
        print(f"  {red}Payload appeared in the response — confirmed exploitable{reset}")
        print(f"{'━' * 64}")

        # Group by category
        by_cat = {}
        for r in reflected:
            cat = r.get("category", "unknown")
            by_cat.setdefault(cat, []).append(r)

        for cat, items in by_cat.items():
            info = vuln_info.get(cat, default_info)
            sev_color = sev_colors.get(info["severity"], yellow)

            print(f"\n  {info['icon']} {bold}{info['name']}{reset} ({sev_color}{info['severity']}{reset}) — {bold}{len(items)} reflected{reset}")
            print(f"  {bold}CWE:{reset} {info['cwe']}")
            print()
            print(f"  {bold}Why this matters:{reset}")
            print(f"  {info['why']}")
            print()
            print(f"  {bold}Impact:{reset}")
            for imp in info["impact"]:
                print(f"    • {imp}")
            print()

            print(f"  {bold}Findings:{reset}")
            for i, r in enumerate(items[:10]):
                payload = r.get("payload", "")
                status = r.get("status", "?")
                # Detect endpoint from payload context
                endpoint = r.get("url", r.get("endpoint", target))
                param = r.get("param", "input")
                if len(payload) > 100:
                    payload = payload[:97] + "..."
                badge = f"{red}↩ REFLECTED{reset}"
                print(f"\n    {dim}#{i+1}{reset} {badge} HTTP {status}")
                print(f"    {bold}Endpoint:{reset} {endpoint}")
                if param:
                    print(f"    {bold}Parameter:{reset} {param}")
                print(f"    {bold}Payload:{reset}  {cyan}{payload}{reset}")

            if len(items) > 10:
                print(f"\n    {dim}... and {len(items) - 10} more reflected findings{reset}")

            print()
            print(f"  {bold}Suggested test payloads:{reset}")
            _print_suggested_payloads(cat)

            print()
            print(f"  {bold}Remediation:{reset}")
            for fix in info["fix"]:
                print(f"    \u2192 {fix}")

            print()
            print(f"  {bold}Next steps:{reset}")
            print(f"    {dim}# Reproduce and capture evidence:{reset}")
            print(f"    curl -v '{target}?{param}=<script>alert(document.domain)</script>'")
            print(f"    {dim}# Generate a report for submission:{reset}")
            print(f"    fray report -i {filepath} -o report.html")
            print(f"    fray report -i {filepath} -o report.md --format markdown")

    # ── High: Bypassed (not blocked, not reflected) ──
    if bypassed:
        print(f"\n{'━' * 64}")
        print(f"  {yellow}{bold}\u26a0\ufe0f  WARNING — {len(bypassed)} Bypassed Finding(s){reset}")
        print(f"  {yellow}Payload passed the WAF but was not reflected in response{reset}")
        print(f"{'━' * 64}")

        by_cat = {}
        for r in bypassed:
            cat = r.get("category", "unknown")
            by_cat.setdefault(cat, []).append(r)

        for cat, items in by_cat.items():
            info = vuln_info.get(cat, default_info)
            sev_color = sev_colors.get(info["severity"], yellow)

            print(f"\n  {info['icon']} {bold}{info['name']}{reset} ({sev_color}{info['severity']}{reset}) — {bold}{len(items)} bypassed{reset}")
            print()
            print(f"  {bold}Why this matters:{reset}")
            print(f"  The WAF did not block these payloads. While not confirmed exploitable")
            print(f"  (no reflection detected), the application may still be vulnerable.")
            print(f"  Manual testing is recommended to confirm impact.")
            print()

            print(f"  {bold}Top bypassed payloads:{reset}")
            for i, r in enumerate(items[:5]):
                payload = r.get("payload", "")
                status = r.get("status", "?")
                if len(payload) > 100:
                    payload = payload[:97] + "..."
                print(f"    {dim}#{i+1}{reset} HTTP {status} — {cyan}{payload}{reset}")

            if len(items) > 5:
                print(f"    {dim}... and {len(items) - 5} more{reset}")

            print()
            print(f"  {bold}Next steps:{reset}")
            print(f"    {dim}# Test with reflection detection:{reset}")
            print(f"    fray test {target} -c {cat} --smart --max 50")
            print(f"    {dim}# Try different injection points:{reset}")
            print(f"    fray scan {target} -c {cat} --depth 3")

    # ── Blocked summary ──
    if blocked and not reflected and not bypassed:
        print(f"\n{'━' * 64}")
        print(f"  {green}{bold}\u2705 ALL PAYLOADS BLOCKED{reset}")
        print(f"  The WAF blocked all {len(blocked)} tested payloads.")
        print(f"  {bold}Recommendation:{reset} Try adaptive/smart mode for deeper testing:")
        print(f"    fray test {target} --smart --max 100")
        print(f"    fray test {target} -c xss,sqli,ssrf --smart")
        print(f"{'━' * 64}")
    elif blocked:
        blk_by_cat = {}
        for r in blocked:
            cat = r.get("category", "unknown")
            blk_by_cat.setdefault(cat, []).append(r)
        print(f"\n  {green}{bold}\u2705 Blocked:{reset} {len(blocked)} payloads across {len(blk_by_cat)} categories")

    # ── Overall risk assessment ──
    print(f"\n{'━' * 64}")
    print(f"  {bold}Overall Risk Assessment{reset}")
    print(f"{'━' * 64}")
    if reflected:
        print(f"\n  {red}{bold}CRITICAL{reset} — {len(reflected)} confirmed exploitable finding(s)")
        print(f"  Immediate action required. File bug bounty reports for reflected payloads.")
        print(f"\n  {bold}Quick commands:{reset}")
        print(f"    fray report -i {filepath} -o report.html")
        print(f"    fray bounty --urls targets.txt -o bounty_report.json")
    elif bypassed:
        print(f"\n  {yellow}{bold}MEDIUM{reset} — {len(bypassed)} WAF bypass(es), no confirmed reflection")
        print(f"  Manual verification needed. The WAF has gaps that should be addressed.")
        print(f"\n  {bold}Quick commands:{reset}")
        print(f"    fray test {target} --smart --max 100")
        print(f"    fray scan {target} --depth 5")
    else:
        print(f"\n  {green}{bold}LOW{reset} — WAF blocked all payloads")
        print(f"  Good defensive posture. Consider testing with more categories.")
        print(f"\n  {bold}Quick commands:{reset}")
        print(f"    fray test {target} -c sqli,ssrf,ssti,command_injection --smart")

    print(f"\n{'━' * 64}\n")


def _print_suggested_payloads(category: str):
    """Print 3 suggested test payloads for a category."""
    dim = "\033[2m"
    cyan = "\033[96m"
    reset = "\033[0m"

    suggestions = {
        "xss": [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=confirm(document.cookie)>',
        ],
        "sqli": [
            "' OR 1=1--",
            "' UNION SELECT null,username,password FROM users--",
            "1; WAITFOR DELAY '0:0:5'--",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://127.0.0.1:8080/admin",
            "http://[::1]/server-status",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
        "command_injection": [
            "; id",
            "| cat /etc/passwd",
            "$(whoami)",
        ],
        "xxe": [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>',
            '<!ENTITY % xxe SYSTEM "file:///etc/hostname"> %xxe;',
        ],
        "path_traversal": [
            "../../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ],
    }

    payloads = suggestions.get(category, [
        "Use fray payloads to browse available payloads for this category",
        f"fray test <target> -c {category} --smart --max 20",
    ])
    for p in payloads[:3]:
        print(f"    {cyan}{p}{reset}")


def cmd_explain(args):
    """Explain a CVE or scan results — dual mode based on input."""
    # If the argument looks like a file path to a JSON file, explain findings
    input_arg = args.cve_id
    if input_arg.endswith('.json') and Path(input_arg).exists():
        _explain_findings(input_arg, verbose=getattr(args, 'verbose', False))
        return

    # Otherwise, fall through to CVE explanation mode
    """Explain a CVE — show payloads, affected versions, severity, and what to test"""
    import glob

    query = args.cve_id.upper().strip()
    # Also support partial matches like "log4shell", "react2shell"
    query_lower = args.cve_id.lower().strip()

    matches = []
    for fpath in glob.glob(str(PAYLOADS_DIR / "**" / "*.json"), recursive=True):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for p in data.get("payloads", []):
            cve_field = p.get("cve", "")
            desc = p.get("description", "")
            subcat = p.get("subcategory", "")
            source = p.get("source", "")
            # Match CVE ID, description, subcategory, or source
            if (query in cve_field.upper()
                    or query in desc.upper()
                    or query_lower in subcat.lower()
                    or query_lower in source.lower()
                    or query_lower in desc.lower()):
                matches.append((p, fpath))

    if not matches:
        print(f"\n  No payloads found for '{args.cve_id}'")
        print(f"  Try: fray explain CVE-2021-44228")
        print(f"        fray explain log4shell")
        print(f"        fray explain react2shell")
        sys.exit(1)

    # Group by CVE ID
    by_cve = {}
    for p, fpath in matches:
        key = p.get("cve", p.get("subcategory", "unknown"))
        by_cve.setdefault(key, []).append((p, fpath))

    # Severity colors
    sev_colors = {
        "critical": "\033[91m",  # red
        "high": "\033[93m",      # yellow
        "medium": "\033[33m",    # orange
        "low": "\033[92m",       # green
    }
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"

    print(f"\n{bold}Fray Explain — CVE Intelligence{reset}")
    print("━" * 60)

    for cve_id, items in by_cve.items():
        first = items[0][0]
        severity = first.get("severity", "unknown")
        cvss = first.get("cvss", "N/A")
        affected = first.get("affected_versions", "N/A")
        disclosure = first.get("disclosure_date", "N/A")
        desc = first.get("description", "")
        source_file = str(Path(items[0][1]).relative_to(PAYLOADS_DIR.parent))

        sev_color = sev_colors.get(severity, "")

        print(f"\n  {bold}{cve_id}{reset}")
        print(f"  {desc}")
        print()
        print(f"  {bold}Severity:{reset}     {sev_color}{severity.upper()}{reset} (CVSS {cvss})")
        print(f"  {bold}Affected:{reset}     {affected}")
        print(f"  {bold}Disclosed:{reset}    {disclosure}")
        print(f"  {bold}Payloads:{reset}     {len(items)} available")
        print(f"  {bold}Source:{reset}       {source_file}")

        # Show payloads
        print(f"\n  {bold}Payloads:{reset}")
        show_count = min(len(items), args.max)
        for i, (p, _) in enumerate(items[:show_count]):
            payload_text = p.get("payload", "")
            # Truncate long payloads
            if len(payload_text) > 120:
                payload_text = payload_text[:117] + "..."
            print(f"\n  {dim}#{i+1}{reset} {p.get('description', '')}")
            print(f"     {payload_text}")

        if len(items) > show_count:
            print(f"\n  {dim}... and {len(items) - show_count} more (use --max {len(items)} to see all){reset}")

        # How to run against a target
        cat = first.get("category", "")
        subcat = first.get("subcategory", "")
        cve_str = cve_id if cve_id.startswith("CVE") else ""

        print(f"\n  {bold}How to run against a target:{reset}")
        if "rce" in cat.lower() or "rce" in desc.lower() or "command" in desc.lower():
            print(f"    → Test command execution endpoints, check input sanitization")
        elif "xss" in cat.lower():
            print(f"    → Test reflected/stored XSS vectors in user input fields")
        elif "sqli" in cat.lower() or "sql" in desc.lower():
            print(f"    → Test SQL injection in query parameters and form fields")
        elif "ssrf" in cat.lower():
            print(f"    → Test SSRF in URL parameters, redirects, and webhooks")

        print()
        print(f"    {dim}# Test this CVE's payloads against your target:{reset}")
        print(f"    fray test https://target.com -c {cat} --max {len(items)}")
        print()
        print(f"    {dim}# Smart mode — recon first, then test recommended categories:{reset}")
        print(f"    fray test https://target.com --smart")
        print()
        print(f"    {dim}# Full recon + test workflow:{reset}")
        print(f"    fray recon https://target.com")
        print(f"    fray test https://target.com -c {cat} --max {len(items)} -o results.json")
        print(f"    fray report -i results.json -o report.html")

    total = sum(len(v) for v in by_cve.values())
    print(f"\n{'━' * 60}")
    print(f"  {bold}{total} payload(s){reset} across {bold}{len(by_cve)} CVE(s){reset}")

    if args.json:
        output = []
        for cve_id, items in by_cve.items():
            for p, fpath in items:
                entry = dict(p)
                entry["file"] = str(Path(fpath).relative_to(PAYLOADS_DIR.parent))
                output.append(entry)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            print(f"\n  JSON saved to {args.output}")
        else:
            _json_print(output)


def cmd_demo(args):
    """Quick showcase: detect WAF + XSS scan on a target (great for GIFs/READMEs)."""
    import time
    from fray.detector import WAFDetector
    from fray.scanner import run_scan, print_scan_result

    DEFAULT_TARGET = "http://testphp.vulnweb.com"
    target = getattr(args, 'target', None) or DEFAULT_TARGET

    print(f"\n  ⚔️  Fray v{__version__} — Demo Mode")
    print(f"  {'─' * 50}")
    print(f"  Target: {target}\n")

    # Phase 1: WAF Detection
    print(f"  [1/2] Detecting WAF...")
    detector = WAFDetector()
    try:
        waf = detector.detect_waf(target, verify_ssl=False)
        if waf.get('waf_detected'):
            vendor = waf['waf_vendor']
            conf = waf['confidence']
            print(f"  ✓ WAF Detected: {vendor} ({conf}% confidence)")
            sigs = waf.get('signatures_found', [])
            for sig in sigs[:3]:
                print(f"    • {sig}")
        else:
            print(f"  ✓ WAF: None detected")
    except Exception as e:
        print(f"  ⚠ WAF detection failed: {e}")

    # Phase 2: Quick XSS Scan
    print(f"\n  [2/2] Scanning for XSS bypasses...")
    print()

    scan = run_scan(
        target=target,
        category='xss',
        max_payloads=3,
        max_depth=2,
        max_pages=8,
        delay=0.2,
        timeout=8,
        verify_ssl=False,
        quiet=False,
    )
    print_scan_result(scan)

    # One-line verdict
    r = scan.total_reflected if hasattr(scan, 'total_reflected') else 0
    b = scan.total_blocked if hasattr(scan, 'total_blocked') else 0
    t = scan.total_tested if hasattr(scan, 'total_tested') else 0
    if r > 0:
        print(f"\n  🎯 Found {r} confirmed XSS bypass{'es' if r != 1 else ''} ({b}/{t} blocked)")
    elif b > 0:
        print(f"\n  🛡️  WAF blocked {b}/{t} payloads — no bypasses found")
    else:
        print(f"\n  ✓ Scan complete — {t} payloads tested")

    print(f"\n  Run 'fray scan {target}' for a full assessment.\n")


def cmd_leak(args):
    """Search for leaked credentials on GitHub and Have I Been Pwned."""
    from fray.leak import search_leaks, print_leak_results

    target = args.target
    if not target:
        print("  Error: No target specified.")
        print("  Usage: fray leak example.com")
        print("         fray leak user@example.com")
        sys.exit(1)

    # Strip scheme if user passes a URL
    if target.startswith(("http://", "https://")):
        import urllib.parse as _up
        target = _up.urlparse(target).hostname or target

    github = not getattr(args, 'hibp_only', False)
    hibp = not getattr(args, 'github_only', False)

    result = search_leaks(
        target=target,
        github=github,
        hibp=hibp,
        timeout=getattr(args, 'timeout', 10),
    )

    if getattr(args, 'json', False):
        out = json.dumps(result, indent=2, ensure_ascii=False)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"  Saved to {args.output}")
        else:
            print(out)
    else:
        print_leak_results(result)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            out = json.dumps(result, indent=2, ensure_ascii=False)
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"  💾 Results saved to {args.output}")

    # Webhook notification
    notify_url = getattr(args, 'notify', None)
    if notify_url:
        from fray.webhook import send_generic_notification
        gh_leaks = len(result.get("github_results", []))
        hibp_leaks = len(result.get("hibp_results", []))
        total = gh_leaks + hibp_leaks
        summary = {
            "github_leaks": gh_leaks,
            "hibp_breaches": hibp_leaks,
            "total_findings": total,
            "_severity": "critical" if total > 5 else "high" if total > 0 else "low",
        }
        send_generic_notification(notify_url, "leak", target, summary)


def cmd_osint(args):
    """Offensive OSINT: accepts domain, email, or company name."""
    from fray.osint import (resolve_target, run_osint, run_osint_email,
                            print_osint, print_osint_email, export_osint_html)

    target = args.target
    if not target:
        print("  Error: No target specified.")
        print("  Usage: fray osint example.com")
        print("         fray osint user@example.com")
        print("         fray osint Amazon")
        sys.exit(1)

    # Resolve input type
    resolved = resolve_target(target)
    input_type = resolved["type"]
    domain = resolved["domain"]

    if not getattr(args, 'json', False):
        if input_type == "email":
            print(f"  📧 Email mode: {resolved['email']} (domain: {domain})")
        elif input_type == "company":
            print(f"  🏢 Company: {resolved.get('company', target)} → {domain}")

    # Route based on input type
    if input_type == "email":
        result = run_osint_email(
            email=resolved["email"],
            timeout=getattr(args, 'timeout', 10),
            quiet=getattr(args, 'json', False),
        )
    else:
        do_whois = True
        do_emails = True
        do_perms = True
        do_github = True
        do_docs = True

        if getattr(args, 'whois_only', False):
            do_emails = do_perms = do_github = do_docs = False
        elif getattr(args, 'emails_only', False):
            do_whois = do_perms = do_github = do_docs = False
        elif getattr(args, 'github_only', False):
            do_whois = do_emails = do_perms = do_docs = False
        elif getattr(args, 'docs_only', False):
            do_whois = do_emails = do_perms = do_github = False
        elif getattr(args, 'permutations_only', False):
            do_whois = do_emails = do_github = do_docs = False

        result = run_osint(
            domain=domain,
            whois=do_whois,
            emails=do_emails,
            permutations=do_perms,
            github=do_github,
            docs=do_docs,
            timeout=getattr(args, 'timeout', 10),
            quiet=getattr(args, 'json', False),
        )

    # Output
    out_path = getattr(args, 'output', None)
    is_html = out_path and (out_path.endswith('.html') or out_path.endswith('.htm'))

    if getattr(args, 'json', False):
        out = json.dumps(result, indent=2, ensure_ascii=False, default=str)
        if out_path and not is_html:
            _validate_output_path(out_path)
            Path(out_path).write_text(out, encoding="utf-8")
            print(f"  Saved to {out_path}")
        else:
            print(out)
    else:
        if input_type == "email":
            print_osint_email(result)
        else:
            print_osint(result)
        if out_path:
            _validate_output_path(out_path)
            if is_html:
                export_osint_html(result, out_path)
                print(f"  📄 HTML report saved to {out_path}")
            else:
                out = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                Path(out_path).write_text(out, encoding="utf-8")
                print(f"  💾 Results saved to {out_path}")

    # Auto-export to ~/.fray/osint/{key}/
    import os as _os
    export_key = resolved.get("email", domain)
    export_dir = _os.path.join(_os.path.expanduser("~"), ".fray", "osint", export_key)
    _os.makedirs(export_dir, exist_ok=True)
    export_json = _os.path.join(export_dir, "osint.json")
    with open(export_json, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    export_html = _os.path.join(export_dir, "osint.html")
    export_osint_html(result, export_html)
    if not getattr(args, 'json', False):
        print(f"\n  📁 Saved to {export_dir}/ (JSON + HTML)")

    # Webhook notification
    notify_url = getattr(args, 'notify', None)
    if notify_url:
        from fray.webhook import send_generic_notification
        gh = result.get("github", {})
        emp = result.get("employees", {})
        summary = {
            "domain": domain,
            "emails_found": result.get("emails", {}).get("total", 0) if result.get("emails") else 0,
            "employees": emp.get("total_unique_people", 0) if emp else 0,
            "github_repos": gh.get("public_repos", 0) if gh else 0,
            "typosquatting": result.get("permutations", {}).get("registered", 0) if result.get("permutations") else 0,
            "_severity": "medium" if result.get("permutations", {}).get("registered", 0) > 3 else "info",
        }
        send_generic_notification(notify_url, "osint", domain, summary)


def cmd_cred(args):
    """Credential stuffing / reuse testing against login endpoints."""
    from fray.cred import run_credential_test, print_cred_results

    target = args.target
    pairs_file = getattr(args, 'pairs', None)

    if not target:
        print("  Error: No target specified.")
        print("  Usage: fray cred https://example.com/login --pairs leaked.txt")
        sys.exit(1)

    if not pairs_file:
        print("  Error: --pairs file required.")
        print("  Usage: fray cred https://example.com/login --pairs leaked.txt")
        sys.exit(1)

    auth_headers = build_auth_headers(args) or None

    result = run_credential_test(
        url=target,
        pairs_file=pairs_file,
        username_field=getattr(args, 'username_field', None),
        password_field=getattr(args, 'password_field', None),
        content_type=getattr(args, 'content_type', None),
        rate=getattr(args, 'rate', 1.0),
        delay=getattr(args, 'delay', 1.0),
        max_attempts=getattr(args, 'max', 0),
        proxy=getattr(args, 'proxy', None),
        headers=auth_headers,
        dry_run=getattr(args, 'dry_run', False),
        timeout=getattr(args, 'timeout', 10),
    )

    if getattr(args, 'json', False):
        out = json.dumps(result, indent=2, ensure_ascii=False)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"  Saved to {args.output}")
        else:
            print(out)
    else:
        print_cred_results(result)
        if getattr(args, 'output', None):
            _validate_output_path(args.output)
            out = json.dumps(result, indent=2, ensure_ascii=False)
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"  💾 Results saved to {args.output}")

    # Webhook notification
    notify_url = getattr(args, 'notify', None)
    if notify_url:
        from fray.webhook import send_generic_notification
        valid = result.get("valid_credentials", [])
        summary = {
            "pairs_tested": result.get("total_tested", 0),
            "valid_found": len(valid),
            "lockouts": result.get("lockout_detected", 0),
            "_severity": "critical" if valid else "info",
        }
        send_generic_notification(notify_url, "cred", target, summary)


def cmd_monitor(args):
    """Continuous monitoring with diff and alerting."""
    from fray.monitor import run_monitor, list_snapshots

    target = args.target
    if not target:
        print("  Error: No target specified.")
        print("  Usage: fray monitor example.com")
        print("         fray monitor example.com --interval 12h --webhook https://hooks.slack.com/...")
        sys.exit(1)

    if getattr(args, 'list', False):
        list_snapshots(target)
        return

    run_monitor(
        domain=target,
        interval=getattr(args, 'interval', '24h'),
        webhook=getattr(args, 'webhook', None),
        email=getattr(args, 'email', None),
        include_leak=getattr(args, 'leak', False),
        once=getattr(args, 'once', False),
        timeout=getattr(args, 'timeout', 10),
    )


def cmd_help(args):
    """Friendly high-level guide to every fray command."""
    print(f"""
  ⚔️  Fray v{__version__} — WAF Security Testing Toolkit
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔍 RECON — Know your target
  ─────────────────────────────
  fray recon <url>              Full recon: TLS, headers, DNS, cookies, fingerprint,
                                GraphQL, API discovery, Host injection, admin panels,
                                rate limits, WAF detection mode, gap analysis (24 checks)
  fray recon <url> --js         LinkFinder-style JS extraction: endpoints, hostnames,
                                cloud buckets (S3/GCS/Azure), API keys, secrets
  fray recon <url> --history    Discover old URLs via Wayback Machine / sitemap / robots
  fray recon <url> --params     Brute-force 136 common parameter names (?id= ?file= ?redirect=)
  fray recon <url> --ai         AI-ready JSON output for LLMs

  🗺️  GRAPH — Attack surface visualization
  ─────────────────────────────
  fray graph <url>              Visual tree: subdomains, DNS, tech, endpoints, files
  fray graph <url> --deep       Deep mode: + JS endpoints + Wayback historical URLs
  fray graph <url> --json       Output graph as JSON

  🛡️  DETECT — Identify the WAF
  ─────────────────────────────
  fray detect <url>             Fingerprint WAF vendor (Cloudflare, AWS, Akamai, etc.)

  🎯 SCAN — Automated vulnerability scan
  ─────────────────────────────
  fray scan <url>               Auto crawl → param discovery → payload injection
  fray scan <url> -c sqli       Scan with specific payload category
  fray scan <url> --depth 5     Control crawl depth and scope
  fray scan <url> --ai          AI-ready JSON output for LLMs (pipe to Claude, GPT, etc.)
  fray scan <url> --sarif        SARIF 2.1.0 output for GitHub Security tab / CodeQL

  ⚡ TEST — Payload injection
  ─────────────────────────────
  fray test <url> -c xss        Test a specific payload category
  fray test <url> --all         Test ALL 24 payload categories
  fray test <url> --smart       Adaptive mode: probe WAF first, skip redundant payloads
  fray test <url> --ai          AI-ready JSON output for LLMs
  fray test <url> --sarif        SARIF 2.1.0 output for GitHub Security tab

  🔓 BYPASS — WAF evasion scoring
  ─────────────────────────────
  fray bypass <url>             Evasion-optimized testing with bypass scorecard
  fray bypass <url> --waf cloudflare   Target a specific WAF vendor

  🕵️  SMUGGLE — HTTP request smuggling
  ─────────────────────────────
  fray smuggle <url>            Detect CL.TE / TE.CL / TE.TE smuggling vulns

  📊 REPORT — Generate reports
  ─────────────────────────────
  fray report -i results.json   Generate HTML security report
  fray report --sample          Generate a sample demo report

  🔍 OSINT — Offensive Open Source Intelligence
  ─────────────────────────────
  fray osint example.com           Full OSINT: whois, emails, typosquatting, GitHub org, employees, docs
  fray osint example.com --github  GitHub org recon + employee enumeration only
  fray osint example.com --docs    Document metadata harvesting only
  fray osint example.com --whois   Whois lookup only
  fray osint example.com --emails  Email harvesting only
  fray osint example.com --permutations   Typosquatting check only

  🔑 CRED — Credential Stuffing Test
  ─────────────────────────────
  fray cred <login-url> --pairs leaked.txt   Test leaked email:password pairs
  fray cred <login-url> --pairs leaked.txt --dry-run   Preview without sending
  fray cred <login-url> --pairs leaked.txt --rate 2 --delay 3   Rate control

  🔄 MONITOR — Continuous Monitoring
  ─────────────────────────────
  fray monitor example.com                    Default: scan every 24h
  fray monitor example.com --interval 12h     Custom interval
  fray monitor example.com --webhook <url>    Alert via Slack/Discord/Teams
  fray monitor example.com --email <addr>     Alert via email (needs RESEND_API_KEY)
  fray monitor example.com --once             Single scan, diff against last
  fray monitor example.com --list             List previous snapshots

  🔎 OTHER TOOLS
  ─────────────────────────────
  fray payloads                 List all {len(list_categories())} payload categories with counts
  fray validate <url>           Blue team: validate WAF config (defense report)
  fray bounty --platform hackerone   Bug bounty integration
  fray leak example.com          Search GitHub + HIBP for leaked credentials
  fray leak user@example.com     Check specific email in breach databases
  fray diff before.json after.json   Compare scan results (regression testing)
  fray explain CVE-2021-44228   Explain a CVE with payloads and severity
  fray explain results.json      Explain scan findings: impact, why it matters, next steps
  fray demo                     Quick showcase: detect WAF + XSS scan
  fray learn xss                Interactive CTF-style security tutorial
  fray ci init                  Generate GitHub Actions workflow for CI/CD
  fray stats                    Payload database statistics
  fray doctor                   Check environment, auto-fix issues

  🔑 AUTHENTICATION (works with any command)
  ─────────────────────────────
  --cookie "session=abc"        Cookie header
  --bearer "eyJ..."             Bearer token
  -H "X-Api-Key: secret"       Custom header (repeatable)
  --login-flow "url,user=x,pass=y"   Auto-login and capture session

  🔗 PIPE-FRIENDLY (like httpx)
  ─────────────────────────────
  cat domains.txt | fray detect                  WAF detect all targets (TSV output)
  cat domains.txt | fray recon                   Attack surface JSONL per target
  cat domains.txt | fray test -c xss -m 10       XSS test all targets (JSONL output)
  subfinder -d example.com | fray detect         Chain with any tool
  cat targets.txt | fray recon | jq '.risk_level'   Filter with jq

  📖 Docs:   https://dalisec.io/docs/#quickstart
  🔗 GitHub: https://github.com/dalisecurity/fray
  ⚠️  Only test systems you own or have written permission to test.
""")


def _cmd_update_legacy(args):
    """Legacy update — now delegates to cloud sync cmd_update."""
    cmd_update(args)


def cmd_cache(args):
    """Manage the adaptive payload cache (fray cache)."""
    from fray.adaptive_cache import (
        print_cache_summary, clear_domain_cache, get_domain_stats, load_cache,
        export_cache, import_cache,
    )

    sub = getattr(args, "cache_cmd", None) or "show"

    if sub == "show":
        domain = getattr(args, "domain", "") or ""
        print()
        print("  Fray Adaptive Cache")
        print("  -------------------")
        print_cache_summary(domain)
        print()

    elif sub == "clear":
        domain = getattr(args, "domain", "") or ""
        removed = clear_domain_cache(domain)
        if removed:
            target = domain if domain else "all domains"
            print(f"  Cache cleared for {target} ({removed} entr{'y' if removed == 1 else 'ies'} removed).")
        else:
            print("  Nothing to clear.")

    elif sub == "stats":
        domain = getattr(args, "domain", "")
        if not domain:
            cache = load_cache()
            if not cache:
                print("  No cache data yet.")
                return
            import json as _json
            print(_json.dumps(cache, indent=2))
        else:
            stats = get_domain_stats(domain)
            if not stats:
                print(f"  No cache data for {domain}")
            else:
                import json as _json
                print(_json.dumps(stats, indent=2))

    elif sub == "export":
        output = getattr(args, "output", "") or "fray-cache-export.json"
        domain = getattr(args, "domain", "") or ""
        result = export_cache(output, domain=domain)
        print(f"  Exported {result['domains']} domain(s) to {result['path']}")

    elif sub == "import":
        input_path = getattr(args, "file", "")
        if not input_path:
            print("  Error: specify a file to import.  Usage: fray cache import <file>")
            return
        merge = not getattr(args, "replace", False)
        result = import_cache(input_path, merge=merge)
        mode = "merged" if result["merged"] else "replaced"
        print(f"  Imported {result['imported_domains']} domain(s) ({mode}). Total: {result['total_domains']} domain(s).")

    else:
        print(f"  Unknown cache subcommand: {sub}")
        print("  Usage: fray cache [show|clear|stats|export|import] [domain]")


def cmd_init_config(args):
    """Create a sample .fray.toml in the current directory"""
    target = Path.cwd() / ".fray.toml"
    if target.exists():
        print(f".fray.toml already exists at {target}")
        sys.exit(1)
    sample = '''\
# Fray configuration file
# CLI arguments always override these defaults.

[test]
timeout = 8
delay = 0.5
# category = "xss"
# insecure = false
# verbose = false
redirect_limit = 5

[test.auth]
# cookie = "session=abc123"
# bearer = "eyJ..."

[bounty]
max = 10
workers = 1
delay = 0.5

[webhook]
# url = "https://hooks.slack.com/services/..."
'''
    target.write_text(sample, encoding="utf-8")
    print(f"Created {target}")
    print("Edit the file to set your defaults, then run fray commands as usual.")


def list_categories():
    """Get sorted list of payload category names"""
    return sorted([
        d.name for d in PAYLOADS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])


def main():
    parser = argparse.ArgumentParser(
        prog="fray",
        description=f"Fray v{__version__} — AI-Powered WAF Security Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fray detect https://example.com
  fray test https://example.com --category xss
  fray test https://example.com --category xss --smart
  fray recon https://example.com

Pipe-friendly (like httpx):
  cat domains.txt | fray detect                    # WAF detect all targets
  cat domains.txt | fray recon                     # JSONL attack surface per target
  cat domains.txt | fray test -c xss -m 10         # XSS test all targets
  echo example.com | fray recon --json             # single target via pipe
  subfinder -d example.com | fray detect           # chain with subfinder
  cat targets.txt | fray recon | jq '.risk_level'  # chain with jq

Docs:   https://dalisec.io/docs/#quickstart
GitHub: https://github.com/dalisecurity/fray
        """
    )

    # Global flags
    parser.add_argument("--no-hints", action="store_true", default=False,
                        help="Suppress 'Next Steps' hints after commands (or set FRAY_NO_HINTS=1)")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # recon
    p_recon = subparsers.add_parser("recon", help="Reconnaissance: HTTP, TLS, headers, app fingerprinting")
    p_recon.add_argument("target", nargs="?", default=None, help="Target URL (or pipe: cat domains.txt | fray recon)")
    p_recon.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_recon.add_argument("--json", action="store_true", help="Output raw JSON instead of pretty-print")
    p_recon.add_argument("--ai", action="store_true", help="AI-ready structured JSON output for LLM consumption")
    p_recon.add_argument("-o", "--output", default=None, help="Save recon JSON to file")
    p_recon.add_argument("--cookie", default=None, help="Cookie header for authenticated recon")
    p_recon.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_recon.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_recon.add_argument("--login-flow", default=None,
                          help="Form login: 'URL,field=value,field=value' — captures session cookies")
    p_recon.add_argument("--save-session", dest="save_session", default=None, metavar="NAME",
                          help="Save session cookies/tokens to ~/.fray/sessions/NAME.json for reuse")
    p_recon.add_argument("--load-session", dest="load_session", default=None, metavar="NAME",
                          help="Load a saved session from ~/.fray/sessions/NAME.json")
    p_recon.add_argument("-q", "--quiet", action="store_true",
                          help="Suppress all non-essential output (only errors and JSON)")
    p_recon.add_argument("-v", "--verbose", action="store_true",
                          help="Verbose output with extra debugging details")
    p_recon.add_argument("--profile", default=None,
                          choices=["quick", "standard", "deep", "stealth", "api", "bounty"],
                          help="Scan preset: quick (~10s), standard (default), deep (~60s), stealth (slow+evasive), api (API-focused), bounty (max coverage)")
    p_recon.add_argument("--fast", action="store_true",
                          help="Fast mode (~15s): skip historical URLs, admin panels, rate limits, GraphQL")
    p_recon.add_argument("--deep", action="store_true",
                          help="Deep mode (~45s): extended DNS (SOA/CAA/SRV/PTR), 300-word subdomain list, Wayback 500")
    p_recon.add_argument("--stealth", action="store_true",
                          help="Stealth mode: 3 parallel threads (vs 13), 0.5-1.5s jitter between requests")
    p_recon.add_argument("--retirejs", action="store_true",
                          help="Fetch Retire.js DB for broader frontend CVE coverage (requires network)")
    p_recon.add_argument("--compare", nargs="?", const="last", default=None,
                          help="Compare with previous scan (default: 'last', or path to JSON file)")
    p_recon.add_argument("--js", action="store_true",
                          help="JS endpoint extraction: find hidden API routes in JavaScript files")
    p_recon.add_argument("--history", action="store_true",
                          help="Historical URL discovery: Wayback Machine, sitemap.xml, robots.txt")
    p_recon.add_argument("--params", action="store_true",
                          help="Parameter mining: brute-force hidden URL parameters (not dir fuzzing)")
    p_recon.add_argument("--sarif", action="store_true",
                          help="Output SARIF 2.1.0 for GitHub/GitLab Security tab")
    p_recon.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                          help="Send Slack/Discord/Teams notification (e.g. https://hooks.slack.com/...)")
    p_recon.add_argument("--ci", action="store_true",
                          help="CI/CD mode: minimal output, JSON to stdout, non-zero exit on findings")
    p_recon.add_argument("--fail-on", dest="fail_on", default=None,
                          choices=["critical", "high", "medium", "low"],
                          help="Exit code 1 if any finding >= this severity (implies --ci)")
    p_recon.add_argument("--leak", action="store_true",
                          help="Include leak search: GitHub code + HIBP breach check (needs GITHUB_TOKEN)")
    p_recon.add_argument("--export-dir", dest="export_dir", default=None, metavar="DIR",
                          help="Export structured results to DIR (default: ~/.fray/recon/{domain}/)")
    p_recon.add_argument("--no-export", dest="no_export", action="store_true",
                          help="Disable auto-export of structured results")
    p_recon.add_argument("--ai-summary", dest="ai_summary", action="store_true",
                          help="AI-powered summary: prioritized findings + recommended next fray commands (needs OPENAI_API_KEY or ANTHROPIC_API_KEY)")
    p_recon.add_argument("--no-interactive", dest="no_interactive", action="store_true",
                          help="Skip interactive menu after recon (default: show menu in TTY)")
    p_recon.set_defaults(func=cmd_recon)

    # detect
    p_detect = subparsers.add_parser("detect", help="Detect WAF vendor on target URL")
    p_detect.add_argument("target", nargs="?", default=None, help="Target URL (or pipe: cat domains.txt | fray detect)")
    p_detect.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    p_detect.add_argument("--cookie", default=None, help="Cookie header for authenticated detection")
    p_detect.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_detect.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_detect.add_argument("--login-flow", default=None,
                           help="Form login: 'URL,field=value,field=value' — captures session cookies")
    p_detect.add_argument("--save-session", dest="save_session", default=None, metavar="NAME",
                           help="Save session cookies/tokens to ~/.fray/sessions/NAME.json")
    p_detect.add_argument("--load-session", dest="load_session", default=None, metavar="NAME",
                           help="Load a saved session from ~/.fray/sessions/NAME.json")
    p_detect.add_argument("-q", "--quiet", action="store_true",
                           help="Suppress all non-essential output")
    p_detect.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose output with extra debugging details")
    p_detect.set_defaults(func=cmd_detect)

    # test
    p_test = subparsers.add_parser("test", help="Test WAF with attack payloads")
    p_test.add_argument("target", nargs="?", default=None, help="Target URL (or pipe: cat domains.txt | fray test -c xss)")
    p_test.add_argument("-c", "--category", help="Payload category (e.g. xss, sqli, ssrf)")
    p_test.add_argument("-p", "--payload-file", help="Specific payload file to use")
    p_test.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    p_test.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    p_test.add_argument("--profile", default=None,
                         choices=["quick", "standard", "deep", "stealth", "api", "bounty"],
                         help="Scan preset: quick (fast, 20 payloads), standard (default), deep (all cats, mutate), stealth (slow+evasive), api (API cats), bounty (max coverage + resume)")
    p_test.add_argument("--all", action="store_true", help="Test all payload categories")
    p_test.add_argument("-m", "--max", type=int, default=None, help="Maximum number of payloads to test")
    p_test.add_argument("-o", "--output", default=None, help="Output results JSON file")
    p_test.add_argument("--smart", action="store_true",
                         help="Adaptive payload evolution: probe WAF, skip redundant payloads, mutate bypasses")
    p_test.add_argument("--webhook", default=None, help="Webhook URL for notifications (Slack/Discord/Teams)")
    p_test.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    p_test.add_argument("--cookie", default=None, help="Cookie header value for authenticated scanning")
    p_test.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_test.add_argument("-H", "--header", action="append", help="Custom header (repeatable, format: 'Name: Value')")
    p_test.add_argument("--login-flow", default=None,
                         help="Form login: 'URL,field=value,field=value' — captures session cookies")
    p_test.add_argument("-v", "--verbose", action="store_true", help="Show raw HTTP request/response for debugging")
    p_test.add_argument("--no-follow-redirects", action="store_true", help="Do not follow HTTP redirects")
    p_test.add_argument("--redirect-limit", type=int, default=5, help="Max redirects to follow (default: 5, 0 = none)")
    p_test.add_argument("--report-format", choices=["html", "markdown"], default=None,
                         help="Auto-generate report in this format after testing")
    p_test.add_argument("-y", "--yes", action="store_true",
                         help="Skip interactive prompt in --smart mode (auto-accept recommendations)")
    p_test.add_argument("--scope", default=None,
                         help="Scope file — only test targets listed in this file (one domain/IP/CIDR per line)")
    p_test.add_argument("--jitter", type=float, default=0.0,
                         help="Random delay variance in seconds added to --delay (e.g. --jitter 1.0)")
    p_test.add_argument("--stealth", action="store_true",
                         help="Stealth mode: randomize User-Agent, add jitter, throttle requests — evade rate limiting")
    p_test.add_argument("--rate-limit", type=float, default=0.0,
                         help="Max requests per second (e.g. --rate-limit 2 = max 2 req/s)")
    p_test.add_argument("--auto-throttle", action="store_true", dest="auto_throttle",
                         help="Fingerprint rate limits before testing, auto-set delay")
    p_test.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    p_test.add_argument("--ai", action="store_true", help="AI-ready structured JSON output for LLM consumption")
    p_test.add_argument("--sarif", action="store_true", help="Output SARIF 2.1.0 for GitHub Security tab / CodeQL")
    p_test.add_argument("--mutate", type=int, nargs="?", const=10, default=0, metavar="N",
                          help="Auto-mutate blocked payloads and re-test (default: 10 variants per payload)")
    p_test.add_argument("--blind", action="store_true",
                         help="Enable blind injection detection (time-based SQLi/SSTI/CMDi + OOB DNS)")
    p_test.add_argument("--oob-server", default=None, metavar="DOMAIN",
                         help="OOB callback server for blind detection (e.g. oast.fun, interact.sh)")
    p_test.add_argument("--auth-profile", default=None, metavar="FILE",
                         help="Auth profile JSON file (~/.fray/auth/*.json) — OAuth2, form login, multi-step")
    p_test.add_argument("--save-session", dest="save_session", default=None, metavar="NAME",
                         help="Save session cookies/tokens to ~/.fray/sessions/NAME.json for reuse")
    p_test.add_argument("--load-session", dest="load_session", default=None, metavar="NAME",
                         help="Load a saved session from ~/.fray/sessions/NAME.json")
    p_test.add_argument("--resume", action="store_true",
                         help="Resume an interrupted scan from checkpoint (~/.fray/checkpoints/)")
    p_test.add_argument("-q", "--quiet", action="store_true",
                         help="Suppress all non-essential output (only errors and JSON)")
    p_test.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                         help="Send Slack/Discord/Teams notification on completion")
    p_test.set_defaults(func=cmd_test)

    # bypass
    p_bypass = subparsers.add_parser("bypass",
        help="WAF bypass scoring — evasion-optimized payload testing with scorecard")
    p_bypass.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_bypass.add_argument("--waf", default=None,
                          help="WAF vendor (cloudflare, akamai, aws_waf, imperva, f5, fastly, modsecurity)")
    p_bypass.add_argument("-c", "--category", default=None, help="Payload category (default: xss)")
    p_bypass.add_argument("-m", "--max", type=int, default=50, help="Max payloads to test (default: 50)")
    p_bypass.add_argument("--mutations", type=int, default=5, help="Max mutations per bypass (default: 5)")
    p_bypass.add_argument("--mutation-budget", type=int, default=30,
                          help="Total mutation test budget across all phases (default: 30)")
    p_bypass.add_argument("--param", default="input", help="URL parameter to inject into (default: input)")
    p_bypass.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_bypass.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    p_bypass.add_argument("-o", "--output", default=None, help="Save bypass scorecard JSON to file")
    p_bypass.add_argument("--json", action="store_true", help="Output scorecard as JSON to stdout")
    p_bypass.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification")
    p_bypass.add_argument("-v", "--verbose", action="store_true", help="Show raw HTTP requests")
    p_bypass.add_argument("--list-wafs", action="store_true", help="List supported WAF targets and exit")
    p_bypass.add_argument("--scope", default=None,
                          help="Scope file — only test targets in this file")
    p_bypass.add_argument("--cookie", default=None, help="Cookie header for authenticated scanning")
    p_bypass.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_bypass.add_argument("-H", "--header", action="append",
                          help="Custom header (repeatable, format: 'Name: Value')")
    p_bypass.add_argument("--login-flow", default=None,
                          help="Form login: 'URL,field=value,field=value'")
    p_bypass.add_argument("--jitter", type=float, default=0.0,
                          help="Random delay variance in seconds")
    p_bypass.add_argument("--stealth", action="store_true",
                          help="Stealth mode: UA rotation + jitter + throttle")
    p_bypass.add_argument("--rate-limit", type=float, default=0.0,
                          help="Max requests per second")
    p_bypass.add_argument("--burp", default=None, metavar="FILE",
                            help="Export results as Burp Suite XML")
    p_bypass.add_argument("--zap", default=None, metavar="FILE",
                            help="Export results as ZAP alerts JSON")
    p_bypass.add_argument("--nuclei-export", dest="nuclei_export", default=None, metavar="DIR",
                            help="Export bypasses as Nuclei YAML templates")
    p_bypass.add_argument("--share", action="store_true",
                            help="Export bypass recipes (anonymized) for community sharing")
    p_bypass.set_defaults(func=cmd_bypass)

    # ai-bypass
    p_ai = subparsers.add_parser("ai-bypass",
        help="AI-assisted WAF bypass — LLM-generated payloads with adaptive feedback")
    p_ai.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_ai.add_argument("-c", "--category", default="xss",
                      help="Attack category: xss, sqli, ssti, command_injection (default: xss)")
    p_ai.add_argument("--param", default="input", help="URL parameter to inject into (default: input)")
    p_ai.add_argument("--rounds", type=int, default=3, help="Adaptive generation rounds (default: 3)")
    p_ai.add_argument("--max-per-round", type=int, default=10, dest="max_per_round",
                      help="Max payloads per round (default: 10)")
    p_ai.add_argument("--no-headers", action="store_true", dest="no_headers",
                      help="Skip header manipulation bypass testing")
    p_ai.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_ai.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests")
    p_ai.add_argument("-o", "--output", default=None, help="Save results JSON to file")
    p_ai.add_argument("--json", action="store_true", help="Output as JSON to stdout")
    p_ai.add_argument("--insecure", action="store_true", help="Skip SSL verification")
    p_ai.add_argument("--cookie", default=None, help="Cookie header")
    p_ai.add_argument("--bearer", default=None, help="Bearer token")
    p_ai.add_argument("-H", "--header", action="append",
                      help="Custom header (repeatable, format: 'Name: Value')")
    p_ai.add_argument("--stealth", action="store_true", help="Stealth mode")
    p_ai.add_argument("--rate-limit", type=float, default=0.0, help="Max requests per second")
    p_ai.add_argument("--jitter", type=float, default=0.0, help="Random delay variance")
    p_ai.add_argument("--scope", default=None, help="Scope file")
    p_ai.set_defaults(func=cmd_ai_bypass)

    # agent
    p_agent = subparsers.add_parser("agent",
        help="Self-improving payload agent — iterative probe → mutate → learn loop")
    p_agent.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_agent.add_argument("-c", "--category", default="xss",
                         help="Payload categories, comma-separated (default: xss)")
    p_agent.add_argument("--param", default="input", help="URL parameter to inject (default: input)")
    p_agent.add_argument("--rounds", type=int, default=5, help="Max mutation rounds (default: 5)")
    p_agent.add_argument("--budget", type=int, default=100,
                         help="Total HTTP request budget (default: 100)")
    p_agent.add_argument("--ai", action="store_true",
                         help="Enable batched LLM fallback (needs OPENAI_API_KEY or ANTHROPIC_API_KEY)")
    p_agent.add_argument("--no-cache", action="store_true", dest="no_cache",
                         help="Disable learned pattern cache (~/.fray/learned_patterns.json)")
    p_agent.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_agent.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests")
    p_agent.add_argument("-o", "--output", default=None, help="Save results JSON to file")
    p_agent.add_argument("--json", action="store_true", help="Output as JSON to stdout")
    p_agent.add_argument("--insecure", action="store_true", help="Skip SSL verification")
    p_agent.add_argument("--cookie", default=None, help="Cookie header")
    p_agent.add_argument("--bearer", default=None, help="Bearer token")
    p_agent.add_argument("-H", "--header", action="append",
                         help="Custom header (repeatable, format: 'Name: Value')")
    p_agent.add_argument("--stealth", action="store_true", help="Stealth mode")
    p_agent.add_argument("--rate-limit", type=float, default=0.0, help="Max requests per second")
    p_agent.add_argument("--jitter", type=float, default=0.0, help="Random delay variance")
    p_agent.add_argument("--scope", default=None, help="Scope file")
    p_agent.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                         help="Send webhook notification on completion")
    p_agent.set_defaults(func=cmd_agent)

    # feed (threat intelligence)
    p_feed = subparsers.add_parser("feed",
        help="Threat intelligence feed — auto-discover & ingest new attack vectors from CVEs, advisories, and research")
    p_feed.add_argument("--sources", default=None,
                        help="Comma-separated sources: nvd,cisa,github,exploitdb,rss,nuclei (default: all)")
    p_feed.add_argument("--since", default="7d",
                        help="Look back period: 7d, 2w, 30d (default: 7d)")
    p_feed.add_argument("-c", "--category", default=None,
                        help="Filter by payload category (e.g. xss, sqli, ssrf)")
    p_feed.add_argument("--auto-add", action="store_true", dest="auto_add",
                        help="Auto-add new payloads to database (default: stage for review)")
    p_feed.add_argument("--dry-run", action="store_true", dest="dry_run",
                        help="Show what would be added without writing any files")
    p_feed.add_argument("--list-sources", action="store_true", dest="list_sources",
                        help="List all available threat intel sources")
    p_feed.add_argument("--test-target", default=None, dest="test_target",
                        metavar="URL",
                        help="Auto-test new payloads against this target URL after ingestion")
    p_feed.add_argument("-d", "--delay", type=float, default=0.3,
                        help="Delay between test requests (default: 0.3)")
    p_feed.add_argument("-t", "--timeout", type=int, default=8,
                        help="Request timeout for tests (default: 8)")
    p_feed.add_argument("--insecure", action="store_true",
                        help="Skip SSL verification for tests")
    p_feed.add_argument("--warm-cache", action="store_true", dest="warm_cache",
                        help="Pre-populate adaptive cache with threat intel payloads (#46)")
    p_feed.add_argument("--json", action="store_true", help="Output as JSON")
    p_feed.add_argument("-o", "--output", default=None, help="Save results to file")
    p_feed.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                        help="Send webhook notification on completion")
    p_feed.set_defaults(func=cmd_feed)

    # update (pull latest payload DB)
    p_update = subparsers.add_parser("update",
        help="Pull latest payload database from cloud (R2 / GitHub Releases)")
    p_update.add_argument("--source", default="auto",
                          choices=["auto", "r2", "github"],
                          help="Download source: auto (R2 first, then GitHub), r2, or github")
    p_update.add_argument("--json", action="store_true", help="Output as JSON")
    p_update.set_defaults(func=cmd_update)

    # sync (push/pull/configure cloud)
    p_sync = subparsers.add_parser("sync",
        help="Cloud sync — publish or pull payload database (R2 + GitHub)")
    p_sync.add_argument("--push", action="store_true",
                        help="Publish local payload DB to cloud (maintainer)")
    p_sync.add_argument("--pull", action="store_true",
                        help="Pull latest payload DB from cloud")
    p_sync.add_argument("--source", default="auto",
                        choices=["auto", "r2", "github"],
                        help="Source for pull: auto, r2, or github")
    p_sync.add_argument("--tag", default=None,
                        help="Release tag for push (default: payloads-YYYYMMDD)")
    p_sync.add_argument("--configure", action="store_true",
                        help="Interactive setup of R2/D1/GitHub credentials")
    p_sync.add_argument("--status", action="store_true",
                        help="Show cloud sync configuration status")
    p_sync.add_argument("--json", action="store_true", help="Output as JSON")
    p_sync.set_defaults(func=cmd_sync)

    # todo (internal private TODO list)
    p_todo = subparsers.add_parser("todo",
        help="Internal TODO list — private, stored in ~/.fray/todo.json")
    p_todo_sub = p_todo.add_subparsers(dest="action")
    p_todo_sub.default = "list"

    # todo list (default)
    p_todo_list = p_todo_sub.add_parser("list", help="Show pending items")
    p_todo_list.add_argument("--all", action="store_true", help="Show completed items too")
    p_todo_list.add_argument("--json", action="store_true", help="Output as JSON")

    # todo add
    p_todo_add = p_todo_sub.add_parser("add", help="Add a new item")
    p_todo_add.add_argument("text", nargs="+", help="Task description")
    p_todo_add.add_argument("-p", "--priority", default="medium",
                            choices=["high", "medium", "low"],
                            help="Priority (default: medium)")
    p_todo_add.add_argument("--json", action="store_true", help="Output as JSON")

    # todo done
    p_todo_done = p_todo_sub.add_parser("done", help="Mark item as completed")
    p_todo_done.add_argument("id", type=int, help="Item ID")
    p_todo_done.add_argument("--json", action="store_true", help="Output as JSON")

    # todo rm
    p_todo_rm = p_todo_sub.add_parser("rm", help="Remove an item")
    p_todo_rm.add_argument("id", type=int, help="Item ID")
    p_todo_rm.add_argument("--json", action="store_true", help="Output as JSON")

    p_todo.add_argument("--all", action="store_true", help="Show completed items too")
    p_todo.add_argument("--json", action="store_true", help="Output as JSON")
    p_todo.set_defaults(func=cmd_todo)

    # harden
    p_harden = subparsers.add_parser("harden",
        help="OWASP Top 10 misconfiguration checks + security header hardening audit")
    p_harden.add_argument("target", nargs="?", default=None, help="Target URL to check")
    p_harden.add_argument("--json", action="store_true", help="Output as JSON")
    p_harden.add_argument("-o", "--output", default=None, help="Save report to file")
    p_harden.set_defaults(func=cmd_harden)

    # auto
    # go — zero-knowledge guided pipeline
    p_go = subparsers.add_parser("go",
        help="Guided pipeline: recon → smart test → report (zero-knowledge, one command)")
    p_go.add_argument("target", nargs="?", default=None, help="Target URL (e.g. example.com)")
    p_go.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_go.add_argument("--deep", action="store_true", help="Deep mode: extended DNS, 300 subdomains, Wayback 500")
    p_go.add_argument("--stealth", action="store_true", help="Stealth mode: slower, randomized requests")
    p_go.add_argument("-o", "--output", default=None, help="Save pipeline summary JSON to file")
    p_go.add_argument("--output-dir", dest="output_dir", default=None, help="Output directory for report + JSON")
    p_go.add_argument("--json", action="store_true", help="Output pipeline summary as JSON")
    p_go.add_argument("--cookie", default=None, help="Cookie header for authenticated testing")
    p_go.add_argument("--bearer", default=None, help="Bearer token for Authorization header")
    p_go.add_argument("-H", "--header", action="append", help="Custom header (repeatable)")
    p_go.add_argument("--login-flow", default=None, help="Form login: 'URL,field=value,field=value'")
    p_go.add_argument("--load-session", dest="load_session", default=None, metavar="NAME",
                       help="Load a saved session from ~/.fray/sessions/NAME.json")
    p_go.add_argument("--save-session", dest="save_session", default=None, metavar="NAME",
                       help="Save session cookies/tokens after pipeline")
    p_go.set_defaults(func=cmd_go)

    # auto — full pipeline (legacy, more flags)
    p_auto = subparsers.add_parser("auto",
        help="Full pipeline: recon → scan → ai-bypass in one command")
    p_auto.add_argument("target", nargs="?", default=None, help="Target URL")
    p_auto.add_argument("-c", "--category", default="xss",
                        help="Attack category (default: xss)")
    p_auto.add_argument("--param", default="input", help="URL parameter (default: input)")
    p_auto.add_argument("--max", type=int, default=20, help="Max payloads for scan (default: 20)")
    p_auto.add_argument("--rounds", type=int, default=2, help="AI bypass rounds (default: 2)")
    p_auto.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout")
    p_auto.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests")
    p_auto.add_argument("-o", "--output", default=None, help="Save full report JSON to file")
    p_auto.add_argument("--json", action="store_true", help="Output as JSON")
    p_auto.add_argument("--insecure", action="store_true", help="Skip SSL verification")
    p_auto.add_argument("--cookie", default=None, help="Cookie header")
    p_auto.add_argument("--bearer", default=None, help="Bearer token")
    p_auto.add_argument("-H", "--header", action="append",
                        help="Custom header (repeatable)")
    p_auto.add_argument("--stealth", action="store_true", help="Stealth mode")
    p_auto.add_argument("--scope", default=None, help="Scope file")
    p_auto.add_argument("--skip-recon", action="store_true", dest="skip_recon",
                        help="Skip recon phase")
    p_auto.add_argument("--skip-scan", action="store_true", dest="skip_scan",
                        help="Skip scan phase")
    p_auto.add_argument("--skip-bypass", action="store_true", dest="skip_bypass",
                        help="Skip ai-bypass phase")
    p_auto.set_defaults(func=cmd_auto)

    # diff
    p_diff = subparsers.add_parser("diff",
        help="Compare two scan results — surface regressions and improvements")
    p_diff.add_argument("before", help="Baseline scan results JSON (before WAF change)")
    p_diff.add_argument("after", help="New scan results JSON (after WAF change)")
    p_diff.add_argument("-o", "--output", default=None, help="Save diff report JSON to file")
    p_diff.add_argument("--json", action="store_true", help="Output diff as JSON to stdout")
    p_diff.set_defaults(func=cmd_diff)

    # smuggle
    p_smuggle = subparsers.add_parser("smuggle",
        help="HTTP request smuggling detection (CL.TE / TE.CL / TE.TE)")
    p_smuggle.add_argument("target", nargs="?", default=None, help="Target URL to test")
    p_smuggle.add_argument("-t", "--timeout", type=int, default=10,
                           help="Request timeout in seconds (default: 10)")
    p_smuggle.add_argument("-d", "--delay", type=float, default=1.0,
                           help="Delay between probes (default: 1.0)")
    p_smuggle.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_smuggle.add_argument("--json", action="store_true", help="Output report as JSON")
    p_smuggle.add_argument("--insecure", action="store_true", help="Skip SSL verification")
    p_smuggle.set_defaults(func=cmd_smuggle)

    # report
    p_report = subparsers.add_parser("report", help="Generate HTML security report")
    p_report.add_argument("-i", "--input", help="Input results JSON file")
    p_report.add_argument("-o", "--output", default="fray_report.html", help="Output HTML file")
    p_report.add_argument("--sample", action="store_true", help="Generate a sample demo report")
    p_report.add_argument("--format", choices=["html", "markdown"], default="html", help="Report format (default: html)")
    p_report.set_defaults(func=cmd_report)

    # payloads
    p_payloads = subparsers.add_parser("payloads", help="List available payload categories")
    p_payloads.set_defaults(func=cmd_payloads)

    # scan
    p_scan = subparsers.add_parser("scan",
        help="Auto scan: crawl → param discovery → payload injection")
    p_scan.add_argument("target", help="Target URL to scan")
    p_scan.add_argument("-c", "--category", default="xss",
                         help="Payload category for injection (default: xss)")
    p_scan.add_argument("-m", "--max", type=int, default=5,
                         help="Max payloads per injection point (default: 5)")
    p_scan.add_argument("--depth", type=int, default=3,
                         help="Max crawl depth (default: 3)")
    p_scan.add_argument("--max-pages", type=int, default=30,
                         help="Max pages to crawl (default: 30)")
    p_scan.add_argument("-t", "--timeout", type=int, default=8,
                         help="Request timeout (default: 8)")
    p_scan.add_argument("-d", "--delay", type=float, default=0.3,
                         help="Delay between requests (default: 0.3)")
    p_scan.add_argument("-o", "--output", default=None,
                         help="Save scan results JSON to file")
    p_scan.add_argument("--json", action="store_true",
                         help="Output results as JSON to stdout")
    p_scan.add_argument("--ai", action="store_true",
                         help="AI-ready structured JSON output for LLM consumption")
    p_scan.add_argument("--sarif", action="store_true",
                         help="Output SARIF 2.1.0 for GitHub Security tab / CodeQL")
    p_scan.add_argument("--insecure", action="store_true",
                         help="Skip SSL certificate verification")
    p_scan.add_argument("--cookie", default=None,
                         help="Cookie header for authenticated scanning")
    p_scan.add_argument("--bearer", default=None,
                         help="Bearer token for Authorization header")
    p_scan.add_argument("-H", "--header", action="append",
                         help="Custom header (repeatable, format: 'Name: Value')")
    p_scan.add_argument("--jitter", type=float, default=0.0,
                         help="Random delay variance (default: 0)")
    p_scan.add_argument("--stealth", action="store_true",
                         help="Stealth mode: randomize UA, add jitter, throttle")
    p_scan.add_argument("--rate-limit", type=float, default=0.0,
                         help="Max requests per second (default: unlimited)")
    p_scan.add_argument("--scope", default=None,
                         help="Scope file: one domain/IP/CIDR per line (restricts crawl)")
    p_scan.add_argument("-w", "--workers", type=int, default=1,
                         help="Concurrent workers for crawl + injection (default: 1)")
    p_scan.add_argument("--auto-throttle", action="store_true", dest="auto_throttle",
                         help="Fingerprint rate limits before scanning, auto-set delay")
    p_scan.add_argument("--browser", action="store_true",
                         help="Use Playwright browser for JS-heavy SPAs (requires: pip install playwright)")
    p_scan.add_argument("--burp", default=None, metavar="FILE",
                         help="Export results as Burp Suite XML (e.g. --burp results.xml)")
    p_scan.add_argument("--zap", default=None, metavar="FILE",
                         help="Export results as ZAP alerts JSON (e.g. --zap results.json)")
    p_scan.add_argument("--nuclei-export", dest="nuclei_export", default=None, metavar="DIR",
                         help="Export bypasses as Nuclei YAML templates to DIR")
    p_scan.add_argument("--burp-import", dest="burp_import", default=None, metavar="FILE",
                         help="Import Burp request file as scan targets")
    p_scan.add_argument("--blind", action="store_true",
                         help="Enable blind injection detection (time-based + OOB DNS)")
    p_scan.add_argument("--oob-server", default=None, metavar="DOMAIN",
                         help="OOB callback server for blind detection (e.g. oast.fun)")
    p_scan.add_argument("--auth-profile", default=None, metavar="FILE",
                         help="Auth profile JSON (~/.fray/auth/*.json) — OAuth2, form login, multi-step")
    p_scan.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                         help="Send Slack/Discord/Teams notification on completion")
    p_scan.set_defaults(func=cmd_scan)

    # graph
    p_graph = subparsers.add_parser("graph",
        help="Visualize attack surface: subdomains, DNS, tech, endpoints, exposed files")
    p_graph.add_argument("target", help="Target URL or domain (e.g. https://example.com)")
    p_graph.add_argument("--deep", action="store_true",
                          help="Deep mode: also discover JS endpoints + historical URLs")
    p_graph.add_argument("-t", "--timeout", type=int, default=8,
                          help="Request timeout (default: 8)")
    p_graph.add_argument("--json", action="store_true",
                          help="Output graph as JSON")
    p_graph.add_argument("-o", "--output", default=None,
                          help="Save graph JSON to file")
    p_graph.add_argument("--cookie", default=None,
                          help="Cookie header for authenticated scanning")
    p_graph.add_argument("--bearer", default=None,
                          help="Bearer token for Authorization header")
    p_graph.add_argument("-H", "--header", action="append",
                          help="Custom header (repeatable, format: 'Name: Value')")
    p_graph.add_argument("--login-flow", default=None,
                          help="Form login: 'URL,field=value,field=value'")
    p_graph.set_defaults(func=cmd_graph)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show payload database statistics")
    p_stats.add_argument("--json", action="store_true", help="Output as JSON")
    p_stats.add_argument("--waf-market", action="store_true", dest="waf_market",
                          help="Show WAF vendor market share from scan data")
    p_stats.add_argument("--trend", metavar="DOMAIN",
                          help="Show historical trend for a domain")
    p_stats.add_argument("--waf", action="store_true",
                          help="Show WAF effectiveness leaderboard (block rate per vendor from scan history)")
    p_stats.set_defaults(func=cmd_stats)

    # version
    p_version = subparsers.add_parser("version", help="Show version")
    p_version.set_defaults(func=cmd_version)

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check environment and auto-fix common issues")
    p_doctor.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")
    p_doctor.add_argument("-v", "--verbose", action="store_true", help="Show detailed fix suggestions")
    p_doctor.set_defaults(func=cmd_doctor)

    # submit-payload
    p_submit = subparsers.add_parser("submit-payload", help="Submit payload to community database via GitHub PR")
    p_submit.add_argument("--payload", default=None, help="Payload string to submit")
    p_submit.add_argument("-c", "--category", default=None, help="Payload category (e.g. xss, sqli)")
    p_submit.add_argument("--subcategory", default=None, help="Subcategory / target file (default: community)")
    p_submit.add_argument("--description", default=None, help="What the payload does")
    p_submit.add_argument("--technique", default=None, help="Technique (e.g. direct_injection, waf_bypass)")
    p_submit.add_argument("--name", default=None, help="Contributor name")
    p_submit.add_argument("--github", default=None, help="Contributor GitHub username")
    p_submit.add_argument("--file", default=None, help="JSON file with payloads for bulk submission")
    p_submit.add_argument("--dry-run", action="store_true", help="Preview without creating PR")
    p_submit.set_defaults(func=cmd_submit_payload)

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate WAF configuration (blue team report)")
    p_validate.add_argument("target", help="Target URL to validate")
    p_validate.add_argument("--waf", default=None, help="Expected WAF vendor (e.g. cloudflare, aws_waf, imperva)")
    p_validate.add_argument("--categories", default=None, help="Comma-separated payload categories to test")
    p_validate.add_argument("-m", "--max", type=int, default=10, help="Max payloads per category (default: 10)")
    p_validate.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_validate.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_validate.add_argument("-d", "--delay", type=float, default=0.3, help="Delay between requests (default: 0.3)")
    p_validate.add_argument("-v", "--verbose", action="store_true", help="Show detailed header and bypass info")
    p_validate.set_defaults(func=cmd_validate)

    # bounty
    p_bounty = subparsers.add_parser("bounty", help="Bug bounty platform integration (HackerOne/Bugcrowd)")
    p_bounty.add_argument("--platform", default=None, help="Platform: hackerone or bugcrowd")
    p_bounty.add_argument("--program", default=None, help="Program handle (e.g. github, tesla)")
    p_bounty.add_argument("--urls", default=None, help="Text file with URLs (one per line)")
    p_bounty.add_argument("--categories", default=None, help="Comma-separated payload categories (default: xss,sqli)")
    p_bounty.add_argument("-m", "--max", type=int, default=10, help="Max payloads per category per target (default: 10)")
    p_bounty.add_argument("-t", "--timeout", type=int, default=8, help="Request timeout (default: 8)")
    p_bounty.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    p_bounty.add_argument("-o", "--output", default=None, help="Save report JSON to file")
    p_bounty.add_argument("--scope-only", action="store_true", help="Show scope URLs only, don't run tests")
    p_bounty.add_argument("--force", action="store_true", help="Test ALL URLs including shared platforms (dangerous)")
    p_bounty.add_argument("--no-smart", action="store_true",
                          help="Disable adaptive payload evolution (use brute-force instead)")
    p_bounty.add_argument("-w", "--workers", type=int, default=1,
                          help="Parallel workers for multi-target scanning (default: 1)")
    p_bounty.set_defaults(func=cmd_bounty)

    # ci
    p_ci = subparsers.add_parser("ci", help="Generate GitHub Actions workflow for WAF testing on PRs")
    p_ci.add_argument("action", nargs="?", default="init", choices=["init", "show"],
                      help="Action: init (write file) or show (print to stdout)")
    p_ci.add_argument("--target", default=None, help="Default target URL for WAF tests")
    p_ci.add_argument("--categories", default=None, help="Comma-separated payload categories (e.g. xss,sqli)")
    p_ci.add_argument("-m", "--max", type=int, default=50, help="Max payloads per run (default: 50)")
    p_ci.add_argument("--webhook", default=None, help="Webhook URL for notifications")
    p_ci.add_argument("--fail-on-bypass", action="store_true", help="Fail CI if any payload bypasses WAF")
    p_ci.add_argument("--no-comment", action="store_true", help="Disable PR comment with results")
    p_ci.add_argument("--minimal", action="store_true", help="Generate minimal workflow")
    p_ci.add_argument("--output-dir", default=None, help="Output directory (default: current dir)")
    p_ci.set_defaults(func=cmd_ci)

    # learn
    p_learn = subparsers.add_parser("learn", help="Interactive CTF-style security tutorial")
    p_learn.add_argument("topic", nargs="?", default=None, help="Topic to learn (xss, sqli, ssrf, cmdi)")
    p_learn.add_argument("--level", type=int, default=None, help="Jump to specific level")
    p_learn.add_argument("--list", action="store_true", help="List all topics and progress")
    p_learn.add_argument("--reset", action="store_true", help="Reset all progress")
    p_learn.set_defaults(func=cmd_learn)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Start MCP server for AI assistant integration")
    p_mcp.set_defaults(func=cmd_mcp)

    # init-config
    p_init_config = subparsers.add_parser("init-config", help="Create a sample .fray.toml config file in the current directory")
    p_init_config.set_defaults(func=cmd_init_config)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain a CVE or scan results — human-readable findings with impact & remediation")
    p_explain.add_argument("cve_id", help="CVE ID (e.g. CVE-2021-44228) or results JSON file (e.g. results.json)")
    p_explain.add_argument("--max", type=int, default=5, help="Max payloads to show per CVE (default: 5)")
    p_explain.add_argument("--json", action="store_true", help="Output as JSON")
    p_explain.add_argument("-o", "--output", help="Save JSON output to file")
    p_explain.set_defaults(func=cmd_explain)

    # scope
    p_scope = subparsers.add_parser("scope", help="Inspect or validate a scope file for bug bounty testing")
    p_scope.add_argument("scope_file", help="Path to scope file (one domain/IP/CIDR per line)")
    p_scope.add_argument("--check", default=None, help="Check if a specific URL is in scope")
    p_scope.add_argument("--json", action="store_true", help="Output parsed scope as JSON")
    p_scope.set_defaults(func=cmd_scope)

    # leak
    p_leak = subparsers.add_parser("leak",
        help="Search for leaked credentials on GitHub and Have I Been Pwned")
    p_leak.add_argument("target", help="Domain (example.com) or email (user@example.com)")
    p_leak.add_argument("--github-only", action="store_true",
                         help="Only search GitHub code (skip HIBP)")
    p_leak.add_argument("--hibp-only", action="store_true",
                         help="Only search Have I Been Pwned (skip GitHub)")
    p_leak.add_argument("--json", action="store_true", help="Output as JSON")
    p_leak.add_argument("-o", "--output", default=None, help="Save results to file")
    p_leak.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (default: 10)")
    p_leak.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                         help="Send Slack/Discord/Teams notification on completion")
    p_leak.set_defaults(func=cmd_leak)

    # osint
    p_osint = subparsers.add_parser("osint",
        help="Offensive OSINT: whois, emails, typosquatting, GitHub org recon, employee enum, doc metadata")
    p_osint.add_argument("target", nargs="?", default=None,
                          help="Target domain (e.g. example.com)")
    p_osint.add_argument("--json", action="store_true", help="Output as JSON")
    p_osint.add_argument("-o", "--output", default=None, help="Save results to file")
    p_osint.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (default: 10)")
    p_osint.add_argument("--whois", dest="whois_only", action="store_true",
                          help="Whois lookup only")
    p_osint.add_argument("--emails", dest="emails_only", action="store_true",
                          help="Email harvesting only")
    p_osint.add_argument("--github", dest="github_only", action="store_true",
                          help="GitHub org recon + employee enumeration only")
    p_osint.add_argument("--docs", dest="docs_only", action="store_true",
                          help="Document metadata harvesting only")
    p_osint.add_argument("--permutations", dest="permutations_only", action="store_true",
                          help="Typosquatting / domain permutation check only")
    p_osint.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                          help="Send Slack/Discord/Teams notification on completion")
    p_osint.set_defaults(func=cmd_osint)

    # cred
    p_cred = subparsers.add_parser("cred",
        help="Credential stuffing test: test leaked email:password pairs against login endpoints")
    p_cred.add_argument("target", nargs="?", default=None,
                         help="Login endpoint URL (e.g. https://example.com/login)")
    p_cred.add_argument("--pairs", required=False, default=None,
                         help="File with credential pairs (email:password, one per line)")
    p_cred.add_argument("--username-field", dest="username_field", default=None,
                         help="Override username field name (auto-detected by default)")
    p_cred.add_argument("--password-field", dest="password_field", default=None,
                         help="Override password field name (auto-detected by default)")
    p_cred.add_argument("--content-type", dest="content_type", default=None,
                         help="Override content type (form or json)")
    p_cred.add_argument("--rate", type=float, default=1.0,
                         help="Max requests per second (default: 1)")
    p_cred.add_argument("-d", "--delay", type=float, default=1.0,
                         help="Delay between attempts in seconds (default: 1)")
    p_cred.add_argument("-m", "--max", type=int, default=0,
                         help="Max attempts (default: 0 = unlimited)")
    p_cred.add_argument("--proxy", default=None,
                         help="HTTP/HTTPS proxy URL")
    p_cred.add_argument("--dry-run", dest="dry_run", action="store_true",
                         help="Preview credential pairs without sending requests")
    p_cred.add_argument("-t", "--timeout", type=int, default=10,
                         help="Request timeout (default: 10)")
    p_cred.add_argument("--json", action="store_true", help="Output as JSON")
    p_cred.add_argument("-o", "--output", default=None, help="Save results to file")
    p_cred.add_argument("--cookie", default=None, help="Cookie header")
    p_cred.add_argument("--bearer", default=None, help="Bearer token")
    p_cred.add_argument("-H", "--header", action="append",
                         help="Custom header (repeatable, format: 'Name: Value')")
    p_cred.add_argument("--notify", default=None, metavar="WEBHOOK_URL",
                         help="Send Slack/Discord/Teams notification on completion")
    p_cred.set_defaults(func=cmd_cred)

    # monitor
    p_monitor = subparsers.add_parser("monitor",
        help="Continuous monitoring: periodic recon + leak, diff against previous, alert on changes")
    p_monitor.add_argument("target", nargs="?", default=None,
                            help="Target domain (e.g. example.com)")
    p_monitor.add_argument("--interval", default="24h",
                            help="Scan interval: 30m, 6h, 12h, 24h, 7d (default: 24h)")
    p_monitor.add_argument("--webhook", default=None,
                            help="Slack/Discord/Teams webhook URL for alerts")
    p_monitor.add_argument("--email", default=None,
                            help="Email address for alerts (needs RESEND_API_KEY)")
    p_monitor.add_argument("--leak", action="store_true",
                            help="Also run leak search each cycle (needs GITHUB_TOKEN)")
    p_monitor.add_argument("--once", action="store_true",
                            help="Run single cycle and exit (compare to last snapshot)")
    p_monitor.add_argument("--list", action="store_true",
                            help="List previous monitoring snapshots")
    p_monitor.add_argument("-t", "--timeout", type=int, default=10,
                            help="Request timeout (default: 10)")
    p_monitor.set_defaults(func=cmd_monitor)

    # demo
    p_demo = subparsers.add_parser("demo",
        help="Quick showcase: detect WAF + XSS scan (great for GIFs)")
    p_demo.add_argument("target", nargs="?", default=None,
                         help="Target URL (default: http://testphp.vulnweb.com)")
    p_demo.set_defaults(func=cmd_demo)

    # cache — adaptive payload cache management
    p_cache = subparsers.add_parser("cache",
        help="Adaptive payload cache — show stats, clear, or inspect learned data")
    p_cache_sub = p_cache.add_subparsers(dest="cache_cmd")

    p_cache_show = p_cache_sub.add_parser("show", help="Show cache summary (default)")
    p_cache_show.add_argument("domain", nargs="?", default="",
                               help="Filter to a specific domain (optional)")

    p_cache_clear = p_cache_sub.add_parser("clear", help="Clear cache for a domain or all")
    p_cache_clear.add_argument("domain", nargs="?", default="",
                                help="Domain to clear, or blank to clear everything")

    p_cache_stats = p_cache_sub.add_parser("stats", help="Dump raw cache JSON")
    p_cache_stats.add_argument("domain", nargs="?", default="",
                                help="Filter to a specific domain (optional)")

    p_cache_export = p_cache_sub.add_parser("export", help="Export cache to portable JSON file")
    p_cache_export.add_argument("-o", "--output", default="fray-cache-export.json",
                                 help="Output file path (default: fray-cache-export.json)")
    p_cache_export.add_argument("domain", nargs="?", default="",
                                 help="Export only this domain (optional)")

    p_cache_import = p_cache_sub.add_parser("import", help="Import cache from JSON file")
    p_cache_import.add_argument("file", help="Path to exported cache JSON")
    p_cache_import.add_argument("--replace", action="store_true",
                                 help="Replace existing cache instead of merging")

    p_cache.set_defaults(func=cmd_cache, cache_cmd="show")

    # completions
    p_completions = subparsers.add_parser("completions",
        help="Generate shell completion scripts (bash/zsh/fish)")
    p_completions.add_argument("shell", nargs="?", choices=["bash", "zsh", "fish"],
                                help="Shell to generate completions for")
    p_completions.set_defaults(func=cmd_completions)

    # help
    p_help = subparsers.add_parser("help",
        help="Show friendly guide to all fray commands")
    p_help.set_defaults(func=cmd_help)

    # ── Environment variable overrides (#186) ──────────────────────────────
    # FRAY_<FLAG> env vars → argparse defaults. CLI flags always win.
    # Example: FRAY_TIMEOUT=15 fray test target -c xss
    #          FRAY_DELAY=1.0 FRAY_CATEGORY=sqli fray test target

    _ENV_TYPE_MAP = {
        'timeout': int, 'delay': float, 'jitter': float, 'rate_limit': float,
        'max': int, 'redirect_limit': int, 'mutate': int,
    }
    _ENV_BOOL_KEYS = {
        'insecure', 'verbose', 'quiet', 'stealth', 'fast', 'deep', 'blind',
        'json', 'all', 'resume', 'retirejs', 'history', 'js', 'params', 'leak',
    }

    def _apply_env_overrides(args):
        """Apply FRAY_* environment variables as defaults. CLI flags take precedence."""
        import os as _os
        for key, val in _os.environ.items():
            if not key.startswith('FRAY_'):
                continue
            attr = key[5:].lower().replace('-', '_')
            current = getattr(args, attr, None)
            # Only apply if CLI didn't set it
            if current is not None and current is not False:
                continue
            if not hasattr(args, attr):
                continue
            if attr in _ENV_BOOL_KEYS:
                setattr(args, attr, val.lower() in ('1', 'true', 'yes'))
            elif attr in _ENV_TYPE_MAP:
                try:
                    setattr(args, attr, _ENV_TYPE_MAP[attr](val))
                except (ValueError, TypeError):
                    pass
            else:
                setattr(args, attr, val)

    # ── Scan Profile Presets ──────────────────────────────────────────────
    # Profiles map to argparse defaults. CLI flags always override profiles.
    # Usage: fray recon target --profile quick
    #        fray test target -c xss --profile bounty

    _RECON_PROFILES = {
        "quick":    {"fast": True, "timeout": 5},
        "standard": {},
        "deep":     {"deep": True, "retirejs": True, "history": True, "js": True,
                     "params": True, "leak": True, "timeout": 15},
        "stealth":  {"stealth": True, "timeout": 15},
        "api":      {"deep": True, "js": True, "params": True},
        "bounty":   {"deep": True, "retirejs": True, "history": True, "js": True,
                     "params": True, "leak": True, "timeout": 15,
                     "ai_summary": True},
    }

    _TEST_PROFILES = {
        "quick":    {"max": 20, "timeout": 5, "delay": 0.2},
        "standard": {},
        "deep":     {"all": True, "mutate": 10, "blind": True, "timeout": 12,
                     "delay": 0.5},
        "stealth":  {"stealth": True, "delay": 2.0, "jitter": 1.5,
                     "rate_limit": 1.0, "timeout": 15},
        "api":      {"category": "sqli,ssrf,ssti,path_traversal,command_injection",
                     "timeout": 10, "delay": 0.3},
        "bounty":   {"all": True, "mutate": 10, "blind": True, "resume": True,
                     "timeout": 12, "delay": 0.5, "auto_throttle": True},
    }

    def _apply_profile(args):
        """Apply --profile preset defaults. Explicit CLI flags take precedence."""
        profile = getattr(args, "profile", None)
        if not profile:
            return
        command = getattr(args, "command", "")
        profiles = _RECON_PROFILES if command == "recon" else _TEST_PROFILES
        defaults = profiles.get(profile, {})
        for key, value in defaults.items():
            current = getattr(args, key, None)
            # Only apply if CLI didn't set it (None for optional, False for store_true,
            # default values for typed args)
            if current is None or current is False:
                setattr(args, key, value)
            elif key == "max" and current is None:
                setattr(args, key, value)
            elif key == "delay" and current == 0.5 and value != 0.5:
                setattr(args, key, value)
            elif key == "timeout" and current == 8 and value != 8:
                setattr(args, key, value)

    args = parser.parse_args()

    if not args.command:
        from fray.welcome import print_welcome
        print_welcome()
        sys.exit(0)

    # ── --no-hints → FRAY_NO_HINTS ──
    if getattr(args, 'no_hints', False):
        os.environ["FRAY_NO_HINTS"] = "1"

    # ── Environment variable overrides (FRAY_* → argparse defaults) ──
    _apply_env_overrides(args)

    # Load .fray.toml: env vars first, then apply defaults for the active subcommand
    from fray.config import load_config, apply_config_defaults, load_env_from_config
    config = load_config()
    load_env_from_config(config)
    if config:
        apply_config_defaults(args, config, args.command)

    # Apply --profile presets (after config, before command execution)
    _apply_profile(args)

    # ── Verbosity level ──
    _verbosity = getattr(args, 'verbose', False)
    _quiet = getattr(args, 'quiet', False)
    args._verbosity = 2 if _verbosity else (0 if _quiet else 1)

    # ── Execute command and map exit code from severity ──
    _exit_code = 0
    try:
        result = args.func(args)
        # cmd functions may return a risk_score or severity hint
        if isinstance(result, dict):
            rs = result.get('risk_score', 0)
            if rs >= 60:
                _exit_code = 3  # CRITICAL
            elif rs >= 40:
                _exit_code = 2  # HIGH
            elif rs >= 20:
                _exit_code = 1  # MEDIUM
        elif isinstance(result, int):
            _exit_code = result
    except SystemExit as e:
        _exit_code = e.code if isinstance(e.code, int) else 1
    except KeyboardInterrupt:
        sys.stderr.write("\n  Interrupted.\n")
        _exit_code = 130
    sys.exit(_exit_code)


if __name__ == "__main__":
    main()
