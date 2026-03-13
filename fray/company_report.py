#!/usr/bin/env python3
"""
Fray — Automated Report Generation Per Company (#73)

Aggregates recon, scan, cache, and OSINT data for a domain
and generates a comprehensive Markdown or JSON report.

CLI:
    fray report --company example.com
    fray report --company example.com -o report.md
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"

_FRAY_DIR = Path.home() / ".fray"


def _load_json(path: Path) -> Optional[Dict]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _collect(domain: str) -> dict:
    """Collect all data sources for a domain."""
    recon = _load_json(_FRAY_DIR / "recon" / domain / "recon.json")
    cache_all = _load_json(_FRAY_DIR / "domain_cache.json") or {}
    cache = cache_all.get(domain, cache_all.get(f"www.{domain}"))
    osint = _load_json(_FRAY_DIR / "osint" / domain / "osint.json")
    scans = []
    sd = _FRAY_DIR / "recon" / domain
    if sd.exists():
        for f in sd.glob("*.json"):
            if f.name != "recon.json":
                d = _load_json(f)
                if d:
                    scans.append(d)
    return {"recon": recon, "cache": cache, "osint": osint, "scans": scans}


def generate_company_report(domain: str, output: str = "",
                             extra_scans: Optional[List[Dict]] = None) -> Dict:
    """Generate comprehensive company report dict."""
    now = datetime.now(timezone.utc)
    src = _collect(domain)
    recon = src["recon"]
    cache = src["cache"]
    osint = src["osint"]
    scans = src["scans"] + (extra_scans or [])

    report = {"company": domain, "generated_at": now.isoformat(),
              "fray_version": __version__, "sections": {}}

    # Executive Summary
    es = {"domain": domain, "sources": [], "risk_level": "unknown",
          "risk_score": 0, "key_findings": []}
    if recon:
        es["sources"].append("recon")
        atk = recon.get("attack_surface", {})
        es["risk_level"] = atk.get("risk_level", "unknown")
        es["risk_score"] = atk.get("risk_score", 0)
        es["key_findings"] = atk.get("findings", [])[:10]
    if cache:
        es["sources"].append("cache")
    if osint:
        es["sources"].append("osint")
    if scans:
        es["sources"].append(f"scans({len(scans)})")
    report["sections"]["executive_summary"] = es

    # Attack Surface
    if recon:
        atk = recon.get("attack_surface", {})
        report["sections"]["attack_surface"] = {
            "waf": atk.get("waf_vendor", "unknown"),
            "vectors": atk.get("attack_vectors", [])[:15],
            "hvt": atk.get("high_value_targets", [])[:15],
            "tests": atk.get("suggested_tests", [])[:10],
        }

    # Infrastructure
    if recon:
        infra = {}
        if recon.get("tls"):
            t = recon["tls"]
            infra["tls"] = {"version": t.get("tls_version", ""),
                            "cipher": t.get("cipher_suite", ""),
                            "issuer": t.get("issuer", "")}
        if recon.get("dns"):
            infra["dns"] = recon["dns"]
        if recon.get("technologies"):
            infra["tech"] = recon["technologies"][:15]
        if recon.get("security_headers"):
            infra["headers"] = recon["security_headers"]
        report["sections"]["infrastructure"] = infra

    # Subdomains
    if recon and recon.get("subdomains"):
        subs = recon["subdomains"]
        report["sections"]["subdomains"] = {
            "total": len(subs) if isinstance(subs, list) else subs,
            "sample": subs[:20] if isinstance(subs, list) else [],
        }

    # WAF / Cache stats
    if cache:
        report["sections"]["waf_cache"] = {
            "vendor": cache.get("waf_vendor", ""),
            "total_tested": cache.get("total_tested", 0),
            "total_blocked": cache.get("total_blocked", 0),
            "last_scan": cache.get("last_scan", ""),
        }

    # OSINT
    if osint:
        report["sections"]["osint"] = {
            "emails": osint.get("emails", {}).get("total", 0),
            "employees": osint.get("employees", {}).get("total_unique_people", 0),
            "github_repos": osint.get("github", {}).get("public_repos", 0),
            "typosquatting": osint.get("permutations", {}).get("registered", 0),
        }

    # Scan results
    if scans:
        scan_summary = []
        for s in scans[:10]:
            scan_summary.append({
                "target": s.get("target", ""),
                "total": s.get("summary", {}).get("total_tested", 0),
                "blocked": s.get("summary", {}).get("blocked", 0),
                "bypassed": s.get("summary", {}).get("passed", 0),
            })
        report["sections"]["scan_results"] = scan_summary

    if output:
        _write_report(report, output)

    return report


def _write_report(report: Dict, output: str):
    """Write report to file (Markdown or JSON based on extension)."""
    if output.endswith(".json"):
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return

    # Markdown output
    md = report_to_markdown(report)
    with open(output, "w", encoding="utf-8") as f:
        f.write(md)


def report_to_markdown(report: Dict) -> str:
    """Convert report dict to Markdown string."""
    s = report.get("sections", {})
    lines = []
    domain = report.get("company", "")

    lines.append(f"# Security Assessment — {domain}")
    lines.append(f"*Generated: {report.get('generated_at', '')} | Fray v{report.get('fray_version', '')}*\n")

    # Executive Summary
    es = s.get("executive_summary", {})
    lines.append("## Executive Summary\n")
    lines.append(f"- **Domain:** {es.get('domain', domain)}")
    lines.append(f"- **Risk Level:** {es.get('risk_level', 'N/A')}")
    lines.append(f"- **Risk Score:** {es.get('risk_score', 0)}/100")
    lines.append(f"- **Data Sources:** {', '.join(es.get('sources', []))}")
    findings = es.get("key_findings", [])
    if findings:
        lines.append(f"\n### Key Findings ({len(findings)})\n")
        for f in findings[:10]:
            if isinstance(f, dict):
                lines.append(f"- **{f.get('severity', '?')}** — {f.get('title', f.get('description', ''))}")
            else:
                lines.append(f"- {f}")

    # Attack Surface
    atk = s.get("attack_surface", {})
    if atk:
        lines.append("\n## Attack Surface\n")
        lines.append(f"- **WAF:** {atk.get('waf', 'unknown')}")
        vecs = atk.get("vectors", [])
        if vecs:
            lines.append(f"\n### Attack Vectors ({len(vecs)})\n")
            for v in vecs[:10]:
                if isinstance(v, dict):
                    lines.append(f"- {v.get('type', '')} — {v.get('description', '')}")
                else:
                    lines.append(f"- {v}")

    # Infrastructure
    infra = s.get("infrastructure", {})
    if infra:
        lines.append("\n## Infrastructure\n")
        tls = infra.get("tls", {})
        if tls:
            lines.append(f"- **TLS:** {tls.get('version', '')} / {tls.get('cipher', '')}")
            lines.append(f"- **Issuer:** {tls.get('issuer', '')}")
        tech = infra.get("tech", [])
        if tech:
            lines.append("\n### Technologies\n")
            for t in tech[:10]:
                if isinstance(t, dict):
                    lines.append(f"- {t.get('name', '')} ({t.get('confidence', '')})")
                else:
                    lines.append(f"- {t}")

    # WAF Cache
    wc = s.get("waf_cache", {})
    if wc:
        lines.append("\n## WAF Test History\n")
        lines.append(f"- **Vendor:** {wc.get('vendor', 'N/A')}")
        lines.append(f"- **Total Tested:** {wc.get('total_tested', 0)}")
        lines.append(f"- **Total Blocked:** {wc.get('total_blocked', 0)}")
        tested = wc.get("total_tested", 0)
        if tested:
            rate = wc.get("total_blocked", 0) / tested * 100
            lines.append(f"- **Block Rate:** {rate:.1f}%")

    # OSINT
    oi = s.get("osint", {})
    if oi:
        lines.append("\n## OSINT Summary\n")
        lines.append(f"- **Emails found:** {oi.get('emails', 0)}")
        lines.append(f"- **Employees:** {oi.get('employees', 0)}")
        lines.append(f"- **GitHub repos:** {oi.get('github_repos', 0)}")
        lines.append(f"- **Typosquatting domains:** {oi.get('typosquatting', 0)}")

    # Scans
    sr = s.get("scan_results", [])
    if sr:
        lines.append("\n## Scan Results\n")
        lines.append("| Target | Tested | Blocked | Bypassed |")
        lines.append("|--------|--------|---------|----------|")
        for r in sr[:10]:
            lines.append(f"| {r.get('target', '')[:40]} | {r.get('total', 0)} | "
                         f"{r.get('blocked', 0)} | {r.get('bypassed', 0)} |")

    lines.append(f"\n---\n*Report generated by Fray v{report.get('fray_version', '')} — https://github.com/dalisecurity/fray*")
    return "\n".join(lines)
