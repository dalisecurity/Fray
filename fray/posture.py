#!/usr/bin/env python3
"""
Fray — Industry-Level Security Posture Comparison (#72)

Aggregates batch recon JSONL results to produce a comparative security
posture report across multiple companies/domains, showing:
  - Per-domain risk score, WAF vendor, header grade, findings count
  - Industry averages and rankings
  - Best/worst performers

CLI:
    fray posture results.jsonl
    fray posture results.jsonl --json
    fray posture results.jsonl -o posture.md
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def _load_jsonl(path: str) -> List[Dict]:
    """Load JSONL file, return list of dicts."""
    results = []
    p = Path(path)
    if not p.exists():
        return results
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def _extract_posture(entry: Dict) -> Dict:
    """Extract security posture metrics from a single recon result."""
    domain = entry.get("domain", entry.get("target", entry.get("host", "unknown")))
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    # WAF
    waf = entry.get("waf_detected", entry.get("waf", {}))
    waf_vendor = ""
    if isinstance(waf, dict):
        waf_vendor = waf.get("vendor", waf.get("waf_vendor", ""))

    # Security headers
    headers = entry.get("security_headers", {})
    header_score = headers.get("score", 0) if isinstance(headers, dict) else 0
    header_grade = headers.get("grade", "?") if isinstance(headers, dict) else "?"

    # TLS
    tls = entry.get("tls", {})
    tls_version = tls.get("version", "") if isinstance(tls, dict) else ""

    # Attack surface
    surface = entry.get("attack_surface", {})
    risk_score = 0
    risk_level = ""
    n_findings = 0
    n_critical = 0
    n_high = 0
    if isinstance(surface, dict):
        risk_score = surface.get("risk_score", 0)
        risk_level = surface.get("risk_level", "")
        findings = surface.get("findings", surface.get("attack_vectors", []))
        if isinstance(findings, list):
            n_findings = len(findings)
            for f in findings:
                sev = f.get("severity", "").lower() if isinstance(f, dict) else ""
                if sev == "critical":
                    n_critical += 1
                elif sev == "high":
                    n_high += 1

    # Subdomains
    subs = entry.get("subdomains", entry.get("subdomain_count", 0))
    n_subdomains = len(subs) if isinstance(subs, list) else (subs if isinstance(subs, int) else 0)

    return {
        "domain": domain,
        "waf_vendor": waf_vendor,
        "has_waf": bool(waf_vendor),
        "header_score": header_score,
        "header_grade": header_grade,
        "tls_version": tls_version,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": n_findings,
        "critical": n_critical,
        "high": n_high,
        "subdomains": n_subdomains,
    }


def generate_posture_report(
    source: str,
    output: str = "",
) -> Dict:
    """Generate an industry-level security posture comparison.

    Args:
        source: Path to JSONL file with recon results.
        output: Optional output file (.md or .json).

    Returns:
        Report dict with rankings, averages, and per-domain metrics.
    """
    entries = _load_jsonl(source)
    if not entries:
        return {"error": f"No data found in {source}", "domains": []}

    postures = [_extract_posture(e) for e in entries]
    postures = [p for p in postures if p["domain"] != "unknown"]

    # Sort by risk (highest first)
    postures.sort(key=lambda x: x["risk_score"], reverse=True)

    total = len(postures)
    waf_count = sum(1 for p in postures if p["has_waf"])
    avg_risk = round(sum(p["risk_score"] for p in postures) / total, 1) if total else 0
    avg_header = round(sum(p["header_score"] for p in postures) / total, 1) if total else 0
    total_critical = sum(p["critical"] for p in postures)
    total_high = sum(p["high"] for p in postures)

    vendor_dist = Counter(p["waf_vendor"] for p in postures if p["waf_vendor"])

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "total_domains": total,
        "waf_coverage": round(waf_count / total * 100, 1) if total else 0,
        "avg_risk_score": avg_risk,
        "avg_header_score": avg_header,
        "total_critical": total_critical,
        "total_high": total_high,
        "vendor_distribution": dict(vendor_dist.most_common()),
        "highest_risk": postures[:5] if postures else [],
        "lowest_risk": list(reversed(postures[-5:])) if postures else [],
        "no_waf": [p["domain"] for p in postures if not p["has_waf"]],
        "domains": postures,
    }

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        if output.endswith(".json"):
            with open(output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        else:
            with open(output, "w", encoding="utf-8") as f:
                f.write(posture_to_markdown(report))

    return report


def posture_to_markdown(report: Dict) -> str:
    lines = [
        "# Industry Security Posture Comparison",
        "",
        f"**Generated:** {report['generated_at']}  ",
        f"**Source:** {report['source']}  ",
        f"**Domains:** {report['total_domains']}  ",
        "",
        "## Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| WAF Coverage | {report['waf_coverage']}% |",
        f"| Avg Risk Score | {report['avg_risk_score']}/100 |",
        f"| Avg Header Score | {report['avg_header_score']}/100 |",
        f"| Total Critical Findings | {report['total_critical']} |",
        f"| Total High Findings | {report['total_high']} |",
        "",
    ]

    if report.get("highest_risk"):
        lines.append("## Highest Risk Domains\n")
        lines.append("| Domain | Risk | WAF | Header Grade | Critical | High |")
        lines.append("|--------|------|-----|-------------|----------|------|")
        for p in report["highest_risk"]:
            lines.append(f"| {p['domain']} | {p['risk_score']} | {p['waf_vendor'] or '—'} | {p['header_grade']} | {p['critical']} | {p['high']} |")
        lines.append("")

    if report.get("no_waf"):
        lines.append("## Domains Without WAF\n")
        for d in report["no_waf"][:20]:
            lines.append(f"- `{d}`")
        lines.append("")

    domains = report.get("domains", [])
    if domains:
        lines.append("## All Domains\n")
        lines.append("| Domain | Risk | WAF | Headers | Findings |")
        lines.append("|--------|------|-----|---------|----------|")
        for p in domains[:100]:
            lines.append(f"| {p['domain']} | {p['risk_score']} | {p['waf_vendor'] or '—'} | {p['header_grade']} | {p['findings']} |")

    return "\n".join(lines)


def print_posture_report(report: Dict) -> None:
    """Pretty-print posture report to terminal."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    GRN = "\033[92m"
    RED = "\033[91m"
    YEL = "\033[93m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 64}{R}")
    print(f"  {B}Industry Security Posture Comparison{R}")
    print(f"  {D}{report['total_domains']} domains | WAF coverage: {report['waf_coverage']}%{R}")
    print(f"{D}{'━' * 64}{R}\n")

    avg_risk = report["avg_risk_score"]
    rc = RED if avg_risk >= 60 else YEL if avg_risk >= 30 else GRN
    print(f"  {B}Avg Risk:{R} {rc}{avg_risk}/100{R}  "
          f"{B}Avg Headers:{R} {report['avg_header_score']}/100  "
          f"{RED}Critical:{R} {report['total_critical']}  "
          f"{YEL}High:{R} {report['total_high']}\n")

    highest = report.get("highest_risk", [])
    if highest:
        print(f"  {RED}{B}Highest Risk:{R}")
        for p in highest:
            rc = RED if p["risk_score"] >= 60 else YEL
            print(f"    {rc}{p['risk_score']:3d}{R}  {p['domain']:30s}  "
                  f"WAF: {p['waf_vendor'] or '—':15s}  "
                  f"Findings: {p['findings']}")
        print()

    no_waf = report.get("no_waf", [])
    if no_waf:
        print(f"  {RED}No WAF ({len(no_waf)}):{R} {', '.join(no_waf[:10])}"
              f"{'...' if len(no_waf) > 10 else ''}\n")

    print(f"{D}{'━' * 64}{R}\n")
