#!/usr/bin/env python3
"""
Fray — Corporate WAF Coverage Report (#71)

Aggregates WAF detection data across all scanned domains to produce
a corporate-level coverage report showing:
  - Which domains have WAF protection (and which don't)
  - WAF vendor distribution
  - Block rate per domain
  - Unprotected domains (critical gaps)
  - Overall security posture score

CLI:
    fray waf-report
    fray waf-report --company example.com
    fray waf-report --json
    fray waf-report -o report.md
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_FRAY_DIR = Path.home() / ".fray"
_CACHE_PATH = _FRAY_DIR / "domain_cache.json"


def _load_cache() -> Dict:
    if not _CACHE_PATH.exists():
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _load_recon_waf() -> Dict[str, Dict]:
    """Load WAF data from recon results in ~/.fray/recon/."""
    recon_dir = _FRAY_DIR / "recon"
    waf_data = {}
    if not recon_dir.is_dir():
        return waf_data
    for f in recon_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            domain = data.get("target", data.get("domain", f.stem))
            domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
            waf = data.get("waf_detected", data.get("waf", {}))
            if isinstance(waf, dict) and waf:
                waf_data[domain] = {
                    "vendor": waf.get("vendor", waf.get("waf_vendor", "")),
                    "confidence": waf.get("confidence", 0),
                    "methods": waf.get("detection_methods", []),
                }
        except Exception:
            continue
    return waf_data


def generate_waf_report(
    company_filter: str = "",
    output: str = "",
) -> Dict:
    """Generate a corporate WAF coverage report.

    Args:
        company_filter: Optional domain suffix filter (e.g. 'example.com').
        output: Output file path (.md or .json).

    Returns:
        Report dict with domains, vendor distribution, gaps, and score.
    """
    cache = _load_cache()
    recon_waf = _load_recon_waf()

    # Merge data sources
    all_domains: Dict[str, Dict] = {}

    for domain, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        if company_filter and company_filter not in domain:
            continue
        vendor = entry.get("waf_vendor", "")
        blocked = entry.get("blocked", {})
        passed = entry.get("passed", {})
        n_blocked = len(blocked) if isinstance(blocked, dict) else 0
        n_passed = len(passed) if isinstance(passed, dict) else 0
        total = n_blocked + n_passed
        block_rate = round(n_blocked / total * 100, 1) if total > 0 else 0

        all_domains[domain] = {
            "vendor": vendor,
            "blocked": n_blocked,
            "passed": n_passed,
            "total_tested": total,
            "block_rate": block_rate,
            "scans": entry.get("total_scans", 0),
            "last_scan": entry.get("updated_at", ""),
            "source": "cache",
        }

    for domain, waf in recon_waf.items():
        if company_filter and company_filter not in domain:
            continue
        if domain not in all_domains:
            all_domains[domain] = {
                "vendor": waf.get("vendor", ""),
                "blocked": 0,
                "passed": 0,
                "total_tested": 0,
                "block_rate": 0,
                "scans": 0,
                "last_scan": "",
                "source": "recon",
            }
        elif not all_domains[domain]["vendor"] and waf.get("vendor"):
            all_domains[domain]["vendor"] = waf["vendor"]

    # Classify
    protected = {d: v for d, v in all_domains.items() if v["vendor"]}
    unprotected = {d: v for d, v in all_domains.items() if not v["vendor"]}

    # Vendor distribution
    vendor_counts = Counter(v["vendor"] for v in protected.values() if v["vendor"])

    # Coverage score (0-100)
    total_domains = len(all_domains)
    if total_domains == 0:
        coverage_score = 0
    else:
        pct_protected = len(protected) / total_domains
        avg_block_rate = 0
        rates = [v["block_rate"] for v in protected.values() if v["total_tested"] > 0]
        if rates:
            avg_block_rate = sum(rates) / len(rates)
        coverage_score = int(pct_protected * 60 + (avg_block_rate / 100) * 40)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "company_filter": company_filter or "(all)",
        "total_domains": total_domains,
        "protected_domains": len(protected),
        "unprotected_domains": len(unprotected),
        "coverage_pct": round(len(protected) / total_domains * 100, 1) if total_domains else 0,
        "coverage_score": coverage_score,
        "vendor_distribution": dict(vendor_counts.most_common()),
        "top_vendors": [{"vendor": v, "count": c} for v, c in vendor_counts.most_common(5)],
        "domains": sorted(all_domains.items(), key=lambda x: x[1]["block_rate"], reverse=True),
        "gaps": sorted(unprotected.keys()),
    }

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        if output.endswith(".json"):
            serializable = dict(report)
            serializable["domains"] = [{"domain": d, **v} for d, v in report["domains"]]
            with open(output, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2, ensure_ascii=False)
        else:
            md = waf_report_to_markdown(report)
            with open(output, "w", encoding="utf-8") as f:
                f.write(md)

    return report


def waf_report_to_markdown(report: Dict) -> str:
    """Convert WAF report dict to Markdown."""
    lines = [
        f"# Corporate WAF Coverage Report",
        f"",
        f"**Generated:** {report['generated_at']}  ",
        f"**Scope:** {report['company_filter']}  ",
        f"**Coverage Score:** {report['coverage_score']}/100  ",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total domains | {report['total_domains']} |",
        f"| Protected (WAF detected) | {report['protected_domains']} |",
        f"| Unprotected (no WAF) | {report['unprotected_domains']} |",
        f"| Coverage | {report['coverage_pct']}% |",
        f"",
    ]

    if report["top_vendors"]:
        lines.append("## WAF Vendor Distribution\n")
        lines.append("| Vendor | Domains |")
        lines.append("|--------|---------|")
        for v in report["top_vendors"]:
            lines.append(f"| {v['vendor']} | {v['count']} |")
        lines.append("")

    if report["gaps"]:
        lines.append("## Unprotected Domains (Gaps)\n")
        lines.append("These domains have no detected WAF — consider adding protection:\n")
        for d in report["gaps"]:
            lines.append(f"- `{d}`")
        lines.append("")

    domains = report.get("domains", [])
    if domains:
        lines.append("## Domain Details\n")
        lines.append("| Domain | WAF Vendor | Block Rate | Tested | Scans |")
        lines.append("|--------|-----------|------------|--------|-------|")
        for domain, info in domains[:50]:
            vendor = info.get("vendor", "—") or "—"
            br = f"{info['block_rate']}%" if info["total_tested"] > 0 else "—"
            lines.append(f"| {domain} | {vendor} | {br} | {info['total_tested']} | {info['scans']} |")
        if len(domains) > 50:
            lines.append(f"\n*...and {len(domains) - 50} more domains*\n")

    return "\n".join(lines)


def print_waf_report(report: Dict) -> None:
    """Pretty-print WAF coverage report to terminal."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    GRN = "\033[92m"
    RED = "\033[91m"
    YEL = "\033[93m"
    CYN = "\033[96m"

    score = report["coverage_score"]
    score_color = GRN if score >= 70 else YEL if score >= 40 else RED

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Corporate WAF Coverage Report{R}")
    print(f"  {D}Scope: {report['company_filter']}{R}")
    print(f"  {D}Score: {score_color}{score}/100{R}")
    print(f"{D}{'━' * 60}{R}\n")

    print(f"  {B}Domains:{R} {report['total_domains']} total")
    print(f"  {GRN}Protected:{R} {report['protected_domains']}  "
          f"{RED}Unprotected:{R} {report['unprotected_domains']}  "
          f"{D}Coverage: {report['coverage_pct']}%{R}\n")

    if report["top_vendors"]:
        print(f"  {B}WAF Distribution:{R}")
        for v in report["top_vendors"]:
            bar = "█" * min(v["count"], 30)
            print(f"    {CYN}{v['vendor']:20s}{R} {bar} {v['count']}")
        print()

    gaps = report.get("gaps", [])
    if gaps:
        print(f"  {RED}{B}Unprotected Domains:{R}")
        for d in gaps[:20]:
            print(f"    {RED}✗{R} {d}")
        if len(gaps) > 20:
            print(f"    {D}...and {len(gaps) - 20} more{R}")
        print()

    print(f"{D}{'━' * 60}{R}\n")
