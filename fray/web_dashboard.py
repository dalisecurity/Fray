#!/usr/bin/env python3
"""
Fray Web Dashboard — Local web UI for browsing recon, scan, and intel data.

Zero external dependencies — uses stdlib http.server + embedded SPA.
Reads data from ~/.fray/ directory.

Usage:
    fray dashboard                  # Start on port 8337
    fray dashboard --port 9000      # Custom port
    fray dashboard --json           # Print API endpoints and exit
"""

import http.server
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

FRAY_DIR = Path.home() / ".fray"
RECON_DIR = FRAY_DIR / "recon"
_DASHBOARD_PORT = 8337  # updated by start_dashboard()


# ══════════════════════════════════════════════════════════════════════════════
#  DATA LAYER — read ~/.fray/ files
# ══════════════════════════════════════════════════════════════════════════════

def _safe_json(path: Path) -> Any:
    """Read a JSON file safely, return None on error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_domains() -> List[Dict]:
    """List all scanned domains with latest scan info."""
    if not RECON_DIR.exists():
        return []

    domains = {}
    for f in RECON_DIR.glob("*_latest.json"):
        domain = f.name.replace("_latest.json", "")
        data = _safe_json(f)
        if not data:
            continue

        # Count historical scans
        history_files = sorted(RECON_DIR.glob(f"{domain}_2*.json"))
        scan_count = len(history_files)

        # Extract key metrics
        attack = data.get("attack_surface", {})
        risk_score = attack.get("risk_score", 0) if isinstance(attack, dict) else 0
        risk_level = attack.get("risk_level", "unknown") if isinstance(attack, dict) else "unknown"

        subs = data.get("subdomains", {})
        sub_count = len(subs.get("subdomains", [])) if isinstance(subs, dict) else 0

        subs_active = data.get("subdomains_active", {})
        sub_active_count = len(subs_active.get("subdomains", [])) if isinstance(subs_active, dict) else 0

        tls = data.get("tls", {})
        tls_version = tls.get("tls_version", "") if isinstance(tls, dict) else ""

        headers = data.get("headers", {})
        header_score = headers.get("score", 0) if isinstance(headers, dict) else 0

        fp = data.get("fingerprint", {})
        techs = list((fp.get("technologies", {}) if isinstance(fp, dict) else {}).keys())

        _as = data.get("attack_surface", {}) if isinstance(data.get("attack_surface"), dict) else {}
        vectors = _as.get("attack_vectors", _as.get("vectors", []))
        findings = _as.get("findings", [])

        grade = risk_grade(risk_score)
        domains[domain] = {
            "domain": domain,
            "target": data.get("target", ""),
            "timestamp": data.get("timestamp", ""),
            "scan_count": scan_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "grade": grade,
            "subdomains": sub_count + sub_active_count,
            "tls_version": tls_version,
            "header_score": header_score,
            "technologies": techs[:8],
            "vectors": len(vectors),
            "findings": len(findings),
            "waf": (data.get("attack_surface", {}) or {}).get("waf_vendor", "") or "",
        }

    # Sort by risk score desc
    return sorted(domains.values(), key=lambda d: d.get("risk_score", 0), reverse=True)


def get_domain_detail(domain: str) -> Optional[Dict]:
    """Get full latest recon data for a domain."""
    latest = RECON_DIR / f"{domain}_latest.json"
    if latest.exists():
        return _safe_json(latest)
    return None


def risk_grade(score: int) -> str:
    """Convert risk score 0-100 to letter grade A-F (lower risk = better grade)."""
    if score <= 10: return "A"
    if score <= 25: return "B"
    if score <= 45: return "C"
    if score <= 65: return "D"
    return "F"


def _extract_scan_summary(data: Dict) -> Dict:
    """Extract a comparable summary from a recon scan result."""
    attack = data.get("attack_surface", {}) or {}
    findings = attack.get("findings", [])
    vectors = attack.get("attack_vectors", attack.get("vectors", []))
    waf = attack.get("waf_vendor", "") or ""
    subs = data.get("subdomains", {}) or {}
    sub_count = len(subs.get("subdomains", [])) if isinstance(subs, dict) else 0
    subs_active = data.get("subdomains_active", {}) or {}
    sub_active = len(subs_active.get("subdomains", [])) if isinstance(subs_active, dict) else 0
    fp = data.get("fingerprint", {}) or {}
    techs = list((fp.get("technologies", {}) if isinstance(fp, dict) else {}).keys())
    risk = attack.get("risk_score", 0) if isinstance(attack, dict) else 0
    return {
        "risk_score": risk,
        "risk_level": attack.get("risk_level", "unknown"),
        "grade": risk_grade(risk),
        "findings": [{"finding": f.get("finding", f.get("title", "")), "severity": f.get("severity", "info"), "category": f.get("category", ""), "risk_score": f.get("risk_score", 0)} for f in findings],
        "finding_count": len(findings),
        "vector_count": len(vectors),
        "waf": waf,
        "subdomains": sub_count + sub_active,
        "technologies": techs,
        "tech_count": len(techs),
    }


def get_domain_history(domain: str) -> List[Dict]:
    """Get scan history for a domain with rich summary per scan."""
    history = []
    for f in sorted(RECON_DIR.glob(f"{domain}_2*.json")):
        data = _safe_json(f)
        if not data:
            continue
        summary = _extract_scan_summary(data)
        summary["file"] = f.name
        summary["timestamp"] = data.get("timestamp", "")
        history.append(summary)
    return history


def get_scan_delta(domain: str) -> Dict:
    """Compare latest scan vs previous scan for a domain. Returns delta object."""
    history_files = sorted(RECON_DIR.glob(f"{domain}_2*.json"))
    latest_file = RECON_DIR / f"{domain}_latest.json"
    if not latest_file.exists():
        return {"error": "No scans found"}

    latest_data = _safe_json(latest_file)
    if not latest_data:
        return {"error": "Cannot read latest scan"}

    current = _extract_scan_summary(latest_data)
    current["timestamp"] = latest_data.get("timestamp", "")

    # Find previous scan (last history file before latest)
    if not history_files:
        return {"current": current, "previous": None, "deltas": []}

    prev_data = _safe_json(history_files[-1])
    if not prev_data:
        return {"current": current, "previous": None, "deltas": []}

    previous = _extract_scan_summary(prev_data)
    previous["timestamp"] = prev_data.get("timestamp", "")

    # Compute deltas
    deltas = []
    # New findings
    prev_findings = {f["finding"] for f in previous["findings"]}
    curr_findings = {f["finding"] for f in current["findings"]}
    for f in current["findings"]:
        if f["finding"] not in prev_findings:
            deltas.append({"type": "new", "category": "finding", "detail": f["finding"], "severity": f["severity"]})
    # Resolved findings
    for f in previous["findings"]:
        if f["finding"] not in curr_findings:
            deltas.append({"type": "fixed", "category": "finding", "detail": f["finding"], "severity": f["severity"]})
    # WAF change
    if current["waf"] != previous["waf"]:
        deltas.append({"type": "changed", "category": "waf", "detail": f"WAF changed: {previous['waf'] or 'None'} → {current['waf'] or 'None'}"})
    else:
        deltas.append({"type": "same", "category": "waf", "detail": f"WAF still {current['waf'] or 'None'}"})
    # Subdomain delta
    sub_diff = current["subdomains"] - previous["subdomains"]
    if sub_diff > 0:
        deltas.append({"type": "new", "category": "subdomains", "detail": f"{sub_diff} new subdomain(s) discovered"})
    elif sub_diff < 0:
        deltas.append({"type": "changed", "category": "subdomains", "detail": f"{abs(sub_diff)} subdomain(s) no longer resolving"})
    # Risk change
    risk_diff = current["risk_score"] - previous["risk_score"]
    if risk_diff > 0:
        deltas.append({"type": "new", "category": "risk", "detail": f"Risk score increased {previous['risk_score']} → {current['risk_score']}"})
    elif risk_diff < 0:
        deltas.append({"type": "fixed", "category": "risk", "detail": f"Risk score decreased {previous['risk_score']} → {current['risk_score']}"})
    # Tech changes
    new_techs = set(current["technologies"]) - set(previous["technologies"])
    if new_techs:
        deltas.append({"type": "new", "category": "tech", "detail": f"New tech: {', '.join(list(new_techs)[:5])}"})

    return {
        "domain": domain,
        "current": current,
        "previous": previous,
        "deltas": deltas,
        "risk_delta": risk_diff,
        "finding_delta": current["finding_count"] - previous["finding_count"],
    }


def get_global_delta() -> Dict:
    """Compute overview-level deltas across all domains."""
    domains = list_domains()
    total_findings = sum(d.get("findings", 0) for d in domains)
    total_vectors = sum(d.get("vectors", 0) for d in domains)

    # Compare with previous scans to get deltas
    new_findings = 0
    resolved_findings = 0
    domains_with_delta = []
    for d in domains:
        delta = get_scan_delta(d["domain"])
        if delta.get("previous"):
            fd = delta.get("finding_delta", 0)
            if fd > 0: new_findings += fd
            if fd < 0: resolved_findings += abs(fd)
            if delta.get("deltas"):
                domains_with_delta.append({
                    "domain": d["domain"],
                    "risk_delta": delta.get("risk_delta", 0),
                    "finding_delta": fd,
                    "deltas": delta["deltas"][:5],
                })

    return {
        "total_findings": total_findings,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "domains_with_changes": sorted(domains_with_delta, key=lambda x: -abs(x.get("risk_delta", 0)))[:10],
    }


def get_all_findings_triage() -> List[Dict]:
    """Get all findings across domains, sorted by severity for triage queue."""
    if not RECON_DIR.exists():
        return []
    findings = []
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in RECON_DIR.glob("*_latest.json"):
        data = _safe_json(f)
        if not data:
            continue
        domain = f.name.replace("_latest.json", "")
        attack = data.get("attack_surface", {}) or {}
        waf = attack.get("waf_vendor", "") or ""
        for fn in attack.get("findings", []):
            findings.append({
                "domain": domain,
                "finding": fn.get("finding", fn.get("title", "")),
                "severity": fn.get("severity", "info"),
                "category": fn.get("category", "other"),
                "risk_score": fn.get("risk_score", 0),
                "waf": waf,
            })
    return sorted(findings, key=lambda f: (_sev_rank.get(f["severity"].lower(), 9), -f["risk_score"]))[:500]


def get_payload_analytics() -> Dict:
    """Get payload hit/miss analytics from learned patterns."""
    learned = _safe_json(FRAY_DIR / "learned_patterns.json") or {}
    vendors = {}
    for vendor, data in learned.items():
        if not isinstance(data, dict):
            continue
        total_runs = data.get("total_runs", 0)
        total_blocked = data.get("total_blocked", 0)
        successes = data.get("successful_payloads", [])
        blocked_hashes = data.get("blocked_hashes", [])
        eff_strats = data.get("effective_strategies", {})
        fail_strats = data.get("failed_strategies", {})
        bypass_rate = round(len(successes) / max(total_blocked + len(successes), 1) * 100, 1)
        vendors[vendor] = {
            "total_runs": total_runs,
            "total_blocked": total_blocked,
            "total_bypassed": len(successes),
            "bypass_rate": bypass_rate,
            "blocked_hashes": len(blocked_hashes),
            "top_effective": sorted(eff_strats.items(), key=lambda x: -x[1])[:5],
            "top_failed": sorted(((k, v) for k, v in fail_strats.items() if isinstance(v, (int, float))), key=lambda x: -x[1])[:5],
        }
    return vendors


def list_command_results(subdir: str) -> List[Dict]:
    """List latest results from ~/.fray/<subdir>/ (tests, scans, agents)."""
    results_dir = FRAY_DIR / subdir
    if not results_dir.exists():
        return []
    results = []
    for f in results_dir.glob("*_latest.json"):
        data = _safe_json(f)
        if not data:
            continue
        domain = f.name.replace("_latest.json", "")
        summary = data.get("summary", {})
        results.append({
            "domain": domain,
            "target": data.get("target", domain),
            "timestamp": data.get("timestamp", ""),
            "command": data.get("command", subdir.rstrip("s")),
            "duration": data.get("duration", ""),
            "total": summary.get("total", summary.get("total_tested", data.get("total_requests", 0))),
            "blocked": summary.get("blocked", 0),
            "passed": summary.get("passed", data.get("bypasses", 0)),
            "block_rate": summary.get("block_rate", ""),
            "bypass_rate": data.get("bypass_rate", ""),
            "rounds": data.get("rounds", 0),
            "techniques": data.get("techniques", []),
        })
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return results


def get_global_stats() -> Dict:
    """Aggregate stats across all domains."""
    domains = list_domains()
    total = len(domains)
    if not total:
        return {"total_domains": 0}

    risk_scores = [d["risk_score"] for d in domains if d["risk_score"] > 0]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
    critical = sum(1 for d in domains if d["risk_score"] >= 70)
    high = sum(1 for d in domains if 50 <= d["risk_score"] < 70)
    medium = sum(1 for d in domains if 30 <= d["risk_score"] < 50)
    low = sum(1 for d in domains if 0 < d["risk_score"] < 30)
    total_subs = sum(d["subdomains"] for d in domains)
    total_vectors = sum(d["vectors"] for d in domains)

    # Tech frequency
    tech_freq = {}
    for d in domains:
        for t in d.get("technologies", []):
            tech_freq[t] = tech_freq.get(t, 0) + 1
    top_techs = sorted(tech_freq.items(), key=lambda x: -x[1])[:10]

    # Learned patterns
    learned = _safe_json(FRAY_DIR / "learned_patterns.json") or {}
    total_blocked = sum(v.get("total_blocked", 0) for v in learned.values() if isinstance(v, dict))
    total_runs = sum(v.get("total_runs", 0) for v in learned.values() if isinstance(v, dict))

    return {
        "total_domains": total,
        "avg_risk": avg_risk,
        "severity": {"critical": critical, "high": high, "medium": medium, "low": low},
        "total_subdomains": total_subs,
        "total_vectors": total_vectors,
        "top_technologies": top_techs,
        "agent_stats": {"total_runs": total_runs, "total_blocked": total_blocked},
    }


def get_executive_summary() -> Dict:
    """Build executive summary across all scanned domains.

    Aggregates findings by severity/category, top remediation actions,
    attack vector trends, WAF gap analysis, and risk posture.
    """
    if not RECON_DIR.exists():
        return {"error": "No recon data"}

    # Collect per-domain data
    all_findings = []
    all_remediation = []
    all_vectors = []
    all_bypass = []
    domain_risks = []
    waf_vendors = {}
    finding_categories = {}
    finding_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vector_types = {}
    remediation_actions = {}  # action -> {severity, count, domains}
    critical_domains = []
    csp_missing = 0
    clickjack_vuln = 0
    cors_vuln = 0
    origin_exposed = 0
    total_cves = 0
    total_critical_cves = 0
    total_vuln_libs = 0
    waf_bypass_count = 0
    takeover_count = 0
    total_domains = 0

    for f in RECON_DIR.glob("*_latest.json"):
        data = _safe_json(f)
        if not data:
            continue
        total_domains += 1
        domain = f.name.replace("_latest.json", "")

        attack = data.get("attack_surface", {}) or {}
        gap = data.get("gap_analysis", {}) or {}
        risk = attack.get("risk_score", 0)
        risk_level = attack.get("risk_level", "unknown")

        domain_risks.append({"domain": domain, "risk_score": risk, "risk_level": risk_level})

        if risk >= 70:
            critical_domains.append({"domain": domain, "risk_score": risk,
                                     "risk_level": risk_level,
                                     "waf": attack.get("waf_vendor", ""),
                                     "cdn": attack.get("cdn", "")})

        # WAF vendors
        waf = attack.get("waf_vendor", "")
        if waf:
            waf_vendors[waf] = waf_vendors.get(waf, 0) + 1

        # Findings
        for fn in attack.get("findings", []):
            sev = (fn.get("severity") or "info").lower()
            finding_severity[sev] = finding_severity.get(sev, 0) + 1
            cat = fn.get("category", "other")
            finding_categories[cat] = finding_categories.get(cat, 0) + 1
            all_findings.append({**fn, "domain": domain})

        # Attack vectors
        for vec in attack.get("attack_vectors", []):
            vtype = vec.get("type", "unknown")
            vector_types[vtype] = vector_types.get(vtype, 0) + 1
            all_vectors.append({**vec, "domain": domain})

        # Remediation
        for rem in attack.get("remediation", []):
            action = rem.get("action", "")
            if action:
                key = action[:80]
                if key not in remediation_actions:
                    remediation_actions[key] = {
                        "action": action,
                        "severity": rem.get("severity", "medium"),
                        "why": rem.get("why", ""),
                        "how": rem.get("how", ""),
                        "timeline": rem.get("timeline", ""),
                        "count": 0,
                        "domains": [],
                    }
                remediation_actions[key]["count"] += 1
                if len(remediation_actions[key]["domains"]) < 5:
                    remediation_actions[key]["domains"].append(domain)

        # Bypass strategies
        for bs in gap.get("bypass_strategies", []):
            all_bypass.append({**bs, "domain": domain, "waf": gap.get("waf_vendor", "")})

        # Quick flags
        if not attack.get("csp_present", True):
            csp_missing += 1
        if attack.get("clickjacking_vulnerable"):
            clickjack_vuln += 1
        if attack.get("cors_vulnerable"):
            cors_vuln += 1
        if attack.get("origin_ip_exposed"):
            origin_exposed += 1
        total_cves += attack.get("frontend_cves", 0)
        total_critical_cves += attack.get("frontend_critical_cves", 0)
        total_vuln_libs += attack.get("vulnerable_frontend_libs", 0)
        if attack.get("waf_bypass_subdomains", 0) > 0:
            waf_bypass_count += 1
        if attack.get("subdomain_takeover", 0) > 0:
            takeover_count += 1

    # Sort & rank
    risk_scores = [d["risk_score"] for d in domain_risks if d["risk_score"] > 0]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    # Top remediation actions sorted by severity then count
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top_remediation = sorted(
        remediation_actions.values(),
        key=lambda r: (_sev_rank.get(r["severity"], 9), -r["count"])
    )

    # Top vectors by frequency
    top_vectors = sorted(vector_types.items(), key=lambda x: -x[1])

    # Top findings by severity
    critical_findings = sorted(
        [f for f in all_findings if f.get("severity") in ("critical", "high")],
        key=lambda f: (-f.get("risk_score", 0))
    )

    # WAF bypass techniques aggregated
    bypass_by_technique = {}
    for b in all_bypass:
        tech = b.get("technique", "unknown")
        if tech not in bypass_by_technique:
            bypass_by_technique[tech] = {
                "technique": tech,
                "confidence": b.get("confidence", ""),
                "description": b.get("description", ""),
                "payload_example": b.get("payload_example", ""),
                "count": 0,
                "wafs": set(),
            }
        bypass_by_technique[tech]["count"] += 1
        bypass_by_technique[tech]["wafs"].add(b.get("waf", ""))
    # Convert sets to lists for JSON
    for v in bypass_by_technique.values():
        v["wafs"] = sorted(v["wafs"] - {""})
    top_bypass = sorted(bypass_by_technique.values(), key=lambda x: -x["count"])

    # Finding categories sorted
    top_categories = sorted(finding_categories.items(), key=lambda x: -x[1])

    return {
        "total_domains": total_domains,
        "avg_risk": avg_risk,
        "finding_severity": finding_severity,
        "total_findings": sum(finding_severity.values()),
        "total_vectors": sum(vector_types.values()),
        "total_remediation": len(top_remediation),
        "critical_domains": sorted(critical_domains, key=lambda d: -d["risk_score"])[:20],
        "critical_findings": critical_findings[:30],
        "top_remediation": top_remediation[:20],
        "top_vectors": top_vectors[:15],
        "top_categories": top_categories[:10],
        "top_bypass_techniques": top_bypass[:15],
        "waf_vendors": sorted(waf_vendors.items(), key=lambda x: -x[1]),
        "posture": {
            "csp_missing": csp_missing,
            "clickjacking_vulnerable": clickjack_vuln,
            "cors_vulnerable": cors_vuln,
            "origin_ip_exposed": origin_exposed,
        },
        "cve_stats": {
            "total_cves": total_cves,
            "critical_cves": total_critical_cves,
            "vulnerable_libs": total_vuln_libs,
            "waf_bypass_domains": waf_bypass_count,
            "takeover_domains": takeover_count,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  TIMELINE — aggregate all command runs for a domain over time
# ══════════════════════════════════════════════════════════════════════════════

def get_domain_timeline(domain: str) -> List[Dict]:
    """Get all runs (any command) for a domain, sorted by time."""
    _SUBDIRS = ["recon", "tests", "scans", "bypasses", "smuggle", "agents", "crawls", "go", "compare"]
    timeline = []
    for subdir in _SUBDIRS:
        d = FRAY_DIR / subdir
        if not d.exists():
            continue
        for f in sorted(d.glob(f"{domain}_2*.json")):
            data = _safe_json(f)
            if not data:
                continue
            entry = {
                "file": f.name,
                "command": data.get("command", subdir.rstrip("s")),
                "timestamp": data.get("timestamp", ""),
                "subdir": subdir,
            }
            # Extract key metrics per command type
            if subdir == "recon":
                s = _extract_scan_summary(data)
                entry.update({"risk_score": s["risk_score"], "findings": s["finding_count"], "vectors": s["vector_count"], "subdomains": s["subdomains"]})
            elif subdir == "tests":
                sm = data.get("summary", {})
                entry.update({"total": sm.get("total", 0), "blocked": sm.get("blocked", 0), "passed": sm.get("passed", 0), "block_rate": sm.get("block_rate", "")})
            elif subdir == "scans":
                sm = data.get("summary", {})
                entry.update({"total": sm.get("total_tested", 0), "blocked": sm.get("blocked", 0), "passed": sm.get("passed", 0)})
            elif subdir == "bypasses":
                entry.update({"total_payloads": data.get("total_payloads", 0), "bypasses": data.get("bypasses", 0), "waf": data.get("waf", "")})
            elif subdir == "agents":
                entry.update({"rounds": data.get("rounds", 0), "total_requests": data.get("total_requests", 0), "bypasses": data.get("bypasses", 0)})
            elif subdir == "smuggle":
                entry.update({"vulnerable": data.get("vulnerable", False), "techniques_tested": data.get("techniques_tested", 0)})
            elif subdir == "crawls":
                entry.update({"pages_crawled": data.get("pages_crawled", 0), "total_endpoints": data.get("total_endpoints", 0)})
            elif subdir == "go":
                entry.update({"phases": data.get("phases", []), "duration": data.get("duration")})
            elif subdir == "compare":
                entry.update({"category": data.get("category", ""), "impersonate": data.get("impersonate", "")})
            timeline.append(entry)
    timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return timeline


# ══════════════════════════════════════════════════════════════════════════════
#  DIFF — compare two specific scan files side-by-side
# ══════════════════════════════════════════════════════════════════════════════

def diff_runs(domain: str, file_a: str, file_b: str) -> Dict:
    """Compare two scan files for the same domain and return structured diff."""
    # Find files across all subdirs
    data_a = data_b = None
    for subdir in ["recon", "tests", "scans", "bypasses", "smuggle", "agents", "crawls", "go", "compare"]:
        d = FRAY_DIR / subdir
        pa = d / file_a
        pb = d / file_b
        if pa.exists() and data_a is None:
            data_a = _safe_json(pa)
        if pb.exists() and data_b is None:
            data_b = _safe_json(pb)
    if not data_a:
        return {"error": f"File not found: {file_a}"}
    if not data_b:
        return {"error": f"File not found: {file_b}"}

    # For recon data, use the rich summary extractor
    if "attack_surface" in data_a or "attack_surface" in data_b:
        sa = _extract_scan_summary(data_a)
        sb = _extract_scan_summary(data_b)
        sa["timestamp"] = data_a.get("timestamp", "")
        sb["timestamp"] = data_b.get("timestamp", "")

        # Compute deltas
        findings_a = {f["finding"] for f in sa.get("findings", [])}
        findings_b = {f["finding"] for f in sb.get("findings", [])}
        new_findings = [f for f in sb.get("findings", []) if f["finding"] not in findings_a]
        resolved = [f for f in sa.get("findings", []) if f["finding"] not in findings_b]
        techs_a = set(sa.get("technologies", []))
        techs_b = set(sb.get("technologies", []))

        return {
            "domain": domain, "file_a": file_a, "file_b": file_b,
            "a": sa, "b": sb,
            "deltas": {
                "risk_score": sb["risk_score"] - sa["risk_score"],
                "findings": sb["finding_count"] - sa["finding_count"],
                "vectors": sb["vector_count"] - sa["vector_count"],
                "subdomains": sb["subdomains"] - sa["subdomains"],
                "new_findings": new_findings,
                "resolved_findings": resolved,
                "new_techs": sorted(techs_b - techs_a),
                "removed_techs": sorted(techs_a - techs_b),
                "waf_changed": sa["waf"] != sb["waf"],
            },
        }
    else:
        # Generic diff: show both payloads side by side
        return {
            "domain": domain, "file_a": file_a, "file_b": file_b,
            "a": {"timestamp": data_a.get("timestamp", ""), "command": data_a.get("command", ""), "data": data_a},
            "b": {"timestamp": data_b.get("timestamp", ""), "command": data_b.get("command", ""), "data": data_b},
        }


# ══════════════════════════════════════════════════════════════════════════════
#  SSE — Server-Sent Events for live reload
# ══════════════════════════════════════════════════════════════════════════════

_sse_clients: List = []  # list of wfile objects
_sse_lock = threading.Lock()


def _sse_broadcast(event: str, data: dict):
    """Send an SSE event to all connected clients."""
    msg = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
    encoded = msg.encode("utf-8")
    with _sse_lock:
        dead = []
        for wfile in _sse_clients:
            try:
                wfile.write(encoded)
                wfile.flush()
            except Exception:
                dead.append(wfile)
        for d in dead:
            _sse_clients.remove(d)


def _file_watcher():
    """Background thread that watches ~/.fray/ for new/modified JSON files."""
    _SUBDIRS = ["recon", "tests", "scans", "bypasses", "smuggle", "agents", "crawls", "go", "compare"]
    seen = {}  # path -> mtime

    # Initial snapshot
    for subdir in _SUBDIRS:
        d = FRAY_DIR / subdir
        if d.exists():
            for f in d.glob("*.json"):
                try:
                    seen[str(f)] = f.stat().st_mtime
                except OSError:
                    pass

    while True:
        time.sleep(2)  # poll every 2 seconds
        try:
            for subdir in _SUBDIRS:
                d = FRAY_DIR / subdir
                if not d.exists():
                    continue
                for f in d.glob("*.json"):
                    fp = str(f)
                    try:
                        mt = f.stat().st_mtime
                    except OSError:
                        continue
                    if fp not in seen or mt > seen[fp]:
                        is_new = fp not in seen
                        seen[fp] = mt
                        domain = f.stem.replace("_latest", "").split("_2")[0]
                        _sse_broadcast("file_change", {
                            "type": "new" if is_new else "updated",
                            "subdir": subdir,
                            "file": f.name,
                            "domain": domain,
                            "timestamp": datetime.now().isoformat(),
                        })
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER + API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the dashboard API + SPA."""

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass

    def _cors(self):
        # Lock to same-origin only — never wildcard.
        # Prevents malicious websites from reading scan data via cross-origin fetch.
        origin = self.headers.get("Origin", "")
        if origin in (f"http://127.0.0.1:{_DASHBOARD_PORT}", f"http://localhost:{_DASHBOARD_PORT}"):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{_DASHBOARD_PORT}")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, data: Any, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode("utf-8"))

    def _html_response(self, html: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._cors()
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    _rescan_tasks = {}  # task_id -> {status, domain, scope, result, ...}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/rescan":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len else {}
            domain = body.get("domain", "")
            scope = body.get("scope", "full")
            finding = body.get("finding", "")

            if not domain:
                self._json_response({"error": "domain required"}, 400)
                return

            task_id = str(uuid.uuid4())[:8]
            task = {"status": "started", "task_id": task_id, "domain": domain, "scope": scope}
            DashboardHandler._rescan_tasks[task_id] = task

            # Build fray CLI command based on scope
            fray_bin = sys.executable
            if scope == "full":
                cmd = [fray_bin, "-m", "fray", "recon", domain]
            elif scope == "waf":
                cmd = [fray_bin, "-m", "fray", "scan", domain, "--checks", "waf"]
            elif scope == "endpoint":
                cmd = [fray_bin, "-m", "fray", "scan", domain, "--checks", "headers,tls,exposed"]
            elif scope == "changed":
                cmd = [fray_bin, "-m", "fray", "recon", domain, "--diff"]
            elif scope == "finding":
                # For single finding re-scan, run targeted recon
                cmd = [fray_bin, "-m", "fray", "recon", domain]
            else:
                cmd = [fray_bin, "-m", "fray", "recon", domain]

            def run_rescan():
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=300,
                        cwd=str(Path.home())
                    )
                    task["status"] = "completed"
                    task["exit_code"] = result.returncode
                    task["stdout"] = result.stdout[-2000:] if result.stdout else ""
                    task["stderr"] = result.stderr[-1000:] if result.stderr else ""
                    # Check if the finding was resolved (for single finding re-scan)
                    if scope == "finding" and finding:
                        new_findings = get_all_findings_triage()
                        task["resolved"] = not any(
                            f["domain"] == domain and f["finding"] == finding
                            for f in new_findings
                        )
                except subprocess.TimeoutExpired:
                    task["status"] = "timeout"
                except Exception as e:
                    task["status"] = "error"
                    task["error"] = str(e)

            thread = threading.Thread(target=run_rescan, daemon=True)
            thread.start()

            self._json_response(task)
        elif path.startswith("/api/share/"):
            domain = path.replace("/api/share/", "").strip("/")
            if not domain:
                self._json_response({"error": "domain required"}, 400)
                return
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len)) if content_len else {}
            expires = body.get("expires_days", 30)
            try:
                from fray.cloud_sync import share_domain
                url = share_domain(domain, expires_days=expires, verbose=False)
                if url:
                    self._json_response({"status": "shared", "url": url, "domain": domain})
                else:
                    self._json_response({"error": "Share failed — check R2 config (fray sync --configure)"}, 500)
            except Exception as e:
                self._json_response({"error": str(e)}, 500)
        elif path.startswith("/api/unshare/"):
            share_id = path.replace("/api/unshare/", "").strip("/")
            try:
                from fray.cloud_sync import unshare_domain
                ok = unshare_domain(share_id, verbose=False)
                if ok:
                    self._json_response({"status": "unshared", "id": share_id})
                else:
                    self._json_response({"error": "Unshare failed"}, 500)
            except Exception as e:
                self._json_response({"error": str(e)}, 500)
        else:
            self._json_response({"error": "Not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # API routes
        if path == "/api/domains":
            self._json_response(list_domains())
        elif path == "/api/stats":
            self._json_response(get_global_stats())
        elif path == "/api/executive-summary":
            self._json_response(get_executive_summary())
        elif path.startswith("/api/domain/"):
            domain = path.replace("/api/domain/", "").strip("/")
            if domain.endswith("/history"):
                domain = domain.replace("/history", "")
                self._json_response(get_domain_history(domain))
            else:
                data = get_domain_detail(domain)
                if data:
                    self._json_response(data)
                else:
                    self._json_response({"error": "Domain not found"}, 404)
        elif path == "/api/learned":
            data = _safe_json(FRAY_DIR / "learned_patterns.json") or {}
            self._json_response(data)
        elif path == "/api/threat-intel":
            data = _safe_json(FRAY_DIR / "threat_intel_cache.json") or {}
            self._json_response(data)
        elif path == "/api/global-delta":
            self._json_response(get_global_delta())
        elif path == "/api/findings-triage":
            self._json_response(get_all_findings_triage())
        elif path == "/api/payload-analytics":
            self._json_response(get_payload_analytics())
        elif path == "/api/shares":
            try:
                from fray.cloud_sync import list_shares
                self._json_response(list_shares())
            except Exception:
                self._json_response({})
        elif path == "/api/tests":
            self._json_response(list_command_results("tests"))
        elif path == "/api/scans":
            self._json_response(list_command_results("scans"))
        elif path == "/api/agents":
            self._json_response(list_command_results("agents"))
        elif path.startswith("/api/export-report/"):
            domain = path.replace("/api/export-report/", "").strip("/")
            data = get_domain_detail(domain)
            if not data:
                self._json_response({"error": "Domain not found"}, 404)
                return
            try:
                from fray.reporter import SecurityReportGenerator
                gen = SecurityReportGenerator()
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
                    gen.generate_recon_html_report(data, tmp.name)
                    tmp_path = tmp.name
                with open(tmp_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                os.unlink(tmp_path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{domain}_report.html"')
                self._cors()
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))
            except Exception as e:
                self._json_response({"error": str(e)}, 500)
        elif path.startswith("/api/rescan-status/"):
            task_id = path.replace("/api/rescan-status/", "").strip("/")
            task = DashboardHandler._rescan_tasks.get(task_id)
            if task:
                self._json_response(task)
            else:
                self._json_response({"error": "Task not found", "status": "unknown"}, 404)
        elif path.startswith("/api/scan-delta/"):
            domain = path.replace("/api/scan-delta/", "").strip("/")
            self._json_response(get_scan_delta(domain))
        elif path == "/api/cve-meta":
            # Serve CVE descriptions from poc cache for tooltips
            poc_cache = _safe_json(FRAY_DIR / "cve_poc_cache.json") or {}
            meta = {}
            for cve_id, info in poc_cache.items():
                if isinstance(info, dict):
                    meta[cve_id] = {
                        "description": (info.get("description") or "")[:200],
                        "cvss": info.get("cvss_score"),
                        "types": [t.get("type", "") for t in info.get("vuln_types", []) if isinstance(t, dict)][:3],
                        "software": (info.get("affected_software") or "")[:100],
                    }
            self._json_response(meta)
        elif path.startswith("/api/timeline/"):
            domain = path.replace("/api/timeline/", "").strip("/")
            self._json_response(get_domain_timeline(domain))
        elif path.startswith("/api/diff/"):
            # /api/diff/domain?a=file_a&b=file_b
            domain = path.replace("/api/diff/", "").strip("/")
            file_a = params.get("a", [""])[0]
            file_b = params.get("b", [""])[0]
            if not file_a or not file_b:
                self._json_response({"error": "Both ?a=<file>&b=<file> params required"}, 400)
            else:
                self._json_response(diff_runs(domain, file_a, file_b))
        elif path == "/api/events":
            # SSE endpoint for live reload
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._cors()
            self.end_headers()
            # Send initial heartbeat
            self.wfile.write(b"event: connected\ndata: {}\n\n")
            self.wfile.flush()
            # Register client
            with _sse_lock:
                _sse_clients.append(self.wfile)
            # Keep connection alive
            try:
                while True:
                    time.sleep(30)
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
            except Exception:
                pass
            finally:
                with _sse_lock:
                    if self.wfile in _sse_clients:
                        _sse_clients.remove(self.wfile)
            return
        else:
            # Serve SPA for all other routes
            self._html_response(_SPA_HTML)


# ══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED SPA — Single-page app (HTML + CSS + JS)
# ══════════════════════════════════════════════════════════════════════════════

_SPA_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fray Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #09090b;
  --bg2: #111114;
  --bg3: #18181c;
  --bg-elevated: #1c1c22;
  --border: rgba(255,255,255,.08);
  --border-strong: rgba(255,255,255,.14);
  --text: #ededf0;
  --text2: #a1a1aa;
  --text3: #7e7e8c;
  --brand: #7c3aed;
  --brand2: #a78bfa;
  --brand-glow: rgba(124,58,237,.12);
  --accent: #8b5cf6;
  --target: #60a5fa;
  --critical: #f43f5e;
  --high: #f97316;
  --medium: #eab308;
  --low: #3b82f6;
  --success: #10b981;
  --font: 'DM Sans', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --mono: 'Geist Mono', 'SF Mono', 'Fira Code', monospace;
  --radius: 10px;
  --shadow-sm: 0 1px 2px rgba(0,0,0,.3), 0 0 1px rgba(0,0,0,.2);
  --shadow-md: 0 4px 12px rgba(0,0,0,.4), 0 0 1px rgba(0,0,0,.3);
  --shadow-lg: 0 8px 30px rgba(0,0,0,.5), 0 0 1px rgba(0,0,0,.3);
}
* { margin:0; padding:0; box-sizing:border-box; }
html { color-scheme:dark; }
body { background:var(--bg); color:var(--text); font-family:var(--font); font-size:13.5px; line-height:1.55; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
a { color:var(--accent); text-decoration:none; transition:color .15s; }
a:hover { color:var(--brand2); }

/* Layout */
.shell { display:flex; min-height:100vh; }
.sidebar { width:220px; background:var(--bg2); border-right:1px solid var(--border); padding:20px 0; flex-shrink:0; position:fixed; height:100vh; overflow-y:auto; display:flex; flex-direction:column; }
.main { margin-left:220px; flex:1; padding:28px 40px 40px; min-height:100vh; background:radial-gradient(ellipse 80% 50% at 50% -20%, rgba(124,58,237,.04), transparent); }

/* Sidebar */
.logo { padding:0 20px 28px; font-size:17px; font-weight:700; color:var(--brand2); display:flex; align-items:baseline; gap:8px; letter-spacing:-.02em; }
.logo span { color:var(--text); font-size:13px; font-weight:400; letter-spacing:-.01em; opacity:.6; }
.nav-desc { font-size:10px; color:var(--text2); padding:0 16px 2px; margin-top:-4px; line-height:1.35; }
.nav-section { padding:16px 20px 6px; font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--text2); font-weight:500; }
.nav-item { display:flex; align-items:center; gap:10px; padding:8px 16px; margin:1px 8px; border-radius:8px; cursor:pointer; color:var(--text); transition:all .15s ease; font-size:13px; font-weight:400; opacity:.7; }
.nav-item:hover { background:rgba(255,255,255,.06); color:var(--text); opacity:1; }
.nav-item.active { background:var(--brand-glow); color:var(--brand2); font-weight:500; box-shadow:inset 0 0 0 1px rgba(124,58,237,.15); opacity:1; }
.sidebar-footer { margin-top:auto; padding:16px 20px; border-top:1px solid var(--border); }
.sidebar-footer-text { font-size:10px; color:var(--text2); letter-spacing:.02em; }

/* Cards */
.cards { display:grid; grid-template-columns:repeat(auto-fill, minmax(200px, 1fr)); gap:14px; margin-bottom:28px; }
.card { background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%); border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px; box-shadow:var(--shadow-sm); transition:border-color .2s, box-shadow .2s; }
.card:hover { border-color:var(--border-strong); box-shadow:var(--shadow-md); }
.card-label { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--text2); margin-bottom:6px; font-weight:500; }
.card-value { font-size:28px; font-weight:700; letter-spacing:-.03em; line-height:1.2; }
.card-sub { font-size:11px; color:var(--text2); margin-top:4px; }

/* Table */
.table-wrap { background:var(--bg2); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:28px; box-shadow:var(--shadow-sm); }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:11px 16px; font-size:10.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--text2); background:var(--bg3); border-bottom:1px solid var(--border); font-weight:600; }
td { padding:10px 16px; border-bottom:1px solid var(--border); font-size:13px; color:var(--text); }
tr:last-child td { border-bottom:none; }
tr:hover td { background:rgba(255,255,255,.015); }

/* Badges */
.badge { display:inline-block; padding:2px 8px; border-radius:5px; font-size:10.5px; font-weight:600; letter-spacing:.02em; border:1px solid transparent; }
.badge-critical { background:rgba(244,63,94,.12); color:var(--critical); border-color:rgba(244,63,94,.2); }
.badge-high { background:rgba(249,115,22,.10); color:var(--high); border-color:rgba(249,115,22,.18); }
.badge-medium { background:rgba(234,179,8,.10); color:var(--medium); border-color:rgba(234,179,8,.18); }
.badge-low { background:rgba(59,130,246,.10); color:var(--low); border-color:rgba(59,130,246,.18); }
.badge-info { background:rgba(113,113,122,.08); color:var(--text2); border-color:rgba(113,113,122,.15); }

/* Risk gauge */
.risk-bar { height:5px; border-radius:3px; background:var(--bg3); overflow:hidden; width:100%; }
.risk-fill { height:100%; border-radius:3px; transition:width .5s ease; }

/* Section headers */
.section-title { font-size:18px; font-weight:700; margin-bottom:18px; display:flex; align-items:center; gap:8px; letter-spacing:-.02em; }
.section-title .count { font-size:12px; color:var(--text2); font-weight:400; }

/* Detail view */
.detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:28px; }
@media (max-width: 960px) { .detail-grid { grid-template-columns:1fr; } }
.detail-section { background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%); border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px; box-shadow:var(--shadow-sm); }
.detail-section h3 { font-size:12px; font-weight:600; margin-bottom:12px; color:var(--brand2); text-transform:uppercase; letter-spacing:.04em; }
.kv { display:flex; justify-content:space-between; align-items:center; padding:6px 0; font-size:12.5px; border-bottom:1px solid var(--border); }
.kv:last-child { border-bottom:none; }
.kv-key { color:var(--text2); }
.kv-val { color:#d4d4d8; font-family:var(--mono); font-size:11.5px; }
.tag { display:inline-block; padding:2px 8px; border-radius:5px; font-size:10px; background:rgba(255,255,255,.05); color:#a1a1aa; margin:2px 1px; border:1px solid rgba(255,255,255,.08); font-weight:500; line-height:1.6; }
.tag-infra { background:rgba(59,130,246,.08); color:#93c5fd; border-color:rgba(59,130,246,.15); }
.tag-frontend { background:rgba(234,179,8,.08); color:#fde68a; border-color:rgba(234,179,8,.15); }
.tag-cms { background:rgba(168,85,247,.08); color:#d8b4fe; border-color:rgba(168,85,247,.15); }
.tag-cdn { background:rgba(16,185,129,.08); color:#6ee7b7; border-color:rgba(16,185,129,.15); }
.tag-analytics { background:rgba(249,115,22,.08); color:#fdba74; border-color:rgba(249,115,22,.15); }
.tag-lang { background:rgba(244,63,94,.08); color:#fda4af; border-color:rgba(244,63,94,.15); }

/* Tooltip */
.tip { position:relative; cursor:help; }
.tip .tiptext { visibility:hidden; position:absolute; z-index:10; bottom:calc(100% + 8px); left:50%; transform:translateX(-50%); background:var(--bg-elevated); border:1px solid var(--border-strong); border-radius:8px; padding:10px 14px; font-size:12px; color:var(--text); width:280px; box-shadow:var(--shadow-lg); line-height:1.5; pointer-events:none; opacity:0; transition:opacity .15s; font-family:var(--font); }
.tip:hover .tiptext { visibility:visible; opacity:1; }
.tiptext strong { color:var(--brand2); }
.tiptext .tip-cvss { display:inline-block; padding:1px 6px; border-radius:4px; font-size:10px; font-weight:700; margin-left:6px; }

/* Clickable cards */
.card-link { cursor:pointer; transition:border-color .2s, box-shadow .2s, transform .15s; }
.card-link:hover { border-color:var(--accent); box-shadow:var(--shadow-md); transform:translateY(-1px); }

/* Delta pills */
.delta-pill { display:inline-block; font-size:10px; padding:1px 7px; border-radius:20px; font-weight:600; flex-shrink:0; text-transform:uppercase; letter-spacing:.02em; }
.pill-new { background:rgba(244,63,94,.12); color:var(--critical); }
.pill-fixed { background:rgba(16,185,129,.12); color:var(--success); }
.pill-changed { background:rgba(234,179,8,.12); color:var(--medium); }
.pill-same { background:rgba(255,255,255,.05); color:var(--text2); }

/* Metric delta */
.metric-delta { font-size:11px; margin-top:4px; }
.delta-up { color:var(--critical); }
.delta-down { color:var(--success); }
.delta-neutral { color:var(--text2); }

/* Grade badge */
.grade-badge { width:30px; height:30px; border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:600; flex-shrink:0; }
.grade-a { background:rgba(16,185,129,.15); color:var(--success); }
.grade-b { background:rgba(59,130,246,.15); color:var(--low); }
.grade-c { background:rgba(234,179,8,.15); color:var(--medium); }
.grade-d { background:rgba(249,115,22,.15); color:var(--high); }
.grade-f { background:rgba(244,63,94,.15); color:var(--critical); }

/* Two column layout */
.two-col { display:grid; grid-template-columns:1fr 340px; gap:16px; margin-bottom:28px; }
@media (max-width: 1100px) { .two-col { grid-template-columns:1fr; } }

/* Scan bar */
.scan-bar { display:flex; align-items:center; gap:10px; background:var(--bg2); border:1px solid var(--border); border-radius:var(--radius); padding:10px 14px; margin-bottom:16px; }
.scan-dot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
.scan-dot-live { background:var(--success); box-shadow:0 0 6px rgba(16,185,129,.4); animation:pulse 2s infinite; }
.scan-dot-idle { background:var(--text3); }
@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.4; } }

/* Finding item — triage queue */
.finding-item { display:flex; align-items:flex-start; gap:10px; padding:10px 0; border-bottom:1px solid var(--border); }
.finding-item:last-child { border-bottom:none; padding-bottom:0; }
.finding-body { flex:1; min-width:0; }
.finding-name { font-size:13px; color:var(--text); font-weight:500; line-height:1.5; }
.finding-endpoint { font-size:11px; color:var(--text2); font-family:var(--mono); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.finding-actions { display:flex; gap:6px; margin-top:6px; }
.btn-xs { font-size:11px; padding:3px 8px; border:1px solid var(--border); border-radius:6px; background:none; color:var(--text2); cursor:pointer; font-family:var(--font); transition:all .15s; }
.btn-xs:hover { background:var(--bg-elevated); border-color:var(--border-strong); color:var(--text); }
.btn-xs.primary { background:var(--bg3); color:var(--text); border-color:var(--border-strong); }

/* Target item — watchlist */
.target-item { display:flex; align-items:center; gap:10px; padding:8px 0; border-bottom:1px solid var(--border); cursor:pointer; }
.target-item:last-child { border-bottom:none; }
.target-item:hover { background:rgba(255,255,255,.02); }
.target-info { flex:1; min-width:0; }
.target-domain { font-size:12px; font-weight:500; color:var(--text); font-family:var(--mono); }
.target-meta { font-size:11px; color:var(--text2); margin-top:1px; }
.waf-chip { font-size:10px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.05); color:var(--text2); border:1px solid var(--border); }

/* Delta row */
.delta-row { display:flex; align-items:center; gap:8px; font-size:12px; color:var(--text); padding:6px 0; border-bottom:1px solid var(--border); }
.delta-row:last-child { border-bottom:none; }

/* Finding highlights */
.hl-zone { color:var(--target); font-weight:600; font-family:var(--mono); font-size:11.5px; }
.hl-domain { color:var(--brand2); font-weight:600; }
.hl-ip { color:var(--high); font-family:var(--mono); font-size:11px; }
.hl-num { color:var(--text); font-weight:700; }
.hl-keyword { color:var(--critical); font-weight:600; }

/* Pagination */
.pager { display:flex; align-items:center; justify-content:space-between; padding:12px 0; font-size:12px; color:var(--text2); }
.pager-info { font-family:var(--mono); font-size:11px; }
.pager-btns { display:flex; gap:4px; }
.pager-btn { display:inline-flex; align-items:center; justify-content:center; min-width:32px; height:30px; padding:0 10px; border-radius:6px; border:1px solid var(--border); background:var(--bg3); color:var(--text2); font-size:12px; cursor:pointer; transition:all .15s; font-family:var(--font); }
.pager-btn:hover:not(:disabled) { background:var(--bg-elevated); border-color:var(--border-strong); color:var(--text); }
.pager-btn:disabled { opacity:.35; cursor:default; }
.pager-btn.active { background:var(--brand); border-color:var(--brand); color:#fff; }

/* Re-scan dropdown */
.rescan-menu { position:relative; display:inline-block; }
.rescan-drop { display:none; position:absolute; right:0; top:calc(100% + 4px); background:var(--bg-elevated); border:1px solid var(--border-strong); border-radius:var(--radius); padding:6px 0; min-width:220px; z-index:50; box-shadow:var(--shadow-lg); }
.rescan-drop.open { display:block; }
.rescan-opt { display:flex; align-items:center; gap:8px; padding:8px 14px; font-size:12px; color:var(--text); cursor:pointer; transition:background .15s; white-space:nowrap; }
.rescan-opt:hover { background:rgba(255,255,255,.06); }
.rescan-opt .rescan-icon { font-size:14px; width:20px; text-align:center; flex-shrink:0; }
.rescan-opt .rescan-desc { font-size:10px; color:var(--text2); }
.rescan-opt.running { opacity:.5; pointer-events:none; }

/* Breadcrumb */
.breadcrumb { font-size:12px; color:var(--text2); margin-bottom:18px; }
.breadcrumb a { color:var(--accent); }

/* Loading */
.loading { text-align:center; padding:48px; color:var(--text2); font-size:13px; }

/* Scrollbar */
::-webkit-scrollbar { width:5px; }
::-webkit-scrollbar-track { background:transparent; }
::-webkit-scrollbar-thumb { background:rgba(255,255,255,.08); border-radius:4px; }
::-webkit-scrollbar-thumb:hover { background:rgba(255,255,255,.14); }

/* Toolbar */
.toolbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; padding-bottom:16px; border-bottom:1px solid var(--border); }
.toolbar-actions { display:flex; gap:8px; }
.btn { display:inline-flex; align-items:center; gap:6px; padding:7px 14px; border-radius:7px; border:1px solid var(--border); background:var(--bg3); color:var(--text2); font-size:12px; cursor:pointer; transition:all .2s ease; font-family:var(--font); font-weight:500; }
.btn:hover { background:var(--bg-elevated); border-color:var(--border-strong); color:var(--text); box-shadow:var(--shadow-sm); }
.btn-brand { background:var(--brand); border-color:var(--brand); color:#fff; }
.btn-brand:hover { background:#6d28d9; box-shadow:0 0 20px rgba(124,58,237,.25); }

/* Toast */
.toast { position:fixed; bottom:24px; right:24px; background:var(--bg-elevated); border:1px solid var(--border-strong); border-radius:var(--radius); padding:12px 20px; color:var(--text); font-size:13px; z-index:999; opacity:0; transform:translateY(8px); transition:all .3s ease; pointer-events:none; box-shadow:var(--shadow-lg); backdrop-filter:blur(12px); }
.toast.show { opacity:1; transform:translateY(0); }

/* Animations */
@keyframes fadeIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:translateY(0); } }
.cards, .table-wrap, .detail-grid, .section-title { animation:fadeIn .35s ease both; }

</style>
</head>
<body>

<div class="shell">
  <div class="sidebar">
    <div class="logo">&#9876; Fray <span>Dashboard</span> <span id="live-dot" class="scan-dot scan-dot-idle" style="margin-left:auto;width:6px;height:6px" title="Connecting..."></span></div>
    <div class="nav-item active" data-page="overview">&#9632;&ensp;Overview</div>
    <div class="nav-item" data-page="findings">&#9888;&ensp;Findings</div>
    <div class="nav-item" data-page="targets">&#9673;&ensp;Targets</div>
    <div class="nav-item" data-page="history">&#9683;&ensp;Scan History</div>
    <div class="nav-section">Intelligence</div>
    <div class="nav-item" data-page="executive">&#9998;&ensp;Executive Report</div>
    <div class="nav-item" data-page="learned">&#9881;&ensp;WAF Intel</div>
    <div class="nav-item" data-page="intel">&#9889;&ensp;CVE Feed</div>
    <div class="nav-section">Analysis</div>
    <div class="nav-item" data-page="timeline">&#128337;&ensp;Timeline</div>
    <div class="nav-item" data-page="diff">&#8644;&ensp;Diff Runs</div>
    <div class="nav-section">Settings</div>
    <div class="nav-item" data-page="domains">&#9776;&ensp;All Domains</div>
    <div class="sidebar-footer">
      <div class="sidebar-footer-text">Fray Security Scanner</div>
    </div>
  </div>
  <div class="main">
    <div class="toolbar" id="toolbar"></div>
    <div id="content"><div class="loading">Loading...</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const API = '';

let _domains = [];
let _stats = {};

function riskColor(score) {
  if (score >= 70) return 'var(--critical)';
  if (score >= 50) return 'var(--high)';
  if (score >= 30) return 'var(--medium)';
  if (score > 0) return 'var(--low)';
  return 'var(--text2)';
}

function riskBadge(level) {
  const l = (level||'').toLowerCase();
  const cls = l === 'critical' ? 'badge-critical' : l === 'high' ? 'badge-high' : l === 'medium' ? 'badge-medium' : l === 'low' ? 'badge-low' : 'badge-info';
  return `<span class="badge ${cls}">${(level||'N/A').toUpperCase()}</span>`;
}

function riskBar(score, width) {
  return `<div class="risk-bar" style="width:${width||'100%'}"><div class="risk-fill" style="width:${Math.min(100,score)}%;background:${riskColor(score)}"></div></div>`;
}

const _TECH_CATS = {
  infra: ['nginx','apache','iis','tomcat','openresty','litespeed','caddy','lighttpd','microsoft-httpapi','jetty','gunicorn','uwsgi'],
  frontend: ['react','vue','angular','jquery','next.js','nuxt','svelte','backbone','ember','bootstrap','tailwind','slick','webpack','vite'],
  cms: ['wordpress','drupal','joomla','shopify','magento','squarespace','wix','ghost','contentful','strapi','hubspot'],
  cdn: ['cloudfront','cloudflare','akamai','fastly','varnish','incapsula','sucuri','stackpath','edgecast','cdn77','bunny','amazon web services'],
  analytics: ['google_analytics','google_tag_manager','hotjar','segment','mixpanel','amplitude','heap','matomo','plausible'],
  lang: ['.net','php','python','java','ruby','go','node','express','laravel','rails','django','flask','spring','asp.net'],
};
function techTag(name) {
  const n = (name||'').toLowerCase();
  let cls = 'tag';
  for (const [cat, list] of Object.entries(_TECH_CATS)) {
    if (list.some(t => n.includes(t))) { cls = `tag tag-${cat}`; break; }
  }
  return `<span class="${cls}">${name}</span>`;
}

function timeAgo(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  } catch(e) { return ts; }
}

function highlightFinding(text) {
  if (!text) return '';
  // Highlight IPs: 1.2.3.4
  text = text.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="hl-ip">$1</span>');
  // Highlight subdomains/zones: word.word.tld patterns (at least 3 parts)
  text = text.replace(/\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b/g, (match) => {
    return `<span class="hl-zone">${match}</span>`;
  });
  // Highlight leading count: "3 subdomain(s)" or "158 subdomain(s)"
  text = text.replace(/^(\d+)\s+(subdomain|endpoint|lib|script|path|check|CDN)/i, '<span class="hl-num">$1</span> $2');
  // Highlight critical keywords
  text = text.replace(/\b(bypass WAF|vulnerable to takeover|Origin IP exposed|WAF completely bypassable|Clickjacking vulnerable|CORS misconfigur|broken chain)\b/gi, '<span class="hl-keyword">$1</span>');
  // Highlight grade letters in parentheses: (grade C)
  text = text.replace(/\(grade ([A-F])\)/gi, '(grade <strong>$1</strong>)');
  return text;
}

// ── Pagination builder ────────────────────────────────────────────────

function buildPager(total, currentPage, totalPages, perPage, goFn) {
  if (totalPages <= 1) {
    return `<div class="pager"><span class="pager-info">Showing ${total} item${total!==1?'s':''}</span><span></span></div>`;
  }
  const start = (currentPage - 1) * perPage + 1;
  const end = Math.min(currentPage * perPage, total);
  let html = `<div class="pager"><span class="pager-info">${start}\u2013${end} of ${total}</span><div class="pager-btns">`;
  html += `<button class="pager-btn" onclick="${goFn}(1)" ${currentPage<=1?'disabled':''}>&#171;</button>`;
  html += `<button class="pager-btn" onclick="${goFn}(${currentPage-1})" ${currentPage<=1?'disabled':''}>&#8249;</button>`;
  // Show page numbers with ellipsis
  const range = [];
  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
      range.push(i);
    } else if (range[range.length-1] !== '...') {
      range.push('...');
    }
  }
  for (const p of range) {
    if (p === '...') {
      html += `<span style="color:var(--text3);padding:0 4px;font-size:12px">&hellip;</span>`;
    } else {
      html += `<button class="pager-btn${p===currentPage?' active':''}" onclick="${goFn}(${p})">${p}</button>`;
    }
  }
  html += `<button class="pager-btn" onclick="${goFn}(${currentPage+1})" ${currentPage>=totalPages?'disabled':''}>&#8250;</button>`;
  html += `<button class="pager-btn" onclick="${goFn}(${totalPages})" ${currentPage>=totalPages?'disabled':''}>&#187;</button>`;
  html += `</div></div>`;
  return html;
}

// ── Re-scan system ────────────────────────────────────────────────────

let _rescanRunning = {};

async function rescanFinding(domain, findingEncoded, elementId) {
  const finding = decodeURIComponent(findingEncoded);
  const key = domain + ':' + finding;
  if (_rescanRunning[key]) return;
  _rescanRunning[key] = true;

  const el = document.getElementById(elementId);
  const btn = el ? el.querySelector('.finding-actions .btn-xs:last-child') : null;
  if (btn) { btn.disabled = true; btn.innerHTML = '&#8987; Scanning...'; }

  showToast(`Re-scanning finding on ${domain}...`);
  try {
    const resp = await fetch('/api/rescan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ domain, scope: 'finding', finding })
    });
    const result = await resp.json();
    if (result.status === 'started') {
      showToast(`Re-scan started for ${domain}. Will refresh when complete.`);
      pollRescan(result.task_id, elementId, key);
    } else if (result.status === 'completed') {
      showToast(result.resolved ? `Finding resolved on ${domain}!` : `Finding still present on ${domain}.`);
      if (el && result.resolved) {
        el.style.opacity = '.4';
        el.style.borderLeft = '3px solid var(--success)';
        if (btn) btn.innerHTML = '&#10004; Resolved';
      } else if (btn) {
        btn.innerHTML = '&#10008; Still present';
        btn.disabled = false;
      }
      delete _rescanRunning[key];
    } else {
      showToast(result.error || 'Re-scan failed');
      if (btn) { btn.disabled = false; btn.innerHTML = '&#8635; Re-scan'; }
      delete _rescanRunning[key];
    }
  } catch(e) {
    showToast('Re-scan request failed: ' + e.message);
    if (btn) { btn.disabled = false; btn.innerHTML = '&#8635; Re-scan'; }
    delete _rescanRunning[key];
  }
}

function pollRescan(taskId, elementId, key) {
  const check = async () => {
    try {
      const resp = await fetch('/api/rescan-status/' + taskId);
      const result = await resp.json();
      if (result.status === 'running') {
        setTimeout(check, 3000);
      } else {
        const el = document.getElementById(elementId);
        const btn = el ? el.querySelector('.finding-actions .btn-xs:last-child') : null;
        if (result.status === 'completed') {
          showToast(result.resolved ? 'Finding resolved!' : 'Finding still present.');
          if (el && result.resolved) {
            el.style.opacity = '.4';
            el.style.borderLeft = '3px solid var(--success)';
            if (btn) btn.innerHTML = '&#10004; Resolved';
          } else if (btn) {
            btn.innerHTML = '&#10008; Still present';
            btn.disabled = false;
          }
        } else {
          showToast('Re-scan finished with status: ' + result.status);
          if (btn) { btn.disabled = false; btn.innerHTML = '&#8635; Re-scan'; }
        }
        delete _rescanRunning[key];
      }
    } catch(e) { setTimeout(check, 5000); }
  };
  setTimeout(check, 3000);
}

async function rescanDomain(domain, scope) {
  showToast(`Starting ${scope} re-scan on ${domain}...`);
  try {
    const resp = await fetch('/api/rescan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ domain, scope })
    });
    const result = await resp.json();
    if (result.status === 'started') {
      showToast(`${scope} re-scan started for ${domain}. Task ID: ${result.task_id}`);
    } else if (result.status === 'completed') {
      showToast(`${scope} re-scan completed for ${domain}. Refreshing...`);
      setTimeout(() => navigate('detail', domain), 1000);
    } else {
      showToast(result.error || 'Re-scan failed');
    }
  } catch(e) {
    showToast('Re-scan request failed: ' + e.message);
  }
}

function toggleRescanMenu(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
  // Close on outside click
  const closer = (e) => {
    if (!el.contains(e.target) && !e.target.closest('.rescan-menu')) {
      el.classList.remove('open');
      document.removeEventListener('click', closer);
    }
  };
  setTimeout(() => document.addEventListener('click', closer), 0);
}

async function exportDomainReport(domain) {
  showToast(`Generating report for ${domain}...`);
  try {
    const resp = await fetch('/api/export-report/' + domain);
    if (!resp.ok) { showToast('Report generation failed'); return; }
    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = domain + '_report.html';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(`Downloaded ${domain}_report.html`);
  } catch(e) {
    showToast('Export failed: ' + e.message);
  }
}

async function shareDomain(domain) {
  showToast(`Sharing ${domain}...`);
  try {
    const resp = await fetch('/api/share/' + domain, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({expires_days: 30})
    });
    const data = await resp.json();
    if (data.url) {
      navigator.clipboard.writeText(data.url).catch(() => {});
      showToast(`Shared! Link copied: ${data.url}`);
      // Update share button to show link
      const shareBtn = document.getElementById('share-btn');
      if (shareBtn) {
        shareBtn.innerHTML = `&#10003; Shared`;
        shareBtn.title = data.url;
      }
    } else {
      showToast(data.error || 'Share failed');
    }
  } catch(e) {
    showToast('Share failed: ' + e.message);
  }
}

async function fetchJSON(url) {
  const r = await fetch(API + url);
  return r.json();
}

// ── Pages ──────────────────────────────────────────────────────────────

async function renderOverview() {
  const [s, domains, delta, triage, tests, scans, agents] = await Promise.all([
    fetchJSON('/api/stats'),
    fetchJSON('/api/domains'),
    fetchJSON('/api/global-delta'),
    fetchJSON('/api/findings-triage'),
    fetchJSON('/api/tests'),
    fetchJSON('/api/scans'),
    fetchJSON('/api/agents'),
  ]);
  _stats = s;
  _domains = domains;
  const sev = s.severity || {};
  const critHigh = (sev.critical||0) + (sev.high||0);
  const totalFindings = delta.total_findings || 0;
  const newF = delta.new_findings || 0;
  const resolvedF = delta.resolved_findings || 0;

  // Compute avg grade
  const grades = domains.map(d => d.grade || 'C');
  const gradeMap = {A:4,B:3,C:2,D:1,F:0};
  const avgGradeNum = grades.length ? grades.reduce((s,g) => s + (gradeMap[g]||2), 0) / grades.length : 2;
  const avgGrade = avgGradeNum >= 3.5 ? 'A' : avgGradeNum >= 2.5 ? 'B' : avgGradeNum >= 1.5 ? 'C' : avgGradeNum >= 0.5 ? 'D' : 'F';
  const gradeCls = avgGrade === 'A' ? 'grade-a' : avgGrade === 'B' ? 'grade-b' : avgGrade === 'C' ? 'grade-c' : avgGrade === 'D' ? 'grade-d' : 'grade-f';

  let html = '';

  // Metric cards with deltas
  html += `<div class="cards">
    <div class="card card-link" onclick="navigate('findings')">
      <div class="card-label">Total Findings</div>
      <div class="card-value">${totalFindings}</div>
      <div class="metric-delta ${newF > 0 ? 'delta-up' : resolvedF > 0 ? 'delta-down' : 'delta-neutral'}">${newF > 0 ? '&#9650; '+newF+' new since last scan' : resolvedF > 0 ? '&#9660; '+resolvedF+' resolved' : '&#8596; no change'}</div>
    </div>
    <div class="card card-link" onclick="navigate('findings')">
      <div class="card-label">Critical / High</div>
      <div class="card-value" style="color:${critHigh > 0 ? 'var(--critical)' : 'var(--success)'}">${critHigh}</div>
      <div class="metric-delta delta-neutral">${sev.critical||0} critical &middot; ${sev.high||0} high</div>
    </div>
    <div class="card card-link" onclick="navigate('targets')">
      <div class="card-label">Targets Watched</div>
      <div class="card-value">${domains.length}</div>
      <div class="metric-delta delta-neutral">${domains.filter(d=>d.scan_count>1).length} scanned multiple times</div>
    </div>
    <div class="card card-link" onclick="navigate('targets')">
      <div class="card-label">Avg. Grade</div>
      <div class="card-value"><span class="grade-badge ${gradeCls}" style="display:inline-flex;width:auto;padding:4px 12px;font-size:20px">${avgGrade}</span></div>
      <div class="metric-delta delta-neutral">${s.avg_risk||0} avg risk score</div>
    </div>
  </div>`;

  // Scan bar — show most recently scanned domain
  const mostRecent = [...domains].sort((a,b) => new Date(b.timestamp||0) - new Date(a.timestamp||0))[0];
  if (mostRecent) {
    html += `<div class="scan-bar">
      <div class="scan-dot scan-dot-idle"></div>
      <div style="font-size:12px;color:var(--text2);flex:1"><strong style="color:var(--text)">${mostRecent.domain}</strong> &mdash; last scanned ${timeAgo(mostRecent.timestamp)} &middot; ${mostRecent.findings} findings &middot; risk ${mostRecent.risk_score}</div>
      <button class="btn-xs" onclick="navigate('detail','${mostRecent.domain}')">View details</button>
    </div>`;
  }

  // Two-column layout: Triage queue + right sidebar (watchlist + delta)
  html += `<div class="two-col">`;

  // Left: Triage queue preview
  html += `<div class="card" style="padding:16px 18px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <span style="font-size:14px;font-weight:600;color:var(--text)">Triage Queue</span>
      <button class="btn-xs" onclick="navigate('findings')">View all &rarr;</button>
    </div>`;
  for (const f of triage.slice(0, 5)) {
    html += `<div class="finding-item">
      ${riskBadge(f.severity)}
      <div class="finding-body">
        <div class="finding-name">${highlightFinding(f.finding)}</div>
        <div class="finding-endpoint"><span class="hl-domain">${f.domain}</span>${f.category ? ' &middot; '+f.category : ''}</div>
        <div class="finding-actions">
          <button class="btn-xs primary" onclick="navigate('detail','${f.domain}')">View domain</button>
        </div>
      </div>
    </div>`;
  }
  if (!triage.length) html += `<div style="color:var(--text2);font-size:13px;padding:16px 0;text-align:center">No findings yet. Run a scan to get started.</div>`;
  html += `</div>`;

  // Right column
  html += `<div style="display:flex;flex-direction:column;gap:16px">`;

  // Target watchlist preview
  html += `<div class="card" style="padding:16px 18px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <span style="font-size:14px;font-weight:600;color:var(--text)">Target Watchlist</span>
      <button class="btn-xs" onclick="navigate('targets')">Manage</button>
    </div>`;
  for (const d of domains.slice(0, 5)) {
    const g = d.grade || 'C';
    const gCls = g === 'A' ? 'grade-a' : g === 'B' ? 'grade-b' : g === 'C' ? 'grade-c' : g === 'D' ? 'grade-d' : 'grade-f';
    html += `<div class="target-item" onclick="navigate('detail','${d.domain}')">
      <div class="grade-badge ${gCls}">${g}</div>
      <div class="target-info">
        <div class="target-domain">${d.domain}</div>
        <div class="target-meta">${d.waf ? d.waf+' &middot; ' : ''}scanned ${timeAgo(d.timestamp)}</div>
      </div>
      <span style="font-size:11px;color:${riskColor(d.risk_score)}">${d.risk_score}</span>
    </div>`;
  }
  html += `</div>`;

  // Delta card — last scan changes
  const domainChanges = (delta.domains_with_changes || []).slice(0, 1);
  if (domainChanges.length) {
    const dc = domainChanges[0];
    html += `<div class="card" style="padding:16px 18px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <span style="font-size:14px;font-weight:600;color:var(--text)">Delta &mdash; last scan</span>
        <span class="hl-domain" style="font-size:12px">${dc.domain}</span>
      </div>`;
    for (const d of dc.deltas) {
      const pillCls = d.type === 'new' ? 'pill-new' : d.type === 'fixed' ? 'pill-fixed' : d.type === 'changed' ? 'pill-changed' : 'pill-same';
      html += `<div class="delta-row"><span class="delta-pill ${pillCls}">${d.type}</span><span>${highlightFinding(d.detail)}</span></div>`;
    }
    html += `<button class="btn-xs" style="margin-top:10px;width:100%" onclick="navigate('history')">View scan history &rarr;</button>`;
    html += `</div>`;
  }

  html += `</div>`; // close right column
  html += `</div>`; // close two-col

  // Activity feed — recent test/scan/agent runs
  const allActivity = [...tests, ...scans, ...agents].sort((a,b) => new Date(b.timestamp||0) - new Date(a.timestamp||0)).slice(0, 8);
  if (allActivity.length) {
    html += `<div class="section-title" style="margin-top:8px">&#9889; Recent Activity <span class="count">(${tests.length + scans.length + agents.length} runs)</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Command</th><th>Target</th><th>Total</th><th>Blocked</th><th>Bypassed</th><th>Block Rate</th><th>Duration</th><th>When</th></tr></thead><tbody>`;
    for (const a of allActivity) {
      const cmdCls = a.command === 'test' ? 'tag-infra' : a.command === 'scan' ? 'tag-frontend' : a.command === 'agent' ? 'tag-cms' : '';
      const bypassed = a.passed || 0;
      const bypassColor = bypassed > 5 ? 'var(--critical)' : bypassed > 0 ? 'var(--high)' : 'var(--success)';
      html += `<tr style="cursor:pointer" onclick="navigate('detail','${a.domain}')">
        <td><span class="tag ${cmdCls}">${a.command}</span></td>
        <td><span class="hl-domain">${a.domain}</span></td>
        <td style="font-weight:500">${a.total||0}</td>
        <td style="color:var(--success);font-weight:600">${a.blocked||0}</td>
        <td style="color:${bypassColor};font-weight:600">${bypassed}</td>
        <td style="font-family:var(--mono);font-size:12px">${a.block_rate || a.bypass_rate || '-'}</td>
        <td style="font-size:12px;color:var(--text2)">${a.duration||'-'}</td>
        <td style="font-size:12px;color:var(--text2)">${timeAgo(a.timestamp)}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  $('#content').innerHTML = html;
}

let _domPage = 1;
const _DOM_PER_PAGE = 20;
let _domFilter = '';

async function renderDomains() {
  _domains = await fetchJSON('/api/domains');
  _domPage = 1;
  _domFilter = '';
  let html = `<div class="section-title">&#9673; All Domains <span class="count">(${_domains.length})</span></div>`;
  html += `<div style="margin-bottom:16px"><input id="domain-search" placeholder="Filter domains..." style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);width:300px;font-size:13px;outline:none"></div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr><th>Grade</th><th>Domain</th><th>Risk</th><th>Score</th><th>Subs</th><th>Vectors</th><th>Findings</th><th>Scans</th><th>TLS</th><th>Headers</th><th>Last Scan</th></tr></thead>
    <tbody id="domain-tbody"></tbody></table></div>`;
  html += `<div id="domain-pager"></div>`;
  $('#content').innerHTML = html;
  renderDomainPage();

  document.getElementById('domain-search').addEventListener('input', e => {
    _domFilter = e.target.value.toLowerCase();
    _domPage = 1;
    renderDomainPage();
  });
}

function renderDomainPage() {
  const filtered = _domFilter ? _domains.filter(d => d.domain.includes(_domFilter)) : _domains;
  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / _DOM_PER_PAGE));
  if (_domPage > pages) _domPage = pages;
  const start = (_domPage - 1) * _DOM_PER_PAGE;
  const slice = filtered.slice(start, start + _DOM_PER_PAGE);
  document.getElementById('domain-tbody').innerHTML = slice.map(domainRow).join('');
  document.getElementById('domain-pager').innerHTML = buildPager(total, _domPage, pages, _DOM_PER_PAGE, 'domGoPage');
}

function domGoPage(p) { _domPage = p; renderDomainPage(); }

function domainRow(d) {
  const _g = d.grade || 'C';
  const _gC = _g === 'A' ? 'grade-a' : _g === 'B' ? 'grade-b' : _g === 'C' ? 'grade-c' : _g === 'D' ? 'grade-d' : 'grade-f';
  return `<tr style="cursor:pointer" onclick="navigate('detail','${d.domain}')">
    <td><div class="grade-badge ${_gC}" style="width:24px;height:24px;font-size:11px;margin:0 auto">${_g}</div></td>
    <td><a href="#" onclick="event.preventDefault();navigate('detail','${d.domain}')">${d.domain}</a></td>
    <td>${riskBadge(d.risk_level)}</td>
    <td style="color:${riskColor(d.risk_score)};font-weight:600;font-size:13px">${d.risk_score}</td>
    <td style="font-weight:500">${d.subdomains}</td>
    <td style="font-weight:500">${d.vectors||0}</td>
    <td style="font-weight:500">${d.findings||0}</td>
    <td style="font-weight:500">${d.scan_count}</td>
    <td><span class="tag tag-infra">${d.tls_version||'?'}</span></td>
    <td style="font-weight:500">${d.header_score}%</td>
    <td style="color:var(--text2);font-size:12px">${timeAgo(d.timestamp)}</td>
  </tr>`;
}

// ── Findings Triage Queue ──────────────────────────────────────────────

let _findingsAll = [];
let _findPage = 1;
let _findSevFilter = 'all';
const _FIND_PER_PAGE = 20;

async function renderFindings() {
  _findingsAll = await fetchJSON('/api/findings-triage');
  _findPage = 1;
  _findSevFilter = 'all';
  let html = `<div class="section-title">&#9888; Findings Triage Queue <span class="count">(${_findingsAll.length})</span></div>`;

  if (!_findingsAll.length) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;text-align:center">
      <div style="font-size:15px;color:var(--text);margin-bottom:8px;font-weight:500">No findings yet</div>
      <p style="color:var(--text2);font-size:13px;max-width:420px;margin:0 auto 16px">Run a recon scan against a target to discover security findings.</p>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:inline-block;font-family:var(--mono);font-size:12px;color:var(--text)">fray recon example.com</div>
    </div>`;
    $('#content').innerHTML = html;
    return;
  }

  // Summary cards
  const sevCounts = {critical:0, high:0, medium:0, low:0};
  for (const f of _findingsAll) { sevCounts[f.severity.toLowerCase()] = (sevCounts[f.severity.toLowerCase()]||0) + 1; }
  html += `<div class="cards">
    <div class="card" style="border-left:3px solid var(--critical)"><div class="card-label">Critical</div><div class="card-value" style="color:var(--critical)">${sevCounts.critical}</div></div>
    <div class="card" style="border-left:3px solid var(--high)"><div class="card-label">High</div><div class="card-value" style="color:var(--high)">${sevCounts.high}</div></div>
    <div class="card" style="border-left:3px solid var(--medium)"><div class="card-label">Medium</div><div class="card-value" style="color:var(--medium)">${sevCounts.medium}</div></div>
    <div class="card" style="border-left:3px solid var(--low)"><div class="card-label">Low</div><div class="card-value" style="color:var(--low)">${sevCounts.low}</div></div>
  </div>`;

  // Filter bar
  html += `<div style="margin-bottom:16px;display:flex;gap:8px">
    <button class="btn btn-brand filter-btn active" data-filter="all" onclick="filterFindings('all')">All (${_findingsAll.length})</button>
    <button class="btn filter-btn" data-filter="critical" onclick="filterFindings('critical')">Critical (${sevCounts.critical})</button>
    <button class="btn filter-btn" data-filter="high" onclick="filterFindings('high')">High (${sevCounts.high})</button>
    <button class="btn filter-btn" data-filter="medium" onclick="filterFindings('medium')">Medium (${sevCounts.medium})</button>
    <button class="btn filter-btn" data-filter="low" onclick="filterFindings('low')">Low (${sevCounts.low})</button>
  </div>`;

  html += `<div id="findings-list"></div>`;
  html += `<div id="findings-pager"></div>`;

  $('#content').innerHTML = html;
  renderFindingsPage();
}

function getFilteredFindings() {
  return _findSevFilter === 'all' ? _findingsAll : _findingsAll.filter(f => f.severity.toLowerCase() === _findSevFilter);
}

function renderFindingsPage() {
  const filtered = getFilteredFindings();
  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / _FIND_PER_PAGE));
  if (_findPage > pages) _findPage = pages;
  const start = (_findPage - 1) * _FIND_PER_PAGE;
  const slice = filtered.slice(start, start + _FIND_PER_PAGE);

  let html = '';
  for (const f of slice) {
    const catCls = f.category === 'infra' ? 'tag-infra' : f.category === 'config' ? 'tag-cdn' : f.category === 'app' ? 'tag-frontend' : f.category === 'data' ? 'tag-lang' : '';
    const findingId = btoa(f.domain + ':' + f.finding).replace(/[^a-zA-Z0-9]/g,'').slice(0,24);
    html += `<div class="finding-item" data-sev="${f.severity.toLowerCase()}" style="padding:12px 0" id="fi-${findingId}">
      ${riskBadge(f.severity)}
      <div class="finding-body">
        <div class="finding-name">${highlightFinding(f.finding)}</div>
        <div class="finding-endpoint"><span class="hl-domain">${f.domain}</span> &middot; <span class="tag ${catCls}">${f.category}</span>${f.waf ? ' &middot; <span class="waf-chip">'+f.waf+'</span>' : ''}</div>
        <div class="finding-actions">
          <button class="btn-xs primary" onclick="navigate('detail','${f.domain}')">View domain</button>
          <button class="btn-xs" onclick="rescanFinding('${f.domain}','${encodeURIComponent(f.finding)}','fi-${findingId}')">&#8635; Re-scan</button>
        </div>
      </div>
      <span style="font-family:var(--mono);font-size:12px;color:${riskColor(f.risk_score)};font-weight:600;flex-shrink:0">${f.risk_score}</span>
    </div>`;
  }
  document.getElementById('findings-list').innerHTML = html;
  document.getElementById('findings-pager').innerHTML = buildPager(total, _findPage, pages, _FIND_PER_PAGE, 'findGoPage');
}

function findGoPage(p) { _findPage = p; renderFindingsPage(); }

function filterFindings(sev) {
  _findSevFilter = sev;
  _findPage = 1;
  renderFindingsPage();
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === sev);
    btn.classList.toggle('btn-brand', btn.dataset.filter === sev);
  });
}

// ── Targets Watchlist ──────────────────────────────────────────────────

async function renderTargets() {
  _domains = await fetchJSON('/api/domains');
  let html = `<div class="section-title">&#9673; Target Watchlist <span class="count">(${_domains.length})</span></div>`;

  if (!_domains.length) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;text-align:center">
      <div style="font-size:15px;color:var(--text);margin-bottom:8px;font-weight:500">No targets yet</div>
      <p style="color:var(--text2);font-size:13px;max-width:420px;margin:0 auto 16px">Scan a domain to add it to your watchlist.</p>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:inline-block;font-family:var(--mono);font-size:12px;color:var(--text)">fray recon example.com</div>
    </div>`;
    $('#content').innerHTML = html;
    return;
  }

  // Grade distribution cards
  const gradeDist = {A:0, B:0, C:0, D:0, F:0};
  for (const d of _domains) { gradeDist[d.grade||'C']++; }
  html += `<div class="cards">
    <div class="card"><div class="card-label">Grade A</div><div class="card-value" style="color:var(--success)">${gradeDist.A}</div><div class="card-sub">Risk &le; 10</div></div>
    <div class="card"><div class="card-label">Grade B</div><div class="card-value" style="color:var(--low)">${gradeDist.B}</div><div class="card-sub">Risk 11&ndash;25</div></div>
    <div class="card"><div class="card-label">Grade C</div><div class="card-value" style="color:var(--medium)">${gradeDist.C}</div><div class="card-sub">Risk 26&ndash;45</div></div>
    <div class="card"><div class="card-label">Grade D / F</div><div class="card-value" style="color:var(--critical)">${gradeDist.D + gradeDist.F}</div><div class="card-sub">Risk &gt; 45</div></div>
  </div>`;

  // Search
  html += `<div style="margin-bottom:16px"><input id="target-search" placeholder="Filter targets..." style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);width:300px;font-size:13px;outline:none"></div>`;

  // Target table
  html += `<div class="table-wrap"><table>
    <thead><tr><th>Grade</th><th>Domain</th><th>Risk</th><th>WAF</th><th>Findings</th><th>Subs</th><th>Scans</th><th>Last Scan</th></tr></thead>
    <tbody id="target-tbody">`;
  for (const d of _domains) {
    html += targetRow(d);
  }
  html += `</tbody></table></div>`;

  $('#content').innerHTML = html;

  document.getElementById('target-search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    const filtered = _domains.filter(d => d.domain.includes(q));
    document.getElementById('target-tbody').innerHTML = filtered.map(targetRow).join('');
  });
}

function targetRow(d) {
  const g = d.grade || 'C';
  const gCls = g === 'A' ? 'grade-a' : g === 'B' ? 'grade-b' : g === 'C' ? 'grade-c' : g === 'D' ? 'grade-d' : 'grade-f';
  return `<tr style="cursor:pointer" onclick="navigate('detail','${d.domain}')">
    <td><div class="grade-badge ${gCls}" style="margin:0 auto">${g}</div></td>
    <td><a href="#" onclick="event.preventDefault();navigate('detail','${d.domain}')" style="font-family:var(--mono);font-size:12px">${d.domain}</a></td>
    <td style="color:${riskColor(d.risk_score)};font-weight:600">${d.risk_score}</td>
    <td>${d.waf ? '<span class="waf-chip">'+d.waf+'</span>' : '<span style="color:var(--text3);font-size:11px">None</span>'}</td>
    <td style="font-weight:500">${d.findings||0}</td>
    <td style="font-weight:500">${d.subdomains}</td>
    <td style="font-weight:500">${d.scan_count}</td>
    <td style="color:var(--text2);font-size:12px">${timeAgo(d.timestamp)}</td>
  </tr>`;
}

// ── Scan History ──────────────────────────────────────────────────────

async function renderHistory() {
  _domains = await fetchJSON('/api/domains');
  let html = `<div class="section-title">&#9683; Scan History</div>`;

  if (!_domains.length) {
    html += `<div class="loading">No scan data yet.</div>`;
    $('#content').innerHTML = html;
    return;
  }

  // Domain selector
  html += `<div style="margin-bottom:16px;display:flex;gap:8px;align-items:center">
    <span style="font-size:12px;color:var(--text2)">Domain:</span>
    <select id="history-domain" style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-size:13px;font-family:var(--mono);outline:none;min-width:280px">
      ${_domains.map(d => `<option value="${d.domain}">${d.domain} (${d.scan_count} scans)</option>`).join('')}
    </select>
  </div>`;
  html += `<div id="history-content"><div class="loading">Select a domain...</div></div>`;

  $('#content').innerHTML = html;

  async function loadHistory(domain) {
    const [history, delta] = await Promise.all([
      fetchJSON('/api/domain/' + domain + '/history'),
      fetchJSON('/api/scan-delta/' + domain),
    ]);
    const hc = document.getElementById('history-content');
    let h = '';

    // Delta summary card
    if (delta.current && delta.previous) {
      h += `<div class="card" style="padding:16px 18px;margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <span style="font-size:14px;font-weight:600;color:var(--text)">Delta: Latest vs Previous Scan</span>
          <span style="font-size:11px;color:var(--text2)">${delta.current.grade} (was ${delta.previous.grade})</span>
        </div>`;
      for (const d of delta.deltas || []) {
        const pillCls = d.type === 'new' ? 'pill-new' : d.type === 'fixed' ? 'pill-fixed' : d.type === 'changed' ? 'pill-changed' : 'pill-same';
        h += `<div class="delta-row"><span class="delta-pill ${pillCls}">${d.type}</span><span>${highlightFinding(d.detail)}</span></div>`;
      }
      if (!(delta.deltas||[]).length) {
        h += `<div style="color:var(--text2);font-size:13px;padding:8px 0">No changes between scans.</div>`;
      }
      h += `</div>`;
    }

    // Summary cards comparing current vs previous
    if (delta.current) {
      const c = delta.current;
      const p = delta.previous || {};
      h += `<div class="cards">
        <div class="card"><div class="card-label">Risk Score</div><div class="card-value" style="color:${riskColor(c.risk_score)}">${c.risk_score}</div>
          ${p.risk_score != null ? `<div class="metric-delta ${c.risk_score > p.risk_score ? 'delta-up' : c.risk_score < p.risk_score ? 'delta-down' : 'delta-neutral'}">${c.risk_score > p.risk_score ? '&#9650; +' : c.risk_score < p.risk_score ? '&#9660; ' : '&#8596; '}${Math.abs(c.risk_score - p.risk_score)} from previous</div>` : ''}
        </div>
        <div class="card"><div class="card-label">Findings</div><div class="card-value">${c.finding_count}</div>
          ${p.finding_count != null ? `<div class="metric-delta ${c.finding_count > p.finding_count ? 'delta-up' : c.finding_count < p.finding_count ? 'delta-down' : 'delta-neutral'}">${c.finding_count > p.finding_count ? '&#9650; +' : c.finding_count < p.finding_count ? '&#9660; ' : '&#8596; '}${Math.abs(c.finding_count - p.finding_count)}</div>` : ''}
        </div>
        <div class="card"><div class="card-label">Subdomains</div><div class="card-value">${c.subdomains}</div>
          ${p.subdomains != null ? `<div class="metric-delta ${c.subdomains > p.subdomains ? 'delta-up' : c.subdomains < p.subdomains ? 'delta-down' : 'delta-neutral'}">${c.subdomains > p.subdomains ? '&#9650; +' : c.subdomains < p.subdomains ? '&#9660; ' : '&#8596; '}${Math.abs(c.subdomains - p.subdomains)}</div>` : ''}
        </div>
        <div class="card"><div class="card-label">WAF</div><div class="card-value" style="font-size:14px">${c.waf || 'None'}</div>
          ${p.waf != null && p.waf !== c.waf ? `<div class="metric-delta delta-up">Changed from ${p.waf||'None'}</div>` : ''}
        </div>
      </div>`;
    }

    // Scan timeline table
    if (history.length) {
      h += `<div class="section-title" style="margin-top:8px">Scan Timeline <span class="count">(${history.length} scans)</span></div>`;
      h += `<div class="table-wrap"><table>
        <thead><tr><th>Date</th><th>Grade</th><th>Risk</th><th>Findings</th><th>Vectors</th><th>Subs</th><th>WAF</th><th>Technologies</th></tr></thead><tbody>`;
      for (const scan of history.reverse()) {
        const g = scan.grade || 'C';
        const gCls = g === 'A' ? 'grade-a' : g === 'B' ? 'grade-b' : g === 'C' ? 'grade-c' : g === 'D' ? 'grade-d' : 'grade-f';
        h += `<tr>
          <td style="font-size:12px;white-space:nowrap">${timeAgo(scan.timestamp)}</td>
          <td><div class="grade-badge ${gCls}" style="width:24px;height:24px;font-size:11px">${g}</div></td>
          <td style="color:${riskColor(scan.risk_score)};font-weight:600">${scan.risk_score}</td>
          <td>${scan.finding_count}</td>
          <td>${scan.vector_count}</td>
          <td>${scan.subdomains}</td>
          <td>${scan.waf ? '<span class="waf-chip">'+scan.waf+'</span>' : ''}</td>
          <td style="font-size:11px">${scan.tech_count} detected</td>
        </tr>`;
      }
      h += `</tbody></table></div>`;
    } else {
      h += `<div style="color:var(--text2);font-size:13px;padding:16px 0">Only one scan available. Re-scan to see delta comparison.</div>`;
    }

    hc.innerHTML = h;
  }

  // Load first domain's history
  loadHistory(_domains[0].domain);

  document.getElementById('history-domain').addEventListener('change', e => {
    loadHistory(e.target.value);
  });
}

async function renderDetail(domain) {
  const data = await fetchJSON(`/api/domain/${domain}`);
  if (data.error) {
    $('#content').innerHTML = `<div class="loading">Domain not found</div>`;
    return;
  }

  const attack = data.attack_surface || {};
  const risk = attack.risk_score || 0;
  const riskLevel = attack.risk_level || 'unknown';
  const tls = data.tls || {};
  const headers = data.headers || {};
  const csp = data.csp || {};
  const fp = data.fingerprint || {};
  const dns = data.dns || {};
  const cors = data.cors || {};
  const subs = (data.subdomains || {}).subdomains || [];
  const subsActive = (data.subdomains_active || {}).subdomains || [];
  const allSubs = [...subs, ...subsActive];
  const vectors = attack.attack_vectors || attack.vectors || [];
  const findings = attack.findings || [];
  const exposed = (data.exposed_files || {}).files || [];
  const exposedFound = exposed.filter(f => f.status === 200);
  const origin = data.origin_ip || {};
  const originCandidates = origin.candidates || [];
  const ct = data.ct_monitor || {};
  const techs = fp.technologies || {};
  const cookies = data.cookies || {};
  const params = data.params || {};
  const graphql = data.graphql || {};
  const secrets = data.secrets || {};
  const bot = data.bot_protection || {};
  const gap = data.gap_analysis || {};
  const subsActiveData = data.subdomains_active || {};
  const discoveredSubs = subsActiveData.discovered || [];
  const wafBypassSubs = subsActiveData.waf_bypass || [];

  const _grade = risk >= 0 ? (risk <= 10 ? 'A' : risk <= 25 ? 'B' : risk <= 45 ? 'C' : risk <= 65 ? 'D' : 'F') : 'C';
  const _gCls = _grade === 'A' ? 'grade-a' : _grade === 'B' ? 'grade-b' : _grade === 'C' ? 'grade-c' : _grade === 'D' ? 'grade-d' : 'grade-f';
  let html = `<div class="breadcrumb"><a href="#" onclick="event.preventDefault();navigate('targets')">Targets</a> / ${domain}</div>`;
  html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
    <div class="section-title" style="margin-bottom:0"><span class="grade-badge ${_gCls}" style="width:32px;height:32px;font-size:14px">${_grade}</span> ${domain} ${riskBadge(riskLevel)}</div>
    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn" onclick="exportDomainReport('${domain}')">&#128196; Export Report</button>
      <button class="btn" id="share-btn" onclick="shareDomain('${domain}')" title="Upload sanitized snapshot to share.dalisec.io">&#128279; Share</button>
      <div class="rescan-menu">
      <button class="btn btn-brand" onclick="toggleRescanMenu('rescan-drop-detail')">&#8635; Re-scan</button>
      <div class="rescan-drop" id="rescan-drop-detail">
        <div class="rescan-opt" onclick="rescanDomain('${domain}','full')">
          <span class="rescan-icon">&#9876;</span>
          <div><div>Full Re-scan</div><div class="rescan-desc">Complete recon + attack surface analysis</div></div>
        </div>
        <div class="rescan-opt" onclick="rescanDomain('${domain}','waf')">
          <span class="rescan-icon">&#9730;</span>
          <div><div>WAF Only</div><div class="rescan-desc">Quick WAF vendor &amp; bypass check</div></div>
        </div>
        <div class="rescan-opt" onclick="rescanDomain('${domain}','changed')">
          <span class="rescan-icon">&#916;</span>
          <div><div>Changed Findings</div><div class="rescan-desc">Re-check only findings that moved since last scan</div></div>
        </div>
        <div class="rescan-opt" onclick="rescanDomain('${domain}','endpoint')">
          <span class="rescan-icon">&#9889;</span>
          <div><div>Endpoint Check</div><div class="rescan-desc">Re-scan exposed files, headers, TLS</div></div>
        </div>
      </div>
    </div>
    </div>
  </div>`;

  // Top cards
  html += `<div class="cards">
    <div class="card"><div class="card-label">Risk Score</div><div class="card-value" style="color:${riskColor(risk)}">${risk}/100</div>${riskBar(risk)}</div>
    <div class="card"><div class="card-label">Subdomains</div><div class="card-value">${allSubs.length}</div></div>
    <div class="card"><div class="card-label">Attack Vectors</div><div class="card-value">${vectors.length}</div></div>
    <div class="card"><div class="card-label">Findings</div><div class="card-value">${findings.length}</div></div>
    <div class="card"><div class="card-label">Header Score</div><div class="card-value">${headers.score||0}%</div></div>
    <div class="card"><div class="card-label">TLS</div><div class="card-value" style="font-size:16px">${tls.tls_version||'N/A'}</div></div>
    <div class="card"><div class="card-label">CSP Score</div><div class="card-value">${csp.score||0}/100</div></div>
  </div>`;

  // Detail grid
  html += `<div class="detail-grid">`;

  // Technologies — grouped by category with confidence bars
  html += `<div class="detail-section"><h3>Discovered Technologies (${Object.keys(techs).length})</h3>`;
  if (Object.keys(techs).length) {
    // Group by category
    const byCategory = {};
    for (const [name, info] of Object.entries(techs)) {
      const cat = (typeof info === 'object' && info.category) ? info.category : 'Other';
      const conf = (typeof info === 'object' && info.confidence != null) ? info.confidence : (typeof info === 'number' ? info : 0);
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push({ name, confidence: conf });
    }
    for (const [cat, items] of Object.entries(byCategory)) {
      html += `<div style="margin-bottom:10px"><div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);margin-bottom:4px;font-weight:600">${cat}</div>`;
      for (const item of items.sort((a,b) => b.confidence - a.confidence)) {
        const confPct = Math.min(100, Math.max(0, item.confidence));
        const confColor = confPct >= 80 ? 'var(--success)' : confPct >= 50 ? 'var(--medium)' : 'var(--text2)';
        html += `<div class="kv">
          <span class="kv-key">${techTag(item.name)}</span>
          <span class="kv-val" style="display:flex;align-items:center;gap:8px">
            <span style="width:50px;height:4px;border-radius:2px;background:var(--bg);overflow:hidden;display:inline-block"><span style="width:${confPct}%;height:100%;background:${confColor};display:block;border-radius:2px"></span></span>
            <span style="color:${confColor}">${confPct}%</span>
          </span>
        </div>`;
      }
      html += `</div>`;
    }
  } else { html += `<div style="color:var(--text2)">None detected</div>`; }
  html += `</div>`;

  // TLS Details
  html += `<div class="detail-section"><h3>TLS</h3>`;
  html += `<div class="kv"><span class="kv-key">Version</span><span class="kv-val">${tls.tls_version||'N/A'}</span></div>`;
  html += `<div class="kv"><span class="kv-key">Cipher</span><span class="kv-val">${tls.cipher||'N/A'}</span></div>`;
  html += `<div class="kv"><span class="kv-key">Issuer</span><span class="kv-val">${tls.issuer||'N/A'}</span></div>`;
  html += `<div class="kv"><span class="kv-key">Expires</span><span class="kv-val">${tls.not_after||'N/A'}</span></div>`;
  html += `<div class="kv"><span class="kv-key">Grade</span><span class="kv-val">${data.tls_grade||'N/A'}</span></div>`;
  html += `</div>`;

  // Attack Vectors
  if (vectors.length) {
    html += `<div class="detail-section" style="grid-column:1/-1"><h3>Attack Vectors (${vectors.length})</h3>`;
    html += `<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">
      <thead><tr><th style="padding:8px 12px">Severity</th><th style="padding:8px 12px">Type</th><th style="padding:8px 12px">Targets</th><th style="padding:8px 12px">Priority</th></tr></thead><tbody>`;
    for (const v of vectors.slice(0, 15)) {
      const sev = (v.severity||'info').toLowerCase();
      const label = v.type || v.name || '?';
      const targetCount = v.targets ? v.targets.length : '';
      html += `<tr>
        <td style="padding:6px 12px;border-bottom:1px solid var(--border)">${riskBadge(sev)}</td>
        <td style="padding:6px 12px;border-bottom:1px solid var(--border);font-size:12.5px">${label}</td>
        <td style="padding:6px 12px;border-bottom:1px solid var(--border);font-size:12px">${targetCount ? targetCount + ' targets' : ''}</td>
        <td style="padding:6px 12px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text2)">${v.count ? v.count+' issues' : v.priority||''}</td>
      </tr>`;
    }
    html += `</tbody></table></div></div>`;
  } else {
    html += `<div class="detail-section"><h3>Attack Vectors</h3><div style="color:var(--text2)">None found</div></div>`;
  }

  html += `</div>`; // close detail-grid before findings table

  // Findings — full-width table
  if (findings.length) {
    html += `<div class="section-title">Findings <span class="count">(${findings.length})</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Risk</th></tr></thead><tbody>`;
    for (const f of findings) {
      const sev = (f.severity||'info').toLowerCase();
      const catCls = f.category === 'infra' ? 'tag-infra' : f.category === 'config' ? 'tag-cdn' : f.category === 'app' ? 'tag-frontend' : f.category === 'data' ? 'tag-lang' : '';
      const riskVal = f.risk_score || 0;
      html += `<tr>
        <td>${riskBadge(sev)}</td>
        <td style="font-size:12.5px">${highlightFinding(f.finding||f.title||'?')}</td>
        <td><span class="tag ${catCls}">${f.category||'other'}</span></td>
        <td style="color:${riskColor(riskVal)};font-weight:600;font-family:var(--mono);font-size:12px">${riskVal}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  html += `<div class="detail-grid">`; // reopen detail-grid for remaining sections

  // DNS
  html += `<div class="detail-section"><h3>DNS</h3>`;
  const aRecords = dns.a || [];
  const aaaa = dns.aaaa || [];
  const mx = dns.mx || [];
  const ns = dns.ns || [];
  if (aRecords.length) html += `<div class="kv"><span class="kv-key">A</span><span class="kv-val">${aRecords.map(r => `<span class="hl-ip">${r}</span>`).join(', ')}</span></div>`;
  if (aaaa.length) html += `<div class="kv"><span class="kv-key">AAAA</span><span class="kv-val">${aaaa.map(r => `<span class="hl-ip">${r}</span>`).join(', ')}</span></div>`;
  if (mx.length) html += `<div class="kv"><span class="kv-key">MX</span><span class="kv-val">${mx.slice(0,3).map(r => `<span class="hl-zone">${r}</span>`).join(', ')}</span></div>`;
  if (ns.length) html += `<div class="kv"><span class="kv-key">NS</span><span class="kv-val">${ns.slice(0,3).map(r => `<span class="hl-zone">${r}</span>`).join(', ')}</span></div>`;
  if (dns.cdn_detected) html += `<div class="kv"><span class="kv-key">CDN</span><span class="kv-val">${dns.cdn_detected}</span></div>`;
  html += `</div>`;

  // CORS
  html += `<div class="detail-section"><h3>CORS</h3>`;
  if (cors.vulnerable) {
    html += `<div class="kv"><span class="kv-key">Status</span><span class="kv-val" style="color:var(--critical)">VULNERABLE</span></div>`;
    html += `<div class="kv"><span class="kv-key">Issue</span><span class="kv-val">${cors.issue||''}</span></div>`;
  } else {
    html += `<div style="color:var(--success)">Properly configured</div>`;
  }
  html += `</div>`;

  // Origin IP
  html += `<div class="detail-section"><h3>Origin IP</h3>`;
  if (originCandidates.length) {
    for (const c of originCandidates.slice(0, 5)) {
      const verified = c.verified ? '<span style="color:var(--critical)">VERIFIED</span>' : '<span style="color:var(--text2)">unverified</span>';
      html += `<div class="kv"><span class="kv-key"><span class="hl-ip">${c.ip||'?'}</span></span><span class="kv-val">${c.source||''} ${verified}</span></div>`;
    }
  } else { html += `<div style="color:var(--text2)">Not found</div>`; }
  html += `</div>`;

  // CT Monitor
  if (ct.total_recent) {
    html += `<div class="detail-section"><h3>CT Monitor</h3>`;
    html += `<div class="kv"><span class="kv-key">Recent Certs</span><span class="kv-val">${ct.total_recent}</span></div>`;
    html += `<div class="kv"><span class="kv-key">New Subdomains</span><span class="kv-val">${(ct.new_subdomains||[]).length}</span></div>`;
    html += `<div class="kv"><span class="kv-key">Wildcards</span><span class="kv-val">${(ct.wildcard_certs||[]).length}</span></div>`;
    html += `<div class="kv"><span class="kv-key">Alerts</span><span class="kv-val">${(ct.alerts||[]).length}</span></div>`;
    for (const a of (ct.alerts||[]).slice(0,5)) {
      html += `<div class="kv"><span class="kv-key">${riskBadge(a.severity)}</span><span class="kv-val">${highlightFinding(a.message)}</span></div>`;
    }
    html += `</div>`;
  }

  html += `</div>`; // close detail-grid

  // WAF Bypass Subdomains — security alert
  if (wafBypassSubs.length) {
    html += `<div class="section-title" style="color:var(--critical)">&#9888; Subdomains Bypassing WAF <span class="count" style="color:var(--critical)">(${wafBypassSubs.length})</span></div>`;
    html += `<div class="table-wrap" style="border-color:rgba(244,63,94,.2)"><table>
      <thead><tr><th>Subdomain</th><th>IPs (Direct Origin)</th><th>CDN</th><th>Bypass Reason</th></tr></thead><tbody>`;
    for (const s of wafBypassSubs) {
      html += `<tr>
        <td style="font-size:12px"><span class="hl-zone" style="color:var(--critical)">${s.subdomain||''}</span></td>
        <td style="font-size:11px">${(s.ips||[]).map(ip => `<span class="hl-ip">${ip}</span>`).join(', ')}</td>
        <td>${s.cdn ? `<span class="tag tag-cdn">${s.cdn}</span>` : '<span style="color:var(--critical);font-size:11px">None</span>'}</td>
        <td style="font-size:12px">${s.bypass_reason||''}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Active Subdomain Discovery
  if (discoveredSubs.length) {
    html += `<div class="section-title">Actively Discovered Subdomains <span class="count">(${discoveredSubs.length})</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Subdomain</th><th>IPs</th><th>CDN</th><th>WAF Status</th></tr></thead><tbody>`;
    for (const s of discoveredSubs.slice(0, 50)) {
      const wafStatus = s.bypasses_waf
        ? '<span class="badge badge-critical">BYPASSES WAF</span>'
        : (s.cdn ? '<span class="badge badge-low">Protected</span>' : '<span class="badge badge-medium">Unknown</span>');
      html += `<tr>
        <td style="font-size:12px"><span class="hl-zone">${s.subdomain||''}</span></td>
        <td style="font-size:11px">${(s.ips||[]).map(ip => `<span class="hl-ip">${ip}</span>`).join(', ')}</td>
        <td>${s.cdn ? `<span class="tag tag-cdn">${s.cdn}</span>` : ''}</td>
        <td>${wafStatus}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // All Subdomains (passive)
  if (allSubs.length) {
    html += `<div class="section-title">All Subdomains <span class="count">(${allSubs.length})</span></div>`;
    html += `<div class="table-wrap"><table><thead><tr><th>FQDN</th></tr></thead><tbody>`;
    const subList = allSubs.slice(0, 50);
    for (const s of subList) {
      const fqdn = typeof s === 'string' ? s : (s.fqdn || s.name || '');
      html += `<tr><td style="font-size:12px"><span class="hl-zone">${fqdn}</span></td></tr>`;
    }
    html += `</tbody></table></div>`;
    if (allSubs.length > 50) html += `<div style="color:var(--text2);font-size:12px;margin-top:-16px;margin-bottom:16px">... and ${allSubs.length-50} more</div>`;
  }

  // Exposed files
  if (exposedFound.length) {
    html += `<div class="section-title">Exposed Files <span class="count">(${exposedFound.length})</span></div>`;
    html += `<div class="table-wrap"><table><thead><tr><th>Path</th><th>Status</th><th>Size</th></tr></thead><tbody>`;
    for (const f of exposedFound.slice(0,20)) {
      html += `<tr><td style="font-family:var(--mono);font-size:12px">${f.path||''}</td><td>${f.status}</td><td>${f.length||''}</td></tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // ── Per-Domain Executive Summary ──────────────────────────────────

  const gapData = data.gap_analysis || {};
  const bypassStrats = gapData.bypass_strategies || [];
  const techMatrix = gapData.technique_matrix || [];
  const remediationList = attack.remediation || [];
  const riskSummary = gapData.risk_summary || '';
  const detGaps = gapData.detection_gaps || {};

  if (remediationList.length || bypassStrats.length || findings.length) {
    html += `<div class="section-title" style="margin-top:24px;border-top:1px solid var(--border);padding-top:20px">&#9998; Domain Executive Summary</div>`;

    // Risk narrative
    if (riskSummary) {
      const narColor = riskSummary.startsWith('HIGH') || riskSummary.startsWith('CRITICAL') ? 'var(--critical)' : riskSummary.startsWith('MEDIUM') ? 'var(--medium)' : 'var(--low)';
      html += `<div class="card" style="margin-bottom:16px;border-left:3px solid ${narColor}"><div class="card-label">Risk Assessment</div><div style="font-size:13px;margin-top:4px;color:var(--text)">${riskSummary}</div></div>`;
    }

    html += `<div class="detail-grid">`;

    // Remediation Plan
    if (remediationList.length) {
      html += `<div class="detail-section"><h3>Remediation Plan (${remediationList.length})</h3>`;
      for (const r of remediationList) {
        const sev = (r.severity||'medium').toLowerCase();
        html += `<div style="padding:8px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">${riskBadge(sev)} <span style="font-weight:600;font-size:12px">${r.action||''}</span></div>
          <div style="font-size:12.5px;color:var(--text2);margin-bottom:2px"><strong style="color:var(--text)">Why:</strong> ${r.why||''}</div>
          <div style="font-size:12.5px;color:var(--text);margin-bottom:2px"><strong>How:</strong> ${r.how||''}</div>
          <div style="font-size:12px"><span class="tag">${r.timeline||'TBD'}</span></div>
        </div>`;
      }
      html += `</div>`;
    }

    // WAF Bypass Strategies
    if (bypassStrats.length) {
      html += `<div class="detail-section"><h3>WAF Bypass Strategies (${bypassStrats.length})</h3>`;
      html += `<div style="margin-bottom:8px;font-size:11px;color:var(--text2)">WAF: ${gapData.waf_vendor||'Unknown'} | Mode: ${gapData.detection_mode||'?'}</div>`;
      for (const b of bypassStrats) {
        const confColor = b.confidence === 'high' ? 'var(--critical)' : b.confidence === 'medium' ? 'var(--medium)' : 'var(--text2)';
        html += `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-weight:600;font-size:12px">${b.technique||''}</span>
            <span style="color:${confColor};font-size:11px">${b.confidence||''}</span>
          </div>
          <div style="font-size:12.5px;color:var(--text2)">${b.description||''}</div>
          ${b.payload_example ? `<div style="font-family:var(--mono);font-size:11px;color:var(--accent);margin-top:4px">${b.payload_example}</div>` : ''}
        </div>`;
      }
      html += `</div>`;
    }

    // Detection Gaps
    const sigMisses = detGaps.signature_misses || [];
    const anomMisses = detGaps.anomaly_misses || [];
    if (sigMisses.length || anomMisses.length) {
      html += `<div class="detail-section"><h3>Detection Gaps</h3>`;
      if (sigMisses.length) {
        html += `<div style="margin-bottom:6px;font-size:11px;color:var(--text2)">Signature misses:</div>`;
        for (const m of sigMisses) {
          html += `<span class="tag" style="background:rgba(239,68,68,.1);color:var(--critical)">${m}</span> `;
        }
      }
      if (anomMisses.length) {
        html += `<div style="margin:8px 0 6px;font-size:11px;color:var(--text2)">Anomaly detection gaps:</div>`;
        for (const m of anomMisses) {
          html += `<span class="tag" style="background:rgba(234,179,8,.1);color:var(--medium)">${m}</span> `;
        }
      }
      html += `</div>`;
    }

    // Technique Matrix
    if (techMatrix.length) {
      html += `<div class="detail-section"><h3>Technique Matrix</h3>`;
      for (const t of techMatrix) {
        const statusColor = t.status === 'viable' ? 'var(--critical)' : t.status === 'blocked' ? 'var(--success)' : 'var(--text2)';
        const statusIcon = t.status === 'viable' ? '&#9888;' : t.status === 'blocked' ? '&#10004;' : '&#8226;';
        html += `<div class="kv"><span class="kv-key"><span style="color:${statusColor}">${statusIcon}</span> ${t.technique||''}</span><span class="kv-val" style="color:${statusColor}">${t.status||''}</span></div>`;
      }
      html += `</div>`;
    }

    html += `</div>`; // close detail-grid
  }

  $('#content').innerHTML = html;
}

async function renderLearned() {
  const data = await fetchJSON('/api/learned');
  let html = `<div class="section-title">&#9881; WAF Intel</div>`;

  // Explanation for new users
  html += `<div style="background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius);padding:18px 22px;margin-bottom:24px;box-shadow:var(--shadow-sm)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin-bottom:8px;font-weight:600">What is this?</div>
    <p style="color:var(--text);font-size:13px;line-height:1.65;margin:0">Fray's AI agent remembers every WAF interaction. When it tests payloads against a WAF (e.g. Cloudflare, AWS WAF), it records what was <strong style="color:var(--critical)">blocked</strong>, what <strong style="color:var(--success)">bypassed</strong>, and which mutation strategies worked. On future runs, the agent skips known-blocked payloads, prioritizes effective strategies, and retests previous bypasses &mdash; getting smarter over time.</p>
  </div>`;

  const vendors = Object.keys(data).filter(k => typeof data[k] === 'object' && k !== 'vendors');
  if (!vendors.length) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;text-align:center">
      <div style="font-size:15px;color:var(--text);margin-bottom:8px;font-weight:500">No WAF bypass data yet</div>
      <p style="color:var(--text2);font-size:13px;margin-bottom:16px;max-width:420px;margin-left:auto;margin-right:auto">The agent hasn't tested any WAFs yet. Run a bypass test against a target to start building the memory database.</p>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:inline-block;font-family:var(--mono);font-size:12px;color:var(--text)">fray agent https://target.com -c xss</div>
    </div>`;
    $('#content').innerHTML = html;
    return;
  }

  // Aggregate stats across vendors
  let totalRuns = 0, totalBlocked = 0, totalSuccess = 0, totalHashes = 0;
  for (const vendor of vendors) {
    const v = data[vendor];
    totalRuns += v.total_runs || 0;
    totalBlocked += v.total_blocked || 0;
    totalSuccess += (v.successful_payloads || []).length;
    totalHashes += (v.blocked_hashes || []).length;
  }

  html += `<div class="cards">
    <div class="card"><div class="card-label">WAF Vendors Tested</div><div class="card-value">${vendors.length}</div></div>
    <div class="card"><div class="card-label">Total Agent Runs</div><div class="card-value">${totalRuns}</div></div>
    <div class="card"><div class="card-label">Payloads Blocked</div><div class="card-value" style="color:var(--critical)">${totalBlocked}</div><div class="card-sub">${totalHashes} unique hashes memorized</div></div>
    <div class="card"><div class="card-label">Successful Bypasses</div><div class="card-value" style="color:var(--success)">${totalSuccess}</div></div>
  </div>`;

  html += `<div class="section-title">Per-WAF Breakdown</div>`;

  for (const vendor of vendors) {
    const v = data[vendor];
    const runs = v.total_runs || 0;
    const blocked = v.total_blocked || 0;
    const hashes = (v.blocked_hashes || []).length;
    const successes = (v.successful_payloads || []).length;
    const effStrats = v.effective_strategies || {};
    const failStrats = v.failed_strategies || {};

    html += `<div class="detail-section" style="margin-bottom:16px">
      <h3>${vendor}</h3>
      <div class="cards" style="margin-bottom:12px">
        <div class="card"><div class="card-label">Runs</div><div class="card-value" style="font-size:20px">${runs}</div></div>
        <div class="card"><div class="card-label">Blocked</div><div class="card-value" style="font-size:20px;color:var(--critical)">${blocked}</div></div>
        <div class="card"><div class="card-label">Memory</div><div class="card-value" style="font-size:20px">${hashes}</div><div class="card-sub">blocked hashes</div></div>
        <div class="card"><div class="card-label">Bypasses</div><div class="card-value" style="font-size:20px;color:var(--success)">${successes}</div></div>
      </div>`;

    if (Object.keys(effStrats).length) {
      html += `<div style="margin-bottom:8px"><div style="font-size:11px;color:var(--success);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:6px">Effective Strategies</div>`;
      const sorted = Object.entries(effStrats).sort((a,b) => b[1] - a[1]);
      for (const [strat, count] of sorted) {
        html += `<div class="kv"><span class="kv-key">${strat}</span><span class="kv-val" style="color:var(--success)">${count} success${count>1?'es':''}</span></div>`;
      }
      html += `</div>`;
    }

    if (Object.keys(failStrats).length) {
      html += `<div><div style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:6px">Deprioritized Strategies</div>`;
      const sorted = Object.entries(failStrats).sort((a,b) => (typeof b[1]==='number'?b[1]:0) - (typeof a[1]==='number'?a[1]:0));
      for (const [strat, count] of sorted.slice(0,8)) {
        html += `<div class="kv"><span class="kv-key" style="color:var(--text2);opacity:.7">${strat}</span><span class="kv-val" style="color:var(--text2);opacity:.7">${typeof count==='number'?count:''} failures</span></div>`;
      }
      html += `</div>`;
    }

    html += `</div>`;
  }

  // Payload Analytics section
  const analytics = await fetchJSON('/api/payload-analytics');
  const analyticsVendors = Object.keys(analytics);
  if (analyticsVendors.length) {
    html += `<div class="section-title" style="margin-top:8px">Payload Hit/Miss Analytics</div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>WAF Vendor</th><th>Bypass Rate</th><th>Bypassed</th><th>Blocked</th><th>Total Runs</th><th>Top Effective Strategy</th></tr></thead><tbody>`;
    for (const v of analyticsVendors) {
      const a = analytics[v];
      const rate = a.bypass_rate || 0;
      const rateColor = rate > 20 ? 'var(--critical)' : rate > 5 ? 'var(--high)' : rate > 0 ? 'var(--medium)' : 'var(--success)';
      const topStrat = (a.top_effective || [])[0];
      html += `<tr>
        <td><strong style="color:var(--text)">${v}</strong></td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="width:60px;height:5px;border-radius:3px;background:var(--bg);overflow:hidden"><div style="width:${Math.min(100,rate)}%;height:100%;background:${rateColor};border-radius:3px"></div></div>
            <span style="color:${rateColor};font-weight:600;font-family:var(--mono);font-size:12px">${rate}%</span>
          </div>
        </td>
        <td style="color:var(--success);font-weight:600">${a.total_bypassed||0}</td>
        <td style="color:var(--critical);font-weight:600">${a.total_blocked||0}</td>
        <td>${a.total_runs||0}</td>
        <td>${topStrat ? `<span class="tag tag-frontend">${topStrat[0]}</span> <span style="font-size:11px;color:var(--text2)">${topStrat[1]}x</span>` : '<span style="color:var(--text3)">None</span>'}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  $('#content').innerHTML = html;
}

async function renderIntel() {
  const data = await fetchJSON('/api/threat-intel');
  let html = `<div class="section-title">&#9889; CVE Feed &amp; Threat Intel</div>`;

  // Explanation for new users
  html += `<div style="background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);border:1px solid var(--border);border-left:3px solid var(--medium);border-radius:var(--radius);padding:18px 22px;margin-bottom:24px;box-shadow:var(--shadow-sm)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--medium);margin-bottom:8px;font-weight:600">What is this?</div>
    <p style="color:var(--text);font-size:13px;line-height:1.65;margin:0">Fray automatically monitors 6 threat intelligence sources (NVD, CISA, GitHub, ExploitDB, RSS, Nuclei) for new CVEs and exploit payloads. Discovered payloads are classified, deduplicated, and can be auto-tested against your targets to check if your WAF blocks them. This page shows what has been ingested so far.</p>
  </div>`;

  if (!data || !Object.keys(data).length) {
    html += `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;text-align:center">
      <div style="font-size:15px;color:var(--text);margin-bottom:8px;font-weight:500">No threat intel data yet</div>
      <p style="color:var(--text2);font-size:13px;margin-bottom:16px;max-width:460px;margin-left:auto;margin-right:auto">Fetch the latest CVEs and exploit payloads from public sources. Fray will classify them and optionally test them against your WAF.</p>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 16px;display:inline-block;font-family:var(--mono);font-size:12px;color:var(--text)">fray feed --since 7d --auto-add</div>
    </div>`;
    $('#content').innerHTML = html;
    return;
  }

  // Parse data
  const seenCves = data.seen_cves || [];
  const seenHashes = data.seen_hashes || [];
  const stats = data.stats || {};
  const lastFetch = data.last_fetch || {};
  const version = data.version || 1;

  // Last fetch time
  let lastFetchStr = 'Never';
  const fetchEntries = Object.entries(lastFetch);
  if (fetchEntries.length) {
    const [sources, ts] = fetchEntries[0];
    try {
      const d = new Date(ts);
      lastFetchStr = d.toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'}) + ' at ' + d.toLocaleTimeString('en-US', {hour:'2-digit', minute:'2-digit'});
    } catch(e) { lastFetchStr = String(ts).slice(0,16); }
  }

  // Summary cards
  html += `<div class="cards">
    <div class="card"><div class="card-label">Known CVEs</div><div class="card-value">${seenCves.length}</div><div class="card-sub">unique vulnerabilities tracked</div></div>
    <div class="card"><div class="card-label">Payloads Ingested</div><div class="card-value">${seenHashes.length}</div><div class="card-sub">${stats.total_fetched||0} fetched, ${stats.total_skipped||0} deduped</div></div>
    <div class="card"><div class="card-label">Last Fetch</div><div class="card-value" style="font-size:16px;color:var(--text)">${lastFetchStr}</div></div>
    <div class="card"><div class="card-label">Sources</div><div class="card-value">${fetchEntries.length ? fetchEntries[0][0].split(',').length : 0}</div><div class="card-sub">NVD, CISA, GitHub, ExploitDB, RSS, Nuclei</div></div>
  </div>`;

  // CVE list — grouped by year with tooltips
  if (seenCves.length) {
    // Fetch CVE metadata for tooltips
    const cveMeta = await fetchJSON('/api/cve-meta');

    function cveTag(cve) {
      const m = cveMeta[cve];
      const isGhsa = cve.startsWith('GHSA');
      const url = isGhsa ? `https://github.com/advisories/${cve}` : `https://nvd.nist.gov/vuln/detail/${cve}`;
      const cls = isGhsa ? 'tag tag-cms' : 'tag';
      // Severity color for the tag itself
      let tagStyle = 'font-family:var(--mono);cursor:pointer';
      if (m && m.cvss) {
        if (m.cvss >= 9) tagStyle += ';background:rgba(244,63,94,.15);color:var(--critical);border-color:rgba(244,63,94,.3)';
        else if (m.cvss >= 7) tagStyle += ';background:rgba(249,115,22,.12);color:var(--high);border-color:rgba(249,115,22,.25)';
        else if (m.cvss >= 4) tagStyle += ';background:rgba(234,179,8,.12);color:var(--medium);border-color:rgba(234,179,8,.25)';
        else tagStyle += ';background:rgba(59,130,246,.12);color:var(--low);border-color:rgba(59,130,246,.25)';
      } else {
        tagStyle += '';
      }
      if (m && m.description) {
        const cvssColor = m.cvss >= 9 ? 'background:var(--critical);color:#fff' : m.cvss >= 7 ? 'background:var(--high);color:#fff' : m.cvss >= 4 ? 'background:var(--medium);color:#000' : 'background:var(--low);color:#fff';
        const types = (m.types||[]).filter(Boolean).map(t => t.replace(/_/g,' ')).join(', ');
        return `<span class="tip ${cls}" style="${tagStyle}" onclick="window.open('${url}','_blank')">
          ${cve}
          <span class="tiptext">
            <strong>${cve}</strong>${m.cvss ? `<span class="tip-cvss" style="${cvssColor}">CVSS ${m.cvss}</span>` : ''}<br>
            ${m.description}${types ? `<br><span style="color:var(--text2);font-size:11px">Type: ${types}</span>` : ''}${m.software ? `<br><span style="color:var(--text2);font-size:11px">Affects: ${m.software}</span>` : ''}
          </span>
        </span>`;
      }
      return `<span class="${cls}" style="${tagStyle}" onclick="window.open('${url}','_blank')" title="Click to view on ${isGhsa?'GitHub':'NVD'}">${cve}</span>`;
    }

    // Classify
    const byYear = {};
    for (const cve of seenCves) {
      if (cve.startsWith('GHSA')) {
        if (!byYear['GitHub']) byYear['GitHub'] = [];
        byYear['GitHub'].push(cve);
        continue;
      }
      const year = cve.split('-')[1] || 'Unknown';
      if (!byYear[year]) byYear[year] = [];
      byYear[year].push(cve);
    }
    const sortedYears = Object.keys(byYear).filter(y=>y!=='GitHub').sort((a,b) => parseInt(b) - parseInt(a));
    if (byYear['GitHub']) sortedYears.push('GitHub');

    html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div class="section-title" style="margin-bottom:0">Tracked CVEs <span class="count">(${seenCves.length})</span></div>
      <button class="btn" onclick="navigator.clipboard.writeText('${seenCves.join('\\n')}');showToast('${seenCves.length} CVE IDs copied')">&#128203; Copy All</button>
    </div>`;

    html += `<div class="table-wrap"><table>
      <thead><tr><th>Source</th><th>Count</th><th>CVE IDs <span style="font-weight:400;text-transform:none;letter-spacing:0">(hover for details, click to open)</span></th></tr></thead><tbody>`;
    for (const year of sortedYears) {
      const cves = byYear[year];
      const yearColor = year === 'GitHub' ? 'var(--accent)' : parseInt(year) >= 2026 ? 'var(--critical)' : parseInt(year) >= 2025 ? 'var(--high)' : 'var(--text2)';
      html += `<tr>
        <td style="font-weight:600;color:${yearColor};white-space:nowrap">${year}</td>
        <td style="font-weight:600">${cves.length}</td>
        <td style="line-height:2.2">${cves.map(c => cveTag(c)).join(' ')}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Pipeline stats
  if (stats.total_fetched) {
    html += `<div class="section-title" style="margin-top:24px">Ingestion Pipeline</div>`;
    html += `<div class="detail-grid"><div class="detail-section">
      <h3>Pipeline Stats</h3>
      <div class="kv"><span class="kv-key">Total Fetched</span><span class="kv-val">${stats.total_fetched||0}</span></div>
      <div class="kv"><span class="kv-key">Added to Database</span><span class="kv-val" style="color:var(--success)">${stats.total_added||0}</span></div>
      <div class="kv"><span class="kv-key">Skipped (duplicates)</span><span class="kv-val">${stats.total_skipped||0}</span></div>
      <div class="kv"><span class="kv-key">Dedup Rate</span><span class="kv-val">${stats.total_fetched ? Math.round(stats.total_skipped / stats.total_fetched * 100) : 0}%</span></div>
    </div>
    <div class="detail-section">
      <h3>Next Steps</h3>
      <div style="font-size:13px;color:var(--text);line-height:1.65">
        <p style="margin-bottom:10px">To auto-test ingested payloads against a WAF target:</p>
        <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:11.5px;color:var(--text);margin-bottom:10px">fray feed --since 7d --auto-add --test-target https://target.com</div>
        <p style="margin:0;color:var(--text2);font-size:12px">This fetches new CVEs, ingests payloads, and tests them against your WAF to verify coverage.</p>
      </div>
    </div></div>`;
  }

  $('#content').innerHTML = html;
}

// ── Executive Summary ──────────────────────────────────────────────────

async function renderExecutive() {
  const s = await fetchJSON('/api/executive-summary');

  let html = `<div class="section-title">&#9998; Executive Summary</div>`;

  // Executive narrative — security consultant tone
  const sev = s.finding_severity || {};
  const cve = s.cve_stats || {};
  const p = s.posture || {};
  const critCount = (s.critical_domains||[]).length;

  let narrative = `Across <strong>${s.total_domains} domains</strong> assessed, we identified <strong style="color:var(--critical)">${s.total_findings||0} security findings</strong> — including <strong style="color:var(--critical)">${sev.critical||0} critical</strong> and <strong style="color:var(--high)">${sev.high||0} high-severity</strong> issues requiring immediate attention. `;
  if (cve.total_cves > 0) {
    narrative += `Frontend dependency analysis uncovered <strong style="color:var(--high)">${cve.total_cves} known CVEs</strong> across <strong>${cve.vulnerable_libs||0} vulnerable libraries</strong>`;
    if (cve.critical_cves > 0) narrative += `, of which <strong style="color:var(--critical)">${cve.critical_cves} are critical-severity</strong>`;
    narrative += `. `;
  }
  if (cve.waf_bypass_domains > 0) {
    narrative += `WAF bypass exposure is significant: <strong style="color:var(--critical)">${cve.waf_bypass_domains} domains</strong> have subdomains that resolve outside their WAF/CDN perimeter, allowing unfiltered access to origin servers. `;
  }
  if (cve.takeover_domains > 0) {
    narrative += `<strong style="color:var(--critical)">${cve.takeover_domains} domain(s)</strong> have subdomains vulnerable to takeover via dangling DNS records. `;
  }
  if (p.csp_missing > s.total_domains * 0.5) {
    const pct = Math.round(p.csp_missing / s.total_domains * 100);
    narrative += `A systemic gap exists in Content Security Policy deployment — <strong>${pct}% of domains</strong> lack CSP headers, leaving them exposed to XSS and data injection attacks. `;
  }
  if (p.origin_ip_exposed > 0) {
    narrative += `Origin IP addresses were identified for <strong>${p.origin_ip_exposed} domains</strong>, enabling potential direct-to-origin attacks bypassing all edge security controls.`;
  }

  html += `<div style="background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);border:1px solid var(--border);border-left:3px solid var(--brand);border-radius:var(--radius);padding:20px 24px;margin-bottom:24px;box-shadow:var(--shadow-sm)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--brand2);margin-bottom:10px;font-weight:600">Security Assessment Overview</div>
    <p style="color:var(--text);font-size:13.5px;line-height:1.7;margin:0">${narrative}</p>
  </div>`;

  // Risk posture cards
  html += `<div class="cards">
    <div class="card"><div class="card-label">Avg Risk Score</div><div class="card-value" style="color:${riskColor(s.avg_risk||0)}">${s.avg_risk||0}/100</div>${riskBar(s.avg_risk||0)}</div>
    <div class="card"><div class="card-label">Total Findings</div><div class="card-value">${s.total_findings||0}</div>
      <div class="card-sub" style="margin-top:4px">
        <span style="color:var(--critical)">${sev.critical||0} crit</span> &middot;
        <span style="color:var(--high)">${sev.high||0} high</span> &middot;
        <span style="color:var(--medium)">${sev.medium||0} med</span> &middot;
        <span style="color:var(--low)">${sev.low||0} low</span>
      </div>
    </div>
    <div class="card"><div class="card-label">Attack Vectors</div><div class="card-value">${s.total_vectors||0}</div></div>
    <div class="card"><div class="card-label">Remediation Actions</div><div class="card-value">${s.total_remediation||0}</div></div>
  </div>`;

  // Security Posture (p already declared above)
  html += `<div class="section-title" style="margin-top:8px">Security Posture Gaps</div>`;
  html += `<div class="cards">
    <div class="card"><div class="card-label">Missing CSP</div><div class="card-value" style="color:${p.csp_missing > s.total_domains*0.5 ? 'var(--critical)' : 'var(--medium)'}">${p.csp_missing}</div><div class="card-sub">of ${s.total_domains} domains</div></div>
    <div class="card"><div class="card-label">Clickjacking Vuln</div><div class="card-value" style="color:${p.clickjacking_vulnerable > 10 ? 'var(--high)' : 'var(--medium)'}">${p.clickjacking_vulnerable}</div></div>
    <div class="card"><div class="card-label">CORS Misconfigured</div><div class="card-value" style="color:${p.cors_vulnerable > 0 ? 'var(--critical)' : 'var(--success)'}">${p.cors_vulnerable}</div></div>
    <div class="card"><div class="card-label">Origin IP Exposed</div><div class="card-value" style="color:${p.origin_ip_exposed > 0 ? 'var(--critical)' : 'var(--success)'}">${p.origin_ip_exposed}</div></div>
  </div>`;

  // Critical Domains
  const cd = s.critical_domains || [];
  if (cd.length) {
    html += `<div class="section-title">Critical Risk Domains <span class="count">(${cd.length})</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Domain</th><th>Risk</th><th>Score</th><th>WAF</th><th>CDN</th></tr></thead><tbody>`;
    for (const d of cd) {
      html += `<tr style="cursor:pointer" onclick="navigate('detail','${d.domain}')">
        <td><a href="#" onclick="event.preventDefault();navigate('detail','${d.domain}')">${d.domain}</a></td>
        <td>${riskBadge(d.risk_level)}</td>
        <td style="color:${riskColor(d.risk_score)};font-weight:600">${d.risk_score}</td>
        <td>${d.waf ? `<span class="tag">${d.waf}</span>` : ''}</td>
        <td>${d.cdn ? `<span class="tag">${d.cdn}</span>` : ''}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Critical Findings — proper table (full width)
  const cf = s.critical_findings || [];
  if (cf.length) {
    html += `<div class="section-title">Critical &amp; High Findings <span class="count">(${cf.length})</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Domain</th></tr></thead><tbody>`;
    for (const f of cf.slice(0, 20)) {
      const sev = (f.severity||'info').toLowerCase();
      const catCls = f.category === 'infra' ? 'tag-infra' : f.category === 'config' ? 'tag-cdn' : f.category === 'app' ? 'tag-frontend' : f.category === 'data' ? 'tag-lang' : '';
      html += `<tr>
        <td>${riskBadge(sev)}</td>
        <td style="font-size:12.5px">${highlightFinding(f.finding||f.title||'')}</td>
        <td><span class="tag ${catCls}">${f.category||'other'}</span></td>
        <td><a href="#" onclick="event.preventDefault();navigate('detail','${f.domain}')">${f.domain}</a></td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  html += `<div class="detail-grid">`;

  // Finding Categories — with bars
  const cats = s.top_categories || [];
  if (cats.length) {
    html += `<div class="detail-section"><h3>Finding Categories</h3>`;
    for (const [cat, count] of cats) {
      const pct = Math.round(count / (s.total_findings||1) * 100);
      html += `<div class="kv"><span class="kv-key">${cat}</span><span class="kv-val" style="display:flex;align-items:center;gap:8px"><span style="width:60px;height:4px;border-radius:2px;background:var(--bg);overflow:hidden;display:inline-block"><span style="width:${pct}%;height:100%;background:var(--accent);display:block;border-radius:2px"></span></span><span>${count} (${pct}%)</span></span></div>`;
    }
    html += `</div>`;
  }

  // Attack Vector Types — with bars
  const vecs = s.top_vectors || [];
  if (vecs.length) {
    html += `<div class="detail-section"><h3>Attack Vector Types</h3>`;
    const maxVec = Math.max(...vecs.map(v=>v[1]));
    for (const [vtype, count] of vecs) {
      const pct = Math.round(count / maxVec * 100);
      html += `<div class="kv"><span class="kv-key">${vtype}</span><span class="kv-val" style="display:flex;align-items:center;gap:8px"><span style="width:60px;height:4px;border-radius:2px;background:var(--bg);overflow:hidden;display:inline-block"><span style="width:${pct}%;height:100%;background:var(--brand2);display:block;border-radius:2px"></span></span><span>${count} domains</span></span></div>`;
    }
    html += `</div>`;
  }

  // WAF Vendors — with bars
  const wafs = s.waf_vendors || [];
  if (wafs.length) {
    html += `<div class="detail-section"><h3>WAF Distribution</h3>`;
    for (const [waf, count] of wafs) {
      const pct = Math.round(count / s.total_domains * 100);
      html += `<div class="kv"><span class="kv-key">${techTag(waf)}</span><span class="kv-val" style="display:flex;align-items:center;gap:8px"><span style="width:60px;height:4px;border-radius:2px;background:var(--bg);overflow:hidden;display:inline-block"><span style="width:${pct}%;height:100%;background:var(--success);display:block;border-radius:2px"></span></span><span>${count} (${pct}%)</span></span></div>`;
    }
    html += `</div>`;
  }

  html += `</div>`; // close detail-grid

  // WAF Bypass Techniques
  const bp = s.top_bypass_techniques || [];
  if (bp.length) {
    html += `<div class="section-title">WAF Bypass Techniques <span class="count">(${bp.length})</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Technique</th><th>Confidence</th><th>Affected WAFs</th><th>Count</th><th>Example Payload</th></tr></thead><tbody>`;
    for (const b of bp) {
      const confColor = b.confidence === 'high' ? 'var(--critical)' : b.confidence === 'medium' ? 'var(--medium)' : 'var(--text2)';
      html += `<tr>
        <td style="font-weight:600">${b.technique}</td>
        <td><span style="color:${confColor}">${b.confidence}</span></td>
        <td>${(b.wafs||[]).map(w=>`<span class="tag">${w}</span>`).join(' ')}</td>
        <td>${b.count}</td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text2)">${(b.payload_example||'').slice(0,40)}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Remediation Plan — with detail steps
  const rem = s.top_remediation || [];
  if (rem.length) {
    html += `<div class="section-title">Remediation Plan <span class="count">(${rem.length} actions)</span></div>`;
    for (const r of rem) {
      const tlColor = r.timeline === 'Immediate' ? 'var(--critical)' : r.timeline === 'Short-term' ? 'var(--high)' : 'var(--medium)';
      const domainList = (r.domains||[]).slice(0, 5);
      html += `<div style="background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;margin-bottom:12px;box-shadow:var(--shadow-sm)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          ${riskBadge(r.severity)}
          <span style="font-weight:600;font-size:14px">${r.action}</span>
          <span class="tag" style="color:${tlColor};border-color:${tlColor}">${r.timeline||'TBD'}</span>
          <span style="font-size:12px;color:var(--text2);margin-left:auto">${r.count} domain${r.count>1?'s':''}</span>
        </div>
        <div style="font-size:12.5px;color:var(--text2);margin-bottom:8px"><strong style="color:var(--text)">Why:</strong> ${r.why||''}</div>
        <div style="font-size:12.5px;color:var(--text);margin-bottom:8px"><strong>How:</strong> ${r.how||'Consult vendor documentation for implementation details.'}</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">${domainList.map(d => `<a href="#" onclick="event.preventDefault();navigate('detail','${d}')" class="tag tag-infra" style="cursor:pointer">${d}</a>`).join('')}${(r.domains||[]).length > 5 ? `<span class="tag">+${r.domains.length - 5} more</span>` : ''}</div>
      </div>`;
    }
  }

  $('#content').innerHTML = html;
}

// ── Timeline View ────────────────────────────────────────────────────

async function renderTimeline(domain) {
  const c = $('#content');
  if (!domain) {
    // Domain picker
    const domains = await fetchJSON('/api/domains');
    let html = '<div class="section-title">Timeline <span class="count">Select a domain</span></div>';
    if (!domains.length) { c.innerHTML = '<div class="loading">No domains found. Run <code>fray recon</code> first.</div>'; return; }
    html += '<div class="table-wrap"><table><thead><tr><th>Domain</th><th>Risk</th><th>Grade</th><th>Scans</th><th></th></tr></thead><tbody>';
    for (const d of domains) {
      html += `<tr style="cursor:pointer" onclick="navigate('timeline','${d.domain}')">
        <td><a href="#" onclick="event.preventDefault();navigate('timeline','${d.domain}')">${d.domain}</a></td>
        <td>${d.risk_score}</td>
        <td><span class="grade-badge grade-${(d.grade||'c').toLowerCase()}">${d.grade||'?'}</span></td>
        <td>${d.scan_count||0}</td>
        <td style="text-align:right"><button class="btn-xs primary" onclick="event.stopPropagation();navigate('timeline','${d.domain}')">View timeline</button></td>
      </tr>`;
    }
    html += '</tbody></table></div>';
    c.innerHTML = html;
    return;
  }

  c.innerHTML = '<div class="loading">Loading timeline...</div>';
  const tl = await fetchJSON(`/api/timeline/${domain}`);
  let html = `<div class="breadcrumb"><a href="#" onclick="event.preventDefault();navigate('timeline')">Timeline</a> / <strong>${domain}</strong></div>`;
  html += `<div class="section-title">${domain} <span class="count">(${tl.length} runs)</span></div>`;

  if (!tl.length) {
    html += '<div class="loading">No runs found for this domain.</div>';
    c.innerHTML = html;
    return;
  }

  // Command type icons
  const cmdIcon = {recon:'\u{1f50d}',test:'\u{1f9ea}',scan:'\u{1f50e}',bypass:'\u{1f6e1}',agent:'\u{1f916}',smuggle:'\u26a0',crawl:'\u{1f578}',go:'\u{1f680}',compare:'\u2194'};

  // Summary cards
  const cmdCounts = {};
  tl.forEach(e => { const c = e.command||'unknown'; cmdCounts[c] = (cmdCounts[c]||0)+1; });
  html += '<div class="cards">';
  for (const [cmd, cnt] of Object.entries(cmdCounts).sort((a,b)=>b[1]-a[1])) {
    html += `<div class="card"><div class="card-label">${cmdIcon[cmd]||'\u25cf'} ${cmd}</div><div class="card-value">${cnt}</div><div class="card-sub">run${cnt>1?'s':''}</div></div>`;
  }
  html += '</div>';

  // Timeline table
  html += '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Command</th><th>Key Metrics</th><th>Actions</th></tr></thead><tbody>';
  for (const e of tl) {
    let metrics = '';
    if (e.risk_score !== undefined) metrics += `Risk: <strong>${e.risk_score}</strong> &middot; `;
    if (e.findings !== undefined) metrics += `Findings: ${e.findings} &middot; `;
    if (e.vectors !== undefined) metrics += `Vectors: ${e.vectors} &middot; `;
    if (e.subdomains !== undefined) metrics += `Subs: ${e.subdomains} &middot; `;
    if (e.total !== undefined) metrics += `Total: ${e.total} &middot; `;
    if (e.blocked !== undefined) metrics += `Blocked: ${e.blocked} &middot; `;
    if (e.passed !== undefined) metrics += `Passed: ${e.passed} &middot; `;
    if (e.bypasses !== undefined) metrics += `Bypasses: ${e.bypasses} &middot; `;
    if (e.total_payloads !== undefined) metrics += `Payloads: ${e.total_payloads} &middot; `;
    if (e.vulnerable !== undefined) metrics += `Vulnerable: ${e.vulnerable?'Yes':'No'} &middot; `;
    if (e.pages_crawled !== undefined) metrics += `Pages: ${e.pages_crawled} &middot; `;
    if (e.total_endpoints !== undefined) metrics += `Endpoints: ${e.total_endpoints} &middot; `;
    if (e.rounds !== undefined && e.rounds) metrics += `Rounds: ${e.rounds} &middot; `;
    metrics = metrics.replace(/ &middot; $/, '');

    const icon = cmdIcon[e.command] || '\u25cf';
    html += `<tr>
      <td style="white-space:nowrap;font-size:12px;color:var(--text2)">${timeAgo(e.timestamp)}<br><span style="font-size:10px;font-family:var(--mono)">${(e.timestamp||'').slice(0,19)}</span></td>
      <td><span class="badge badge-info">${icon} ${e.command}</span></td>
      <td style="font-size:12px">${metrics || '<span style="color:var(--text3)">—</span>'}</td>
      <td><button class="btn-xs" onclick="_diffSelect('${domain}','${e.file}','${e.subdir}')">Select for diff</button></td>
    </tr>`;
  }
  html += '</tbody></table></div>';

  // Diff selection UI
  html += `<div id="diff-bar" style="display:none;position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--bg-elevated);border:1px solid var(--brand);border-radius:10px;padding:12px 20px;box-shadow:var(--shadow-lg);z-index:100;display:flex;align-items:center;gap:12px">
    <span style="font-size:12px;color:var(--text2)">Selected: <strong id="diff-sel-a" style="color:var(--brand2)">—</strong> vs <strong id="diff-sel-b" style="color:var(--brand2)">—</strong></span>
    <button class="btn btn-brand" id="diff-go-btn" onclick="_launchDiff('${domain}')" disabled>Compare</button>
    <button class="btn" onclick="_diffClear()">Clear</button>
  </div>`;

  c.innerHTML = html;
  _diffClear(); // Reset diff bar initially hidden
}

// Diff selection state
let _diffFileA = '', _diffFileB = '', _diffSubdirA = '', _diffSubdirB = '';
function _diffSelect(domain, file, subdir) {
  if (!_diffFileA) {
    _diffFileA = file; _diffSubdirA = subdir;
    const bar = document.getElementById('diff-bar');
    if (bar) { bar.style.display = 'flex'; }
    const a = document.getElementById('diff-sel-a');
    if (a) a.textContent = file;
    showToast('First run selected. Pick a second run to compare.');
  } else if (!_diffFileB && file !== _diffFileA) {
    _diffFileB = file; _diffSubdirB = subdir;
    const b = document.getElementById('diff-sel-b');
    if (b) b.textContent = file;
    const btn = document.getElementById('diff-go-btn');
    if (btn) btn.disabled = false;
    showToast('Two runs selected. Click Compare.');
  }
}
function _diffClear() {
  _diffFileA = ''; _diffFileB = ''; _diffSubdirA = ''; _diffSubdirB = '';
  const bar = document.getElementById('diff-bar');
  if (bar) bar.style.display = 'none';
}
function _launchDiff(domain) {
  if (_diffFileA && _diffFileB) {
    navigate('diff', `${domain}|${_diffFileA}|${_diffFileB}`);
  }
}

// ── Diff View ────────────────────────────────────────────────────────

async function renderDiff(arg) {
  const c = $('#content');

  if (!arg || !arg.includes('|')) {
    // Domain picker — same as timeline but redirect to timeline for selection
    const domains = await fetchJSON('/api/domains');
    let html = '<div class="section-title">Diff Runs <span class="count">Select a domain to pick runs</span></div>';
    html += '<p style="color:var(--text2);font-size:13px;margin-bottom:18px">Go to a domain\'s timeline to select two runs for comparison.</p>';
    if (!domains.length) { c.innerHTML = '<div class="loading">No domains found.</div>'; return; }
    html += '<div class="table-wrap"><table><thead><tr><th>Domain</th><th>Risk</th><th>Scans</th><th></th></tr></thead><tbody>';
    for (const d of domains) {
      html += `<tr style="cursor:pointer" onclick="navigate('timeline','${d.domain}')">
        <td>${d.domain}</td><td>${d.risk_score}</td><td>${d.scan_count||0}</td>
        <td style="text-align:right"><button class="btn-xs primary" onclick="event.stopPropagation();navigate('timeline','${d.domain}')">Pick runs</button></td>
      </tr>`;
    }
    html += '</tbody></table></div>';
    c.innerHTML = html;
    return;
  }

  // Parse arg: domain|fileA|fileB
  const parts = arg.split('|');
  const domain = parts[0], fileA = parts[1], fileB = parts[2];
  c.innerHTML = '<div class="loading">Computing diff...</div>';
  const diff = await fetchJSON(`/api/diff/${domain}?a=${encodeURIComponent(fileA)}&b=${encodeURIComponent(fileB)}`);

  if (diff.error) { c.innerHTML = `<div class="loading" style="color:var(--critical)">${diff.error}</div>`; return; }

  let html = `<div class="breadcrumb"><a href="#" onclick="event.preventDefault();navigate('timeline','${domain}')">Timeline: ${domain}</a> / <strong>Diff</strong></div>`;
  html += `<div class="section-title">Diff: ${domain}</div>`;

  const a = diff.a || {}, b = diff.b || {}, deltas = diff.deltas || {};

  // Side-by-side summary cards
  html += '<div class="detail-grid">';
  html += `<div class="detail-section"><h3>Run A: ${fileA}</h3>`;
  html += `<div class="kv"><span class="kv-key">Timestamp</span><span>${a.timestamp||'—'}</span></div>`;
  if (a.risk_score !== undefined) html += `<div class="kv"><span>Risk Score</span><span style="color:${riskColor(a.risk_score)}">${a.risk_score}</span></div>`;
  if (a.grade) html += `<div class="kv"><span>Grade</span><span class="grade-badge grade-${a.grade.toLowerCase()}">${a.grade}</span></div>`;
  if (a.finding_count !== undefined) html += `<div class="kv"><span>Findings</span><span>${a.finding_count}</span></div>`;
  if (a.vector_count !== undefined) html += `<div class="kv"><span>Vectors</span><span>${a.vector_count}</span></div>`;
  if (a.subdomains !== undefined) html += `<div class="kv"><span>Subdomains</span><span>${a.subdomains}</span></div>`;
  if (a.waf) html += `<div class="kv"><span>WAF</span><span class="waf-chip">${a.waf}</span></div>`;
  html += '</div>';

  html += `<div class="detail-section"><h3>Run B: ${fileB}</h3>`;
  html += `<div class="kv"><span class="kv-key">Timestamp</span><span>${b.timestamp||'—'}</span></div>`;
  if (b.risk_score !== undefined) html += `<div class="kv"><span>Risk Score</span><span style="color:${riskColor(b.risk_score)}">${b.risk_score}</span></div>`;
  if (b.grade) html += `<div class="kv"><span>Grade</span><span class="grade-badge grade-${b.grade.toLowerCase()}">${b.grade}</span></div>`;
  if (b.finding_count !== undefined) html += `<div class="kv"><span>Findings</span><span>${b.finding_count}</span></div>`;
  if (b.vector_count !== undefined) html += `<div class="kv"><span>Vectors</span><span>${b.vector_count}</span></div>`;
  if (b.subdomains !== undefined) html += `<div class="kv"><span>Subdomains</span><span>${b.subdomains}</span></div>`;
  if (b.waf) html += `<div class="kv"><span>WAF</span><span class="waf-chip">${b.waf}</span></div>`;
  html += '</div></div>';

  // Delta summary
  html += '<div class="section-title">Changes</div>';
  html += '<div class="cards">';
  if (deltas.risk_score !== undefined) {
    const d = deltas.risk_score;
    const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'delta-neutral';
    html += `<div class="card"><div class="card-label">Risk Score</div><div class="card-value ${cls}">${d>0?'+':''}${d}</div></div>`;
  }
  if (deltas.findings !== undefined) {
    const d = deltas.findings;
    const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'delta-neutral';
    html += `<div class="card"><div class="card-label">Findings</div><div class="card-value ${cls}">${d>0?'+':''}${d}</div></div>`;
  }
  if (deltas.vectors !== undefined) {
    const d = deltas.vectors;
    const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'delta-neutral';
    html += `<div class="card"><div class="card-label">Vectors</div><div class="card-value ${cls}">${d>0?'+':''}${d}</div></div>`;
  }
  if (deltas.subdomains !== undefined) {
    const d = deltas.subdomains;
    html += `<div class="card"><div class="card-label">Subdomains</div><div class="card-value">${d>0?'+':''}${d}</div></div>`;
  }
  if (deltas.waf_changed) {
    html += `<div class="card"><div class="card-label">WAF</div><div class="card-value" style="font-size:14px">${a.waf||'None'} \u2192 ${b.waf||'None'}</div></div>`;
  }
  html += '</div>';

  // New findings
  const nf = deltas.new_findings || [];
  if (nf.length) {
    html += `<div class="section-title" style="color:var(--critical)">New Findings <span class="count">(${nf.length})</span></div>`;
    html += '<div class="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Category</th></tr></thead><tbody>';
    for (const f of nf) {
      html += `<tr><td>${highlightFinding(f.finding)}</td><td>${riskBadge(f.severity)}</td><td><span class="tag">${f.category||''}</span></td></tr>`;
    }
    html += '</tbody></table></div>';
  }

  // Resolved findings
  const rf = deltas.resolved_findings || [];
  if (rf.length) {
    html += `<div class="section-title" style="color:var(--success)">Resolved Findings <span class="count">(${rf.length})</span></div>`;
    html += '<div class="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th></tr></thead><tbody>';
    for (const f of rf) {
      html += `<tr><td style="text-decoration:line-through;opacity:.6">${f.finding}</td><td>${riskBadge(f.severity)}</td></tr>`;
    }
    html += '</tbody></table></div>';
  }

  // Tech changes
  const nt = deltas.new_techs || [], rt = deltas.removed_techs || [];
  if (nt.length || rt.length) {
    html += '<div class="section-title">Technology Changes</div><div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px">';
    for (const t of nt) html += `<span class="tag" style="border-color:var(--success);color:var(--success)">+ ${t}</span>`;
    for (const t of rt) html += `<span class="tag" style="border-color:var(--critical);color:var(--critical);text-decoration:line-through">\u2212 ${t}</span>`;
    html += '</div>';
  }

  c.innerHTML = html;
  _diffClear();
}

// ── SSE Live Reload ──────────────────────────────────────────────────

let _evtSource = null;
let _liveIndicator = null;

function initSSE() {
  if (_evtSource) return;
  try {
    _evtSource = new EventSource('/api/events');
    _evtSource.addEventListener('connected', () => {
      _setLiveStatus(true);
    });
    _evtSource.addEventListener('file_change', (e) => {
      try {
        const data = JSON.parse(e.data);
        showToast(`\u{1f504} ${data.type}: ${data.subdir}/${data.file}`);
        // Auto-refresh current page if relevant
        const cur = _currentPage;
        if (cur === 'overview') renderOverview();
        else if (cur === 'findings') renderFindings();
        else if (cur === 'targets') renderTargets();
        else if (cur === 'history') renderHistory();
        else if (cur === 'domains') renderDomains();
        else if (cur === 'detail' && _currentArg === data.domain) renderDetail(data.domain);
        else if (cur === 'timeline' && _currentArg === data.domain) renderTimeline(data.domain);
      } catch(err) {}
    });
    _evtSource.onerror = () => {
      _setLiveStatus(false);
      // Reconnect after 5s
      setTimeout(() => { if (_evtSource) { _evtSource.close(); _evtSource = null; } initSSE(); }, 5000);
    };
  } catch(e) {}
}

function _setLiveStatus(connected) {
  const dot = document.getElementById('live-dot');
  if (dot) {
    dot.className = connected ? 'scan-dot scan-dot-live' : 'scan-dot scan-dot-idle';
    dot.title = connected ? 'Live — watching ~/.fray/' : 'Disconnected';
  }
}

// ── Router ────────────────────────────────────────────────────────────

function navigate(page, arg) {
  _currentPage = page || 'overview';
  _currentArg = arg || '';

  // Update nav
  $$('.nav-item').forEach(n => n.classList.remove('active'));
  const navItem = $(`.nav-item[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');

  // Update toolbar + URL hash
  updateToolbar();
  updateHash(page, arg);

  // Render
  switch(page) {
    case 'overview': renderOverview(); break;
    case 'findings': renderFindings(); break;
    case 'targets': renderTargets(); break;
    case 'history': renderHistory(); break;
    case 'executive': renderExecutive(); break;
    case 'domains': renderDomains(); break;
    case 'detail': renderDetail(arg); break;
    case 'learned': renderLearned(); break;
    case 'intel': renderIntel(); break;
    case 'timeline': renderTimeline(arg); break;
    case 'diff': renderDiff(arg); break;
    default: renderOverview();
  }
}

// ── Toolbar ───────────────────────────────────────────────────────────

let _currentPage = 'overview';
let _currentArg = '';

function updateToolbar() {
  const tb = document.getElementById('toolbar');
  const pageTitle = {
    overview: 'Overview',
    findings: 'Findings',
    targets: 'Targets',
    history: 'Scan History',
    executive: 'Executive Report',
    domains: 'All Domains',
    detail: _currentArg || 'Domain Detail',
    learned: 'WAF Intel',
    intel: 'CVE Feed',
    timeline: _currentArg ? `Timeline: ${_currentArg}` : 'Timeline',
    diff: 'Diff Runs',
  }[_currentPage] || 'Dashboard';

  tb.innerHTML = `
    <div style="font-size:12px;color:var(--text)">&#9876; Fray <span style="color:var(--text2)">/</span> ${pageTitle}</div>
    <div class="toolbar-actions">
      <button class="btn" onclick="copyShareLink()" title="Copy shareable link">
        &#128279; Share Link
      </button>
      <button class="btn" onclick="downloadJSON()" title="Download page data as JSON">
        &#128230; JSON
      </button>
    </div>
  `;
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

function copyShareLink() {
  const url = window.location.origin + window.location.pathname + '#' + _currentPage + (_currentArg ? '/' + _currentArg : '');
  navigator.clipboard.writeText(url).then(() => showToast('Link copied to clipboard')).catch(() => {
    // Fallback
    const inp = document.createElement('input');
    inp.value = url; document.body.appendChild(inp);
    inp.select(); document.execCommand('copy');
    document.body.removeChild(inp);
    showToast('Link copied to clipboard');
  });
}

function downloadJSON() {
  let endpoint = '/api/stats';
  let filename = 'fray-dashboard.json';
  if (_currentPage === 'findings') { endpoint = '/api/findings-triage'; filename = 'fray-findings-triage.json'; }
  else if (_currentPage === 'targets') { endpoint = '/api/domains'; filename = 'fray-targets.json'; }
  else if (_currentPage === 'history') { endpoint = '/api/global-delta'; filename = 'fray-scan-delta.json'; }
  else if (_currentPage === 'executive') { endpoint = '/api/executive-summary'; filename = 'fray-executive-summary.json'; }
  else if (_currentPage === 'domains') { endpoint = '/api/domains'; filename = 'fray-domains.json'; }
  else if (_currentPage === 'detail' && _currentArg) { endpoint = `/api/domain/${_currentArg}`; filename = `fray-${_currentArg}.json`; }
  else if (_currentPage === 'learned') { endpoint = '/api/learned'; filename = 'fray-learned.json'; }
  else if (_currentPage === 'intel') { endpoint = '/api/threat-intel'; filename = 'fray-threat-intel.json'; }
  else if (_currentPage === 'timeline' && _currentArg) { endpoint = `/api/timeline/${_currentArg}`; filename = `fray-timeline-${_currentArg}.json`; }

  fetchJSON(endpoint).then(data => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = filename;
    a.click(); URL.revokeObjectURL(a.href);
    showToast(`Downloaded ${filename}`);
  });
}

// ── Hash-based deep linking ───────────────────────────────────────────

function updateHash(page, arg) {
  const hash = arg ? `${page}/${arg}` : page;
  history.replaceState(null, '', '#' + hash);
}

function loadFromHash() {
  const hash = window.location.hash.replace('#', '');
  if (!hash) return false;
  const parts = hash.split('/');
  const page = parts[0];
  const arg = parts.slice(1).join('/');
  if (['overview','findings','targets','history','executive','domains','detail','learned','intel','timeline','diff'].includes(page)) {
    navigate(page, arg || undefined);
    return true;
  }
  return false;
}

// ── Init ──────────────────────────────────────────────────────────────

$$('.nav-item').forEach(n => {
  n.addEventListener('click', () => navigate(n.dataset.page));
});

window.addEventListener('hashchange', () => loadFromHash());

// Start SSE live reload
initSSE();

// Start — load from hash or default to overview
if (!loadFromHash()) renderOverview();
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  SERVER LAUNCHER
# ══════════════════════════════════════════════════════════════════════════════

def start_dashboard(port: int = 8337, open_browser: bool = True,
                    quiet: bool = False) -> None:
    """Start the dashboard web server."""
    global _DASHBOARD_PORT
    _DASHBOARD_PORT = port
    handler = DashboardHandler

    # Start file watcher for SSE live reload
    watcher = threading.Thread(target=_file_watcher, daemon=True)
    watcher.start()

    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        httpd.allow_reuse_address = True
        url = f"http://127.0.0.1:{port}"

        if not quiet:
            import sys
            sys.stderr.write(f"\n  \033[1m\033[95m⚔  Fray Dashboard\033[0m\n")
            sys.stderr.write(f"  \033[90m{'─' * 40}\033[0m\n")
            sys.stderr.write(f"  URL:  \033[96m{url}\033[0m\n")
            sys.stderr.write(f"  Data: \033[90m{FRAY_DIR}\033[0m\n")
            sys.stderr.write(f"  Live: \033[92m✓ watching ~/.fray/ (SSE)\033[0m\n")
            sys.stderr.write(f"  \033[90m{'─' * 40}\033[0m\n")
            sys.stderr.write(f"  \033[90mPress Ctrl+C to stop\033[0m\n\n")

        if open_browser:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            if not quiet:
                sys.stderr.write("\n  Dashboard stopped.\n")
