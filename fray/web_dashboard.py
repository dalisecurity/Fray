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
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

FRAY_DIR = Path.home() / ".fray"
RECON_DIR = FRAY_DIR / "recon"


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

        domains[domain] = {
            "domain": domain,
            "target": data.get("target", ""),
            "timestamp": data.get("timestamp", ""),
            "scan_count": scan_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "subdomains": sub_count + sub_active_count,
            "tls_version": tls_version,
            "header_score": header_score,
            "technologies": techs[:8],
            "vectors": len(vectors),
            "findings": len(findings),
        }

    # Sort by risk score desc
    return sorted(domains.values(), key=lambda d: d.get("risk_score", 0), reverse=True)


def get_domain_detail(domain: str) -> Optional[Dict]:
    """Get full latest recon data for a domain."""
    latest = RECON_DIR / f"{domain}_latest.json"
    if latest.exists():
        return _safe_json(latest)
    return None


def get_domain_history(domain: str) -> List[Dict]:
    """Get scan history for a domain."""
    history = []
    for f in sorted(RECON_DIR.glob(f"{domain}_2*.json")):
        data = _safe_json(f)
        if not data:
            continue
        attack = data.get("attack_surface", {})
        risk = attack.get("risk_score", 0) if isinstance(attack, dict) else 0
        subs = data.get("subdomains", {})
        sub_count = len(subs.get("subdomains", [])) if isinstance(subs, dict) else 0

        history.append({
            "file": f.name,
            "timestamp": data.get("timestamp", ""),
            "risk_score": risk,
            "subdomains": sub_count,
        })
    return history


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
#  HTTP SERVER + API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the dashboard API + SPA."""

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
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

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

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
  --border: rgba(255,255,255,.06);
  --border-strong: rgba(255,255,255,.10);
  --text: #ededf0;
  --text2: #71717a;
  --text3: #52525b;
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
.logo span { color:var(--text2); font-size:13px; font-weight:400; letter-spacing:-.01em; }
.nav-desc { font-size:10px; color:var(--text3); padding:0 16px 2px; margin-top:-4px; line-height:1.35; }
.nav-section { padding:16px 20px 6px; font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--text3); font-weight:500; }
.nav-item { display:flex; align-items:center; gap:10px; padding:8px 16px; margin:1px 8px; border-radius:8px; cursor:pointer; color:var(--text2); transition:all .15s ease; font-size:13px; font-weight:400; }
.nav-item:hover { background:rgba(255,255,255,.04); color:var(--text); }
.nav-item.active { background:var(--brand-glow); color:var(--brand2); font-weight:500; box-shadow:inset 0 0 0 1px rgba(124,58,237,.15); }
.sidebar-footer { margin-top:auto; padding:16px 20px; border-top:1px solid var(--border); }
.sidebar-footer-text { font-size:10px; color:var(--text3); letter-spacing:.02em; }

/* Cards */
.cards { display:grid; grid-template-columns:repeat(auto-fill, minmax(200px, 1fr)); gap:14px; margin-bottom:28px; }
.card { background:linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 100%); border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px; box-shadow:var(--shadow-sm); transition:border-color .2s, box-shadow .2s; }
.card:hover { border-color:var(--border-strong); box-shadow:var(--shadow-md); }
.card-label { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--text3); margin-bottom:6px; font-weight:500; }
.card-value { font-size:26px; font-weight:700; letter-spacing:-.03em; line-height:1.2; }
.card-sub { font-size:11px; color:var(--text3); margin-top:4px; }

/* Table */
.table-wrap { background:var(--bg2); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom:28px; box-shadow:var(--shadow-sm); }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:11px 16px; font-size:10.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--text3); background:var(--bg3); border-bottom:1px solid var(--border); font-weight:600; }
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
.section-title { font-size:17px; font-weight:600; margin-bottom:18px; display:flex; align-items:center; gap:8px; letter-spacing:-.01em; }
.section-title .count { font-size:12px; color:var(--text3); font-weight:400; }

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

/* Breadcrumb */
.breadcrumb { font-size:12px; color:var(--text3); margin-bottom:18px; }
.breadcrumb a { color:var(--accent); }

/* Loading */
.loading { text-align:center; padding:48px; color:var(--text3); font-size:13px; }

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

/* Print / PDF */
@media print {
  .sidebar { display:none !important; }
  .main { margin-left:0 !important; padding:16px !important; background:none !important; }
  .toolbar { display:none !important; }
  .shell { display:block !important; }
  body { background:#fff !important; color:#111 !important; font-size:10.5px !important; }
  .card { border:1px solid #d4d4d8 !important; background:#fafafa !important; break-inside:avoid; box-shadow:none !important; }
  .card-value { color:#111 !important; }
  .card-label { color:#666 !important; }
  .detail-section { border:1px solid #d4d4d8 !important; background:#fafafa !important; break-inside:avoid; box-shadow:none !important; }
  .detail-section h3 { color:#333 !important; }
  .table-wrap { border:1px solid #d4d4d8 !important; break-inside:avoid; box-shadow:none !important; }
  th { background:#f4f4f5 !important; color:#333 !important; border-bottom:1px solid #d4d4d8 !important; }
  td { border-bottom:1px solid #e4e4e7 !important; color:#111 !important; }
  .kv-key { color:#555 !important; }
  .kv-val { color:#111 !important; }
  .badge { border:1px solid currentColor !important; }
  .tag { border:1px solid #d4d4d8 !important; background:#f4f4f5 !important; color:#333 !important; }
  .section-title { color:#111 !important; }
  .risk-bar { border:1px solid #d4d4d8 !important; }
  .nav-item, .nav-section, .logo, .sidebar-footer { display:none !important; }
  a { color:#333 !important; text-decoration:underline !important; }
  .breadcrumb { color:#666 !important; }
  .toast { display:none !important; }
  * { animation:none !important; }
  @page { margin:1cm; size:A4; }
}
</style>
</head>
<body>

<div class="shell">
  <div class="sidebar">
    <div class="logo">&#9876; Fray <span>Dashboard</span></div>
    <div class="nav-section">Overview</div>
    <div class="nav-item active" data-page="overview">&#9632;&ensp;Overview</div>
    <div class="nav-item" data-page="executive">&#9998;&ensp;Executive Report</div>
    <div class="nav-item" data-page="domains">&#9673;&ensp;All Domains</div>
    <div class="nav-section">AI Agent</div>
    <div class="nav-item" data-page="learned">&#9881;&ensp;WAF Bypass Memory</div>
    <div class="nav-desc">What the agent learned per WAF</div>
    <div class="nav-item" data-page="intel">&#9889;&ensp;CVE Feed</div>
    <div class="nav-desc">Ingested vulnerabilities &amp; payloads</div>
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

async function fetchJSON(url) {
  const r = await fetch(API + url);
  return r.json();
}

// ── Pages ──────────────────────────────────────────────────────────────

async function renderOverview() {
  _stats = await fetchJSON('/api/stats');
  _domains = await fetchJSON('/api/domains');
  const s = _stats;

  let html = `<div class="section-title">&#9876; Dashboard Overview</div>`;

  // Stat cards
  html += `<div class="cards">
    <div class="card"><div class="card-label">Domains Scanned</div><div class="card-value">${s.total_domains||0}</div></div>
    <div class="card"><div class="card-label">Avg Risk Score</div><div class="card-value" style="color:${riskColor(s.avg_risk||0)}">${s.avg_risk||0}</div>${riskBar(s.avg_risk||0)}</div>
    <div class="card"><div class="card-label">Total Subdomains</div><div class="card-value">${(s.total_subdomains||0).toLocaleString()}</div></div>
    <div class="card"><div class="card-label">Attack Vectors</div><div class="card-value">${s.total_vectors||0}</div></div>
  </div>`;

  // Severity breakdown
  const sev = s.severity || {};
  html += `<div class="cards">
    <div class="card"><div class="card-label">Critical</div><div class="card-value" style="color:var(--critical)">${sev.critical||0}</div></div>
    <div class="card"><div class="card-label">High</div><div class="card-value" style="color:var(--high)">${sev.high||0}</div></div>
    <div class="card"><div class="card-label">Medium</div><div class="card-value" style="color:var(--medium)">${sev.medium||0}</div></div>
    <div class="card"><div class="card-label">Low</div><div class="card-value" style="color:var(--low)">${sev.low||0}</div></div>
  </div>`;

  // Top domains table
  html += `<div class="section-title">Top Domains by Risk <span class="count">(${_domains.length})</span></div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr><th>Domain</th><th>Risk</th><th>Subs</th><th>Vectors</th><th>Findings</th><th>Tech</th><th>Last Scan</th></tr></thead>
    <tbody>`;
  for (const d of _domains.slice(0, 25)) {
    html += `<tr style="cursor:pointer" onclick="navigate('detail','${d.domain}')">
      <td><a href="#" onclick="event.preventDefault();navigate('detail','${d.domain}')">${d.domain}</a></td>
      <td>${riskBadge(d.risk_level)} <span style="color:${riskColor(d.risk_score)};font-size:12px;font-weight:600">${d.risk_score}</span></td>
      <td style="font-weight:500">${d.subdomains}</td>
      <td style="font-weight:500">${d.vectors}</td>
      <td style="font-weight:500">${d.findings||0}</td>
      <td>${(d.technologies||[]).map(t=>techTag(t)).join('')}</td>
      <td style="color:var(--text2);font-size:12px">${timeAgo(d.timestamp)}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;

  // Top technologies
  if (s.top_technologies && s.top_technologies.length) {
    html += `<div class="section-title">Top Technologies</div><div class="detail-section">`;
    for (const [tech, count] of s.top_technologies) {
      const pct = Math.round(count / s.total_domains * 100);
      html += `<div class="kv"><span class="kv-key">${tech}</span><span class="kv-val">${count} (${pct}%)</span></div>`;
    }
    html += `</div>`;
  }

  $('#content').innerHTML = html;
}

async function renderDomains() {
  _domains = await fetchJSON('/api/domains');
  let html = `<div class="section-title">&#9673; All Domains <span class="count">(${_domains.length})</span></div>`;
  html += `<div style="margin-bottom:16px"><input id="domain-search" placeholder="Filter domains..." style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);width:300px;font-size:13px;outline:none"></div>`;
  html += `<div class="table-wrap"><table>
    <thead><tr><th>Domain</th><th>Risk</th><th>Score</th><th>Subs</th><th>Vectors</th><th>Findings</th><th>Scans</th><th>TLS</th><th>Headers</th><th>Last Scan</th></tr></thead>
    <tbody id="domain-tbody">`;
  for (const d of _domains) {
    html += domainRow(d);
  }
  html += `</tbody></table></div>`;
  $('#content').innerHTML = html;

  // Wire filter
  document.getElementById('domain-search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    const filtered = _domains.filter(d => d.domain.includes(q));
    document.getElementById('domain-tbody').innerHTML = filtered.map(domainRow).join('');
  });
}

function domainRow(d) {
  return `<tr style="cursor:pointer" onclick="navigate('detail','${d.domain}')">
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

  let html = `<div class="breadcrumb"><a href="#" onclick="event.preventDefault();navigate('domains')">Domains</a> / ${domain}</div>`;
  html += `<div class="section-title">${domain} ${riskBadge(riskLevel)}</div>`;

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

  // Technologies
  html += `<div class="detail-section"><h3>Technologies</h3>`;
  if (Object.keys(techs).length) {
    for (const [t, conf] of Object.entries(techs)) {
      html += `<div class="kv"><span class="kv-key">${t}</span><span class="kv-val">${Math.round(conf*100)}%</span></div>`;
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
  html += `<div class="detail-section"><h3>Attack Vectors (${vectors.length})</h3>`;
  for (const v of vectors.slice(0, 15)) {
    const sev = (v.severity||'info').toLowerCase();
    const label = v.type || v.name || '?';
    const targets = v.targets ? ` (${v.targets.length} targets)` : '';
    html += `<div class="kv"><span class="kv-key">${riskBadge(sev)} ${label}${targets}</span><span class="kv-val">${v.count ? v.count+' issues' : v.priority||''}</span></div>`;
  }
  if (!vectors.length) html += `<div style="color:var(--text2)">None found</div>`;
  html += `</div>`;

  // Findings
  if (findings.length) {
    html += `<div class="detail-section"><h3>Findings (${findings.length})</h3>`;
    for (const f of findings.slice(0, 15)) {
      const sev = (f.severity||'info').toLowerCase();
      html += `<div class="kv"><span class="kv-key">${riskBadge(sev)} ${f.finding||f.title||'?'}</span><span class="kv-val">${f.category||''} ${f.risk_score ? 'risk:'+f.risk_score : ''}</span></div>`;
    }
    html += `</div>`;
  }

  // DNS
  html += `<div class="detail-section"><h3>DNS</h3>`;
  const aRecords = dns.a || [];
  const aaaa = dns.aaaa || [];
  const mx = dns.mx || [];
  const ns = dns.ns || [];
  if (aRecords.length) html += `<div class="kv"><span class="kv-key">A</span><span class="kv-val">${aRecords.join(', ')}</span></div>`;
  if (aaaa.length) html += `<div class="kv"><span class="kv-key">AAAA</span><span class="kv-val">${aaaa.join(', ')}</span></div>`;
  if (mx.length) html += `<div class="kv"><span class="kv-key">MX</span><span class="kv-val">${mx.slice(0,3).join(', ')}</span></div>`;
  if (ns.length) html += `<div class="kv"><span class="kv-key">NS</span><span class="kv-val">${ns.slice(0,3).join(', ')}</span></div>`;
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
      html += `<div class="kv"><span class="kv-key">${c.ip||'?'}</span><span class="kv-val">${c.source||''} ${verified}</span></div>`;
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
      html += `<div class="kv"><span class="kv-key">${riskBadge(a.severity)}</span><span class="kv-val">${a.message}</span></div>`;
    }
    html += `</div>`;
  }

  html += `</div>`; // close detail-grid

  // Subdomains table
  if (allSubs.length) {
    html += `<div class="section-title">Subdomains <span class="count">(${allSubs.length})</span></div>`;
    html += `<div class="table-wrap"><table><thead><tr><th>FQDN</th><th>IP</th><th>WAF</th><th>Status</th></tr></thead><tbody>`;
    const subList = allSubs.slice(0, 50);
    for (const s of subList) {
      const fqdn = typeof s === 'string' ? s : (s.fqdn || s.name || '');
      const ip = typeof s === 'object' ? (s.ip || s.a || '') : '';
      const waf = typeof s === 'object' ? (s.waf || s.cdn || '') : '';
      const status = typeof s === 'object' ? (s.status || '') : '';
      html += `<tr><td style="font-family:var(--mono);font-size:12px">${fqdn}</td><td>${ip}</td><td>${waf ? `<span class="tag">${waf}</span>` : ''}</td><td>${status}</td></tr>`;
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
          <div style="font-size:11px;color:var(--text2);margin-bottom:2px"><strong>Why:</strong> ${r.why||''}</div>
          <div style="font-size:11px;color:var(--text2);margin-bottom:2px"><strong>How:</strong> ${r.how||''}</div>
          <div style="font-size:11px"><span class="tag">${r.timeline||'TBD'}</span></div>
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
          <div style="font-size:11px;color:var(--text2)">${b.description||''}</div>
          ${b.payload_example ? `<div style="font-family:var(--mono);font-size:10px;color:var(--accent);margin-top:2px">${b.payload_example}</div>` : ''}
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
  let html = `<div class="section-title">&#9881; WAF Bypass Memory</div>`;

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
      html += `<div><div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:6px">Deprioritized Strategies</div>`;
      const sorted = Object.entries(failStrats).sort((a,b) => (typeof b[1]==='number'?b[1]:0) - (typeof a[1]==='number'?a[1]:0));
      for (const [strat, count] of sorted.slice(0,8)) {
        html += `<div class="kv"><span class="kv-key" style="color:var(--text3)">${strat}</span><span class="kv-val" style="color:var(--text3)">${typeof count==='number'?count:''} failures</span></div>`;
      }
      html += `</div>`;
    }

    html += `</div>`;
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
    <div class="card"><div class="card-label">Last Fetch</div><div class="card-value" style="font-size:14px;color:var(--text)">${lastFetchStr}</div></div>
    <div class="card"><div class="card-label">Sources</div><div class="card-value" style="font-size:14px">${fetchEntries.length ? fetchEntries[0][0].split(',').length : 0}</div><div class="card-sub">NVD, CISA, GitHub, ExploitDB, RSS, Nuclei</div></div>
  </div>`;

  // CVE list
  if (seenCves.length) {
    html += `<div class="section-title">Tracked CVEs <span class="count">(${seenCves.length})</span></div>`;
    html += `<div class="detail-section"><div style="display:flex;flex-wrap:wrap;gap:6px">`;
    for (const cve of seenCves.slice(0, 80)) {
      const year = cve.split('-')[1] || '';
      const isRecent = parseInt(year) >= 2025;
      const cls = isRecent ? 'tag tag-lang' : 'tag';
      html += `<span class="${cls}" style="font-family:var(--mono);font-size:11px">${cve}</span>`;
    }
    if (seenCves.length > 80) html += `<span class="tag">+${seenCves.length - 80} more</span>`;
    html += `</div></div>`;
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

  html += `<div class="detail-grid">`;

  // Critical Findings
  const cf = s.critical_findings || [];
  if (cf.length) {
    html += `<div class="detail-section"><h3>Critical & High Findings (${cf.length})</h3>`;
    for (const f of cf.slice(0, 20)) {
      const sev = (f.severity||'info').toLowerCase();
      html += `<div class="kv">
        <span class="kv-key">${riskBadge(sev)} ${(f.finding||f.title||'').slice(0,70)}</span>
        <span class="kv-val"><a href="#" onclick="event.preventDefault();navigate('detail','${f.domain}')" style="font-size:11px">${f.domain}</a></span>
      </div>`;
    }
    html += `</div>`;
  }

  // Finding Categories
  const cats = s.top_categories || [];
  if (cats.length) {
    html += `<div class="detail-section"><h3>Finding Categories</h3>`;
    for (const [cat, count] of cats) {
      const pct = Math.round(count / (s.total_findings||1) * 100);
      html += `<div class="kv"><span class="kv-key">${cat}</span><span class="kv-val">${count} (${pct}%)</span></div>`;
    }
    html += `</div>`;
  }

  // Attack Vector Types
  const vecs = s.top_vectors || [];
  if (vecs.length) {
    html += `<div class="detail-section"><h3>Attack Vector Types</h3>`;
    for (const [vtype, count] of vecs) {
      html += `<div class="kv"><span class="kv-key">${vtype}</span><span class="kv-val">${count} domains</span></div>`;
    }
    html += `</div>`;
  }

  // WAF Vendors
  const wafs = s.waf_vendors || [];
  if (wafs.length) {
    html += `<div class="detail-section"><h3>WAF Distribution</h3>`;
    for (const [waf, count] of wafs) {
      const pct = Math.round(count / s.total_domains * 100);
      html += `<div class="kv"><span class="kv-key">${waf}</span><span class="kv-val">${count} (${pct}%)</span></div>`;
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

  // Remediation Plan
  const rem = s.top_remediation || [];
  if (rem.length) {
    html += `<div class="section-title">Remediation Plan <span class="count">(${rem.length} actions)</span></div>`;
    html += `<div class="table-wrap"><table>
      <thead><tr><th>Priority</th><th>Action</th><th>Why</th><th>Timeline</th><th>Affected</th></tr></thead><tbody>`;
    for (const r of rem) {
      html += `<tr>
        <td>${riskBadge(r.severity)}</td>
        <td style="font-weight:500">${r.action}</td>
        <td style="font-size:12px;color:var(--text2)">${(r.why||'').slice(0,80)}</td>
        <td><span class="tag">${r.timeline||'TBD'}</span></td>
        <td style="font-size:11px">${r.count} domain${r.count>1?'s':''}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  $('#content').innerHTML = html;
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
    case 'executive': renderExecutive(); break;
    case 'domains': renderDomains(); break;
    case 'detail': renderDetail(arg); break;
    case 'learned': renderLearned(); break;
    case 'intel': renderIntel(); break;
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
    executive: 'Executive Report',
    domains: 'All Domains',
    detail: _currentArg || 'Domain Detail',
    learned: 'WAF Bypass Memory',
    intel: 'Threat Intel',
  }[_currentPage] || 'Dashboard';

  tb.innerHTML = `
    <div style="font-size:11px;color:var(--text2)">&#9876; Fray / ${pageTitle}</div>
    <div class="toolbar-actions">
      <button class="btn" onclick="copyShareLink()" title="Copy shareable link">
        &#128279; Share Link
      </button>
      <button class="btn" onclick="downloadJSON()" title="Download page data as JSON">
        &#128230; JSON
      </button>
      <button class="btn btn-brand" onclick="downloadPDF()" title="Export as PDF">
        &#128196; Download PDF
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

function downloadPDF() {
  showToast('Preparing PDF...');
  setTimeout(() => window.print(), 300);
}

function downloadJSON() {
  let endpoint = '/api/stats';
  let filename = 'fray-dashboard.json';
  if (_currentPage === 'executive') { endpoint = '/api/executive-summary'; filename = 'fray-executive-summary.json'; }
  else if (_currentPage === 'domains') { endpoint = '/api/domains'; filename = 'fray-domains.json'; }
  else if (_currentPage === 'detail' && _currentArg) { endpoint = `/api/domain/${_currentArg}`; filename = `fray-${_currentArg}.json`; }
  else if (_currentPage === 'learned') { endpoint = '/api/learned'; filename = 'fray-learned.json'; }
  else if (_currentPage === 'intel') { endpoint = '/api/threat-intel'; filename = 'fray-threat-intel.json'; }

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
  if (['overview','executive','domains','detail','learned','intel'].includes(page)) {
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
    handler = DashboardHandler

    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        httpd.allow_reuse_address = True
        url = f"http://127.0.0.1:{port}"

        if not quiet:
            import sys
            sys.stderr.write(f"\n  \033[1m\033[95m⚔  Fray Dashboard\033[0m\n")
            sys.stderr.write(f"  \033[90m{'─' * 40}\033[0m\n")
            sys.stderr.write(f"  URL:  \033[96m{url}\033[0m\n")
            sys.stderr.write(f"  Data: \033[90m{FRAY_DIR}\033[0m\n")
            sys.stderr.write(f"  \033[90m{'─' * 40}\033[0m\n")
            sys.stderr.write(f"  \033[90mPress Ctrl+C to stop\033[0m\n\n")

        if open_browser:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            if not quiet:
                sys.stderr.write("\n  Dashboard stopped.\n")
