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
<style>
:root {
  --bg: #0f0f13;
  --bg2: #16161d;
  --bg3: #1e1e28;
  --border: #2a2a3a;
  --text: #e0e0e8;
  --text2: #8888a0;
  --brand: #6366f1;
  --brand2: #a78bfa;
  --accent: #818cf8;
  --target: #60a5fa;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #3b82f6;
  --success: #22c55e;
  --font: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --mono: 'JetBrains Mono', 'SF Mono', 'Fira Code', Consolas, monospace;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:var(--font); font-size:14px; }
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }

/* Layout */
.shell { display:flex; min-height:100vh; }
.sidebar { width:240px; background:var(--bg2); border-right:1px solid var(--border); padding:16px 0; flex-shrink:0; position:fixed; height:100vh; overflow-y:auto; }
.main { margin-left:240px; flex:1; padding:24px 32px; min-height:100vh; }

/* Sidebar */
.logo { padding:0 20px 20px; font-size:18px; font-weight:700; color:var(--brand); display:flex; align-items:center; gap:8px; }
.logo span { color:var(--text2); font-size:12px; font-weight:400; }
.nav-section { padding:8px 20px 4px; font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--text2); }
.nav-item { display:flex; align-items:center; gap:8px; padding:8px 20px; cursor:pointer; color:var(--text2); transition:all .15s; font-size:13px; }
.nav-item:hover { background:var(--bg3); color:var(--text); }
.nav-item.active { background:var(--bg3); color:var(--brand); border-right:2px solid var(--brand); }

/* Cards */
.cards { display:grid; grid-template-columns:repeat(auto-fill, minmax(200px, 1fr)); gap:16px; margin-bottom:24px; }
.card { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; }
.card-label { font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--text2); margin-bottom:4px; }
.card-value { font-size:24px; font-weight:700; }
.card-sub { font-size:11px; color:var(--text2); margin-top:2px; }

/* Table */
.table-wrap { background:var(--bg2); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:24px; }
table { width:100%; border-collapse:collapse; }
th { text-align:left; padding:10px 14px; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--text2); background:var(--bg3); border-bottom:1px solid var(--border); }
td { padding:10px 14px; border-bottom:1px solid var(--border); font-size:13px; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:rgba(99,102,241,.04); }

/* Badges */
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
.badge-critical { background:rgba(239,68,68,.15); color:var(--critical); }
.badge-high { background:rgba(249,115,22,.15); color:var(--high); }
.badge-medium { background:rgba(234,179,8,.15); color:var(--medium); }
.badge-low { background:rgba(59,130,246,.15); color:var(--low); }
.badge-info { background:rgba(136,136,160,.15); color:var(--text2); }

/* Risk gauge */
.risk-bar { height:6px; border-radius:3px; background:var(--bg3); overflow:hidden; width:100%; }
.risk-fill { height:100%; border-radius:3px; transition:width .4s; }

/* Section headers */
.section-title { font-size:16px; font-weight:600; margin-bottom:16px; display:flex; align-items:center; gap:8px; }
.section-title .count { font-size:12px; color:var(--text2); font-weight:400; }

/* Detail view */
.detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:24px; }
@media (max-width: 900px) { .detail-grid { grid-template-columns:1fr; } }
.detail-section { background:var(--bg2); border:1px solid var(--border); border-radius:8px; padding:16px; }
.detail-section h3 { font-size:13px; font-weight:600; margin-bottom:10px; color:var(--brand2); }
.kv { display:flex; justify-content:space-between; padding:4px 0; font-size:12px; border-bottom:1px solid var(--border); }
.kv:last-child { border-bottom:none; }
.kv-key { color:var(--text2); }
.kv-val { color:var(--text); font-family:var(--mono); font-size:11px; }
.tag { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; background:var(--bg3); color:var(--text2); margin:1px; }

/* Breadcrumb */
.breadcrumb { font-size:12px; color:var(--text2); margin-bottom:16px; }
.breadcrumb a { color:var(--accent); }

/* Loading */
.loading { text-align:center; padding:40px; color:var(--text2); }

/* Scrollbar */
::-webkit-scrollbar { width:6px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
</style>
</head>
<body>

<div class="shell">
  <div class="sidebar">
    <div class="logo">&#9876; Fray <span>Dashboard</span></div>
    <div class="nav-section">Overview</div>
    <div class="nav-item active" data-page="overview">&#9632; Dashboard</div>
    <div class="nav-item" data-page="domains">&#9673; Domains</div>
    <div class="nav-section">Intelligence</div>
    <div class="nav-item" data-page="learned">&#9881; Learned Patterns</div>
    <div class="nav-item" data-page="intel">&#9889; Threat Intel</div>
  </div>
  <div class="main" id="content">
    <div class="loading">Loading...</div>
  </div>
</div>

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
      <td>${riskBadge(d.risk_level)} <span style="color:var(--text2);font-size:11px">${d.risk_score}</span></td>
      <td>${d.subdomains}</td>
      <td>${d.vectors}</td>
      <td>${d.findings||0}</td>
      <td>${(d.technologies||[]).map(t=>`<span class="tag">${t}</span>`).join('')}</td>
      <td style="color:var(--text2);font-size:11px">${timeAgo(d.timestamp)}</td>
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
    <td style="color:${riskColor(d.risk_score)};font-weight:600">${d.risk_score}</td>
    <td>${d.subdomains}</td>
    <td>${d.vectors||0}</td>
    <td>${d.findings||0}</td>
    <td>${d.scan_count}</td>
    <td><span class="tag">${d.tls_version||'?'}</span></td>
    <td>${d.header_score}%</td>
    <td style="color:var(--text2);font-size:11px">${timeAgo(d.timestamp)}</td>
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

  $('#content').innerHTML = html;
}

async function renderLearned() {
  const data = await fetchJSON('/api/learned');
  let html = `<div class="section-title">&#9881; Learned Patterns (Agent Cache)</div>`;

  const vendors = Object.keys(data).filter(k => typeof data[k] === 'object');
  if (!vendors.length) {
    html += `<div class="loading">No learned patterns yet. Run: fray agent &lt;url&gt; -c xss</div>`;
    $('#content').innerHTML = html;
    return;
  }

  for (const vendor of vendors) {
    const v = data[vendor];
    html += `<div class="detail-section" style="margin-bottom:16px"><h3>${vendor}</h3>`;
    html += `<div class="kv"><span class="kv-key">Total Runs</span><span class="kv-val">${v.total_runs||0}</span></div>`;
    html += `<div class="kv"><span class="kv-key">Total Blocked</span><span class="kv-val">${v.total_blocked||0}</span></div>`;
    html += `<div class="kv"><span class="kv-key">Blocked Hashes</span><span class="kv-val">${(v.blocked_hashes||[]).length}</span></div>`;
    html += `<div class="kv"><span class="kv-key">Successful Payloads</span><span class="kv-val">${(v.successful_payloads||[]).length}</span></div>`;
    const strats = v.effective_strategies || {};
    if (Object.keys(strats).length) {
      html += `<div style="margin-top:8px;font-size:11px;color:var(--text2)">Effective strategies:</div>`;
      for (const [s, c] of Object.entries(strats)) {
        html += `<div class="kv"><span class="kv-key">${s}</span><span class="kv-val">${c}</span></div>`;
      }
    }
    html += `</div>`;
  }

  $('#content').innerHTML = html;
}

async function renderIntel() {
  const data = await fetchJSON('/api/threat-intel');
  let html = `<div class="section-title">&#9889; Threat Intel Cache</div>`;

  if (!data || !Object.keys(data).length) {
    html += `<div class="loading">No threat intel data. Run: fray feed --since 7d</div>`;
    $('#content').innerHTML = html;
    return;
  }

  html += `<div class="detail-section"><h3>Cached Data</h3>`;
  for (const [k, v] of Object.entries(data)) {
    const display = Array.isArray(v) ? `${v.length} items` : typeof v === 'object' ? JSON.stringify(v).slice(0,80) : String(v);
    html += `<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${display}</span></div>`;
  }
  html += `</div>`;

  $('#content').innerHTML = html;
}

// ── Router ────────────────────────────────────────────────────────────

function navigate(page, arg) {
  // Update nav
  $$('.nav-item').forEach(n => n.classList.remove('active'));
  const navItem = $(`.nav-item[data-page="${page}"]`);
  if (navItem) navItem.classList.add('active');

  // Render
  switch(page) {
    case 'overview': renderOverview(); break;
    case 'domains': renderDomains(); break;
    case 'detail': renderDetail(arg); break;
    case 'learned': renderLearned(); break;
    case 'intel': renderIntel(); break;
    default: renderOverview();
  }
}

// ── Init ──────────────────────────────────────────────────────────────

$$('.nav-item').forEach(n => {
  n.addEventListener('click', () => navigate(n.dataset.page));
});

// Start
renderOverview();
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
