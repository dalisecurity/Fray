#!/usr/bin/env python3
"""
Fray — Natural Language Query for Findings (#142)

Provides `fray ask` — a keyword-based query engine over local recon,
scan, and OSINT data stored in ~/.fray/. No LLM required (works offline).

Supports queries like:
    fray ask "which domains have no WAF?"
    fray ask "show XSS bypasses for cloudflare"
    fray ask "open ports on softbank.jp"
    fray ask "critical findings for toyota.co.jp"
    fray ask "domains with expired certs"

Architecture:
  1. Parse query → extract intent + filters (domain, severity, vuln type)
  2. Load relevant data from ~/.fray/recon/, domain_cache.json, osint/
  3. Filter + rank results
  4. Format output (table or JSON)
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"

_FRAY_DIR = Path.home() / ".fray"


# ── Intent classification ────────────────────────────────────────────────────

_INTENT_PATTERNS = [
    (r"\b(no waf|without waf|missing waf|unprotected)\b", "no_waf"),
    (r"\b(waf|firewall)\b", "waf"),
    (r"\b(bypass|bypassed|passed)\b", "bypasses"),
    (r"\b(blocked|block rate)\b", "blocked"),
    (r"\b(xss|cross.?site)\b", "xss"),
    (r"\b(sqli|sql.?injection)\b", "sqli"),
    (r"\b(ssrf)\b", "ssrf"),
    (r"\b(ssti|template.?injection)\b", "ssti"),
    (r"\b(subdomain|sub)\b", "subdomains"),
    (r"\b(port|open port)\b", "ports"),
    (r"\b(cert|certificate|ssl|tls|expired)\b", "tls"),
    (r"\b(tech|technology|stack|framework)\b", "tech"),
    (r"\b(critical|high|severe)\b", "critical"),
    (r"\b(admin|panel)\b", "admin"),
    (r"\b(finding|vulnerability|vuln)\b", "findings"),
    (r"\b(dns|nameserver|mx|txt)\b", "dns"),
    (r"\b(email|employee)\b", "osint"),
    (r"\b(header|security.?header|csp|hsts)\b", "headers"),
    (r"\b(scan|test|result)\b", "scans"),
    (r"\b(all|everything|summary|overview)\b", "summary"),
]


def _classify_intent(query: str) -> List[str]:
    """Extract intents from natural language query."""
    q = query.lower()
    intents = []
    for pattern, intent in _INTENT_PATTERNS:
        if re.search(pattern, q):
            intents.append(intent)
    if not intents:
        intents.append("summary")
    return intents


def _extract_domain(query: str) -> Optional[str]:
    """Extract domain from query string."""
    # Try explicit domain patterns
    m = re.search(r'(?:for|on|of|about)\s+([a-z0-9][-a-z0-9.]+\.[a-z]{2,})', query.lower())
    if m:
        return m.group(1)
    # Try bare domain in query
    m = re.search(r'\b([a-z0-9][-a-z0-9]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b', query.lower())
    if m:
        return m.group(1)
    return None


def _extract_vendor(query: str) -> Optional[str]:
    """Extract WAF vendor name from query."""
    vendors = ["cloudflare", "akamai", "imperva", "incapsula", "aws_waf",
               "sucuri", "fortiweb", "f5", "barracuda", "citrix",
               "fastly", "stackpath", "azure"]
    q = query.lower()
    for v in vendors:
        if v in q:
            return v
    return None


# ── Data loaders ─────────────────────────────────────────────────────────────

def _load_json(path: Path) -> Optional[dict]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _list_domains() -> List[str]:
    """List all domains with recon data."""
    recon_dir = _FRAY_DIR / "recon"
    if not recon_dir.exists():
        return []
    return sorted(d.name for d in recon_dir.iterdir()
                  if d.is_dir() and (d / "recon.json").exists())


def _load_cache() -> dict:
    return _load_json(_FRAY_DIR / "domain_cache.json") or {}


def _load_recon(domain: str) -> Optional[dict]:
    return _load_json(_FRAY_DIR / "recon" / domain / "recon.json")


# ── Query handlers ───────────────────────────────────────────────────────────

def _query_no_waf(domain: Optional[str]) -> List[dict]:
    """Find domains with no WAF detected."""
    results = []
    cache = _load_cache()
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon:
            continue
        waf = recon.get("attack_surface", {}).get("waf_vendor", "")
        if not waf or waf.lower() in ("none", "unknown", ""):
            results.append({"domain": d, "waf": "None detected",
                            "risk": recon.get("attack_surface", {}).get("risk_level", "?")})
    return results


def _query_waf(domain: Optional[str], vendor: Optional[str]) -> List[dict]:
    """Show WAF info for domains."""
    results = []
    cache = _load_cache()
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon:
            continue
        waf = recon.get("attack_surface", {}).get("waf_vendor", "unknown")
        if vendor and vendor.lower() not in waf.lower():
            continue
        entry = {"domain": d, "waf": waf}
        if d in cache:
            c = cache[d]
            entry["tested"] = c.get("total_tested", 0)
            entry["blocked"] = c.get("total_blocked", 0)
        results.append(entry)
    return results


def _query_bypasses(domain: Optional[str], vendor: Optional[str]) -> List[dict]:
    """Show bypass stats."""
    results = []
    cache = _load_cache()
    for d, c in cache.items():
        if domain and d != domain:
            continue
        tested = c.get("total_tested", 0)
        blocked = c.get("total_blocked", 0)
        passed = tested - blocked
        if passed <= 0:
            continue
        waf = c.get("waf_vendor", "")
        if vendor and vendor.lower() not in waf.lower():
            continue
        results.append({"domain": d, "waf": waf, "tested": tested,
                        "blocked": blocked, "bypassed": passed,
                        "rate": f"{blocked/tested*100:.1f}%" if tested else "N/A"})
    results.sort(key=lambda x: x.get("bypassed", 0), reverse=True)
    return results


def _query_subdomains(domain: Optional[str]) -> List[dict]:
    """Show subdomain counts."""
    results = []
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon:
            continue
        subs = recon.get("subdomains", [])
        count = len(subs) if isinstance(subs, list) else subs
        if count:
            results.append({"domain": d, "subdomains": count})
    results.sort(key=lambda x: x.get("subdomains", 0), reverse=True)
    return results


def _query_tls(domain: Optional[str]) -> List[dict]:
    """Show TLS/cert info, highlight expired."""
    results = []
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon or not recon.get("tls"):
            continue
        t = recon["tls"]
        expiry = t.get("not_after", "")
        expired = False
        if expiry:
            try:
                exp_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                expired = exp_dt < datetime.now(exp_dt.tzinfo)
            except Exception:
                pass
        results.append({"domain": d, "tls_version": t.get("tls_version", ""),
                        "issuer": t.get("issuer", ""), "expiry": expiry,
                        "expired": expired})
    return results


def _query_critical(domain: Optional[str]) -> List[dict]:
    """Show critical/high findings."""
    results = []
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon:
            continue
        findings = recon.get("attack_surface", {}).get("findings", [])
        for f in findings:
            sev = f.get("severity", "").lower() if isinstance(f, dict) else ""
            if sev in ("critical", "high"):
                results.append({"domain": d, "severity": sev,
                                "title": f.get("title", f.get("description", str(f)))})
    return results


def _query_summary(domain: Optional[str]) -> List[dict]:
    """Show summary for domain(s)."""
    results = []
    cache = _load_cache()
    domains = [domain] if domain else _list_domains()
    for d in domains:
        recon = _load_recon(d)
        if not recon:
            continue
        atk = recon.get("attack_surface", {})
        entry = {
            "domain": d,
            "risk": atk.get("risk_level", "?"),
            "score": atk.get("risk_score", 0),
            "waf": atk.get("waf_vendor", "none"),
            "vectors": len(atk.get("attack_vectors", [])),
            "findings": len(atk.get("findings", [])),
        }
        if d in cache:
            entry["tested"] = cache[d].get("total_tested", 0)
        results.append(entry)
    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    return results


# ── Main query engine ────────────────────────────────────────────────────────

_HANDLERS = {
    "no_waf": lambda d, v: _query_no_waf(d),
    "waf": _query_waf,
    "bypasses": _query_bypasses,
    "blocked": _query_bypasses,
    "xss": lambda d, v: _query_bypasses(d, v),
    "subdomains": lambda d, v: _query_subdomains(d),
    "tls": lambda d, v: _query_tls(d),
    "critical": lambda d, v: _query_critical(d),
    "findings": lambda d, v: _query_critical(d),
    "summary": lambda d, v: _query_summary(d),
}


def ask(query: str) -> dict:
    """Process a natural language query over Fray data.

    Returns:
        {"query": str, "intents": list, "domain": str|None,
         "results": list, "count": int}
    """
    intents = _classify_intent(query)
    domain = _extract_domain(query)
    vendor = _extract_vendor(query)

    all_results = []
    seen = set()
    for intent in intents:
        handler = _HANDLERS.get(intent)
        if handler:
            rows = handler(domain, vendor)
            for r in rows:
                key = json.dumps(r, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    all_results.append(r)

    return {
        "query": query,
        "intents": intents,
        "domain": domain,
        "vendor": vendor,
        "results": all_results[:50],
        "count": len(all_results),
    }


# ── CLI output ───────────────────────────────────────────────────────────────

def print_ask_result(result: dict):
    """Pretty-print ask results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    CYN = "\033[96m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    RED = "\033[91m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Fray Ask{R} — {D}{result['query']}{R}")
    print(f"  {D}Intents: {', '.join(result['intents'])}")
    if result.get("domain"):
        print(f"  Domain: {result['domain']}")
    print(f"  Results: {result['count']}{R}")
    print(f"{D}{'━' * 60}{R}\n")

    rows = result.get("results", [])
    if not rows:
        print(f"  {YEL}No results found.{R}")
        print(f"  {D}Tip: Run 'fray recon <domain>' first to populate data.{R}\n")
        return

    # Auto-detect columns from first row
    cols = list(rows[0].keys())

    # Print table
    widths = {c: max(len(c), max(len(str(r.get(c, "")))[:40] for r in rows)) for c in cols}
    header = " | ".join(f"{c:<{widths[c]}}" for c in cols)
    print(f"  {B}{header}{R}")
    print(f"  {'─' * len(header)}")

    for row in rows[:30]:
        parts = []
        for c in cols:
            val = str(row.get(c, ""))[:40]
            # Color code certain values
            if c in ("risk", "severity"):
                if val.lower() in ("critical", "high"):
                    val = f"{RED}{val}{R}"
                elif val.lower() == "medium":
                    val = f"{YEL}{val}{R}"
                else:
                    val = f"{GRN}{val}{R}"
            elif c == "waf" and val.lower() in ("none", "none detected", "unknown", ""):
                val = f"{RED}{val or 'none'}{R}"
            elif c == "expired" and val == "True":
                val = f"{RED}EXPIRED{R}"
            parts.append(f"{val:<{widths[c]}}")
        print(f"  {' | '.join(parts)}")

    if len(rows) > 30:
        print(f"\n  {D}... and {len(rows) - 30} more results{R}")
    print()
