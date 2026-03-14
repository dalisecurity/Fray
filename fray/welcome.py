"""
Fray CLI Welcome Screen — Claude Code-inspired interactive dashboard.

Shows: ASCII logo, personalized greeting, recent activity, what's new, tips.
"""

import json
import os
import random
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR

# ── ANSI color helpers (delegated to fray.ui) ────────────────────────────────

from fray.ui import S as _S

class _C:
    """Thin shim over fray.ui.S — provides NO_COLOR / truecolor for free."""
    BOLD = _S.bold
    DIM = _S.dim
    ITALIC = _S.italic
    UNDER = _S.underline
    STRIKE = ""  # unused in welcome
    R = _S.reset
    # Colors
    RED = _S.error
    GREEN = _S.success
    YELLOW = _S.warning
    BLUE = _S.info
    MAGENTA = _S.brand2
    CYAN = _S.cyan
    WHITE = _S.white
    # Bright
    BRED = _S.error
    BGREEN = _S.success
    BYELLOW = _S.warning
    BBLUE = _S.info
    BMAGENTA = _S.brand
    BCYAN = _S.bright_cyan
    # BG
    BG_BLUE = _S.bg_info
    BG_CYAN = _S.bg_brand
    BG_RED = _S.bg_error
    BG_GREEN = _S.bg_success

# ── ASCII Art Logo ───────────────────────────────────────────────────────────

_LOGO_LINES = [
    f"{_C.BCYAN}      ╱╲    ╱╲    ╱╲{_C.R}{_C.BMAGENTA}  · .{_C.R}",
    f"{_C.BCYAN}   ──╱──╲──╱──╲──╱──╲──{_C.R}{_C.BMAGENTA}·  ·{_C.R}     {_C.BOLD}{_C.WHITE}F R A Y{_C.R}  {_C.DIM}v{__version__}{_C.R}",
    f"{_C.BCYAN}     ╲  ╱╲  ╱╲  ╱{_C.R}  {_C.BMAGENTA}·    ·{_C.R}    {_C.DIM}AI-Native Security Toolkit{_C.R}",
    f"{_C.BCYAN}      ╲╱  ╲╱  ╲╱{_C.R}   {_C.BMAGENTA} ·{_C.R}",
]


def _get_user_name() -> str:
    """Get the user's display name."""
    # Try macOS full name
    try:
        result = subprocess.run(["id", "-F"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split()[0]  # First name only
    except Exception:
        pass
    # Fallback to env vars
    for var in ("USER", "USERNAME", "LOGNAME"):
        name = os.environ.get(var)
        if name:
            return name.capitalize()
    return "Hacker"


def _get_greeting() -> str:
    """Time-based greeting."""
    hour = datetime.now().hour
    if hour < 6:
        return "Burning the midnight oil"
    elif hour < 12:
        return "Good morning"
    elif hour < 17:
        return "Good afternoon"
    elif hour < 21:
        return "Good evening"
    else:
        return "Late night hacking"


def _count_payloads() -> Tuple[int, int]:
    """Count total payloads and categories."""
    cats = 0
    total = 0
    if PAYLOADS_DIR.exists():
        for cat_dir in PAYLOADS_DIR.iterdir():
            if cat_dir.is_dir() and not cat_dir.name.startswith("."):
                cats += 1
                for pf in cat_dir.glob("*.json"):
                    try:
                        data = json.loads(pf.read_text(encoding="utf-8"))
                        plist = data.get("payloads", data) if isinstance(data, dict) else data
                        total += len(plist) if isinstance(plist, list) else 0
                    except Exception:
                        pass
    return total, cats


def _get_recent_activity() -> List[Dict]:
    """Gather recent activity from ~/.fray/ caches."""
    activities = []
    fray_dir = Path.home() / ".fray"

    # Recent recon scans
    recon_dir = fray_dir / "recon"
    if recon_dir.exists():
        latest_files = sorted(
            recon_dir.glob("*_latest.json"),
            key=lambda f: f.stat().st_mtime, reverse=True
        )
        for f in latest_files[:3]:
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                age = datetime.now() - mtime
                target = f.stem.replace("_latest", "").replace("_", ".")
                activities.append({
                    "icon": "🔍",
                    "text": f"Recon: {target}",
                    "time": _relative_time(age),
                    "mtime": mtime,
                })
            except Exception:
                pass

    # Recent results files
    results_dir = Path.cwd()
    for pat in ("fray_results*.json", "fray_results*.sarif"):
        for f in sorted(results_dir.glob(pat), key=lambda x: x.stat().st_mtime, reverse=True)[:2]:
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                age = datetime.now() - mtime
                activities.append({
                    "icon": "📊",
                    "text": f"Report: {f.name}",
                    "time": _relative_time(age),
                    "mtime": mtime,
                })
            except Exception:
                pass

    # Learned patterns
    lp = fray_dir / "learned_patterns.json"
    if lp.exists():
        try:
            data = json.loads(lp.read_text())
            vendors = data.get("vendors", {})
            if isinstance(vendors, dict):
                total_runs = sum(v.get("total_runs", 0) for v in vendors.values() if isinstance(v, dict))
                total_blocked = sum(len(v.get("blocked_hashes", [])) for v in vendors.values() if isinstance(v, dict))
                if total_runs > 0:
                    activities.append({
                        "icon": "🧠",
                        "text": f"Agent: {total_runs} runs, {total_blocked} patterns learned",
                        "time": "",
                        "mtime": datetime.fromtimestamp(lp.stat().st_mtime),
                    })
        except Exception:
            pass

    # Threat intel cache
    tic = fray_dir / "threat_intel_cache.json"
    if tic.exists():
        try:
            mtime = datetime.fromtimestamp(tic.stat().st_mtime)
            age = datetime.now() - mtime
            activities.append({
                "icon": "📡",
                "text": f"Threat intel feed updated",
                "time": _relative_time(age),
                "mtime": mtime,
            })
        except Exception:
            pass

    # Sort by most recent
    activities.sort(key=lambda a: a.get("mtime", datetime.min), reverse=True)
    return activities[:5]


def _get_todo_summary() -> Tuple[int, int, str]:
    """Get pending/completed counts and top pending item."""
    todo_path = Path.home() / ".fray" / "todo.json"
    if not todo_path.exists():
        return 0, 0, ""
    try:
        items = json.loads(todo_path.read_text(encoding="utf-8"))
        pending = [i for i in items if i.get("status") != "completed"]
        completed = [i for i in items if i.get("status") == "completed"]
        top = pending[0].get("content", "") if pending else ""
        return len(pending), len(completed), top
    except Exception:
        return 0, 0, ""


def _relative_time(delta: timedelta) -> str:
    """Human-readable relative time."""
    secs = int(delta.total_seconds())
    if secs < 60:
        return "just now"
    elif secs < 3600:
        m = secs // 60
        return f"{m}m ago"
    elif secs < 86400:
        h = secs // 3600
        return f"{h}h ago"
    elif secs < 604800:
        d = secs // 86400
        return f"{d}d ago"
    else:
        return f"{secs // 604800}w ago"


# ── Threat Intelligence Summary ───────────────────────────────────────────────

def _get_threat_intel_summary() -> Dict:
    """Get threat intel stats for the welcome screen.

    Reads ~/.fray/cve_poc_cache.json and ~/.fray/threat_intel_cache.json
    to show recently auto-detected CVEs and payloads.
    """
    result = {
        "total_cves": 0,
        "cves_with_poc": 0,
        "total_poc_payloads": 0,
        "recent_cves": [],      # [{cve_id, poc_count, source, enriched_at}, ...]
        "last_feed": "",        # human-readable time since last feed run
        "sources_active": 0,
    }

    # Read PoC cache
    poc_cache = Path.home() / ".fray" / "cve_poc_cache.json"
    if poc_cache.exists():
        try:
            data = json.loads(poc_cache.read_text(encoding="utf-8"))
            result["total_cves"] = len(data)
            with_poc = []
            for cve_id, info in data.items():
                if isinstance(info, dict) and info.get("poc_count", 0) > 0:
                    with_poc.append({
                        "cve_id": cve_id,
                        "poc_count": info.get("poc_count", 0),
                        "source": info.get("source", "real_poc"),
                        "enriched_at": info.get("enriched_at", ""),
                    })
            result["cves_with_poc"] = len(with_poc)
            result["total_poc_payloads"] = sum(i["poc_count"] for i in with_poc)

            # Sort by enriched_at descending, take newest 5
            with_poc.sort(key=lambda x: x.get("enriched_at", ""), reverse=True)
            result["recent_cves"] = with_poc[:5]
        except Exception:
            pass

    # Read threat intel cache for last feed time
    ti_cache = Path.home() / ".fray" / "threat_intel_cache.json"
    if ti_cache.exists():
        try:
            tc = json.loads(ti_cache.read_text(encoding="utf-8"))
            last_fetch = tc.get("last_fetch", {})
            if last_fetch:
                latest = max(last_fetch.values()) if last_fetch.values() else ""
                if latest:
                    try:
                        dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                        delta = datetime.now(dt.tzinfo) - dt
                        result["last_feed"] = _relative_time(delta)
                    except Exception:
                        pass
            result["sources_active"] = len(last_fetch)
        except Exception:
            pass

    return result


# ── What's New ───────────────────────────────────────────────────────────────

_WHATS_NEW = [
    ("\U0001f680", "One command does everything", "fray go <url>", "Recon + smart test + HTML report, zero config"),
    ("\U0001f9e0", "AI agent that learns", "fray agent <url>", "Remembers what\u2019s blocked, never repeats, gets smarter"),
    ("\U0001f4e1", "Auto CVE feed", "Runs daily", "New CVEs auto-detected, PoC extracted, payloads ready"),
    ("\U0001f50d", "Deep recon", "fray recon <url>", "Subdomains, WAF, tech stack, JS endpoints, secrets"),
]

# ── Tips ─────────────────────────────────────────────────────────────────────

_TIPS = [
    "Just type {C}fray go <url>{R} \u2014 it does recon + testing + report automatically",
    "Not sure what to test? {C}fray go{R} picks the right attacks for your target",
    "Pipe targets: {C}cat domains.txt | fray detect{R} \u2014 works like httpx",
    "New CVEs are auto-detected daily \u2014 payloads appear in your next {C}fray test{R}",
    "The agent learns from each run: {C}fray agent <url>{R} gets smarter over time",
    "Need auth? Just add {C}--cookie 'session=abc'{R} to any command",
    "Found a CVE? {C}fray explain CVE-2024-XXXX{R} gives you payloads instantly",
    "Want to go deeper? {C}fray scan <url>{R} crawls + finds + tests automatically",
    "All results auto-save \u2014 run {C}fray report{R} to generate HTML anytime",
]

# ── Main render ──────────────────────────────────────────────────────────────

def render_welcome() -> str:
    """Render the full welcome screen — vibe security theme.

    Design: friendly, conversational, zero-research-needed.
    User sees what Fray can do and just picks an action.
    """
    lines = []

    name = _get_user_name()
    greeting = _get_greeting()
    total_payloads, num_cats = _count_payloads()
    activities = _get_recent_activity()
    ti = _get_threat_intel_summary()

    # ── Logo ─────────────────────────────────────────────────────────────
    lines.append("")
    for line in _LOGO_LINES:
        lines.append(f"  {line}")
    lines.append("")

    # ── Friendly greeting ───────────────────────────────────────────────
    lines.append(f"  {_C.BOLD}{greeting}, {_C.BCYAN}{name}{_C.R}{_C.BOLD}!{_C.R}")
    lines.append(f"  {_C.DIM}Your arsenal: {_C.R}{_C.BCYAN}{total_payloads:,}{_C.R}{_C.DIM} payloads across {_C.R}{_C.BCYAN}{num_cats}{_C.R}{_C.DIM} categories — locked and loaded.{_C.R}")
    lines.append("")

    # ── Live Threat Intel Dashboard ──────────────────────────────────────
    if ti["total_cves"] > 0:
        feed_ago = ti['last_feed'] or 'never'
        lines.append(f"  {_C.BOLD}{_C.WHITE}\U0001f6e1\ufe0f  Live Threat Intel{_C.R}  {_C.DIM}updated {feed_ago}{_C.R}")
        lines.append(f"  {_C.DIM}{chr(9473) * 56}{_C.R}")
        lines.append(
            f"  {_C.BCYAN}{ti['total_cves']}{_C.R} CVEs   "
            f"{_C.GREEN}{_C.BOLD}{ti['cves_with_poc']}{_C.R} real exploits   "
            f"{_C.YELLOW}{ti['total_poc_payloads']}{_C.R} payloads ready"
        )
        if ti["recent_cves"]:
            lines.append(f"  {_C.DIM}Latest:{_C.R}")
            for cve in ti["recent_cves"][:3]:
                src = cve.get("source", "")
                if src in ("generic", "nvd_template"):
                    dot = f"{_C.YELLOW}\u25cf{_C.R}"
                else:
                    dot = f"{_C.GREEN}\u25cf{_C.R}"
                lines.append(
                    f"    {dot} {_C.BOLD}{cve['cve_id']}{_C.R}  "
                    f"{_C.DIM}{cve['poc_count']} payloads{_C.R}"
                )
        lines.append(f"  {_C.DIM}Feeds: NVD \u00b7 CISA KEV \u00b7 ExploitDB \u00b7 GitHub \u00b7 Nuclei \u00b7 Metasploit{_C.R}")
        lines.append("")

    # ── What do you want to do? (Action cards) ─────────────────────────
    lines.append(f"  {_C.BOLD}{_C.WHITE}What do you want to do?{_C.R}")
    lines.append(f"  {_C.DIM}{chr(9473) * 56}{_C.R}")

    actions = [
        ("\U0001f680", "Test everything automatically", "fray go <url>",
         "Recon + smart testing + report in one shot"),
        ("\U0001f50d", "Scan a target",                "fray recon <url>",
         "Discover WAF, tech stack, subdomains, secrets"),
        ("\u2694\ufe0f",  "Test WAF defenses",             "fray test <url> -c xss",
         "Fire payloads and see what gets through"),
        ("\U0001f9e0", "Let the AI figure it out",      "fray agent <url>",
         "Self-improving agent that learns and adapts"),
        ("\U0001f578\ufe0f",  "Deep crawl + inject",          "fray scan <url>",
         "Auto-discover pages, forms, params and test them"),
        ("\U0001f4e1", "Get latest CVE payloads",       "fray feed --auto-add",
         "Pull new exploits from 8 intel sources"),
        ("\U0001f4cb", "Explain a CVE",                 "fray explain CVE-XXXX",
         "Instant payloads + remediation for any CVE"),
    ]

    for emoji, title, cmd, desc in actions:
        lines.append(
            f"  {emoji}  {_C.BOLD}{title}{_C.R}"
        )
        lines.append(
            f"      {_C.BCYAN}{cmd}{_C.R}  {_C.DIM}\u2014 {desc}{_C.R}"
        )
    lines.append("")

    # ── Recent Activity (compact) ───────────────────────────────────────
    if activities:
        lines.append(f"  {_C.BOLD}{_C.WHITE}\U0001f4ac  Recent{_C.R}")
        lines.append(f"  {_C.DIM}{chr(9473) * 56}{_C.R}")
        for act in activities[:3]:
            time_str = f"{_C.DIM}{act['time']}{_C.R}" if act.get("time") else ""
            lines.append(f"  {act['icon']}  {act['text']}  {time_str}")
        lines.append("")

    # ── Tip ─────────────────────────────────────────────────────────────
    tip_raw = random.choice(_TIPS)
    tip = tip_raw.replace("{B}", _C.BOLD).replace("{R}", _C.R).replace("{C}", _C.BCYAN).replace("{T}", _C.BCYAN)
    lines.append(f"  {_C.DIM}\U0001f4a1{_C.R} {tip}")
    lines.append("")

    # ── Footer ─────────────────────────────────────────────────────────
    lines.append(f"  {_C.DIM}{chr(9473) * 56}{_C.R}")
    lines.append(f"  {_C.DIM}\U0001f4d6 {_C.BCYAN}dalisec.io/docs{_C.R}  {_C.DIM}\u00b7  \U0001f517 {_C.R}{_C.DIM}github.com/dalisecurity/fray{_C.R}")
    lines.append(f"  {_C.DIM}\u26a0  Only test systems you own or have written permission to test.{_C.R}")
    lines.append("")

    return "\n".join(lines)


def print_welcome():
    """Print the welcome screen to stdout."""
    print(render_welcome())
