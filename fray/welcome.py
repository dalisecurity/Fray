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
    f"{_C.BCYAN}       ┌─────────┐{_C.R}",
    f"{_C.BCYAN}       │ {_C.WHITE}{_C.BOLD}◉{_C.R}{_C.BCYAN}   {_C.WHITE}{_C.BOLD}◉{_C.R}{_C.BCYAN} │{_C.R}",
    f"{_C.BCYAN}       │  {_C.WHITE}{_C.BOLD}▬▬▬{_C.R}{_C.BCYAN}  │{_C.R}",
    f"{_C.BCYAN}       └────┬────┘{_C.R}",
    f"{_C.BCYAN}      ╔═════╧═════╗{_C.R}",
    f"{_C.BCYAN}      ║{_C.R} {_C.BOLD}{_C.WHITE}F  R  A  Y{_C.R} {_C.BCYAN}║{_C.R}  {_C.DIM}v{__version__}{_C.R}",
    f"{_C.BCYAN}      ╚═══════════╝{_C.R}  {_C.DIM}WAF Security Testing Platform{_C.R}",
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
    ("Guided pipeline", "fray go <url>", "Zero-knowledge: recon → smart test → report in one command"),
    ("Interactive hints", "After every command", "Smart next-step suggestions — no security knowledge needed"),
    ("Blind injection detection", "fray test <url> --blind", "Time-based SQLi/SSTI/CMDi + OOB DNS callbacks"),
    ("Self-improving agent", "fray agent <url>", "Iterative probe → mutate → learn loop with persistent cache"),
    ("Threat intel feed", "fray feed --auto-add", "Auto-ingest CVEs from NVD, CISA, GitHub, ExploitDB, RSS, Nuclei"),
    ("Cloud sync", "fray update / fray sync", "Pull/push payload database via Cloudflare R2 or GitHub releases"),
]

# ── Tips ─────────────────────────────────────────────────────────────────────

_TIPS = [
    "Use {B}--smart{R} to auto-detect your target's tech stack and pick the right payloads",
    "Pipe targets: {C}cat domains.txt | fray detect{R} — works like httpx",
    "Use {B}fray agent <url>{R} for self-improving testing that remembers what's blocked",
    "Add {B}--blind{R} to detect time-based SQLi and OOB vulnerabilities",
    "Try {B}fray recon <url> --js{R} to extract API endpoints from JavaScript files",
    "Set up auth once: {B}fray test <url> --auth-profile ~/.fray/auth/site.json{R}",
    "Try {B}fray go <url>{R} for a zero-knowledge guided pipeline (recon+test+report)",
    "Use {B}fray scan <url> --sarif{R} to upload results to GitHub Security tab",
    "Run {B}fray todo add \"my task\"{R} to track your private roadmap",
    "The threat feed runs daily in CI: {B}fray feed --auto-add --test-target <url>{R}",
    "Use {B}fray explain CVE-2024-XXXX{R} to get payloads + remediation for any CVE",
    "Add {B}--stealth{R} for extra evasion: DNT, randomized timing, cache-control",
    "Chain tools: {B}fray recon <url> --json | jq '.technologies'{R}",
]


# ── Main render ──────────────────────────────────────────────────────────────

def render_welcome() -> str:
    """Render the full welcome screen as a string."""
    lines = []
    w = 70  # max width

    name = _get_user_name()
    greeting = _get_greeting()
    total_payloads, num_cats = _count_payloads()
    activities = _get_recent_activity()
    todo_pending, todo_done, todo_top = _get_todo_summary()

    # ── Logo ─────────────────────────────────────────────────────────────
    lines.append("")
    for line in _LOGO_LINES:
        lines.append(f"  {line}")
    lines.append("")

    # ── Greeting + version ───────────────────────────────────────────────
    lines.append(f"  {_C.BOLD}{greeting}, {_C.BCYAN}{name}{_C.R}{_C.BOLD}!{_C.R}")
    lines.append(f"  {_C.DIM}{total_payloads:,} payloads · {num_cats} categories · ready to deploy{_C.R}")
    lines.append("")

    # ── Recent Activity ──────────────────────────────────────────────────
    if activities:
        lines.append(f"  {_C.BOLD}{_C.WHITE}Recent Activity{_C.R}")
        lines.append(f"  {_C.DIM}{'─' * 50}{_C.R}")
        for act in activities[:4]:
            time_str = f"  {_C.DIM}{act['time']}{_C.R}" if act.get("time") else ""
            lines.append(f"  {act['icon']}  {act['text']}{time_str}")
        lines.append("")

    # ── TODO ─────────────────────────────────────────────────────────────
    if todo_pending > 0:
        lines.append(f"  {_C.BOLD}{_C.WHITE}TODO{_C.R}  {_C.DIM}({todo_pending} pending, {todo_done} done){_C.R}")
        lines.append(f"  {_C.DIM}{'─' * 50}{_C.R}")
        if todo_top:
            truncated = todo_top[:55] + ("..." if len(todo_top) > 55 else "")
            lines.append(f"  {_C.YELLOW}→{_C.R} {truncated}")
        lines.append(f"  {_C.DIM}  fray todo{_C.R}")
        lines.append("")

    # ── Threat Intel ─────────────────────────────────────────────────────
    ti = _get_threat_intel_summary()
    if ti["total_cves"] > 0:
        feed_status = f"  {_C.DIM}Last feed: {ti['last_feed'] or 'never'}{_C.R}" if ti["last_feed"] else ""
        lines.append(f"  {_C.BOLD}{_C.WHITE}🛡️  Threat Intelligence{_C.R}{feed_status}")
        lines.append(f"  {_C.DIM}{'─' * 50}{_C.R}")
        lines.append(
            f"  {_C.CYAN}{ti['total_cves']}{_C.R} CVEs tracked  "
            f"{_C.GREEN}●{_C.R} {_C.GREEN}{ti['cves_with_poc']}{_C.R} with real PoC  "
            f"{_C.DIM}{ti['total_poc_payloads']} exploit payloads{_C.R}"
        )
        if ti["recent_cves"]:
            lines.append(f"  {_C.DIM}Recently enriched:{_C.R}")
            for cve in ti["recent_cves"][:4]:
                src = cve.get("source", "")
                if src in ("generic", "nvd_template"):
                    badge = f"{_C.DIM}template{_C.R}"
                else:
                    badge = f"{_C.GREEN}real PoC{_C.R}"
                lines.append(
                    f"    {_C.RED}▸{_C.R} {_C.BOLD}{cve['cve_id']}{_C.R}  "
                    f"{cve['poc_count']} payloads [{badge}]"
                )
        lines.append(f"  {_C.DIM}  Auto-updated via: NVD · CISA KEV · ExploitDB · GitHub · Nuclei{_C.R}")
        lines.append(f"  {_C.DIM}  Run manually: fray feed --auto-add{_C.R}")
        lines.append("")

    # ── What's New ─────────────────────────────────────────────────────────
    lines.append(f"  {_C.BOLD}{_C.WHITE}What's New{_C.R}")
    lines.append(f"  {_C.DIM}{'─' * 50}{_C.R}")
    for feat_name, feat_cmd, feat_desc in _WHATS_NEW[:4]:
        lines.append(f"  {_C.GREEN}●{_C.R} {_C.BOLD}{feat_name}{_C.R}  {_C.DIM}— {feat_desc}{_C.R}")
    lines.append("")

    # ── Quick Start ──────────────────────────────────────────────────────
    lines.append(f"  {_C.BOLD}{_C.WHITE}Quick Start{_C.R}")
    lines.append(f"  {_C.DIM}{'─' * 50}{_C.R}")
    cmds = [
        ("fray go <url>", "Guided pipeline (recon→test→report)"),
        ("fray recon <url>", "Reconnaissance & fingerprinting"),
        ("fray test <url>", "Test WAF with payloads"),
        ("fray scan <url>", "Auto crawl → discover → inject"),
        ("fray agent <url>", "Self-improving payload agent"),
        ("fray detect <url>", "Identify the WAF vendor"),
    ]
    for cmd, desc in cmds:
        lines.append(f"  {_C.BCYAN}{cmd:<28s}{_C.R} {_C.DIM}{desc}{_C.R}")
    lines.append("")

    # ── More Commands ────────────────────────────────────────────────────
    lines.append(f"  {_C.DIM}More: fray bypass, fray smuggle, fray osint, fray bounty, fray feed{_C.R}")
    lines.append(f"  {_C.DIM}Auth: --cookie, --bearer, --auth-profile, --login-flow{_C.R}")
    lines.append(f"  {_C.DIM}Pipe: cat targets.txt | fray detect  (works like httpx){_C.R}")
    lines.append(f"  {_C.DIM}Full help: fray help{_C.R}")
    lines.append("")

    # ── Tip of the day ───────────────────────────────────────────────────
    tip_raw = random.choice(_TIPS)
    tip = tip_raw.replace("{B}", _C.BOLD).replace("{R}", _C.R).replace("{C}", _C.CYAN).replace("{T}", _C.BCYAN)
    lines.append(f"  {_C.DIM}💡 Tip:{_C.R} {tip}")
    lines.append("")

    # ── Footer ───────────────────────────────────────────────────────────
    lines.append(f"  {_C.DIM}──────────────────────────────────────────────────{_C.R}")
    lines.append(f"  {_C.BCYAN}📖 Docs:{_C.R}   https://dalisec.io/docs/#quickstart")
    lines.append(f"  {_C.DIM}🔗 GitHub:{_C.R} https://github.com/dalisecurity/fray")
    lines.append(f"  {_C.DIM}⚠  Only test systems you own or have written permission to test.{_C.R}")
    lines.append("")

    return "\n".join(lines)


def print_welcome():
    """Print the welcome screen to stdout."""
    print(render_welcome())
