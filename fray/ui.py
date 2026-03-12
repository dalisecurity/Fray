"""
Fray UI — Zero-dependency ANSI terminal styling system.

Design inspired by: Vercel CLI (gradients), Railway (purple accents),
GitHub CLI (green/cyan status), Charm/lipgloss (borders), Nuclei (severity colors).

Brand colors:
  Primary:   #6366f1 (indigo-500) — Fray brand, links, accents
  Secondary: #a78bfa (violet-400) — highlights, hover states
  Surface:   #1e1b4b (indigo-950) — dark backgrounds

Severity palette:
  Critical: bright red (#ef4444)
  High:     orange (#f97316)
  Medium:   yellow (#eab308)
  Low:      blue (#3b82f6)
  Info:     dim gray

Usage:
    from fray.ui import S, banner, pill, severity_color, dim, bold, brand
    print(f"  {pill('VULNERABLE', 'red')}  {S.target}example.com{S.reset}")
    print(f"  {severity_color('critical')}5 critical findings{S.reset}")
    banner("Fray Recon", "https://example.com")
"""

from __future__ import annotations

import os
import sys


# ── Color Support Detection ───────────────────────────────────────────

def _supports_color() -> bool:
    """Detect if terminal supports ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(sys.stderr, "isatty"):
        return False
    return sys.stderr.isatty()


def _supports_256() -> bool:
    """Detect 256-color support."""
    term = os.environ.get("TERM", "")
    colorterm = os.environ.get("COLORTERM", "")
    return "256color" in term or colorterm in ("truecolor", "24bit")


def _supports_truecolor() -> bool:
    """Detect 24-bit truecolor support."""
    colorterm = os.environ.get("COLORTERM", "")
    return colorterm in ("truecolor", "24bit")


_COLOR = _supports_color()
_TC = _supports_truecolor()


# ── ANSI Escape Helpers ───────────────────────────────────────────────

def _fg(r: int, g: int, b: int) -> str:
    if not _COLOR:
        return ""
    if _TC:
        return f"\033[38;2;{r};{g};{b}m"
    # Fallback to 256-color approximation
    code = 16 + (36 * (r // 51)) + (6 * (g // 51)) + (b // 51)
    return f"\033[38;5;{code}m"


def _bg(r: int, g: int, b: int) -> str:
    if not _COLOR:
        return ""
    if _TC:
        return f"\033[48;2;{r};{g};{b}m"
    code = 16 + (36 * (r // 51)) + (6 * (g // 51)) + (b // 51)
    return f"\033[48;5;{code}m"


def _ansi(code: str) -> str:
    return f"\033[{code}m" if _COLOR else ""


# ── Style Constants ───────────────────────────────────────────────────

class S:
    """Style constants — import and use inline: f"{S.brand}text{S.reset}" """
    reset      = _ansi("0")
    bold       = _ansi("1")
    dim        = _ansi("2")
    italic     = _ansi("3")
    underline  = _ansi("4")

    # Brand colors (indigo/violet palette)
    brand      = _fg(99, 102, 241)    # #6366f1 indigo-500
    brand2     = _fg(167, 139, 250)   # #a78bfa violet-400
    accent     = _fg(129, 140, 248)   # #818cf8 indigo-400
    subtle     = _fg(99, 102, 241)    # #6366f1 (dimmed context)

    # Semantic colors
    success    = _fg(34, 197, 94)     # #22c55e green-500
    error      = _fg(239, 68, 68)     # #ef4444 red-500
    warning    = _fg(234, 179, 8)     # #eab308 yellow-500
    info       = _fg(59, 130, 246)    # #3b82f6 blue-500

    # Severity colors
    critical   = _fg(239, 68, 68)     # #ef4444 bright red
    high       = _fg(249, 115, 22)    # #f97316 orange
    medium     = _fg(234, 179, 8)     # #eab308 yellow
    low        = _fg(59, 130, 246)    # #3b82f6 blue
    info_sev   = _ansi("2")           # dim

    # Text colors
    white      = _fg(255, 255, 255)
    gray       = _fg(156, 163, 175)   # #9ca3af gray-400
    dark       = _fg(107, 114, 128)   # #6b7280 gray-500
    muted      = _ansi("2")           # dim

    # Target / URL
    target     = _fg(96, 165, 250)    # #60a5fa blue-400
    url        = _fg(96, 165, 250)

    # Background pills
    bg_brand   = _bg(99, 102, 241)    # indigo bg
    bg_success = _bg(22, 101, 52)     # green-900 bg
    bg_error   = _bg(127, 29, 29)     # red-900 bg
    bg_warning = _bg(113, 63, 18)     # yellow-900 bg
    bg_info    = _bg(30, 58, 138)     # blue-900 bg
    bg_dark    = _bg(30, 27, 75)      # indigo-950 bg


# ── High-Level Helpers ────────────────────────────────────────────────

def brand(text: str) -> str:
    """Brand-colored text."""
    return f"{S.brand}{text}{S.reset}"


def bold(text: str) -> str:
    """Bold white text."""
    return f"{S.bold}{S.white}{text}{S.reset}"


def dim(text: str) -> str:
    """Dimmed text."""
    return f"{S.dim}{text}{S.reset}"


def success(text: str) -> str:
    return f"{S.success}{text}{S.reset}"


def error(text: str) -> str:
    return f"{S.error}{text}{S.reset}"


def warning(text: str) -> str:
    return f"{S.warning}{text}{S.reset}"


def severity_color(sev: str) -> str:
    """Return ANSI escape for severity level."""
    return {
        "critical": S.critical,
        "high": S.high,
        "medium": S.medium,
        "low": S.low,
        "info": S.info_sev,
    }.get(sev.lower(), S.dim)


def sev(text: str, severity: str) -> str:
    """Color text by severity."""
    return f"{severity_color(severity)}{text}{S.reset}"


def pill(text: str, color: str = "brand") -> str:
    """Colored pill/badge: ` TEXT ` with background."""
    bg_map = {
        "brand": S.bg_brand,
        "success": S.bg_success,
        "error": S.bg_error,
        "warning": S.bg_warning,
        "info": S.bg_info,
        "red": S.bg_error,
        "green": S.bg_success,
        "yellow": S.bg_warning,
        "blue": S.bg_info,
    }
    bg = bg_map.get(color, S.bg_brand)
    return f"{bg}{S.bold}{S.white} {text} {S.reset}"


def severity_pill(sev_level: str) -> str:
    """Severity badge: ` CRITICAL `, ` HIGH `, etc."""
    color_map = {
        "critical": "red",
        "high": "warning",
        "medium": "yellow",
        "low": "blue",
        "info": "info",
    }
    color = color_map.get(sev_level.lower(), "info")
    return pill(sev_level.upper(), color)


# ── Box Drawing ───────────────────────────────────────────────────────

def _box_line(text: str, width: int, pad: bool = True) -> str:
    """Single line inside a box, with brand-colored border."""
    border = S.dark
    inner_w = width - 4
    # Count escape codes to get visual length
    visible = _visible_len(text)
    if visible > inner_w:
        text = text[:inner_w - 1] + "…"
        visible = inner_w
    padding = " " * max(0, inner_w - visible)
    return f"  {border}│{S.reset}  {text}{padding} {border}│{S.reset}\n"


def _visible_len(text: str) -> int:
    """Length of text excluding ANSI escape sequences."""
    import re
    return len(re.sub(r'\033\[[0-9;]*m', '', text))


def box_top(width: int = 62) -> str:
    return f"  {S.dark}┌{'─' * (width - 2)}┐{S.reset}\n"


def box_mid(width: int = 62) -> str:
    return f"  {S.dark}├{'─' * (width - 2)}┤{S.reset}\n"


def box_bot(width: int = 62) -> str:
    return f"  {S.dark}└{'─' * (width - 2)}┘{S.reset}\n"


def box(title: str, lines: list, width: int = 62) -> str:
    """Build a complete styled box."""
    out = box_top(width)
    out += _box_line(f"{S.bold}{S.white}{title}{S.reset}", width)
    out += box_mid(width)
    for line in lines:
        out += _box_line(line, width)
    out += box_bot(width)
    return out


# ── Banners ───────────────────────────────────────────────────────────

def banner(title: str, target: str = "", subtitle: str = "") -> str:
    """Fray branded banner with gradient-style header."""
    w = 62
    out = "\n"
    out += f"  {S.brand}{'━' * w}{S.reset}\n"
    out += f"  {S.brand}{S.bold}  ⚔  {title}{S.reset}\n"
    if target:
        out += f"  {S.gray}  Target: {S.target}{target}{S.reset}\n"
    if subtitle:
        out += f"  {S.gray}  {subtitle}{S.reset}\n"
    out += f"  {S.brand}{'━' * w}{S.reset}\n"
    return out


def phase_header(num: int, name: str, status: str = "") -> str:
    """Phase header with number badge and optional status."""
    badge = f"{S.bg_brand}{S.bold}{S.white} {num} {S.reset}"
    status_str = f"  {S.success}{status}{S.reset}" if status else ""
    line = f"\n  {badge} {S.bold}{S.white}{name}{S.reset}{status_str}\n"
    line += f"  {S.dark}{'─' * 58}{S.reset}\n"
    return line


def summary_line(label: str, value: str, color: str = "") -> str:
    """Key-value line for summaries: dim label, colored value."""
    c = getattr(S, color, "") if color else ""
    return f"  {S.gray}{label:<20}{S.reset} {c}{value}{S.reset}"


def result_line(status: str, text: str, detail: str = "") -> str:
    """Single result line with status pill."""
    if status == "vuln":
        tag = pill("VULN", "red")
    elif status == "safe":
        tag = pill("SAFE", "green")
    elif status == "skip":
        tag = f"{S.dark} SKIP {S.reset}"
    elif status == "error":
        tag = pill("ERR", "warning")
    else:
        tag = f"{S.dim}{status}{S.reset}"
    detail_str = f"  {S.dim}{detail}{S.reset}" if detail else ""
    return f"  {tag} {text}{detail_str}"


# ── Severity Summary ──────────────────────────────────────────────────

_SEV_ICONS = {
    "critical": "●",
    "high": "●",
    "medium": "●",
    "low": "●",
    "info": "○",
}


def severity_summary(counts: dict) -> str:
    """Format severity counts: ● 3 critical  ● 2 high  ● 1 medium"""
    order = ["critical", "high", "medium", "low", "info"]
    parts = []
    for s in order:
        c = counts.get(s, 0)
        if c > 0:
            icon = _SEV_ICONS.get(s, "○")
            color = severity_color(s)
            parts.append(f"{color}{icon} {c} {s}{S.reset}")
    return "  ".join(parts) if parts else f"{S.dim}No findings{S.reset}"


# ── Command Hint ──────────────────────────────────────────────────────

def cmd_hint(command: str, description: str = "") -> str:
    """Styled command suggestion: ▸ fray test ... — description"""
    desc = f"  {S.dark}— {description}{S.reset}" if description else ""
    return f"  {S.brand}▸{S.reset} {S.white}{command}{S.reset}{desc}"


def section_title(text: str) -> str:
    """Section title with brand accent line."""
    return f"\n  {S.brand}■{S.reset} {S.bold}{S.white}{text}{S.reset}\n"
