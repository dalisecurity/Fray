#!/usr/bin/env python3
"""
Fray Dashboard — Rich terminal TUI for fray go pipeline.

Provides live-updating display with:
  - Phase progress bars
  - Finding severity feed
  - Risk gauge
  - Stats counters

Uses only ANSI escape codes — no external TUI library required.
"""

import sys
import time
import threading
from typing import Dict, List, Optional


# ── ANSI codes ────────────────────────────────────────────────────────────

class _A:
    """ANSI escape codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    HIDE_CURSOR = "\033[?25l"
    SHOW_CURSOR = "\033[?25h"
    CLEAR_LINE = "\033[2K"
    UP = "\033[A"
    SAVE = "\033[s"
    RESTORE = "\033[u"


_SEV_COLORS = {
    "critical": _A.RED,
    "high": _A.RED,
    "medium": _A.YELLOW,
    "low": _A.CYAN,
    "info": _A.GRAY,
}

_SEV_ICONS = {
    "critical": "\u25CF",  # ●
    "high": "\u25CF",
    "medium": "\u25CB",     # ○
    "low": "\u25CB",
    "info": "\u00B7",       # ·
}


def _bar(pct: float, width: int = 30) -> str:
    """Render a progress bar."""
    filled = int(pct / 100 * width)
    empty = width - filled
    bar_char = "\u2588"  # █
    empty_char = "\u2591"  # ░
    color = _A.GREEN if pct >= 100 else _A.CYAN if pct >= 50 else _A.YELLOW
    return f"{color}{bar_char * filled}{_A.GRAY}{empty_char * empty}{_A.RESET}"


def _risk_gauge(score: int) -> str:
    """Render a mini risk gauge."""
    if score >= 70:
        color, label = _A.RED, "CRITICAL"
    elif score >= 50:
        color, label = _A.YELLOW, "HIGH"
    elif score >= 30:
        color, label = _A.YELLOW, "MEDIUM"
    elif score >= 10:
        color, label = _A.GREEN, "LOW"
    else:
        color, label = _A.GREEN, "MINIMAL"

    # ASCII gauge: [====------] 75/100
    filled = int(score / 100 * 20)
    empty = 20 - filled
    gauge = f"{color}{'=' * filled}{_A.GRAY}{'-' * empty}{_A.RESET}"
    return f"[{gauge}] {color}{score}/100 {label}{_A.RESET}"


class Dashboard:
    """Live terminal dashboard for fray go pipeline.

    Usage:
        dash = Dashboard(target="example.com")
        dash.start()
        dash.set_phase(1, "Recon", total=50)
        dash.update_progress(done=10)
        dash.add_finding("XSS in /search", "high")
        dash.set_phase(2, "Testing", total=100)
        dash.set_risk(65)
        dash.finish()
    """

    def __init__(self, target: str, quiet: bool = False):
        self.target = target
        self.quiet = quiet
        self._phase = 0
        self._phase_name = ""
        self._total = 0
        self._done = 0
        self._risk_score = 0
        self._findings: List[Dict] = []
        self._stats: Dict[str, int] = {
            "subdomains": 0,
            "endpoints": 0,
            "vectors": 0,
            "bypasses": 0,
            "requests": 0,
        }
        self._start_time = time.monotonic()
        self._phase_start = time.monotonic()
        self._lock = threading.Lock()
        self._height = 0  # Lines we've written
        self._active = False
        self._out = sys.stderr

    def start(self):
        """Begin dashboard display."""
        if self.quiet:
            return
        self._active = True
        self._out.write(_A.HIDE_CURSOR)
        self._render()

    def finish(self):
        """Finalize dashboard — show summary."""
        if self.quiet:
            return
        self._active = False
        self._clear()
        elapsed = time.monotonic() - self._start_time

        self._out.write(f"\n{_A.BOLD}{_A.WHITE}  \u2694  Fray Pipeline Complete{_A.RESET}\n")
        self._out.write(f"  {_A.GRAY}{'─' * 50}{_A.RESET}\n")
        self._out.write(f"  Target:    {_A.CYAN}{self.target}{_A.RESET}\n")
        self._out.write(f"  Duration:  {_A.WHITE}{elapsed:.1f}s{_A.RESET}\n")
        self._out.write(f"  Risk:      {_risk_gauge(self._risk_score)}\n")

        sev_counts = {}
        for f in self._findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        if sev_counts:
            parts = []
            for s in ["critical", "high", "medium", "low", "info"]:
                if s in sev_counts:
                    c = _SEV_COLORS.get(s, "")
                    parts.append(f"{c}{sev_counts[s]} {s}{_A.RESET}")
            _sep = ' \u2502 '
            self._out.write(f"  Findings:  {_sep.join(parts)}\n")

        for k, v in self._stats.items():
            if v > 0:
                self._out.write(f"  {k.title():<12} {_A.WHITE}{v}{_A.RESET}\n")

        self._out.write(f"  {_A.GRAY}{'─' * 50}{_A.RESET}\n\n")
        self._out.write(_A.SHOW_CURSOR)
        self._out.flush()

    def set_phase(self, phase: int, name: str, total: int = 0):
        """Start a new pipeline phase."""
        with self._lock:
            self._phase = phase
            self._phase_name = name
            self._total = total
            self._done = 0
            self._phase_start = time.monotonic()
        if self._active:
            self._render()

    def update_progress(self, done: int = None, increment: int = 0):
        """Update progress for current phase."""
        with self._lock:
            if done is not None:
                self._done = done
            else:
                self._done += increment
        if self._active:
            self._render()

    def set_risk(self, score: int):
        """Update risk score."""
        with self._lock:
            self._risk_score = min(100, max(0, score))
        if self._active:
            self._render()

    def add_finding(self, title: str, severity: str = "info"):
        """Add a finding to the live feed."""
        with self._lock:
            self._findings.append({"title": title, "severity": severity,
                                    "time": time.monotonic() - self._start_time})
        if self._active:
            self._render()

    def update_stat(self, key: str, value: int):
        """Update a stats counter."""
        with self._lock:
            self._stats[key] = value
        if self._active:
            self._render()

    def _clear(self):
        """Clear dashboard lines."""
        if self._height > 0:
            for _ in range(self._height):
                self._out.write(f"{_A.UP}{_A.CLEAR_LINE}")
            self._height = 0

    def _render(self):
        """Render the full dashboard."""
        if self.quiet or not self._active:
            return

        with self._lock:
            self._clear()
            lines = []

            elapsed = time.monotonic() - self._start_time
            phase_elapsed = time.monotonic() - self._phase_start

            # Header
            lines.append(f"  {_A.BOLD}{_A.WHITE}\u2694  Fray{_A.RESET} "
                         f"{_A.GRAY}\u2502{_A.RESET} {_A.CYAN}{self.target}{_A.RESET} "
                         f"{_A.GRAY}\u2502 {elapsed:.0f}s{_A.RESET}")

            # Phase + progress bar
            pct = (self._done / self._total * 100) if self._total > 0 else 0
            phase_str = f"Phase {self._phase}: {self._phase_name}"
            bar = _bar(pct)
            speed = f"{self._done / phase_elapsed:.1f}/s" if phase_elapsed > 0 and self._done > 0 else ""
            eta = ""
            if self._done > 0 and self._total > self._done and phase_elapsed > 0:
                remaining = (self._total - self._done) / (self._done / phase_elapsed)
                eta = f"ETA {remaining:.0f}s" if remaining < 60 else f"ETA {remaining/60:.1f}m"

            lines.append(f"  {_A.BOLD}{phase_str}{_A.RESET}  "
                         f"{bar} {pct:.0f}%  "
                         f"{_A.GRAY}{self._done}/{self._total}  {speed}  {eta}{_A.RESET}")

            # Risk gauge
            if self._risk_score > 0:
                lines.append(f"  Risk: {_risk_gauge(self._risk_score)}")

            # Stats row
            stat_parts = []
            for k, v in self._stats.items():
                if v > 0:
                    stat_parts.append(f"{_A.WHITE}{v}{_A.RESET} {k}")
            if stat_parts:
                _sep = ' \u2502 '
                lines.append(f"  {_sep.join(stat_parts)}")

            # Finding feed (last 4)
            if self._findings:
                lines.append(f"  {_A.GRAY}{'─' * 48}{_A.RESET}")
                for f in self._findings[-4:]:
                    sev = f["severity"]
                    sc = _SEV_COLORS.get(sev, _A.GRAY)
                    icon = _SEV_ICONS.get(sev, "\u00B7")
                    t = f["title"][:55]
                    ts = f"{f['time']:.0f}s"
                    lines.append(f"  {sc}{icon}{_A.RESET} {t}  {_A.GRAY}{ts}{_A.RESET}")

            # Write
            for line in lines:
                self._out.write(f"{_A.CLEAR_LINE}{line}\n")
            self._height = len(lines)
            self._out.flush()
