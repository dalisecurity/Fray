#!/usr/bin/env python3
"""
Fray Output — Rich-powered terminal output for beautiful CLI results.

Provides a centralized Console and helper functions used by all Fray commands.
All output goes through this module so formatting is consistent everywhere.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TransferSpeedColumn, MofNCompleteColumn
from rich.columns import Columns
from rich.theme import Theme

# ── Fray Theme ────────────────────────────────────────────────────────────

FRAY_THEME = Theme({
    # Brand
    "brand": "#6366f1",
    "brand.bold": "bold #6366f1",
    "accent": "#818cf8",
    # Status
    "blocked": "bold #ef4444",
    "passed": "bold #22c55e",
    "bypass": "bold #22c55e",
    "warning": "bold #eab308",
    "info": "bold #3b82f6",
    "dim": "dim",
    # Severity
    "sev.critical": "bold #ef4444",
    "sev.high": "bold #f97316",
    "sev.medium": "bold #eab308",
    "sev.low": "#3b82f6",
    "sev.info": "dim",
    # Score (backward compat)
    "score.critical": "bold #ef4444",
    "score.high": "bold #f97316",
    "score.medium": "bold #eab308",
    "score.low": "#3b82f6",
    "score.none": "dim",
    # Layout
    "header": "bold white",
    "target": "#60a5fa",
    "phase": "bold #818cf8",
    "muted": "#6b7280",
    "hint": "#9ca3af",
})

console = Console(theme=FRAY_THEME, highlight=False)


# ── Status Helpers ────────────────────────────────────────────────────────

def blocked_text(text: str = "BLOCKED") -> Text:
    return Text(f" {text} ", style="bold white on red")


def passed_text(text: str = "PASSED") -> Text:
    return Text(f" {text} ", style="bold white on green")


def bypass_text(text: str = "BYPASS") -> Text:
    return Text(f" {text} ", style="bold white on green")


def safe_text(text: str = "SAFE") -> Text:
    return Text(f" {text} ", style="bold white on green")


def vuln_text(text: str = "VULNERABLE") -> Text:
    return Text(f" {text} ", style="bold white on red")


def warn_text(text: str = "WARNING") -> Text:
    return Text(f" {text} ", style="bold white on yellow")


def score_style(score) -> str:
    s = float(score)
    if s >= 90:
        return "score.critical"
    elif s >= 70:
        return "score.high"
    elif s >= 40:
        return "score.medium"
    elif s > 0:
        return "score.low"
    return "score.none"


def severity_style(severity: str) -> str:
    s = severity.lower()
    if s == "critical":
        return "sev.critical"
    elif s == "high":
        return "sev.high"
    elif s == "medium":
        return "sev.medium"
    elif s == "low":
        return "sev.low"
    return "sev.info"


def grade_label(score) -> str:
    """Return severity label.  NONE only appears when score is exactly 0 (not tested)."""
    s = float(score)
    if s >= 90:
        return "CRITICAL"
    elif s >= 70:
        return "HIGH"
    elif s >= 40:
        return "MEDIUM"
    elif s > 0:
        return "LOW"
    return "NONE"


# ── Header / Banner ──────────────────────────────────────────────────────

def print_header(title: str, subtitle: str = "", target: str = ""):
    console.print()
    console.print(f"  [brand.bold]{'━' * 62}[/]")
    console.print(f"  [bold white]  ⚔  {title}[/]")
    if target:
        console.print(f"  [hint]  Target:[/] [target]{target}[/]")
    if subtitle:
        console.print(f"  [hint]  {subtitle}[/]")
    console.print(f"  [brand.bold]{'━' * 62}[/]")
    console.print()


def print_phase(number: int, text: str):
    console.print(f"  [on #6366f1 bold white] {number} [/] [bold white]{text}[/]")
    console.print(f"  [muted]{'─' * 58}[/]")


def print_verdict(vulnerable: bool, label: str = ""):
    if vulnerable:
        t = Text()
        t.append("  ")
        t.append(f" {label or 'VULNERABLE'} ", style="bold white on red")
        console.print(t)
    else:
        t = Text()
        t.append("  ")
        t.append(f" {label or 'NOT VULNERABLE'} ", style="bold white on green")
        console.print(t)


# ── Progress ──────────────────────────────────────────────────────────────

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]ETA[/]"),
        TimeRemainingColumn(compact=True),
        console=console,
    )


class _ReqSpeedColumn(TextColumn):
    """Show requests/sec based on task.speed (set via update(speed=...))."""
    def __init__(self):
        super().__init__("")

    def render(self, task) -> Text:
        speed = task.speed if task.speed is not None else 0
        return Text(f"({speed:.1f} req/s)", style="dim")


def make_scan_progress() -> Progress:
    """Progress bar with speed (req/s) + ETA — ideal for payload testing."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        MofNCompleteColumn(),
        _ReqSpeedColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]ETA[/]"),
        TimeRemainingColumn(compact=True),
        console=console,
    )


# ── Tables ────────────────────────────────────────────────────────────────

def make_results_table(title: str = "Results") -> Table:
    table = Table(title=title, show_lines=False, pad_edge=False, box=None)
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Status", width=10, justify="center")
    table.add_column("HTTP", width=5, justify="center")
    table.add_column("Description", min_width=30)
    return table


def make_summary_table() -> Table:
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
    table.add_column("Key", style="dim", width=20)
    table.add_column("Value", min_width=20)
    return table
