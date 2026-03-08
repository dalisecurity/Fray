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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.columns import Columns
from rich.theme import Theme

# ── Fray Theme ────────────────────────────────────────────────────────────

FRAY_THEME = Theme({
    "blocked": "bold red",
    "passed": "bold green",
    "bypass": "bold green",
    "warning": "bold yellow",
    "info": "bold cyan",
    "dim": "dim",
    "score.critical": "bold red",
    "score.high": "bold yellow",
    "score.medium": "bold blue",
    "score.low": "bold green",
    "score.none": "dim",
    "header": "bold white",
    "target": "cyan",
    "phase": "bold cyan",
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
        return "bold red"
    elif s == "high":
        return "red"
    elif s == "medium":
        return "yellow"
    elif s == "low":
        return "dim"
    return "dim"


def grade_label(score) -> str:
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
    console.rule(f"[header]{title}[/]", style="bold")
    if subtitle:
        console.print(f"  [dim]{subtitle}[/]")
    if target:
        console.print(f"  Target: [target]{target}[/]")
    console.print()


def print_phase(number: int, text: str):
    console.print(f"  [phase]Phase {number}:[/] {text}")


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
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
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
