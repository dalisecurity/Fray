#!/usr/bin/env python3
"""
Fray — Interactive Scan Wizard (#143)

Guided mode for users who don't know which flags to use.
Asks a series of questions and builds the optimal fray command.

CLI:
    fray wizard
    fray init        (alias)

Flow:
    1. What's your target? (URL or domain)
    2. What's your goal? (recon / test / bounty / full pipeline)
    3. Do you have credentials? (cookie, bearer, basic auth)
    4. How aggressive? (stealth / normal / deep)
    5. Output preferences? (HTML report, JSON, terminal)
    6. Generate and optionally execute the command
"""

import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"


# ── ANSI helpers ─────────────────────────────────────────────────────────────

B = "\033[1m"
D = "\033[2m"
R = "\033[0m"
CYN = "\033[96m"
GRN = "\033[92m"
YEL = "\033[93m"
RED = "\033[91m"
MAG = "\033[95m"


def _prompt(question: str, options: List[Tuple[str, str]],
            default: str = "1") -> str:
    """Display a numbered prompt and return the chosen key."""
    print(f"\n  {B}{question}{R}")
    for key, label in options:
        marker = f"{CYN}▸{R}" if key == default else " "
        print(f"  {marker} {D}[{key}]{R} {label}")
    while True:
        try:
            choice = input(f"\n  {D}Choice [{default}]:{R} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not choice:
            return default
        valid = [k for k, _ in options]
        if choice in valid:
            return choice
        print(f"  {YEL}Invalid choice. Options: {', '.join(valid)}{R}")


def _input(label: str, default: str = "") -> str:
    """Simple text input with default."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {D}{label}{suffix}:{R} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val or default


def _confirm(question: str, default: bool = True) -> bool:
    """Yes/no confirmation."""
    hint = "Y/n" if default else "y/N"
    try:
        val = input(f"  {D}{question} [{hint}]:{R} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not val:
        return default
    return val in ("y", "yes")


# ── Wizard Steps ─────────────────────────────────────────────────────────────

def _step_target() -> str:
    """Step 1: Get target URL or domain."""
    print(f"\n{D}{'━' * 55}{R}")
    print(f"  {MAG}{B}Fray Scan Wizard{R}  {D}v{__version__}{R}")
    print(f"{D}{'━' * 55}{R}")
    print(f"\n  {D}Answer a few questions and I'll build the perfect command.{R}")

    target = _input(f"{B}Target URL or domain{R}")
    if not target:
        print(f"  {RED}No target provided. Exiting.{R}")
        return ""

    # Normalize: add scheme if missing
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Validate URL
    parsed = urllib.parse.urlparse(target)
    if not parsed.hostname:
        print(f"  {RED}Invalid URL: {target}{R}")
        return ""

    print(f"  {GRN}Target:{R} {CYN}{target}{R}")
    return target


def _step_goal() -> str:
    """Step 2: What does the user want to do?"""
    return _prompt("What would you like to do?", [
        ("1", f"🔍 {B}Recon{R} — Discover attack surface, subdomains, tech stack"),
        ("2", f"🎯 {B}Test{R} — Test for vulnerabilities (XSS, SQLi, etc.)"),
        ("3", f"🚀 {B}Full Pipeline{R} — Recon → Test → Report (zero-knowledge)"),
        ("4", f"💰 {B}Bug Bounty{R} — Fetch scope + batch test"),
        ("5", f"🤖 {B}Agent{R} — Self-improving payload agent"),
        ("6", f"🔬 {B}WAF Analysis{R} — Reverse engineer WAF rules"),
    ], default="1")


def _step_categories() -> List[str]:
    """Step 2b: Which vuln categories to test?"""
    choice = _prompt("Which vulnerability categories?", [
        ("1", f"🎯 {B}Smart mode{R} — Auto-select based on tech stack (recommended)"),
        ("2", f"💉 {B}XSS + SQLi{R} — Most common web vulns"),
        ("3", f"🔓 {B}All categories{R} — XSS, SQLi, SSRF, SSTI, CMDi, etc."),
        ("4", f"📝 {B}Custom{R} — Choose specific categories"),
    ], default="1")

    if choice == "1":
        return ["smart"]
    elif choice == "2":
        return ["xss", "sqli"]
    elif choice == "3":
        return ["all"]
    else:
        cats = _input("Categories (comma-separated)", "xss,sqli")
        return [c.strip() for c in cats.split(",") if c.strip()]


def _step_auth() -> Dict[str, str]:
    """Step 3: Authentication."""
    has_auth = _confirm("Do you have authentication credentials?", default=False)
    if not has_auth:
        return {}

    auth_type = _prompt("Authentication type?", [
        ("1", f"🍪 {B}Cookie{R} — Session cookie string"),
        ("2", f"🔑 {B}Bearer token{R} — JWT or API token"),
        ("3", f"👤 {B}Basic auth{R} — Username:password"),
        ("4", f"📄 {B}Auth profile{R} — Load from ~/.fray/auth/ file"),
    ], default="1")

    auth: Dict[str, str] = {}
    if auth_type == "1":
        auth["cookie"] = _input("Cookie string")
    elif auth_type == "2":
        auth["bearer"] = _input("Bearer token")
    elif auth_type == "3":
        auth["basic"] = _input("Username:password")
    elif auth_type == "4":
        auth["profile"] = _input("Auth profile path", "~/.fray/auth/default.json")

    return auth


def _step_intensity() -> str:
    """Step 4: How aggressive?"""
    return _prompt("Scan intensity?", [
        ("1", f"🐱 {B}Stealth{R} — Slow, polite, evade rate limits (2s delay)"),
        ("2", f"⚡ {B}Normal{R} — Balanced speed/thoroughness (recommended)"),
        ("3", f"🔥 {B}Deep{R} — Thorough, more payloads, blind injection"),
        ("4", f"💨 {B}Quick{R} — Fast scan, fewer payloads"),
    ], default="2")


def _step_output(target: str) -> Dict[str, str]:
    """Step 5: Output preferences."""
    output: Dict[str, str] = {}

    choice = _prompt("Output format?", [
        ("1", f"🖥️  {B}Terminal only{R} — Print results to screen"),
        ("2", f"📄 {B}HTML report{R} — Beautiful interactive report"),
        ("3", f"📊 {B}JSON{R} — Machine-readable output"),
        ("4", f"📝 {B}Markdown{R} — For documentation/PRs"),
    ], default="2")

    if choice == "2":
        parsed = urllib.parse.urlparse(target)
        domain = parsed.hostname or "target"
        output["format"] = "html"
        output["file"] = _input("Report filename", f"{domain}_report.html")
    elif choice == "3":
        output["format"] = "json"
    elif choice == "4":
        output["format"] = "markdown"
        output["file"] = _input("Output filename", "report.md")
    else:
        output["format"] = "terminal"

    return output


# ── Command Builder ──────────────────────────────────────────────────────────

def build_command(
    target: str,
    goal: str,
    categories: List[str] = None,
    auth: Dict[str, str] = None,
    intensity: str = "2",
    output: Dict[str, str] = None,
) -> str:
    """Build a fray CLI command from wizard answers.

    Returns the complete command string.
    """
    categories = categories or []
    auth = auth or {}
    output = output or {}

    parts = ["fray"]

    # Command based on goal
    if goal == "1":
        parts.append("recon")
        parts.append(target)
    elif goal == "2":
        parts.append("test")
        parts.append(target)
    elif goal == "3":
        parts.append("go")
        parts.append(target)
    elif goal == "4":
        parts.append("bounty")
    elif goal == "5":
        parts.append("agent")
        parts.append(target)
    elif goal == "6":
        parts.append("waf-reverse")
        parts.append(target)

    # Categories (for test/go/agent)
    if goal in ("2", "3", "5") and categories:
        if "smart" in categories:
            parts.append("--smart")
        elif "all" in categories:
            parts.append("--all")
        else:
            parts.extend(["-c", ",".join(categories)])

    # Intensity → profile
    if intensity == "1":
        parts.append("--profile stealth")
    elif intensity == "3":
        parts.append("--profile deep")
    elif intensity == "4":
        parts.append("--profile quick")
    # "2" (normal) = default, no flag needed

    # Auth
    if auth.get("cookie"):
        parts.append(f"--cookie \"{auth['cookie']}\"")
    if auth.get("bearer"):
        parts.append(f"--bearer \"{auth['bearer']}\"")
    if auth.get("profile"):
        parts.append(f"--auth-profile {auth['profile']}")

    # Output
    fmt = output.get("format", "terminal")
    if fmt == "json":
        parts.append("--json")
    elif fmt in ("html", "markdown") and output.get("file"):
        parts.extend(["-o", output["file"]])

    return " ".join(parts)


# ── Main Wizard ──────────────────────────────────────────────────────────────

def run_wizard() -> Optional[str]:
    """Run the interactive scan wizard.

    Returns:
        The generated command string, or None if cancelled.
    """
    # Check if stdin is a terminal
    if not sys.stdin.isatty():
        print(f"  {YEL}Wizard requires interactive terminal.{R}")
        print(f"  {D}Use: fray go <url> for zero-knowledge pipeline.{R}")
        return None

    # Step 1: Target
    target = _step_target()
    if not target:
        return None

    # Step 2: Goal
    goal = _step_goal()

    # Step 2b: Categories (only for test/go/agent)
    categories: List[str] = []
    if goal in ("2", "3", "5"):
        categories = _step_categories()

    # Step 3: Auth
    auth = _step_auth()

    # Step 4: Intensity
    intensity = _step_intensity()

    # Step 5: Output
    output = _step_output(target)

    # Build command
    cmd = build_command(target, goal, categories, auth, intensity, output)

    # Display
    print(f"\n{D}{'━' * 55}{R}")
    print(f"  {B}Generated Command:{R}")
    print(f"\n  {GRN}{cmd}{R}")
    print(f"\n{D}{'━' * 55}{R}")

    # Execute?
    execute = _confirm(f"\n  {B}Execute this command now?{R}", default=True)
    if execute:
        print(f"\n  {CYN}Launching...{R}\n")
        os.system(cmd)
    else:
        print(f"\n  {D}Copy and run when ready:{R}")
        print(f"  {GRN}{cmd}{R}\n")

    return cmd


# ── Non-Interactive Quick Config ─────────────────────────────────────────────

def generate_config_from_target(target: str) -> Dict[str, Any]:
    """Generate a recommended .fray.toml config from a target URL.

    Useful for `fray init <url>` — creates optimal config without prompts.
    """
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""

    config: Dict[str, Any] = {
        "target": target,
        "recommended_commands": [],
        "config": {
            "test": {
                "timeout": 8,
                "delay": 0.3,
                "method": "GET",
            },
            "output": {
                "format": "html",
            },
        },
    }

    # Add recommended commands based on target
    config["recommended_commands"].append(
        f"fray recon {target} --profile standard")
    config["recommended_commands"].append(
        f"fray test {target} -c xss,sqli --smart")
    config["recommended_commands"].append(
        f"fray go {target}")

    # If looks like an API
    if any(kw in target.lower() for kw in ("/api", "/v1", "/v2", "/graphql")):
        config["config"]["test"]["method"] = "POST"
        config["recommended_commands"].insert(1,
            f"fray proto {target}")

    return config
