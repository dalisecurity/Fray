#!/usr/bin/env python3
"""
Fray — Color Theme Customization (#184)

Provides configurable CLI color themes via:
  - FRAY_THEME env var (dark, light, hacker, minimal, none)
  - ~/.fray/config.json {"theme": "hacker"}
  - fray --theme hacker <command>

Usage:
    from fray.themes import T
    print(f"{T.BOLD}Title{T.RESET}")
    print(f"{T.OK}Passed{T.RESET}")
    print(f"{T.FAIL}Blocked{T.RESET}")
"""

import json
import os
from pathlib import Path


# ── Theme definitions ────────────────────────────────────────────────────────

_THEMES = {
    "dark": {
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RESET": "\033[0m",
        "OK": "\033[92m",       # green
        "FAIL": "\033[91m",     # red
        "WARN": "\033[93m",     # yellow
        "INFO": "\033[96m",     # cyan
        "ACCENT": "\033[95m",   # magenta
        "HEADER": "\033[1;96m", # bold cyan
        "MUTED": "\033[2m",     # dim
    },
    "light": {
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RESET": "\033[0m",
        "OK": "\033[32m",       # dark green
        "FAIL": "\033[31m",     # dark red
        "WARN": "\033[33m",     # dark yellow
        "INFO": "\033[34m",     # blue
        "ACCENT": "\033[35m",   # dark magenta
        "HEADER": "\033[1;34m", # bold blue
        "MUTED": "\033[2m",
    },
    "hacker": {
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RESET": "\033[0m",
        "OK": "\033[92m",       # bright green
        "FAIL": "\033[91m",     # bright red
        "WARN": "\033[93m",     # bright yellow
        "INFO": "\033[92m",     # green (hacker green)
        "ACCENT": "\033[92m",   # green
        "HEADER": "\033[1;92m", # bold green
        "MUTED": "\033[2;92m",  # dim green
    },
    "minimal": {
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RESET": "\033[0m",
        "OK": "",
        "FAIL": "\033[1m",     # just bold for failures
        "WARN": "",
        "INFO": "",
        "ACCENT": "",
        "HEADER": "\033[1m",
        "MUTED": "\033[2m",
    },
    "none": {
        "BOLD": "",
        "DIM": "",
        "RESET": "",
        "OK": "",
        "FAIL": "",
        "WARN": "",
        "INFO": "",
        "ACCENT": "",
        "HEADER": "",
        "MUTED": "",
    },
}

# Default theme
_DEFAULT_THEME = "dark"


class _Theme:
    """Lazy-loaded theme object. Attributes resolve to ANSI codes."""

    def __init__(self):
        self._loaded = False
        self._codes = {}

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        name = _DEFAULT_THEME

        # Priority 1: FRAY_THEME env var
        env = os.environ.get("FRAY_THEME", "").lower().strip()
        if env and env in _THEMES:
            name = env
        else:
            # Priority 2: ~/.fray/config.json
            try:
                cfg_path = Path.home() / ".fray" / "config.json"
                if cfg_path.exists():
                    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                    t = cfg.get("theme", "").lower().strip()
                    if t and t in _THEMES:
                        name = t
            except Exception:
                pass

        # Priority 3: NO_COLOR convention
        if os.environ.get("NO_COLOR"):
            name = "none"

        # Non-TTY → no colors
        import sys
        if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
            name = "none"

        self._codes = _THEMES.get(name, _THEMES[_DEFAULT_THEME])

    def __getattr__(self, key):
        if key.startswith("_"):
            return super().__getattribute__(key)
        self._load()
        return self._codes.get(key, "")

    def set_theme(self, name: str):
        """Override theme at runtime."""
        if name in _THEMES:
            self._codes = _THEMES[name]
            self._loaded = True

    @property
    def available(self):
        return list(_THEMES.keys())


# Singleton — import and use: from fray.themes import T
T = _Theme()
