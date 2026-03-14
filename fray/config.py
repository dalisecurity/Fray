#!/usr/bin/env python3
"""
Fray Config — Load defaults from .fray.toml

Searches for .fray.toml in CWD, then home directory.
CLI arguments always override config file values.

Example .fray.toml:

    [env]
    GITHUB_TOKEN = "ghp_xxxx..."
    OPENAI_API_KEY = "sk-..."

    [test]
    timeout = 10
    delay = 0.3
    category = "xss"
    insecure = false
    verbose = false
    redirect_limit = 5

    [test.auth]
    cookie = "session=abc123"
    bearer = "eyJ..."

    [bounty]
    max = 20
    workers = 4
    delay = 0.5

    [webhook]
    url = "https://hooks.slack.com/services/..."
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]

_CONFIG_FILENAME = ".fray.toml"


def find_config() -> Optional[Path]:
    """Search for .fray.toml in CWD then home directory."""
    cwd_config = Path.cwd() / _CONFIG_FILENAME
    if cwd_config.is_file():
        return cwd_config
    home_config = Path.home() / _CONFIG_FILENAME
    if home_config.is_file():
        return home_config
    return None


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and return config dict from .fray.toml. Returns {} if not found."""
    if tomllib is None:
        return {}
    config_path = path or find_config()
    if config_path is None:
        return {}
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def load_env_from_config(config: Optional[Dict[str, Any]] = None) -> None:
    """Load env vars from .fray.toml [env] section.

    Only sets variables that are NOT already in the environment,
    so real env vars always take precedence.
    Also checks GH_TOKEN as a fallback for GITHUB_TOKEN.
    """
    if config is None:
        config = load_config()
    env_section = config.get("env", {})
    if isinstance(env_section, dict):
        for key, value in env_section.items():
            if key not in os.environ and isinstance(value, str):
                os.environ[key] = value

    # GH_TOKEN → GITHUB_TOKEN fallback (GitHub CLI convention)
    if not os.environ.get("GITHUB_TOKEN") and os.environ.get("GH_TOKEN"):
        os.environ["GITHUB_TOKEN"] = os.environ["GH_TOKEN"]


_CONFIG_SCHEMA: Dict[str, Dict[str, Any]] = {
    "env": {"_type": "dict", "_value_type": "str"},
    "test": {
        "timeout": {"_type": "int", "_min": 1, "_max": 300},
        "delay": {"_type": "float", "_min": 0.0, "_max": 60.0},
        "category": {"_type": "str"},
        "insecure": {"_type": "bool"},
        "verbose": {"_type": "bool"},
        "redirect_limit": {"_type": "int", "_min": 0, "_max": 20},
        "stealth": {"_type": "bool"},
        "method": {"_type": "str", "_choices": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
        "impersonate": {"_type": "str"},
        "solve_challenge": {"_type": "bool"},
        "auth": {
            "cookie": {"_type": "str"},
            "bearer": {"_type": "str"},
        },
    },
    "scan": {
        "timeout": {"_type": "int", "_min": 1, "_max": 300},
        "delay": {"_type": "float", "_min": 0.0, "_max": 60.0},
        "category": {"_type": "str"},
        "depth": {"_type": "int", "_min": 1, "_max": 10},
        "max_pages": {"_type": "int", "_min": 1, "_max": 500},
        "max_payloads": {"_type": "int", "_min": 1, "_max": 5000},
        "workers": {"_type": "int", "_min": 1, "_max": 32},
        "parallel": {"_type": "int", "_min": 0, "_max": 50},
        "follow_redirects": {"_type": "bool"},
        "baseline": {"_type": "bool"},
        "insecure": {"_type": "bool"},
        "stealth": {"_type": "bool"},
        "impersonate": {"_type": "str"},
        "auto_throttle": {"_type": "bool"},
    },
    "bypass": {
        "timeout": {"_type": "int", "_min": 1, "_max": 300},
        "delay": {"_type": "float", "_min": 0.0, "_max": 60.0},
        "max": {"_type": "int", "_min": 1, "_max": 5000},
        "mutations": {"_type": "int", "_min": 1, "_max": 100},
        "mutation_budget": {"_type": "int", "_min": 1, "_max": 500},
        "category": {"_type": "str"},
        "waf": {"_type": "str"},
        "param": {"_type": "str"},
        "insecure": {"_type": "bool"},
        "stealth": {"_type": "bool"},
        "impersonate": {"_type": "str"},
        "jitter": {"_type": "float", "_min": 0.0, "_max": 60.0},
        "rate_limit": {"_type": "float", "_min": 0.0},
    },
    "go": {
        "deep": {"_type": "bool"},
        "stealth": {"_type": "bool"},
        "impersonate": {"_type": "str"},
        "solve_challenge": {"_type": "bool"},
        "output": {"_type": "str"},
    },
    "recon": {
        "timeout": {"_type": "int", "_min": 1, "_max": 300},
        "deep": {"_type": "bool"},
        "fast": {"_type": "bool"},
    },
    "bounty": {
        "max": {"_type": "int", "_min": 1},
        "workers": {"_type": "int", "_min": 1, "_max": 32},
        "delay": {"_type": "float", "_min": 0.0},
        "platform": {"_type": "str", "_choices": ["hackerone", "bugcrowd"]},
    },
    "agent": {
        "rounds": {"_type": "int", "_min": 1, "_max": 50},
        "budget": {"_type": "int", "_min": 1, "_max": 5000},
        "category": {"_type": "str"},
        "ai": {"_type": "bool"},
    },
    "auth": {
        "cookie": {"_type": "str"},
        "bearer": {"_type": "str"},
        "login_url": {"_type": "str"},
        "username": {"_type": "str"},
        "password": {"_type": "str"},
        "session_file": {"_type": "str"},
    },
    "targets": {"_type": "list"},
    "profiles": {"_type": "dict"},
    "webhook": {
        "url": {"_type": "str"},
    },
    "theme": {"_type": "str", "_choices": ["dark", "light", "hacker", "minimal", "none"]},
}


def validate_config(config: Optional[Dict[str, Any]] = None,
                    path: Optional[Path] = None) -> list:
    """Validate .fray.toml config against known schema (#185).

    Returns a list of warning strings. Empty list = valid.
    """
    if config is None:
        config = load_config(path)
    if not config:
        return []

    warnings: list = []

    def _check(schema: dict, data: dict, prefix: str = "") -> None:
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if key.startswith("_"):
                continue

            if key not in schema:
                warnings.append(f"Unknown key: '{full_key}'")
                continue

            spec = schema[key]

            # Nested section
            if isinstance(spec, dict) and "_type" not in spec:
                if isinstance(value, dict):
                    _check(spec, value, full_key)
                else:
                    warnings.append(f"'{full_key}' should be a table/section, got {type(value).__name__}")
                continue

            # Type check
            expected = spec.get("_type", "")
            type_map = {"str": str, "int": int, "float": (int, float), "bool": bool, "dict": dict}
            expected_types = type_map.get(expected)
            if expected_types and not isinstance(value, expected_types):
                warnings.append(f"'{full_key}': expected {expected}, got {type(value).__name__}")
                continue

            # Range checks
            if "_min" in spec and isinstance(value, (int, float)):
                if value < spec["_min"]:
                    warnings.append(f"'{full_key}': {value} < minimum {spec['_min']}")
            if "_max" in spec and isinstance(value, (int, float)):
                if value > spec["_max"]:
                    warnings.append(f"'{full_key}': {value} > maximum {spec['_max']}")

            # Choice check
            if "_choices" in spec and isinstance(value, str):
                if value not in spec["_choices"]:
                    warnings.append(f"'{full_key}': '{value}' not in {spec['_choices']}")

    _check(_CONFIG_SCHEMA, config)
    return warnings


def apply_config_defaults(args, config: Dict[str, Any], section: str) -> None:
    """Apply config defaults to argparse Namespace. CLI args take precedence.

    For boolean flags (store_true), the CLI default is False — so if the flag
    is False we apply the config value. For other types, we check against None.
    """
    section_config = config.get(section, {})
    if not isinstance(section_config, dict):
        return

    # Also apply [auth] section to all commands
    auth_config = config.get("auth", {})
    if isinstance(auth_config, dict):
        section_config = {**section_config}  # shallow copy
        # Merge auth into section (section keys win)
        for k, v in auth_config.items():
            if k not in section_config:
                section_config[k] = v

    # Flatten nested dicts (e.g. [test.auth] -> cookie, bearer)
    flat: Dict[str, Any] = {}
    for k, v in section_config.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[sub_k] = sub_v
        else:
            flat[k] = v

    for key, value in flat.items():
        attr = key.replace("-", "_")
        current = getattr(args, attr, None)
        # Only apply if CLI didn't set it (None for optional, False for store_true)
        if current is None or current is False:
            setattr(args, attr, value)


def get_profile(config: Dict[str, Any], profile_name: str) -> Dict[str, Any]:
    """Get a named profile from config. Returns {} if not found.

    Profiles are defined under [profiles.<name>] and can override any setting.
    Example:
        [profiles.stealth]
        stealth = true
        delay = 1.0
        impersonate = "chrome"
        parallel = 2

        [profiles.aggressive]
        parallel = 10
        delay = 0.0
        workers = 4
    """
    profiles = config.get("profiles", {})
    if not isinstance(profiles, dict):
        return {}
    return profiles.get(profile_name, {})


def apply_profile(args, config: Dict[str, Any], profile_name: str) -> None:
    """Apply a named profile to argparse Namespace. Profile overrides config defaults."""
    profile = get_profile(config, profile_name)
    if not profile:
        return
    for key, value in profile.items():
        attr = key.replace("-", "_")
        setattr(args, attr, value)


def get_targets(config: Dict[str, Any]) -> list:
    """Get target list from config. Returns [].

    Example:
        targets = [
            "https://target1.com",
            "https://target2.com",
            "https://staging.target1.com",
        ]
    """
    targets = config.get("targets", [])
    if isinstance(targets, list):
        return [str(t) for t in targets if t]
    return []


def init_config(path: Optional[Path] = None, force: bool = False) -> Path:
    """Create a starter .fray.toml in CWD or specified path.

    Returns the path to the created config file.
    Raises FileExistsError if file exists and force is False.
    """
    target = path or (Path.cwd() / _CONFIG_FILENAME)
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists (use --force to overwrite)")

    template = '''# Fray Configuration — https://github.com/dalisecurity/Fray
# CLI arguments always override these values.

[env]
# GITHUB_TOKEN = "ghp_xxxx"
# OPENAI_API_KEY = "sk-xxxx"

# ── Global Auth (applied to all commands) ─────────────────────
[auth]
# cookie = "session=abc123"
# bearer = "eyJ..."
# login_url = "https://target.com/login"
# session_file = "~/.fray/sessions/target.json"

# ── Test Defaults ─────────────────────────────────────────────
[test]
timeout = 10
delay = 0.3
category = "xss"
insecure = false
stealth = false
# impersonate = "chrome"
# solve_challenge = false

# ── Scan Defaults ─────────────────────────────────────────────
[scan]
timeout = 8
delay = 0.5
category = "xss"
depth = 3
max_pages = 30
max_payloads = 5
workers = 1
parallel = 0
follow_redirects = false
baseline = false
insecure = false
stealth = false
# auto_throttle = true
# impersonate = "chrome"

# ── Go Pipeline Defaults ─────────────────────────────────────
[go]
deep = false
stealth = false
# impersonate = "chrome"
# solve_challenge = false

# ── Recon Defaults ───────────────────────────────────────────
[recon]
timeout = 10
deep = false
fast = false

# ── Agent Defaults ───────────────────────────────────────────
[agent]
rounds = 5
budget = 100
category = "xss"
# ai = false

# ── Bounty Defaults ──────────────────────────────────────────
[bounty]
max = 20
workers = 4
delay = 0.5
# platform = "hackerone"

# ── Webhook ──────────────────────────────────────────────────
[webhook]
# url = "https://hooks.slack.com/services/..."

# ── Targets (for fray bounty or batch scanning) ──────────────
# targets = [
#     "https://target1.com",
#     "https://target2.com",
# ]

# ── Profiles ─────────────────────────────────────────────────
# Use with: fray test --profile stealth

[profiles.stealth]
stealth = true
delay = 1.0
jitter = 0.5
impersonate = "chrome"
parallel = 2

[profiles.aggressive]
delay = 0.0
parallel = 10
workers = 4
baseline = true
follow_redirects = true

[profiles.ci]
insecure = true
parallel = 5
baseline = true

# theme = "dark"  # dark | light | hacker | minimal | none
'''
    target.write_text(template, encoding="utf-8")
    return target


def show_config(config: Optional[Dict[str, Any]] = None) -> str:
    """Return a human-readable summary of loaded config."""
    if config is None:
        config = load_config()
    if not config:
        return "No .fray.toml found."

    lines = []
    path = find_config()
    if path:
        lines.append(f"Config: {path}")
    lines.append("")

    for section, values in config.items():
        if section == "env":
            # Mask secrets
            lines.append(f"[{section}]")
            for k, v in (values if isinstance(values, dict) else {}).items():
                masked = v[:4] + "..." + v[-4:] if isinstance(v, str) and len(v) > 12 else "***"
                lines.append(f"  {k} = {masked}")
        elif isinstance(values, dict):
            lines.append(f"[{section}]")
            for k, v in values.items():
                if isinstance(v, dict):
                    lines.append(f"  [{section}.{k}]")
                    for sk, sv in v.items():
                        lines.append(f"    {sk} = {sv}")
                else:
                    lines.append(f"  {k} = {v}")
        elif isinstance(values, list):
            lines.append(f"{section} = [{len(values)} items]")
        else:
            lines.append(f"{section} = {values}")

    return "\n".join(lines)
