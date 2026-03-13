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
        "auth": {
            "cookie": {"_type": "str"},
            "bearer": {"_type": "str"},
        },
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
