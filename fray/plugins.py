"""
Fray Plugin / Extension API (#163) — Decorator-based hook system.

Allows external scripts and community extensions to hook into Fray's
request/response/finding pipeline without modifying core code.

Hooks:
    @fray_hook("on_request")      — Called before each HTTP request is sent.
    @fray_hook("on_response")     — Called after each HTTP response is received.
    @fray_hook("on_finding")      — Called when a vulnerability finding is recorded.
    @fray_hook("on_scan_start")   — Called when a scan begins.
    @fray_hook("on_scan_end")     — Called when a scan completes.

Usage:
    # my_plugin.py
    from fray.plugins import fray_hook

    @fray_hook("on_request")
    def log_request(event):
        print(f"[plugin] → {event['method']} {event['url']}")

    @fray_hook("on_response")
    def check_response(event):
        if event["status"] == 403:
            print(f"[plugin] BLOCKED: {event['url']}")

    @fray_hook("on_finding")
    def slack_notify(event):
        # Send to Slack, Jira, etc.
        pass

Loading plugins:
    fray test <url> --plugin my_plugin.py
    fray test <url> --plugin ./plugins/          # load all .py in dir
    FRAY_PLUGINS=my_plugin.py,other.py fray test <url>
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ── Hook types ───────────────────────────────────────────────────────────────

HOOK_TYPES = frozenset({
    "on_request",
    "on_response",
    "on_finding",
    "on_scan_start",
    "on_scan_end",
})

# ── Registry ─────────────────────────────────────────────────────────────────

_registry: Dict[str, List[Callable]] = {h: [] for h in HOOK_TYPES}
_registry_lock = threading.Lock()
_loaded_plugins: List[str] = []


def fray_hook(hook_type: str) -> Callable:
    """Decorator to register a function as a Fray plugin hook.

    Args:
        hook_type: One of 'on_request', 'on_response', 'on_finding',
                   'on_scan_start', 'on_scan_end'.

    Example:
        @fray_hook("on_finding")
        def my_handler(event: dict):
            print(event)
    """
    if hook_type not in HOOK_TYPES:
        raise ValueError(
            f"Unknown hook type '{hook_type}'. "
            f"Must be one of: {', '.join(sorted(HOOK_TYPES))}"
        )

    def decorator(fn: Callable) -> Callable:
        with _registry_lock:
            _registry[hook_type].append(fn)
        fn._fray_hook = hook_type
        return fn

    return decorator


# ── Dispatch ─────────────────────────────────────────────────────────────────

def emit(hook_type: str, event: Dict[str, Any]) -> None:
    """Fire all registered handlers for a hook type.

    Handlers run synchronously in registration order. Exceptions in
    individual handlers are caught and printed to stderr — they never
    crash the core Fray pipeline.

    Args:
        hook_type: The hook to fire.
        event:     Dict with event-specific keys (see below).

    Event schemas:
        on_request:
            method, url, headers, payload, param, target

        on_response:
            method, url, status, headers, body_length, elapsed_ms,
            blocked, target

        on_finding:
            target, category, payload, status, blocked, reflected,
            bypass_confidence, description, severity

        on_scan_start:
            target, total_payloads, method, param, waf_vendor

        on_scan_end:
            target, total, blocked, passed, elapsed_s, waf_vendor
    """
    if hook_type not in HOOK_TYPES:
        return

    with _registry_lock:
        handlers = list(_registry[hook_type])

    if not handlers:
        return

    for handler in handlers:
        try:
            handler(event)
        except Exception as e:
            name = getattr(handler, "__name__", repr(handler))
            sys.stderr.write(f"  [plugin] {hook_type}/{name}: {e}\n")


# ── Plugin loader ────────────────────────────────────────────────────────────

def load_plugin(path: str) -> str:
    """Load a single plugin .py file.

    The file is imported as a module. Any @fray_hook decorators inside
    will auto-register handlers during import.

    Args:
        path: Path to a .py file.

    Returns:
        Module name that was loaded.

    Raises:
        FileNotFoundError: If path doesn't exist.
        Exception: If the module fails to import.
    """
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Plugin not found: {path}")
    if not p.suffix == ".py":
        raise ValueError(f"Plugin must be a .py file: {path}")

    module_name = f"fray_plugin_{p.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(p))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load plugin: {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    _loaded_plugins.append(str(p))
    return module_name


def load_plugins(paths: Optional[List[str]] = None) -> int:
    """Load plugins from a list of paths and/or FRAY_PLUGINS env var.

    Each path can be:
        - A .py file → loaded directly
        - A directory → all .py files inside are loaded

    Also reads FRAY_PLUGINS env var (comma-separated paths).

    Args:
        paths: Optional list of file/directory paths.

    Returns:
        Number of plugins loaded.
    """
    all_paths: List[str] = []

    # From argument
    if paths:
        all_paths.extend(paths)

    # From environment
    env_plugins = os.environ.get("FRAY_PLUGINS", "")
    if env_plugins:
        all_paths.extend(p.strip() for p in env_plugins.split(",") if p.strip())

    loaded = 0
    for path in all_paths:
        p = Path(path).resolve()
        if p.is_dir():
            for py_file in sorted(p.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                try:
                    load_plugin(str(py_file))
                    loaded += 1
                except Exception as e:
                    sys.stderr.write(f"  [plugin] Failed to load {py_file.name}: {e}\n")
        elif p.is_file():
            try:
                load_plugin(str(p))
                loaded += 1
            except Exception as e:
                sys.stderr.write(f"  [plugin] Failed to load {p.name}: {e}\n")
        else:
            sys.stderr.write(f"  [plugin] Not found: {path}\n")

    return loaded


# ── Introspection ────────────────────────────────────────────────────────────

def list_hooks() -> Dict[str, int]:
    """Return a dict of {hook_type: handler_count}."""
    with _registry_lock:
        return {h: len(handlers) for h, handlers in _registry.items()}


def list_plugins() -> List[str]:
    """Return list of loaded plugin file paths."""
    return list(_loaded_plugins)


def clear() -> None:
    """Remove all registered hooks and loaded plugins (for testing)."""
    with _registry_lock:
        for h in _registry:
            _registry[h].clear()
    _loaded_plugins.clear()
