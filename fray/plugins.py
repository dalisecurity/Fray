"""
Fray Plugin / Extension API (#163) — Decorator-based hook system.

Allows external scripts and community extensions to hook into Fray's
request/response/finding pipeline without modifying core code.

Hooks:
    @fray_hook("on_request")        — Called before each HTTP request is sent.
    @fray_hook("on_response")       — Called after each HTTP response is received.
    @fray_hook("on_finding")        — Called when a vulnerability finding is recorded.
    @fray_hook("on_scan_start")     — Called when a scan begins.
    @fray_hook("on_scan_end")       — Called when a scan completes.
    @fray_hook("on_recon_complete")  — Called after recon pipeline finishes.
    @fray_hook("on_payload_tested")  — Called after each payload test (blocked/passed).
    @fray_hook("on_report_generate") — Called before report generation (modify data).
    @fray_hook("custom_check")       — Run custom security checks during scan.
    @fray_hook("custom_payloads")    — Supply additional payloads for a category.

Plugin metadata (optional module-level attributes):
    PLUGIN_NAME = "My Plugin"        # Display name
    PLUGIN_VERSION = "1.0.0"         # SemVer
    PLUGIN_AUTHOR = "author"         # Author name
    PLUGIN_DESCRIPTION = "..."       # Short description

Usage:
    # my_plugin.py
    from fray.plugins import fray_hook

    PLUGIN_NAME = "Request Logger"
    PLUGIN_VERSION = "1.0.0"

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

Auto-discovery:
    ~/.fray/plugins/*.py     — User plugins (auto-loaded)
    ./plugins/*.py           — Project plugins (auto-loaded)
    .fray.toml [plugins]     — paths = ["path/to/plugin.py"]
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
    "on_recon_complete",
    "on_payload_tested",
    "on_report_generate",
    "custom_check",
    "custom_payloads",
})

# ── Registry ─────────────────────────────────────────────────────────────────

_registry: Dict[str, List[Callable]] = {h: [] for h in HOOK_TYPES}
_registry_lock = threading.Lock()
_loaded_plugins: List[Dict[str, Any]] = []  # [{path, name, version, author, desc, hooks}]

_PLUGINS_DIR = Path.home() / ".fray" / "plugins"
_PROJECT_PLUGINS_DIR = Path("plugins")


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

    # Extract plugin metadata
    meta = {
        "path": str(p),
        "name": getattr(module, "PLUGIN_NAME", p.stem),
        "version": getattr(module, "PLUGIN_VERSION", ""),
        "author": getattr(module, "PLUGIN_AUTHOR", ""),
        "description": getattr(module, "PLUGIN_DESCRIPTION", ""),
        "hooks": [k for k, v in _registry.items()
                  if any(getattr(fn, '_fray_source', '') == str(p) for fn in v)],
    }
    # Tag hooks with source file
    with _registry_lock:
        for hook_list in _registry.values():
            for fn in hook_list:
                if not hasattr(fn, '_fray_source'):
                    fn._fray_source = str(p)

    _loaded_plugins.append(meta)
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


def auto_discover() -> int:
    """Auto-discover and load plugins from standard locations.

    Searches (in order):
        1. ~/.fray/plugins/*.py
        2. ./plugins/*.py (project-local)
        3. .fray.toml [plugins] paths

    Returns:
        Number of plugins loaded.
    """
    dirs: List[str] = []

    # 1. User plugins
    if _PLUGINS_DIR.is_dir():
        dirs.append(str(_PLUGINS_DIR))

    # 2. Project plugins
    project_dir = _PROJECT_PLUGINS_DIR.resolve()
    if project_dir.is_dir():
        dirs.append(str(project_dir))

    # 3. Config-specified plugin paths
    try:
        from fray.config import load_config
        config = load_config()
        plugin_cfg = config.get("plugins", {})
        if isinstance(plugin_cfg, dict):
            extra_paths = plugin_cfg.get("paths", [])
            if isinstance(extra_paths, list):
                dirs.extend(str(p) for p in extra_paths if p)
    except Exception:
        pass

    if not dirs:
        return 0

    return load_plugins(dirs)


# ── Introspection ────────────────────────────────────────────────────────────

def list_hooks() -> Dict[str, int]:
    """Return a dict of {hook_type: handler_count}."""
    with _registry_lock:
        return {h: len(handlers) for h, handlers in _registry.items()}


def list_plugins() -> List[Dict[str, Any]]:
    """Return list of loaded plugin metadata dicts."""
    return list(_loaded_plugins)


def get_custom_payloads(category: str) -> List[str]:
    """Collect additional payloads from custom_payloads hooks.

    Plugins return a list of payload strings for the given category.
    """
    with _registry_lock:
        handlers = list(_registry.get("custom_payloads", []))

    payloads: List[str] = []
    for handler in handlers:
        try:
            result = handler({"category": category})
            if isinstance(result, list):
                payloads.extend(str(p) for p in result)
        except Exception as e:
            name = getattr(handler, "__name__", repr(handler))
            sys.stderr.write(f"  [plugin] custom_payloads/{name}: {e}\n")
    return payloads


def run_custom_checks(target: str, context: Dict[str, Any]) -> List[Dict]:
    """Run all custom_check hooks and collect findings.

    Each handler receives {target, ...context} and returns a list of
    finding dicts: [{title, severity, description, ...}].
    """
    with _registry_lock:
        handlers = list(_registry.get("custom_check", []))

    findings: List[Dict] = []
    for handler in handlers:
        try:
            event = {"target": target, **context}
            result = handler(event)
            if isinstance(result, list):
                findings.extend(result)
        except Exception as e:
            name = getattr(handler, "__name__", repr(handler))
            sys.stderr.write(f"  [plugin] custom_check/{name}: {e}\n")
    return findings


def clear() -> None:
    """Remove all registered hooks and loaded plugins (for testing)."""
    with _registry_lock:
        for h in _registry:
            _registry[h].clear()
    _loaded_plugins.clear()


# ── Plugin scaffold ────────────────────────────────────────────────────────

_PLUGIN_TEMPLATE = '''"""Fray Plugin — {name}

Drop this file in ~/.fray/plugins/ or ./plugins/ for auto-loading.
Or load explicitly: fray test <url> --plugin {filename}
"""
from fray.plugins import fray_hook

PLUGIN_NAME = "{name}"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = ""
PLUGIN_DESCRIPTION = "{description}"


@fray_hook("on_scan_start")
def on_start(event):
    """Called when a scan begins."""
    print(f"[{name}] Scan started: {{event.get(\'target\', \'\')}}")


@fray_hook("on_finding")
def on_finding(event):
    """Called when a vulnerability finding is recorded."""
    if not event.get("blocked"):
        print(f"[{name}] BYPASS: {{event.get(\'payload\', \'\')[:60]}}")


@fray_hook("on_scan_end")
def on_end(event):
    """Called when a scan completes."""
    total = event.get("total", 0)
    passed = event.get("passed", 0)
    print(f"[{name}] Scan complete: {{passed}}/{{total}} passed")


# Uncomment to add custom security checks:
# @fray_hook("custom_check")
# def my_check(event):
#     """Custom security check. Return list of finding dicts."""
#     target = event["target"]
#     return [{{
#         "title": "Custom Check Finding",
#         "severity": "medium",
#         "description": f"Found issue on {{target}}",
#     }}]

# Uncomment to supply custom payloads:
# @fray_hook("custom_payloads")
# def my_payloads(event):
#     """Return extra payloads for a category."""
#     category = event.get("category", "")
#     if category == "xss":
#         return ["<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
#     return []
'''


def init_plugin(name: str, directory: Optional[Path] = None,
                description: str = "") -> Path:
    """Scaffold a new plugin file.

    Args:
        name: Plugin name (used as filename and display name).
        directory: Where to create the file. Default: ~/.fray/plugins/

    Returns:
        Path to the created plugin file.
    """
    target_dir = directory or _PLUGINS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    filename = name.lower().replace(" ", "_").replace("-", "_")
    if not filename.endswith(".py"):
        filename += ".py"
    filepath = target_dir / filename

    if filepath.exists():
        raise FileExistsError(f"Plugin already exists: {filepath}")

    content = _PLUGIN_TEMPLATE.format(
        name=name,
        filename=filename,
        description=description or f"Custom plugin: {name}",
    )
    filepath.write_text(content, encoding="utf-8")
    return filepath


def install_plugin(source: str, target_dir: Optional[Path] = None) -> Path:
    """Install a plugin file to the plugins directory.

    Args:
        source: Path to the .py file to install.
        target_dir: Where to copy. Default: ~/.fray/plugins/

    Returns:
        Path to the installed plugin.
    """
    import shutil
    src = Path(source).resolve()
    if not src.is_file() or not src.suffix == ".py":
        raise ValueError(f"Source must be a .py file: {source}")

    dest_dir = target_dir or _PLUGINS_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(str(src), str(dest))
    return dest
