#!/usr/bin/env python3
"""
Fray Doctor — Environment check + auto-fix common issues

Usage:
    fray doctor          Run all checks
    fray doctor --fix    Auto-fix issues where possible

Checks:
    - Python version compatibility (3.8+)
    - Payload directory integrity (all categories present, JSON valid)
    - Network connectivity (DNS resolution, HTTPS)
    - SSL/TLS configuration
    - File permissions
    - MCP server availability
    - Optional dependency status
"""

import json
import os
import platform
import socket
import ssl
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from fray import __version__, PACKAGE_DIR, PAYLOADS_DIR


class Colors:
    """Terminal colors"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# Status constants
PASS = "pass"
WARN = "warn"
FAIL = "fail"
FIXED = "fixed"

EXPECTED_CATEGORIES = [
    "ai_prompt_injection", "api_security", "command_injection", "crlf_injection",
    "crypto_failures", "file_upload", "iot_rce", "ldap_injection", "llm_testing",
    "logging_failures", "modern_bypasses", "open-redirect", "other", "path_traversal",
    "sqli", "ssrf", "ssti", "web_shells", "wordpress", "xpath_injection", "xss", "xxe",
]


def _status_icon(status: str) -> str:
    icons = {
        PASS: f"{Colors.GREEN}OK{Colors.END}",
        WARN: f"{Colors.YELLOW}WARN{Colors.END}",
        FAIL: f"{Colors.RED}FAIL{Colors.END}",
        FIXED: f"{Colors.GREEN}FIXED{Colors.END}",
    }
    return icons.get(status, "??")


class FrayDoctor:
    """Diagnose and fix common Fray issues."""

    def __init__(self, auto_fix: bool = False, verbose: bool = False):
        self.auto_fix = auto_fix
        self.verbose = verbose
        self.checks: List[Dict] = []

    def _add(self, name: str, status: str, detail: str = "", fix_hint: str = ""):
        self.checks.append({
            "name": name,
            "status": status,
            "detail": detail,
            "fix_hint": fix_hint,
        })

    # ── Individual checks ──────────────────────────────────────────────

    def check_python_version(self):
        """Verify Python >= 3.8"""
        v = sys.version_info
        version_str = f"{v.major}.{v.minor}.{v.micro}"
        if v >= (3, 8):
            self._add("Python version", PASS, f"{version_str}")
        else:
            self._add("Python version", FAIL, f"{version_str} (requires 3.8+)",
                       fix_hint="Install Python 3.8 or newer: https://python.org/downloads/")

    def check_package_integrity(self):
        """Verify fray package files exist"""
        required_files = ["__init__.py", "cli.py", "detector.py", "tester.py", "reporter.py"]
        missing = [f for f in required_files if not (PACKAGE_DIR / f).exists()]
        if not missing:
            self._add("Package integrity", PASS, f"All {len(required_files)} core modules present")
        else:
            self._add("Package integrity", FAIL, f"Missing: {', '.join(missing)}",
                       fix_hint="Reinstall Fray: pip install --force-reinstall fray")

    def check_payloads_directory(self):
        """Verify payload categories and JSON validity"""
        if not PAYLOADS_DIR.exists():
            self._add("Payloads directory", FAIL, f"Not found: {PAYLOADS_DIR}",
                       fix_hint="Reinstall Fray: pip install --force-reinstall fray")
            return

        # Check categories
        existing = sorted([d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")])
        missing_cats = [c for c in EXPECTED_CATEGORIES if c not in existing]

        if missing_cats and self.auto_fix:
            for cat in missing_cats:
                (PAYLOADS_DIR / cat).mkdir(parents=True, exist_ok=True)
            self._add("Payload categories", FIXED,
                       f"Created {len(missing_cats)} missing directories: {', '.join(missing_cats)}")
        elif missing_cats:
            self._add("Payload categories", WARN,
                       f"Missing {len(missing_cats)} categories: {', '.join(missing_cats)}",
                       fix_hint="Run: fray doctor --fix")
        else:
            self._add("Payload categories", PASS, f"{len(existing)} categories present")

        # Validate JSON files
        invalid_files = []
        total_json = 0
        total_payloads = 0
        for cat_dir in PAYLOADS_DIR.iterdir():
            if not cat_dir.is_dir():
                continue
            for json_file in cat_dir.glob("*.json"):
                total_json += 1
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and "payloads" in data:
                        total_payloads += len(data["payloads"])
                    elif isinstance(data, list):
                        total_payloads += len(data)
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    invalid_files.append((str(json_file.relative_to(PAYLOADS_DIR)), str(e)))

        if invalid_files:
            detail = "; ".join([f"{f}: {e[:40]}" for f, e in invalid_files[:5]])
            self._add("Payload JSON validity", FAIL, f"{len(invalid_files)} invalid files — {detail}",
                       fix_hint="Fix or regenerate corrupt payload files")
        elif total_json > 0:
            self._add("Payload JSON validity", PASS, f"{total_json} files valid, {total_payloads} payloads loaded")
        else:
            self._add("Payload JSON validity", WARN, "No JSON payload files found",
                       fix_hint="Payload files may not be installed. Reinstall: pip install --force-reinstall fray")

    def check_network_connectivity(self):
        """Check DNS resolution and HTTPS connectivity"""
        test_hosts = [("github.com", 443), ("example.com", 443)]
        for host, port in test_hosts:
            try:
                socket.setdefaulttimeout(5)
                ip = socket.gethostbyname(host)
                sock = socket.create_connection((host, port), timeout=5)
                sock.close()
                self._add(f"Network: {host}", PASS, f"Resolved to {ip}, port {port} reachable")
                return  # One success is enough
            except socket.gaierror:
                self._add(f"Network: {host}", FAIL, "DNS resolution failed",
                           fix_hint="Check your internet connection and DNS settings")
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                self._add(f"Network: {host}", FAIL, f"Connection failed: {e}",
                           fix_hint="Check firewall settings or proxy configuration")

    def check_ssl_tls(self):
        """Verify SSL/TLS support"""
        try:
            ctx = ssl.create_default_context()
            protocols = []
            if hasattr(ssl, 'TLSVersion'):
                protocols.append(f"TLS available")
            openssl_ver = ssl.OPENSSL_VERSION
            self._add("SSL/TLS", PASS, f"{openssl_ver}")
        except Exception as e:
            self._add("SSL/TLS", FAIL, str(e),
                       fix_hint="Reinstall Python with SSL support or update OpenSSL")

    def check_file_permissions(self):
        """Check that payload directory and files are readable"""
        if not PAYLOADS_DIR.exists():
            return  # Already caught by check_payloads_directory

        unreadable = []
        for root, dirs, files in os.walk(PAYLOADS_DIR):
            for f in files:
                fpath = Path(root) / f
                if not os.access(fpath, os.R_OK):
                    unreadable.append(str(fpath.relative_to(PAYLOADS_DIR)))

        if unreadable and self.auto_fix:
            fixed = 0
            for rel in unreadable:
                fpath = PAYLOADS_DIR / rel
                try:
                    os.chmod(fpath, 0o644)
                    fixed += 1
                except OSError:
                    pass
            if fixed == len(unreadable):
                self._add("File permissions", FIXED, f"Fixed {fixed} files (chmod 644)")
            else:
                self._add("File permissions", WARN,
                           f"Fixed {fixed}/{len(unreadable)} files",
                           fix_hint=f"Manually fix: chmod -R 644 {PAYLOADS_DIR}")
        elif unreadable:
            self._add("File permissions", FAIL,
                       f"{len(unreadable)} unreadable files",
                       fix_hint="Run: fray doctor --fix  or  chmod -R 644 payloads/")
        else:
            self._add("File permissions", PASS, "All payload files readable")

    def check_mcp_server(self):
        """Check if MCP SDK is available"""
        try:
            import mcp  # noqa: F401
            self._add("MCP server", PASS, "mcp package installed — AI integration available")
        except ImportError:
            self._add("MCP server", WARN, "mcp package not installed (optional)",
                       fix_hint="Install for AI integration: pip install 'fray[mcp]'")

    def check_optional_deps(self):
        """Check optional dependencies that enhance Fray capabilities"""
        _OPTIONAL = [
            ("curl_cffi", "TLS fingerprint spoofing (--impersonate)",
             "pip install curl_cffi"),
            ("playwright", "Headless browser for SPA crawling (--browser)",
             "pip install playwright && playwright install chromium"),
            ("aiohttp", "Async parallel testing (--concurrency >1)",
             "pip install aiohttp"),
            ("rich", "Enhanced terminal output (tables, progress bars)",
             "pip install rich"),
        ]
        installed = []
        missing = []
        for mod, desc, install_cmd in _OPTIONAL:
            try:
                __import__(mod)
                installed.append(mod)
            except ImportError:
                missing.append((mod, desc, install_cmd))

        if not missing:
            self._add("Optional dependencies", PASS,
                       f"All {len(installed)} optional packages installed")
        else:
            names = ", ".join(m[0] for m in missing)
            self._add("Optional dependencies", WARN,
                       f"{len(missing)} optional: {names}",
                       fix_hint="; ".join(f"{m[2]}" for m in missing[:2])
                       + (" ..." if len(missing) > 2 else ""))
            if self.verbose:
                for mod, desc, cmd in missing:
                    self._add(f"  └ {mod}", WARN, desc, fix_hint=cmd)

    def check_api_keys(self):
        """Check if commonly used API keys / env vars are configured"""
        _KEYS = [
            ("GITHUB_TOKEN", "Leak search, threat intel feed, CVE monitoring"),
            ("FRAY_CF_KEY", "Cloudflare Workers AI integration"),
            ("FRAY_CF_WORKER_URL", "Cloudflare Workers AI endpoint"),
            ("RESEND_API_KEY", "Email alerts for fray monitor"),
            ("FRAY_LLM_PROVIDER", "LLM provider (cloudflare/ollama/openai)"),
        ]
        configured = []
        missing = []
        for key, desc in _KEYS:
            if os.environ.get(key):
                configured.append(key)
            else:
                missing.append((key, desc))

        if configured:
            self._add("API keys", PASS,
                       f"{len(configured)} configured: {', '.join(configured)}")
        else:
            self._add("API keys", WARN, "No API keys configured (all optional)",
                       fix_hint="Set GITHUB_TOKEN for leak search; see docs for others")

        if self.verbose and missing:
            for key, desc in missing:
                self._add(f"  └ {key}", WARN, f"Not set — {desc}",
                           fix_hint=f"export {key}=<value>")

    def check_config_file(self):
        """Check if .fray.toml exists and is valid"""
        from pathlib import Path as _Path
        config_path = _Path.cwd() / ".fray.toml"
        if not config_path.exists():
            self._add("Config file", WARN, ".fray.toml not found in current directory",
                       fix_hint="Run: fray config init")
            return

        try:
            text = config_path.read_text(encoding="utf-8")
            # Basic TOML validation (Python 3.11+ has tomllib, fallback to simple check)
            try:
                import tomllib
                tomllib.loads(text)
            except ImportError:
                try:
                    import tomli
                    tomli.loads(text)
                except ImportError:
                    # No TOML parser — just check it's not empty and has [sections]
                    if not text.strip():
                        raise ValueError("File is empty")
                    if "[" not in text:
                        raise ValueError("No TOML sections found")
            self._add("Config file", PASS, f".fray.toml valid ({len(text)} bytes)")
        except Exception as e:
            self._add("Config file", FAIL, f".fray.toml invalid: {e}",
                       fix_hint="Fix syntax or regenerate: fray config init")

    def check_fray_directory(self):
        """Check ~/.fray/ directory exists and is writable"""
        fray_dir = Path.home() / ".fray"
        if not fray_dir.exists():
            if self.auto_fix:
                try:
                    fray_dir.mkdir(parents=True, exist_ok=True)
                    self._add("Data directory", FIXED, f"Created {fray_dir}")
                except OSError as e:
                    self._add("Data directory", FAIL, f"Cannot create {fray_dir}: {e}",
                               fix_hint=f"mkdir -p {fray_dir}")
            else:
                self._add("Data directory", WARN, f"{fray_dir} does not exist",
                           fix_hint="Run: fray doctor --fix  (or mkdir -p ~/.fray)")
            return

        # Check writable
        test_file = fray_dir / ".doctor_write_test"
        try:
            test_file.write_text("ok")
            test_file.unlink()
            # Count contents
            items = list(fray_dir.iterdir())
            self._add("Data directory", PASS,
                       f"{fray_dir} writable ({len(items)} items)")
        except OSError as e:
            self._add("Data directory", FAIL, f"{fray_dir} not writable: {e}",
                       fix_hint=f"chmod 755 {fray_dir}")

    def check_latest_version(self):
        """Check if running the latest version from PyPI"""
        try:
            import urllib.request
            url = "https://pypi.org/pypi/fray/json"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            latest = data.get("info", {}).get("version", "")
            from fray import __version__
            if latest and latest != __version__:
                self._add("Fray version", WARN,
                           f"v{__version__} installed, v{latest} available",
                           fix_hint=f"pip install --upgrade fray")
            elif latest:
                self._add("Fray version", PASS, f"v{__version__} (latest)")
            else:
                self._add("Fray version", PASS, f"v{__version__} (PyPI check skipped)")
        except Exception:
            self._add("Fray version", PASS,
                       f"v{__version__} (PyPI unreachable, skipped)")

    def check_encoding(self):
        """Verify stdout encoding supports Unicode"""
        encoding = sys.stdout.encoding or "unknown"
        if encoding.lower() in ("utf-8", "utf8"):
            self._add("Terminal encoding", PASS, encoding)
        else:
            self._add("Terminal encoding", WARN, f"{encoding} (UTF-8 recommended)",
                       fix_hint="Set PYTHONIOENCODING=utf-8 or use a UTF-8 terminal")

    def check_disk_space(self):
        """Check available disk space"""
        try:
            stat = os.statvfs(str(PACKAGE_DIR))
            free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
            if free_mb > 100:
                self._add("Disk space", PASS, f"{free_mb:.0f} MB available")
            elif free_mb > 10:
                self._add("Disk space", WARN, f"{free_mb:.0f} MB available (low)",
                           fix_hint="Free up disk space for scan reports")
            else:
                self._add("Disk space", FAIL, f"{free_mb:.0f} MB available (critical)",
                           fix_hint="Free up disk space immediately")
        except (OSError, AttributeError):
            # os.statvfs not available on all platforms
            self._add("Disk space", PASS, "Check skipped (unsupported platform)")

    # ── Run all checks ─────────────────────────────────────────────────

    def run_all(self) -> List[Dict]:
        """Run all diagnostic checks"""
        self.checks = []

        self.check_python_version()
        self.check_latest_version()
        self.check_package_integrity()
        self.check_payloads_directory()
        self.check_file_permissions()
        self.check_fray_directory()
        self.check_config_file()
        self.check_network_connectivity()
        self.check_ssl_tls()
        self.check_optional_deps()
        self.check_mcp_server()
        self.check_api_keys()
        self.check_encoding()
        self.check_disk_space()

        return self.checks

    def print_report(self):
        """Print formatted diagnostic report"""
        print(f"\n{Colors.BOLD}Fray Doctor v{__version__}{Colors.END}")
        print(f"{Colors.DIM}{'─' * 56}{Colors.END}")
        print(f"{Colors.DIM}Environment: Python {platform.python_version()} | "
              f"{platform.system()} {platform.release()}{Colors.END}\n")

        for check in self.checks:
            icon = _status_icon(check["status"])
            detail = f"  {Colors.DIM}{check['detail']}{Colors.END}" if check["detail"] else ""
            print(f"  [{icon}]  {check['name']}{detail}")

            if check["status"] in (FAIL, WARN) and check.get("fix_hint") and self.verbose:
                print(f"         {Colors.BLUE}Fix: {check['fix_hint']}{Colors.END}")

        # Summary
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["status"] in (PASS, FIXED))
        warnings = sum(1 for c in self.checks if c["status"] == WARN)
        failures = sum(1 for c in self.checks if c["status"] == FAIL)
        fixed = sum(1 for c in self.checks if c["status"] == FIXED)

        print(f"\n{Colors.DIM}{'─' * 56}{Colors.END}")

        parts = [f"{Colors.GREEN}{passed} passed{Colors.END}"]
        if fixed:
            parts.append(f"{Colors.GREEN}{fixed} fixed{Colors.END}")
        if warnings:
            parts.append(f"{Colors.YELLOW}{warnings} warnings{Colors.END}")
        if failures:
            parts.append(f"{Colors.RED}{failures} failures{Colors.END}")

        print(f"  {total} checks: {', '.join(parts)}")

        if failures > 0:
            print(f"\n  {Colors.RED}Some checks failed.{Colors.END} Run with --fix to auto-repair, "
                  f"or -v for detailed hints.")
        elif warnings > 0 and not self.verbose:
            print(f"\n  {Colors.DIM}Run with -v for fix suggestions.{Colors.END}")
        else:
            print(f"\n  {Colors.GREEN}Fray is ready to use.{Colors.END}")

        print()


def run_doctor(auto_fix: bool = False, verbose: bool = False,
               json_mode: bool = False):
    """Entry point for fray doctor command"""
    doctor = FrayDoctor(auto_fix=auto_fix, verbose=verbose)
    doctor.run_all()
    if json_mode:
        import json as _json
        result = {
            "version": __version__,
            "checks": doctor.checks,
            "summary": {
                "total": len(doctor.checks),
                "passed": sum(1 for c in doctor.checks if c["status"] in (PASS, FIXED)),
                "warnings": sum(1 for c in doctor.checks if c["status"] == WARN),
                "failures": sum(1 for c in doctor.checks if c["status"] == FAIL),
            },
        }
        print(_json.dumps(result, indent=2))
    else:
        doctor.print_report()
    return doctor.checks
