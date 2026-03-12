"""
Interactive post-recon menu — analyzes findings and offers targeted next steps.

After `fray recon <target>` completes, this module presents a smart menu:

  ┌──────────────────────────────────────────────┐
  │  What would you like to do next?             │
  ├──────────────────────────────────────────────┤
  │  [1] 📄 Generate HTML Report                 │
  │  [2] 🎯 Test XSS (3 reflected params found)  │
  │  [3] 💉 Test SQLi (search endpoint, no WAF)  │
  │  [4] 🔬 Deep Scan (all vulns, smart mode)    │
  │  [5] 🚀 Auto-Pilot (report + test all)       │
  │  [q] Exit                                    │
  └──────────────────────────────────────────────┘

Options are dynamically generated based on actual recon findings.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── Severity ordering ──────────────────────────────────────────────────

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# ── Vuln type → module mapping ─────────────────────────────────────────

_VULN_MODULE_MAP = {
    "xss": ("fray.xss", "XSSScanner", "XSS (Cross-Site Scripting)"),
    "sqli": ("fray.sqli", "SQLiInjector", "SQL Injection"),
    "cmdi": ("fray.cmdi", "CMDiScanner", "Command Injection"),
    "cache_poison": ("fray.cache_poison", "CachePoisonScanner", "Cache Poisoning"),
    "massassign": ("fray.massassign", "MassAssignScanner", "Mass Assignment / HPP"),
    "deser": ("fray.deser", "DeserScanner", "Deserialization"),
    "ssrf": ("fray.ssrf", "SSRFScanner", "Server-Side Request Forgery"),
    "ssti": (None, None, "Server-Side Template Injection"),
    "prototype_pollution": (None, None, "Prototype Pollution"),
    "csp_bypass": (None, None, "CSP Bypass"),
    "modern_bypasses": (None, None, "Modern WAF Bypasses"),
}

# ── Category keywords in findings text ─────────────────────────────────

_FINDING_KEYWORDS = {
    "xss": ["xss", "cross-site", "reflected", "dom source", "dom sink", "script injection"],
    "sqli": ["sql", "injection", "database", "query", "union", "error-based"],
    "cmdi": ["command injection", "rce", "remote code", "shell", "os command"],
    "ssrf": ["ssrf", "server-side request", "internal", "redirect"],
    "ssti": ["template injection", "ssti", "jinja", "twig", "freemarker"],
    "cache_poison": ["cache", "poison", "cdn", "x-forwarded", "unkeyed header"],
    "cors": ["cors", "access-control", "origin"],
    "csp": ["csp", "content-security-policy", "unsafe-inline", "unsafe-eval"],
    "host_header": ["host header", "host injection"],
    "open_redirect": ["redirect", "open redirect"],
    "takeover": ["takeover", "dangling", "cname", "subdomain takeover"],
    "exposed": ["exposed", "admin panel", "sensitive file", "backup", ".env", "debug"],
    "tls": ["tls", "ssl", "certificate", "expired cert", "weak cipher"],
}


@dataclass
class MenuOption:
    """A single interactive menu option."""
    key: str                    # "1", "2", etc.
    emoji: str                  # Display emoji
    label: str                  # Short label
    description: str            # Why this option is recommended
    action: str                 # Action type: "report", "test", "deep", "autopilot"
    command: str                # Exact fray CLI command
    priority: int = 0           # Lower = higher priority
    vuln_types: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)


class ReconInteractive:
    """Analyze recon results and present an interactive menu of next steps."""

    def __init__(self, target: str, recon_result: dict, export_dir: str = ""):
        self.target = target
        self.recon = recon_result
        self.export_dir = export_dir
        self.atk = recon_result.get("attack_surface", {})
        self.findings = self.atk.get("findings", [])
        self.waf = self.atk.get("waf_vendor") or ""
        self.risk_score = self.atk.get("risk_score", 0)
        self.risk_level = self.atk.get("risk_level", "?")
        self.recs = recon_result.get("recommended_categories", [])
        self.vectors = self.atk.get("attack_vectors", [])
        self.hvt = self.atk.get("high_value_targets", [])
        self.suggested = self.atk.get("suggested_tests", [])
        self.subdomains = self.atk.get("subdomains", 0)

    # ── Analyze findings to determine what vulns to test ───────────────

    def _classify_findings(self) -> Dict[str, List[dict]]:
        """Group findings by vulnerability type based on keywords."""
        classified: Dict[str, List[dict]] = {}
        for f in self.findings:
            text = f.get("finding", "").lower()
            sev = f.get("severity", "info")
            matched = False
            for vuln_type, keywords in _FINDING_KEYWORDS.items():
                if any(kw in text for kw in keywords):
                    classified.setdefault(vuln_type, []).append(f)
                    matched = True
                    break
            if not matched:
                classified.setdefault("other", []).append(f)
        return classified

    def _get_injectable_params(self) -> List[Dict[str, str]]:
        """Extract injectable parameters from recon data."""
        params_data = self.recon.get("params", {})
        injectable = []
        if isinstance(params_data, dict):
            for param_name, info in params_data.items():
                if isinstance(info, dict) and info.get("injectable"):
                    injectable.append({
                        "param": param_name,
                        "url": info.get("url", self.target),
                        "method": info.get("method", "GET"),
                    })
        return injectable

    def _get_search_endpoints(self) -> List[str]:
        """Find search/query endpoints from recon."""
        endpoints = []
        # From high-value targets
        for hvt in self.hvt:
            url = hvt if isinstance(hvt, str) else hvt.get("url", "")
            if any(kw in url.lower() for kw in ["search", "query", "q=", "s=", "keyword"]):
                endpoints.append(url)
        # From attack vectors
        for vec in self.vectors:
            url = vec.get("url", "") if isinstance(vec, dict) else ""
            if any(kw in url.lower() for kw in ["search", "query", "q=", "s="]):
                endpoints.append(url)
        return list(set(endpoints))[:5]

    # ── Build smart menu options ───────────────────────────────────────

    def build_options(self) -> List[MenuOption]:
        """Generate 3-5 context-aware menu options based on findings."""
        options: List[MenuOption] = []
        classified = self._classify_findings()
        injectable = self._get_injectable_params()

        # ── Option: Generate HTML Report (always available) ────────────
        report_path = ""
        if self.export_dir:
            report_path = os.path.join(self.export_dir, "report.html")
        else:
            domain = self.recon.get("host", "target")
            report_path = f"{domain}_recon.html"

        options.append(MenuOption(
            key="1", emoji="📄", label="Generate HTML Report",
            description=f"Full recon report ({len(self.findings)} findings, risk {self.risk_score}/100)",
            action="report",
            command=f"fray recon {self.target} -o {report_path}",
            priority=10,
            params={"output": report_path},
        ))

        # ── Vuln-specific test options ─────────────────────────────────
        priority_counter = 0
        vuln_options: List[MenuOption] = []

        # Sort classified findings by highest severity
        sorted_vulns = sorted(
            classified.items(),
            key=lambda x: min(_SEV_RANK.get(f.get("severity", "info"), 4) for f in x[1])
        )

        for vuln_type, vuln_findings in sorted_vulns:
            if vuln_type == "other":
                continue

            top_sev = min(f.get("severity", "info") for f in vuln_findings)
            count = len(vuln_findings)
            emoji = _SEV_EMOJI.get(top_sev, "⚪")

            # Map to fray test category
            test_cat = vuln_type
            if vuln_type in ("cors", "host_header", "exposed", "tls", "takeover"):
                continue  # Not directly testable with payload modules

            module_info = _VULN_MODULE_MAP.get(vuln_type)
            if not module_info:
                continue

            _, _, display_name = module_info

            # Build description based on findings
            finding_texts = [f.get("finding", "")[:60] for f in vuln_findings[:2]]
            desc_parts = [f"{count} finding{'s' if count > 1 else ''}"]
            if finding_texts:
                desc_parts.append(finding_texts[0])

            # Determine target URL for the test
            test_target = self.target
            test_params = {}

            # If we have injectable params, target the best one
            if injectable and vuln_type in ("xss", "sqli", "cmdi"):
                best = injectable[0]
                test_target = best["url"]
                test_params["param"] = best["param"]

            cmd = f"fray test {self.target} -c {test_cat} --smart"
            if self.waf:
                cmd += f"  # WAF: {self.waf}"

            vuln_options.append(MenuOption(
                key="",  # Assigned later
                emoji=emoji,
                label=f"Test {display_name}",
                description=" — ".join(desc_parts),
                action="test",
                command=cmd,
                priority=priority_counter,
                vuln_types=[vuln_type],
                targets=[test_target],
                params=test_params,
            ))
            priority_counter += 1

        # If no findings-based vulns, use recommended_categories
        if not vuln_options and self.recs:
            for cat in self.recs[:3]:
                cat_name = cat if isinstance(cat, str) else cat.get("category", "xss")
                module_info = _VULN_MODULE_MAP.get(cat_name)
                display_name = module_info[2] if module_info else cat_name.upper()

                vuln_options.append(MenuOption(
                    key="",
                    emoji="🎯",
                    label=f"Test {display_name}",
                    description=f"Recommended based on tech stack + WAF profile",
                    action="test",
                    command=f"fray test {self.target} -c {cat_name} --smart",
                    priority=priority_counter,
                    vuln_types=[cat_name],
                    targets=[self.target],
                ))
                priority_counter += 1

        # Take top 2-3 vuln options
        vuln_options.sort(key=lambda o: o.priority)
        for opt in vuln_options[:3]:
            options.append(opt)

        # ── Deep scan option ───────────────────────────────────────────
        all_cats = [o.vuln_types[0] for o in vuln_options if o.vuln_types]
        if not all_cats:
            all_cats = [c if isinstance(c, str) else c.get("category", "xss")
                        for c in self.recs[:5]] or ["xss", "sqli"]

        deep_cats = ",".join(all_cats[:5])
        deep_desc = f"All identified vulns ({', '.join(all_cats[:3])}{'...' if len(all_cats) > 3 else ''})"
        options.append(MenuOption(
            key="",
            emoji="🔬",
            label="Deep Scan — All Vulnerabilities",
            description=deep_desc,
            action="deep",
            command=f"fray test {self.target} -c {deep_cats} --smart --max 200",
            priority=90,
            vuln_types=all_cats[:5],
        ))

        # ── Auto-pilot option ─────────────────────────────────────────
        options.append(MenuOption(
            key="",
            emoji="🚀",
            label="Auto-Pilot (Report + Test All)",
            description=f"Generate report, then test top {min(len(all_cats), 5)} categories automatically",
            action="autopilot",
            command=f"fray scan {self.target} --smart",
            priority=99,
            vuln_types=all_cats[:5],
            params={"report_path": report_path},
        ))

        # Assign keys
        for i, opt in enumerate(options):
            opt.key = str(i + 1)

        return options

    # ── Display ────────────────────────────────────────────────────────

    def print_menu(self, options: List[MenuOption]) -> None:
        """Print the interactive menu to stderr (so stdout stays clean for pipes)."""
        w = 60
        iw = w - 4  # inner width (accounting for "  │  " prefix + "│" suffix)
        out = sys.stderr

        def _line(text: str) -> str:
            """Pad/truncate text to fit inside the box."""
            # Emoji characters occupy 2 columns but len() counts them as 1
            # Use a simple heuristic: count common emoji as +1 extra width
            extra = sum(1 for c in text if ord(c) > 0x1F000)
            visible = len(text) + extra
            if visible > iw:
                text = text[:iw - extra - 1] + "…"
                visible = len(text) + extra
            pad = iw - visible
            return f"  │  {text}{' ' * max(0, pad)} │\n"

        # Findings summary
        sev_counts = {}
        for f in self.findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        out.write(f"\n  ┌{'─' * w}┐\n")
        out.write(_line("🎯 Recon Complete — What next?"))
        out.write(f"  ├{'─' * w}┤\n")

        # Brief findings summary
        if self.findings:
            sev_parts = []
            for s, c in sorted(sev_counts.items(), key=lambda x: _SEV_RANK.get(x[0], 4)):
                sev_parts.append(f"{_SEV_EMOJI.get(s, '⚪')} {c} {s}")
            out.write(_line(f"Findings: {', '.join(sev_parts)}"))
        if self.waf:
            out.write(_line(f"WAF: {self.waf}"))
        out.write(_line(f"Risk: {self.risk_score}/100 ({self.risk_level})"))
        out.write(f"  ├{'─' * w}┤\n")

        # Options
        for opt in options:
            out.write(_line(f"[{opt.key}] {opt.emoji} {opt.label}"))
            out.write(_line(f"    {opt.description}"))

        out.write(f"  ├{'─' * w}┤\n")
        out.write(_line("[q] Exit"))
        out.write(f"  └{'─' * w}┘\n")
        out.flush()

    # ── Execute selected option ────────────────────────────────────────

    def execute(self, option: MenuOption) -> None:
        """Execute the selected menu option."""
        if option.action == "report":
            self._do_report(option)
        elif option.action == "test":
            self._do_test(option)
        elif option.action == "deep":
            self._do_deep(option)
        elif option.action == "autopilot":
            self._do_autopilot(option)

    def _do_report(self, option: MenuOption) -> None:
        """Generate HTML report from recon data."""
        from fray.reporter import SecurityReportGenerator

        report_path = option.params.get("output", "")
        if not report_path:
            domain = self.recon.get("host", "target")
            report_path = f"{domain}_recon.html"

        gen = SecurityReportGenerator()
        gen.generate_recon_html_report(self.recon, report_path)
        sys.stderr.write(f"\n  ✅ HTML report generated: {report_path}\n")
        sys.stderr.write(f"     Open in browser: file://{os.path.abspath(report_path)}\n\n")

    def _do_test(self, option: MenuOption) -> None:
        """Run targeted payload tests for specific vulnerability types."""
        vuln_types = option.vuln_types
        targets = option.targets or [self.target]

        sys.stderr.write(f"\n  🎯 Testing: {', '.join(vuln_types)}\n")
        sys.stderr.write(f"     Target: {targets[0]}\n")
        if self.waf:
            sys.stderr.write(f"     WAF: {self.waf}\n")
        sys.stderr.write(f"     Command: {option.command}\n\n")

        for vtype in vuln_types:
            self._run_module(vtype, targets[0], option.params)

    def _do_deep(self, option: MenuOption) -> None:
        """Run all identified vulnerability tests."""
        sys.stderr.write(f"\n  🔬 Deep scan: {', '.join(option.vuln_types)}\n")
        sys.stderr.write(f"     Target: {self.target}\n\n")

        for vtype in option.vuln_types:
            self._run_module(vtype, self.target, option.params)

    def _do_autopilot(self, option: MenuOption) -> None:
        """Generate report + run all tests."""
        # Step 1: Report
        report_path = option.params.get("report_path", "")
        if report_path:
            sys.stderr.write("  ── Step 1/2: Generating HTML Report ──\n")
            from fray.reporter import SecurityReportGenerator
            gen = SecurityReportGenerator()
            gen.generate_recon_html_report(self.recon, report_path)
            sys.stderr.write(f"  ✅ Report: {report_path}\n\n")

        # Step 2: Test all vuln types
        sys.stderr.write("  ── Step 2/2: Testing Vulnerabilities ──\n")
        for vtype in option.vuln_types:
            self._run_module(vtype, self.target, option.params)

        sys.stderr.write(f"\n  🏁 Auto-pilot complete.\n")
        if report_path:
            sys.stderr.write(f"     Report: file://{os.path.abspath(report_path)}\n")
        sys.stderr.write("\n")

    def _run_module(self, vuln_type: str, target: str, params: dict) -> None:
        """Run a specific vulnerability test module and print results."""
        module_info = _VULN_MODULE_MAP.get(vuln_type)
        if not module_info or not module_info[0]:
            # No deep module — fallback to fray test CLI
            sys.stderr.write(f"  ⏭  {vuln_type}: use `fray test {target} -c {vuln_type} --smart`\n")
            return

        mod_path, class_name, display_name = module_info
        sys.stderr.write(f"  ▶ {display_name}...")
        sys.stderr.flush()
        t0 = time.monotonic()

        try:
            import importlib
            mod = importlib.import_module(mod_path)
            scanner_cls = getattr(mod, class_name)

            # Build scanner kwargs
            kwargs = {
                "timeout": 15,
                "verify_ssl": False,
            }

            if vuln_type == "cache_poison":
                scanner = scanner_cls(target, level=2, **kwargs)
            elif vuln_type in ("xss", "sqli", "cmdi"):
                # Need a param — try to find one
                param = params.get("param", "")
                if not param:
                    param = self._guess_param(target)
                if not param:
                    sys.stderr.write(f" no injectable param found, skipping\n")
                    return
                kwargs["param"] = param
                if vuln_type in ("sqli", "cmdi"):
                    kwargs["level"] = 1
                    kwargs["risk"] = 1
                scanner = scanner_cls(target, **kwargs)
            elif vuln_type == "massassign":
                scanner = scanner_cls(target, method="GET", level=1, **kwargs)
            elif vuln_type == "deser":
                param = params.get("param", "") or self._guess_param(target)
                if not param:
                    sys.stderr.write(f" no param found, skipping\n")
                    return
                scanner = scanner_cls(target, param=param, **kwargs)
            else:
                scanner = scanner_cls(target, **kwargs)

            result = scanner.scan()
            elapsed = (time.monotonic() - t0) * 1000

            # Print result
            vuln = getattr(result, "vulnerable", False)
            findings = getattr(result, "findings", [])
            requests = getattr(result, "requests_made", 0)

            if vuln:
                sys.stderr.write(f" \033[91mVULNERABLE\033[0m ({len(findings)} findings, {requests} reqs, {elapsed:.0f}ms)\n")
                for f in findings[:5]:
                    if hasattr(f, "payload"):
                        sys.stderr.write(f"    → {f.payload[:80]}\n")
                    elif hasattr(f, "technique"):
                        sys.stderr.write(f"    → [{f.technique}] {getattr(f, 'evidence', '')[:60]}\n")
                    elif hasattr(f, "header"):
                        sys.stderr.write(f"    → [{f.header}] {getattr(f, 'evidence', '')[:60]}\n")
            else:
                sys.stderr.write(f" clean ({requests} reqs, {elapsed:.0f}ms)\n")

            # Output JSON to stdout for piping
            result_dict = result.to_dict() if hasattr(result, "to_dict") else {"vulnerable": vuln}
            result_dict["module"] = vuln_type
            result_dict["target"] = target
            print(json.dumps(result_dict, ensure_ascii=False, default=str))

        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            sys.stderr.write(f" error: {e} ({elapsed:.0f}ms)\n")

    def _guess_param(self, url: str) -> str:
        """Guess the best injectable parameter from URL or recon data."""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        if qs:
            # Prefer common injectable param names
            for preferred in ["q", "s", "search", "query", "keyword", "id", "cat",
                              "page", "name", "user", "input", "url", "path", "file"]:
                if preferred in qs:
                    return preferred
            return list(qs.keys())[0]

        # Try recon params data
        params_data = self.recon.get("params", {})
        if isinstance(params_data, dict):
            for pname, info in params_data.items():
                if isinstance(info, dict) and info.get("injectable"):
                    return pname

        # Fallback: common param names
        return "q"

    # ── Main interactive loop ──────────────────────────────────────────

    def run(self) -> Optional[str]:
        """Show menu, get user choice, execute. Returns action taken or None."""
        if not sys.stdin.isatty():
            return None  # Non-interactive — skip

        options = self.build_options()
        if not options:
            return None

        self.print_menu(options)

        # Prompt
        try:
            choice = input("\n  Select [1-{}/q]: ".format(len(options))).strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\n")
            return None

        if choice == "q" or choice == "":
            return None

        # Find matching option
        selected = None
        for opt in options:
            if opt.key == choice:
                selected = opt
                break

        if not selected:
            sys.stderr.write(f"  Invalid choice: {choice}\n")
            return None

        sys.stderr.write(f"\n  → {selected.emoji} {selected.label}\n")
        self.execute(selected)
        return selected.action
