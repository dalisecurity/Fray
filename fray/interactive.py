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
    "prototype_pollution": ("fray.proto_pollution", "PPScanner", "Prototype Pollution"),
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
    "prototype_pollution": ["prototype", "__proto__", "pollution", "constructor.prototype", "merge", "lodash"],
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
        from fray.ui import S, severity_color, severity_summary, pill

        out = sys.stderr

        # Findings summary
        sev_counts = {}
        for f in self.findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        # Header
        out.write(f"\n  {S.brand}{'━' * 62}{S.reset}\n")
        out.write(f"  {S.bold}{S.white}  ⚔  Recon Complete — What next?{S.reset}\n")
        out.write(f"  {S.brand}{'━' * 62}{S.reset}\n")
        out.write("\n")

        # Stats row
        if self.findings:
            out.write(f"  {severity_summary(sev_counts)}\n")
        risk_color = S.critical if self.risk_score >= 70 else S.high if self.risk_score >= 40 else S.success
        out.write(f"  {S.gray}Risk{S.reset}  {risk_color}{S.bold}{self.risk_score}/100{S.reset} {S.dim}({self.risk_level}){S.reset}")
        if self.waf:
            out.write(f"  {S.gray}WAF{S.reset}  {S.accent}{self.waf}{S.reset}")
        out.write("\n\n")

        # Options
        for opt in options:
            # Key badge
            key_badge = f"{S.bg_brand}{S.bold}{S.white} {opt.key} {S.reset}"

            # Severity-colored emoji for vuln options
            if opt.vuln_types and opt.action == "test":
                # Find top severity for this vuln type
                top_sev = "info"
                classified = self._classify_findings()
                for vt in opt.vuln_types:
                    for f in classified.get(vt, []):
                        fs = f.get("severity", "info")
                        if _SEV_RANK.get(fs, 4) < _SEV_RANK.get(top_sev, 4):
                            top_sev = fs
                sc = severity_color(top_sev)
                label = f"{sc}{S.bold}{opt.label}{S.reset}"
            elif opt.action == "report":
                label = f"{S.brand2}{S.bold}{opt.label}{S.reset}"
            elif opt.action == "deep":
                label = f"{S.info}{S.bold}{opt.label}{S.reset}"
            elif opt.action == "autopilot":
                label = f"{S.success}{S.bold}{opt.label}{S.reset}"
            else:
                label = f"{S.white}{S.bold}{opt.label}{S.reset}"

            out.write(f"  {key_badge} {label}\n")
            out.write(f"       {S.dim}{opt.description}{S.reset}\n\n")

        # Exit
        out.write(f"  {S.dark}  q   Exit{S.reset}\n")
        out.write(f"\n  {S.dark}{'─' * 62}{S.reset}\n")
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

    def _run_module(self, vuln_type: str, target: str, params: dict) -> Optional[dict]:
        """Run a specific vulnerability test module and print results.

        Returns dict with keys: module, target, vulnerable, findings, requests
        or None on skip/error.
        """
        module_info = _VULN_MODULE_MAP.get(vuln_type)
        if not module_info or not module_info[0]:
            # No deep module — fallback to fray test CLI
            sys.stderr.write(f"  ⏭  {vuln_type}: use `fray test {target} -c {vuln_type} --smart`\n")
            return None

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
                "timeout": 6,
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
            elif vuln_type in ("deser", "ssrf"):
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

            return {
                "module": vuln_type,
                "target": target,
                "vulnerable": vuln,
                "findings": len(findings),
                "requests": requests,
                "elapsed_ms": elapsed,
            }

        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            sys.stderr.write(f" error: {e} ({elapsed:.0f}ms)\n")
            return None

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
            from fray.ui import S
            prompt = f"\n  {S.brand}▸{S.reset} {S.white}Select{S.reset} {S.dim}[1-{len(options)}/q]{S.reset}: "
            choice = input(prompt).strip().lower()
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

        from fray.ui import S
        sys.stderr.write(f"\n  {S.brand}▸{S.reset} {S.bold}{S.white}{selected.label}{S.reset}\n")
        self.execute(selected)
        return selected.action


# ═══════════════════════════════════════════════════════════════════════
# Next-step hints — printed after any fray command to guide the user
# ═══════════════════════════════════════════════════════════════════════

def next_steps(target: str, context: str = "recon", *,
               recon: dict = None, findings_count: int = 0,
               bypassed: int = 0, blocked: int = 0,
               categories: list = None, waf: str = "") -> None:
    """Print smart 'what to type next' hints after any fray command.

    context: "recon", "test", "scan", "bypass", "harden"
    """
    if not sys.stderr.isatty():
        return
    if os.environ.get("FRAY_NO_HINTS"):
        return

    from fray.ui import S, cmd_hint, section_title

    out = sys.stderr
    out.write(section_title("Next Steps"))

    if context == "recon":
        cats = categories or []
        if cats:
            top = cats[0] if isinstance(cats[0], str) else cats[0].get("category", "xss")
            out.write(cmd_hint(f"fray test {target} -c {top} --smart",
                               f"Test top category ({top})") + "\n")
        out.write(cmd_hint(f"fray go {target}",
                           "Full guided pipeline") + "\n")
        if waf:
            out.write(cmd_hint(f"fray bypass {target} -c xss",
                               f"WAF bypass ({waf})") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Security headers audit (A-F)") + "\n")

    elif context == "test":
        if bypassed > 0:
            out.write(cmd_hint(f"fray report -i results.json -o report.html",
                               f"Generate report ({bypassed} bypasses)") + "\n")
            out.write(cmd_hint(f"fray bypass {target} -c xss",
                               "AI-powered bypass amplification") + "\n")
        else:
            other_cats = ["sqli", "ssrf", "ssti", "cmdi"]
            if categories:
                other_cats = [c for c in other_cats if c not in categories]
            cat_str = ",".join(other_cats[:3])
            out.write(cmd_hint(f"fray test {target} -c {cat_str} --smart",
                               "Try different categories") + "\n")
            out.write(cmd_hint(f"fray agent {target} -c xss --rounds 3",
                               "Self-learning agent") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Check security posture") + "\n")

    elif context == "scan":
        if bypassed > 0:
            out.write(cmd_hint(f"fray report -i results.json -o report.html",
                               "Generate client-ready report") + "\n")
        out.write(cmd_hint(f"fray recon {target} --deep",
                           "Deep recon (300 subdomains)") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "OWASP hardening audit") + "\n")

    elif context == "bypass":
        if bypassed > 0:
            out.write(cmd_hint(f"fray report -i results.json -o report.html",
                               f"Generate report ({bypassed} bypasses)") + "\n")
        out.write(cmd_hint(f"fray agent {target} -c xss --rounds 5",
                           "Self-improving agent (longer)") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Check security posture") + "\n")

    elif context == "detect":
        out.write(cmd_hint(f"fray recon {target}",
                           "Full reconnaissance (35+ checks)") + "\n")
        out.write(cmd_hint(f"fray go {target}",
                           "Guided pipeline (recon+test+report)") + "\n")
        if waf:
            out.write(cmd_hint(f"fray test {target} -c xss --smart",
                               f"Test payloads against {waf}") + "\n")
            out.write(cmd_hint(f"fray bypass {target} --waf {waf.lower().replace(' ', '_')} -c xss",
                               f"WAF bypass scoring") + "\n")
        else:
            out.write(cmd_hint(f"fray test {target} -c xss --smart",
                               "No WAF detected — test payloads") + "\n")

    elif context == "harden":
        out.write(cmd_hint(f"fray recon {target}",
                           "Full recon for deeper analysis") + "\n")
        out.write(cmd_hint(f"fray test {target} -c xss --smart",
                           "Test WAF with smart payloads") + "\n")
        out.write(cmd_hint(f"fray scan {target}",
                           "Auto crawl + inject + detect") + "\n")

    elif context == "agent":
        if bypassed > 0:
            out.write(cmd_hint(f"fray report -i results.json -o report.html",
                               f"Generate report ({bypassed} bypasses)") + "\n")
        out.write(cmd_hint(f"fray agent {target} -c xss --rounds 10 --ai",
                           "AI-assisted agent (longer run)") + "\n")
        out.write(cmd_hint(f"fray bypass {target} -c xss",
                           "WAF bypass scoring") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Security posture audit") + "\n")

    elif context == "graph":
        out.write(cmd_hint(f"fray recon {target} --deep",
                           "Deep recon (300 subdomains)") + "\n")
        out.write(cmd_hint(f"fray go {target}",
                           "Guided pipeline (recon+test+report)") + "\n")
        out.write(cmd_hint(f"fray scan {target}",
                           "Auto crawl + payload injection") + "\n")

    elif context == "bounty":
        out.write(cmd_hint(f"fray go {target}",
                           "Guided pipeline per target") + "\n")
        out.write(cmd_hint(f"fray recon {target}",
                           "Deep recon on interesting target") + "\n")
        out.write(cmd_hint(f"fray agent {target} -c xss --rounds 5",
                           "Self-learning agent") + "\n")

    elif context == "auto":
        out.write(cmd_hint(f"fray agent {target} -c xss --rounds 5",
                           "Self-learning agent (deeper)") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Security headers + OWASP audit") + "\n")
        out.write(cmd_hint(f"fray recon {target} --deep",
                           "Extended DNS, 300 subdomains") + "\n")

    elif context == "smuggle":
        out.write(cmd_hint(f"fray recon {target}",
                           "Full reconnaissance") + "\n")
        out.write(cmd_hint(f"fray scan {target}",
                           "Auto crawl + payload injection") + "\n")
        out.write(cmd_hint(f"fray harden {target}",
                           "Security posture audit") + "\n")

    out.write("\n")
    out.flush()


# ═══════════════════════════════════════════════════════════════════════
# GuidedPipeline — `fray go <url>` zero-knowledge full pipeline
# ═══════════════════════════════════════════════════════════════════════

def _auto_concurrency(recon_result: dict) -> int:
    """Determine safe parallel concurrency from recon intelligence.

    Returns concurrency level: 1 (sequential) to 10 (aggressive).
    """
    if not recon_result:
        return 1

    atk = recon_result.get("attack_surface", {})
    waf = (atk.get("waf_vendor") or "").lower()
    bot = recon_result.get("bot_protection", {})
    rate_info = recon_result.get("rate_limits", {})
    has_bot_detection = bool(bot.get("detected") or bot.get("has_captcha")
                            or bot.get("has_fingerprinting"))
    has_rate_limit = bool(rate_info.get("threshold_rps")
                         or rate_info.get("rate_limited"))

    # Aggressive: no WAF, no bot detection, no rate limits
    if not waf and not has_bot_detection and not has_rate_limit:
        return 10

    # Moderate: WAF present but no bot detection or rate limits
    if waf and not has_bot_detection and not has_rate_limit:
        return 5

    # Careful: WAF + rate limits but no bot detection
    if waf and has_rate_limit and not has_bot_detection:
        return 2

    # Very careful: bot detection active (Turnstile, DataDome, etc.)
    if has_bot_detection:
        return 1

    # Default: moderate
    return 3


class GuidedPipeline:
    """Zero-knowledge guided pipeline: recon → smart test → report.

    Usage:
        fray go https://target.com          # Full auto pipeline
        fray go https://target.com --deep   # Deep mode
        fray go https://target.com -o out/  # Custom output dir
    """

    def __init__(self, target: str, *, timeout: int = 8, deep: bool = False,
                 output_dir: str = "", headers: dict = None,
                 stealth: bool = False, quiet: bool = False,
                 impersonate: str = None):
        self.target = target
        self.timeout = timeout
        self.deep = deep
        self.output_dir = output_dir
        self.headers = headers
        self.stealth = stealth
        self.quiet = quiet
        self.impersonate = impersonate
        self.recon_result = None
        self.test_results = []
        self.report_path = ""

    def run(self) -> dict:
        """Execute the full guided pipeline. Returns summary dict."""
        from fray.ui import (S, banner, phase_header, summary_line, severity_summary,
                             cmd_hint, section_title, pill, severity_color)

        t0 = time.monotonic()
        out = sys.stderr
        summary = {"target": self.target, "phases": []}

        # ── Dashboard (optional live TUI) ──────────────────────────────
        _dash = None
        try:
            from fray.dashboard import Dashboard
            _dash = Dashboard(target=self.target, quiet=self.quiet)
        except Exception:
            pass

        # ── Banner ─────────────────────────────────────────────────────
        if not self.quiet:
            out.write(banner("⚔  Fray — Guided Security Pipeline", self.target))
            out.write(f"  {S.dim}[1/3]{S.reset} Recon       Fingerprint tech stack, WAF, TLS, headers, DNS...\n")
            out.write(f"  {S.dim}[2/3]{S.reset} Test        Select & run payloads based on what recon found\n")
            out.write(f"  {S.dim}[3/3]{S.reset} Report      Generate findings report with remediation\n\n")
            out.flush()

        # ── Phase 1: Recon ─────────────────────────────────────────────
        if not self.quiet:
            out.write(phase_header(1, "Attack Surface Intelligence"))
            out.write(f"  {S.dim}Checking TLS, headers, DNS, CORS, subdomains, tech stack, WAF...{S.reset}\n")
        if _dash:
            _dash.set_phase(1, "Recon", total=50)
        self.recon_result = self._run_recon()
        if _dash:
            _dash.update_progress(done=50)

        if not self.recon_result:
            out.write(f"  {S.error}\u2716 Recon failed — cannot continue.{S.reset}\n")
            return summary

        atk = self.recon_result.get("attack_surface", {})
        risk = atk.get("risk_score", 0)
        risk_level = atk.get("risk_level", "?")
        waf = atk.get("waf_vendor", "")
        findings = atk.get("findings", [])
        recs = self.recon_result.get("recommended_categories", [])

        summary["phases"].append({
            "name": "recon",
            "risk_score": risk,
            "risk_level": risk_level,
            "waf": waf,
            "findings": len(findings),
        })

        # Feed dashboard with recon results
        if _dash:
            _dash.set_risk(risk)
            _dash.update_stat("subdomains", len(self.recon_result.get("subdomains", {}).get("subdomains", [])))
            _dash.update_stat("vectors", len(atk.get("attack_vectors", [])))
            for f in findings[:20]:
                _dash.add_finding(f.get("title", f.get("type", ""))[:60],
                                  f.get("severity", "info"))

        if not self.quiet:
            # Severity summary
            sev_counts = {}
            for f in findings:
                s = f.get("severity", "info")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            out.write(f"\n  {S.success}\u2714{S.reset} {S.bold}{S.white}Intelligence gathered{S.reset}\n\n")
            out.write(f"  {severity_summary(sev_counts)}\n")
            risk_c = S.critical if risk >= 70 else S.high if risk >= 40 else S.success
            out.write(summary_line("Risk", f"{risk}/100 ({risk_level})", "") + "\n")
            if waf:
                out.write(summary_line("WAF", waf, "accent") + "\n")
            out.write("\n")
            out.flush()

        # ── Phase 2: Smart Testing ─────────────────────────────────────
        if not self.quiet:
            _waf_note = f" against {waf}" if waf else ""
            out.write(phase_header(2, "Smart Vulnerability Testing"))
            out.write(f"  {S.dim}Selecting payloads based on recon findings{_waf_note}...{S.reset}\n")
        if _dash:
            _n_modules = len(vuln_types[:5]) + len(_smart_cats if '_smart_cats' in dir() else [])
            _dash.set_phase(2, "Testing", total=max(_n_modules, 5))

        # Build interactive menu to determine what to test
        menu = ReconInteractive(self.target, self.recon_result)
        classified = menu._classify_findings()

        # Determine vuln types to test — from findings or recommendations
        vuln_types = []
        for vuln_type, vuln_findings in classified.items():
            if vuln_type != "other" and vuln_type in _VULN_MODULE_MAP:
                info = _VULN_MODULE_MAP[vuln_type]
                if info[0]:  # Has a runnable module
                    vuln_types.append(vuln_type)

        if not vuln_types and recs:
            for cat in recs[:3]:
                cat_name = cat if isinstance(cat, str) else cat.get("category", "")
                if cat_name in _VULN_MODULE_MAP and _VULN_MODULE_MAP[cat_name][0]:
                    vuln_types.append(cat_name)

        # Fallback: test xss + sqli
        if not vuln_types:
            vuln_types = ["xss", "sqli"]

        if not self.quiet:
            mods = f"{S.white}{', '.join(vuln_types)}{S.reset}"
            out.write(f"  {S.dim}Modules:{S.reset} {mods}\n\n")
            out.flush()

        # Run test modules in parallel (each module is independent)
        module_results = []
        if len(vuln_types[:5]) > 1:
            import concurrent.futures as _cf_test
            with _cf_test.ThreadPoolExecutor(max_workers=min(3, len(vuln_types[:5]))) as _tpool:
                _futs = {_tpool.submit(menu._run_module, vt, self.target, {}): vt
                         for vt in vuln_types[:5]}
                for fut in _cf_test.as_completed(_futs, timeout=120):
                    try:
                        res = fut.result(timeout=60)
                        if res:
                            module_results.append(res)
                    except Exception:
                        pass
        else:
            for vtype in vuln_types[:5]:
                res = menu._run_module(vtype, self.target, {})
                if res:
                    module_results.append(res)

        # ── Smart payload testing (WAFTester + clustering + vendor mutations) ──
        # If recon found a WAF and recommended xss/sqli categories, run an
        # adaptive clustered test using WAFTester with impersonation.
        # Auto-parallel: use recon intelligence to pick safe concurrency.
        _smart_results = []
        _smart_cats = [c for c in (recs[:2] if recs else ["xss"]) if isinstance(c, str)]
        if not _smart_cats:
            _smart_cats = [c.get("category", "") for c in recs[:2] if isinstance(c, dict)]
        _smart_cats = [c for c in _smart_cats if c][:2]

        _concurrency = _auto_concurrency(self.recon_result)

        if _smart_cats:
            try:
                from fray.tester import WAFTester
                from fray.evolve import cluster_payloads, test_clustered
                from pathlib import Path as _P

                _payloads_dir = _P(__file__).parent / "payloads"
                _waf_vendor = waf.split("(")[0].strip() if waf else None
                _imp = self.impersonate

                for _sc in _smart_cats:
                    _cat_dir = _payloads_dir / _sc
                    if not _cat_dir.exists():
                        continue
                    _payloads = []
                    for _pf in sorted(_cat_dir.glob("*.json"))[:3]:
                        try:
                            import json as _jmod
                            _payloads.extend(_jmod.loads(_pf.read_text(encoding="utf-8")))
                        except Exception:
                            pass
                    if not _payloads or len(_payloads) < 2:
                        continue

                    _mode_label = f"\u26A1 parallel\u00D7{_concurrency}" if _concurrency > 1 else "sequential"
                    if not self.quiet:
                        out.write(f"  \u25B6 Smart {_sc.upper()} test ({len(_payloads)} payloads")
                        if _waf_vendor:
                            out.write(f", vendor: {_waf_vendor}")
                        out.write(f", {_mode_label})...")
                        out.flush()

                    # Parallel path: use async engine for speed
                    if _concurrency > 1:
                        try:
                            from fray.async_engine import parallel_test_payloads, ResponseBaseline
                            _payload_strs = [p.get("payload", p) if isinstance(p, dict)
                                             else str(p) for p in _payloads[:100]]
                            _baseline = ResponseBaseline.capture(
                                self.target, param="q", method="GET",
                                timeout=6, verify_ssl=False,
                                headers=self.headers,
                            )
                            _par_res = parallel_test_payloads(
                                url=self.target, param="q",
                                payloads=_payload_strs,
                                method="GET", category=_sc,
                                concurrency=_concurrency,
                                timeout=6, verify_ssl=False,
                                headers=self.headers,
                                baseline=_baseline,
                                follow_redirect=True,
                            )
                            _bypasses = [r for r in _par_res if not r.get("blocked", True)]
                            _fp = sum(1 for r in _par_res if r.get("false_positive"))
                            _result = {
                                "module": f"smart_{_sc}",
                                "target": self.target,
                                "vulnerable": len(_bypasses) > 0,
                                "findings": len(_bypasses),
                                "requests": len(_par_res),
                                "false_positives": _fp,
                                "parallel": _concurrency,
                                "bypasses": [{"payload": b.get("payload", ""), "status": b.get("status", 0)}
                                             for b in _bypasses[:10]],
                            }
                            _smart_results.append(_result)

                            if not self.quiet:
                                _status = f"{S.error}{len(_bypasses)} bypass(es){S.reset}" if _bypasses else f"{S.success}clean{S.reset}"
                                _fp_tag = f", {_fp} FP filtered" if _fp else ""
                                out.write(f" {_status} ({len(_par_res)} reqs{_fp_tag})\n")
                                out.flush()
                            continue  # Skip sequential fallback
                        except ImportError:
                            pass  # Fall through to sequential

                    # Sequential fallback (or concurrency=1)
                    _t = WAFTester(
                        self.target, timeout=6, delay=0.1,
                        verify_ssl=False, stealth=self.stealth,
                        impersonate=_imp,
                    )
                    _cluster_res = test_clustered(_t, _payloads[:100], param="q")
                    _bypasses = [r for r in _cluster_res if not r.get("blocked", True)]
                    _n_req = sum(1 for r in _cluster_res if not r.get("skipped_by_cluster"))
                    _n_skip = sum(1 for r in _cluster_res if r.get("skipped_by_cluster"))

                    _result = {
                        "module": f"smart_{_sc}",
                        "target": self.target,
                        "vulnerable": len(_bypasses) > 0,
                        "findings": len(_bypasses),
                        "requests": _n_req,
                        "skipped_by_cluster": _n_skip,
                        "bypasses": [{"payload": b.get("payload", ""), "family": b.get("family", "")} for b in _bypasses[:10]],
                    }
                    _smart_results.append(_result)

                    if not self.quiet:
                        _status = f"{S.error}{len(_bypasses)} bypass(es){S.reset}" if _bypasses else f"{S.success}clean{S.reset}"
                        out.write(f" {_status} ({_n_req} reqs, {_n_skip} skipped by cluster)\n")
                        out.flush()
            except Exception:
                pass

        module_results.extend(_smart_results)

        total_vulns = sum(1 for r in module_results if r.get("vulnerable"))
        total_findings = sum(r.get("findings", 0) for r in module_results)
        total_requests = sum(r.get("requests", 0) for r in module_results)

        # Feed dashboard with test results
        if _dash:
            _dash.update_progress(done=_dash._total)
            _dash.update_stat("requests", total_requests)
            _dash.update_stat("bypasses", total_vulns)
            for _mr in module_results:
                if _mr.get("vulnerable"):
                    _dash.add_finding(f"{_mr.get('module', '?')}: vulnerable", "high")

        if not self.quiet and module_results:
            out.write(f"\n  {S.success}✔{S.reset} {S.bold}{S.white}Testing complete{S.reset}\n")
            vuln_c = S.error if total_vulns > 0 else S.success
            out.write(summary_line("Modules", f"{len(module_results)} tested") + "\n")
            out.write(f"  {S.gray}{'Vulnerable':<20}{S.reset} {vuln_c}{total_vulns}{S.reset}\n")
            out.write(summary_line("Findings", str(total_findings)) + "\n")
            out.write(summary_line("Requests", str(total_requests)) + "\n")
            out.write("\n")
            out.flush()

        self.test_results = module_results
        summary["phases"].append({
            "name": "test",
            "modules_tested": vuln_types[:5],
            "count": len(vuln_types[:5]),
            "vulnerable": total_vulns,
            "findings": total_findings,
            "requests": total_requests,
            "results": module_results,
        })

        # ── Phase 3: Report ────────────────────────────────────────────
        if not self.quiet:
            out.write(phase_header(3, "Report Generation"))
            out.write(f"  {S.dim}Compiling findings into HTML report with remediation guidance...{S.reset}\n")

        domain = self.recon_result.get("host", "target")
        if self.output_dir:
            self.report_path = os.path.join(self.output_dir, f"{domain}_report.html")
        else:
            self.report_path = f"{domain}_report.html"

        try:
            from fray.reporter import SecurityReportGenerator
            gen = SecurityReportGenerator()
            gen.generate_recon_html_report(self.recon_result, self.report_path)
            if not self.quiet:
                report_abs = os.path.abspath(self.report_path)
                out.write(f"  {S.success}\u2714{S.reset} {S.white}HTML report:{S.reset} {S.target}{self.report_path}{S.reset}\n")
                out.write(f"  {S.success}\u2714{S.reset} {S.white}Dashboard updated{S.reset} {S.dim}— run{S.reset} {S.target}fray dashboard{S.reset} {S.dim}to view live{S.reset}\n")
                out.write(f"\n  {S.dim}Open report:    open {self.report_path}{S.reset}\n")
                out.write(f"  {S.dim}Open dashboard: fray dashboard{S.reset}\n")
        except Exception as e:
            if not self.quiet:
                out.write(f"  {S.warning}\u26a0{S.reset} Report generation failed: {e}\n")

        summary["phases"].append({
            "name": "report",
            "path": self.report_path,
        })

        # Finish dashboard
        if _dash:
            _dash.set_phase(3, "Report", total=1)
            _dash.update_progress(done=1)
            _dash.finish()

        # ── Final Summary ──────────────────────────────────────────────
        elapsed = time.monotonic() - t0
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        summary["duration"] = duration

        if not self.quiet:
            out.write(f"\n  {S.success}{'━' * 62}{S.reset}\n")
            out.write(f"  {S.success}{S.bold}  ✔  Pipeline Complete{S.reset}\n")
            out.write(f"  {S.success}{'━' * 62}{S.reset}\n\n")

            risk_c = severity_color(risk_level.lower() if risk_level != "?" else "info")
            out.write(summary_line("Duration", duration) + "\n")
            out.write(f"  {S.gray}{'Risk':<20}{S.reset} {risk_c}{risk}/100 ({risk_level}){S.reset}\n")
            if waf:
                out.write(summary_line("WAF", waf, "accent") + "\n")
            out.write(summary_line("Recon findings", str(len(findings))) + "\n")
            out.write(summary_line("Modules tested", str(len(vuln_types[:5]))) + "\n")
            if total_vulns > 0:
                out.write(f"  {S.gray}{'Vulnerabilities':<20}{S.reset} {S.error}{total_vulns} vulnerable{S.reset}\n")
            else:
                out.write(f"  {S.gray}{'Vulnerabilities':<20}{S.reset} {S.success}0 (clean){S.reset}\n")
            if total_findings > 0:
                out.write(summary_line("Test findings", str(total_findings)) + "\n")
            out.write(summary_line("Total requests", str(total_requests)) + "\n")
            out.write(summary_line("Report", self.report_path, "target") + "\n")

            # What's Next
            out.write(section_title("What's Next"))
            if recs:
                top = recs[0] if isinstance(recs[0], str) else recs[0].get("category", "xss")
                out.write(cmd_hint(f"fray test {self.target} -c {top} --smart --max 100",
                                   "Deep test top category") + "\n")
            if waf:
                out.write(cmd_hint(f"fray agent {self.target} -c xss --rounds 5",
                                   f"Self-learning agent vs {waf[:20]}") + "\n")
                out.write(cmd_hint(f"fray bypass {self.target} -c xss",
                                   "AI-powered WAF bypass") + "\n")
            out.write(cmd_hint(f"fray harden {self.target}",
                               "Security headers + OWASP audit") + "\n")
            out.write(cmd_hint(f"fray recon {self.target} --deep",
                               "Extended DNS, 300 subdomains") + "\n")
            out.write("\n")
            out.flush()

        # Also export recon JSON
        try:
            recon_json_path = self.report_path.replace(".html", ".json")
            with open(recon_json_path, "w", encoding="utf-8") as f:
                json.dump(self.recon_result, f, indent=2, ensure_ascii=False)
            summary["recon_json"] = recon_json_path
        except Exception:
            pass

        return summary

    def _phase_header(self, num: int, name: str) -> None:
        if not self.quiet:
            from fray.ui import phase_header as _ph
            sys.stderr.write(_ph(num, name))
            sys.stderr.flush()

    def _run_recon(self) -> Optional[dict]:
        """Run recon and return result dict."""
        try:
            from fray.recon import run_recon
            mode = "deep" if self.deep else "default"
            return run_recon(
                self.target,
                timeout=self.timeout,
                headers=self.headers,
                mode=mode,
                stealth=self.stealth,
                quiet=self.quiet,
            )
        except Exception as e:
            sys.stderr.write(f"  Error: {e}\n")
            return None
