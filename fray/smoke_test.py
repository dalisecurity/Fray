"""
Fray QA Smoke Test — Internal quality assurance against 10 test targets.

10 hardcoded intentionally-vulnerable sites provided by the security community
and vendors. These run as part of the test process on every code change to
assure quality. All targets are public test apps designed to be scanned.

Usage:
    fray smoke                     # Run all 10 QA targets
    fray smoke --quick             # Quick mode (detect + recon only)
    fray smoke --full              # Full mode (detect + recon + payload test)
    fray smoke --json              # JSON output for CI

Targets:
    1. Acunetix PHP        (testphp.vulnweb.com)
    2. Acunetix ASP.NET    (testaspnet.vulnweb.com)
    3. Acunetix Classic ASP (testasp.vulnweb.com)
    4. OWASP Juice Shop    (juice-shop.herokuapp.com)
    5. Zero Bank           (zero.webappsecurity.com)
    6. Gin & Juice Shop    (ginandjuice.shop) — PortSwigger
    7. DVWA                (www.dvwa.co.uk)
    8. Google Firing Range (public-firing-range.appspot.com)
    9. Altoro Mutual       (demo.testfire.net) — HCL/IBM
   10. Hackable Vercel     (hackable-vulnerable-website.vercel.app)
"""

import json
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fray import __version__

# ── Smoke Test Target Zones ──────────────────────────────────────────────────

@dataclass
class SmokeTarget:
    """A smoke test target."""
    url: str
    name: str
    zone: str           # "real" or "vulnerable"
    expected_waf: str   # Expected WAF vendor (or "none" for vuln sites)
    description: str
    tags: List[str] = field(default_factory=list)


# ── Internal QA Test Targets ─────────────────────────────────────────────────
#
# These are intentionally vulnerable web applications provided by the security
# community and vendors specifically for testing. They are our internal QA
# targets — run on every code change to assure quality.
#
# All sites below are PUBLIC test targets designed and maintained for this
# purpose. Do NOT add production sites here.

QA_TARGETS = [
    # ── Acunetix Vulnerable Sites (3) ─────────────────────────────────────
    # Provided by Acunetix/Invicti for scanner testing
    SmokeTarget(
        url="http://testphp.vulnweb.com",
        name="Acunetix PHP",
        zone="qa",
        expected_waf="none",
        description="Acunetix intentionally vulnerable PHP app (XSS, SQLi, LFI)",
        tags=["php", "xss", "sqli", "lfi"],
    ),
    SmokeTarget(
        url="http://testaspnet.vulnweb.com",
        name="Acunetix ASP.NET",
        zone="qa",
        expected_waf="none",
        description="Acunetix intentionally vulnerable ASP.NET app",
        tags=["aspnet", "xss", "sqli"],
    ),
    SmokeTarget(
        url="http://testasp.vulnweb.com",
        name="Acunetix Classic ASP",
        zone="qa",
        expected_waf="none",
        description="Acunetix intentionally vulnerable classic ASP app",
        tags=["asp", "xss", "sqli"],
    ),

    # ── OWASP / Community (3) ─────────────────────────────────────────────
    SmokeTarget(
        url="https://juice-shop.herokuapp.com",
        name="OWASP Juice Shop",
        zone="qa",
        expected_waf="none",
        description="OWASP Juice Shop — modern JS app with 100+ vulns",
        tags=["owasp", "nodejs", "xss", "sqli", "auth"],
    ),
    SmokeTarget(
        url="http://zero.webappsecurity.com",
        name="Zero Bank",
        zone="qa",
        expected_waf="none",
        description="Micro Focus vulnerable banking app (auth, injection)",
        tags=["banking", "auth", "sqli"],
    ),
    SmokeTarget(
        url="https://ginandjuice.shop",
        name="Gin & Juice Shop",
        zone="qa",
        expected_waf="none",
        description="PortSwigger (Burp) public vulnerable target",
        tags=["portswigger", "xss", "sqli", "ssrf"],
    ),

    # ── HackTheBox / TryHackMe style public targets (2) ──────────────────
    SmokeTarget(
        url="http://www.dvwa.co.uk",
        name="DVWA",
        zone="qa",
        expected_waf="none",
        description="Damn Vulnerable Web Application — classic training target",
        tags=["dvwa", "xss", "sqli", "cmdi"],
    ),
    SmokeTarget(
        url="https://public-firing-range.appspot.com",
        name="Google Firing Range",
        zone="qa",
        expected_waf="none",
        description="Google's test bed for web vulnerability scanners",
        tags=["google", "xss", "dom"],
    ),

    # ── Vendor-provided test apps (2) ────────────────────────────────────
    SmokeTarget(
        url="http://demo.testfire.net",
        name="Altoro Mutual",
        zone="qa",
        expected_waf="none",
        description="HCL/IBM AppScan demo vulnerable banking site",
        tags=["ibm", "banking", "sqli", "xss"],
    ),
    SmokeTarget(
        url="https://hackable-vulnerable-website.vercel.app",
        name="Hackable Vercel",
        zone="qa",
        expected_waf="none",
        description="Community-maintained vulnerable app on Vercel",
        tags=["vercel", "xss", "modern"],
    ),
]


def get_targets(zone: str = "all") -> List[SmokeTarget]:
    """Get QA test targets.

    Args:
        zone: 'all' or 'qa' — kept for CLI compat, always returns QA targets.
    """
    return QA_TARGETS


# ── Smoke Test Runner ────────────────────────────────────────────────────────

@dataclass
class SmokeResult:
    """Result of a smoke test run on one target."""
    target: str
    name: str
    zone: str
    status: str = "pending"   # pending, pass, fail, error, skip
    waf_detected: str = ""
    waf_match: bool = False   # True if detected WAF matches expected
    recon_ok: bool = False
    test_ok: bool = False
    findings_count: int = 0
    duration_s: float = 0.0
    error: str = ""
    details: Dict = field(default_factory=dict)


def _run_detect(target: SmokeTarget, timeout: int = 15) -> Dict:
    """Run WAF detection on a target."""
    try:
        from fray.detector import WAFDetector
        detector = WAFDetector()
        result = detector.detect_waf(target.url, timeout=timeout, verify_ssl=False)
        return {
            "waf": result.get("waf_vendor", ""),
            "confidence": result.get("confidence", 0),
            "status_code": result.get("status_code", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def _run_recon(target: SmokeTarget, timeout: int = 15) -> Dict:
    """Run lightweight recon on a target."""
    try:
        from fray.recon.pipeline import run_recon
        result = run_recon(
            target.url,
            timeout=timeout,
            verify_ssl=False,
            quiet=True,
        )
        return {
            "technologies": len(result.get("technologies", [])),
            "subdomains": len(result.get("subdomains", [])),
            "risk_score": result.get("risk_score", 0),
            "findings": len(result.get("findings", [])),
            "attack_vectors": len(result.get("attack_vectors", [])),
        }
    except Exception as e:
        return {"error": str(e)}


def _run_test(target: SmokeTarget, category: str = "xss",
              max_payloads: int = 5, timeout: int = 10) -> Dict:
    """Run a small payload test on a target."""
    try:
        from fray.tester import WAFTester
        tester = WAFTester(
            target.url, timeout=timeout,
            delay=0.3, verify_ssl=False,
        )
        result = tester.test_category(category, max_payloads=max_payloads)
        return {
            "total": result.get("total", 0),
            "blocked": result.get("blocked", 0),
            "passed": result.get("passed", 0),
            "errors": result.get("errors", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def run_smoke_test(
    zone: str = "all",
    mode: str = "quick",  # "quick" = detect+recon, "full" = +test
    verbose: bool = True,
    json_output: bool = False,
) -> List[SmokeResult]:
    """Run QA smoke tests against all 10 internal test targets.

    Args:
        zone: kept for CLI compat, always uses all QA targets.
        mode: "quick" (detect+recon) or "full" (+payload test)
        verbose: print progress
        json_output: return JSON instead of pretty-print

    Returns:
        List of SmokeResult objects.
    """
    targets = get_targets(zone)
    results: List[SmokeResult] = []

    if verbose and not json_output:
        from fray.ui import S
        print(f"\n  {S.bold}{S.white}Fray QA Smoke Test{S.reset}  "
              f"{S.dim}v{__version__} · {len(targets)} targets · {mode} mode{S.reset}")
        print(f"  {S.dim}{'━' * 56}{S.reset}\n")

    for i, target in enumerate(targets, 1):
        sr = SmokeResult(
            target=target.url,
            name=target.name,
            zone=target.zone,
        )
        t0 = time.time()

        if verbose and not json_output:
            from fray.ui import S
            zone_badge = f"{S.bright_cyan}QA{S.reset}"
            print(f"  [{zone_badge}] {S.bold}{target.name}{S.reset} ({target.url})")

        # Phase 1: WAF Detection
        try:
            det = _run_detect(target)
            if "error" not in det:
                sr.waf_detected = det.get("waf", "")
                expected = target.expected_waf.lower()
                detected = sr.waf_detected.lower()
                if expected == "none":
                    sr.waf_match = detected == "" or detected == "none"
                elif expected == "":
                    sr.waf_match = True  # No expectation
                else:
                    sr.waf_match = expected in detected or detected in expected
                if verbose and not json_output:
                    from fray.ui import S
                    waf_str = sr.waf_detected or "none"
                    match_icon = f"{S.success}✓{S.reset}" if sr.waf_match else f"{S.warning}~{S.reset}"
                    print(f"    WAF: {waf_str} {match_icon}")
            else:
                sr.error = det["error"]
        except Exception as e:
            sr.error = str(e)

        # Phase 2: Recon (if not errored)
        if not sr.error:
            try:
                rec = _run_recon(target)
                if "error" not in rec:
                    sr.recon_ok = True
                    sr.findings_count = rec.get("findings", 0)
                    sr.details["recon"] = rec
                    if verbose and not json_output:
                        from fray.ui import S
                        print(f"    Recon: {rec.get('technologies', 0)} techs, "
                              f"risk={rec.get('risk_score', 0)}, "
                              f"{rec.get('attack_vectors', 0)} vectors {S.success}✓{S.reset}")
                else:
                    sr.error = rec["error"]
            except Exception as e:
                sr.error = str(e)

        # Phase 3: Payload test (full mode — all QA targets are testable)
        if mode == "full" and not sr.error:
            try:
                tst = _run_test(target, category="xss", max_payloads=5)
                if "error" not in tst:
                    sr.test_ok = True
                    sr.details["test"] = tst
                    if verbose and not json_output:
                        from fray.ui import S
                        print(f"    Test: {tst.get('total', 0)} payloads, "
                              f"{tst.get('passed', 0)} passed, "
                              f"{tst.get('blocked', 0)} blocked {S.success}✓{S.reset}")
            except Exception as e:
                sr.error = str(e)

        sr.duration_s = round(time.time() - t0, 1)
        sr.status = "pass" if not sr.error else "error"

        if verbose and not json_output:
            from fray.ui import S
            status_icon = f"{S.success}PASS{S.reset}" if sr.status == "pass" else f"{S.error}ERR{S.reset}"
            print(f"    {status_icon} ({sr.duration_s}s)\n")

        results.append(sr)

    # Summary
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status != "pass")
    waf_matches = sum(1 for r in results if r.waf_match)
    total_time = sum(r.duration_s for r in results)

    if verbose and not json_output:
        from fray.ui import S
        print(f"  {S.dim}{'━' * 56}{S.reset}")
        print(f"  {S.bold}Results:{S.reset} "
              f"{S.success}{passed} passed{S.reset}  "
              f"{S.error}{failed} failed{S.reset}  "
              f"WAF match: {waf_matches}/{len(results)}  "
              f"({total_time:.0f}s)")
        print()

    if json_output:
        output = {
            "version": __version__,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "zone": zone,
            "mode": mode,
            "targets": len(results),
            "passed": passed,
            "failed": failed,
            "waf_accuracy": f"{waf_matches}/{len(results)}",
            "total_time_s": round(total_time, 1),
            "results": [asdict(r) for r in results],
        }
        print(json.dumps(output, indent=2, default=str))

    return results


# ── CLI entry point ──────────────────────────────────────────────────────────

def cmd_smoke(args):
    """CLI handler for 'fray smoke'."""
    quick = getattr(args, "quick", False)
    full = getattr(args, "full", False)
    json_out = getattr(args, "json", False)

    mode = "full" if full else "quick"

    results = run_smoke_test(
        mode=mode,
        verbose=True,
        json_output=json_out,
    )

    # Exit code: 0 if all pass, 1 if any fail
    failed = sum(1 for r in results if r.status != "pass")
    return 1 if failed > 0 else 0
