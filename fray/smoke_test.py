"""
Fray Smoke Test — Run against real sites + community vulnerable targets.

Hardcoded target zones covering:
- Real production sites with known WAFs (Panasonic, Sony, Toyota, etc.)
- Community-provided intentionally vulnerable web apps (OWASP, HackTheBox, etc.)

Usage:
    fray smoke                     # Run all zones
    fray smoke --zone real         # Only real sites
    fray smoke --zone vulnerable   # Only intentionally vulnerable sites
    fray smoke --quick             # Quick mode (detect + recon only)
    fray smoke --full              # Full mode (detect + recon + test + agent)
    fray smoke --json              # JSON output for CI
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


# Real production sites — major companies with known WAF protection.
# These are public websites; we only do non-destructive recon + detection.
REAL_TARGETS = [
    SmokeTarget(
        url="https://www.panasonic.com",
        name="Panasonic",
        zone="real",
        expected_waf="akamai",
        description="Japanese electronics — Akamai WAF",
        tags=["akamai", "enterprise", "japan"],
    ),
    SmokeTarget(
        url="https://www.sony.com",
        name="Sony",
        zone="real",
        expected_waf="akamai",
        description="Entertainment/electronics — Akamai WAF",
        tags=["akamai", "enterprise", "japan"],
    ),
    SmokeTarget(
        url="https://www.toyota.com",
        name="Toyota",
        zone="real",
        expected_waf="cloudflare",
        description="Automotive — Cloudflare WAF",
        tags=["cloudflare", "enterprise", "japan"],
    ),
    SmokeTarget(
        url="https://www.shopify.com",
        name="Shopify",
        zone="real",
        expected_waf="cloudflare",
        description="E-commerce platform — Cloudflare WAF",
        tags=["cloudflare", "saas"],
    ),
    SmokeTarget(
        url="https://www.github.com",
        name="GitHub",
        zone="real",
        expected_waf="",
        description="Developer platform — custom edge",
        tags=["custom", "saas"],
    ),
]

# Intentionally vulnerable sites — provided by the security community
# for testing. These are designed to be tested against.
VULNERABLE_TARGETS = [
    SmokeTarget(
        url="http://testphp.vulnweb.com",
        name="Acunetix testphp",
        zone="vulnerable",
        expected_waf="none",
        description="Acunetix intentionally vulnerable PHP app",
        tags=["vuln", "php", "acunetix"],
    ),
    SmokeTarget(
        url="http://testaspnet.vulnweb.com",
        name="Acunetix testaspnet",
        zone="vulnerable",
        expected_waf="none",
        description="Acunetix intentionally vulnerable ASP.NET app",
        tags=["vuln", "aspnet", "acunetix"],
    ),
    SmokeTarget(
        url="http://testasp.vulnweb.com",
        name="Acunetix testasp",
        zone="vulnerable",
        expected_waf="none",
        description="Acunetix intentionally vulnerable classic ASP app",
        tags=["vuln", "asp", "acunetix"],
    ),
    SmokeTarget(
        url="https://juice-shop.herokuapp.com",
        name="OWASP Juice Shop",
        zone="vulnerable",
        expected_waf="none",
        description="OWASP Juice Shop — intentionally insecure JS app",
        tags=["vuln", "owasp", "nodejs"],
    ),
    SmokeTarget(
        url="http://zero.webappsecurity.com",
        name="Zero Bank",
        zone="vulnerable",
        expected_waf="none",
        description="Micro Focus intentionally vulnerable banking app",
        tags=["vuln", "banking", "microfocus"],
    ),
]

ALL_TARGETS = REAL_TARGETS + VULNERABLE_TARGETS


def get_targets(zone: str = "all") -> List[SmokeTarget]:
    """Get targets by zone: 'all', 'real', or 'vulnerable'."""
    if zone == "real":
        return REAL_TARGETS
    elif zone == "vulnerable":
        return VULNERABLE_TARGETS
    return ALL_TARGETS


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
    mode: str = "quick",  # "quick" = detect+recon, "full" = +test+agent
    verbose: bool = True,
    json_output: bool = False,
) -> List[SmokeResult]:
    """Run smoke tests against all targets in a zone.

    Args:
        zone: "all", "real", or "vulnerable"
        mode: "quick" (detect+recon) or "full" (+test)
        verbose: print progress
        json_output: return JSON instead of pretty-print

    Returns:
        List of SmokeResult objects.
    """
    targets = get_targets(zone)
    results: List[SmokeResult] = []

    if verbose and not json_output:
        from fray.ui import S
        print(f"\n  {S.bold}{S.white}Fray Smoke Test{S.reset}  "
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
            zone_badge = f"{S.bright_cyan}REAL{S.reset}" if target.zone == "real" else f"{S.warning}VULN{S.reset}"
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

        # Phase 3: Payload test (full mode only, vulnerable targets only)
        if mode == "full" and target.zone == "vulnerable" and not sr.error:
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
    zone = getattr(args, "zone", "all")
    quick = getattr(args, "quick", False)
    full = getattr(args, "full", False)
    json_out = getattr(args, "json", False)

    mode = "full" if full else "quick"

    results = run_smoke_test(
        zone=zone,
        mode=mode,
        verbose=True,
        json_output=json_out,
    )

    # Exit code: 0 if all pass, 1 if any fail
    failed = sum(1 for r in results if r.status != "pass")
    return 1 if failed > 0 else 0
