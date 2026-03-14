#!/usr/bin/env python3
"""
Fray Compare — A/B bypass testing: impersonated vs raw TLS fingerprint.

Tests the same payloads twice:
  1. Raw (Python default TLS) — how WAF sees a scanner
  2. Impersonated (curl_cffi browser TLS) — how WAF sees a real browser

Reports which blocks are TLS-fingerprint-based vs content-based.

Usage:
    fray compare https://target.com -c xss --max 20
"""

import time
from typing import Dict, List, Optional


class CompareResult:
    """Result of A/B bypass comparison."""

    def __init__(self):
        self.target = ""
        self.category = ""
        self.total_payloads = 0
        self.raw_bypasses = 0
        self.raw_blocked = 0
        self.imp_bypasses = 0
        self.imp_blocked = 0
        self.tls_fingerprint_blocks = 0  # Blocked raw but passed impersonated
        self.content_blocks = 0           # Blocked in both
        self.both_pass = 0                # Passed in both
        self.imp_only_blocked = 0         # Passed raw but blocked impersonated (rare)
        self.details: List[Dict] = []
        self.elapsed_s = 0.0
        self.impersonate_browser = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "category": self.category,
            "total_payloads": self.total_payloads,
            "impersonate_browser": self.impersonate_browser,
            "raw": {"bypasses": self.raw_bypasses, "blocked": self.raw_blocked},
            "impersonated": {"bypasses": self.imp_bypasses, "blocked": self.imp_blocked},
            "tls_fingerprint_blocks": self.tls_fingerprint_blocks,
            "content_blocks": self.content_blocks,
            "both_pass": self.both_pass,
            "imp_only_blocked": self.imp_only_blocked,
            "tls_block_pct": round(self.tls_fingerprint_blocks / max(self.total_payloads, 1) * 100, 1),
            "elapsed_s": round(self.elapsed_s, 1),
            "details": self.details[:50],
        }


def run_compare(target: str, category: str = "xss", max_payloads: int = 20,
                param: str = "q", timeout: int = 8, delay: float = 0.3,
                verify_ssl: bool = False, impersonate: str = "chrome",
                custom_headers: Dict[str, str] = None,
                verbose: bool = False) -> CompareResult:
    """Run A/B comparison: raw vs impersonated requests.

    Args:
        target: Target URL.
        category: Payload category.
        max_payloads: Max payloads to test (each tested twice).
        param: Query parameter for injection.
        timeout: Request timeout.
        delay: Delay between requests.
        verify_ssl: Verify SSL certs.
        impersonate: Browser to impersonate (chrome, firefox, safari).
        custom_headers: Custom headers.
        verbose: Verbose output.

    Returns:
        CompareResult with breakdown of TLS-based vs content-based blocks.
    """
    from fray.tester import WAFTester
    from fray import PAYLOADS_DIR
    from pathlib import Path
    import json as _json

    t0 = time.monotonic()
    result = CompareResult()
    result.target = target
    result.category = category
    result.impersonate_browser = impersonate

    # Load payloads
    cat_dir = PAYLOADS_DIR / category
    payloads = []
    if cat_dir.is_dir():
        for pf in sorted(cat_dir.glob("*.json")):
            try:
                data = _json.loads(pf.read_text(encoding="utf-8"))
                plist = data.get("payloads", data) if isinstance(data, dict) else data
                if isinstance(plist, list):
                    payloads.extend(plist)
            except Exception:
                pass

    if not payloads:
        return result

    test_payloads = payloads[:max_payloads]
    result.total_payloads = len(test_payloads)

    # Create two testers: raw (no impersonation) and impersonated
    tester_raw = WAFTester(
        target=target, timeout=timeout, delay=delay,
        verify_ssl=verify_ssl, custom_headers=custom_headers,
        impersonate=None,  # Raw Python TLS
    )
    tester_imp = WAFTester(
        target=target, timeout=timeout, delay=delay,
        verify_ssl=verify_ssl, custom_headers=custom_headers,
        impersonate=impersonate,  # Browser TLS fingerprint
    )

    for i, payload_data in enumerate(test_payloads):
        payload = payload_data.get("payload", payload_data) if isinstance(payload_data, dict) else str(payload_data)

        # Test with raw TLS
        r_raw = tester_raw.test_payload(payload, param=param)
        time.sleep(delay)

        # Test with impersonated TLS
        r_imp = tester_imp.test_payload(payload, param=param)
        time.sleep(delay)

        raw_blocked = r_raw.get("blocked", True)
        imp_blocked = r_imp.get("blocked", True)

        detail = {
            "payload": payload[:80],
            "raw_blocked": raw_blocked,
            "raw_status": r_raw.get("status", 0),
            "imp_blocked": imp_blocked,
            "imp_status": r_imp.get("status", 0),
            "classification": "",
        }

        if raw_blocked and not imp_blocked:
            result.tls_fingerprint_blocks += 1
            detail["classification"] = "tls_fingerprint"
        elif raw_blocked and imp_blocked:
            result.content_blocks += 1
            detail["classification"] = "content_based"
        elif not raw_blocked and not imp_blocked:
            result.both_pass += 1
            detail["classification"] = "both_pass"
        elif not raw_blocked and imp_blocked:
            result.imp_only_blocked += 1
            detail["classification"] = "imp_only_blocked"

        if raw_blocked:
            result.raw_blocked += 1
        else:
            result.raw_bypasses += 1

        if imp_blocked:
            result.imp_blocked += 1
        else:
            result.imp_bypasses += 1

        result.details.append(detail)

        if verbose:
            _C = {
                "tls_fingerprint": "\033[92mTLS-FINGERPRINT\033[0m",
                "content_based": "\033[91mCONTENT-BASED\033[0m",
                "both_pass": "\033[92mBOTH-PASS\033[0m",
                "imp_only_blocked": "\033[93mIMP-ONLY-BLOCKED\033[0m",
            }
            cls = _C.get(detail["classification"], detail["classification"])
            print(f"  [{i+1}/{len(test_payloads)}] {cls:>30}  "
                  f"raw={r_raw.get('status', '?')} imp={r_imp.get('status', '?')}  "
                  f"{payload[:40]}")

    result.elapsed_s = time.monotonic() - t0
    return result


def print_compare(result: CompareResult):
    """Pretty-print comparison results."""
    R = "\033[0m"
    B = "\033[1m"
    G = "\033[92m"
    Y = "\033[93m"
    RED = "\033[91m"
    C = "\033[96m"
    D = "\033[90m"

    print(f"\n  {B}⚔  Fray Compare — A/B TLS Fingerprint Analysis{R}")
    print(f"  {'─' * 52}")
    print(f"  Target:     {C}{result.target}{R}")
    print(f"  Category:   {result.category}")
    print(f"  Payloads:   {result.total_payloads}")
    print(f"  Browser:    {result.impersonate_browser}")
    print(f"  Duration:   {result.elapsed_s:.1f}s\n")

    # Side-by-side comparison
    print(f"  {'':>18} {D}{'Raw (Python TLS)':>18}  {'Impersonated':>18}{R}")
    print(f"  {'Bypasses':<18} {G}{result.raw_bypasses:>18}{R}  {G}{result.imp_bypasses:>18}{R}")
    print(f"  {'Blocked':<18} {RED}{result.raw_blocked:>18}{R}  {RED}{result.imp_blocked:>18}{R}")

    print(f"\n  {B}Classification:{R}")
    _total = max(result.total_payloads, 1)
    tls_pct = result.tls_fingerprint_blocks / _total * 100
    content_pct = result.content_blocks / _total * 100
    both_pct = result.both_pass / _total * 100

    print(f"  {G}TLS-fingerprint blocks:{R}  {B}{result.tls_fingerprint_blocks}{R} "
          f"({tls_pct:.0f}%) — WAF blocks based on Python TLS, browser TLS passes")
    print(f"  {RED}Content-based blocks:{R}    {B}{result.content_blocks}{R} "
          f"({content_pct:.0f}%) — WAF blocks payload content regardless of TLS")
    print(f"  {G}Both pass:{R}               {B}{result.both_pass}{R} "
          f"({both_pct:.0f}%) — WAF allows both raw and impersonated")

    if result.imp_only_blocked:
        print(f"  {Y}Impersonated-only blocks:{R} {result.imp_only_blocked} (unusual)")

    # Recommendation
    print(f"\n  {B}Recommendation:{R}")
    if tls_pct > 30:
        print(f"  {G}▸ Use --impersonate or --stealth{R} — {tls_pct:.0f}% of blocks are TLS-based")
        print(f"    The WAF is fingerprinting Python's TLS handshake as a scanner.")
    elif tls_pct > 10:
        print(f"  {Y}▸ --impersonate helps marginally{R} — {tls_pct:.0f}% of blocks are TLS-based")
        print(f"    Most blocks are content-based; focus on payload mutation.")
    else:
        print(f"  {D}▸ Impersonation has minimal effect{R} — blocks are content-based")
        print(f"    Focus on fray agent/bypass for WAF-specific payload mutations.")
    print()
