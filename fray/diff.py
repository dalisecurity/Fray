#!/usr/bin/env python3
"""
Fray Diff — Compare two scan results and surface regressions.

Usage:
    fray diff before.json after.json
    fray diff before.json after.json --json
    fray diff before.json after.json -o diff_report.json

Compares two Fray scan results (from `fray bypass --output` or `fray test`)
and highlights:
  - Regressions: payloads that were BLOCKED before but BYPASS now
  - Improvements: payloads that BYPASSED before but are BLOCKED now
  - Score changes, strictness changes, new/removed blocked patterns
  - Summary verdict: PASS / REGRESSED / IMPROVED

Designed for WAF config change validation in CI/CD pipelines.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class DiffResult:
    """Result of comparing two scan reports."""
    # Metadata
    before_file: str = ""
    after_file: str = ""
    target: str = ""
    before_timestamp: str = ""
    after_timestamp: str = ""

    # Verdict: PASS, REGRESSED, IMPROVED, MIXED
    verdict: str = ""

    # Score delta
    before_score: float = 0.0
    after_score: float = 0.0
    score_delta: float = 0.0

    # Bypass rate delta
    before_bypass_rate: float = 0.0
    after_bypass_rate: float = 0.0
    bypass_rate_delta: float = 0.0

    # Strictness change
    before_strictness: str = ""
    after_strictness: str = ""

    # Stat deltas
    before_total_tested: int = 0
    after_total_tested: int = 0
    before_total_blocked: int = 0
    after_total_blocked: int = 0
    before_total_bypassed: int = 0
    after_total_bypassed: int = 0

    # Regressions: payloads blocked before → bypass now
    regressions: List[Dict] = field(default_factory=list)

    # Improvements: payloads bypassed before → blocked now
    improvements: List[Dict] = field(default_factory=list)

    # New bypasses (payload not in before scan at all)
    new_bypasses: List[Dict] = field(default_factory=list)

    # WAF profile changes
    new_blocked_tags: List[str] = field(default_factory=list)
    removed_blocked_tags: List[str] = field(default_factory=list)
    new_blocked_events: List[str] = field(default_factory=list)
    removed_blocked_events: List[str] = field(default_factory=list)
    new_blocked_keywords: List[str] = field(default_factory=list)
    removed_blocked_keywords: List[str] = field(default_factory=list)


def _normalize_report(data: dict) -> dict:
    """Normalize both bypass scorecard and test result formats into a common shape."""
    # Bypass scorecard format (from `fray bypass --output`)
    if "overall_evasion_score" in data:
        total = data.get("total_tested", 0) + data.get("mutations_tested", 0)
        bypassed = data.get("total_bypassed", 0) + data.get("mutations_bypassed", 0)
        blocked = total - bypassed

        # Build payload→status map from bypasses list
        payload_map = {}
        for bp in data.get("bypasses", []):
            payload_map[bp.get("payload", "")] = {
                "blocked": False,
                "status": bp.get("status", 0),
                "evasion_score": bp.get("evasion_score", 0),
                "technique": bp.get("technique", ""),
                "reflected": bp.get("reflected", False),
            }

        return {
            "format": "bypass",
            "target": data.get("target", ""),
            "timestamp": data.get("timestamp", ""),
            "score": data.get("overall_evasion_score", 0.0),
            "strictness": data.get("waf_strictness", ""),
            "total_tested": total,
            "total_blocked": blocked,
            "total_bypassed": bypassed,
            "bypass_rate": (bypassed / total * 100) if total > 0 else 0.0,
            "blocked_tags": set(data.get("blocked_tags", [])),
            "blocked_events": set(data.get("blocked_events", [])),
            "blocked_keywords": set(data.get("blocked_keywords", [])),
            "payload_map": payload_map,
        }

    # Test result format (from `fray test`)
    if "results" in data:
        results = data["results"]
    elif isinstance(data, list):
        results = data
    else:
        results = []

    total = len(results)
    bypassed = sum(1 for r in results if not r.get("blocked", True))
    blocked = total - bypassed

    payload_map = {}
    for r in results:
        p = r.get("payload", "")
        payload_map[p] = {
            "blocked": r.get("blocked", True),
            "status": r.get("status", 0),
            "evasion_score": 0.0,
            "technique": "",
            "reflected": r.get("reflected", False),
        }

    return {
        "format": "test",
        "target": data.get("target", ""),
        "timestamp": data.get("timestamp", ""),
        "score": 0.0,
        "strictness": "",
        "total_tested": total,
        "total_blocked": blocked,
        "total_bypassed": bypassed,
        "bypass_rate": (bypassed / total * 100) if total > 0 else 0.0,
        "blocked_tags": set(),
        "blocked_events": set(),
        "blocked_keywords": set(),
        "payload_map": payload_map,
    }


def run_diff(before_path: str, after_path: str) -> DiffResult:
    """Compare two scan result files and return a DiffResult.

    Args:
        before_path: Path to the baseline ("before") scan JSON
        after_path: Path to the new ("after") scan JSON

    Returns:
        DiffResult with regressions, improvements, and verdict
    """
    with open(before_path, "r", encoding="utf-8") as f:
        before_raw = json.load(f)
    with open(after_path, "r", encoding="utf-8") as f:
        after_raw = json.load(f)

    before = _normalize_report(before_raw)
    after = _normalize_report(after_raw)

    result = DiffResult(
        before_file=before_path,
        after_file=after_path,
        target=after.get("target", before.get("target", "")),
        before_timestamp=before.get("timestamp", ""),
        after_timestamp=after.get("timestamp", ""),
        before_score=before["score"],
        after_score=after["score"],
        score_delta=round(after["score"] - before["score"], 1),
        before_bypass_rate=round(before["bypass_rate"], 1),
        after_bypass_rate=round(after["bypass_rate"], 1),
        bypass_rate_delta=round(after["bypass_rate"] - before["bypass_rate"], 1),
        before_strictness=before["strictness"],
        after_strictness=after["strictness"],
        before_total_tested=before["total_tested"],
        after_total_tested=after["total_tested"],
        before_total_blocked=before["total_blocked"],
        after_total_blocked=after["total_blocked"],
        before_total_bypassed=before["total_bypassed"],
        after_total_bypassed=after["total_bypassed"],
    )

    # WAF profile changes (bypass format only)
    result.new_blocked_tags = sorted(after["blocked_tags"] - before["blocked_tags"])
    result.removed_blocked_tags = sorted(before["blocked_tags"] - after["blocked_tags"])
    result.new_blocked_events = sorted(after["blocked_events"] - before["blocked_events"])
    result.removed_blocked_events = sorted(before["blocked_events"] - after["blocked_events"])
    result.new_blocked_keywords = sorted(after["blocked_keywords"] - before["blocked_keywords"])
    result.removed_blocked_keywords = sorted(before["blocked_keywords"] - after["blocked_keywords"])

    # Payload-level comparison
    before_map = before["payload_map"]
    after_map = after["payload_map"]

    for payload, after_info in after_map.items():
        if payload in before_map:
            before_info = before_map[payload]
            # Regression: was blocked → now bypasses
            if before_info["blocked"] and not after_info["blocked"]:
                result.regressions.append({
                    "payload": payload[:80],
                    "before_status": before_info["status"],
                    "after_status": after_info["status"],
                    "evasion_score": after_info.get("evasion_score", 0),
                    "technique": after_info.get("technique", ""),
                    "reflected": after_info.get("reflected", False),
                })
            # Improvement: was bypass → now blocked
            elif not before_info["blocked"] and after_info["blocked"]:
                result.improvements.append({
                    "payload": payload[:80],
                    "before_status": before_info["status"],
                    "after_status": after_info["status"],
                })
        else:
            # New bypass not in before scan
            if not after_info["blocked"]:
                result.new_bypasses.append({
                    "payload": payload[:80],
                    "status": after_info["status"],
                    "evasion_score": after_info.get("evasion_score", 0),
                    "technique": after_info.get("technique", ""),
                })

    # Verdict
    if result.regressions and not result.improvements:
        result.verdict = "REGRESSED"
    elif result.improvements and not result.regressions:
        result.verdict = "IMPROVED"
    elif result.regressions and result.improvements:
        result.verdict = "MIXED"
    elif result.score_delta > 0.5:
        result.verdict = "REGRESSED"
    elif result.score_delta < -0.5:
        result.verdict = "IMPROVED"
    else:
        result.verdict = "PASS"

    # Sort regressions by score (worst first)
    result.regressions.sort(key=lambda r: r.get("evasion_score", 0), reverse=True)

    return result


class _Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'


def _verdict_color(verdict: str) -> str:
    if verdict == "REGRESSED":
        return f"{_Colors.RED}{_Colors.BOLD}{verdict}{_Colors.END}"
    elif verdict == "IMPROVED":
        return f"{_Colors.GREEN}{_Colors.BOLD}{verdict}{_Colors.END}"
    elif verdict == "MIXED":
        return f"{_Colors.YELLOW}{_Colors.BOLD}{verdict}{_Colors.END}"
    else:
        return f"{_Colors.GREEN}{_Colors.BOLD}{verdict}{_Colors.END}"


def _delta_str(val: float, suffix: str = "", higher_is_worse: bool = True) -> str:
    """Format a delta value with color (green=better, red=worse)."""
    if val == 0:
        return f"{_Colors.DIM}±0{suffix}{_Colors.END}"
    sign = "+" if val > 0 else ""
    color = _Colors.RED if (val > 0 and higher_is_worse) or (val < 0 and not higher_is_worse) else _Colors.GREEN
    return f"{color}{sign}{val}{suffix}{_Colors.END}"


def print_diff(diff: DiffResult) -> None:
    """Print a formatted diff report to stdout."""
    C = _Colors

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
    print(f"{C.BOLD}  Fray Diff — Scan Comparison{C.END}")
    print(f"{C.BOLD}{'━' * 60}{C.END}")
    print(f"  Target:  {diff.target}")
    print(f"  Before:  {diff.before_file}")
    print(f"  After:   {diff.after_file}")
    print(f"  Verdict: {_verdict_color(diff.verdict)}")

    # Score & rate changes
    print(f"\n  {'─' * 45}")
    if diff.before_score or diff.after_score:
        print(f"  Evasion Score:  {diff.before_score} → {diff.after_score}  "
              f"{_delta_str(diff.score_delta)}")
    print(f"  Bypass Rate:    {diff.before_bypass_rate}% → {diff.after_bypass_rate}%  "
          f"{_delta_str(diff.bypass_rate_delta, '%')}")
    print(f"  Tested:         {diff.before_total_tested} → {diff.after_total_tested}")
    print(f"  Blocked:        {diff.before_total_blocked} → {diff.after_total_blocked}  "
          f"{_delta_str(diff.after_total_blocked - diff.before_total_blocked, '', higher_is_worse=False)}")
    print(f"  Bypassed:       {diff.before_total_bypassed} → {diff.after_total_bypassed}  "
          f"{_delta_str(diff.after_total_bypassed - diff.before_total_bypassed, '')}")

    # Strictness change
    if diff.before_strictness and diff.after_strictness and diff.before_strictness != diff.after_strictness:
        print(f"\n  Strictness:     {diff.before_strictness} → {diff.after_strictness}")

    # WAF profile changes
    profile_changes = (diff.new_blocked_tags or diff.removed_blocked_tags or
                       diff.new_blocked_events or diff.removed_blocked_events or
                       diff.new_blocked_keywords or diff.removed_blocked_keywords)
    if profile_changes:
        print(f"\n  {C.CYAN}WAF Profile Changes:{C.END}")
        if diff.new_blocked_tags:
            print(f"    {C.GREEN}+ Now blocking tags:{C.END} {', '.join(diff.new_blocked_tags)}")
        if diff.removed_blocked_tags:
            print(f"    {C.RED}- No longer blocking tags:{C.END} {', '.join(diff.removed_blocked_tags)}")
        if diff.new_blocked_events:
            print(f"    {C.GREEN}+ Now blocking events:{C.END} {', '.join(diff.new_blocked_events)}")
        if diff.removed_blocked_events:
            print(f"    {C.RED}- No longer blocking events:{C.END} {', '.join(diff.removed_blocked_events)}")
        if diff.new_blocked_keywords:
            print(f"    {C.GREEN}+ Now blocking keywords:{C.END} {', '.join(diff.new_blocked_keywords)}")
        if diff.removed_blocked_keywords:
            print(f"    {C.RED}- No longer blocking keywords:{C.END} {', '.join(diff.removed_blocked_keywords)}")

    # Regressions
    if diff.regressions:
        print(f"\n  {C.RED}{C.BOLD}⚠ Regressions ({len(diff.regressions)} payloads now bypass):{C.END}")
        for i, reg in enumerate(diff.regressions[:10], 1):
            reflected = f" {C.YELLOW}REFLECTED{C.END}" if reg.get("reflected") else ""
            technique = f" [{reg['technique']}]" if reg.get("technique") else ""
            print(f"    {i}. {reg['before_status']} → {reg['after_status']}{technique}{reflected}")
            print(f"       {C.DIM}{reg['payload']}{C.END}")
        if len(diff.regressions) > 10:
            print(f"    {C.DIM}... and {len(diff.regressions) - 10} more{C.END}")

    # Improvements
    if diff.improvements:
        print(f"\n  {C.GREEN}{C.BOLD}✓ Improvements ({len(diff.improvements)} payloads now blocked):{C.END}")
        for i, imp in enumerate(diff.improvements[:10], 1):
            print(f"    {i}. {imp['before_status']} → {imp['after_status']}")
            print(f"       {C.DIM}{imp['payload']}{C.END}")
        if len(diff.improvements) > 10:
            print(f"    {C.DIM}... and {len(diff.improvements) - 10} more{C.END}")

    # New bypasses
    if diff.new_bypasses:
        print(f"\n  {C.YELLOW}New bypasses ({len(diff.new_bypasses)} not in baseline):{C.END}")
        for i, nb in enumerate(diff.new_bypasses[:5], 1):
            technique = f" [{nb['technique']}]" if nb.get("technique") else ""
            print(f"    {i}. status {nb['status']}{technique}")
            print(f"       {C.DIM}{nb['payload']}{C.END}")
        if len(diff.new_bypasses) > 5:
            print(f"    {C.DIM}... and {len(diff.new_bypasses) - 5} more{C.END}")

    if not diff.regressions and not diff.improvements and not diff.new_bypasses:
        print(f"\n  {C.GREEN}No payload-level changes detected.{C.END}")

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
