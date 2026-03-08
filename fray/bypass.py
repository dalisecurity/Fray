#!/usr/bin/env python3
"""
Fray Bypass — WAF evasion scoring engine.

Usage:
    fray bypass https://target.com --waf cloudflare -c xss
    fray bypass https://target.com --waf aws_waf -c sqli --stealth
    fray bypass https://target.com -c xss --max 100 --json

Runs evasion-optimized payload variants, scores which ones slip through,
and generates a shareable bypass scorecard for the bug bounty community.
"""

import json
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from fray import __version__
from fray.evolve import (
    WAFProfile, PayloadMutator, DIAGNOSTIC_PROBES,
    run_probes, score_payload, rank_payloads,
    _extract_tags, _extract_events, _extract_keywords,
)


# ── WAF-Specific Evasion Strategies ──────────────────────────────────────────

# Known WAF weaknesses — used to prioritize mutation strategies per vendor
WAF_EVASION_HINTS: Dict[str, Dict] = {
    "cloudflare": {
        "label": "Cloudflare",
        "weak_encodings": ["unicode", "mixed_case"],
        "tips": [
            "Cloudflare blocks most <script> but allows some <svg> and <details>",
            "HTML entity encoding often bypasses Cloudflare rules",
            "Nested template literals can evade JS function detection",
            "Cloudflare's parser struggles with null bytes in tag names",
        ],
        "priority_mutations": [
            "html_entity_encode", "case_randomize", "comment_injection",
            "tag_substitute", "whitespace_variation",
        ],
    },
    "akamai": {
        "label": "Akamai",
        "weak_encodings": ["html_entity", "double_url"],
        "tips": [
            "Akamai Kona is strict on <script> and onerror",
            "Double URL-encoding often slips through",
            "Alternative event handlers (onfocus, onpointerenter) less monitored",
            "Content-type confusion can bypass body inspection",
        ],
        "priority_mutations": [
            "double_url_encode", "event_swap", "unicode_escape",
            "null_byte_insert", "whitespace_variation",
        ],
    },
    "aws_waf": {
        "label": "AWS WAF",
        "weak_encodings": ["unicode", "html_entity"],
        "tips": [
            "AWS WAF rules are regex-based — comment injection breaks patterns",
            "Mixed case and unicode escapes often bypass managed rules",
            "AWS WAF v2 managed rules focus on OWASP Top 10 — niche vectors slip through",
            "Rate limiting is aggressive — use --stealth",
        ],
        "priority_mutations": [
            "comment_injection", "case_randomize", "unicode_escape",
            "html_entity_encode", "null_byte_insert",
        ],
    },
    "imperva": {
        "label": "Imperva (Incapsula)",
        "weak_encodings": ["mixed_case"],
        "tips": [
            "Imperva's SecureSphere uses deep packet inspection",
            "Whitespace variations and tab characters often bypass",
            "Imperva blocks by content-length anomalies — keep payloads short",
            "Polyglot payloads across HTML/JS contexts can evade",
        ],
        "priority_mutations": [
            "whitespace_variation", "case_randomize", "comment_injection",
            "tag_substitute", "null_byte_insert",
        ],
    },
    "f5": {
        "label": "F5 BIG-IP ASM",
        "weak_encodings": ["unicode", "double_url"],
        "tips": [
            "F5 ASM uses violation ratings — stay below threshold",
            "HTML entity encoding is effective against signature matching",
            "Double encoding exploits normalization differences",
            "F5 is weakest on newer HTML5 event handlers",
        ],
        "priority_mutations": [
            "html_entity_encode", "double_url_encode", "event_swap",
            "unicode_escape", "comment_injection",
        ],
    },
    "fastly": {
        "label": "Fastly (Signal Sciences)",
        "weak_encodings": ["html_entity", "mixed_case"],
        "tips": [
            "Signal Sciences focuses on anomaly scoring, not regex",
            "Low-entropy payloads score lower — use obfuscation",
            "Alternative protocol handlers (data:, blob:) less monitored",
        ],
        "priority_mutations": [
            "html_entity_encode", "case_randomize", "whitespace_variation",
            "double_url_encode", "tag_substitute",
        ],
    },
    "modsecurity": {
        "label": "ModSecurity (CRS)",
        "weak_encodings": ["unicode", "mixed_case", "double_url"],
        "tips": [
            "CRS paranoia level 1-2 is bypassable with most encoding tricks",
            "Paranoia level 3-4 is harder — focus on comment injection and null bytes",
            "CRS regex rules have known bypass patterns for each version",
            "Double encoding is the #1 ModSecurity bypass technique",
        ],
        "priority_mutations": [
            "double_url_encode", "comment_injection", "unicode_escape",
            "case_randomize", "null_byte_insert",
        ],
    },
}

# Normalize WAF name aliases
_WAF_ALIASES = {
    "cf": "cloudflare", "cloudflare": "cloudflare",
    "akamai": "akamai", "kona": "akamai",
    "aws": "aws_waf", "aws_waf": "aws_waf", "awswaf": "aws_waf",
    "imperva": "imperva", "incapsula": "imperva",
    "f5": "f5", "bigip": "f5", "big-ip": "f5", "asm": "f5",
    "fastly": "fastly", "signal_sciences": "fastly", "sigsci": "fastly",
    "modsecurity": "modsecurity", "modsec": "modsecurity", "crs": "modsecurity",
}


def resolve_waf_name(name: str) -> Optional[str]:
    """Resolve a WAF name/alias to a canonical key."""
    return _WAF_ALIASES.get(name.lower().replace(" ", "_").replace("-", "_"))


# ── Bypass Scorecard ─────────────────────────────────────────────────────────

@dataclass
class BypassResult:
    """Result of a single bypass attempt."""
    payload: str
    blocked: bool
    status: int
    technique: str = ""         # mutation technique used
    parent: str = ""            # original payload before mutation
    evasion_score: int = 0  # 0–100%
    reflected: bool = False
    reflection_context: str = ""
    response_length: int = 0
    category: str = ""
    description: str = ""


@dataclass
class BypassScorecard:
    """Full bypass assessment results."""
    target: str
    waf_vendor: str = ""
    waf_detected: str = ""
    category: str = ""
    timestamp: str = ""
    duration: str = ""

    # WAF Profile
    waf_strictness: str = ""
    blocked_tags: List[str] = field(default_factory=list)
    blocked_events: List[str] = field(default_factory=list)
    blocked_keywords: List[str] = field(default_factory=list)
    allowed_tags: List[str] = field(default_factory=list)
    probe_block_rate: float = 0.0

    # Test stats
    total_tested: int = 0
    total_blocked: int = 0
    total_bypassed: int = 0
    mutations_tested: int = 0
    mutations_bypassed: int = 0

    # Scoring
    overall_evasion_score: int = 0  # 0–100%

    # Results
    bypasses: List[Dict] = field(default_factory=list)
    top_techniques: List[Dict] = field(default_factory=list)
    tips: List[str] = field(default_factory=list)


def _is_baseline_match(result: dict, baseline: Optional[dict]) -> bool:
    """Check if a response looks identical to the clean baseline.

    If the response status and body length closely match the baseline,
    the app is likely just ignoring the parameter — not a real bypass.
    """
    if not baseline:
        return False
    bl_status = baseline.get("status", 0)
    bl_length = baseline.get("response_length", 0)
    r_status = result.get("status", 0)
    r_length = result.get("response_length", 0)

    if r_status != bl_status:
        return False

    # Body length within 15% of baseline → likely same page
    if bl_length > 0 and r_length > 0:
        ratio = r_length / bl_length
        if 0.85 <= ratio <= 1.15:
            return True
    # Both zero-length
    if bl_length == 0 and r_length == 0:
        return True

    return False


def _is_soft_block(result: dict, baseline: Optional[dict]) -> bool:
    """Detect WAF soft blocks: status 200 but body diverges from baseline.

    Modern WAFs and secure apps return 200 for everything — the real signal
    is body content. If baseline is 95K and payload response is 3K at the
    same status code, the WAF replaced the real page with a block/challenge
    page. This catches:
    - Cloudflare JS challenges (200 with tiny challenge body)
    - AWS WAF custom error pages at 200
    - App-level security (login-style "200 but denied" patterns)
    - CAPTCHA interstitials served at 200
    """
    if not baseline:
        return False
    bl_status = baseline.get("status", 0)
    bl_length = baseline.get("response_length", 0)
    r_status = result.get("status", 0)
    r_length = result.get("response_length", 0)

    # Only applies when status matches baseline (both 200)
    if r_status != bl_status:
        return False

    # If baseline is substantial (>1K) and response shrunk dramatically
    # (under 40% of baseline), it's likely a block/error page
    if bl_length > 1000 and r_length > 0:
        ratio = r_length / bl_length
        if ratio < 0.40:
            return True

    # If baseline has content but response is empty/tiny
    if bl_length > 1000 and r_length < 500:
        return True

    return False


def _score_label(pct: int) -> str:
    """Return a human-readable severity label for a bypass score percentage.

    Score meaning (higher = more dangerous / exploitable bypass):
      90-100%  CRITICAL — Confirmed real bypass, exploit-ready
      70-89%   HIGH     — Strong bypass, likely exploitable with refinement
      40-69%   MEDIUM   — Bypass detected, needs manual verification
      1-39%    LOW      — WAF is strong; weak signals or false positives
      0%       NONE     — No testing performed
    """
    if pct >= 90:
        return "CRITICAL"
    elif pct >= 70:
        return "HIGH"
    elif pct >= 40:
        return "MEDIUM"
    elif pct > 0:
        return "LOW"
    return "NONE"


def _next_steps_for_score(score: int, total_blocked: int, total_bypassed: int,
                           waf_label: str, strictness: str, target: str,
                           category: str = "xss") -> list:
    """Generate actionable next-step recommendations based on results.

    Returns a list of recommendation strings.
    """
    steps = []
    total = total_blocked + total_bypassed

    if total == 0:
        steps.append(f"No payloads tested. Run: fray bypass {target} -c {category} -m 20")
        return steps

    waf_slug = waf_label.lower().replace(" ", "_").split("(")[0].strip("_")

    if total_bypassed == 0:
        # All blocked — WAF is strong, guide the user to try harder
        steps.append(f"WAF held strong: {waf_label} blocked all {total_blocked} payloads ({strictness} strictness)")
        steps.append(f"Increase mutation depth: fray bypass {target} -c {category} -m 100 --waf {waf_slug}")
        steps.append(f"Try different category:  fray bypass {target} -c sqli -m 30")
        steps.append(f"Try smart mode:          fray test {target} -c {category} --smart --max 100")
        if strictness in ("strict", "moderate"):
            steps.append(f"Try stealth mode:        fray bypass {target} -c {category} --stealth -d 1.5")
        steps.append(f"Run full recon:          fray recon {target}")
        return steps

    bypass_rate = total_bypassed / total * 100

    if score >= 90:
        steps.append(f"CRITICAL: {total_bypassed} confirmed bypass(es) — this WAF is vulnerable")
        steps.append(f"Export for report:    fray bypass {target} -c {category} -o bypass_report.json")
        steps.append(f"Generate HTML report: fray report -i bypass_report.json --format html")
        steps.append(f"Test more categories: fray bypass {target} -c sqli,rce,ssrf -m 30")
    elif score >= 70:
        steps.append(f"HIGH: {total_bypassed} strong bypass(es) found ({bypass_rate:.0f}% bypass rate)")
        steps.append(f"Amplify with mutations: fray bypass {target} -c {category} -m 50")
        steps.append(f"Verify with reflection: check if payloads execute in browser context")
        steps.append(f"Try more categories:    fray bypass {target} -c sqli -m 30")
    elif score >= 40:
        steps.append(f"MEDIUM: {total_bypassed} bypass(es) detected but not confirmed")
        steps.append(f"Verify manually — open target in browser and inject payload")
        steps.append(f"Increase testing:   fray bypass {target} -c {category} -m 100")
        steps.append(f"Try smart mode:     fray test {target} -c {category} --smart --max 100")
    else:
        # LOW with some bypasses — likely false positives
        if bypass_rate > 80:
            steps.append(f"LOW: {total_bypassed} passed but likely no real WAF filtering (responses match baseline)")
            steps.append(f"The target may not have a WAF on this endpoint")
            steps.append(f"Detect WAF:            fray detect {target}")
            steps.append(f"Scan for real inputs:   fray scan {target} -c {category}")
        else:
            steps.append(f"LOW: {total_bypassed} weak signal(s) — responses match baseline, likely false positives")
            steps.append(f"Try with a real param:  fray test {target}?q=test -c {category} -m 10")
            steps.append(f"Scan for injection pts: fray scan {target} -c {category}")
        steps.append(f"Run recon to find endpoints: fray recon {target}")

    return steps


def _compute_evasion_score(result: dict, profile: WAFProfile, is_mutation: bool,
                           baseline: Optional[dict] = None) -> int:
    """Compute an evasion score as a percentage (0–100%).

    Higher % = more dangerous bypass:
      90-100%  CRITICAL — Reflected + strict WAF + mutation + blocked-pattern overlap
      70-89%   HIGH     — Strong bypass, reflected or novel mutation
      40-69%   MEDIUM   — Bypassed but no reflection, or permissive WAF
      1-39%    LOW      — Baseline match / likely false positive
      0%       NONE     — Blocked

    Components (max 100 raw points, then penalties applied):
      WAF strictness:  10–40 pts
      Reflected:       +20 pts
      Mutation:        +15 pts
      Blocked-pattern: +5 per overlap (max 20)
      Status 200:      +5 pts
      Baseline match:  ×0.30 penalty (heavy — likely FP)
      Soft block:      ×0.10 penalty (near-zero — WAF interception)
    """
    if result.get("blocked"):
        return 0

    score = 0.0

    # Base: WAF strictness (10–40 pts)
    strictness_map = {"strict": 40.0, "moderate": 30.0, "permissive": 20.0, "minimal": 10.0}
    score += strictness_map.get(profile.strictness, 20.0)

    # Bonus: payload reflected in response (+20 pts)
    if result.get("reflected"):
        score += 20.0

    # Bonus: mutation-generated bypass — novel technique (+15 pts)
    if is_mutation:
        score += 15.0

    # Bonus: bypassed despite using blocked patterns (+5 per overlap, max 20)
    payload = result.get("payload", "")
    tags = _extract_tags(payload)
    events = _extract_events(payload)
    keywords = _extract_keywords(payload)

    blocked_overlap = (
        len(tags & profile.blocked_tags) +
        len(events & profile.blocked_events) +
        len(keywords & profile.blocked_keywords)
    )
    score += min(blocked_overlap * 5.0, 20.0)

    # Bonus: real 200 response (+5 pts)
    if result.get("status") == 200:
        score += 5.0

    # Penalty: response matches clean baseline → likely false positive
    if _is_baseline_match(result, baseline):
        score *= 0.30  # Heavy penalty — probably not a real bypass
    # Penalty: soft block — status 200 but body drastically smaller than baseline
    elif _is_soft_block(result, baseline):
        score *= 0.10  # Near-zero — almost certainly a WAF block at 200

    return int(round(min(score, 100.0)))


def _overall_score(bypasses: List[BypassResult], total_tested: int,
                   profile: WAFProfile) -> int:
    """Compute an overall WAF evasion score as a percentage (0–100%).

    Combines bypass rate and average individual scores, weighted by WAF strictness.

    Minimum score logic (never 0% if testing happened):
      - WAF detected + probes ran = base 3%
      - Testing effort bonus:  +1% per 10 payloads tested (max +5%)
      - Strictness bonus: strict +4%, moderate +3%, permissive +1%
      This ensures even 100% blocked targets show 5-12% ("WAF is strong, tested it")
    """
    if total_tested == 0:
        return 0

    bypass_rate = len(bypasses) / total_tested

    # Weight by strictness
    strictness_weight = {"strict": 1.5, "moderate": 1.2, "permissive": 0.8, "minimal": 0.5}
    weight = strictness_weight.get(profile.strictness, 1.0)

    # Average individual scores (already 0–100)
    if bypasses:
        avg_score = sum(b.evasion_score for b in bypasses) / len(bypasses)
    else:
        avg_score = 0.0

    # Combine: bypass rate (40%) + average score (60%), weighted by strictness
    overall = (bypass_rate * 40.0 * weight) + (avg_score * 0.6)

    # Minimum floor: never 0% if we actually tested payloads
    # This reflects the value of WAF detection + probe + testing effort
    if total_tested > 0:
        base = 3  # WAF detected + probes ran
        effort_bonus = min(total_tested // 10, 5)  # +1% per 10 payloads, max +5%
        strictness_bonus = {"strict": 4, "moderate": 3, "permissive": 1, "minimal": 0}
        s_bonus = strictness_bonus.get(profile.strictness, 1)
        floor = base + effort_bonus + s_bonus  # 3–12%
        overall = max(overall, floor)

    return int(round(min(overall, 100.0)))


# ── Main Bypass Runner ───────────────────────────────────────────────────────

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'


def run_bypass(
    tester,
    payloads: List[Dict],
    waf_name: Optional[str] = None,
    max_payloads: int = 50,
    max_mutations: int = 5,
    mutation_budget: int = 20,
    param: str = "input",
    verbose: bool = True,
    output_file: Optional[str] = None,
    json_output: bool = False,
    category: str = "xss",
) -> BypassScorecard:
    """Run the full bypass assessment.

    1. Detect/confirm WAF vendor
    2. Probe WAF behavior
    3. Score & rank payloads
    4. Test top-ranked payloads
    5. Mutate bypasses aggressively
    6. Score and report
    """
    start_time = time.time()

    # ── Resolve WAF vendor ────────────────────────────────────────────────
    waf_key = resolve_waf_name(waf_name) if waf_name else None

    # Auto-detect WAF if not specified
    if not waf_key:
        try:
            from fray.detector import WAFDetector
            detector = WAFDetector()
            det = detector.detect_waf(tester.target, timeout=tester.timeout,
                                       verify_ssl=tester.verify_ssl)
            detected_name = det.get("waf_vendor", "") or ""
            if detected_name and detected_name.lower() not in ("none", "unknown", ""):
                waf_key = resolve_waf_name(detected_name)
                if not waf_key:
                    # Try matching individual words against known WAF keys
                    import re
                    words = re.findall(r'[a-zA-Z0-9_]+', detected_name.lower())
                    for word in words:
                        if word in WAF_EVASION_HINTS:
                            waf_key = word
                            break
                if not waf_key:
                    # Last resort: use raw detected name
                    waf_key = detected_name.lower().replace(" ", "_")
        except Exception:
            pass

    hints = WAF_EVASION_HINTS.get(waf_key, {}) if waf_key else {}
    waf_label = hints.get("label", waf_name or (waf_key or "Unknown"))

    if verbose:
        from fray.output import console, print_header, print_phase
        print_header(f"Fray Bypass — WAF Evasion Scorer v{__version__}",
                     target=tester.target)
        detected_tag = " [dim](auto-detected)[/dim]" if not waf_name and waf_key else ""
        console.print(f"  WAF:      [bold]{waf_label}[/bold]{detected_tag}")
        console.print(f"  Category: {len(payloads)} payloads loaded")

    # ── Phase 1: Probe WAF ────────────────────────────────────────────────
    if verbose:
        console.print()
        print_phase(1, f"Probing WAF behavior ({len(DIAGNOSTIC_PROBES)} requests)...")

    profile = run_probes(tester, param=param)
    if waf_key:
        profile.waf_vendor = waf_label

    if verbose:
        console.print(f"    Strictness: [bold]{profile.strictness}[/bold] "
                      f"({profile.block_rate:.0f}% probe block rate)")
        if profile.blocked_tags:
            console.print(f"    Blocked tags:    {', '.join(sorted(profile.blocked_tags))}")
        if profile.allowed_tags:
            console.print(f"    Allowed tags:    [green]{', '.join(sorted(profile.allowed_tags))}[/green]")
        if profile.blocked_events:
            console.print(f"    Blocked events:  {', '.join(sorted(profile.blocked_events))}")
        if profile.blocked_keywords:
            console.print(f"    Blocked keywords: {', '.join(sorted(profile.blocked_keywords))}")

    # ── Baseline: send a clean request to capture normal response ────────
    baseline_result = tester.test_payload("hello", param=param)
    baseline = {
        "status": baseline_result.get("status", 0),
        "response_length": baseline_result.get("response_length", 0),
    }
    if verbose:
        console.print(f"\n    Baseline: status={baseline['status']}, "
                      f"length={baseline['response_length']}")

    # ── Phase 2: Score & rank with WAF-specific weighting ─────────────────
    if verbose:
        console.print()
        print_phase(2, f"Scoring {len(payloads)} payloads for evasion potential...")

    threshold_map = {"strict": 0.25, "moderate": 0.15, "permissive": 0.1, "minimal": 0.0}
    threshold = threshold_map.get(profile.strictness, 0.15)
    ranked = rank_payloads(payloads, profile, threshold=threshold)

    if verbose:
        skipped = len(payloads) - len(ranked)
        console.print(f"    Ranked: {len(ranked)} candidates (skipped {skipped} low-probability)")

    # ── Phase 3: Test top-ranked payloads ─────────────────────────────────
    test_count = min(len(ranked), max_payloads)
    if verbose:
        console.print()
        print_phase(3, f"Testing top {test_count} evasion candidates...")

    all_results = []
    bypass_results: List[BypassResult] = []

    for i, p in enumerate(ranked[:test_count]):
        payload_str = p.get("payload", p) if isinstance(p, dict) else p
        desc = p.get("description", "") if isinstance(p, dict) else ""
        cat = p.get("category", "") if isinstance(p, dict) else ""

        result = tester.test_payload(payload_str, param=param)
        all_results.append(result)

        bl_match = _is_baseline_match(result, baseline)
        soft_block = _is_soft_block(result, baseline)
        ev_score = _compute_evasion_score(result, profile, is_mutation=False, baseline=baseline)

        # Soft block: WAF returned 200 but body diverged — treat as blocked
        effective_blocked = result.get("blocked", True) or soft_block

        br = BypassResult(
            payload=payload_str,
            blocked=effective_blocked,
            status=result.get("status", 0),
            evasion_score=ev_score,
            reflected=result.get("reflected", False),
            reflection_context=result.get("reflection_context", ""),
            response_length=result.get("response_length", 0),
            category=cat,
            description=desc,
        )

        if not br.blocked:
            bypass_results.append(br)

        if verbose:
            from fray.output import blocked_text, bypass_text
            if br.blocked:
                soft_tag = f" [dim](soft block: {result.get('response_length', 0)}b vs {baseline.get('response_length', 0)}b baseline)[/dim]" if soft_block and not result.get("blocked") else ""
                console.print(f"    [{i+1}/{test_count}] ", blocked_text(), f" {result.get('status', 0)} │ {desc[:40] or payload_str[:40]}{soft_tag}")
            else:
                reflected_tag = " [yellow]REFLECTED[/yellow]" if br.reflected else ""
                bl_tag = " [dim](baseline)[/dim]" if bl_match else ""
                console.print(f"    [{i+1}/{test_count}] ", bypass_text(), f" {ev_score}% {_score_label(ev_score)} │ {result.get('status', 0)} │ {desc[:35] or payload_str[:35]}{reflected_tag}{bl_tag}")

        tester._stealth_delay()

    # ── Phase 4: Feedback loop — mutate BLOCKED payloads, retry ─────────
    #
    # Core insight: the real value is turning blocks INTO bypasses.
    # For each blocked payload: mutate → test → if still blocked → re-mutate → retry.
    # Also mutate bypasses to find MORE variants (amplification).
    #
    mutation_count = 0
    mutation_bypasses: List[BypassResult] = []
    mutator = PayloadMutator(profile, category=category)
    mut_remaining = mutation_budget
    max_retry_depth = 2  # How many times to re-mutate a blocked mutation
    seen_payloads: set = set()  # Dedup: skip mutations we've already tested

    # Collect blocked payloads from Phase 3 (top candidates by score)
    blocked_results = [r for r in all_results if r.get("blocked")]
    blocked_payloads = [r.get("payload", "") for r in blocked_results[:10]]

    # Also include bypasses for amplification
    bypass_payloads = [b.payload for b in bypass_results[:5]]

    # WAF-specific mutation ordering: reorder mutator strategies if hints available
    priority_muts = hints.get("priority_mutations", [])
    if priority_muts:
        mutator_strategies = mutator._pick_strategies()
        # Reorder: priority mutations first, then the rest
        priority_set = set(priority_muts)
        ordered = [s for s in mutator_strategies if s[0] in priority_set]
        rest = [s for s in mutator_strategies if s[0] not in priority_set]
        mutator._pick_strategies = lambda: ordered + rest

    if mut_remaining > 0 and (blocked_payloads or bypass_payloads):
        if verbose:
            console.print()
            print_phase(4, f"Evasion feedback loop "
                        f"({len(blocked_payloads)} blocked + {len(bypass_payloads)} bypasses, "
                        f"budget: {mutation_budget}, depth: {max_retry_depth})...")

        # --- 4a: Mutate BLOCKED payloads → try to turn blocks into bypasses ---
        for payload_str in blocked_payloads:
            if mut_remaining <= 0:
                break

            # Iterative retry: mutate → test → if blocked, mutate the mutation
            candidates = [payload_str]
            for depth in range(max_retry_depth + 1):
                if mut_remaining <= 0:
                    break
                next_candidates = []
                for candidate in candidates:
                    if mut_remaining <= 0:
                        break
                    mutations = mutator.mutate(candidate, max_mutations=max_mutations)
                    for mut in mutations:
                        if mut_remaining <= 0:
                            break
                        # Dedup: include content_type in key for CT confusion mutations
                        dedup_key = mut["payload"] + (f"||ct:{mut['content_type']}" if "content_type" in mut else "")
                        if dedup_key in seen_payloads:
                            continue
                        seen_payloads.add(dedup_key)
                        result = tester.test_payload(
                            mut["payload"], param=param,
                            method=mut.get("method", "GET"),
                            content_type=mut.get("content_type"),
                        )
                        mutation_count += 1
                        mut_remaining -= 1
                        bl_match = _is_baseline_match(result, baseline)
                        soft_block = _is_soft_block(result, baseline)
                        ev_score = _compute_evasion_score(result, profile, is_mutation=True, baseline=baseline)
                        effective_blocked = result.get("blocked", True) or soft_block

                        mbr = BypassResult(
                            payload=mut["payload"],
                            blocked=effective_blocked,
                            status=result.get("status", 0),
                            technique=mut["mutation"],
                            parent=mut["parent"],
                            evasion_score=ev_score,
                            reflected=result.get("reflected", False),
                            reflection_context=result.get("reflection_context", ""),
                            response_length=result.get("response_length", 0),
                        )

                        if verbose:
                            from fray.output import blocked_text, bypass_text
                            depth_tag = f"d{depth}" if depth > 0 else "MUT"
                            if mbr.blocked:
                                soft_tag = " [dim](soft block)[/dim]" if soft_block and not result.get("blocked") else ""
                                console.print(f"    {depth_tag} ", blocked_text(), f" [{mut['mutation']}] │ {result.get('status', 0)}{soft_tag}")
                            else:
                                reflected_tag = " [yellow]REFLECTED[/yellow]" if mbr.reflected else ""
                                bl_tag = " [dim](baseline)[/dim]" if bl_match else ""
                                console.print(f"    {depth_tag} ", bypass_text(), f" [{mut['mutation']}] │ {ev_score}% {_score_label(ev_score)} │ {result.get('status', 0)}{reflected_tag}{bl_tag}")

                        if not mbr.blocked:
                            mutation_bypasses.append(mbr)
                        else:
                            # Feed back into next depth for re-mutation
                            next_candidates.append(mut["payload"])

                        tester._stealth_delay()

                # Next depth: re-mutate blocked mutations
                candidates = next_candidates[:3]  # Limit re-mutation breadth
                if not candidates:
                    break  # All mutations bypassed or no more to try

        # --- 4b: Amplify bypasses — find more variants of what already works ---
        if mut_remaining > 0 and bypass_payloads:
            if verbose:
                console.print(f"\n    [dim]Amplifying {len(bypass_payloads)} bypass(es)...[/dim]")
            for payload_str in bypass_payloads:
                if mut_remaining <= 0:
                    break
                mutations = mutator.mutate(payload_str, max_mutations=max_mutations)
                for mut in mutations:
                    if mut_remaining <= 0:
                        break
                    dedup_key = mut["payload"] + (f"||ct:{mut['content_type']}" if "content_type" in mut else "")
                    if dedup_key in seen_payloads:
                        continue
                    seen_payloads.add(dedup_key)
                    result = tester.test_payload(
                        mut["payload"], param=param,
                        method=mut.get("method", "GET"),
                        content_type=mut.get("content_type"),
                    )
                    mutation_count += 1
                    mut_remaining -= 1
                    bl_match = _is_baseline_match(result, baseline)
                    soft_block = _is_soft_block(result, baseline)
                    ev_score = _compute_evasion_score(result, profile, is_mutation=True, baseline=baseline)
                    effective_blocked = result.get("blocked", True) or soft_block
                    mbr = BypassResult(
                        payload=mut["payload"],
                        blocked=effective_blocked,
                        status=result.get("status", 0),
                        technique=mut["mutation"],
                        parent=mut["parent"],
                        evasion_score=ev_score,
                        reflected=result.get("reflected", False),
                        reflection_context=result.get("reflection_context", ""),
                        response_length=result.get("response_length", 0),
                    )
                    if not mbr.blocked:
                        mutation_bypasses.append(mbr)
                    if verbose:
                        from fray.output import blocked_text, bypass_text
                        if mbr.blocked:
                            soft_tag = " [dim](soft block)[/dim]" if soft_block and not result.get("blocked") else ""
                            console.print(f"    AMP ", blocked_text(), f" [{mut['mutation']}] │ {result.get('status', 0)}{soft_tag}")
                        else:
                            reflected_tag = " [yellow]REFLECTED[/yellow]" if mbr.reflected else ""
                            bl_tag = " [dim](baseline)[/dim]" if bl_match else ""
                            console.print(f"    AMP ", bypass_text(), f" [{mut['mutation']}] │ {ev_score}% {_score_label(ev_score)} │ {result.get('status', 0)}{reflected_tag}{bl_tag}")
                    tester._stealth_delay()
    elif verbose:
        console.print(f"\n  [dim]Phase 4: Skipped — no payloads to mutate[/dim]")

    # ── Phase 5: Brute-force mutation fallback ────────────────────────────
    #
    # If Phase 4 still has budget and blocked payloads remain, try the
    # broader mutator.py engine (20 strategies: URL encode, double encode,
    # HTML entities, unicode fullwidth, tag substitution, data URIs, etc.)
    # These are WAF-agnostic brute-force transforms that may find bypasses
    # the profile-aware mutator missed.
    #
    if mut_remaining > 0 and blocked_payloads:
        from fray.mutator import mutate_payload as brute_mutate

        # Gather payloads still blocked after Phase 4
        phase4_bypassed = {b.payload for b in mutation_bypasses}
        still_blocked = [p for p in blocked_payloads if p not in phase4_bypassed]

        if still_blocked and verbose:
            console.print()
            print_phase(5, f"Brute-force mutations on {len(still_blocked)} "
                        f"remaining blocked payload(s), budget: {mut_remaining}...")

        for payload_str in still_blocked:
            if mut_remaining <= 0:
                break
            brute_variants = brute_mutate(payload_str, max_variants=min(mut_remaining, 15))
            for bv in brute_variants:
                if mut_remaining <= 0:
                    break
                if bv["payload"] in seen_payloads:
                    continue
                seen_payloads.add(bv["payload"])
                result = tester.test_payload(bv["payload"], param=param)
                mutation_count += 1
                mut_remaining -= 1
                bl_match = _is_baseline_match(result, baseline)
                soft_block = _is_soft_block(result, baseline)
                ev_score = _compute_evasion_score(result, profile, is_mutation=True, baseline=baseline)
                effective_blocked = result.get("blocked", True) or soft_block

                mbr = BypassResult(
                    payload=bv["payload"],
                    blocked=effective_blocked,
                    status=result.get("status", 0),
                    technique=bv["strategy"],
                    parent=bv["original"][:60],
                    evasion_score=ev_score,
                    reflected=result.get("reflected", False),
                    reflection_context=result.get("reflection_context", ""),
                    response_length=result.get("response_length", 0),
                )

                if not mbr.blocked:
                    mutation_bypasses.append(mbr)
                    # Amplify: if brute mutation worked, try deeper mutations
                    if mut_remaining > 0:
                        deeper = brute_mutate(bv["payload"], max_variants=min(mut_remaining, 3),
                                              strategies=["url_encode", "double_url_encode",
                                                          "html_entity", "mixed_case"])
                        for dv in deeper:
                            if mut_remaining <= 0:
                                break
                            if dv["payload"] in seen_payloads:
                                continue
                            seen_payloads.add(dv["payload"])
                            dr = tester.test_payload(dv["payload"], param=param)
                            mutation_count += 1
                            mut_remaining -= 1
                            d_ev = _compute_evasion_score(dr, profile, is_mutation=True, baseline=baseline)
                            d_blocked = dr.get("blocked", True) or _is_soft_block(dr, baseline)
                            dbr = BypassResult(
                                payload=dv["payload"],
                                blocked=d_blocked,
                                status=dr.get("status", 0),
                                technique=dv["strategy"],
                                parent=dv["original"][:60],
                                evasion_score=d_ev,
                                reflected=dr.get("reflected", False),
                                response_length=dr.get("response_length", 0),
                            )
                            if not dbr.blocked:
                                mutation_bypasses.append(dbr)
                            tester._stealth_delay()

                if verbose:
                    from fray.output import blocked_text, bypass_text
                    if mbr.blocked:
                        console.print(f"    BF  ", blocked_text(), f" [{bv['strategy']}] │ {result.get('status', 0)}")
                    else:
                        ref_tag = " [yellow]REFLECTED[/yellow]" if mbr.reflected else ""
                        console.print(f"    BF  ", bypass_text(), f" [{bv['strategy']}] │ {ev_score}% {_score_label(ev_score)} │ {result.get('status', 0)}{ref_tag}")

                tester._stealth_delay()

    # ── Build Scorecard ───────────────────────────────────────────────────
    all_bypasses = bypass_results + mutation_bypasses
    all_bypasses.sort(key=lambda b: b.evasion_score, reverse=True)

    # Technique analysis
    technique_counts: Dict[str, Dict] = {}
    for bp in mutation_bypasses:
        t = bp.technique or "original"
        if t not in technique_counts:
            technique_counts[t] = {"technique": t, "tested": 0, "bypassed": 0}
        technique_counts[t]["tested"] += 1
        if not bp.blocked:
            technique_counts[t]["bypassed"] += 1
    # Sort by bypass count
    top_techniques = sorted(technique_counts.values(),
                            key=lambda x: x["bypassed"], reverse=True)

    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    duration = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"

    scorecard = BypassScorecard(
        target=tester.target,
        waf_vendor=waf_label,
        waf_detected=profile.waf_vendor or waf_label,
        category=category,
        timestamp=datetime.now().isoformat(),
        duration=duration,
        waf_strictness=profile.strictness,
        blocked_tags=sorted(profile.blocked_tags),
        blocked_events=sorted(profile.blocked_events),
        blocked_keywords=sorted(profile.blocked_keywords),
        allowed_tags=sorted(profile.allowed_tags),
        probe_block_rate=round(profile.block_rate, 1),
        total_tested=test_count,
        total_blocked=test_count - len(bypass_results),
        total_bypassed=len(bypass_results),
        mutations_tested=mutation_count,
        mutations_bypassed=len(mutation_bypasses),
        overall_evasion_score=_overall_score(all_bypasses, test_count + mutation_count, profile),
        bypasses=[{
            "payload": b.payload,
            "evasion_score": b.evasion_score,
            "status": b.status,
            "technique": b.technique,
            "reflected": b.reflected,
            "reflection_context": b.reflection_context[:100],
            "description": b.description,
        } for b in all_bypasses[:20]],  # Top 20 bypasses
        top_techniques=top_techniques,
        tips=hints.get("tips", []),
    )

    # ── Print Scorecard ───────────────────────────────────────────────────
    if verbose and not json_output:
        _print_scorecard(scorecard)

    # ── Output ────────────────────────────────────────────────────────────
    if json_output:
        print(json.dumps(asdict(scorecard), indent=2, ensure_ascii=False))

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(asdict(scorecard), f, indent=2, ensure_ascii=False)
        if verbose and not json_output:
            console.print(f"\n  [dim]Results saved to: {output_file}[/dim]")

    return scorecard


def _print_scorecard(sc: BypassScorecard):
    """Print the bypass scorecard to terminal with rich formatting."""
    from fray.output import (console, score_style, grade_label,
                              make_summary_table, blocked_text, bypass_text)
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns

    score = sc.overall_evasion_score
    grade = grade_label(score)
    style = score_style(score)

    # ── Score badge ──
    score_badge = Text()
    score_badge.append(f" {score}% ", style=f"bold white on {'red' if score >= 90 else 'yellow' if score >= 70 else 'blue' if score >= 40 else 'green' if score > 0 else 'white'}")
    score_badge.append(f" {grade}", style=style)

    # ── Summary table ──
    tbl = make_summary_table()
    tbl.add_row("Target", sc.target)
    tbl.add_row("WAF", f"{sc.waf_vendor} ({sc.waf_strictness})")
    tbl.add_row("Duration", sc.duration)
    tbl.add_row("Evasion Score", score_badge)
    tbl.add_row("", "")
    tbl.add_row("Payloads tested", str(sc.total_tested))
    tbl.add_row("Blocked", Text(str(sc.total_blocked), style="bold red"))
    tbl.add_row("Bypassed", Text(str(sc.total_bypassed), style="bold green"))
    if sc.mutations_tested > 0:
        tbl.add_row("Mutations tested", str(sc.mutations_tested))
        tbl.add_row("Mutations bypassed", Text(str(sc.mutations_bypassed), style="bold green"))

    total_bypass = sc.total_bypassed + sc.mutations_bypassed
    total_all = sc.total_tested + sc.mutations_tested
    if total_all > 0:
        rate = total_bypass / total_all * 100
        tbl.add_row("Bypass rate", Text(f"{rate:.1f}%", style="bold"))

    console.print()
    console.print(Panel(tbl, title="[bold]WAF Bypass Scorecard[/bold]",
                        border_style="bright_cyan", expand=False))

    # ── Top Bypasses table ──
    if sc.bypasses:
        bp_table = Table(title="Top Bypasses", show_lines=False, pad_edge=False,
                         box=None, title_style="bold")
        bp_table.add_column("#", style="dim", width=3, justify="right")
        bp_table.add_column("Score", width=12, justify="center")
        bp_table.add_column("Technique", width=20)
        bp_table.add_column("Payload", min_width=40)

        for i, b in enumerate(sc.bypasses[:10], 1):
            pct = b["evasion_score"]
            label = _score_label(pct)
            score_txt = Text(f"{pct}% {label}", style=score_style(pct))
            technique = b.get("technique") or "-"
            payload_preview = b["payload"][:65]
            ref_tag = " [yellow]REFLECTED[/yellow]" if b.get("reflected") else ""
            bp_table.add_row(str(i), score_txt, technique,
                             f"[dim]{payload_preview}[/dim]{ref_tag}")

        console.print()
        console.print(Panel(bp_table, border_style="dim", expand=False))

    # ── Techniques table ──
    if sc.top_techniques:
        tech_table = Table(title="Evasion Techniques", show_lines=False,
                           box=None, title_style="bold", pad_edge=False)
        tech_table.add_column("Technique", min_width=25)
        tech_table.add_column("Bypassed", width=10, justify="center")
        tech_table.add_column("Tested", width=8, justify="center")

        for t in sc.top_techniques[:5]:
            if t["bypassed"] > 0:
                tech_table.add_row(
                    t["technique"],
                    Text(str(t["bypassed"]), style="bold green"),
                    str(t["tested"]),
                )
        if tech_table.row_count > 0:
            console.print()
            console.print(tech_table)

    # ── Tips ──
    if sc.tips:
        console.print()
        console.print("  [bold]WAF-Specific Tips:[/bold]")
        for tip in sc.tips[:4]:
            console.print(f"    [dim]💡 {tip}[/dim]")

    # ── Next Steps (actionable recommendations) ──
    next_steps = _next_steps_for_score(
        score=sc.overall_evasion_score,
        total_blocked=sc.total_blocked + (sc.mutations_tested - sc.mutations_bypassed),
        total_bypassed=sc.total_bypassed + sc.mutations_bypassed,
        waf_label=sc.waf_vendor,
        strictness=sc.waf_strictness,
        target=sc.target,
        category=sc.category or "xss",
    )
    if next_steps:
        console.print()
        console.print("  [bold]What This Means / Next Steps:[/bold]")
        for i, step in enumerate(next_steps):
            prefix = "  →" if i == 0 else "   "
            style = "bold" if i == 0 else "dim"
            console.print(f"    {prefix} [{style}]{step}[/{style}]")

    # ── Score Guide (compact) ──
    console.print()
    console.print("  [dim]Score: 90%+ CRITICAL (exploit-ready) │ 70%+ HIGH (strong bypass) │ 40%+ MEDIUM (unconfirmed) │ <40% LOW (WAF holding)[/dim]")

    console.print()
    console.rule(style="dim")
