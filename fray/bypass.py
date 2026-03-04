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
    evasion_score: float = 0.0  # 0.0–10.0
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
    overall_evasion_score: float = 0.0  # 0.0–10.0

    # Results
    bypasses: List[Dict] = field(default_factory=list)
    top_techniques: List[Dict] = field(default_factory=list)
    tips: List[str] = field(default_factory=list)


def _compute_evasion_score(result: dict, profile: WAFProfile, is_mutation: bool) -> float:
    """Compute an evasion score (0.0–10.0) for a bypass.

    Higher score = more impressive bypass:
    - Bypassing a strict WAF scores higher
    - Reflected payloads score higher (potential real XSS)
    - Mutation-generated bypasses score higher (novel)
    - Payloads that bypass more blocked patterns score higher
    """
    score = 0.0

    if result.get("blocked"):
        return 0.0

    # Base: WAF strictness multiplier
    strictness_map = {"strict": 4.0, "moderate": 3.0, "permissive": 2.0, "minimal": 1.0}
    score += strictness_map.get(profile.strictness, 2.0)

    # Bonus: payload reflected in response
    if result.get("reflected"):
        score += 2.0

    # Bonus: mutation-generated bypass (novel technique)
    if is_mutation:
        score += 1.5

    # Bonus: bypassed despite using blocked patterns
    payload = result.get("payload", "")
    tags = _extract_tags(payload)
    events = _extract_events(payload)
    keywords = _extract_keywords(payload)

    blocked_overlap = (
        len(tags & profile.blocked_tags) +
        len(events & profile.blocked_events) +
        len(keywords & profile.blocked_keywords)
    )
    score += min(blocked_overlap * 0.5, 2.0)

    # Bonus: non-trivial status code (200 = real response, not just a passthrough)
    if result.get("status") == 200:
        score += 0.5

    return round(min(score, 10.0), 1)


def _overall_score(bypasses: List[BypassResult], total_tested: int,
                   profile: WAFProfile) -> float:
    """Compute an overall WAF evasion score for the scorecard."""
    if total_tested == 0:
        return 0.0

    bypass_rate = len(bypasses) / total_tested

    # Weight by strictness
    strictness_weight = {"strict": 1.5, "moderate": 1.2, "permissive": 0.8, "minimal": 0.5}
    weight = strictness_weight.get(profile.strictness, 1.0)

    # Average individual scores
    if bypasses:
        avg_score = sum(b.evasion_score for b in bypasses) / len(bypasses)
    else:
        avg_score = 0.0

    # Combine: bypass rate contribution + average score contribution
    overall = (bypass_rate * 4.0 * weight) + (avg_score * 0.6)
    return round(min(overall, 10.0), 1)


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
    hints = WAF_EVASION_HINTS.get(waf_key, {}) if waf_key else {}
    waf_label = hints.get("label", waf_name or "Unknown")

    if verbose:
        print(f"\n{Colors.BOLD}{'━' * 60}{Colors.END}")
        print(f"{Colors.BOLD}  Fray Bypass — WAF Evasion Scorer v{__version__}{Colors.END}")
        print(f"{Colors.BOLD}{'━' * 60}{Colors.END}")
        print(f"  Target:   {tester.target}")
        print(f"  WAF:      {waf_label}")
        print(f"  Category: {len(payloads)} payloads loaded")

    # ── Phase 1: Probe WAF ────────────────────────────────────────────────
    if verbose:
        print(f"\n{Colors.CYAN}  Phase 1: Probing WAF behavior ({len(DIAGNOSTIC_PROBES)} requests)...{Colors.END}")

    profile = run_probes(tester, param=param)
    if waf_key:
        profile.waf_vendor = waf_label

    if verbose:
        print(f"    Strictness: {Colors.BOLD}{profile.strictness}{Colors.END} "
              f"({profile.block_rate:.0f}% probe block rate)")
        if profile.blocked_tags:
            print(f"    Blocked tags:    {', '.join(sorted(profile.blocked_tags))}")
        if profile.allowed_tags:
            print(f"    Allowed tags:    {Colors.GREEN}{', '.join(sorted(profile.allowed_tags))}{Colors.END}")
        if profile.blocked_events:
            print(f"    Blocked events:  {', '.join(sorted(profile.blocked_events))}")
        if profile.blocked_keywords:
            print(f"    Blocked keywords: {', '.join(sorted(profile.blocked_keywords))}")

    # ── Phase 2: Score & rank with WAF-specific weighting ─────────────────
    if verbose:
        print(f"\n{Colors.CYAN}  Phase 2: Scoring {len(payloads)} payloads for evasion potential...{Colors.END}")

    threshold_map = {"strict": 0.25, "moderate": 0.15, "permissive": 0.1, "minimal": 0.0}
    threshold = threshold_map.get(profile.strictness, 0.15)
    ranked = rank_payloads(payloads, profile, threshold=threshold)

    if verbose:
        skipped = len(payloads) - len(ranked)
        print(f"    Ranked: {len(ranked)} candidates (skipped {skipped} low-probability)")

    # ── Phase 3: Test top-ranked payloads ─────────────────────────────────
    test_count = min(len(ranked), max_payloads)
    if verbose:
        print(f"\n{Colors.CYAN}  Phase 3: Testing top {test_count} evasion candidates...{Colors.END}")

    all_results = []
    bypass_results: List[BypassResult] = []

    for i, p in enumerate(ranked[:test_count]):
        payload_str = p.get("payload", p) if isinstance(p, dict) else p
        desc = p.get("description", "") if isinstance(p, dict) else ""
        cat = p.get("category", "") if isinstance(p, dict) else ""

        result = tester.test_payload(payload_str, param=param)
        all_results.append(result)

        ev_score = _compute_evasion_score(result, profile, is_mutation=False)

        br = BypassResult(
            payload=payload_str,
            blocked=result.get("blocked", True),
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
            if br.blocked:
                print(f"    [{i+1}/{test_count}] {Colors.RED}BLOCKED{Colors.END} "
                      f"| {result.get('status', 0)} | {desc[:40] or payload_str[:40]}")
            else:
                reflected_tag = f" {Colors.YELLOW}REFLECTED{Colors.END}" if br.reflected else ""
                print(f"    [{i+1}/{test_count}] {Colors.GREEN}BYPASS{Colors.END}  "
                      f"| Score: {Colors.BOLD}{ev_score}{Colors.END} "
                      f"| {result.get('status', 0)} "
                      f"| {desc[:35] or payload_str[:35]}{reflected_tag}")

        tester._stealth_delay()

    # ── Phase 4: Feedback loop — mutate BLOCKED payloads, retry ─────────
    #
    # Core insight: the real value is turning blocks INTO bypasses.
    # For each blocked payload: mutate → test → if still blocked → re-mutate → retry.
    # Also mutate bypasses to find MORE variants (amplification).
    #
    mutation_count = 0
    mutation_bypasses: List[BypassResult] = []
    mutator = PayloadMutator(profile)
    mut_remaining = mutation_budget
    max_retry_depth = 2  # How many times to re-mutate a blocked mutation

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
            print(f"\n{Colors.CYAN}  Phase 4: Evasion feedback loop "
                  f"({len(blocked_payloads)} blocked + {len(bypass_payloads)} bypasses, "
                  f"budget: {mutation_budget}, depth: {max_retry_depth})...{Colors.END}")

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
                        result = tester.test_payload(mut["payload"], param=param)
                        mutation_count += 1
                        mut_remaining -= 1
                        ev_score = _compute_evasion_score(result, profile, is_mutation=True)

                        mbr = BypassResult(
                            payload=mut["payload"],
                            blocked=result.get("blocked", True),
                            status=result.get("status", 0),
                            technique=mut["mutation"],
                            parent=mut["parent"],
                            evasion_score=ev_score,
                            reflected=result.get("reflected", False),
                            reflection_context=result.get("reflection_context", ""),
                            response_length=result.get("response_length", 0),
                        )

                        if verbose:
                            depth_tag = f"d{depth}" if depth > 0 else "MUT"
                            if mbr.blocked:
                                print(f"    {depth_tag} {Colors.RED}BLOCKED{Colors.END} "
                                      f"[{mut['mutation']}] | {result.get('status', 0)}")
                            else:
                                reflected_tag = f" {Colors.YELLOW}REFLECTED{Colors.END}" if mbr.reflected else ""
                                print(f"    {depth_tag} {Colors.GREEN}BYPASS{Colors.END}  "
                                      f"[{mut['mutation']}] | Score: {Colors.BOLD}{ev_score}{Colors.END} "
                                      f"| {result.get('status', 0)}{reflected_tag}")

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
                print(f"\n    {Colors.DIM}Amplifying {len(bypass_payloads)} bypass(es)...{Colors.END}")
            for payload_str in bypass_payloads:
                if mut_remaining <= 0:
                    break
                mutations = mutator.mutate(payload_str, max_mutations=max_mutations)
                for mut in mutations:
                    if mut_remaining <= 0:
                        break
                    result = tester.test_payload(mut["payload"], param=param)
                    mutation_count += 1
                    mut_remaining -= 1
                    ev_score = _compute_evasion_score(result, profile, is_mutation=True)
                    mbr = BypassResult(
                        payload=mut["payload"],
                        blocked=result.get("blocked", True),
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
                        if mbr.blocked:
                            print(f"    AMP {Colors.RED}BLOCKED{Colors.END} "
                                  f"[{mut['mutation']}] | {result.get('status', 0)}")
                        else:
                            reflected_tag = f" {Colors.YELLOW}REFLECTED{Colors.END}" if mbr.reflected else ""
                            print(f"    AMP {Colors.GREEN}BYPASS{Colors.END}  "
                                  f"[{mut['mutation']}] | Score: {Colors.BOLD}{ev_score}{Colors.END} "
                                  f"| {result.get('status', 0)}{reflected_tag}")
                    tester._stealth_delay()
    elif verbose:
        print(f"\n{Colors.DIM}  Phase 4: Skipped — no payloads to mutate{Colors.END}")

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
        category="",
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
            print(f"\n  {Colors.DIM}Results saved to: {output_file}{Colors.END}")

    return scorecard


def _print_scorecard(sc: BypassScorecard):
    """Print the bypass scorecard to terminal."""
    C = Colors

    # Overall score with color
    score = sc.overall_evasion_score
    if score >= 7.0:
        score_color = C.RED
        grade = "CRITICAL"
    elif score >= 5.0:
        score_color = C.YELLOW
        grade = "HIGH"
    elif score >= 3.0:
        score_color = C.BLUE
        grade = "MEDIUM"
    elif score > 0:
        score_color = C.GREEN
        grade = "LOW"
    else:
        score_color = C.DIM
        grade = "NONE"

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
    print(f"{C.BOLD}  WAF Bypass Scorecard{C.END}")
    print(f"{C.BOLD}{'━' * 60}{C.END}")
    print(f"  Target:     {sc.target}")
    print(f"  WAF:        {sc.waf_vendor} ({sc.waf_strictness})")
    print(f"  Duration:   {sc.duration}")
    print()
    print(f"  {C.BOLD}Evasion Score: {score_color}{score}/10.0 ({grade}){C.END}")
    print()
    print(f"  {'─' * 45}")
    print(f"  Payloads tested:   {sc.total_tested}")
    print(f"  Blocked:           {C.RED}{sc.total_blocked}{C.END}")
    print(f"  Bypassed:          {C.GREEN}{sc.total_bypassed}{C.END}")
    if sc.mutations_tested > 0:
        print(f"  Mutations tested:  {sc.mutations_tested}")
        print(f"  Mutations bypassed: {C.GREEN}{sc.mutations_bypassed}{C.END}")

    total_bypass = sc.total_bypassed + sc.mutations_bypassed
    total_all = sc.total_tested + sc.mutations_tested
    if total_all > 0:
        rate = total_bypass / total_all * 100
        print(f"  Bypass rate:       {C.BOLD}{rate:.1f}%{C.END}")

    # Top bypasses
    if sc.bypasses:
        print(f"\n  {C.BOLD}Top Bypasses:{C.END}")
        for i, b in enumerate(sc.bypasses[:10], 1):
            reflected = f" {C.YELLOW}[REFLECTED]{C.END}" if b.get("reflected") else ""
            technique = f" [{b['technique']}]" if b.get("technique") else ""
            print(f"    {i}. Score {C.BOLD}{b['evasion_score']}{C.END}"
                  f"{technique}{reflected}")
            payload_preview = b["payload"][:70]
            print(f"       {C.DIM}{payload_preview}{C.END}")

    # Top techniques
    if sc.top_techniques:
        print(f"\n  {C.BOLD}Evasion Techniques:{C.END}")
        for t in sc.top_techniques[:5]:
            if t["bypassed"] > 0:
                print(f"    • {t['technique']}: "
                      f"{C.GREEN}{t['bypassed']}/{t['tested']} bypassed{C.END}")

    # Tips
    if sc.tips:
        print(f"\n  {C.BOLD}WAF-Specific Tips:{C.END}")
        for tip in sc.tips[:4]:
            print(f"    💡 {tip}")

    print(f"\n{C.BOLD}{'━' * 60}{C.END}")
