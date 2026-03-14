#!/usr/bin/env python3
"""
Fray Agent — Self-Improving Payload Engine

Iterative feedback loop that learns from each blocked/bypassed payload
and adapts its mutation strategy. Local-first (zero latency), with
optional batched LLM fallback when local mutations are exhausted.

Flow:
    Round 1: Probe WAF → build WAFProfile → pick best payloads
    Round 2: Test payloads → analyze blocked responses → learn block reasons
    Round 3: Apply targeted mutations based on learned reasons
    Round 4+: Re-analyze → re-mutate → iterate until budget exhausted
    Final:   Cache learned patterns for next scan

Usage:
    fray agent https://target.com
    fray agent https://target.com -c xss --rounds 5
    fray agent https://target.com --budget 100    # max 100 requests total

Cache: ~/.fray/learned_patterns.json
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from fray import __version__
from fray.evolve import (
    WAFProfile, run_probes, score_payload, rank_payloads,
    PayloadMutator, DIAGNOSTIC_PROBES,
)
from fray.mutator import mutate_payload


# ── Colors ───────────────────────────────────────────────────────────────────

class _C:
    B = '\033[1m'
    G = '\033[92m'
    R = '\033[91m'
    Y = '\033[93m'
    BL = '\033[94m'
    CY = '\033[96m'
    DIM = '\033[2m'
    E = '\033[0m'


# ── Block Reason Analyzer ────────────────────────────────────────────────────

@dataclass
class BlockReason:
    """Why a payload was blocked — inferred from response patterns."""
    payload: str
    tags_triggered: Set[str] = field(default_factory=set)
    events_triggered: Set[str] = field(default_factory=set)
    keywords_triggered: Set[str] = field(default_factory=set)
    patterns_triggered: Set[str] = field(default_factory=set)
    encoding_detected: str = ""
    likely_rule: str = ""  # e.g. "tag:script+event:onerror"

    def suggested_mutations(self) -> List[str]:
        """Return mutation strategy names most likely to bypass this block."""
        strategies = []

        # Tag blocked → try tag substitution, SVG/math wrapping
        if self.tags_triggered:
            strategies.extend(["tag_substitution", "svg_wrap", "math_wrap"])

        # Event blocked → try event swap, backtick, data URI
        if self.events_triggered:
            strategies.extend(["event_swap", "backtick", "data_uri", "javascript_uri"])

        # Keyword blocked → try encoding, concat split, unicode
        if self.keywords_triggered:
            strategies.extend(["concat_split", "unicode_fullwidth",
                               "html_entity", "html_hex_entity"])

        # Pattern blocked → try double encode, null byte, whitespace
        if self.patterns_triggered:
            strategies.extend(["double_url_encode", "null_byte",
                               "whitespace", "newline_in_tag"])

        # Encoding detected (WAF decodes before matching) → try compound
        if self.encoding_detected:
            strategies.extend(["html_comment", "case_swap", "mixed_case"])

        # Fallback: try everything
        if not strategies:
            strategies = ["mixed_case", "url_encode", "tag_substitution",
                          "html_comment", "whitespace"]

        return strategies


def analyze_block_reason(payload: str, profile: WAFProfile) -> BlockReason:
    """Analyze WHY a payload was likely blocked based on the WAF profile."""
    reason = BlockReason(payload=payload)
    lower = payload.lower()

    # Check which blocked elements the payload contains
    for tag in re.findall(r'<(\w+)[\s/>]', lower):
        if tag in profile.blocked_tags:
            reason.tags_triggered.add(tag)

    for event in re.findall(r'(on\w+)\s*=', lower):
        if event in profile.blocked_events:
            reason.events_triggered.add(event)

    for kw in ['alert', 'eval', 'document', 'window', 'cookie',
               'fetch', 'prompt', 'confirm', 'constructor']:
        if kw in lower and kw in profile.blocked_keywords:
            reason.keywords_triggered.add(kw)

    for pattern in ['javascript:', 'data:', 'vbscript:', 'expression(']:
        if pattern in lower and pattern in profile.blocked_patterns:
            reason.patterns_triggered.add(pattern)

    # Check if encoding was detected (WAF decoded it)
    if '&' in payload and ';' in payload and 'html_entity' in profile.blocked_encodings:
        reason.encoding_detected = "html_entity"
    elif '\\u' in payload and 'unicode' in profile.blocked_encodings:
        reason.encoding_detected = "unicode"

    # Build a rule signature
    parts = []
    if reason.tags_triggered:
        parts.append(f"tag:{','.join(sorted(reason.tags_triggered))}")
    if reason.events_triggered:
        parts.append(f"event:{','.join(sorted(reason.events_triggered))}")
    if reason.keywords_triggered:
        parts.append(f"kw:{','.join(sorted(reason.keywords_triggered))}")
    if reason.patterns_triggered:
        parts.append(f"pat:{','.join(sorted(reason.patterns_triggered))}")
    reason.likely_rule = "+".join(parts) if parts else "unknown"

    return reason


# ── Learned Pattern Cache ────────────────────────────────────────────────────

_CACHE_DIR = Path.home() / ".fray"
_CACHE_FILE = _CACHE_DIR / "learned_patterns.json"


def _load_cache() -> Dict:
    """Load learned patterns from disk."""
    if _CACHE_FILE.exists():
        try:
            return json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"version": 1, "vendors": {}}


def _save_cache(cache: Dict) -> None:
    """Save learned patterns to disk."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False),
                           encoding="utf-8")


def _get_vendor_cache(cache: Dict, vendor: str) -> Dict:
    """Get or create cache entry for a WAF vendor."""
    vendor_key = vendor.lower().strip() if vendor else "unknown"
    if vendor_key not in cache["vendors"]:
        cache["vendors"][vendor_key] = {
            "successful_payloads": [],
            "successful_mutations": [],
            "blocked_rules": [],
            "effective_strategies": {},
            "blocked_hashes": [],
            "failed_strategies": {},
            "waf_profile": None,
            "total_runs": 0,
            "total_blocked": 0,
        }
    # Migrate older cache entries missing new keys
    vc = cache["vendors"][vendor_key]
    vc.setdefault("blocked_hashes", [])
    vc.setdefault("failed_strategies", {})
    vc.setdefault("waf_profile", None)
    vc.setdefault("total_runs", 0)
    vc.setdefault("total_blocked", 0)
    return vc


def _payload_hash(payload: str) -> str:
    """Short hash of a payload for dedup. First 12 chars of sha256."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:12]


def _get_blocked_set(vendor_cache: Dict) -> Set[str]:
    """Load the set of blocked payload hashes for fast lookup."""
    return set(vendor_cache.get("blocked_hashes", []))


def _restore_waf_profile(vendor_cache: Dict) -> Optional[WAFProfile]:
    """Restore a cached WAF profile so we don't re-probe."""
    wp = vendor_cache.get("waf_profile")
    if not wp:
        return None
    try:
        p = WAFProfile()
        p.blocked_tags = set(wp.get("blocked_tags", []))
        p.blocked_events = set(wp.get("blocked_events", []))
        p.blocked_keywords = set(wp.get("blocked_keywords", []))
        p.blocked_patterns = set(wp.get("blocked_patterns", []))
        p.blocked_encodings = set(wp.get("blocked_encodings", []))
        p.allowed_tags = set(wp.get("allowed_tags", []))
        p.allowed_events = set(wp.get("allowed_events", []))
        p.allowed_keywords = set(wp.get("allowed_keywords", []))
        p.block_status = wp.get("block_status", 403)
        p.baseline_status = wp.get("baseline_status", 200)
        p.total_probes = wp.get("total_probes", 0)
        p.total_blocked = wp.get("total_blocked", 0)
        p.waf_vendor = wp.get("waf_vendor", "")
        return p
    except Exception:
        return None


# ── Agent Stats ──────────────────────────────────────────────────────────────

@dataclass
class AgentStats:
    """Statistics from an agent run."""
    rounds_completed: int = 0
    total_requests: int = 0
    probes_sent: int = 0
    payloads_tested: int = 0
    mutations_tested: int = 0
    bypasses_from_payloads: int = 0
    bypasses_from_mutations: int = 0
    bypasses_from_cache: int = 0
    unique_bypass_techniques: Set[str] = field(default_factory=set)
    cache_hits: int = 0
    cache_misses: int = 0
    skipped_known_blocked: int = 0
    profile_from_cache: bool = False

    @property
    def total_bypasses(self) -> int:
        return self.bypasses_from_payloads + self.bypasses_from_mutations + self.bypasses_from_cache

    @property
    def bypass_rate(self) -> str:
        tested = self.payloads_tested + self.mutations_tested
        if tested == 0:
            return "0%"
        return f"{self.total_bypasses / tested * 100:.1f}%"


# ── Main Agent ───────────────────────────────────────────────────────────────

def run_agent(tester, payloads: List[Dict], *,
              max_rounds: int = 5,
              budget: int = 100,
              param: str = 'input',
              category: str = '',
              verbose: bool = True,
              use_cache: bool = True,
              use_ai: bool = False) -> Tuple[List[Dict], AgentStats, WAFProfile]:
    """Run the self-improving payload agent.

    Args:
        tester: WAFTester instance (configured with target)
        payloads: full list of payload dicts
        max_rounds: maximum mutation rounds (default 5)
        budget: total HTTP request budget (default 100)
        param: URL parameter to inject into
        category: payload category filter (e.g. 'xss', 'sqli')
        verbose: print progress
        use_cache: load/save learned patterns from ~/.fray/
        use_ai: enable batched LLM fallback (optional)

    Returns:
        (results, stats, profile)
    """
    stats = AgentStats()
    all_results = []
    all_bypasses = []
    requests_remaining = budget

    if verbose:
        print(f"\n  {_C.B}Fray Agent — Self-Improving Payload Engine{_C.E}")
        print(f"  {_C.DIM}Budget: {budget} requests | Max rounds: {max_rounds}{_C.E}")

    # ── Phase 0: Load cached patterns ────────────────────────────────────
    cache = _load_cache() if use_cache else {"version": 1, "vendors": {}}

    # Pre-detect vendor from cache keys or tester
    _pre_vendor = tester.__dict__.get("waf_vendor", "")

    # ── Phase 1: Probe WAF (or restore from cache) ───────────────────────
    profile = None
    if use_cache and _pre_vendor:
        _pre_vc = _get_vendor_cache(cache, _pre_vendor)
        profile = _restore_waf_profile(_pre_vc)
        if profile:
            stats.profile_from_cache = True
            if verbose:
                print(f"\n  {_C.CY}Phase 1: WAF profile restored from cache ({_pre_vendor}){_C.E}")
                print(f"    {_C.DIM}Skipping {len(DIAGNOSTIC_PROBES)} probes — already learned{_C.E}")

    if not profile:
        if verbose:
            print(f"\n  {_C.BL}Phase 1: Probing WAF ({len(DIAGNOSTIC_PROBES)} probes)...{_C.E}")
        profile = run_probes(tester, param=param)
        stats.probes_sent = profile.total_probes
        requests_remaining -= profile.total_probes
        stats.total_requests += profile.total_probes

    if verbose:
        print(f"    WAF strictness: {_C.B}{profile.strictness}{_C.E} "
              f"({profile.block_rate:.0f}% probe block rate)")
        if profile.blocked_tags:
            print(f"    Blocked tags:    {_C.R}{', '.join(sorted(profile.blocked_tags))}{_C.E}")
        if profile.allowed_tags - {'b'}:
            print(f"    Allowed tags:    {_C.G}{', '.join(sorted(profile.allowed_tags - {'b'}))}{_C.E}")
        if profile.blocked_events:
            print(f"    Blocked events:  {_C.R}{', '.join(sorted(profile.blocked_events))}{_C.E}")
        if profile.blocked_keywords:
            print(f"    Blocked keywords:{_C.R} {', '.join(sorted(profile.blocked_keywords))}{_C.E}")
        if profile.blocked_encodings:
            print(f"    Blocks encodings:{_C.R} {', '.join(sorted(profile.blocked_encodings))}{_C.E}")

    # ── Phase 1.5: Try cached bypasses for this WAF vendor ───────────────
    vendor = profile.waf_vendor or tester.__dict__.get("waf_vendor", "unknown")
    vendor_cache = _get_vendor_cache(cache, vendor)
    blocked_hash_set = _get_blocked_set(vendor_cache)

    if verbose and blocked_hash_set:
        print(f"\n  {_C.CY}Memory: {len(blocked_hash_set)} previously blocked payloads "
              f"for {vendor} (will skip){_C.E}")

    cached_payloads = vendor_cache.get("successful_payloads", [])
    if cached_payloads and requests_remaining > 0 and verbose:
        print(f"\n  {_C.CY}Phase 1.5: Testing {len(cached_payloads[:5])} cached bypasses "
              f"for {vendor}...{_C.E}")

    for cp in cached_payloads[:5]:
        if requests_remaining <= 0:
            break
        payload_str = cp if isinstance(cp, str) else cp.get("payload", "")
        if not payload_str:
            continue

        result = tester.test_payload(payload_str, param=param)
        requests_remaining -= 1
        stats.total_requests += 1
        stats.cache_hits += 1

        if not result.get("blocked"):
            stats.bypasses_from_cache += 1
            result["source"] = "cache"
            result["technique"] = cp.get("technique", "cached_pattern")
            all_bypasses.append(result)
            if verbose:
                print(f"    {_C.G}CACHE HIT{_C.E}  {payload_str[:50]}")
        else:
            stats.cache_misses += 1
            # Add to blocked set so we don't try it again
            blocked_hash_set.add(_payload_hash(payload_str))
            if verbose:
                print(f"    {_C.R}STALE{_C.E}      {payload_str[:50]}")

        all_results.append(result)
        time.sleep(tester.delay)

    # ── Phase 2: Score, rank, and filter payloads ────────────────────────
    if verbose:
        print(f"\n  {_C.BL}Phase 2: Scoring {len(payloads)} payloads...{_C.E}")

    threshold_map = {"strict": 0.3, "moderate": 0.2, "permissive": 0.1, "minimal": 0.0}
    threshold = threshold_map.get(profile.strictness, 0.2)
    ranked = rank_payloads(payloads, profile, threshold=threshold)

    # Use cached effective strategies to boost scoring
    effective = vendor_cache.get("effective_strategies", {})
    failed_strats = vendor_cache.get("failed_strategies", {})
    if effective:
        for p in ranked:
            ps = p.get("payload", "")
            for strat, count in effective.items():
                if strat in ps.lower():
                    p["evolve_score"] = min(1.0, p.get("evolve_score", 0) + 0.1 * count)
        ranked.sort(key=lambda x: x.get("evolve_score", 0), reverse=True)

    skipped_score = len(payloads) - len(ranked)

    # Filter out payloads we already know are blocked for this vendor
    if blocked_hash_set:
        before_filter = len(ranked)
        ranked = [p for p in ranked
                  if _payload_hash(p.get("payload", "")) not in blocked_hash_set]
        skipped_blocked = before_filter - len(ranked)
        stats.skipped_known_blocked = skipped_blocked
    else:
        skipped_blocked = 0

    if verbose:
        msg = f"    Kept {_C.B}{len(ranked)}{_C.E} payloads"
        parts = []
        if skipped_score:
            parts.append(f"{skipped_score} low-score")
        if skipped_blocked:
            parts.append(f"{_C.Y}{skipped_blocked} already-blocked{_C.E}")
        if parts:
            msg += f" (skipped {', '.join(parts)})"
        print(msg)

    # ── Phase 2.5: Cluster payloads by technique family ─────────────────
    # Skip entire families when representative is blocked — saves 60-70% requests
    _use_clustering = len(ranked) > 10
    _blocked_families = set()
    if _use_clustering:
        try:
            from fray.evolve import cluster_payloads
            _clusters = cluster_payloads(
                [p.get("payload", p) if isinstance(p, dict) else p for p in ranked]
            )
            # Reorder: one representative per family first, then rest
            _representatives = []
            _others = []
            _seen_families = set()
            for p in ranked:
                _ps = p.get("payload", p) if isinstance(p, dict) else p
                _fam = _clusters.get(_ps, "other")
                if _fam not in _seen_families:
                    _seen_families.add(_fam)
                    _representatives.append(p)
                else:
                    _others.append(p)
            ranked = _representatives + _others
            if verbose:
                print(f"    Clustered into {_C.B}{len(_seen_families)}{_C.E} technique families "
                      f"({len(_representatives)} representatives)")
        except Exception:
            _use_clustering = False

    # ── Phase 3+: Iterative test → analyze → mutate rounds ──────────────
    round_size = min(20, requests_remaining // max(max_rounds, 1))

    for round_num in range(1, max_rounds + 1):
        if requests_remaining <= 0:
            break

        is_first_round = round_num == 1
        pool = ranked[:round_size] if is_first_round else _build_mutation_pool(
            all_results, all_bypasses, profile, category, round_num,
            blocked_hash_set, failed_strats
        )

        if not pool:
            if verbose:
                print(f"\n  {_C.DIM}Round {round_num}: No candidates — stopping{_C.E}")
            break

        n_test = min(len(pool), round_size, requests_remaining)
        if verbose:
            label = "Testing top payloads" if is_first_round else "Testing mutations"
            print(f"\n  {_C.BL}Round {round_num}: {label} ({n_test} requests)...{_C.E}")

        round_bypasses = 0
        round_blocked = []

        for i, p in enumerate(pool[:n_test]):
            if requests_remaining <= 0:
                break

            payload_str = p.get("payload", p) if isinstance(p, dict) else p

            # Skip if this exact payload was blocked before
            ph = _payload_hash(payload_str)
            if ph in blocked_hash_set:
                stats.skipped_known_blocked += 1
                continue

            result = tester.test_payload(payload_str, param=param)
            requests_remaining -= 1
            stats.total_requests += 1

            if is_first_round:
                stats.payloads_tested += 1
            else:
                stats.mutations_tested += 1

            result["round"] = round_num
            if isinstance(p, dict):
                result["evolve_score"] = p.get("evolve_score", 0)
                result["mutation"] = p.get("mutation", p.get("strategy", ""))

            all_results.append(result)

            if not result.get("blocked"):
                round_bypasses += 1
                if is_first_round:
                    stats.bypasses_from_payloads += 1
                else:
                    stats.bypasses_from_mutations += 1
                result["source"] = "mutation" if not is_first_round else "payload"
                technique = (p.get("mutation", "") or p.get("strategy", "")
                             or p.get("technique", "")) if isinstance(p, dict) else ""
                result["technique"] = technique
                if technique:
                    stats.unique_bypass_techniques.add(technique)
                all_bypasses.append(result)

                if verbose:
                    tech = technique[:25] if technique else ""
                    print(f"    [{i+1}/{n_test}] {_C.G}BYPASS{_C.E}  "
                          f"{payload_str[:40]} {_C.DIM}{tech}{_C.E}")
            else:
                round_blocked.append((payload_str, result))
                # Remember this payload was blocked — never try again
                blocked_hash_set.add(_payload_hash(payload_str))
                # Track failed mutation strategy
                tech = (p.get("mutation", "") or p.get("strategy", "")
                        ) if isinstance(p, dict) else ""
                if tech:
                    failed_strats[tech] = failed_strats.get(tech, 0) + 1
                if verbose:
                    print(f"    [{i+1}/{n_test}] {_C.R}BLOCKED{_C.E} "
                          f"{payload_str[:40]}")

            time.sleep(tester.delay)

        stats.rounds_completed = round_num

        if verbose:
            print(f"    {_C.DIM}Round {round_num} result: "
                  f"{round_bypasses} bypasses, {len(round_blocked)} blocked{_C.E}")

        # If no blocked payloads to learn from, no need for more rounds
        if not round_blocked:
            if verbose:
                print(f"    {_C.G}All passed — no more rounds needed{_C.E}")
            break

    # ── Optional: Batched LLM fallback ───────────────────────────────────
    if use_ai and requests_remaining > 5 and all_results:
        ai_bypasses = _try_ai_batch(tester, profile, all_results,
                                     all_bypasses, param, requests_remaining,
                                     verbose)
        for r in ai_bypasses:
            all_results.append(r)
            if not r.get("blocked"):
                all_bypasses.append(r)
                stats.bypasses_from_mutations += 1
                stats.unique_bypass_techniques.add(r.get("technique", "ai"))
            stats.mutations_tested += 1
            stats.total_requests += 1

    # ── Save ALL learned data to cache (successes AND failures) ──────────
    if use_cache:
        _update_cache(cache, vendor, all_bypasses, all_results, profile,
                       blocked_hash_set, failed_strats)
        _save_cache(cache)
        n_blocked = len(blocked_hash_set)
        if verbose:
            if all_bypasses:
                print(f"\n  {_C.CY}Cached {len(all_bypasses)} bypass(es) + "
                      f"{n_blocked} blocked hashes for {vendor}{_C.E}")
            else:
                print(f"\n  {_C.CY}Cached {n_blocked} blocked hashes for {vendor} "
                      f"(will skip next run){_C.E}")

    # ── Summary ──────────────────────────────────────────────────────────
    if verbose:
        print(f"\n  {_C.B}Agent Summary{_C.E}")
        print(f"    Rounds:     {stats.rounds_completed}")
        print(f"    Requests:   {stats.total_requests} / {budget}"
              f"{' (saved ' + str(stats.skipped_known_blocked) + ' from memory)' if stats.skipped_known_blocked else ''}")
        if stats.profile_from_cache:
            print(f"    Probes:     {_C.CY}skipped (cached profile){_C.E}")
        print(f"    Bypasses:   {_C.G}{stats.total_bypasses}{_C.E} "
              f"(payload: {stats.bypasses_from_payloads}, "
              f"mutation: {stats.bypasses_from_mutations}, "
              f"cache: {stats.bypasses_from_cache})")
        if stats.skipped_known_blocked:
            print(f"    Memory:     {_C.Y}skipped {stats.skipped_known_blocked} "
                  f"payloads blocked in previous runs{_C.E}")
        if stats.unique_bypass_techniques:
            techs = ', '.join(sorted(stats.unique_bypass_techniques)[:8])
            print(f"    Techniques: {techs}")
        print(f"    Bypass rate:{_C.B} {stats.bypass_rate}{_C.E}")

    return all_results, stats, profile


# ── Mutation Pool Builder ────────────────────────────────────────────────────

def _build_mutation_pool(results: List[Dict], bypasses: List[Dict],
                          profile: WAFProfile, category: str,
                          round_num: int,
                          blocked_hash_set: Set[str] = None,
                          failed_strats: Dict[str, int] = None) -> List[Dict]:
    """Build the next round's payload pool from previous results.

    Strategy:
      1. Analyze WHY blocked payloads were blocked
      2. Pick targeted mutations for each block reason
      3. Also mutate successful bypasses to find more variants
    """
    pool = []

    # ── Mutate bypasses (find more variants of what works) ───────────────
    mutator = PayloadMutator(profile, category=category or "xss")
    for bypass in bypasses[-5:]:  # Last 5 bypasses
        payload_str = bypass.get("payload", "")
        if not payload_str:
            continue
        mutations = mutator.mutate(payload_str, max_mutations=3)
        pool.extend(mutations)

    # ── Vendor-specific mutations (try WAF-tailored evasions first) ─────
    _waf_vendor = profile.waf_vendor or ""
    if _waf_vendor:
        try:
            from fray.mutator import mutate_payload as _mp_vendor
            # Pick a few recent blocked payloads and apply vendor mutations
            _recent_blocked = [r for r in results[-10:] if r.get("blocked")]
            for _rb in _recent_blocked[:4]:
                _rp = _rb.get("payload", "")
                if _rp:
                    _vm = _mp_vendor(_rp, max_variants=2, waf_vendor=_waf_vendor)
                    pool.extend(_vm)
        except Exception:
            pass

    # ── Analyze blocked payloads → targeted mutations ────────────────────
    blocked = [r for r in results[-20:] if r.get("blocked")]
    seen_rules = set()

    for r in blocked:
        payload_str = r.get("payload", "")
        if not payload_str:
            continue

        reason = analyze_block_reason(payload_str, profile)

        # Skip if we've already tried mutations for this rule pattern
        if reason.likely_rule in seen_rules:
            continue
        seen_rules.add(reason.likely_rule)

        # Get suggested strategies and apply them
        strategies = reason.suggested_mutations()
        # Rotate strategies by round to avoid repeating
        offset = (round_num - 2) * 2  # Start from 0 in round 2
        strategies = strategies[offset:] + strategies[:offset]

        # Deprioritize strategies that failed many times before
        if failed_strats:
            strategies = sorted(
                strategies,
                key=lambda s: failed_strats.get(s, 0)
            )

        mutations = mutate_payload(payload_str,
                                    max_variants=3,
                                    strategies=strategies[:5])
        pool.extend(mutations)

    # Filter out payloads we already know are blocked
    if blocked_hash_set:
        pool = [m for m in pool
                if _payload_hash(m.get("payload", "")) not in blocked_hash_set]

    return pool


# ── Batched LLM Fallback ────────────────────────────────────────────────────

def _try_ai_batch(tester, profile: WAFProfile, results: List[Dict],
                   bypasses: List[Dict], param: str,
                   budget: int, verbose: bool) -> List[Dict]:
    """Last resort: batch blocked payloads → single LLM call → test results."""
    try:
        from fray.ai_bypass import _call_llm, _llm_available
    except ImportError:
        return []

    if not _llm_available():
        return []

    if verbose:
        print(f"\n  {_C.CY}AI Fallback: Batching blocked payloads → LLM...{_C.E}")

    # Build context for LLM
    blocked_samples = []
    for r in results[-30:]:
        if r.get("blocked"):
            blocked_samples.append({
                "payload": r.get("payload", "")[:80],
                "status": r.get("status", 0),
            })

    if not blocked_samples:
        return []

    bypass_samples = []
    for b in bypasses[:5]:
        bypass_samples.append({
            "payload": b.get("payload", "")[:80],
            "technique": b.get("technique", ""),
        })

    waf_info = {
        "strictness": profile.strictness,
        "blocked_tags": list(profile.blocked_tags),
        "blocked_events": list(profile.blocked_events),
        "blocked_keywords": list(profile.blocked_keywords),
        "allowed_tags": list(profile.allowed_tags - {"b"}),
        "allowed_events": list(profile.allowed_events),
    }

    messages = [
        {"role": "system", "content": (
            "You are a WAF bypass expert. Given blocked payloads and WAF behavior, "
            "generate 5-8 bypass payloads. Output ONLY a JSON array of objects: "
            '[{"payload": "...", "technique": "..."}]. No markdown, no explanation.'
        )},
        {"role": "user", "content": json.dumps({
            "waf_profile": waf_info,
            "blocked_payloads": blocked_samples[:10],
            "successful_bypasses": bypass_samples,
            "request": "Generate new bypass payloads that avoid the blocked patterns.",
        }, indent=2)},
    ]

    try:
        response = _call_llm(messages, temperature=0.9, max_tokens=1500)
        # Parse JSON array from response
        match = re.search(r'\[.*\]', response, re.DOTALL)
        if not match:
            return []
        ai_payloads = json.loads(match.group(0))
    except Exception:
        return []

    # Test AI-generated payloads
    ai_results = []
    for ap in ai_payloads[:min(8, budget)]:
        payload_str = ap.get("payload", "")
        if not payload_str:
            continue

        result = tester.test_payload(payload_str, param=param)
        result["source"] = "ai"
        result["technique"] = f"ai:{ap.get('technique', 'llm')}"
        ai_results.append(result)

        if verbose:
            status = f"{_C.G}BYPASS{_C.E}" if not result.get("blocked") else f"{_C.R}BLOCKED{_C.E}"
            print(f"    AI {status} {payload_str[:40]}")

        time.sleep(tester.delay)

    return ai_results


# ── Cache Update ─────────────────────────────────────────────────────────────

def _update_cache(cache: Dict, vendor: str, bypasses: List[Dict],
                   all_results: List[Dict], profile: WAFProfile,
                   blocked_hash_set: Set[str],
                   failed_strats: Dict[str, int]) -> None:
    """Update the learned pattern cache — both successes AND failures."""
    vc = _get_vendor_cache(cache, vendor)
    vc["total_runs"] = vc.get("total_runs", 0) + 1

    # ── Save successful payloads (deduplicated, max 50) ──────────────────
    existing = set()
    for p in vc["successful_payloads"]:
        ps = p if isinstance(p, str) else p.get("payload", "")
        existing.add(ps)

    for b in bypasses:
        payload_str = b.get("payload", "")
        if payload_str and payload_str not in existing:
            existing.add(payload_str)
            vc["successful_payloads"].append({
                "payload": payload_str,
                "technique": b.get("technique", b.get("mutation", "")),
                "status": b.get("status", 200),
            })

    vc["successful_payloads"] = vc["successful_payloads"][-50:]

    # ── Save blocked payload hashes (max 2000) ───────────────────────────
    existing_hashes = set(vc.get("blocked_hashes", []))
    existing_hashes.update(blocked_hash_set)
    vc["blocked_hashes"] = list(existing_hashes)[-2000:]
    vc["total_blocked"] = len(vc["blocked_hashes"])

    # ── Track effective strategies ────────────────────────────────────────
    for b in bypasses:
        tech = b.get("technique", b.get("mutation", ""))
        if tech:
            base_tech = tech.split(":")[0] if ":" in tech else tech
            base_tech = base_tech.split("+")[0]
            vc["effective_strategies"][base_tech] = (
                vc["effective_strategies"].get(base_tech, 0) + 1
            )

    # ── Track failed strategies ───────────────────────────────────────────
    for strat, count in failed_strats.items():
        vc["failed_strategies"][strat] = (
            vc["failed_strategies"].get(strat, 0) + count
        )

    # ── Save WAF profile for future runs ─────────────────────────────────
    vc["waf_profile"] = {
        "blocked_tags": list(profile.blocked_tags),
        "blocked_events": list(profile.blocked_events),
        "blocked_keywords": list(profile.blocked_keywords),
        "blocked_patterns": list(profile.blocked_patterns),
        "blocked_encodings": list(profile.blocked_encodings),
        "allowed_tags": list(profile.allowed_tags),
        "allowed_events": list(profile.allowed_events),
        "allowed_keywords": list(profile.allowed_keywords),
        "block_status": profile.block_status,
        "baseline_status": profile.baseline_status,
        "total_probes": profile.total_probes,
        "total_blocked": profile.total_blocked,
        "waf_vendor": profile.waf_vendor,
    }

    # ── Save blocked rules for this vendor ────────────────────────────────
    vc["blocked_rules"] = list(profile.blocked_tags | profile.blocked_events
                                | profile.blocked_keywords)
