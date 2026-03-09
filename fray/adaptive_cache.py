#!/usr/bin/env python3
"""
Fray Adaptive Cache — Per-domain payload intelligence.

Learns which payloads get blocked on a specific domain/WAF over time and
reorders subsequent scan attempts to lead with proven bypasses and skip
known-blocked payloads in the first N slots.

Phase 1 — Local:
    ~/.fray/domain_cache.json   persists blocked/passed payload hashes per domain

Phase 2 — Community (opt-in, async):
    Cloudflare D1 via cloud_sync.py  share_patterns: true in ~/.fray/cloud.json

Cache schema (domain_cache.json):
{
  "cloudflare.com": {
    "waf_vendor": "Cloudflare",
    "blocked": {
      "<sha256[:16]>": {
        "payload": "<original payload>",
        "count": 3,
        "last_seen": "ISO8601"
      }
    },
    "passed": {
      "<sha256[:16]>": {
        "payload": "<original payload>",
        "count": 1,
        "bypass_confidence": 82,
        "last_seen": "ISO8601"
      }
    },
    "total_scans": 5,
    "updated_at": "ISO8601"
  }
}

Usage:
    from fray.adaptive_cache import smart_sort_payloads, save_scan_results

    # Before scan — reorder payloads
    payloads = smart_sort_payloads(payloads, domain="cloudflare.com", top_n=10)

    # After scan — record outcomes (also async-shares to D1 if opted in)
    save_scan_results(results, domain="cloudflare.com", waf_vendor="Cloudflare")
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

_FRAY_DIR = Path.home() / ".fray"
_CACHE_PATH = _FRAY_DIR / "domain_cache.json"

# Slots at the front reserved for proven bypasses
DEFAULT_TOP_N = 10

# Blocked this many times → deprioritised to end of queue.
# Set to 1 so a single confirmed block is enough to deprioritise —
# most payloads are only tested once per domain in practice.
BLOCK_THRESHOLD = 1

_cache_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _payload_hash(payload: str) -> str:
    """16-char SHA-256 prefix for a payload string."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _extract_domain(target: str) -> str:
    """Normalise a URL or bare hostname to a lowercase domain key.

    Examples:
        "https://cloudflare.com/foo?bar=1" → "cloudflare.com"
        "www.cloudflare.com"               → "cloudflare.com"
    """
    if "://" not in target:
        target = "https://" + target
    host = (urlparse(target).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Cache I/O ─────────────────────────────────────────────────────────────────

def load_cache() -> Dict:
    """Load domain cache from disk. Returns {} on missing/corrupt file."""
    if not _CACHE_PATH.exists():
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: Dict) -> None:
    """Persist cache atomically (write tmp → rename)."""
    _FRAY_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _CACHE_PATH.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
        tmp.replace(_CACHE_PATH)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _get_domain_entry(cache: Dict, domain: str) -> Dict:
    """Return (and create if missing) a domain entry in the cache."""
    if domain not in cache:
        cache[domain] = {
            "waf_vendor": "",
            "blocked": {},
            "passed": {},
            "total_scans": 0,
            "updated_at": _now_iso(),
        }
    return cache[domain]


# ── Core API ──────────────────────────────────────────────────────────────────

def _detect_vendor(domain: str) -> str:
    """Best-effort WAF vendor detection for a domain.

    Check order (fastest first):
      1. Already stored in local cache for this domain
      2. Lightweight HTTP probe — inspect response headers for known WAF signatures

    Returns vendor string (e.g. "Cloudflare") or "" if unknown.
    Never raises — always returns safely.
    """
    # 1. Check local cache first — free, instant
    try:
        cache = load_cache()
        vendor = cache.get(domain, {}).get("waf_vendor", "")
        if vendor:
            return vendor
    except Exception:
        pass

    # 2. Quick HTTP probe — inspect headers only (no body read)
    try:
        import http.client, ssl as _ssl
        ctx = _ssl.create_default_context()
        conn = http.client.HTTPSConnection(domain, 443, timeout=5, context=ctx)
        conn.request("HEAD", "/", headers={"User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v.lower() for k, v in resp.getheaders()}
        conn.close()

        if "cf-ray" in headers or headers.get("server", "") == "cloudflare":
            return "Cloudflare"
        if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
            return "Sucuri"
        if "x-amzn-requestid" in headers or "x-amz-cf-id" in headers:
            return "AWS WAF"
        if "x-cdn" in headers and "imperva" in headers.get("x-cdn", ""):
            return "Imperva"
        if "x-fw-hash" in headers:
            return "Fastly"
    except Exception:
        pass

    return ""


def save_scan_results(
    results: List[Dict],
    domain: str,
    waf_vendor: str = "",
    share_async: bool = True,
) -> None:
    """Persist scan outcomes to local cache, and optionally share to D1.

    Call this after every test_payloads() or run_scan() call.

    Args:
        results:      List of result dicts from WAFTester.test_payloads().
                      Each must have "payload" (str) and "blocked" (bool).
                      Optional: "bypass_confidence" (int), "category" (str).
        domain:       Target domain or full URL.
        waf_vendor:   Detected WAF vendor name (stored for reference).
        share_async:  If True and share_patterns is enabled in cloud.json,
                      submit results to Cloudflare D1 in a background thread.
    """
    if not results:
        return

    domain = _extract_domain(domain) if domain else ""
    if not domain:
        return

    # Auto-detect WAF vendor if not supplied — check cache first, then headers
    if not waf_vendor:
        waf_vendor = _detect_vendor(domain)

    with _cache_lock:
        cache = load_cache()
        entry = _get_domain_entry(cache, domain)

        if waf_vendor:
            entry["waf_vendor"] = waf_vendor

        now = _now_iso()

        for r in results:
            payload = r.get("payload", "")
            if not payload or not isinstance(payload, str):
                continue

            ph = _payload_hash(payload)
            blocked = bool(r.get("blocked", True))

            if blocked:
                rec = entry["blocked"].get(ph, {
                    "payload": payload[:500],
                    "count": 0,
                    "last_seen": now,
                })
                rec["count"] = rec.get("count", 0) + 1
                rec["last_seen"] = now
                entry["blocked"][ph] = rec
                # Remove from passed if stale
                entry["passed"].pop(ph, None)
            else:
                blocked_count = entry["blocked"].get(ph, {}).get("count", 0)
                if blocked_count >= BLOCK_THRESHOLD:
                    continue  # Still confidently blocked — don't promote
                rec = entry["passed"].get(ph, {
                    "payload": payload[:500],
                    "count": 0,
                    "bypass_confidence": 0,
                    "last_seen": now,
                })
                rec["count"] = rec.get("count", 0) + 1
                rec["bypass_confidence"] = max(
                    rec.get("bypass_confidence", 0),
                    int(r.get("bypass_confidence", 0)),
                )
                rec["last_seen"] = now
                entry["passed"][ph] = rec
                entry["blocked"].pop(ph, None)

        entry["total_scans"] = entry.get("total_scans", 0) + 1
        entry["updated_at"] = now
        _save_cache(cache)

    # ── D1 share (opt-in) ─────────────────────────────────────────────────
    # Run in a non-daemon thread so it completes even if called near process
    # exit. Still async so it never blocks the caller.
    if share_async:
        def _share():
            try:
                from fray.cloud_sync import load_config, d1_share_test_results
                cfg = load_config()
                if cfg.share_patterns:
                    d1_share_test_results(cfg, results, domain)
            except Exception:
                pass  # Never crash the caller

        t = threading.Thread(target=_share, daemon=False)
        t.start()
        # Give it up to 8 seconds to complete before returning —
        # short enough to not feel slow, long enough for a D1 round-trip.
        t.join(timeout=8)


def _get_vendor_blocked_hashes(cache: Dict, vendor: str, exclude_domain: str) -> Dict[str, int]:
    """Aggregate blocked payload hashes across all domains sharing the same WAF vendor.

    This allows smart_sort_payloads() to skip payloads already confirmed blocked
    on a sibling zone (e.g. 3test.mnishihara.com → httpbin.mnishihara.com) without
    needing to waste attempts re-testing them.

    Args:
        cache:          Full loaded cache dict.
        vendor:         WAF vendor name to match (case-insensitive).
        exclude_domain: The current scan domain — excluded to avoid double-counting.

    Returns:
        Dict of {payload_hash: block_count} aggregated from all sibling domains.
    """
    if not vendor:
        return {}

    vendor_lower = vendor.lower()
    aggregated: Dict[str, int] = {}

    for d, entry in cache.items():
        if d == exclude_domain:
            continue
        if entry.get("waf_vendor", "").lower() != vendor_lower:
            continue
        for ph, info in entry.get("blocked", {}).items():
            count = info.get("count", 1)
            # Accumulate across sibling domains
            aggregated[ph] = aggregated.get(ph, 0) + count

    return aggregated


def smart_sort_payloads(
    payloads: List[Dict],
    domain: str,
    top_n: int = DEFAULT_TOP_N,
    waf_vendor: str = "",
) -> List[Dict]:
    """Reorder payloads using accumulated domain knowledge.

    Ordering strategy
    -----------------
    Front (slots 1..top_n) — Proven bypasses sorted by bypass_confidence desc.
                              These run FIRST so high-value attempts happen early.
    Middle                  — Unknown payloads (never seen for this domain or vendor).
    End                     — Payloads blocked >= BLOCK_THRESHOLD times on this domain
                              OR on any sibling domain sharing the same WAF vendor.
                              Still included (WAF rules change) but deprioritised.

    Args:
        payloads:   List of payload dicts (must contain "payload" key).
        domain:     Target domain or full URL.
        top_n:      Number of front slots reserved for proven bypasses.
        waf_vendor: WAF vendor name — used to pull cross-domain blocked payloads
                    from sibling zones with the same WAF config.

    Returns:
        Reordered list (same objects, new order).
    """
    if not payloads:
        return payloads

    domain = _extract_domain(domain) if domain else ""
    if not domain:
        return payloads

    cache = load_cache()

    # Fall back gracefully if domain not seen before — but still apply
    # vendor-level intelligence from sibling domains if available.
    entry = cache.get(domain, {})
    vendor = waf_vendor or entry.get("waf_vendor", "")

    blocked_counts: Dict[str, int] = {
        ph: info.get("count", 1)
        for ph, info in entry.get("blocked", {}).items()
    }
    passed_confidence: Dict[str, int] = {
        ph: info.get("bypass_confidence", 50)
        for ph, info in entry.get("passed", {}).items()
    }

    # ── Cross-domain vendor intelligence ─────────────────────────────────
    # Merge blocked hashes from all sibling domains sharing the same WAF vendor.
    # A payload confirmed blocked on 3test.mnishihara.com (Cloudflare) will be
    # deprioritised on httpbin.mnishihara.com (also Cloudflare) automatically.
    vendor_blocked: Dict[str, int] = _get_vendor_blocked_hashes(cache, vendor, domain)
    # Merge: domain-specific counts take priority, vendor counts fill the gaps
    for ph, count in vendor_blocked.items():
        if ph not in blocked_counts:
            blocked_counts[ph] = count

    # Also pull community bypasses from D1 if available (best-effort, sync)
    community_hashes: Dict[str, int] = {}
    try:
        from fray.cloud_sync import load_config, d1_get_community_bypasses, d1_available
        cfg = load_config()
        if d1_available(cfg):
            vendor = waf_vendor or entry.get("waf_vendor", "")
            bypasses = d1_get_community_bypasses(cfg, waf_vendor=vendor, limit=100)
            for b in bypasses:
                p = b.get("payload", "")
                if p:
                    ph = _payload_hash(p)
                    community_hashes[ph] = 90  # High confidence for community-verified
    except Exception:
        pass

    proven_bypasses: List[Dict] = []
    unknown: List[Dict] = []
    likely_blocked: List[Dict] = []

    for p in payloads:
        raw = p.get("payload", p) if isinstance(p, dict) else str(p)
        ph = _payload_hash(raw)

        if ph in passed_confidence or ph in community_hashes:
            item = dict(p) if isinstance(p, dict) else {"payload": raw}
            # Prefer local confidence, fall back to community
            item["_cached_confidence"] = max(
                passed_confidence.get(ph, 0),
                community_hashes.get(ph, 0),
            )
            proven_bypasses.append(item)
        elif ph in blocked_counts and blocked_counts[ph] >= BLOCK_THRESHOLD:
            likely_blocked.append(p)
        else:
            unknown.append(p)

    # Sort proven bypasses by confidence desc
    proven_bypasses.sort(key=lambda x: x.get("_cached_confidence", 0), reverse=True)

    # Strip internal tag
    for item in proven_bypasses:
        item.pop("_cached_confidence", None)

    return proven_bypasses[:top_n] + unknown + proven_bypasses[top_n:] + likely_blocked


def get_domain_stats(domain: str) -> Optional[Dict]:
    """Return cache statistics for a domain. Returns None if no data."""
    domain = _extract_domain(domain) if domain else ""
    cache = load_cache()
    if domain not in cache:
        return None

    entry = cache[domain]

    top_bypasses = sorted(
        [
            {
                "payload": v.get("payload", ""),
                "bypass_confidence": v.get("bypass_confidence", 0),
                "count": v.get("count", 1),
            }
            for v in entry.get("passed", {}).values()
        ],
        key=lambda x: x["bypass_confidence"],
        reverse=True,
    )[:10]

    top_blocked = sorted(
        [
            {
                "payload": v.get("payload", ""),
                "count": v.get("count", 1),
            }
            for v in entry.get("blocked", {}).values()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    return {
        "domain": domain,
        "waf_vendor": entry.get("waf_vendor", ""),
        "total_scans": entry.get("total_scans", 0),
        "blocked_payloads": len(entry.get("blocked", {})),
        "passed_payloads": len(entry.get("passed", {})),
        "top_bypasses": top_bypasses,
        "top_blocked": top_blocked,
        "updated_at": entry.get("updated_at", ""),
    }


def clear_domain_cache(domain: str = "") -> int:
    """Clear cache for one domain, or wipe all. Returns number of entries removed."""
    with _cache_lock:
        cache = load_cache()
        if not domain or domain == "*":
            count = len(cache)
            _save_cache({})
            return count
        domain = _extract_domain(domain)
        if domain in cache:
            del cache[domain]
            _save_cache(cache)
            return 1
        return 0


def print_cache_summary(domain: str = "") -> None:
    """Print a human-readable cache summary to stdout."""
    cache = load_cache()
    if not cache:
        print("  No adaptive cache data yet.")
        print("  Run a scan first: fray test <url> -c xss")
        return

    domains = [_extract_domain(domain)] if domain else list(cache.keys())

    for d in domains:
        if d not in cache:
            print(f"  No cache data for {d}")
            continue
        stats = get_domain_stats(d)
        if not stats:
            continue

        vendor = f" [{stats['waf_vendor']}]" if stats["waf_vendor"] else ""
        print(f"\n  {d}{vendor}")
        print(f"    Scans:    {stats['total_scans']}")
        print(f"    Blocked:  {stats['blocked_payloads']} unique payloads")
        print(f"    Bypasses: {stats['passed_payloads']} unique payloads")
        print(f"    Updated:  {stats['updated_at']}")

        if stats["top_bypasses"]:
            print("    Top bypasses (by confidence):")
            for b in stats["top_bypasses"][:5]:
                print(f"      [{b['bypass_confidence']:>3}%] {b['payload'][:70]}")

        if stats["top_blocked"]:
            print("    Most blocked (skipped in first 10 attempts next scan):")
            for b in stats["top_blocked"][:5]:
                print(f"      [x{b['count']:>2}]  {b['payload'][:70]}")
