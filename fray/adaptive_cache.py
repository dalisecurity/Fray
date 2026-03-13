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

# Cache size limits (#43) — evict least-recently-used domains when exceeded
MAX_DOMAINS = 500
MAX_PAYLOADS_PER_DOMAIN = 2000  # max blocked + passed hashes per domain

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
    """Persist cache atomically (write tmp → rename).

    Applies size limits (#43):
    - Per-domain: truncate blocked/passed lists to MAX_PAYLOADS_PER_DOMAIN
    - Global: evict least-recently-updated domains beyond MAX_DOMAINS
    """
    # ── Per-domain payload cap ──
    for domain, entry in cache.items():
        if isinstance(entry, dict):
            for key in ("blocked", "passed"):
                lst = entry.get(key)
                if isinstance(lst, list) and len(lst) > MAX_PAYLOADS_PER_DOMAIN:
                    entry[key] = lst[-MAX_PAYLOADS_PER_DOMAIN:]

    # ── Global domain cap (LRU eviction) ──
    if len(cache) > MAX_DOMAINS:
        # Sort by updated_at ascending (oldest first), evict oldest
        sorted_domains = sorted(
            cache.keys(),
            key=lambda d: cache[d].get("updated_at", "") if isinstance(cache[d], dict) else "",
        )
        evict_count = len(cache) - MAX_DOMAINS
        for d in sorted_domains[:evict_count]:
            del cache[d]

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


def check_waf_config_change(domain: str, current_vendor: str = "") -> Dict:
    """#42 — Detect WAF configuration changes and invalidate stale cache.

    Compares the current WAF vendor against cached vendor. If the vendor
    changed (e.g. migrated from Cloudflare to Akamai), all cached
    blocked/passed data is invalidated because the WAF rules are different.

    Also checks if the cache is older than MAX_CACHE_AGE_DAYS.

    Returns:
        Dict with 'changed' (bool), 'reason' (str), 'invalidated' (int),
        'old_vendor', 'new_vendor'.
    """
    from datetime import datetime

    MAX_CACHE_AGE_DAYS = 30

    result = {
        "changed": False,
        "reason": "",
        "invalidated": 0,
        "old_vendor": "",
        "new_vendor": current_vendor,
    }

    domain = _extract_domain(domain) if domain else ""
    if not domain:
        return result

    # Auto-detect if not supplied
    if not current_vendor:
        current_vendor = _detect_vendor(domain)
        result["new_vendor"] = current_vendor

    with _cache_lock:
        cache = load_cache()
        entry = cache.get(domain)
        if not entry or not isinstance(entry, dict):
            return result

        old_vendor = entry.get("waf_vendor", "")
        result["old_vendor"] = old_vendor
        updated_at = entry.get("updated_at", "")

        # Check 1: Vendor changed
        if (old_vendor and current_vendor and
                old_vendor.lower() != current_vendor.lower()):
            n_blocked = len(entry.get("blocked", {}))
            n_passed = len(entry.get("passed", {}))
            entry["blocked"] = {}
            entry["passed"] = {}
            entry["waf_vendor"] = current_vendor
            entry["updated_at"] = _now_iso()
            entry["invalidation_reason"] = f"WAF vendor changed: {old_vendor} → {current_vendor}"
            _save_cache(cache)
            result["changed"] = True
            result["reason"] = f"WAF vendor changed: {old_vendor} → {current_vendor}"
            result["invalidated"] = n_blocked + n_passed
            return result

        # Check 2: Cache too old
        if updated_at:
            try:
                last_update = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                age_days = (datetime.now(last_update.tzinfo) - last_update).days
                if age_days > MAX_CACHE_AGE_DAYS:
                    n_blocked = len(entry.get("blocked", {}))
                    n_passed = len(entry.get("passed", {}))
                    entry["blocked"] = {}
                    entry["passed"] = {}
                    entry["updated_at"] = _now_iso()
                    entry["invalidation_reason"] = f"Cache expired ({age_days} days old)"
                    _save_cache(cache)
                    result["changed"] = True
                    result["reason"] = f"Cache expired ({age_days} days old, max {MAX_CACHE_AGE_DAYS})"
                    result["invalidated"] = n_blocked + n_passed
                    return result
            except Exception:
                pass

    return result


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
                    "bypasses": [],
                    "last_seen": now,
                })
                rec["count"] = rec.get("count", 0) + 1
                rec["bypass_confidence"] = max(
                    rec.get("bypass_confidence", 0),
                    int(r.get("bypass_confidence", 0)),
                )
                rec["last_seen"] = now
                # Track which WAF vendors this payload bypasses
                if waf_vendor:
                    existing_bp = rec.get("bypasses", [])
                    if waf_vendor not in existing_bp:
                        existing_bp.append(waf_vendor)
                        rec["bypasses"] = existing_bp
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
    vendor_tagged: List[Dict] = []  # payloads with matching "bypasses" metadata
    unknown: List[Dict] = []
    likely_blocked: List[Dict] = []

    vendor_lower = vendor.lower() if vendor else ""

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
        elif vendor_lower and isinstance(p, dict) and p.get("bypasses"):
            # Payload declares which WAFs it bypasses — boost if vendor matches
            bp_lower = [b.lower() for b in p.get("bypasses", [])]
            if any(vendor_lower in b or b in vendor_lower for b in bp_lower):
                vendor_tagged.append(p)
            else:
                unknown.append(p)
        else:
            unknown.append(p)

    # Sort proven bypasses by confidence desc
    proven_bypasses.sort(key=lambda x: x.get("_cached_confidence", 0), reverse=True)

    # Strip internal tag
    for item in proven_bypasses:
        item.pop("_cached_confidence", None)

    # Order: proven cache bypasses → vendor-tagged → unknown → likely blocked
    return proven_bypasses[:top_n] + vendor_tagged + unknown + proven_bypasses[top_n:] + likely_blocked


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


def get_waf_leaderboard() -> List[Dict]:
    """Aggregate payload effectiveness stats per WAF vendor from the cache.

    Returns a list of dicts sorted by block_rate descending:
    [
        {
            "vendor": "Cloudflare",
            "domains": 3,
            "total_scans": 12,
            "blocked": 847,
            "passed": 23,
            "block_rate": 97.4,
            "top_bypasses": [...],
        },
        ...
    ]
    """
    cache = load_cache()
    if not cache:
        return []

    # Aggregate by vendor
    vendors: Dict[str, Dict] = {}
    for domain, entry in cache.items():
        vendor = entry.get("waf_vendor", "").strip()
        if not vendor:
            vendor = "Unknown"

        if vendor not in vendors:
            vendors[vendor] = {
                "vendor": vendor,
                "domains": 0,
                "total_scans": 0,
                "blocked": 0,
                "passed": 0,
                "bypasses": [],  # collect all bypass payloads
            }

        v = vendors[vendor]
        v["domains"] += 1
        v["total_scans"] += entry.get("total_scans", 0)
        v["blocked"] += len(entry.get("blocked", {}))
        v["passed"] += len(entry.get("passed", {}))

        # Collect bypass details for top_bypasses
        for _ph, info in entry.get("passed", {}).items():
            v["bypasses"].append({
                "payload": info.get("payload", "")[:100],
                "confidence": info.get("bypass_confidence", 0),
                "domain": domain,
            })

    # Build final list
    result = []
    for v in vendors.values():
        total = v["blocked"] + v["passed"]
        block_rate = (v["blocked"] / total * 100) if total > 0 else 0.0

        # Top 5 bypasses by confidence
        top = sorted(v["bypasses"], key=lambda x: x["confidence"], reverse=True)[:5]

        result.append({
            "vendor": v["vendor"],
            "domains": v["domains"],
            "total_scans": v["total_scans"],
            "blocked": v["blocked"],
            "passed": v["passed"],
            "total_payloads": total,
            "block_rate": round(block_rate, 1),
            "top_bypasses": top,
        })

    # Sort: highest block rate first (hardest WAFs at top)
    result.sort(key=lambda x: (-x["block_rate"], -x["total_payloads"]))
    return result


def print_waf_leaderboard() -> None:
    """Print a rich WAF effectiveness leaderboard to stdout."""
    from fray.output import console
    from fray import __version__
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    leaderboard = get_waf_leaderboard()
    if not leaderboard:
        console.print("[yellow]  No scan data yet. Run some tests first:[/yellow]")
        console.print("    fray test https://example.com -c xss --smart")
        return

    table = Table(show_lines=False, pad_edge=False, box=None)
    table.add_column("#", width=3, justify="right", style="dim")
    table.add_column("WAF Vendor", min_width=18, style="bold")
    table.add_column("Block Rate", width=10, justify="right")
    table.add_column("", min_width=20)  # bar
    table.add_column("Blocked", width=8, justify="right")
    table.add_column("Bypassed", width=8, justify="right")
    table.add_column("Domains", width=7, justify="right", style="dim")
    table.add_column("Scans", width=6, justify="right", style="dim")

    for i, entry in enumerate(leaderboard):
        rate = entry["block_rate"]
        # Color by block rate
        if rate >= 95:
            color = "bright_red"
        elif rate >= 80:
            color = "red"
        elif rate >= 60:
            color = "yellow"
        elif rate >= 40:
            color = "bright_yellow"
        else:
            color = "green"

        bar_width = int(rate / 100 * 20)
        bar = Text("█" * bar_width + "░" * (20 - bar_width), style=color)
        rate_txt = Text(f"{rate:.1f}%", style=f"bold {color}")

        bypassed_style = "bold green" if entry["passed"] > 0 else "dim"

        table.add_row(
            str(i + 1),
            entry["vendor"],
            rate_txt,
            bar,
            str(entry["blocked"]),
            Text(str(entry["passed"]), style=bypassed_style),
            str(entry["domains"]),
            str(entry["total_scans"]),
        )

    total_blocked = sum(e["blocked"] for e in leaderboard)
    total_passed = sum(e["passed"] for e in leaderboard)
    total_domains = sum(e["domains"] for e in leaderboard)
    total_scans = sum(e["total_scans"] for e in leaderboard)

    table.add_row("", "", "", "", "", "", "", "")
    table.add_row(
        "",
        Text("TOTAL", style="bold white"),
        Text("", style="dim"),
        Text("━" * 20, style="bold"),
        Text(str(total_blocked), style="bold white"),
        Text(str(total_passed), style="bold white"),
        Text(str(total_domains), style="bold white"),
        Text(str(total_scans), style="bold white"),
    )

    console.print()
    console.print(Panel(
        table,
        title=f"[bold]Fray v{__version__} — WAF Effectiveness Leaderboard[/bold]",
        subtitle=f"[dim]{len(leaderboard)} vendors · {total_domains} domains · {total_scans} scans · {total_blocked + total_passed:,} payloads[/dim]",
        border_style="bright_cyan",
        expand=False,
    ))

    # Show top bypasses per vendor
    any_bypasses = any(e["passed"] > 0 for e in leaderboard)
    if any_bypasses:
        console.print()
        console.print("  [bold]Top Bypasses by Vendor:[/bold]")
        for entry in leaderboard:
            if not entry["top_bypasses"]:
                continue
            console.print(f"\n  [bold]{entry['vendor']}[/bold]")
            for b in entry["top_bypasses"]:
                conf = b.get("confidence", 0)
                payload = b.get("payload", "")[:60]
                domain = b.get("domain", "")
                console.print(f"    [{conf:>3}%] {payload}  [dim]({domain})[/dim]")

    console.print()


def get_waf_market_share() -> Dict:
    """Aggregate WAF vendor distribution from scan cache data (#78).

    Returns:
        Dict with 'vendors', 'total_domains', 'distribution', 'top_vendor'.
    """
    cache = load_cache()
    vendor_counts: Dict[str, int] = {}
    total = 0

    for domain, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        total += 1
        vendor = entry.get("waf_vendor", "").strip()
        if vendor:
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    no_waf = total - sum(vendor_counts.values())
    if no_waf > 0:
        vendor_counts["(no WAF detected)"] = no_waf

    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: -x[1])

    distribution = {}
    for name, count in sorted_vendors:
        pct = round(count / total * 100, 1) if total else 0
        distribution[name] = {"count": count, "pct": pct}

    return {
        "vendors": [v[0] for v in sorted_vendors if v[0] != "(no WAF detected)"],
        "total_domains": total,
        "domains_with_waf": total - no_waf if no_waf > 0 else total,
        "top_vendor": sorted_vendors[0][0] if sorted_vendors else None,
        "distribution": distribution,
    }


def print_waf_market_share() -> None:
    """Print WAF market share table to stdout."""
    data = get_waf_market_share()
    if not data["total_domains"]:
        print("  No scan data yet. Run: fray recon <domain>")
        return

    print(f"\n  WAF Market Share ({data['total_domains']} domains scanned)")
    print("  " + "-" * 45)
    for vendor, info in data["distribution"].items():
        bar = "█" * int(info["pct"] / 2.5)
        print(f"  {vendor:<25} {info['count']:>4}  ({info['pct']:>5.1f}%)  {bar}")
    print()


def export_cache(output_path: str, domain: str = "") -> Dict:
    """Export adaptive cache to a portable JSON file.

    Args:
        output_path: Destination file path.
        domain: If set, export only this domain. Otherwise export all.

    Returns:
        Dict with 'domains', 'entries', 'path'.
    """
    cache = load_cache()

    if domain:
        domain = _extract_domain(domain)
        export_data = {domain: cache[domain]} if domain in cache else {}
    else:
        export_data = cache

    meta = {
        "_fray_cache_export": True,
        "_version": 1,
        "_exported_at": _now_iso(),
        "_domains": len(export_data),
        "data": export_data,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    return {"domains": len(export_data), "entries": sum(1 for _ in export_data), "path": str(out)}


def import_cache(input_path: str, merge: bool = True) -> Dict:
    """Import adaptive cache from a previously exported JSON file.

    Args:
        input_path: Source file path.
        merge: If True, merge with existing cache (default). If False, replace.

    Returns:
        Dict with 'imported_domains', 'merged', 'total_domains'.
    """
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(f"Cache file not found: {input_path}")

    with open(inp, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Support both wrapped (with _fray_cache_export header) and raw formats
    if isinstance(raw, dict) and raw.get("_fray_cache_export"):
        import_data = raw.get("data", {})
    elif isinstance(raw, dict):
        import_data = raw
    else:
        raise ValueError("Invalid cache file format")

    with _cache_lock:
        if merge:
            cache = load_cache()
            for domain, entry in import_data.items():
                if domain in cache:
                    # Merge: combine blocked/passed sets, keep higher counts
                    existing = cache[domain]
                    existing_blocked = set(existing.get("blocked", []))
                    existing_passed = set(existing.get("passed", []))
                    new_blocked = set(entry.get("blocked", []))
                    new_passed = set(entry.get("passed", []))
                    existing["blocked"] = list(existing_blocked | new_blocked)
                    existing["passed"] = list(existing_passed | new_passed)
                    existing["total_scans"] = max(
                        existing.get("total_scans", 0),
                        entry.get("total_scans", 0))
                    # Keep newer timestamp
                    if entry.get("updated_at", "") > existing.get("updated_at", ""):
                        existing["updated_at"] = entry["updated_at"]
                    if entry.get("waf_vendor") and not existing.get("waf_vendor"):
                        existing["waf_vendor"] = entry["waf_vendor"]
                else:
                    cache[domain] = entry
        else:
            cache = import_data

        _save_cache(cache)

    return {
        "imported_domains": len(import_data),
        "merged": merge,
        "total_domains": len(cache),
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


# ── Historical trend tracking (#79) ───────────────────────────────────────────

_TREND_DIR = _FRAY_DIR / "trends"


def save_trend_snapshot(domain: str, scan_result: Dict) -> Dict:
    """Append a timestamped snapshot for trend tracking.

    Called after each recon scan to record key metrics over time.
    Snapshots are stored in ~/.fray/trends/<domain>.json as a JSON array.

    Args:
        domain: Target domain.
        scan_result: Full recon result dict.

    Returns:
        Dict with 'snapshots_total', 'path'.
    """
    domain = _extract_domain(domain)
    _TREND_DIR.mkdir(parents=True, exist_ok=True)
    trend_path = _TREND_DIR / f"{domain}.json"

    # Load existing snapshots
    snapshots = []
    if trend_path.exists():
        try:
            with open(trend_path, "r", encoding="utf-8") as f:
                snapshots = json.load(f)
        except (json.JSONDecodeError, OSError):
            snapshots = []

    # Extract key metrics from scan result
    dns = scan_result.get("dns", {})
    subs = scan_result.get("subdomains", {})
    tls = scan_result.get("tls", {})
    hygiene = scan_result.get("dns_hygiene", {})
    takeover = scan_result.get("subdomain_takeover", {})
    summary = scan_result.get("attack_surface_summary", {})

    snapshot = {
        "timestamp": _now_iso(),
        "subdomains_count": subs.get("count", 0) if isinstance(subs, dict) else 0,
        "dns_hygiene_score": hygiene.get("score", 0) if isinstance(hygiene, dict) else 0,
        "dns_hygiene_grade": hygiene.get("grade", "?") if isinstance(hygiene, dict) else "?",
        "takeover_count": takeover.get("count", 0) if isinstance(takeover, dict) else 0,
        "tls_grade": scan_result.get("tls_grade", "?"),
        "cert_days_remaining": tls.get("days_remaining") if isinstance(tls, dict) else None,
        "waf_vendor": scan_result.get("waf", {}).get("vendor", "") if isinstance(scan_result.get("waf"), dict) else "",
        "findings_count": len(summary.get("findings", [])) if isinstance(summary, dict) else 0,
        "risk_score": summary.get("risk_score", 0) if isinstance(summary, dict) else 0,
        "critical_findings": summary.get("critical", 0) if isinstance(summary, dict) else 0,
        "high_findings": summary.get("high", 0) if isinstance(summary, dict) else 0,
    }

    snapshots.append(snapshot)

    # Keep last 100 snapshots per domain
    if len(snapshots) > 100:
        snapshots = snapshots[-100:]

    with open(trend_path, "w", encoding="utf-8") as f:
        json.dump(snapshots, f, indent=2, ensure_ascii=False)

    return {"snapshots_total": len(snapshots), "path": str(trend_path)}


def get_trend(domain: str, limit: int = 20) -> Dict:
    """Get historical trend data for a domain.

    Returns:
        Dict with 'domain', 'snapshots', 'trend' (improving/stable/degrading).
    """
    domain = _extract_domain(domain)
    trend_path = _TREND_DIR / f"{domain}.json"

    if not trend_path.exists():
        return {"domain": domain, "snapshots": [], "trend": "unknown",
                "message": "No historical data yet"}

    try:
        with open(trend_path, "r", encoding="utf-8") as f:
            snapshots = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"domain": domain, "snapshots": [], "trend": "unknown"}

    recent = snapshots[-limit:]

    # Compute trend from risk scores
    trend = "stable"
    if len(recent) >= 2:
        first_half = recent[:len(recent) // 2]
        second_half = recent[len(recent) // 2:]
        avg_first = sum(s.get("risk_score", 0) for s in first_half) / len(first_half)
        avg_second = sum(s.get("risk_score", 0) for s in second_half) / len(second_half)
        delta = avg_second - avg_first
        if delta > 5:
            trend = "degrading"
        elif delta < -5:
            trend = "improving"

    return {
        "domain": domain,
        "snapshots": recent,
        "snapshot_count": len(snapshots),
        "trend": trend,
    }


def warm_cache_from_threat_intel(domain: str = "", waf_vendor: str = "",
                                  verbose: bool = False) -> Dict:
    """#46 — Pre-populate adaptive cache with threat intel payloads.

    Loads payloads from threat_intel.json files in the payload DB and
    ~/.fray/staged_payloads/, inserting them as 'passed' entries with
    low initial confidence (10).  Real scan results always override.

    Args:
        domain:     If set, tag entries for this domain.  Otherwise uses
                    a synthetic "__threat_intel__" domain key so payloads
                    are available via vendor-level cross-domain intelligence.
        waf_vendor: WAF vendor name to associate (enables cross-domain boost).
        verbose:    Print progress.

    Returns:
        Dict with 'payloads_loaded', 'categories', 'sources'.
    """
    import glob

    payloads_root = Path(__file__).parent.parent / "payloads"
    if not payloads_root.exists():
        from fray import PAYLOADS_DIR
        payloads_root = PAYLOADS_DIR

    staged_dir = _FRAY_DIR / "staged_payloads"

    # Collect all threat-intel payload strings
    collected: List[Dict] = []
    categories: set = set()
    sources: set = set()

    def _load_json(path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for entry in data.get("payloads", []):
                ps = entry.get("payload", "")
                if not ps or ps.startswith("#") or len(ps) < 5:
                    continue
                cat = entry.get("category", data.get("category", ""))
                src = entry.get("source", data.get("source", "threat_intel"))
                collected.append({"payload": ps, "category": cat, "source": src})
                if cat:
                    categories.add(cat)
                if src:
                    sources.add(src)
        except (json.JSONDecodeError, OSError):
            pass

    # 1. Load from payloads/**/threat_intel.json
    if payloads_root.exists():
        for ti_file in payloads_root.rglob("threat_intel.json"):
            _load_json(ti_file)

    # 2. Load from staged payloads
    if staged_dir.exists():
        for staged_file in staged_dir.glob("staged_*.json"):
            _load_json(staged_file)

    if not collected:
        return {"payloads_loaded": 0, "categories": [], "sources": []}

    # Insert into adaptive cache
    domain_key = _extract_domain(domain) if domain else "__threat_intel__"

    with _cache_lock:
        cache = load_cache()
        entry = _get_domain_entry(cache, domain_key)
        if waf_vendor:
            entry["waf_vendor"] = waf_vendor

        now = _now_iso()
        loaded = 0
        for item in collected:
            ph = _payload_hash(item["payload"])
            # Don't overwrite real test results (higher confidence)
            existing = entry["passed"].get(ph)
            if existing and existing.get("bypass_confidence", 0) > 10:
                continue
            # Don't warm payloads already confirmed blocked
            if ph in entry.get("blocked", {}):
                continue
            entry["passed"][ph] = {
                "payload": item["payload"][:500],
                "count": 0,
                "bypass_confidence": 10,  # low — real tests override
                "last_seen": now,
                "source": "threat_intel_warm",
            }
            loaded += 1

        entry["updated_at"] = now
        _save_cache(cache)

    if verbose:
        import sys
        sys.stderr.write(f"  Cache warmed: {loaded} threat-intel payloads"
                         f" ({len(categories)} categories)\n")

    return {
        "payloads_loaded": loaded,
        "categories": sorted(categories),
        "sources": sorted(sources),
    }


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
