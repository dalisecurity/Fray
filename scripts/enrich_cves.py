#!/usr/bin/env python3
"""Batch CVE PoC enrichment — processes all CVEs in Fray's payload database.

Usage:
    python scripts/enrich_cves.py                  # Process all, resume from cache
    python scripts/enrich_cves.py --force           # Re-process everything
    python scripts/enrich_cves.py --limit 10        # Process only 10 CVEs
    python scripts/enrich_cves.py --stats           # Show stats from cache

Saves results to ~/.fray/cve_poc_cache.json (resumable).
Rate-limits NVD API to ~5 requests per 30 seconds.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fray.cve_payload import generate_payloads_from_cve

CACHE_PATH = Path.home() / ".fray" / "cve_poc_cache.json"
NVD_DELAY = 2.0  # Reduced: GitHub searches add natural inter-request delays

def _print(*args, **kwargs):
    """Print with flush for real-time output."""
    print(*args, **kwargs, flush=True)


def discover_cves() -> list:
    """Find all unique CVEs referenced in Fray's payload files."""
    cves = set()
    project_root = Path(__file__).resolve().parent.parent

    for payloads_dir in [project_root / "payloads", project_root / "fray" / "payloads"]:
        if not payloads_dir.exists():
            continue
        for json_file in payloads_dir.rglob("*.json"):
            try:
                text = json_file.read_text(errors="ignore")
                found = re.findall(r"CVE-\d{4}-\d+", text)
                cves.update(found)
            except Exception:
                pass

    # Also check threat_intel.json
    ti_path = project_root / "threat_intel.json"
    if ti_path.exists():
        try:
            text = ti_path.read_text(errors="ignore")
            cves.update(re.findall(r"CVE-\d{4}-\d+", text))
        except Exception:
            pass

    return sorted(cves)


def load_cache() -> dict:
    """Load existing cache or return empty dict."""
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except Exception:
            pass
    return {}


def save_cache(cache: dict):
    """Save cache to disk."""
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2, ensure_ascii=False, default=str))


def print_stats(cache: dict):
    """Print summary statistics from cache."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    G = "\033[92m"
    Y = "\033[93m"
    C = "\033[96m"
    RED = "\033[91m"

    total = len(cache)
    with_poc = sum(1 for v in cache.values() if v.get("poc_count", 0) > 0)
    total_pocs = sum(v.get("poc_count", 0) for v in cache.values())
    total_sources = sum(v.get("source_count", 0) for v in cache.values())
    errors = sum(1 for v in cache.values() if v.get("error"))

    print(f"\n{D}{'━' * 64}{R}")
    print(f"  {B}CVE PoC Enrichment Cache{R}  {D}{CACHE_PATH}{R}")
    print(f"{D}{'━' * 64}{R}")
    print(f"  {B}Total CVEs cached:{R}    {C}{total}{R}")
    print(f"  {B}With PoC payloads:{R}    {G}{with_poc}{R}  ({with_poc*100//max(total,1)}%)")
    print(f"  {B}Total PoC payloads:{R}   {G}{total_pocs}{R}")
    print(f"  {B}Exploit sources:{R}      {total_sources}")
    print(f"  {B}Errors:{R}               {Y}{errors}{R}")

    # By vuln type
    types = {}
    for v in cache.values():
        for vt in v.get("vuln_types", []):
            t = vt.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
    if types:
        print(f"\n  {B}Vulnerability Types:{R}")
        for t, count in sorted(types.items(), key=lambda x: -x[1])[:15]:
            bar = "█" * min(count, 30)
            print(f"    {t:20s} {count:3d}  {D}{bar}{R}")

    # Top CVEs with most PoC payloads
    top_poc = sorted(
        [(k, v.get("poc_count", 0)) for k, v in cache.items()],
        key=lambda x: -x[1]
    )
    top_with = [(k, c) for k, c in top_poc if c > 0]
    if top_with:
        print(f"\n  {B}Top CVEs with PoC Payloads:{R}")
        for cve_id, count in top_with[:20]:
            entry = cache[cve_id]
            vtypes = ", ".join(vt["type"] for vt in entry.get("vuln_types", [])[:2])
            cvss = entry.get("cvss_score", 0)
            cvss_color = RED if cvss >= 9 else Y if cvss >= 7 else G
            sources = entry.get("source_count", 0)
            print(f"    {G}{count:2d} PoC{R}  {cvss_color}CVSS {cvss:4.1f}{R}  {C}{cve_id}{R}  {D}{vtypes}  ({sources} sources){R}")

    # CVEs without PoC (but with high CVSS)
    no_poc_high = sorted(
        [(k, v.get("cvss_score", 0)) for k, v in cache.items()
         if v.get("poc_count", 0) == 0 and v.get("cvss_score", 0) >= 7.0],
        key=lambda x: -x[1]
    )
    if no_poc_high:
        print(f"\n  {Y}High-CVSS CVEs without PoC ({len(no_poc_high)}):{R}")
        for cve_id, cvss in no_poc_high[:10]:
            vtypes = ", ".join(vt["type"] for vt in cache[cve_id].get("vuln_types", [])[:2])
            print(f"    {RED}CVSS {cvss:4.1f}{R}  {cve_id}  {D}{vtypes}{R}")

    print(f"\n{D}{'━' * 64}{R}\n")


def enrich_batch(cves: list, cache: dict, force: bool = False, limit: int = 0) -> dict:
    """Process CVEs with PoC extraction, respecting NVD rate limits."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    G = "\033[92m"
    Y = "\033[93m"
    C = "\033[96m"
    RED = "\033[91m"

    # Filter to real CVEs (skip synthetic 2026+)
    real_cves = [c for c in cves if not c.startswith("CVE-2026-")]

    # Filter already cached (unless force)
    if not force:
        todo = [c for c in real_cves if c not in cache]
    else:
        todo = real_cves

    if limit > 0:
        todo = todo[:limit]

    total = len(todo)
    skipped = len(real_cves) - total
    _print(f"\n{D}{'━' * 64}{R}")
    _print(f"  {B}CVE PoC Batch Enrichment{R}")
    _print(f"  {C}{total}{R} to process  {D}{skipped} cached/skipped  {len(cves) - len(real_cves)} synthetic{R}")
    _print(f"{D}{'━' * 64}{R}\n")

    new_poc = 0
    new_sources = 0
    errors = 0

    for i, cve_id in enumerate(todo, 1):
        elapsed_label = f"[{i}/{total}]"
        try:
            result = generate_payloads_from_cve(
                cve_id=cve_id,
                max_payloads=20,
                timeout=15,
                extract_poc=True,
            )

            poc_count = len(result.get("poc_payloads", []))
            source_count = len(result.get("poc_sources", []))
            vtypes = result.get("vuln_types", [])
            cvss = result.get("cvss_score", 0)

            # Store compact result in cache
            cache[cve_id] = {
                "cvss_score": cvss,
                "vuln_types": vtypes,
                "poc_count": poc_count,
                "source_count": source_count,
                "poc_sources": result.get("poc_sources", []),
                "poc_payloads": result.get("poc_payloads", []),
                "payloads": result.get("payloads", []),
                "affected_software": result.get("affected_software", []),
                "description": result.get("description", "")[:200],
                "parameters": result.get("parameters", {}),
                "error": result.get("error", ""),
                "enriched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

            # Status line
            cvss_color = RED if cvss >= 9 else Y if cvss >= 7 else G
            vtype_str = vtypes[0]["type"] if vtypes else "?"
            if poc_count > 0:
                new_poc += poc_count
                new_sources += source_count
                _print(f"  {G}●{R} {elapsed_label} {C}{cve_id}{R}  {cvss_color}CVSS {cvss:4.1f}{R}  {vtype_str:12s}  {G}{poc_count} PoC from {source_count} sources{R}")
            else:
                _print(f"  {D}○{R} {elapsed_label} {C}{cve_id}{R}  {cvss_color}CVSS {cvss:4.1f}{R}  {vtype_str:12s}  {D}no PoC ({source_count} refs checked){R}")

            if result.get("error"):
                errors += 1

        except Exception as e:
            errors += 1
            cache[cve_id] = {"error": str(e)[:200], "enriched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
            _print(f"  {RED}✗{R} {elapsed_label} {cve_id}  {RED}{str(e)[:60]}{R}")

        # Save cache every 5 CVEs (resume support)
        if i % 5 == 0:
            save_cache(cache)

        # Rate limit NVD API
        if i < total:
            time.sleep(NVD_DELAY)

    # Final save
    save_cache(cache)

    # Summary
    total_poc = sum(v.get("poc_count", 0) for v in cache.values())
    total_cached = len(cache)
    _print(f"\n{D}{'─' * 64}{R}")
    _print(f"  {B}Batch complete:{R} {total} processed, {new_poc} new PoC payloads, {errors} errors")
    _print(f"  {B}Cache total:{R} {total_cached} CVEs, {total_poc} PoC payloads")
    _print(f"  {B}Saved:{R} {CACHE_PATH}")
    _print(f"{D}{'━' * 64}{R}\n")

    return cache


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Batch CVE PoC enrichment")
    parser.add_argument("--force", action="store_true", help="Re-process all CVEs")
    parser.add_argument("--limit", type=int, default=0, help="Max CVEs to process")
    parser.add_argument("--stats", action="store_true", help="Show cache stats only")
    parser.add_argument("--cve", default="", help="Process a single CVE")
    args = parser.parse_args()

    cache = load_cache()

    if args.stats:
        print_stats(cache)
        return

    if args.cve:
        cves = [args.cve]
    else:
        cves = discover_cves()
        _print(f"  Discovered {len(cves)} CVEs in payload database")

    cache = enrich_batch(cves, cache, force=args.force, limit=args.limit)
    print_stats(cache)


if __name__ == "__main__":
    main()
