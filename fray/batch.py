#!/usr/bin/env python3
"""
Fray — Batch Recon for Domain Lists (#70)

Run parallel recon across a list of domains (e.g., Nikkei 225,
Fortune 500, custom target lists). Outputs JSONL for aggregation.

Features:
  - Resume support — skips already-scanned domains
  - Parallel workers (configurable)
  - JSONL streaming output
  - Aggregate summary statistics
  - Compatible with `fray ask` for querying results

CLI:
    fray batch domains.txt
    fray batch domains.txt -w 4 -o results.jsonl
    fray batch domains.txt --profile quick --resume
    fray batch --nikkei225
"""

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"

_FRAY_DIR = Path.home() / ".fray"

# Built-in Nikkei 225 domains (top companies by market cap)
_NIKKEI225_SAMPLE = [
    "toyota.co.jp", "sony.co.jp", "keyence.co.jp", "ntt.co.jp",
    "softbank.jp", "recruit.co.jp", "kddi.com", "mitsubishielectric.co.jp",
    "hitachi.co.jp", "shin-etsu.co.jp", "daikin.co.jp", "hoya.co.jp",
    "murata.com", "smc.co.jp", "fanuc.co.jp", "tokio-marine.co.jp",
    "fast-retailing.co.jp", "nintendo.co.jp", "takeda.com", "honda.co.jp",
    "denso.com", "fujitsu.com", "panasonic.com", "canon.co.jp",
    "bridgestone.co.jp", "7andi.com", "astellas.com", "terumo.co.jp",
    "nec.com", "tdk.co.jp", "olympus.co.jp", "suzuki.co.jp",
    "renesas.com", "itochu.co.jp", "sumitomo.co.jp", "mitsui.com",
    "mitsubishi.com", "jcb.co.jp", "daiichi-sankyo.co.jp", "ajinomoto.co.jp",
]


def _load_done(output_path: str) -> Set[str]:
    """Load already-scanned domains from JSONL output."""
    done = set()
    p = Path(output_path)
    if not p.exists():
        return done
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            for key in ("target", "host", "domain"):
                val = d.get(key, "")
                if val:
                    done.add(val)
                    bare = val.replace("https://", "").replace("http://", "").rstrip("/")
                    done.add(bare)
        except json.JSONDecodeError:
            continue
    return done


def _scan_single(domain: str, profile: str = "quick",
                 timeout: int = 120) -> Optional[Dict]:
    """Run fray recon on a single domain, return JSON result."""
    target = domain if domain.startswith("http") else f"https://{domain}"
    cmd = [sys.executable, "-m", "fray", "recon", target, "--json"]
    if profile == "quick":
        cmd.append("--fast")
    elif profile == "deep":
        cmd.append("--deep")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        stdout = proc.stdout.strip()
        if not stdout:
            return None

        # Find first { to skip any banner output
        idx = stdout.find("{")
        if idx < 0:
            return None
        data = json.loads(stdout[idx:])
        if not isinstance(data, dict):
            return None

        # Ensure domain is tagged
        data.setdefault("domain", domain)
        data.setdefault("host", domain)
        return data
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        return {"domain": domain, "error": str(e)[:200]}


def run_batch(
    domains: List[str],
    output: str = "",
    workers: int = 4,
    profile: str = "quick",
    timeout: int = 120,
    resume: bool = True,
) -> Dict:
    """Run batch recon across a list of domains.

    Args:
        domains:  List of domain names.
        output:   JSONL output file path.
        workers:  Number of parallel workers.
        profile:  Scan profile (quick, standard, deep).
        timeout:  Per-domain timeout.
        resume:   Skip already-scanned domains.

    Returns:
        Summary dict with stats.
    """
    if not output:
        output = str(_FRAY_DIR / "batch_results.jsonl")

    # Resume support
    done = _load_done(output) if resume else set()
    pending = [d for d in domains if d not in done
               and d.replace("https://", "").replace("http://", "").rstrip("/") not in done]

    total = len(domains)
    skipped = total - len(pending)
    completed = 0
    errors = 0
    t0 = time.time()

    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    RED = "\033[91m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Fray Batch Recon{R}")
    print(f"  {D}Domains: {total} total, {len(pending)} pending, {skipped} skipped (resume){R}")
    print(f"  {D}Workers: {workers} | Profile: {profile} | Timeout: {timeout}s{R}")
    print(f"{D}{'━' * 60}{R}\n")

    if not pending:
        print(f"  {GRN}All domains already scanned. Use --no-resume to rescan.{R}\n")
        return {"total": total, "scanned": 0, "skipped": skipped,
                "errors": 0, "output": output}

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_single, d, profile, timeout): d
            for d in pending
        }

        with open(output, "a", encoding="utf-8") as f:
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    if result:
                        line = json.dumps(result, ensure_ascii=False)
                        f.write(line + "\n")
                        f.flush()
                        completed += 1
                        has_error = "error" in result
                        if has_error:
                            errors += 1
                            print(f"  {RED}✗{R} {domain}: {result.get('error', '')[:60]}")
                        else:
                            waf = result.get("attack_surface", result.get("waf_detected", {}))
                            vendor = ""
                            if isinstance(waf, dict):
                                vendor = waf.get("waf_vendor", waf.get("vendor", ""))
                            risk = ""
                            if isinstance(result.get("attack_surface"), dict):
                                risk = result["attack_surface"].get("risk_level", "")
                            print(f"  {GRN}✓{R} {domain}"
                                  f"{f' — WAF: {vendor}' if vendor else ''}"
                                  f"{f' — Risk: {risk}' if risk else ''}")
                    else:
                        errors += 1
                        print(f"  {YEL}?{R} {domain}: no response")
                except Exception as e:
                    errors += 1
                    print(f"  {RED}✗{R} {domain}: {str(e)[:60]}")

    duration = time.time() - t0
    summary = {
        "total": total,
        "scanned": completed,
        "skipped": skipped,
        "errors": errors,
        "duration_s": round(duration, 1),
        "output": output,
    }

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Summary:{R} {completed} scanned, {errors} errors, {skipped} skipped")
    print(f"  {D}Duration: {duration:.0f}s | Output: {output}{R}")
    print(f"{D}{'━' * 60}{R}\n")

    return summary


def load_domains_file(path: str) -> List[str]:
    """Load domains from a text file (one per line, skip comments)."""
    domains = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # Handle CSV format (domain might be in first column)
            if "," in line:
                line = line.split(",")[0].strip()
            domains.append(line)
    return domains
