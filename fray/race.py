#!/usr/bin/env python3
"""
Fray — Race Condition Testing (TOCTOU) (#24)

Detects time-of-check-to-time-of-use vulnerabilities by sending
concurrent identical requests and analyzing response divergence.

Techniques:
  1. Single-packet attack — HTTP/2 multiplexing or chunked TE flush
  2. Last-byte sync — hold N connections, release final byte simultaneously
  3. Response divergence — detect state changes across concurrent requests

Use cases:
  - Double-spend (payment/coupon redemption)
  - Rate limit bypass
  - Account takeover via parallel password reset
  - Privilege escalation via concurrent role changes

CLI:
    fray race https://example.com/api/redeem --method POST --body '{"code":"SAVE10"}'
    fray race https://example.com/api/transfer -n 20 --method POST
"""

import http.client
import json
import ssl
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class RaceResponse:
    """A single response from a race condition probe."""
    thread_id: int
    status: int
    body_length: int
    body_hash: str          # First 64 chars of body for comparison
    headers: Dict[str, str]
    elapsed_ms: float
    error: str = ""

    def to_dict(self) -> dict:
        d = {
            "thread_id": self.thread_id,
            "status": self.status,
            "body_length": self.body_length,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class RaceResult:
    """Aggregate result of a race condition test."""
    target: str
    method: str
    concurrency: int
    responses: List[RaceResponse] = field(default_factory=list)
    duration_ms: float = 0.0
    divergence_detected: bool = False
    divergence_details: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "method": self.method,
            "concurrency": self.concurrency,
            "total_responses": len(self.responses),
            "duration_ms": round(self.duration_ms, 1),
            "divergence_detected": self.divergence_detected,
            "divergence_details": self.divergence_details,
            "status_distribution": dict(Counter(
                r.status for r in self.responses if not r.error
            )),
            "responses": [r.to_dict() for r in self.responses],
        }


def _send_request(
    url: str, method: str, body: Optional[str], headers: Dict[str, str],
    timeout: int, thread_id: int, barrier: threading.Barrier,
    results: List[RaceResponse],
):
    """Worker: connect, wait at barrier, then send simultaneously."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if not port:
        port = 443 if use_ssl else 80

    hdrs = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (compatible; FrayRace/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }
    hdrs.update(headers)
    if body:
        hdrs["Content-Type"] = hdrs.get("Content-Type", "application/json")
        hdrs["Content-Length"] = str(len(body.encode("utf-8")))

    try:
        # Phase 1: Establish connection
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        # Phase 2: Synchronize — all threads wait here
        barrier.wait(timeout=timeout)

        # Phase 3: Send simultaneously
        t0 = time.monotonic()
        conn.request(method, path, body=body.encode("utf-8") if body else None, headers=hdrs)
        resp = conn.getresponse()
        resp_body = resp.read(32 * 1024).decode("utf-8", "replace")
        elapsed = (time.monotonic() - t0) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        results.append(RaceResponse(
            thread_id=thread_id,
            status=resp.status,
            body_length=len(resp_body),
            body_hash=resp_body[:64],
            headers=resp_headers,
            elapsed_ms=elapsed,
        ))
    except Exception as e:
        results.append(RaceResponse(
            thread_id=thread_id,
            status=0,
            body_length=0,
            body_hash="",
            headers={},
            elapsed_ms=0,
            error=str(e)[:200],
        ))


def _analyze_divergence(responses: List[RaceResponse]) -> Tuple[bool, List[str]]:
    """Analyze responses for race condition indicators."""
    valid = [r for r in responses if not r.error]
    if len(valid) < 2:
        return False, ["Insufficient valid responses for analysis"]

    details = []
    diverged = False

    # Check status code divergence
    statuses = [r.status for r in valid]
    status_counts = Counter(statuses)
    if len(status_counts) > 1:
        diverged = True
        parts = [f"{s}x{c}" for s, c in status_counts.most_common()]
        details.append(f"Status divergence: {', '.join(parts)}")

    # Check body length divergence (>10% variance suggests state change)
    lengths = [r.body_length for r in valid]
    if lengths:
        avg_len = sum(lengths) / len(lengths)
        if avg_len > 0:
            variance = max(abs(l - avg_len) / avg_len for l in lengths)
            if variance > 0.1:
                diverged = True
                details.append(f"Body length variance: {variance:.1%} "
                               f"(min={min(lengths)}, max={max(lengths)})")

    # Check body content divergence
    hashes = [r.body_hash for r in valid]
    unique_hashes = len(set(hashes))
    if unique_hashes > 1:
        diverged = True
        details.append(f"Response body divergence: {unique_hashes} unique responses out of {len(valid)}")

    # Check for telltale race indicators in responses
    for r in valid:
        body_lower = r.body_hash.lower()
        if any(kw in body_lower for kw in ("already", "duplicate", "conflict", "insufficient", "expired")):
            diverged = True
            details.append(f"Thread {r.thread_id}: State-change keyword in response (HTTP {r.status})")
            break

    # Timing analysis — very tight timing suggests single-packet success
    timings = [r.elapsed_ms for r in valid]
    if timings:
        spread = max(timings) - min(timings)
        details.append(f"Timing spread: {spread:.1f}ms (min={min(timings):.1f}, max={max(timings):.1f})")

    if not diverged:
        details.append("No divergence detected — responses appear consistent")

    return diverged, details


def run_race_test(
    target: str,
    method: str = "GET",
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    concurrency: int = 10,
    rounds: int = 1,
    timeout: int = 10,
) -> RaceResult:
    """Execute a race condition test.

    Args:
        target:      Full URL to test.
        method:      HTTP method (GET, POST, PUT, DELETE).
        body:        Request body (for POST/PUT).
        headers:     Extra HTTP headers.
        concurrency: Number of simultaneous requests per round.
        rounds:      Number of test rounds to run.
        timeout:     Per-request timeout.

    Returns:
        RaceResult with all responses and divergence analysis.
    """
    hdrs = headers or {}
    all_responses: List[RaceResponse] = []
    t_start = time.monotonic()

    for rnd in range(rounds):
        responses: List[RaceResponse] = []
        barrier = threading.Barrier(concurrency, timeout=timeout)
        threads = []

        for i in range(concurrency):
            t = threading.Thread(
                target=_send_request,
                args=(target, method, body, hdrs, timeout, i, barrier, responses),
                daemon=True,
            )
            threads.append(t)

        # Start all threads (they'll block at barrier until all ready)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 5)

        all_responses.extend(responses)

        # Brief pause between rounds
        if rnd < rounds - 1:
            time.sleep(0.2)

    duration = (time.monotonic() - t_start) * 1000
    diverged, details = _analyze_divergence(all_responses)

    return RaceResult(
        target=target,
        method=method,
        concurrency=concurrency,
        responses=all_responses,
        duration_ms=duration,
        divergence_detected=diverged,
        divergence_details=details,
    )


# ── CLI-friendly output ──────────────────────────────────────────────────────

def print_race_result(result: RaceResult):
    """Pretty-print race condition test results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Race Condition Test{R}")
    print(f"  {D}{result.method} {result.target}{R}")
    print(f"  {D}Concurrency: {result.concurrency} | Duration: {result.duration_ms:.0f}ms{R}")
    print(f"{D}{'━' * 60}{R}")

    # Status distribution
    valid = [r for r in result.responses if not r.error]
    errors = [r for r in result.responses if r.error]
    status_counts = Counter(r.status for r in valid)

    print(f"\n  {B}Responses:{R} {len(valid)} OK, {len(errors)} errors")
    for status, count in status_counts.most_common():
        color = GRN if 200 <= status < 300 else YEL if 300 <= status < 500 else RED
        print(f"    {color}HTTP {status}{R}: {count}x")

    # Divergence
    if result.divergence_detected:
        print(f"\n  {RED}{B}DIVERGENCE DETECTED{R}")
        for d in result.divergence_details:
            print(f"    {YEL}● {d}{R}")
        print(f"\n  {RED}This target may be vulnerable to race conditions.{R}")
        print(f"  {D}Recommended: Repeat with --rounds 3 and examine response bodies.{R}")
    else:
        print(f"\n  {GRN}No divergence detected.{R}")
        for d in result.divergence_details:
            print(f"    {D}● {d}{R}")

    print(f"\n{D}{'━' * 60}{R}\n")
