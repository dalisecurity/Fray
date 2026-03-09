"""
Tests for fray.adaptive_cache — per-domain payload intelligence.

All tests are fully offline (no real HTTP, no D1 calls).
Cache writes are redirected to a tmp directory via monkeypatch.
"""
import json
import threading
from pathlib import Path

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Redirect all cache I/O to a temp directory so tests are isolated."""
    import fray.adaptive_cache as ac
    monkeypatch.setattr(ac, "_FRAY_DIR", tmp_path)
    monkeypatch.setattr(ac, "_CACHE_PATH", tmp_path / "domain_cache.json")
    yield tmp_path


# ── _extract_domain ───────────────────────────────────────────────────────────

class TestExtractDomain:
    def test_full_url(self):
        from fray.adaptive_cache import _extract_domain
        assert _extract_domain("https://cloudflare.com/foo?bar=1") == "cloudflare.com"

    def test_strips_www(self):
        from fray.adaptive_cache import _extract_domain
        assert _extract_domain("https://www.cloudflare.com") == "cloudflare.com"

    def test_bare_hostname(self):
        from fray.adaptive_cache import _extract_domain
        assert _extract_domain("cloudflare.com") == "cloudflare.com"

    def test_subdomain_kept(self):
        from fray.adaptive_cache import _extract_domain
        assert _extract_domain("https://api.example.com/v1") == "api.example.com"


# ── save_scan_results ─────────────────────────────────────────────────────────

class TestSaveResults:
    def _make_results(self, payloads_blocked):
        """Helper: list of result dicts given [(payload, blocked), ...]."""
        return [
            {"payload": p, "blocked": b, "bypass_confidence": 0 if b else 80}
            for p, b in payloads_blocked
        ]

    def test_saves_blocked_payload(self):
        from fray.adaptive_cache import save_scan_results, load_cache
        results = self._make_results([("<script>alert(1)</script>", True)])
        save_scan_results(results, domain="cloudflare.com", share_async=False)
        cache = load_cache()
        entry = cache["cloudflare.com"]
        assert len(entry["blocked"]) == 1
        assert len(entry["passed"]) == 0
        assert entry["total_scans"] == 1

    def test_saves_passed_payload(self):
        from fray.adaptive_cache import save_scan_results, load_cache
        results = self._make_results([("<img src=x onerror=alert(1)>", False)])
        save_scan_results(results, domain="example.com", share_async=False)
        cache = load_cache()
        entry = cache["example.com"]
        assert len(entry["passed"]) == 1
        assert entry["passed"][list(entry["passed"].keys())[0]]["bypass_confidence"] == 80

    def test_waf_vendor_stored(self):
        from fray.adaptive_cache import save_scan_results, load_cache
        save_scan_results(
            self._make_results([("x", True)]),
            domain="cloudflare.com",
            waf_vendor="Cloudflare",
            share_async=False,
        )
        cache = load_cache()
        assert cache["cloudflare.com"]["waf_vendor"] == "Cloudflare"

    def test_blocked_count_accumulates(self):
        from fray.adaptive_cache import save_scan_results, load_cache, _payload_hash
        payload = "<script>alert(1)</script>"
        for _ in range(3):
            save_scan_results(
                [{"payload": payload, "blocked": True, "bypass_confidence": 0}],
                domain="cloudflare.com", share_async=False,
            )
        cache = load_cache()
        ph = _payload_hash(payload)
        assert cache["cloudflare.com"]["blocked"][ph]["count"] == 3

    def test_passed_moves_out_of_blocked(self):
        """A payload that was never blocked and then passes should be in passed."""
        from fray.adaptive_cache import save_scan_results, load_cache, _payload_hash
        payload = "<svg/onload=alert(1)>"
        ph = _payload_hash(payload)
        # First scan: passes immediately (never blocked)
        save_scan_results(
            [{"payload": payload, "blocked": False, "bypass_confidence": 75}],
            domain="target.com", share_async=False,
        )
        cache = load_cache()
        entry = cache["target.com"]
        assert ph not in entry["blocked"]
        assert ph in entry["passed"]

    def test_confidently_blocked_not_promoted(self):
        """A payload blocked >= BLOCK_THRESHOLD times stays in blocked even if it passes."""
        from fray.adaptive_cache import save_scan_results, load_cache, _payload_hash, BLOCK_THRESHOLD
        payload = "<script>bad()</script>"
        ph = _payload_hash(payload)
        # Block BLOCK_THRESHOLD times
        for _ in range(BLOCK_THRESHOLD):
            save_scan_results(
                [{"payload": payload, "blocked": True}],
                domain="site.com", share_async=False,
            )
        # Now attempt a pass — should be ignored
        save_scan_results(
            [{"payload": payload, "blocked": False, "bypass_confidence": 99}],
            domain="site.com", share_async=False,
        )
        cache = load_cache()
        entry = cache["site.com"]
        assert ph in entry["blocked"]
        assert ph not in entry["passed"]

    def test_empty_results_noop(self):
        from fray.adaptive_cache import save_scan_results, load_cache
        save_scan_results([], domain="x.com", share_async=False)
        assert load_cache() == {}

    def test_thread_safe_concurrent_writes(self):
        """Multiple threads writing simultaneously must not corrupt the cache."""
        from fray.adaptive_cache import save_scan_results, load_cache
        errors = []

        def _write(i):
            try:
                save_scan_results(
                    [{"payload": f"payload_{i}", "blocked": i % 2 == 0}],
                    domain="concurrent.com", share_async=False,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        cache = load_cache()
        assert "concurrent.com" in cache
        entry = cache["concurrent.com"]
        total = len(entry["blocked"]) + len(entry["passed"])
        assert total > 0


# ── smart_sort_payloads ───────────────────────────────────────────────────────

class TestSmartSort:
    def _payloads(self, names):
        return [{"payload": n, "category": "xss"} for n in names]

    def test_returns_unchanged_on_no_cache(self):
        from fray.adaptive_cache import smart_sort_payloads
        payloads = self._payloads(["a", "b", "c"])
        result = smart_sort_payloads(payloads, domain="new.com")
        assert [p["payload"] for p in result] == ["a", "b", "c"]

    def test_proven_bypasses_go_first(self):
        from fray.adaptive_cache import save_scan_results, smart_sort_payloads
        # Record "bypass_payload" as passing with high confidence
        save_scan_results(
            [{"payload": "bypass_payload", "blocked": False, "bypass_confidence": 90}],
            domain="waf.com", share_async=False,
        )
        payloads = self._payloads(["unknown_1", "unknown_2", "bypass_payload"])
        result = smart_sort_payloads(payloads, domain="waf.com", top_n=10)
        assert result[0]["payload"] == "bypass_payload"

    def test_blocked_payloads_go_last(self):
        from fray.adaptive_cache import save_scan_results, smart_sort_payloads, BLOCK_THRESHOLD
        blocked_payload = "bad_payload"
        for _ in range(BLOCK_THRESHOLD):
            save_scan_results(
                [{"payload": blocked_payload, "blocked": True}],
                domain="waf.com", share_async=False,
            )
        payloads = self._payloads(["unknown_1", blocked_payload, "unknown_2"])
        result = smart_sort_payloads(payloads, domain="waf.com")
        assert result[-1]["payload"] == blocked_payload

    def test_bypasses_sorted_by_confidence(self):
        from fray.adaptive_cache import save_scan_results, smart_sort_payloads
        save_scan_results(
            [
                {"payload": "low_conf", "blocked": False, "bypass_confidence": 40},
                {"payload": "high_conf", "blocked": False, "bypass_confidence": 95},
                {"payload": "mid_conf", "blocked": False, "bypass_confidence": 70},
            ],
            domain="site.com", share_async=False,
        )
        payloads = self._payloads(["low_conf", "high_conf", "mid_conf"])
        result = smart_sort_payloads(payloads, domain="site.com", top_n=10)
        assert result[0]["payload"] == "high_conf"
        assert result[1]["payload"] == "mid_conf"
        assert result[2]["payload"] == "low_conf"

    def test_empty_payloads_returned_unchanged(self):
        from fray.adaptive_cache import smart_sort_payloads
        assert smart_sort_payloads([], domain="x.com") == []

    def test_no_domain_returned_unchanged(self):
        from fray.adaptive_cache import smart_sort_payloads
        payloads = self._payloads(["a", "b"])
        result = smart_sort_payloads(payloads, domain="")
        assert result == payloads


# ── get_domain_stats ──────────────────────────────────────────────────────────

class TestGetDomainStats:
    def test_returns_none_for_unknown_domain(self):
        from fray.adaptive_cache import get_domain_stats
        assert get_domain_stats("unknown.com") is None

    def test_returns_stats_after_scan(self):
        from fray.adaptive_cache import save_scan_results, get_domain_stats
        save_scan_results(
            [
                {"payload": "p1", "blocked": True},
                {"payload": "p2", "blocked": False, "bypass_confidence": 80},
            ],
            domain="stats.com", share_async=False,
        )
        stats = get_domain_stats("stats.com")
        assert stats is not None
        assert stats["blocked_payloads"] == 1
        assert stats["passed_payloads"] == 1
        assert stats["total_scans"] == 1
        assert len(stats["top_bypasses"]) == 1
        assert stats["top_bypasses"][0]["bypass_confidence"] == 80


# ── clear_domain_cache ────────────────────────────────────────────────────────

class TestClearCache:
    def test_clear_specific_domain(self):
        from fray.adaptive_cache import save_scan_results, clear_domain_cache, load_cache
        save_scan_results([{"payload": "x", "blocked": True}],
                          domain="a.com", share_async=False)
        save_scan_results([{"payload": "x", "blocked": True}],
                          domain="b.com", share_async=False)
        removed = clear_domain_cache("a.com")
        assert removed == 1
        cache = load_cache()
        assert "a.com" not in cache
        assert "b.com" in cache

    def test_clear_all(self):
        from fray.adaptive_cache import save_scan_results, clear_domain_cache, load_cache
        for d in ["x.com", "y.com", "z.com"]:
            save_scan_results([{"payload": "p", "blocked": True}],
                              domain=d, share_async=False)
        removed = clear_domain_cache("")
        assert removed == 3
        assert load_cache() == {}

    def test_clear_nonexistent_returns_zero(self):
        from fray.adaptive_cache import clear_domain_cache
        assert clear_domain_cache("noexist.com") == 0
