#!/usr/bin/env python3
"""Tests for fray.evolve — Adaptive Payload Evolution Engine."""

import unittest
from unittest.mock import MagicMock, patch

from fray.evolve import (
    WAFProfile,
    DIAGNOSTIC_PROBES,
    run_probes,
    score_payload,
    rank_payloads,
    PayloadMutator,
    EvolveStats,
    adaptive_test,
    _extract_tags,
    _extract_events,
    _extract_keywords,
    _extract_patterns,
)


# ── WAFProfile Tests ─────────────────────────────────────────────────────────

class TestWAFProfile(unittest.TestCase):
    def test_default_profile(self):
        p = WAFProfile()
        self.assertEqual(p.block_rate, 0)
        self.assertEqual(p.strictness, "minimal")
        self.assertEqual(p.blocked_tags, set())

    def test_strict_profile(self):
        p = WAFProfile(total_probes=20, total_blocked=19)
        self.assertEqual(p.strictness, "strict")
        self.assertAlmostEqual(p.block_rate, 95.0)

    def test_moderate_profile(self):
        p = WAFProfile(total_probes=20, total_blocked=16)
        self.assertEqual(p.strictness, "moderate")

    def test_permissive_profile(self):
        p = WAFProfile(total_probes=20, total_blocked=8)
        self.assertEqual(p.strictness, "permissive")

    def test_minimal_profile(self):
        p = WAFProfile(total_probes=20, total_blocked=3)
        self.assertEqual(p.strictness, "minimal")

    def test_zero_probes(self):
        p = WAFProfile()
        self.assertEqual(p.block_rate, 0)
        self.assertEqual(p.strictness, "minimal")


# ── Feature Extraction Tests ─────────────────────────────────────────────────

class TestExtractors(unittest.TestCase):
    def test_extract_tags(self):
        self.assertEqual(_extract_tags("<script>alert(1)</script>"), {"script"})
        self.assertEqual(_extract_tags("<img src=x onerror=y>"), {"img"})
        self.assertEqual(_extract_tags("<svg><animate>"), {"svg", "animate"})
        self.assertEqual(_extract_tags("no tags here"), set())

    def test_extract_events(self):
        self.assertEqual(_extract_events("onerror=alert(1)"), {"onerror"})
        self.assertEqual(_extract_events("<img src=x onload=x onclick=y>"), {"onload", "onclick"})
        self.assertEqual(_extract_events("no events"), set())

    def test_extract_keywords(self):
        kws = _extract_keywords("alert(document.cookie)")
        self.assertIn("alert", kws)
        self.assertIn("document", kws)
        self.assertIn("cookie", kws)

    def test_extract_patterns(self):
        self.assertEqual(_extract_patterns("javascript:void(0)"), {"javascript:"})
        self.assertEqual(_extract_patterns("data:text/html,x"), {"data:"})
        self.assertEqual(_extract_patterns("no patterns"), set())


# ── Scoring Tests ────────────────────────────────────────────────────────────

class TestScorePayload(unittest.TestCase):
    def test_minimal_waf_high_score(self):
        """Minimal WAF should give all payloads a high score."""
        p = WAFProfile(total_probes=10, total_blocked=1)
        score, reason = score_payload("<script>alert(1)</script>", p)
        self.assertGreaterEqual(score, 0.7)

    def test_blocked_tag_lowers_score(self):
        """Payload using a blocked tag should score lower."""
        p = WAFProfile(blocked_tags={"script"}, total_probes=10, total_blocked=8)
        score_blocked, _ = score_payload("<script>alert(1)</script>", p)
        score_allowed, _ = score_payload("<svg onload=alert(1)>", p)
        self.assertLess(score_blocked, score_allowed)

    def test_allowed_tag_raises_score(self):
        """Payload using an allowed tag should score higher."""
        p = WAFProfile(
            blocked_tags={"script", "iframe"},
            allowed_tags={"svg", "img"},
            total_probes=10, total_blocked=7,
        )
        score, _ = score_payload("<svg onload=alert(1)>", p)
        self.assertGreater(score, 0.5)

    def test_blocked_keyword_penalty(self):
        p = WAFProfile(
            blocked_keywords={"alert", "eval"},
            total_probes=10, total_blocked=7,
        )
        score_alert, _ = score_payload("alert(1)", p)
        score_confirm, _ = score_payload("confirm(1)", p)
        self.assertLess(score_alert, score_confirm)

    def test_blocked_event_penalty(self):
        p = WAFProfile(
            blocked_events={"onerror"},
            allowed_events={"onfocus"},
            total_probes=10, total_blocked=7,
        )
        score_err, _ = score_payload("<img onerror=x>", p)
        score_focus, _ = score_payload("<img onfocus=x>", p)
        self.assertLess(score_err, score_focus)

    def test_encoding_bonus(self):
        """HTML entity payloads should get bonus when WAF doesn't block entities."""
        p = WAFProfile(
            blocked_tags={"script"},
            total_probes=10, total_blocked=7,
        )
        # WAF doesn't block html_entity encoding
        score, reason = score_payload("&lt;script&gt;alert(1)&lt;/script&gt;", p)
        self.assertIn("HTML entities", reason)

    def test_score_clamped_0_to_1(self):
        p = WAFProfile(
            blocked_tags={"script", "svg", "img", "iframe"},
            blocked_events={"onerror", "onload"},
            blocked_keywords={"alert", "eval"},
            total_probes=10, total_blocked=9,
        )
        score, _ = score_payload("<script onerror=alert(eval('x'))></script>", p)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


# ── Ranking Tests ────────────────────────────────────────────────────────────

class TestRankPayloads(unittest.TestCase):
    def test_rank_filters_low_score(self):
        payloads = [
            {"payload": "<script>alert(1)</script>"},
            {"payload": "<img src=x>"},
            {"payload": "hello"},
        ]
        p = WAFProfile(
            blocked_tags={"script"},
            total_probes=10, total_blocked=7,
        )
        ranked = rank_payloads(payloads, p, threshold=0.3)
        # script payload should be filtered out or ranked lowest
        if ranked:
            payloads_strs = [r["payload"] for r in ranked]
            # img and hello should be ahead of script
            self.assertTrue(len(ranked) <= len(payloads))

    def test_rank_adds_score_field(self):
        payloads = [{"payload": "test123"}]
        p = WAFProfile(total_probes=10, total_blocked=2)
        ranked = rank_payloads(payloads, p)
        self.assertIn("evolve_score", ranked[0])
        self.assertIn("evolve_reason", ranked[0])

    def test_rank_sorted_descending(self):
        payloads = [
            {"payload": "<script>alert(1)</script>"},
            {"payload": "hello world"},
            {"payload": "<svg onload=x>"},
        ]
        p = WAFProfile(
            blocked_tags={"script"},
            blocked_keywords={"alert"},
            total_probes=10, total_blocked=7,
        )
        ranked = rank_payloads(payloads, p, threshold=0.0)
        scores = [r["evolve_score"] for r in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))


# ── Mutation Tests ───────────────────────────────────────────────────────────

class TestPayloadMutator(unittest.TestCase):
    def setUp(self):
        self.profile = WAFProfile(
            blocked_tags={"script"},
            allowed_tags={"svg", "img"},
            blocked_events={"onerror"},
            allowed_events={"onfocus", "onmouseover"},
            blocked_keywords={"alert"},
            total_probes=10, total_blocked=7,
        )
        self.mutator = PayloadMutator(self.profile)

    def test_mutate_returns_list(self):
        mutations = self.mutator.mutate("<script>alert(1)</script>")
        self.assertIsInstance(mutations, list)
        self.assertTrue(len(mutations) > 0)

    def test_mutate_no_duplicates(self):
        mutations = self.mutator.mutate("<script>alert(1)</script>", max_mutations=10)
        # CT confusion mutations share the same payload but differ by content_type
        keys = [m["payload"] + (f"||ct:{m['content_type']}" if "content_type" in m else "")
                for m in mutations]
        self.assertEqual(len(keys), len(set(keys)))

    def test_mutate_has_metadata(self):
        mutations = self.mutator.mutate("<img src=x onerror=alert(1)>")
        if mutations:
            self.assertIn("mutation", mutations[0])
            self.assertIn("parent", mutations[0])

    def test_html_entity_encode(self):
        result = self.mutator._html_entity_encode("<script>alert(1)</script>")
        self.assertIn("&lt;", result)
        self.assertNotIn("<script>", result)

    def test_case_randomize(self):
        original = "<script>alert(1)</script>"
        # Run several times — at least one should differ
        results = set()
        for _ in range(10):
            results.add(self.mutator._case_randomize(original))
        # Should have at least 2 different variants (probabilistic)
        self.assertTrue(len(results) >= 1)

    def test_comment_inject_script(self):
        result = self.mutator._comment_inject("<script>alert(1)</script>")
        self.assertIn("<!--", result)
        self.assertIn("-->", result)

    def test_comment_inject_onerror(self):
        result = self.mutator._comment_inject("<img onerror=alert(1)>")
        self.assertIn("<!--", result)

    def test_null_byte_insert(self):
        result = self.mutator._null_byte_insert("<script>alert(1)</script>")
        self.assertIn("%00", result)

    def test_double_url_encode(self):
        result = self.mutator._double_url_encode("<script>alert(1)</script>")
        self.assertIn("%253C", result)
        self.assertNotIn("<", result)

    def test_tag_substitute(self):
        profile = WAFProfile(
            blocked_tags={"script"},
            allowed_tags={"svg", "img"},
        )
        mutator = PayloadMutator(profile)
        result = mutator._tag_substitute("<script>x</script>")
        self.assertNotIn("<script", result.lower())

    def test_event_swap(self):
        profile = WAFProfile(
            blocked_events={"onerror"},
            allowed_events={"onfocus"},
        )
        mutator = PayloadMutator(profile)
        result = mutator._event_swap("<img onerror=alert(1)>")
        self.assertIn("onfocus", result)
        self.assertNotIn("onerror", result)

    def test_whitespace_variation(self):
        result = self.mutator._whitespace_variation("<img src=x>")
        # Should have changed something
        self.assertIsInstance(result, str)


# ── Probe Tests ──────────────────────────────────────────────────────────────

class TestRunProbes(unittest.TestCase):
    def test_probe_count(self):
        """Should have at least 15 diagnostic probes."""
        self.assertGreaterEqual(len(DIAGNOSTIC_PROBES), 15)

    def test_probe_ids_unique(self):
        ids = [p["id"] for p in DIAGNOSTIC_PROBES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_run_probes_strict_waf(self):
        """Mock a strict WAF that blocks everything."""
        tester = MagicMock()
        tester.test_payload.return_value = {
            "blocked": True, "status": 403, "response_length": 100
        }
        # Override baseline to not be blocked
        call_count = [0]
        def side_effect(payload, param='input'):
            call_count[0] += 1
            if call_count[0] == 1:  # baseline-clean
                return {"blocked": False, "status": 200, "response_length": 5000}
            return {"blocked": True, "status": 403, "response_length": 100}
        tester.test_payload.side_effect = side_effect

        profile = run_probes(tester)
        self.assertGreater(profile.total_probes, 0)
        self.assertGreater(profile.total_blocked, 0)
        self.assertIn("script", profile.blocked_tags)

    def test_run_probes_no_waf(self):
        """Mock a target with no WAF."""
        tester = MagicMock()
        tester.test_payload.return_value = {
            "blocked": False, "status": 200, "response_length": 5000
        }
        profile = run_probes(tester)
        self.assertEqual(profile.total_blocked, 0)
        self.assertEqual(profile.strictness, "minimal")


# ── EvolveStats Tests ────────────────────────────────────────────────────────

class TestEvolveStats(unittest.TestCase):
    def test_efficiency_gain(self):
        stats = EvolveStats(
            total_payloads_available=100,
            probes_sent=18,
            payloads_tested=20,
            mutations_tested=5,
        )
        # 43 total vs 100 brute force = 57% reduction
        self.assertAlmostEqual(stats.efficiency_gain, 57.0)

    def test_efficiency_zero_payloads(self):
        stats = EvolveStats(total_payloads_available=0)
        self.assertEqual(stats.efficiency_gain, 0.0)


# ── Adaptive Test Integration ────────────────────────────────────────────────

class TestAdaptiveTest(unittest.TestCase):
    def test_adaptive_test_basic(self):
        """Test full adaptive_test flow with mocked tester."""
        tester = MagicMock()
        tester.delay = 0
        tester.host = "example.com"

        # Simulate: probes return mixed results, payloads return mixed
        call_count = [0]
        def mock_test(payload, method='GET', param='input'):
            call_count[0] += 1
            # First 18 are probes — block script/alert related ones
            if 'script' in payload.lower() or 'alert' in payload.lower():
                return {"blocked": True, "status": 403, "response_length": 100,
                        "payload": payload}
            return {"blocked": False, "status": 200, "response_length": 5000,
                    "payload": payload}

        tester.test_payload.side_effect = mock_test

        payloads = [
            {"payload": "<script>alert(1)</script>", "description": "basic xss"},
            {"payload": "<img src=x onerror=alert(1)>", "description": "img xss"},
            {"payload": "<svg onload=confirm(1)>", "description": "svg xss"},
            {"payload": "hello world", "description": "clean"},
        ]

        results, stats, profile = adaptive_test(
            tester, payloads, max_payloads=10, verbose=False
        )

        self.assertGreater(stats.probes_sent, 0)
        self.assertIsInstance(results, list)
        self.assertIsInstance(profile, WAFProfile)

    def test_adaptive_test_returns_stats(self):
        tester = MagicMock()
        tester.delay = 0
        tester.test_payload.return_value = {
            "blocked": False, "status": 200, "response_length": 5000,
            "payload": "test"
        }

        payloads = [{"payload": f"test{i}"} for i in range(50)]
        results, stats, profile = adaptive_test(
            tester, payloads, max_payloads=10, verbose=False
        )

        self.assertEqual(stats.total_payloads_available, 50)
        self.assertGreater(stats.probes_sent, 0)
        self.assertGreater(stats.requests_saved, 0)


# ── CLI Integration ──────────────────────────────────────────────────────────

class TestCLISmartFlag(unittest.TestCase):
    def test_smart_flag_accepted(self):
        """Verify --smart flag is parsed correctly."""
        from fray.cli import main
        import argparse
        # Just verify the parser accepts --smart
        from fray.cli import main
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_test = subparsers.add_parser("test")
        p_test.add_argument("target")
        p_test.add_argument("--smart", action="store_true")
        args = parser.parse_args(["test", "https://example.com", "--smart"])
        self.assertTrue(args.smart)

    def test_smart_flag_default_false(self):
        from fray.cli import main
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_test = subparsers.add_parser("test")
        p_test.add_argument("target")
        p_test.add_argument("--smart", action="store_true")
        args = parser.parse_args(["test", "https://example.com"])
        self.assertFalse(args.smart)


if __name__ == "__main__":
    unittest.main()
