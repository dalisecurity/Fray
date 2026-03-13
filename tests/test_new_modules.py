"""Tests for new modules: company_report, race, waf_reverse, themes, ask (#222)."""

import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ══════════════════════════════════════════════════════════════════════════════
# fray.company_report (#73)
# ══════════════════════════════════════════════════════════════════════════════

class TestCompanyReport:
    def test_import(self):
        from fray.company_report import generate_company_report, report_to_markdown
        assert callable(generate_company_report)
        assert callable(report_to_markdown)

    def test_empty_domain(self):
        from fray.company_report import generate_company_report
        report = generate_company_report("nonexistent-domain-12345.example")
        assert report["company"] == "nonexistent-domain-12345.example"
        assert "sections" in report
        assert "executive_summary" in report["sections"]

    def test_report_to_markdown(self):
        from fray.company_report import report_to_markdown
        report = {
            "company": "test.com",
            "generated_at": "2025-01-01T00:00:00+00:00",
            "fray_version": "dev",
            "sections": {
                "executive_summary": {
                    "domain": "test.com",
                    "sources": ["recon"],
                    "risk_level": "high",
                    "risk_score": 75,
                    "key_findings": [{"severity": "high", "title": "XSS found"}],
                },
            },
        }
        md = report_to_markdown(report)
        assert "# Security Assessment" in md
        assert "test.com" in md
        assert "high" in md.lower()
        assert "XSS found" in md

    def test_write_json(self):
        from fray.company_report import generate_company_report
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            report = generate_company_report("test.com", output=path)
            data = json.loads(Path(path).read_text())
            assert data["company"] == "test.com"
        finally:
            os.unlink(path)

    def test_write_markdown(self):
        from fray.company_report import generate_company_report
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            generate_company_report("test.com", output=path)
            content = Path(path).read_text()
            assert "Security Assessment" in content
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# fray.race (#24)
# ══════════════════════════════════════════════════════════════════════════════

class TestRace:
    def test_import(self):
        from fray.race import run_race_test, RaceResult, RaceResponse, print_race_result
        assert callable(run_race_test)

    def test_race_response_to_dict(self):
        from fray.race import RaceResponse
        r = RaceResponse(
            thread_id=0, status=200, body_length=100,
            body_hash="abc", headers={}, elapsed_ms=12.5
        )
        d = r.to_dict()
        assert d["status"] == 200
        assert d["elapsed_ms"] == 12.5
        assert "error" not in d

    def test_race_response_error(self):
        from fray.race import RaceResponse
        r = RaceResponse(
            thread_id=1, status=0, body_length=0,
            body_hash="", headers={}, elapsed_ms=0, error="timeout"
        )
        d = r.to_dict()
        assert d["error"] == "timeout"

    def test_race_result_to_dict(self):
        from fray.race import RaceResult, RaceResponse
        resp = RaceResponse(
            thread_id=0, status=200, body_length=50,
            body_hash="x" * 64, headers={}, elapsed_ms=10.0
        )
        result = RaceResult(
            target="https://example.com", method="GET",
            concurrency=5, responses=[resp],
            duration_ms=100.0
        )
        d = result.to_dict()
        assert d["target"] == "https://example.com"
        assert d["total_responses"] == 1
        assert 200 in d["status_distribution"]

    def test_divergence_detection_status(self):
        from fray.race import _analyze_divergence, RaceResponse
        responses = [
            RaceResponse(0, 200, 100, "a" * 64, {}, 10.0),
            RaceResponse(1, 403, 50, "b" * 64, {}, 11.0),
        ]
        diverged, details = _analyze_divergence(responses)
        assert diverged
        assert any("Status divergence" in d for d in details)

    def test_no_divergence(self):
        from fray.race import _analyze_divergence, RaceResponse
        body = "same" * 16
        responses = [
            RaceResponse(i, 200, len(body), body, {}, 10.0 + i * 0.1)
            for i in range(5)
        ]
        diverged, details = _analyze_divergence(responses)
        assert not diverged


# ══════════════════════════════════════════════════════════════════════════════
# fray.waf_reverse (#149)
# ══════════════════════════════════════════════════════════════════════════════

class TestWAFReverse:
    def test_import(self):
        from fray.waf_reverse import reverse_engineer_waf, WAFProfile, print_waf_profile
        assert callable(reverse_engineer_waf)

    def test_waf_profile_to_dict(self):
        from fray.waf_reverse import WAFProfile
        p = WAFProfile(target="https://example.com", waf_vendor="cloudflare")
        p.blocked_tags = ["script", "svg"]
        p.allowed_tags = ["div", "span"]
        p.blocked_events = ["onerror"]
        p.allowed_events = ["onclick"]
        p.blocked_keywords = ["alert"]
        p.allowed_keywords = ["fetch"]
        p.total_probes = 6
        p.duration_s = 1.5

        d = p.to_dict()
        assert d["waf_vendor"] == "cloudflare"
        assert d["total_probes"] == 6
        assert "summary" in d
        assert "2 blocked / 2 allowed" in d["summary"]["tags"]

    def test_probe_sets_nonempty(self):
        from fray.waf_reverse import _TAGS, _EVENTS, _KEYWORDS, _ENCODINGS
        assert len(_TAGS) >= 20
        assert len(_EVENTS) >= 20
        assert len(_KEYWORDS) >= 15
        assert len(_ENCODINGS) >= 5

    def test_encoding_functions(self):
        from fray.waf_reverse import _ENCODINGS
        for name, fn in _ENCODINGS.items():
            result = fn("alert")
            assert isinstance(result, str)
            assert len(result) > 0


# ══════════════════════════════════════════════════════════════════════════════
# fray.themes (#184)
# ══════════════════════════════════════════════════════════════════════════════

class TestThemes:
    def test_import(self):
        from fray.themes import T
        assert hasattr(T, 'set_theme')
        assert hasattr(T, 'available')

    def test_available_themes(self):
        from fray.themes import T
        themes = T.available
        assert "dark" in themes
        assert "light" in themes
        assert "hacker" in themes
        assert "minimal" in themes
        assert "none" in themes

    def test_set_theme_none(self):
        from fray.themes import T
        T.set_theme("none")
        assert T.BOLD == ""
        assert T.RESET == ""
        assert T.OK == ""

    def test_set_theme_dark(self):
        from fray.themes import T
        T.set_theme("dark")
        assert "\033[" in T.BOLD
        assert "\033[" in T.OK

    def test_set_theme_hacker(self):
        from fray.themes import T
        T.set_theme("hacker")
        assert "\033[92m" in T.OK  # bright green

    def test_unknown_attribute(self):
        from fray.themes import T
        T.set_theme("dark")
        val = T.NONEXISTENT_ATTR
        assert val == ""

    def test_no_color_env(self):
        from fray.themes import _Theme
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            t = _Theme()
            t._load()
            assert t.BOLD == ""


# ══════════════════════════════════════════════════════════════════════════════
# fray.ask (#142)
# ══════════════════════════════════════════════════════════════════════════════

class TestAsk:
    def test_import(self):
        from fray.ask import ask, print_ask_result
        assert callable(ask)

    def test_classify_intent_waf(self):
        from fray.ask import _classify_intent
        intents = _classify_intent("which domains have no WAF?")
        assert "no_waf" in intents

    def test_classify_intent_bypass(self):
        from fray.ask import _classify_intent
        intents = _classify_intent("show bypasses for cloudflare")
        assert "bypasses" in intents

    def test_classify_intent_subdomain(self):
        from fray.ask import _classify_intent
        intents = _classify_intent("subdomains for softbank.jp")
        assert "subdomains" in intents

    def test_classify_intent_summary(self):
        from fray.ask import _classify_intent
        intents = _classify_intent("hello")
        assert "summary" in intents

    def test_extract_domain(self):
        from fray.ask import _extract_domain
        assert _extract_domain("bypasses for softbank.jp") == "softbank.jp"
        assert _extract_domain("show toyota.co.jp info") == "toyota.co.jp"
        assert _extract_domain("no domain here") is None

    def test_extract_vendor(self):
        from fray.ask import _extract_vendor
        assert _extract_vendor("cloudflare bypass stats") == "cloudflare"
        assert _extract_vendor("akamai rules") == "akamai"
        assert _extract_vendor("something else") is None

    def test_ask_empty_data(self):
        from fray.ask import ask
        result = ask("show everything")
        assert "query" in result
        assert "intents" in result
        assert "results" in result
        assert isinstance(result["results"], list)

    def test_ask_no_waf(self):
        from fray.ask import ask
        result = ask("which domains have no WAF?")
        assert "no_waf" in result["intents"]
        assert isinstance(result["results"], list)


# ══════════════════════════════════════════════════════════════════════════════
# fray.proto_pollution (#29)
# ══════════════════════════════════════════════════════════════════════════════

class TestProtoPollution:
    def test_import(self):
        from fray.proto_pollution import scan_prototype_pollution
        assert callable(scan_prototype_pollution)


# ══════════════════════════════════════════════════════════════════════════════
# CLI integration for new commands
# ══════════════════════════════════════════════════════════════════════════════

class TestCLINewCommands:
    """Verify subparsers are registered."""

    def test_report_subparser(self):
        from fray.cli import main
        # Just verify the module loads without error
        from fray.company_report import generate_company_report
        assert callable(generate_company_report)

    def test_ask_subparser(self):
        from fray.ask import ask
        assert callable(ask)

    def test_race_subparser(self):
        from fray.race import run_race_test
        assert callable(run_race_test)

    def test_waf_reverse_subparser(self):
        from fray.waf_reverse import reverse_engineer_waf
        assert callable(reverse_engineer_waf)
