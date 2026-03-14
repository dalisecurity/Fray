"""Unit tests for new feature modules:
  - crawler.py (CrawlEndpoint, regex extraction, Crawler)
  - nuclei_export.py (template generation, batch export)
  - recon_diff.py (diff_reports, print_diff)
  - dashboard.py (Dashboard lifecycle)
  - impersonate.py (pick_browser, ImpersonateResponse, ImpersonatedSession, rotation)
  - compare.py (CompareResult)
  - waf_rules.py (pattern extraction, rule generation)
"""

import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

import pytest


# ══════════════════════════════════════════════════════════════════════════════
# 1. fray.crawler
# ══════════════════════════════════════════════════════════════════════════════

class TestCrawlEndpoint:
    def test_import(self):
        from fray.crawler import CrawlEndpoint, Crawler
        assert CrawlEndpoint is not None
        assert Crawler is not None

    def test_to_dict(self):
        from fray.crawler import CrawlEndpoint
        ep = CrawlEndpoint(url="https://x.com/search", method="GET",
                           params=["q", "page"], source="form", depth=1)
        d = ep.to_dict()
        assert d["url"] == "https://x.com/search"
        assert d["method"] == "GET"
        assert d["params"] == ["q", "page"]
        assert d["source"] == "form"
        assert d["depth"] == 1

    def test_method_uppercased(self):
        from fray.crawler import CrawlEndpoint
        ep = CrawlEndpoint(url="https://x.com", method="post")
        assert ep.method == "POST"

    def test_hash_and_eq(self):
        from fray.crawler import CrawlEndpoint
        a = CrawlEndpoint(url="https://x.com", method="GET", params=["q"])
        b = CrawlEndpoint(url="https://x.com", method="GET", params=["q"])
        c = CrawlEndpoint(url="https://x.com", method="POST", params=["q"])
        assert a == b
        assert a != c
        assert hash(a) == hash(b)

    def test_dedup_in_set(self):
        from fray.crawler import CrawlEndpoint
        a = CrawlEndpoint(url="https://x.com", params=["a", "b"])
        b = CrawlEndpoint(url="https://x.com", params=["b", "a"])
        assert a == b
        s = {a}
        # hash uses sorted params, so b should match
        assert hash(a) == hash(b)

    def test_default_params_empty(self):
        from fray.crawler import CrawlEndpoint
        ep = CrawlEndpoint(url="https://x.com")
        assert ep.params == []
        assert ep.source == "link"


class TestCrawlerRegex:
    """Test the regex patterns used by the crawler for JS analysis."""

    def test_fetch_regex(self):
        from fray.crawler import _RE_FETCH
        js = '''fetch("/api/users")'''
        m = _RE_FETCH.findall(js)
        assert "/api/users" in m

    def test_xhr_regex(self):
        from fray.crawler import _RE_XHR
        js = '''xhr.open("POST", "/api/data")'''
        matches = _RE_XHR.findall(js)
        assert len(matches) >= 1
        assert matches[0] == ("POST", "/api/data")

    def test_axios_regex(self):
        from fray.crawler import _RE_AXIOS
        js = '''axios.get("/api/v1/items")'''
        matches = _RE_AXIOS.findall(js)
        assert len(matches) >= 1
        assert matches[0][1] == "/api/v1/items"

    def test_jquery_regex(self):
        from fray.crawler import _RE_JQUERY
        js = '''$.post("/submit")'''
        matches = _RE_JQUERY.findall(js)
        assert len(matches) >= 1
        assert matches[0][1] == "/submit"

    def test_form_action_regex(self):
        from fray.crawler import _RE_FORM_ACTION
        html = '<form action="/login" method="post">'
        m = _RE_FORM_ACTION.findall(html)
        assert "/login" in m

    def test_input_name_regex(self):
        from fray.crawler import _RE_INPUT
        html = '<input type="text" name="username" /><input name="password" />'
        m = _RE_INPUT.findall(html)
        assert "username" in m
        assert "password" in m

    def test_api_path_regex(self):
        from fray.crawler import _RE_API_PATH
        js = '''const url = "/api/v2/users/search"'''
        m = _RE_API_PATH.findall(js)
        assert any("/api/v2/users/search" in x for x in m)


class TestCrawlerInit:
    def test_defaults(self):
        from fray.crawler import Crawler
        c = Crawler.__new__(Crawler)
        c.__init__("example.com")
        assert c.target == "https://example.com"
        assert c.max_pages == 50
        assert c.max_depth == 3
        assert c.browser is False

    def test_http_prefix_preserved(self):
        from fray.crawler import Crawler
        c = Crawler.__new__(Crawler)
        c.__init__("http://example.com")
        assert c.target == "http://example.com"
        assert c.scheme == "http"

    def test_browser_flag(self):
        from fray.crawler import Crawler
        c = Crawler.__new__(Crawler)
        c.__init__("https://example.com", browser=True)
        assert c.browser is True

    def test_normalize_url(self):
        from fray.crawler import Crawler
        c = Crawler.__new__(Crawler)
        c.__init__("https://example.com")
        # Absolute same-host URL
        assert c._normalize_url("https://example.com/page", "https://example.com") == "https://example.com/page"
        # Relative URL
        norm = c._normalize_url("/about", "https://example.com/index")
        assert norm == "https://example.com/about"
        # Different host → None
        assert c._normalize_url("https://other.com/x", "https://example.com") is None
        # Fragment stripped
        norm = c._normalize_url("/page#section", "https://example.com")
        assert "#" not in norm


# ══════════════════════════════════════════════════════════════════════════════
# 2. fray.nuclei_export
# ══════════════════════════════════════════════════════════════════════════════

class TestNucleiExport:
    def test_import(self):
        from fray.nuclei_export import bypass_to_template, export_templates, _safe_id
        assert callable(bypass_to_template)
        assert callable(export_templates)

    def test_safe_id_deterministic(self):
        from fray.nuclei_export import _safe_id
        a = _safe_id("<svg onload=alert(1)>")
        b = _safe_id("<svg onload=alert(1)>")
        assert a == b
        assert a.startswith("fray-bypass-")
        assert len(a) == len("fray-bypass-") + 8

    def test_safe_id_unique(self):
        from fray.nuclei_export import _safe_id
        a = _safe_id("payload_a")
        b = _safe_id("payload_b")
        assert a != b

    def test_severity_mapping(self):
        from fray.nuclei_export import _severity_from_category
        assert _severity_from_category("xss") == "medium"
        assert _severity_from_category("sqli") == "critical"
        assert _severity_from_category("cmdi") == "critical"
        assert _severity_from_category("ssti") == "high"
        assert _severity_from_category("unknown_cat") == "medium"

    def test_bypass_to_template_get(self):
        from fray.nuclei_export import bypass_to_template
        bypass = {"payload": "<img src=x onerror=alert(1)>", "param": "q",
                  "method": "GET", "status": 200}
        tmpl = bypass_to_template(bypass, category="xss", target="https://t.com",
                                   waf_vendor="Cloudflare")
        assert "id: fray-bypass-" in tmpl
        assert "severity: medium" in tmpl
        assert "author: fray" in tmpl
        assert "xss" in tmpl
        assert "cloudflare" in tmpl.lower()
        assert "method: GET" in tmpl
        assert "{{BaseURL}}" in tmpl

    def test_bypass_to_template_post(self):
        from fray.nuclei_export import bypass_to_template
        bypass = {"payload": "' OR 1=1--", "param": "user", "method": "POST", "status": 200}
        tmpl = bypass_to_template(bypass, category="sqli")
        assert "method: POST" in tmpl
        assert "Content-Type" in tmpl
        assert "severity: critical" in tmpl

    def test_export_templates_writes_files(self):
        from fray.nuclei_export import export_templates
        bypasses = [
            {"payload": "<svg/onload=alert(1)>", "param": "q"},
            {"payload": "' UNION SELECT 1--", "param": "id"},
        ]
        with tempfile.TemporaryDirectory() as d:
            written = export_templates(bypasses, output_dir=d, category="xss")
            assert len(written) == 2
            for p in written:
                assert os.path.exists(p)
                assert p.endswith(".yaml")
                content = open(p).read()
                assert "id: fray-bypass-" in content

    def test_export_templates_skips_empty(self):
        from fray.nuclei_export import export_templates
        bypasses = [{"payload": ""}, {"payload": "<script>alert(1)</script>"}]
        with tempfile.TemporaryDirectory() as d:
            written = export_templates(bypasses, output_dir=d)
            assert len(written) == 1  # Empty payload skipped

    def test_export_templates_creates_dir(self):
        from fray.nuclei_export import export_templates
        with tempfile.TemporaryDirectory() as base:
            out = os.path.join(base, "nested", "nuclei")
            written = export_templates(
                [{"payload": "test"}], output_dir=out)
            assert os.path.isdir(out)


# ══════════════════════════════════════════════════════════════════════════════
# 3. fray.recon_diff
# ══════════════════════════════════════════════════════════════════════════════

class TestReconDiff:
    def _make_report(self, **overrides):
        """Build a minimal recon report dict for testing."""
        base = {
            "host": "example.com",
            "attack_surface": {
                "risk_score": 40, "risk_level": "Medium",
                "waf_vendor": "Cloudflare",
                "findings": [], "attack_vectors": [],
            },
            "subdomains": {"subdomains": []},
            "headers": {"score": 50, "missing": {}},
            "fingerprint": {"technologies": {}},
            "admin_panels": {"panels_found": []},
        }
        for k, v in overrides.items():
            if "." in k:
                parts = k.split(".")
                d = base
                for p in parts[:-1]:
                    d = d[p]
                d[parts[-1]] = v
            else:
                base[k] = v
        return base

    def test_import(self):
        from fray.recon_diff import diff_reports, print_diff
        assert callable(diff_reports)
        assert callable(print_diff)

    def test_no_changes(self):
        from fray.recon_diff import diff_reports
        r = self._make_report()
        diff = diff_reports(r, r)
        assert diff["summary"]["total_changes"] == 0
        assert diff["sections"] == []

    def test_risk_score_change(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        new = self._make_report()
        new["attack_surface"]["risk_score"] = 75
        new["attack_surface"]["risk_level"] = "High"
        diff = diff_reports(old, new)
        risk_sections = [s for s in diff["sections"] if s["section"] == "Risk Score"]
        assert len(risk_sections) == 1
        assert risk_sections[0]["type"] == "changed"
        assert "increased" in risk_sections[0].get("detail", "")

    def test_waf_change(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        new = self._make_report()
        new["attack_surface"]["waf_vendor"] = "Akamai"
        diff = diff_reports(old, new)
        waf_sections = [s for s in diff["sections"] if s["section"] == "WAF"]
        assert len(waf_sections) == 1

    def test_subdomain_added(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        new = self._make_report()
        new["subdomains"]["subdomains"] = ["api.example.com"]
        diff = diff_reports(old, new)
        sub_sections = [s for s in diff["sections"]
                        if s["section"] == "Subdomains" and s["type"] == "added"]
        assert len(sub_sections) == 1
        assert sub_sections[0]["count"] == 1

    def test_finding_added(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        new = self._make_report()
        new["attack_surface"]["findings"] = [{"type": "xss", "title": "Reflected XSS", "severity": "high"}]
        diff = diff_reports(old, new)
        finding_sections = [s for s in diff["sections"]
                            if s["section"] == "Findings" and s["type"] == "added"]
        assert len(finding_sections) == 1

    def test_tech_added_and_removed(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        old["fingerprint"]["technologies"] = {"Nginx": {}, "PHP": {}}
        new = self._make_report()
        new["fingerprint"]["technologies"] = {"Nginx": {}, "Node.js": {}}
        diff = diff_reports(old, new)
        added = [s for s in diff["sections"]
                 if s["section"] == "Technologies" and s["type"] == "added"]
        removed = [s for s in diff["sections"]
                   if s["section"] == "Technologies" and s["type"] == "removed"]
        assert len(added) == 1
        assert "Node.js" in added[0]["items"]
        assert len(removed) == 1
        assert "PHP" in removed[0]["items"]

    def test_header_regression(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        old["headers"]["missing"] = {"CSP": {}}
        new = self._make_report()
        new["headers"]["missing"] = {"CSP": {}, "HSTS": {}}
        diff = diff_reports(old, new)
        regressed = [s for s in diff["sections"]
                     if s["section"] == "Security Headers" and s["type"] == "regressed"]
        assert len(regressed) == 1
        assert "HSTS" in regressed[0]["items"]

    def test_print_diff_runs(self):
        from fray.recon_diff import diff_reports, print_diff
        old = self._make_report()
        new = self._make_report()
        new["attack_surface"]["risk_score"] = 80
        new["attack_surface"]["risk_level"] = "Critical"
        diff = diff_reports(old, new)
        # Should not raise
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            print_diff(diff)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        assert "Fray Diff" in output

    def test_summary_counts(self):
        from fray.recon_diff import diff_reports
        old = self._make_report()
        new = self._make_report()
        new["attack_surface"]["risk_score"] = 90
        new["attack_surface"]["risk_level"] = "Critical"
        new["subdomains"]["subdomains"] = ["a.example.com"]
        diff = diff_reports(old, new)
        s = diff["summary"]
        assert s["total_changes"] >= 2
        assert s["added"] >= 1
        assert s["changed"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. fray.dashboard
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboard:
    def test_import(self):
        from fray.dashboard import Dashboard, _bar, _risk_gauge
        assert Dashboard is not None

    def test_bar_0(self):
        from fray.dashboard import _bar
        b = _bar(0, width=10)
        assert len(b) > 0  # Contains ANSI codes + chars

    def test_bar_100(self):
        from fray.dashboard import _bar
        b = _bar(100, width=10)
        assert len(b) > 0

    def test_risk_gauge(self):
        from fray.dashboard import _risk_gauge
        for score in [0, 15, 35, 55, 80]:
            g = _risk_gauge(score)
            assert str(score) in g

    def test_dashboard_lifecycle_quiet(self):
        """Dashboard in quiet mode should be a no-op."""
        from fray.dashboard import Dashboard
        d = Dashboard(target="test.com", quiet=True)
        d.start()
        d.set_phase(1, "Recon", total=10)
        d.update_progress(done=5)
        d.set_risk(50)
        d.add_finding("XSS found", "high")
        d.update_stat("requests", 100)
        d.finish()
        # Should not raise, should not output

    def test_dashboard_lifecycle_active(self):
        """Dashboard renders to stderr without crashing."""
        from fray.dashboard import Dashboard
        buf = io.StringIO()
        d = Dashboard(target="test.com", quiet=False)
        d._out = buf  # Redirect output to buffer
        d.start()
        assert d._active is True
        d.set_phase(1, "Recon", total=10)
        d.update_progress(done=3)
        d.update_progress(increment=2)
        assert d._done == 5
        d.set_risk(45)
        assert d._risk_score == 45
        d.add_finding("Test finding", "medium")
        assert len(d._findings) == 1
        d.update_stat("requests", 50)
        assert d._stats["requests"] == 50
        d.finish()
        assert d._active is False
        output = buf.getvalue()
        assert "test.com" in output

    def test_dashboard_risk_clamped(self):
        from fray.dashboard import Dashboard
        d = Dashboard(target="t.com", quiet=True)
        d.set_risk(150)
        assert d._risk_score == 100
        d.set_risk(-10)
        assert d._risk_score == 0

    def test_dashboard_phase_resets_progress(self):
        from fray.dashboard import Dashboard
        d = Dashboard(target="t.com", quiet=True)
        d.set_phase(1, "A", total=10)
        d.update_progress(done=5)
        d.set_phase(2, "B", total=20)
        assert d._done == 0
        assert d._total == 20


# ══════════════════════════════════════════════════════════════════════════════
# 5. fray.impersonate
# ══════════════════════════════════════════════════════════════════════════════

class TestPickBrowser:
    def test_import(self):
        from fray.impersonate import (pick_browser, ImpersonateResponse,
                                       ImpersonatedSession, AVAILABLE,
                                       CHROME_PROFILES, FIREFOX_PROFILES,
                                       SAFARI_PROFILES, ALL_PROFILES)
        assert callable(pick_browser)

    def test_chrome(self):
        from fray.impersonate import pick_browser, CHROME_PROFILES
        for _ in range(10):
            p = pick_browser("chrome")
            assert p in CHROME_PROFILES[:3]

    def test_firefox(self):
        from fray.impersonate import pick_browser, FIREFOX_PROFILES
        p = pick_browser("firefox")
        assert p in FIREFOX_PROFILES[:2]

    def test_safari(self):
        from fray.impersonate import pick_browser, SAFARI_PROFILES
        p = pick_browser("safari")
        assert p in SAFARI_PROFILES[:2]

    def test_tor(self):
        from fray.impersonate import pick_browser
        assert pick_browser("tor") == "tor145"

    def test_random(self):
        from fray.impersonate import pick_browser, ALL_PROFILES
        p = pick_browser("random")
        assert p in ALL_PROFILES[:6]

    def test_exact_profile(self):
        from fray.impersonate import pick_browser
        assert pick_browser("chrome142") == "chrome142"
        assert pick_browser("firefox135") == "firefox135"

    def test_unknown_defaults_chrome(self):
        from fray.impersonate import pick_browser, CHROME_PROFILES
        assert pick_browser("netscape") == CHROME_PROFILES[0]

    def test_aliases(self):
        from fray.impersonate import pick_browser, CHROME_PROFILES, FIREFOX_PROFILES
        assert pick_browser("chr") in CHROME_PROFILES[:3]
        assert pick_browser("ff") in FIREFOX_PROFILES[:2]
        assert pick_browser("saf") in ["safari184", "safari180"]


class TestImpersonateResponse:
    def test_defaults(self):
        from fray.impersonate import ImpersonateResponse
        r = ImpersonateResponse()
        assert r.status_code == 0
        assert r.headers == {}
        assert r.text == ""
        assert r.content == b""
        assert r.url == ""
        assert r.elapsed_ms == 0.0
        assert r.ok is False

    def test_ok_range(self):
        from fray.impersonate import ImpersonateResponse
        assert ImpersonateResponse(status_code=200).ok is True
        assert ImpersonateResponse(status_code=301).ok is True
        assert ImpersonateResponse(status_code=399).ok is True
        assert ImpersonateResponse(status_code=400).ok is False
        assert ImpersonateResponse(status_code=500).ok is False

    def test_fields(self):
        from fray.impersonate import ImpersonateResponse
        r = ImpersonateResponse(
            status_code=403,
            headers={"server": "cloudflare"},
            text="blocked",
            content=b"blocked",
            url="https://x.com",
            elapsed_ms=42.5,
        )
        assert r.status_code == 403
        assert r.headers["server"] == "cloudflare"
        assert r.text == "blocked"
        assert r.elapsed_ms == 42.5
        assert r.ok is False


class TestImpersonatedSession:
    def test_context_manager(self):
        from fray.impersonate import ImpersonatedSession
        with ImpersonatedSession(browser="chrome") as s:
            assert s is not None
            assert s.browser.startswith("chrome") or s.browser.startswith("firefox")

    def test_close_idempotent(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(browser="chrome")
        s.close()
        s.close()  # Should not raise

    def test_rotation_config(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(browser="chrome", rotate=True, rotate_every=3)
        assert s._rotate is True
        assert s._rotate_every == 3
        assert s._request_count == 0
        s.close()

    def test_rotation_every_min_1(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(rotate=True, rotate_every=0)
        assert s._rotate_every == 1
        s.close()

    def test_extra_headers_stored(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(headers={"X-Custom": "val"})
        assert s.extra_headers == {"X-Custom": "val"}
        s.close()

    def test_proxy_stored(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(proxy="http://127.0.0.1:8080")
        assert s.proxy == "http://127.0.0.1:8080"
        s.close()


class TestRotateSession:
    """Test profile rotation logic (mocked, no network)."""

    def test_no_rotate_when_disabled(self):
        from fray.impersonate import ImpersonatedSession
        s = ImpersonatedSession(browser="chrome", rotate=False)
        orig = s.browser
        for _ in range(20):
            s._rotate_session()
        assert s.browser == orig
        s.close()

    def test_rotate_changes_family(self):
        from fray.impersonate import ImpersonatedSession, _HAS_CURL_CFFI
        if not _HAS_CURL_CFFI:
            pytest.skip("curl_cffi not installed")
        s = ImpersonatedSession(browser="chrome", rotate=True, rotate_every=1)
        orig = s.browser
        families_seen = {orig.rstrip('0123456789_')}
        for _ in range(20):
            s._rotate_session()
            families_seen.add(s.browser.rstrip('0123456789_'))
        # After 20 rotations, should have seen at least 2 families
        assert len(families_seen) >= 2
        s.close()


# ══════════════════════════════════════════════════════════════════════════════
# 6. fray.compare
# ══════════════════════════════════════════════════════════════════════════════

class TestCompareResult:
    def test_import(self):
        from fray.compare import CompareResult, run_compare, print_compare
        assert CompareResult is not None

    def test_to_dict(self):
        from fray.compare import CompareResult
        r = CompareResult()
        r.target = "https://example.com"
        r.category = "xss"
        r.total_payloads = 10
        r.raw_bypasses = 3
        r.raw_blocked = 7
        r.imp_bypasses = 6
        r.imp_blocked = 4
        r.tls_fingerprint_blocks = 3
        r.content_blocks = 4
        r.both_pass = 3
        r.elapsed_s = 5.0
        r.impersonate_browser = "chrome"
        d = r.to_dict()
        assert d["target"] == "https://example.com"
        assert d["raw"]["bypasses"] == 3
        assert d["impersonated"]["bypasses"] == 6
        assert d["tls_fingerprint_blocks"] == 3
        assert d["tls_block_pct"] == 30.0

    def test_tls_block_pct_zero_payloads(self):
        from fray.compare import CompareResult
        r = CompareResult()
        r.total_payloads = 0
        d = r.to_dict()
        assert d["tls_block_pct"] == 0.0

    def test_print_compare_runs(self):
        from fray.compare import CompareResult, print_compare
        r = CompareResult()
        r.target = "https://test.com"
        r.total_payloads = 5
        r.tls_fingerprint_blocks = 2
        r.content_blocks = 2
        r.both_pass = 1
        r.impersonate_browser = "chrome"
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            print_compare(r)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        assert "Fray Compare" in output
        assert "TLS" in output


# ══════════════════════════════════════════════════════════════════════════════
# 7. fray.waf_rules
# ══════════════════════════════════════════════════════════════════════════════

class TestWafRules:
    def test_import(self):
        from fray.waf_rules import generate_rules, rules_to_html, _extract_pattern
        assert callable(generate_rules)
        assert callable(rules_to_html)

    def test_extract_pattern_xss(self):
        from fray.waf_rules import _extract_pattern
        p = _extract_pattern("<img src=x onerror=alert(1)>")
        assert "onerror=" in p or "<img" in p

    def test_extract_pattern_sqli(self):
        from fray.waf_rules import _extract_pattern
        p = _extract_pattern("' UNION SELECT 1,2,3--")
        assert "union" in p.lower() or "select" in p.lower()

    def test_extract_pattern_script(self):
        from fray.waf_rules import _extract_pattern
        p = _extract_pattern("<script>alert(1)</script>")
        assert "<script" in p

    def test_extract_pattern_cmdi(self):
        from fray.waf_rules import _extract_pattern
        p = _extract_pattern("; cat /etc/passwd")
        assert "cat" in p

    def test_generate_rules_modsecurity(self):
        from fray.waf_rules import generate_rules
        bypasses = [{"payload": "<svg/onload=alert(1)>"}]
        result = generate_rules(bypasses, waf_vendor="modsecurity", category="xss")
        assert result["count"] == 1
        assert result["rules"][0]["type"] == "modsecurity"
        assert "SecRule" in result["rules"][0]["rule"]
        assert "deny" in result["rules"][0]["rule"]

    def test_generate_rules_cloudflare(self):
        from fray.waf_rules import generate_rules
        bypasses = [{"payload": "<img src=x onerror=alert(1)>"}]
        result = generate_rules(bypasses, waf_vendor="cloudflare", category="xss")
        assert result["count"] == 1
        assert result["rules"][0]["type"] == "cloudflare"
        assert "http.request" in result["rules"][0]["expression"]

    def test_generate_rules_aws(self):
        from fray.waf_rules import generate_rules
        bypasses = [{"payload": "' OR 1=1--"}]
        result = generate_rules(bypasses, waf_vendor="aws", category="sqli")
        assert result["count"] == 1
        assert result["rules"][0]["type"] == "aws_waf"
        assert "RegexString" in result["rules"][0]["regex_pattern"]

    def test_generate_rules_generic(self):
        from fray.waf_rules import generate_rules
        bypasses = [{"payload": "<script>x</script>"}]
        result = generate_rules(bypasses, waf_vendor="unknown_waf")
        assert result["rules"][0]["type"] == "generic"
        assert "modsecurity" in result["rules"][0]
        assert "cloudflare" in result["rules"][0]
        assert "aws_waf" in result["rules"][0]

    def test_generate_rules_dedup(self):
        from fray.waf_rules import generate_rules
        bypasses = [
            {"payload": "<svg onload=alert(1)>"},
            {"payload": "<svg onload=alert(2)>"},
        ]
        result = generate_rules(bypasses, waf_vendor="modsecurity")
        # Same pattern family → deduplicated
        assert result["count"] <= 2

    def test_generate_rules_empty(self):
        from fray.waf_rules import generate_rules
        result = generate_rules([], waf_vendor="modsecurity")
        assert result["count"] == 0
        assert result["rules"] == []

    def test_rules_to_html(self):
        from fray.waf_rules import generate_rules, rules_to_html
        bypasses = [{"payload": "<script>alert(1)</script>"}]
        data = generate_rules(bypasses, waf_vendor="modsecurity", category="xss")
        html = rules_to_html(data)
        assert "Suggested WAF Rules" in html
        assert "<table" in html
        assert "XSS" in html

    def test_rules_to_html_empty(self):
        from fray.waf_rules import rules_to_html
        html = rules_to_html({"rules": [], "count": 0, "vendor": "x", "category": "xss"})
        assert html == ""


# ══════════════════════════════════════════════════════════════════════════════
# 8. fray.challenge_solver
# ══════════════════════════════════════════════════════════════════════════════

class TestChallengeType:
    def test_import(self):
        from fray.challenge_solver import (ChallengeType, SolveResult, ChallengeSolver,
                                            detect_challenge, solve_challenge,
                                            extract_cf_clearance, _STEALTH_JS)
        assert ChallengeType.CF_JS == "cloudflare_js"
        assert ChallengeType.CF_TURNSTILE == "cloudflare_turnstile"
        assert ChallengeType.RECAPTCHA_V2 == "recaptcha_v2"
        assert ChallengeType.HCAPTCHA == "hcaptcha"
        assert ChallengeType.NONE == "none"

    def test_all_types_distinct(self):
        from fray.challenge_solver import ChallengeType
        types = [ChallengeType.NONE, ChallengeType.CF_JS, ChallengeType.CF_TURNSTILE,
                 ChallengeType.RECAPTCHA_V2, ChallengeType.RECAPTCHA_V3,
                 ChallengeType.HCAPTCHA, ChallengeType.DATADOME,
                 ChallengeType.AKAMAI, ChallengeType.UNKNOWN]
        assert len(set(types)) == len(types)


class TestSolveResult:
    def test_defaults(self):
        from fray.challenge_solver import SolveResult
        r = SolveResult()
        assert r.success is False
        assert r.challenge_type == "none"
        assert r.cookies == {}
        assert r.headers == {}
        assert r.token == ""
        assert r.user_agent == ""
        assert r.elapsed_s == 0.0
        assert r.error == ""

    def test_to_dict(self):
        from fray.challenge_solver import SolveResult
        r = SolveResult(
            success=True,
            challenge_type="cloudflare_js",
            cookies={"cf_clearance": "abc123"},
            token="tok" * 30,
            user_agent="UA",
            elapsed_s=3.5,
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["challenge_type"] == "cloudflare_js"
        assert d["cookies"] == {"cf_clearance": "abc123"}
        assert d["token"].endswith("...")  # Long token truncated
        assert d["elapsed_s"] == 3.5

    def test_to_dict_short_token(self):
        from fray.challenge_solver import SolveResult
        r = SolveResult(token="short")
        d = r.to_dict()
        assert d["token"] == "short"  # Not truncated


class TestDetectChallenge:
    def test_no_challenge(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        assert detect_challenge("", {}, 200) == ChallengeType.NONE
        assert detect_challenge("<html>Hello</html>", {}, 200) == ChallengeType.NONE

    def test_cf_js_body(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<html><body>Just a moment...</body></html>'
        assert detect_challenge(body, {}, 503) == ChallengeType.CF_JS

    def test_cf_js_checking(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<div>Checking if the site connection is secure</div>'
        assert detect_challenge(body, {}, 503) == ChallengeType.CF_JS

    def test_cf_js_header(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        assert detect_challenge("", {"server": "cloudflare"}, 503) == ChallengeType.CF_JS

    def test_cf_turnstile(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
        assert detect_challenge(body, {}, 200) == ChallengeType.CF_TURNSTILE

    def test_cf_turnstile_widget(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<div class="cf-turnstile" data-sitekey="abc"></div>'
        assert detect_challenge(body, {}, 200) == ChallengeType.CF_TURNSTILE

    def test_recaptcha_v2(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha"></div>'
        assert detect_challenge(body, {}, 200) == ChallengeType.RECAPTCHA_V2

    def test_recaptcha_v3(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script src="https://www.google.com/recaptcha/api.js?render=sitekey123"></script>'
        assert detect_challenge(body, {}, 200) == ChallengeType.RECAPTCHA_V3

    def test_hcaptcha(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script src="https://hcaptcha.com/1/api.js"></script>'
        assert detect_challenge(body, {}, 200) == ChallengeType.HCAPTCHA

    def test_datadome(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script src="https://datadome.co/captcha/v2"></script>'
        assert detect_challenge(body, {}, 403) == ChallengeType.DATADOME

    def test_datadome_header(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        assert detect_challenge("blocked", {"x-datadome": "1"}, 403) == ChallengeType.DATADOME

    def test_akamai(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<script>var _abck = "abc";</script>'
        assert detect_challenge(body, {}, 403) == ChallengeType.AKAMAI

    def test_unknown_403_captcha(self):
        from fray.challenge_solver import detect_challenge, ChallengeType
        body = '<div>Please complete the captcha to continue</div>'
        assert detect_challenge(body, {}, 403) == ChallengeType.UNKNOWN


class TestStealthJS:
    def test_stealth_js_content(self):
        from fray.challenge_solver import _STEALTH_JS
        assert "webdriver" in _STEALTH_JS
        assert "plugins" in _STEALTH_JS
        assert "Chrome PDF" in _STEALTH_JS
        assert "languages" in _STEALTH_JS
        assert "WebGL" in _STEALTH_JS
        assert "connection" in _STEALTH_JS

    def test_stealth_ua(self):
        from fray.challenge_solver import _STEALTH_UA
        assert "Chrome" in _STEALTH_UA
        assert "Mozilla" in _STEALTH_UA

    def test_stealth_viewport(self):
        from fray.challenge_solver import _STEALTH_VIEWPORT
        assert _STEALTH_VIEWPORT["width"] == 1920
        assert _STEALTH_VIEWPORT["height"] == 1080


class TestChallengeSolverInit:
    def test_defaults(self):
        from fray.challenge_solver import ChallengeSolver
        s = ChallengeSolver("https://example.com")
        assert s.target == "https://example.com"
        assert s.timeout == 30
        assert s.verbose is False
        assert s.headless is True

    def test_custom_params(self):
        from fray.challenge_solver import ChallengeSolver
        s = ChallengeSolver("https://t.com", timeout=10, verbose=True, headless=False)
        assert s.timeout == 10
        assert s.verbose is True
        assert s.headless is False


# ══════════════════════════════════════════════════════════════════════════════
# 9. fray.async_engine — ResponseBaseline, redirect following, parallel API
# ══════════════════════════════════════════════════════════════════════════════

class TestAsyncRequest:
    def test_import(self):
        from fray.async_engine import AsyncRequest, AsyncResponse, AsyncEngine
        assert AsyncRequest is not None

    def test_defaults(self):
        from fray.async_engine import AsyncRequest
        r = AsyncRequest("https://x.com")
        assert r.url == "https://x.com"
        assert r.method == "GET"
        assert r.headers == {}
        assert r.body is None
        assert r.timeout == 10
        assert r.tag == ""

    def test_method_uppercase(self):
        from fray.async_engine import AsyncRequest
        r = AsyncRequest("https://x.com", method="post")
        assert r.method == "POST"


class TestAsyncResponse:
    def test_defaults(self):
        from fray.async_engine import AsyncResponse
        r = AsyncResponse()
        assert r.status == 0
        assert r.body == ""
        assert r.error == ""

    def test_to_dict(self):
        from fray.async_engine import AsyncResponse
        r = AsyncResponse(url="https://x.com", status=200, body="hello",
                          elapsed_ms=42.5, tag="test_1")
        d = r.to_dict()
        assert d["status"] == 200
        assert d["body_length"] == 5
        assert d["elapsed_ms"] == 42.5
        assert d["tag"] == "test_1"


class TestAsyncEngine:
    def test_init_defaults(self):
        from fray.async_engine import AsyncEngine
        e = AsyncEngine()
        assert e.concurrency == 20
        assert e.rate_limit == 0
        assert e.max_retries == 1

    def test_concurrency_clamped(self):
        from fray.async_engine import AsyncEngine
        e = AsyncEngine(concurrency=500)
        assert e.concurrency == 200
        e2 = AsyncEngine(concurrency=-5)
        assert e2.concurrency == 1

    def test_build_requests_get(self):
        from fray.async_engine import AsyncEngine
        reqs = AsyncEngine.build_requests(
            "https://x.com/search", "q", ["<script>", "' OR 1=1"],
            method="GET", timeout=5,
        )
        assert len(reqs) == 2
        assert "q=%3Cscript%3E" in reqs[0].url or "q=" in reqs[0].url
        assert reqs[0].method == "GET"
        assert reqs[0].body is None
        assert reqs[0].meta["payload"] == "<script>"
        assert reqs[1].meta["index"] == 1

    def test_build_requests_post(self):
        from fray.async_engine import AsyncEngine
        reqs = AsyncEngine.build_requests(
            "https://x.com/login", "user", ["admin"], method="POST",
        )
        assert len(reqs) == 1
        assert reqs[0].method == "POST"
        assert reqs[0].body is not None
        assert "Content-Type" in reqs[0].headers

    def test_build_url_requests(self):
        from fray.async_engine import AsyncEngine
        reqs = AsyncEngine.build_url_requests(
            ["https://a.com", "https://b.com"], cookie="sess=abc",
        )
        assert len(reqs) == 2
        assert reqs[0].headers["Cookie"] == "sess=abc"

    def test_stats_initial(self):
        from fray.async_engine import AsyncEngine
        e = AsyncEngine()
        s = e.stats()
        assert s["total_requests"] == 0
        assert s["total_errors"] == 0

    def test_run_empty(self):
        from fray.async_engine import AsyncEngine
        e = AsyncEngine()
        results = e.run([])
        assert results == []


class TestResponseBaseline:
    def test_init_defaults(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline()
        assert b.status == 0
        assert b.body == ""
        assert b.body_length == 0

    def test_body_tokens(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline(body="Hello World this is a test page")
        tokens = b.body_tokens
        assert "hello" in tokens
        assert "world" in tokens
        assert "test" in tokens
        assert "page" in tokens
        # Tokens cached
        assert b.body_tokens is tokens

    def test_false_positive_no_baseline(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline()  # status=0
        assert b.is_false_positive(403, "blocked") is False

    def test_false_positive_identical(self):
        from fray.async_engine import ResponseBaseline
        body = "Welcome to example.com — default page with many words here"
        b = ResponseBaseline(status=200, body=body)
        # Same body → false positive
        assert b.is_false_positive(200, body) is True

    def test_false_positive_different_status(self):
        from fray.async_engine import ResponseBaseline
        body = "Welcome to example.com — default page"
        b = ResponseBaseline(status=200, body=body)
        # Different status → not false positive
        assert b.is_false_positive(403, "Access denied") is False

    def test_false_positive_different_body(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline(status=200, body="Welcome to example.com page with content here")
        # Completely different body → not false positive
        assert b.is_false_positive(200, "Completely different response entirely new") is False

    def test_classify_block_no_baseline(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline()
        assert b.classify_block(403, "blocked") == "blocked"
        assert b.classify_block(200, "ok") == "unknown"

    def test_classify_block_same(self):
        from fray.async_engine import ResponseBaseline
        body = "Welcome to the site with plenty of words to match against"
        b = ResponseBaseline(status=200, body=body)
        assert b.classify_block(200, body) == "same"

    def test_classify_block_blocked(self):
        from fray.async_engine import ResponseBaseline
        b = ResponseBaseline(status=200, body="Welcome page")
        assert b.classify_block(403, "Forbidden") == "blocked"


class TestClassifyRedirectBlock:
    def test_no_redirect(self):
        from fray.async_engine import classify_redirect_block
        assert classify_redirect_block([], 200, "ok") == "no_redirect"

    def test_redirect_to_captcha(self):
        from fray.async_engine import classify_redirect_block
        chain = [{"status": 302, "url": "https://x.com", "location": "/captcha-challenge"}]
        assert classify_redirect_block(chain, 200, "solve captcha") == "redirect_block"

    def test_redirect_to_blocked(self):
        from fray.async_engine import classify_redirect_block
        chain = [{"status": 302, "url": "https://x.com", "location": "/firewall-blocked"}]
        assert classify_redirect_block(chain, 403, "denied") == "redirect_block"

    def test_captcha_in_final_body(self):
        from fray.async_engine import classify_redirect_block
        chain = [{"status": 302, "url": "https://x.com", "location": "/verify"}]
        assert classify_redirect_block(chain, 200, "Please complete the captcha") == "captcha_redirect"

    def test_normal_redirect(self):
        from fray.async_engine import classify_redirect_block
        chain = [{"status": 301, "url": "http://x.com", "location": "https://x.com"}]
        assert classify_redirect_block(chain, 200, "Welcome") == "normal_redirect"

    def test_final_403(self):
        from fray.async_engine import classify_redirect_block
        chain = [{"status": 302, "url": "https://x.com", "location": "/page"}]
        assert classify_redirect_block(chain, 403, "nope") == "redirect_block"


# ══════════════════════════════════════════════════════════════════════════════
# 10. _auto_concurrency — smart parallel selection from recon
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoConcurrency:
    def test_import(self):
        from fray.interactive import _auto_concurrency
        assert callable(_auto_concurrency)

    def test_no_recon(self):
        from fray.interactive import _auto_concurrency
        assert _auto_concurrency(None) == 1
        assert _auto_concurrency({}) == 1

    def test_no_waf_no_bot(self):
        from fray.interactive import _auto_concurrency
        recon = {"attack_surface": {"waf_vendor": ""}}
        assert _auto_concurrency(recon) == 10

    def test_waf_no_bot_no_rate(self):
        from fray.interactive import _auto_concurrency
        recon = {"attack_surface": {"waf_vendor": "Cloudflare"}}
        assert _auto_concurrency(recon) == 5

    def test_waf_with_rate_limit(self):
        from fray.interactive import _auto_concurrency
        recon = {
            "attack_surface": {"waf_vendor": "Cloudflare"},
            "rate_limits": {"threshold_rps": 10},
        }
        assert _auto_concurrency(recon) == 2

    def test_bot_detection_sequential(self):
        from fray.interactive import _auto_concurrency
        recon = {
            "attack_surface": {"waf_vendor": "Cloudflare"},
            "bot_protection": {"detected": True, "has_captcha": True},
        }
        assert _auto_concurrency(recon) == 1

    def test_no_waf_but_rate_limited(self):
        from fray.interactive import _auto_concurrency
        recon = {
            "attack_surface": {"waf_vendor": ""},
            "rate_limits": {"rate_limited": True},
        }
        # No WAF, no bot → still aggressive (rate limit only matters with WAF)
        assert _auto_concurrency(recon) >= 3

    def test_bot_fingerprinting(self):
        from fray.interactive import _auto_concurrency
        recon = {
            "attack_surface": {"waf_vendor": "Akamai"},
            "bot_protection": {"has_fingerprinting": True},
        }
        assert _auto_concurrency(recon) == 1
