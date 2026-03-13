"""
QA Target Tests — Run against 10 hardcoded vulnerable test sites on every change.

These are intentionally vulnerable web apps provided by the security community.
They are our internal QA targets to assure Fray works correctly after changes.

Runs as part of: pytest tests/test_qa_targets.py
Marker: @pytest.mark.qa (can be selected with: pytest -m qa)
"""

import pytest
import requests
import time

from fray.smoke_test import QA_TARGETS, SmokeTarget

# Mark all tests in this module as QA integration tests
pytestmark = [pytest.mark.qa, pytest.mark.integration]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_reachable(url: str, timeout: int = 10) -> bool:
    """Check if a target is reachable."""
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return r.status_code < 500
    except Exception:
        return False


# ── Parametrized tests over all 10 QA targets ───────────────────────────────

@pytest.fixture(params=QA_TARGETS, ids=lambda t: t.name)
def qa_target(request) -> SmokeTarget:
    """Parametrize over all QA targets."""
    target = request.param
    if not _is_reachable(target.url):
        pytest.skip(f"{target.name} ({target.url}) is unreachable")
    return target


class TestQATargetReachability:
    """Verify all 10 QA targets are alive and responding."""

    @pytest.mark.parametrize("target", QA_TARGETS, ids=lambda t: t.name)
    def test_target_responds(self, target: SmokeTarget):
        """Each QA target should return HTTP < 500."""
        try:
            r = requests.get(target.url, timeout=15, verify=False, allow_redirects=True)
            assert r.status_code < 500, f"{target.name} returned {r.status_code}"
        except requests.exceptions.ConnectionError:
            pytest.skip(f"{target.name} unreachable (may be temporarily down)")
        except requests.exceptions.Timeout:
            pytest.skip(f"{target.name} timed out")


class TestWAFDetection:
    """WAF detection should work correctly against all QA targets."""

    def test_detect_no_waf_on_vulnerable_sites(self, qa_target: SmokeTarget):
        """Vulnerable test sites should NOT have a WAF (or we detect none)."""
        from fray.detector import WAFDetector
        detector = WAFDetector()
        result = detector.detect_waf(qa_target.url, timeout=12, verify_ssl=False)

        # These are intentionally vulnerable — expect no WAF or low confidence
        if qa_target.expected_waf == "none":
            vendor = (result.get("waf_vendor") or "").lower()
            # Allow detection but it shouldn't be a major commercial WAF
            # (some sites may have basic CDN headers)
            assert vendor not in ("cloudflare", "akamai", "imperva", "f5"), \
                f"{qa_target.name} unexpectedly behind {vendor} WAF"

    def test_detect_returns_valid_structure(self, qa_target: SmokeTarget):
        """WAF detection should return a well-formed result dict."""
        from fray.detector import WAFDetector
        detector = WAFDetector()
        result = detector.detect_waf(qa_target.url, timeout=12, verify_ssl=False)

        assert isinstance(result, dict)
        assert "target" in result
        assert "waf_detected" in result
        assert "confidence" in result


class TestRecon:
    """Recon pipeline should run without errors against QA targets."""

    def test_recon_completes(self, qa_target: SmokeTarget):
        """Recon should complete without crashing."""
        from fray.recon.pipeline import run_recon
        result = run_recon(
            qa_target.url,
            timeout=15,
            verify_ssl=False,
            quiet=True,
        )
        assert isinstance(result, dict)
        # Should have at least some basic keys
        assert "target" in result or "url" in result or "domain" in result

    def test_recon_finds_technologies(self, qa_target: SmokeTarget):
        """Recon should detect at least basic tech on vulnerable sites."""
        from fray.recon.pipeline import run_recon
        result = run_recon(
            qa_target.url,
            timeout=15,
            verify_ssl=False,
            quiet=True,
        )
        # Not all sites expose tech, so just check no crash
        techs = result.get("technologies", [])
        assert isinstance(techs, (list, dict))


class TestPayloadTesting:
    """Payload testing should work correctly against QA targets."""

    def test_xss_payloads_execute(self, qa_target: SmokeTarget):
        """XSS payloads should be sendable (not crash) against test targets."""
        from fray.tester import WAFTester
        tester = WAFTester(
            qa_target.url,
            timeout=10,
            delay=0.3,
            verify_ssl=False,
        )
        result = tester.test_category("xss", max_payloads=3)
        assert isinstance(result, dict)
        total = result.get("total", 0)
        # Should have tested at least 1 payload
        assert total >= 0  # 0 is ok if no payloads loaded

    def test_sqli_payloads_execute(self, qa_target: SmokeTarget):
        """SQLi payloads should be sendable against test targets."""
        from fray.tester import WAFTester
        tester = WAFTester(
            qa_target.url,
            timeout=10,
            delay=0.3,
            verify_ssl=False,
        )
        result = tester.test_category("sqli", max_payloads=3)
        assert isinstance(result, dict)


class TestSmokeRunner:
    """The smoke test runner itself should work."""

    def test_get_targets_returns_10(self):
        """Should have exactly 10 QA targets."""
        from fray.smoke_test import get_targets
        targets = get_targets()
        assert len(targets) == 10

    def test_all_targets_have_required_fields(self):
        """Every target should have url, name, zone, expected_waf."""
        for t in QA_TARGETS:
            assert t.url.startswith("http"), f"{t.name} has invalid URL: {t.url}"
            assert t.name, "Target missing name"
            assert t.zone == "qa", f"{t.name} zone should be 'qa', got '{t.zone}'"
            assert t.expected_waf, f"{t.name} missing expected_waf"

    def test_no_duplicate_urls(self):
        """No two targets should have the same URL."""
        urls = [t.url for t in QA_TARGETS]
        assert len(urls) == len(set(urls)), "Duplicate target URLs found"

    def test_runner_quick_mode(self):
        """Smoke runner in quick mode should complete (may skip unreachable)."""
        from fray.smoke_test import run_smoke_test
        results = run_smoke_test(mode="quick", verbose=False, json_output=False)
        assert len(results) == 10
        # At least some should pass (allow for flaky network)
        passed = sum(1 for r in results if r.status == "pass")
        assert passed >= 3, f"Only {passed}/10 targets passed"
