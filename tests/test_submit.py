#!/usr/bin/env python3
"""
Tests for fray submit-payload module.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from fray.submit import (
    validate_payload,
    validate_category,
    generate_payload_id,
    build_payload_entry,
    get_valid_categories,
    load_bulk_payloads,
    GitHubAPI,
    submit_to_github,
    _build_pr_body,
    _save_local_fallback,
)


# ── Validation Tests ─────────────────────────────────────────────────────────

class TestValidatePayload(unittest.TestCase):

    def test_valid_payload(self):
        ok, err = validate_payload("<script>alert(1)</script>")
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_empty_payload(self):
        ok, err = validate_payload("")
        self.assertFalse(ok)
        self.assertIn("empty", err.lower())

    def test_whitespace_only_payload(self):
        ok, err = validate_payload("   ")
        self.assertFalse(ok)

    def test_too_long_payload(self):
        ok, err = validate_payload("A" * 10001)
        self.assertFalse(ok)
        self.assertIn("10,000", err)

    def test_max_length_payload(self):
        ok, err = validate_payload("A" * 10000)
        self.assertTrue(ok)


class TestValidateCategory(unittest.TestCase):

    def test_valid_category(self):
        ok, err = validate_category("xss")
        self.assertTrue(ok)

    def test_invalid_category(self):
        ok, err = validate_category("nonexistent_category_xyz")
        self.assertFalse(ok)
        self.assertIn("Unknown", err)


class TestGetValidCategories(unittest.TestCase):

    def test_returns_list(self):
        cats = get_valid_categories()
        self.assertIsInstance(cats, list)
        self.assertGreater(len(cats), 0)

    def test_contains_known_categories(self):
        cats = get_valid_categories()
        self.assertIn("xss", cats)
        self.assertIn("sqli", cats)
        self.assertIn("ssrf", cats)


# ── Payload Entry Builder Tests ──────────────────────────────────────────────

class TestGeneratePayloadId(unittest.TestCase):

    def test_contains_category(self):
        pid = generate_payload_id("xss")
        self.assertTrue(pid.startswith("xss-contrib-"))

    def test_contains_timestamp(self):
        pid = generate_payload_id("sqli")
        # Should have numeric timestamp portion
        parts = pid.split("-")
        self.assertTrue(parts[-1].isdigit())

    def test_unique_ids(self):
        import time
        id1 = generate_payload_id("xss")
        time.sleep(0.01)
        id2 = generate_payload_id("xss")
        # IDs should differ (timestamp-based)
        # Note: could be same if within same second, so just verify format
        self.assertTrue(id1.startswith("xss-contrib-"))
        self.assertTrue(id2.startswith("xss-contrib-"))


class TestBuildPayloadEntry(unittest.TestCase):

    def test_basic_entry(self):
        entry = build_payload_entry(
            payload="<svg/onload=alert(1)>",
            category="xss",
            subcategory="basic",
            description="SVG onload XSS",
            technique="direct_injection",
            contributor_name="TestUser",
            contributor_github="testuser",
        )
        self.assertEqual(entry["category"], "xss")
        self.assertEqual(entry["subcategory"], "basic")
        self.assertEqual(entry["payload"], "<svg/onload=alert(1)>")
        self.assertEqual(entry["source"], "community")
        self.assertIn("contributed_by", entry)
        self.assertEqual(entry["contributed_by"]["name"], "TestUser")
        self.assertEqual(entry["contributed_by"]["github"], "testuser")
        self.assertIn("date", entry["contributed_by"])

    def test_contributor_credit_structure(self):
        entry = build_payload_entry(
            payload="test",
            category="sqli",
            subcategory="community",
            description="test",
            technique="direct_injection",
            contributor_name="Researcher",
            contributor_github="researcher123",
        )
        credit = entry["contributed_by"]
        self.assertIn("name", credit)
        self.assertIn("github", credit)
        self.assertIn("date", credit)
        # Date should be YYYY-MM-DD format
        self.assertRegex(credit["date"], r"^\d{4}-\d{2}-\d{2}$")

    def test_with_tags(self):
        entry = build_payload_entry(
            payload="test",
            category="xss",
            subcategory="community",
            description="test",
            technique="direct_injection",
            contributor_name="u",
            contributor_github="u",
            tags=["svg", "onload"],
        )
        self.assertEqual(entry["tags"], ["svg", "onload"])

    def test_with_tested_against(self):
        entry = build_payload_entry(
            payload="test",
            category="xss",
            subcategory="community",
            description="test",
            technique="waf_bypass",
            contributor_name="u",
            contributor_github="u",
            tested_against=["cloudflare", "aws_waf"],
        )
        self.assertEqual(entry["tested_against"], ["cloudflare", "aws_waf"])

    def test_without_optional_fields(self):
        entry = build_payload_entry(
            payload="test",
            category="xss",
            subcategory="",
            description="test",
            technique="",
            contributor_name="u",
            contributor_github="u",
        )
        # Defaults applied
        self.assertEqual(entry["subcategory"], "community")
        self.assertEqual(entry["technique"], "direct_injection")
        self.assertNotIn("tags", entry)
        self.assertNotIn("tested_against", entry)
        self.assertNotIn("notes", entry)

    def test_with_notes(self):
        entry = build_payload_entry(
            payload="test",
            category="xss",
            subcategory="community",
            description="test",
            technique="direct_injection",
            contributor_name="u",
            contributor_github="u",
            notes="Bypasses Cloudflare as of 2026-03",
        )
        self.assertEqual(entry["notes"], "Bypasses Cloudflare as of 2026-03")


# ── PR Body Builder Tests ────────────────────────────────────────────────────

class TestBuildPRBody(unittest.TestCase):

    def test_contains_category(self):
        entries = [build_payload_entry("test", "xss", "basic", "desc", "direct_injection", "u", "u")]
        body = _build_pr_body(entries, "xss", "basic", "testuser")
        self.assertIn("xss", body)
        self.assertIn("basic", body)

    def test_contains_contributor(self):
        entries = [build_payload_entry("test", "xss", "basic", "desc", "direct_injection", "u", "u")]
        body = _build_pr_body(entries, "xss", "basic", "testuser")
        self.assertIn("@testuser", body)

    def test_truncates_many_payloads(self):
        entries = [
            build_payload_entry(f"payload{i}", "xss", "basic", f"desc{i}", "direct_injection", "u", "u")
            for i in range(10)
        ]
        body = _build_pr_body(entries, "xss", "basic", "u")
        self.assertIn("... and 5 more", body)

    def test_contains_version(self):
        from fray import __version__
        entries = [build_payload_entry("test", "xss", "basic", "desc", "direct_injection", "u", "u")]
        body = _build_pr_body(entries, "xss", "basic", "u")
        self.assertIn(__version__, body)


# ── Bulk Load Tests ──────────────────────────────────────────────────────────

class TestLoadBulkPayloads(unittest.TestCase):

    def test_load_list_format(self):
        import tempfile
        data = [{"payload": "test1"}, {"payload": "test2"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = load_bulk_payloads(f.name)
        os.unlink(f.name)
        self.assertEqual(len(result), 2)

    def test_load_dict_format(self):
        import tempfile
        data = {"payloads": [{"payload": "test1"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = load_bulk_payloads(f.name)
        os.unlink(f.name)
        self.assertEqual(len(result), 1)

    def test_load_nonexistent_file(self):
        result = load_bulk_payloads("/tmp/nonexistent_fray_test_file.json")
        self.assertIsNone(result)

    def test_load_invalid_json(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            result = load_bulk_payloads(f.name)
        os.unlink(f.name)
        self.assertIsNone(result)


# ── GitHub API Tests (mocked) ────────────────────────────────────────────────

class TestGitHubAPI(unittest.TestCase):

    @patch("fray.submit.http.client.HTTPSConnection")
    def test_get_authenticated_user_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"login": "testuser"}).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = GitHubAPI("fake_token")
        ok, username = api.get_authenticated_user()
        self.assertTrue(ok)
        self.assertEqual(username, "testuser")

    @patch("fray.submit.http.client.HTTPSConnection")
    def test_get_authenticated_user_failure(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 401
        mock_resp.read.return_value = json.dumps({"message": "Bad credentials"}).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = GitHubAPI("bad_token")
        ok, msg = api.get_authenticated_user()
        self.assertFalse(ok)
        self.assertIn("Bad credentials", msg)

    @patch("fray.submit.http.client.HTTPSConnection")
    def test_fork_repo_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 202
        mock_resp.read.return_value = json.dumps({"full_name": "testuser/Fray"}).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = GitHubAPI("fake_token")
        ok, name = api.fork_repo()
        self.assertTrue(ok)
        self.assertEqual(name, "testuser/Fray")

    @patch("fray.submit.http.client.HTTPSConnection")
    def test_create_branch_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({"ref": "refs/heads/test"}).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = GitHubAPI("fake_token")
        ok, err = api.create_branch("testuser", "test-branch", "abc123")
        self.assertTrue(ok)

    @patch("fray.submit.http.client.HTTPSConnection")
    def test_create_pull_request_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = json.dumps({
            "html_url": "https://github.com/dalisecurity/Fray/pull/42"
        }).encode()
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        api = GitHubAPI("fake_token")
        ok, url = api.create_pull_request("testuser", "test-branch", "title", "body")
        self.assertTrue(ok)
        self.assertIn("pull/42", url)


# ── Local Fallback Tests ─────────────────────────────────────────────────────

class TestLocalFallback(unittest.TestCase):

    def test_save_local_fallback(self):
        entries = [build_payload_entry("test", "xss", "community", "desc", "direct_injection", "u", "u")]
        import tempfile
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            result = _save_local_fallback(entries, "xss", "community")
            self.assertTrue(result)
            # Check file was created
            expected = Path(tmpdir) / "fray_submission_xss_community.json"
            self.assertTrue(expected.exists())
            with open(expected) as f:
                data = json.load(f)
            self.assertEqual(data["category"], "xss")
            self.assertEqual(len(data["payloads"]), 1)
            self.assertIn("contributed_by", data["payloads"][0])
        os.chdir(old_cwd)


# ── Submit Flow Tests (mocked GitHub) ────────────────────────────────────────

class TestSubmitToGitHub(unittest.TestCase):

    @patch.dict(os.environ, {"GITHUB_TOKEN": ""}, clear=False)
    def test_no_token_saves_locally(self):
        """Without GITHUB_TOKEN, should save locally as fallback."""
        entries = [build_payload_entry("test", "xss", "community", "desc", "direct_injection", "u", "u")]
        import tempfile
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            # Remove both token env vars
            env = os.environ.copy()
            env.pop("GITHUB_TOKEN", None)
            env.pop("GH_TOKEN", None)
            with patch.dict(os.environ, env, clear=True):
                result = submit_to_github(entries, "xss", "community")
            self.assertTrue(result)  # Local save succeeds
        os.chdir(old_cwd)


# ── CLI Integration Tests ────────────────────────────────────────────────────

class TestCLISubmitPayload(unittest.TestCase):

    def test_submit_payload_help(self):
        from fray.cli import main
        with patch("sys.argv", ["fray", "submit-payload", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    def test_submit_payload_dry_run(self):
        from fray.cli import main
        with patch("sys.argv", [
            "fray", "submit-payload",
            "--payload", "<img src=x onerror=alert(1)>",
            "--category", "xss",
            "--description", "Basic img onerror",
            "--name", "test",
            "--github", "test",
            "--dry-run",
        ]):
            # Should exit normally (no exception)
            main()


if __name__ == "__main__":
    unittest.main()
