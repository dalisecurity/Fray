"""Tests for fray.tester — WAFTester core functionality."""

import json
import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from fray.tester import WAFTester, _is_private_host


# ── _is_private_host ───────────────────────────────────────────────────

class TestIsPrivateHost:
    @patch('fray.tester.socket.gethostbyname', return_value='192.168.1.1')
    def test_private_ip(self, mock_dns):
        assert _is_private_host('internal.corp') is True

    @patch('fray.tester.socket.gethostbyname', return_value='127.0.0.1')
    def test_loopback(self, mock_dns):
        assert _is_private_host('localhost') is True

    @patch('fray.tester.socket.gethostbyname', return_value='8.8.8.8')
    def test_public_ip(self, mock_dns):
        assert _is_private_host('example.com') is False

    def test_empty_hostname(self):
        assert _is_private_host('') is True

    @patch('fray.tester.socket.gethostbyname', side_effect=__import__('socket').gaierror('DNS fail'))
    def test_dns_failure(self, mock_dns):
        assert _is_private_host('nonexistent.invalid') is False


# ── WAFTester.__init__ ─────────────────────────────────────────────────

class TestWAFTesterInit:
    def test_url_parsing_https(self):
        t = WAFTester('https://example.com/api/v1?q=1')
        assert t.host == 'example.com'
        assert t.port == 443
        assert t.use_ssl is True
        assert t.path == '/api/v1'
        assert t.query == 'q=1'

    def test_url_parsing_http(self):
        t = WAFTester('http://test.com:8080/path')
        assert t.host == 'test.com'
        assert t.port == 8080
        assert t.use_ssl is False
        assert t.path == '/path'

    def test_auto_https_prefix(self):
        t = WAFTester('example.com')
        assert t.use_ssl is True
        assert t.host == 'example.com'

    def test_default_path(self):
        t = WAFTester('https://example.com')
        assert t.path == '/'

    def test_stealth_mode_defaults(self):
        t = WAFTester('https://example.com', stealth=True)
        assert t.delay >= 1.0
        assert t.jitter >= 1.0
        assert t.rate_limit >= 2.0

    def test_stealth_preserves_higher_delay(self):
        t = WAFTester('https://example.com', stealth=True, delay=3.0)
        assert t.delay == 3.0

    def test_custom_headers(self):
        hdrs = {'Authorization': 'Bearer abc123'}
        t = WAFTester('https://example.com', custom_headers=hdrs)
        assert t.custom_headers == hdrs


# ── _build_post_body ───────────────────────────────────────────────────

class TestBuildPostBody:
    def setup_method(self):
        self.t = WAFTester('https://example.com')

    def test_default_form_urlencoded(self):
        ct, body = self.t._build_post_body('<script>', 'q', '%3Cscript%3E')
        assert ct == 'application/x-www-form-urlencoded'
        assert 'q=' in body

    def test_json_body(self):
        ct, body = self.t._build_post_body('<script>', 'q', '%3Cscript%3E',
                                           content_type='application/json')
        assert ct == 'application/json'
        parsed = json.loads(body)
        assert parsed['q'] == '<script>'

    def test_multipart_body(self):
        ct, body = self.t._build_post_body('payload', 'p', 'enc',
                                           content_type='multipart/form-data')
        assert 'multipart/form-data' in ct
        assert 'FrayBoundary' in ct
        assert 'Content-Disposition: form-data' in body
        assert 'payload' in body

    def test_xml_body(self):
        ct, body = self.t._build_post_body('payload', 'p', 'enc',
                                           content_type='text/xml')
        assert ct == 'text/xml'
        assert '<?xml' in body
        assert '<p>payload</p>' in body

    def test_plain_text_body(self):
        ct, body = self.t._build_post_body('payload', 'p', 'enc',
                                           content_type='text/plain')
        assert ct == 'text/plain'
        assert body == 'p=payload'

    def test_custom_content_type(self):
        ct, body = self.t._build_post_body('payload', 'p', 'enc',
                                           content_type='application/x-custom')
        assert ct == 'application/x-custom'


# ── _build_extra_headers ──────────────────────────────────────────────

class TestBuildExtraHeaders:
    def test_empty_headers(self):
        t = WAFTester('https://example.com')
        assert t._build_extra_headers() == ""

    def test_custom_headers_formatted(self):
        t = WAFTester('https://example.com', custom_headers={'X-Api-Key': 'abc'})
        hdr_str = t._build_extra_headers()
        assert 'X-Api-Key: abc\r\n' in hdr_str

    def test_crlf_injection_sanitized(self):
        t = WAFTester('https://example.com',
                      custom_headers={'Evil': 'val\r\nInjected: yes'})
        hdr_str = t._build_extra_headers()
        assert '\r\nInjected' not in hdr_str
        assert 'Evil: valInjected: yes\r\n' in hdr_str


# ── _get_stealth_headers ──────────────────────────────────────────────

class TestGetStealthHeaders:
    def test_no_stealth(self):
        t = WAFTester('https://example.com', stealth=False)
        assert t._get_stealth_headers() == ""

    def test_stealth_returns_ua(self):
        t = WAFTester('https://example.com', stealth=True)
        hdrs = t._get_stealth_headers()
        assert 'User-Agent:' in hdrs
        assert 'Accept-Language:' in hdrs


# ── _resolve_and_check ────────────────────────────────────────────────

class TestResolveAndCheck:
    def setup_method(self):
        self.t = WAFTester('https://example.com')

    @patch('fray.tester.socket.gethostbyname', return_value='93.184.216.34')
    def test_public_ip_ok(self, mock_dns):
        ip = self.t._resolve_and_check('example.com')
        assert ip == '93.184.216.34'

    @patch('fray.tester.socket.gethostbyname', return_value='10.0.0.1')
    def test_private_ip_blocked(self, mock_dns):
        with pytest.raises(ValueError, match='private/internal'):
            self.t._resolve_and_check('internal.corp')

    @patch('fray.tester.socket.gethostbyname', return_value='127.0.0.1')
    def test_loopback_blocked(self, mock_dns):
        with pytest.raises(ValueError, match='private/internal'):
            self.t._resolve_and_check('localhost')


# ── _raw_request (mocked socket) ──────────────────────────────────────

class TestRawRequest:
    def setup_method(self):
        self.t = WAFTester('https://example.com', verify_ssl=False)

    @patch('fray.tester.socket.create_connection')
    @patch('fray.tester.ssl.create_default_context')
    @patch.object(WAFTester, '_resolve_and_check', return_value='93.184.216.34')
    def test_basic_response_parsing(self, mock_resolve, mock_ssl_ctx, mock_conn):
        mock_sock = MagicMock()
        mock_wrapped = MagicMock()
        mock_conn.return_value = mock_sock
        mock_ssl_ctx.return_value.wrap_socket.return_value = mock_wrapped

        raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html>OK</html>"
        mock_wrapped.recv = MagicMock(side_effect=[raw_resp, b""])

        status, resp_str, headers, elapsed_ms = self.t._raw_request('example.com', 443, True,
                                                         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert status == 200
        assert 'content-type' in headers
        assert headers['server'] == 'nginx'
        assert '<html>OK</html>' in resp_str
        assert elapsed_ms >= 0

    @patch('fray.tester.socket.create_connection')
    @patch.object(WAFTester, '_resolve_and_check', return_value='93.184.216.34')
    def test_http_no_ssl(self, mock_resolve, mock_conn):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        raw_resp = b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked"
        mock_sock.recv = MagicMock(side_effect=[raw_resp, b""])

        t = WAFTester('http://example.com:80', verify_ssl=False)
        status, resp_str, headers, elapsed_ms = t._raw_request('example.com', 80, False,
                                                    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert status == 403
        assert elapsed_ms >= 0

    @patch.object(WAFTester, '_resolve_and_check', side_effect=ValueError('private/internal'))
    def test_private_ip_blocked(self, mock_resolve):
        with pytest.raises(ValueError, match='private/internal'):
            self.t._raw_request('evil.local', 443, True, "GET / HTTP/1.1\r\n\r\n")


# ── test_payload (block detection logic) ──────────────────────────────

class TestBlockDetection:
    def _make_tester_with_response(self, status, body, extra_headers=""):
        """Create a WAFTester that returns a canned response from _raw_request."""
        t = WAFTester('https://example.com')
        t._baseline = {'status': 200, 'response_length': 100, 'elapsed_ms': 50.0}
        raw = f"HTTP/1.1 {status} OK\r\n{extra_headers}\r\n\r\n{body}"
        headers = {}
        for line in extra_headers.split('\r\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        with patch.object(t, '_raw_request', return_value=(status, raw, headers, 50.0)):
            result = t.test_payload('<script>alert(1)</script>')
        return result

    def test_403_is_blocked(self):
        r = self._make_tester_with_response(403, 'Forbidden')
        assert r['blocked'] is True

    def test_200_is_not_blocked(self):
        r = self._make_tester_with_response(200, '<html>Normal page</html>')
        assert r['blocked'] is False

    def test_cloudflare_challenge_page(self):
        r = self._make_tester_with_response(200, '<html>Attention Required! Checking your browser</html>')
        assert r['blocked'] is True

    def test_akamai_block_page(self):
        r = self._make_tester_with_response(200, 'Access Denied. Reference #12345 Akamai')
        assert r['blocked'] is True

    def test_imperva_block_page(self):
        r = self._make_tester_with_response(200, 'Incident ID: abc123 Incapsula powered by Imperva')
        assert r['blocked'] is True

    def test_modsecurity_block(self):
        r = self._make_tester_with_response(200, 'ModSecurity blocked this request')
        assert r['blocked'] is True

    def test_captcha_challenge(self):
        r = self._make_tester_with_response(200, '<div class="recaptcha">Please verify you are human</div>')
        assert r['blocked'] is True

    def test_json_error_response(self):
        r = self._make_tester_with_response(200, '{"error": "forbidden", "code": 403}')
        assert r['blocked'] is True

    def test_aws_waf_block(self):
        r = self._make_tester_with_response(200, 'Request blocked by security policy - AWS WAF')
        assert r['blocked'] is True

    def test_sucuri_block(self):
        r = self._make_tester_with_response(200, 'Sucuri WebSite Firewall - Access Blocked')
        assert r['blocked'] is True

    def test_f5_bigip_block(self):
        r = self._make_tester_with_response(200, 'The requested URL was rejected. Please consult with your administrator.')
        assert r['blocked'] is True

    def test_generic_waf_message(self):
        r = self._make_tester_with_response(200, 'Web Application Firewall has blocked your request')
        assert r['blocked'] is True

    def test_reflection_detected(self):
        payload = '<script>alert(1)</script>'
        r = self._make_tester_with_response(200, f'<html>Search: {payload}</html>')
        assert r['blocked'] is False
        assert r['reflected'] is True
        assert payload in r['reflection_context']


# ── load_payloads ─────────────────────────────────────────────────────

class TestLoadPayloads:
    def setup_method(self):
        self.t = WAFTester('https://example.com')

    def test_load_json_with_payloads_key(self):
        data = {"payloads": [{"payload": "<script>", "category": "xss"}]}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = self.t.load_payloads(f.name)
        os.unlink(f.name)
        assert len(result) == 1
        assert result[0]['payload'] == '<script>'

    def test_load_json_bare_list(self):
        data = [{"payload": "test1"}, {"payload": "test2"}]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = self.t.load_payloads(f.name)
        os.unlink(f.name)
        assert len(result) == 2

    def test_load_txt_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("<script>alert(1)</script>\n")
            f.write("# comment line\n")
            f.write("\n")
            f.write("' OR 1=1--\n")
            f.flush()
            result = self.t.load_payloads(f.name)
        os.unlink(f.name)
        assert len(result) == 2
        assert result[0]['payload'] == '<script>alert(1)</script>'
        assert result[0]['category'] == 'custom'
        assert result[1]['payload'] == "' OR 1=1--"


# ── generate_report ───────────────────────────────────────────────────

class TestGenerateReport:
    def test_report_json_structure(self):
        t = WAFTester('https://example.com')
        t.start_time = __import__('datetime').datetime.now()
        results = [
            {'payload': 'p1', 'blocked': True},
            {'payload': 'p2', 'blocked': False},
            {'payload': 'p3', 'blocked': True},
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            outpath = f.name

        # Patch rich output to avoid terminal dependency
        with patch('fray.tester.WAFTester.generate_report.__module__', 'fray.tester'):
            with patch('fray.output.console'):
                with patch('fray.output.make_summary_table'):
                    with patch('rich.panel.Panel'):
                        try:
                            t.generate_report(results, output=outpath)
                        except Exception:
                            # Rich output may fail in test env; report file should still be written
                            pass

        with open(outpath) as f:
            report = json.load(f)
        os.unlink(outpath)

        assert report['target'] == 'https://example.com'
        assert report['summary']['total'] == 3
        assert report['summary']['blocked'] == 2
        assert report['summary']['passed'] == 1
        assert '66.67%' in report['summary']['block_rate']
