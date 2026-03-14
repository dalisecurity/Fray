#!/usr/bin/env python3
"""
TLS Fingerprint Spoofing — curl_cffi browser impersonation layer.

Modern WAFs (Cloudflare, Akamai, Imperva) fingerprint the TLS handshake
(JA3/JA4) and reject non-browser clients. Python's default ssl module has
a unique fingerprint that is trivially detected.

curl_cffi uses BoringSSL compiled with browser-specific TLS settings,
producing identical JA3/JA4 fingerprints to real browsers.

Usage:
    from fray.impersonate import ImpersonatedSession, AVAILABLE

    with ImpersonatedSession(browser="chrome") as s:
        r = s.get("https://target.com", timeout=10)
        print(r.status_code, r.text)

Falls back to stdlib requests-style if curl_cffi is not installed.
"""

import random
import time
from typing import Dict, Optional, Any

# ── Browser profiles ─────────────────────────────────────────────────────
# Ordered newest → oldest. We pick randomly from top 3 for variety.
CHROME_PROFILES = [
    "chrome142", "chrome136", "chrome133a", "chrome131",
    "chrome124", "chrome123", "chrome120", "chrome119",
]
FIREFOX_PROFILES = ["firefox144", "firefox135", "firefox133"]
SAFARI_PROFILES = ["safari184", "safari180", "safari172_ios"]
TOR_PROFILES = ["tor145"]

ALL_PROFILES = CHROME_PROFILES + FIREFOX_PROFILES + SAFARI_PROFILES

_HAS_CURL_CFFI = False
try:
    from curl_cffi import requests as _cffi_requests
    from curl_cffi.requests import Session as _CffiSession
    _HAS_CURL_CFFI = True
except ImportError:
    _cffi_requests = None
    _CffiSession = None

AVAILABLE = _HAS_CURL_CFFI


def pick_browser(preference: str = "chrome") -> str:
    """Pick a browser impersonation profile.

    Args:
        preference: "chrome", "firefox", "safari", "random", or exact profile name.

    Returns:
        A curl_cffi BrowserType string like "chrome142".
    """
    pref = preference.lower()
    if pref in ("chrome", "chr"):
        return random.choice(CHROME_PROFILES[:3])
    elif pref in ("firefox", "ff"):
        return random.choice(FIREFOX_PROFILES[:2])
    elif pref in ("safari", "saf"):
        return random.choice(SAFARI_PROFILES[:2])
    elif pref == "tor":
        return TOR_PROFILES[0]
    elif pref == "random":
        return random.choice(ALL_PROFILES[:6])
    # Exact profile name
    if pref in ALL_PROFILES + TOR_PROFILES:
        return pref
    return CHROME_PROFILES[0]


class ImpersonateResponse:
    """Unified response object that works with both curl_cffi and fallback."""

    def __init__(self, status_code: int = 0, headers: Optional[Dict] = None,
                 text: str = "", content: bytes = b"", url: str = "",
                 elapsed_ms: float = 0.0):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = content
        self.url = url
        self.elapsed_ms = elapsed_ms
        self.ok = 200 <= status_code < 400


class ImpersonatedSession:
    """HTTP session with browser TLS fingerprint impersonation.

    Falls back to urllib if curl_cffi is not installed.
    """

    def __init__(self, browser: str = "chrome", verify: bool = True,
                 timeout: int = 10, proxy: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None,
                 rotate: bool = False, rotate_every: int = 5):
        self.browser = pick_browser(browser)
        self._browser_pref = browser  # Original preference for rotation
        self.verify = verify
        self.timeout = timeout
        self.proxy = proxy
        self.extra_headers = headers or {}
        self._session = None
        self._rotate = rotate
        self._rotate_every = max(1, rotate_every)
        self._request_count = 0

        if _HAS_CURL_CFFI:
            self._session = _CffiSession(impersonate=self.browser)
        else:
            import warnings
            warnings.warn(
                "curl_cffi not installed — TLS fingerprint spoofing disabled. "
                "Install with: pip install curl_cffi",
                stacklevel=2,
            )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self._session and hasattr(self._session, 'close'):
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def _rotate_session(self):
        """Rotate to a different browser profile to look like multiple users."""
        if not _HAS_CURL_CFFI or not self._rotate:
            return
        self._request_count += 1
        if self._request_count % self._rotate_every != 0:
            return
        # Pick a different profile family each rotation
        _families = ["chrome", "firefox", "safari"]
        _current = self.browser.rstrip('0123456789_')
        _others = [f for f in _families if f != _current]
        _next_family = random.choice(_others) if _others else "chrome"
        new_browser = pick_browser(_next_family)
        if new_browser != self.browser:
            try:
                if self._session:
                    self._session.close()
            except Exception:
                pass
            self.browser = new_browser
            self._session = _CffiSession(impersonate=self.browser)

    def request(self, method: str, url: str, **kwargs) -> ImpersonateResponse:
        """Send an HTTP request with browser impersonation.

        Supports same kwargs as curl_cffi: headers, data, json, params, timeout, verify, cookies, allow_redirects.
        """
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify)
        if self.extra_headers:
            hdrs = dict(self.extra_headers)
            hdrs.update(kwargs.get('headers', {}))
            kwargs['headers'] = hdrs
        if self.proxy:
            kwargs.setdefault('proxies', {'https': self.proxy, 'http': self.proxy})

        t0 = time.monotonic()

        # Rotate browser profile periodically in stealth mode
        self._rotate_session()

        if self._session:
            # curl_cffi path — real TLS fingerprint spoofing
            try:
                r = self._session.request(method, url, **kwargs)
                elapsed = (time.monotonic() - t0) * 1000
                return ImpersonateResponse(
                    status_code=r.status_code,
                    headers=dict(r.headers) if r.headers else {},
                    text=r.text or "",
                    content=r.content or b"",
                    url=str(r.url) if r.url else url,
                    elapsed_ms=elapsed,
                )
            except Exception as e:
                elapsed = (time.monotonic() - t0) * 1000
                return ImpersonateResponse(
                    status_code=0,
                    text=f"Error: {e}",
                    elapsed_ms=elapsed,
                )
        else:
            # Fallback: urllib (no TLS spoofing)
            return self._fallback_request(method, url, t0, **kwargs)

    def get(self, url: str, **kwargs) -> ImpersonateResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> ImpersonateResponse:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> ImpersonateResponse:
        return self.request("HEAD", url, **kwargs)

    def _fallback_request(self, method: str, url: str, t0: float,
                          **kwargs) -> ImpersonateResponse:
        """Fallback using urllib when curl_cffi is not available."""
        import urllib.request
        import urllib.error
        import ssl as _ssl

        headers = kwargs.get('headers', {})
        data = kwargs.get('data')
        timeout = kwargs.get('timeout', self.timeout)
        verify = kwargs.get('verify', self.verify)

        if isinstance(data, str):
            data = data.encode('utf-8')

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

        ctx = None
        if url.startswith('https'):
            ctx = _ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = resp.read()
            elapsed = (time.monotonic() - t0) * 1000
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return ImpersonateResponse(
                status_code=resp.status,
                headers=resp_headers,
                text=body.decode('utf-8', errors='replace'),
                content=body,
                url=resp.url,
                elapsed_ms=elapsed,
            )
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - t0) * 1000
            body = e.read() if e.fp else b""
            return ImpersonateResponse(
                status_code=e.code,
                headers=dict(e.headers) if e.headers else {},
                text=body.decode('utf-8', errors='replace'),
                content=body,
                elapsed_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            return ImpersonateResponse(
                status_code=0,
                text=f"Error: {e}",
                elapsed_ms=elapsed,
            )


def impersonated_raw_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    browser: str = "chrome",
    timeout: int = 10,
    verify: bool = False,
) -> tuple:
    """One-shot impersonated request — convenience function.

    Returns (status_code, headers_dict, body_text, elapsed_ms).
    Same signature as tester._raw_request return tuple.
    """
    with ImpersonatedSession(browser=browser, verify=verify, timeout=timeout) as s:
        kwargs: Dict[str, Any] = {}
        if headers:
            kwargs['headers'] = headers
        if data:
            kwargs['data'] = data
        r = s.request(method, url, **kwargs)
        return r.status_code, r.headers, r.text, r.elapsed_ms
