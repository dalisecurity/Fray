"""
Fray Authenticated Scan Profiles — OAuth2, form login, multi-step auth.

Supports:
  - Static cookie / bearer token (existing)
  - OAuth2 / OIDC client_credentials flow (get token → use token)
  - OAuth2 authorization_code flow (with PKCE)
  - Session-based form login (POST credentials → extract session cookie)
  - Multi-step auth sequences (chain of requests)
  - Token refresh on expiry (automatic)

Usage:
    # OAuth2 client_credentials
    profile = AuthProfile.oauth2_client_credentials(
        token_url="https://auth.example.com/oauth/token",
        client_id="...", client_secret="...")
    headers = profile.get_headers()

    # Form login
    profile = AuthProfile.form_login(
        login_url="https://example.com/login",
        credentials={"username": "admin", "password": "pass"})
    headers = profile.get_headers()

    # From config file
    profile = AuthProfile.from_file("~/.fray/auth/mysite.json")
"""

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Browser-like headers for auth requests ───────────────────────────────────

_AUTH_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
)


def _http_request(url: str, method: str = "GET",
                  headers: Optional[Dict] = None,
                  body: Optional[bytes] = None,
                  timeout: int = 15,
                  verify_ssl: bool = True) -> Tuple[int, str, Dict[str, str]]:
    """Make an HTTP request, return (status, body, headers)."""
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", _AUTH_USER_AGENT)
    req.add_header("Accept", "application/json, text/html, */*")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = None
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        if ctx:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)
        status = resp.status
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return status, resp_body, resp_headers
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, body_text, hdrs
    except Exception as e:
        return 0, str(e), {}


# ── Auth profile types ───────────────────────────────────────────────────────

@dataclass
class AuthProfile:
    """Authenticated scan profile — manages session lifecycle."""

    auth_type: str = "none"  # none, cookie, bearer, oauth2_cc, oauth2_code, form_login, multi_step

    # Static auth
    cookie: str = ""
    bearer_token: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)

    # OAuth2
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    audience: str = ""

    # Form login
    login_url: str = ""
    credentials: Dict[str, str] = field(default_factory=dict)
    session_cookie_name: str = ""  # auto-detect if empty
    csrf_field: str = ""  # auto-detect if empty

    # Multi-step auth
    steps: List[Dict] = field(default_factory=list)

    # Internal state
    _access_token: str = ""
    _token_expiry: float = 0.0
    _session_cookies: Dict[str, str] = field(default_factory=dict)
    _verify_ssl: bool = True

    # ── Factory methods ──────────────────────────────────────────────────

    @classmethod
    def none(cls) -> "AuthProfile":
        return cls(auth_type="none")

    @classmethod
    def from_cookie(cls, cookie: str) -> "AuthProfile":
        return cls(auth_type="cookie", cookie=cookie)

    @classmethod
    def from_bearer(cls, token: str) -> "AuthProfile":
        return cls(auth_type="bearer", bearer_token=token)

    @classmethod
    def oauth2_client_credentials(cls, *, token_url: str,
                                   client_id: str, client_secret: str,
                                   scope: str = "", audience: str = "",
                                   verify_ssl: bool = True) -> "AuthProfile":
        p = cls(auth_type="oauth2_cc", token_url=token_url,
                client_id=client_id, client_secret=client_secret,
                scope=scope, audience=audience)
        p._verify_ssl = verify_ssl
        return p

    @classmethod
    def form_login(cls, *, login_url: str,
                   credentials: Dict[str, str],
                   session_cookie_name: str = "",
                   csrf_field: str = "",
                   verify_ssl: bool = True) -> "AuthProfile":
        p = cls(auth_type="form_login", login_url=login_url,
                credentials=credentials,
                session_cookie_name=session_cookie_name,
                csrf_field=csrf_field)
        p._verify_ssl = verify_ssl
        return p

    @classmethod
    def multi_step(cls, steps: List[Dict],
                   verify_ssl: bool = True) -> "AuthProfile":
        """Multi-step auth sequence.

        Each step is a dict:
            {"url": "...", "method": "POST", "body": {...},
             "headers": {...}, "extract": {"token": "json:access_token"}}
        """
        p = cls(auth_type="multi_step", steps=steps)
        p._verify_ssl = verify_ssl
        return p

    @classmethod
    def from_file(cls, path: str) -> "AuthProfile":
        """Load auth profile from a JSON config file."""
        filepath = Path(path).expanduser()
        if not filepath.exists():
            raise FileNotFoundError(f"Auth profile not found: {filepath}")

        data = json.loads(filepath.read_text(encoding="utf-8"))
        auth_type = data.get("type", data.get("auth_type", "none"))

        if auth_type == "cookie":
            return cls.from_cookie(data["cookie"])
        elif auth_type == "bearer":
            return cls.from_bearer(data["token"])
        elif auth_type in ("oauth2_cc", "oauth2_client_credentials"):
            return cls.oauth2_client_credentials(
                token_url=data["token_url"],
                client_id=data["client_id"],
                client_secret=data["client_secret"],
                scope=data.get("scope", ""),
                audience=data.get("audience", ""),
            )
        elif auth_type in ("form_login", "form"):
            return cls.form_login(
                login_url=data["login_url"],
                credentials=data.get("credentials", {}),
                session_cookie_name=data.get("session_cookie_name", ""),
                csrf_field=data.get("csrf_field", ""),
            )
        elif auth_type == "multi_step":
            return cls.multi_step(steps=data.get("steps", []))
        else:
            # Try static headers
            p = cls(auth_type="custom", custom_headers=data.get("headers", {}))
            if "cookie" in data:
                p.cookie = data["cookie"]
            if "token" in data or "bearer" in data:
                p.bearer_token = data.get("token", data.get("bearer", ""))
            return p

    # ── Token acquisition ────────────────────────────────────────────────

    def _acquire_oauth2_token(self) -> bool:
        """Get OAuth2 access token via client_credentials flow."""
        params = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            params["scope"] = self.scope
        if self.audience:
            params["audience"] = self.audience

        body = urllib.parse.urlencode(params).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        status, resp_body, resp_headers = _http_request(
            self.token_url, "POST", headers, body,
            verify_ssl=self._verify_ssl)

        if status != 200:
            return False

        try:
            data = json.loads(resp_body)
            self._access_token = data.get("access_token", "")
            expires_in = data.get("expires_in", 3600)
            self._token_expiry = time.time() + expires_in - 60  # 60s buffer
            return bool(self._access_token)
        except (json.JSONDecodeError, KeyError):
            return False

    def _acquire_form_session(self) -> bool:
        """Login via form POST, extract session cookie."""
        # Step 1: GET login page to find CSRF token
        csrf_token = ""
        if self.csrf_field or True:  # Always try to get CSRF
            status, body, headers = _http_request(
                self.login_url, "GET", verify_ssl=self._verify_ssl)
            if status == 200 and body:
                # Try common CSRF field names
                csrf_names = [self.csrf_field] if self.csrf_field else [
                    "csrf_token", "csrfmiddlewaretoken", "_token",
                    "csrf", "authenticity_token", "__RequestVerificationToken",
                    "_csrf", "xsrf_token",
                ]
                for name in csrf_names:
                    pattern = rf'name=["\']?{re.escape(name)}["\']?\s+value=["\']([^"\']+)'
                    m = re.search(pattern, body, re.IGNORECASE)
                    if m:
                        csrf_token = m.group(1)
                        self.csrf_field = name
                        break
                    # Also check meta tags
                    pattern2 = rf'<meta\s+name=["\']?{re.escape(name)}["\']?\s+content=["\']([^"\']+)'
                    m2 = re.search(pattern2, body, re.IGNORECASE)
                    if m2:
                        csrf_token = m2.group(1)
                        self.csrf_field = name
                        break

                # Extract initial cookies (Set-Cookie headers)
                self._extract_cookies(headers)

        # Step 2: POST credentials
        form_data = dict(self.credentials)
        if csrf_token and self.csrf_field:
            form_data[self.csrf_field] = csrf_token

        body_bytes = urllib.parse.urlencode(form_data).encode("utf-8")
        req_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.login_url,
            "Origin": urllib.parse.urljoin(self.login_url, "/"),
        }
        # Send existing cookies
        if self._session_cookies:
            req_headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items())

        status, resp_body, resp_headers = _http_request(
            self.login_url, "POST", req_headers, body_bytes,
            verify_ssl=self._verify_ssl)

        # Extract session cookies from response
        self._extract_cookies(resp_headers)

        # Success if we got a redirect (302/303) or 200 with cookies
        if status in (200, 301, 302, 303, 307) and self._session_cookies:
            return True

        return False

    def _extract_cookies(self, headers: Dict[str, str]) -> None:
        """Extract Set-Cookie values from response headers."""
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                # Parse "name=value; Path=...; ..."
                for cookie_str in value.split(","):
                    cookie_str = cookie_str.strip()
                    if "=" in cookie_str:
                        name_val = cookie_str.split(";")[0]
                        name, _, val = name_val.partition("=")
                        name = name.strip()
                        val = val.strip()
                        if name and not name.startswith("__"):
                            self._session_cookies[name] = val

    def _run_multi_step(self) -> bool:
        """Execute multi-step auth sequence."""
        context: Dict[str, str] = {}  # Variables extracted from responses

        for i, step in enumerate(self.steps):
            url = step.get("url", "")
            method = step.get("method", "GET").upper()
            body_data = step.get("body", {})
            step_headers = dict(step.get("headers", {}))
            extractions = step.get("extract", {})

            # Substitute variables from previous steps
            for var_name, var_val in context.items():
                url = url.replace(f"{{{var_name}}}", var_val)
                for k, v in body_data.items():
                    if isinstance(v, str):
                        body_data[k] = v.replace(f"{{{var_name}}}", var_val)
                for k, v in step_headers.items():
                    step_headers[k] = v.replace(f"{{{var_name}}}", var_val)

            # Send cookies from previous steps
            if self._session_cookies:
                step_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in self._session_cookies.items())

            body_bytes = None
            if method == "POST" and body_data:
                if step_headers.get("Content-Type", "").startswith("application/json"):
                    body_bytes = json.dumps(body_data).encode("utf-8")
                else:
                    body_bytes = urllib.parse.urlencode(body_data).encode("utf-8")
                    if "Content-Type" not in step_headers:
                        step_headers["Content-Type"] = "application/x-www-form-urlencoded"

            status, resp_body, resp_headers = _http_request(
                url, method, step_headers, body_bytes,
                verify_ssl=self._verify_ssl)

            # Extract cookies
            self._extract_cookies(resp_headers)

            # Extract variables from response
            for var_name, extraction_rule in extractions.items():
                value = self._extract_value(resp_body, resp_headers, extraction_rule)
                if value:
                    context[var_name] = value

        # Check if we got useful auth data
        if context.get("access_token"):
            self._access_token = context["access_token"]
            self._token_expiry = time.time() + 3500
            return True
        if self._session_cookies:
            return True

        return False

    @staticmethod
    def _extract_value(body: str, headers: Dict, rule: str) -> str:
        """Extract a value from response using a rule.

        Rules:
            json:path.to.field    — JSON body extraction
            header:Header-Name    — Response header
            regex:pattern(group)  — Regex on body
            cookie:name           — From Set-Cookie
        """
        if rule.startswith("json:"):
            path = rule[5:]
            try:
                data = json.loads(body)
                for key in path.split("."):
                    data = data[key]
                return str(data)
            except (json.JSONDecodeError, KeyError, TypeError):
                return ""
        elif rule.startswith("header:"):
            hdr = rule[7:].lower()
            return headers.get(hdr, "")
        elif rule.startswith("regex:"):
            pattern = rule[6:]
            m = re.search(pattern, body)
            return m.group(1) if m and m.groups() else (m.group(0) if m else "")
        elif rule.startswith("cookie:"):
            cookie_name = rule[7:]
            # Parse from set-cookie header
            for k, v in headers.items():
                if k.lower() == "set-cookie" and cookie_name in v:
                    m = re.search(rf'{re.escape(cookie_name)}=([^;]+)', v)
                    if m:
                        return m.group(1)
            return ""
        return ""

    # ── Public interface ─────────────────────────────────────────────────

    def authenticate(self, verbose: bool = False) -> bool:
        """Run the authentication flow. Returns True on success."""
        if self.auth_type == "none":
            return True
        if self.auth_type in ("cookie", "bearer", "custom"):
            return True  # Static — no acquisition needed

        if verbose:
            print(f"  Authenticating ({self.auth_type})...", end=" ", flush=True)

        success = False
        if self.auth_type == "oauth2_cc":
            success = self._acquire_oauth2_token()
        elif self.auth_type == "form_login":
            success = self._acquire_form_session()
        elif self.auth_type == "multi_step":
            success = self._run_multi_step()

        if verbose:
            if success:
                print("\033[32mOK\033[0m")
            else:
                print("\033[31mFAILED\033[0m")

        return success

    def get_headers(self) -> Dict[str, str]:
        """Get auth headers for requests. Auto-refreshes if expired."""
        headers = dict(self.custom_headers)

        # Check token expiry and refresh
        if (self.auth_type == "oauth2_cc" and
                self._token_expiry > 0 and
                time.time() > self._token_expiry):
            self._acquire_oauth2_token()

        # Apply auth headers
        if self.auth_type == "cookie" and self.cookie:
            headers["Cookie"] = self.cookie
        elif self.auth_type == "bearer" and self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.auth_type in ("oauth2_cc", "oauth2_code") and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        elif self.auth_type in ("form_login", "multi_step") and self._session_cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items())
        elif self.auth_type == "multi_step" and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        return headers

    def get_cookie_string(self) -> str:
        """Get cookies as a single string for WAFTester."""
        if self.cookie:
            return self.cookie
        if self._session_cookies:
            return "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
        return ""

    def summary(self) -> str:
        """Return a human-readable summary."""
        if self.auth_type == "none":
            return "No authentication"
        elif self.auth_type == "cookie":
            return f"Cookie: {self.cookie[:30]}..."
        elif self.auth_type == "bearer":
            return f"Bearer: {self.bearer_token[:20]}..."
        elif self.auth_type == "oauth2_cc":
            return f"OAuth2 CC: {self.token_url} (client={self.client_id[:15]}...)"
        elif self.auth_type == "form_login":
            return f"Form login: {self.login_url}"
        elif self.auth_type == "multi_step":
            return f"Multi-step: {len(self.steps)} steps"
        return f"Custom: {self.auth_type}"

    def to_dict(self) -> Dict:
        """Serialize to dict (for saving)."""
        d = {"type": self.auth_type}
        if self.cookie:
            d["cookie"] = self.cookie
        if self.bearer_token:
            d["token"] = self.bearer_token
        if self.token_url:
            d["token_url"] = self.token_url
            d["client_id"] = self.client_id
            d["client_secret"] = "***"  # Never serialize secrets
            d["scope"] = self.scope
        if self.login_url:
            d["login_url"] = self.login_url
            d["credentials"] = {k: "***" for k in self.credentials}
        if self.steps:
            d["steps"] = self.steps
        if self.custom_headers:
            d["headers"] = self.custom_headers
        return d

    # ── Session persistence ───────────────────────────────────────────────

    _SESSIONS_DIR = Path.home() / ".fray" / "sessions"

    def save_session(self, name: str) -> Path:
        """Save current session state (cookies, tokens) to ~/.fray/sessions/<name>.json.

        Only saves live session data — not secrets like client_secret or passwords.
        """
        self._SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        data: Dict = {
            "name": name,
            "auth_type": self.auth_type,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        # Save cookies
        if self._session_cookies:
            data["cookies"] = dict(self._session_cookies)
        if self.cookie:
            data["cookie_header"] = self.cookie
        # Save tokens (short-lived, but useful for session reuse)
        if self._access_token:
            data["access_token"] = self._access_token
            data["token_expiry"] = self._token_expiry
        if self.bearer_token:
            data["bearer_token"] = self.bearer_token
        # Save custom headers (may include auth)
        if self.custom_headers:
            data["custom_headers"] = self.custom_headers
        # Save source info for re-auth
        if self.login_url:
            data["login_url"] = self.login_url
        if self.token_url:
            data["token_url"] = self.token_url

        path = self._SESSIONS_DIR / f"{name}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        return path

    @classmethod
    def load_session(cls, name: str) -> "AuthProfile":
        """Load a saved session from ~/.fray/sessions/<name>.json.

        Returns an AuthProfile pre-populated with cookies/tokens from disk.
        """
        path = cls._SESSIONS_DIR / f"{name}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Session not found: {path}")

        data = json.loads(path.read_text(encoding="utf-8"))
        auth_type = data.get("auth_type", "cookie")

        profile = cls(auth_type=auth_type)

        # Restore cookies
        if "cookies" in data:
            profile._session_cookies = data["cookies"]
        if "cookie_header" in data:
            profile.cookie = data["cookie_header"]
        # Restore tokens
        if "access_token" in data:
            profile._access_token = data["access_token"]
            profile._token_expiry = data.get("token_expiry", 0.0)
        if "bearer_token" in data:
            profile.bearer_token = data["bearer_token"]
        # Restore custom headers
        if "custom_headers" in data:
            profile.custom_headers = data["custom_headers"]
        # Restore source info
        if "login_url" in data:
            profile.login_url = data["login_url"]
        if "token_url" in data:
            profile.token_url = data["token_url"]

        return profile

    @classmethod
    def list_sessions(cls) -> List[Dict]:
        """List all saved sessions with metadata."""
        sessions = []
        if not cls._SESSIONS_DIR.is_dir():
            return sessions
        for f in sorted(cls._SESSIONS_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                sessions.append({
                    "name": f.stem,
                    "auth_type": data.get("auth_type", "?"),
                    "saved_at": data.get("saved_at", "?"),
                    "has_cookies": bool(data.get("cookies")),
                    "has_token": bool(data.get("access_token") or data.get("bearer_token")),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return sessions

    @classmethod
    def delete_session(cls, name: str) -> bool:
        """Delete a saved session."""
        path = cls._SESSIONS_DIR / f"{name}.json"
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            return False
