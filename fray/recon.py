#!/usr/bin/env python3
"""
Fray Recon — Target Reconnaissance & Fingerprinting

Before firing payloads, understand the target:
  1. HTTP check — port 80 open? redirects to HTTPS?
  2. TLS audit — version, cipher, cert validity
  3. Security headers — HSTS, CSP, XFO, XCTO, etc.
  4. App fingerprinting — WordPress, Drupal, PHP, Node, Java, .NET, etc.
  5. Smart payload recommendation — map stack → priority payloads

Usage:
    fray recon https://example.com
    fray recon https://example.com --json
"""

import http.client
import json
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── Tech → payload priority mapping ─────────────────────────────────────

_TECH_PAYLOAD_MAP: Dict[str, List[str]] = {
    "wordpress": ["sqli", "xss", "path_traversal", "command_injection", "ssrf"],
    "drupal": ["sqli", "ssti", "xss", "command_injection"],
    "joomla": ["sqli", "xss", "path_traversal", "command_injection"],
    "php": ["command_injection", "ssti", "path_traversal", "sqli", "xss"],
    "node.js": ["ssti", "ssrf", "xss", "command_injection"],
    "python": ["ssti", "ssrf", "command_injection", "sqli"],
    "java": ["sqli", "xxe", "ssti", "ssrf", "command_injection"],
    ".net": ["sqli", "xss", "path_traversal", "xxe"],
    "ruby": ["ssti", "command_injection", "sqli", "ssrf"],
    "nginx": ["path_traversal", "ssrf"],
    "apache": ["path_traversal", "ssrf"],
    "iis": ["path_traversal", "xss", "sqli"],
    "api_json": ["sqli", "ssrf", "command_injection", "ssti"],
    "react": ["xss"],
    "angular": ["xss", "ssti"],
    "vue": ["xss"],
}

# ── Fingerprint signatures ───────────────────────────────────────────────

_HEADER_FINGERPRINTS: Dict[str, Dict[str, str]] = {
    # header_name_lower -> {pattern: tech_name}
    "x-powered-by": {
        r"PHP": "php",
        r"Express": "node.js",
        r"ASP\.NET": ".net",
        r"Servlet": "java",
        r"Django": "python",
        r"Phusion Passenger": "ruby",
    },
    "server": {
        r"nginx": "nginx",
        r"Apache": "apache",
        r"Microsoft-IIS": "iis",
        r"Kestrel": ".net",
        r"Jetty": "java",
        r"Tomcat": "java",
        r"gunicorn": "python",
        r"Werkzeug": "python",
        r"uvicorn": "python",
        r"Cowboy": "node.js",
    },
    "x-drupal-cache": {
        r".*": "drupal",
    },
    "x-generator": {
        r"Drupal": "drupal",
        r"WordPress": "wordpress",
        r"Joomla": "joomla",
    },
}

_BODY_FINGERPRINTS: List[Tuple[str, str]] = [
    # (regex_pattern, tech_name)
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+[\d.]+', "wordpress"),
    (r'/wp-content/', "wordpress"),
    (r'/wp-includes/', "wordpress"),
    (r'/wp-json/', "wordpress"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "drupal"),
    (r'/misc/drupal\.js', "drupal"),
    (r'/sites/default/files', "drupal"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "joomla"),
    (r'/media/system/js/', "joomla"),
    (r'/administrator/', "joomla"),
    (r'<div\s+id=["\']app["\']', "vue"),
    (r'<div\s+id=["\']root["\']', "react"),
    (r'__NEXT_DATA__', "react"),
    (r'ng-app=', "angular"),
    (r'ng-version=', "angular"),
    (r'<script\s+src=[^>]*angular', "angular"),
    (r'csrfmiddlewaretoken', "python"),
    (r'__RequestVerificationToken', ".net"),
    (r'__VIEWSTATE', ".net"),
    (r'JSESSIONID', "java"),
    (r'laravel_session', "php"),
    (r'ci_session', "php"),
    (r'_rails', "ruby"),
    (r'X-Request-Id.*[a-f0-9-]{36}', "ruby"),
]

_COOKIE_FINGERPRINTS: Dict[str, str] = {
    "PHPSESSID": "php",
    "laravel_session": "php",
    "ci_session": "php",
    "JSESSIONID": "java",
    "connect.sid": "node.js",
    "ASP.NET_SessionId": ".net",
    "_rails": "ruby",
    "csrftoken": "python",
    "sessionid": "python",
    "wp-settings-": "wordpress",
    "wordpress_logged_in": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
}

# ── Security header checklist ────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "HTTP Strict Transport Security",
        "severity": "high",
    },
    "content-security-policy": {
        "name": "CSP",
        "description": "Content Security Policy",
        "severity": "high",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Clickjacking protection",
        "severity": "medium",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "MIME type sniffing prevention",
        "severity": "medium",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Browser XSS filter (legacy)",
        "severity": "low",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information",
        "severity": "low",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Browser feature permissions",
        "severity": "low",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "description": "Cross-Origin Opener Policy",
        "severity": "low",
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "description": "Cross-Origin Resource Policy",
        "severity": "low",
    },
}


# ── Core recon functions ─────────────────────────────────────────────────

def _parse_url(url: str) -> Tuple[str, str, int, bool]:
    """Parse URL into (scheme, host, port, use_ssl)."""
    if not url.startswith("http"):
        url = f"https://{url}"
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)
    path = parsed.path or "/"
    return host, path, port, use_ssl


def _make_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """Create an SSL context, optionally unverified."""
    if verify:
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(host: str, port: int, path: str, use_ssl: bool,
              timeout: int = 8, max_redirects: int = 5) -> Tuple[int, Dict[str, str], str]:
    """Make a raw HTTP GET, follow redirects, return (status, headers_dict, body)."""
    all_headers: Dict[str, str] = {}
    for _ in range(max_redirects + 1):
        try:
            if use_ssl:
                # Try verified first, fallback to unverified on cert errors
                try:
                    ctx = _make_ssl_context(verify=True)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers={
                        "Host": host,
                        "User-Agent": f"Fray/{__version__} Recon",
                        "Accept": "text/html,application/json,*/*",
                        "Connection": "close",
                    })
                    resp = conn.getresponse()
                except ssl.SSLError:
                    ctx = _make_ssl_context(verify=False)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers={
                        "Host": host,
                        "User-Agent": f"Fray/{__version__} Recon",
                        "Accept": "text/html,application/json,*/*",
                        "Connection": "close",
                    })
                    resp = conn.getresponse()
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": f"Fray/{__version__} Recon",
                    "Accept": "text/html,application/json,*/*",
                    "Connection": "close",
                })
                resp = conn.getresponse()

            status = resp.status
            headers = {k.lower(): v for k, v in resp.getheaders()}
            all_headers.update(headers)
            body = resp.read(200000).decode("utf-8", errors="replace")
            conn.close()

            if status in (301, 302, 303, 307, 308):
                location = headers.get("location", "")
                if location.startswith("https://") or location.startswith("http://"):
                    parsed = urllib.parse.urlparse(location)
                    host = parsed.hostname or host
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    use_ssl = parsed.scheme == "https"
                    path = parsed.path or "/"
                    if parsed.query:
                        path += f"?{parsed.query}"
                    continue
                elif location.startswith("/"):
                    path = location
                    continue
            return status, all_headers, body
        except Exception as e:
            return 0, all_headers, str(e)
    return status, all_headers, body


def check_http(host: str, timeout: int = 5) -> Dict[str, Any]:
    """Check if port 80 is open and whether it redirects to HTTPS."""
    result: Dict[str, Any] = {
        "port_80_open": False,
        "redirects_to_https": False,
        "http_status": 0,
    }
    try:
        sock = socket.create_connection((host, 80), timeout=timeout)
        sock.close()
        result["port_80_open"] = True
    except (socket.error, socket.timeout, OSError):
        return result

    # Check redirect
    status, headers, _ = _http_get(host, 80, "/", use_ssl=False, timeout=timeout)
    result["http_status"] = status
    if status in (301, 302, 307, 308):
        location = headers.get("location", "")
        if location.startswith("https://"):
            result["redirects_to_https"] = True
    return result


def check_tls(host: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    """Audit TLS configuration: version, cipher, certificate."""
    result: Dict[str, Any] = {
        "tls_version": None,
        "cipher": None,
        "cipher_bits": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_expired": None,
        "cert_days_remaining": None,
        "supports_tls_1_0": False,
        "supports_tls_1_1": False,
        "error": None,
    }

    # Main connection — best TLS version
    # Try verified first; fallback to unverified on cert errors (common on macOS)
    ssock = None
    for verify in (True, False):
        try:
            if verify:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            break
        except ssl.SSLError:
            if verify:
                continue  # Retry without verification
            result["error"] = "TLS handshake failed"
        except Exception as e:
            result["error"] = str(e)
            break

    if ssock:
        try:
            result["tls_version"] = ssock.version()
            cipher_info = ssock.cipher()
            if cipher_info:
                result["cipher"] = cipher_info[0]
                result["cipher_bits"] = cipher_info[2]

            cert = ssock.getpeercert()
            if cert:
                # Subject
                subject_parts = []
                for rdn in cert.get("subject", ()):
                    for attr_type, attr_value in rdn:
                        if attr_type == "commonName":
                            subject_parts.append(attr_value)
                result["cert_subject"] = ", ".join(subject_parts) or None

                # Issuer
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr_type, attr_value in rdn:
                        if attr_type in ("organizationName", "commonName"):
                            issuer_parts.append(attr_value)
                result["cert_issuer"] = ", ".join(issuer_parts) or None

                # Expiry
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        result["cert_expiry"] = expiry.isoformat()
                        now = datetime.now(timezone.utc)
                        delta = expiry - now
                        result["cert_days_remaining"] = delta.days
                        result["cert_expired"] = delta.days < 0
                    except ValueError:
                        result["cert_expiry"] = not_after

            ssock.close()
        except Exception as e:
            result["error"] = str(e)

    # Probe for weak TLS versions
    for proto_name, proto_const in [("tls_1_0", ssl.PROTOCOL_TLS), ("tls_1_1", ssl.PROTOCOL_TLS)]:
        try:
            ctx_weak = ssl.SSLContext(proto_const)
            ctx_weak.check_hostname = False
            ctx_weak.verify_mode = ssl.CERT_NONE
            if proto_name == "tls_1_0":
                ctx_weak.maximum_version = ssl.TLSVersion.TLSv1
            else:
                ctx_weak.maximum_version = ssl.TLSVersion.TLSv1_1
            sock = socket.create_connection((host, port), timeout=timeout)
            ssock = ctx_weak.wrap_socket(sock, server_hostname=host)
            version = ssock.version()
            ssock.close()
            if version and "TLSv1.0" in version:
                result["supports_tls_1_0"] = True
            elif version and "TLSv1.1" in version:
                result["supports_tls_1_1"] = True
        except Exception:
            pass  # Good — weak version not supported

    return result


def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Audit security headers from an HTTP response."""
    results: Dict[str, Any] = {
        "present": {},
        "missing": {},
        "score": 0,
    }

    total = len(_SECURITY_HEADERS)
    found = 0

    for header_key, info in _SECURITY_HEADERS.items():
        if header_key in headers:
            found += 1
            results["present"][info["name"]] = {
                "value": headers[header_key],
                "description": info["description"],
            }
        else:
            results["missing"][info["name"]] = {
                "description": info["description"],
                "severity": info["severity"],
            }

    results["score"] = round((found / total) * 100) if total > 0 else 0
    return results


def check_cookies(headers: Dict[str, str]) -> Dict[str, Any]:
    """Audit cookies for security flags: HttpOnly, Secure, SameSite, Path."""
    results: Dict[str, Any] = {
        "cookies": [],
        "issues": [],
        "score": 100,
    }

    # Collect all Set-Cookie headers. http.client merges them with ", " but
    # that's unreliable. We look for the raw header which may appear once or
    # be comma-joined. Split carefully on ", " only when followed by a cookie name=.
    raw = headers.get("set-cookie", "")
    if not raw:
        return results

    # Split on boundaries that look like a new cookie (name=value after ", ")
    cookie_strings = re.split(r',\s*(?=[A-Za-z0-9_.-]+=)', raw)

    for cs in cookie_strings:
        cs = cs.strip()
        if not cs or '=' not in cs:
            continue

        parts = cs.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=", 1)[0].strip()

        flags_raw = [p.strip().lower() for p in parts[1:]]
        flags_set = set(flags_raw)

        has_httponly = any("httponly" in f for f in flags_set)
        has_secure = any("secure" in f for f in flags_set)
        has_samesite = any("samesite" in f for f in flags_set)
        samesite_value = None
        for f in flags_raw:
            if f.startswith("samesite="):
                samesite_value = f.split("=", 1)[1].strip()
                break

        cookie_info: Dict[str, Any] = {
            "name": name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite_value or (True if has_samesite else None),
        }
        results["cookies"].append(cookie_info)

        # Flag issues
        if not has_httponly:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing HttpOnly flag",
                "severity": "high",
                "risk": "Cookie accessible via JavaScript — XSS can steal sessions",
            })
        if not has_secure:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing Secure flag",
                "severity": "high",
                "risk": "Cookie sent over HTTP — vulnerable to MITM interception",
            })
        if not has_samesite:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing SameSite attribute",
                "severity": "medium",
                "risk": "Vulnerable to CSRF attacks",
            })
        elif samesite_value and samesite_value.lower() == "none" and not has_secure:
            results["issues"].append({
                "cookie": name,
                "issue": "SameSite=None without Secure flag",
                "severity": "high",
                "risk": "Browser will reject this cookie (Chrome/Firefox require Secure with SameSite=None)",
            })

    # Score: deduct points per issue
    if results["cookies"]:
        deductions = len([i for i in results["issues"] if i["severity"] == "high"]) * 15
        deductions += len([i for i in results["issues"] if i["severity"] == "medium"]) * 8
        results["score"] = max(0, 100 - deductions)

    return results


def fingerprint_app(headers: Dict[str, str], body: str,
                    cookies_raw: str = "") -> Dict[str, Any]:
    """Detect technology stack from headers, body, and cookies."""
    detected: Dict[str, float] = {}  # tech -> confidence (0-1)

    def _add(tech: str, conf: float):
        detected[tech] = min(1.0, detected.get(tech, 0) + conf)

    # Header-based detection
    for header_name, patterns in _HEADER_FINGERPRINTS.items():
        value = headers.get(header_name, "")
        if not value:
            continue
        for pattern, tech in patterns.items():
            if re.search(pattern, value, re.IGNORECASE):
                _add(tech, 0.7)

    # Body-based detection
    for pattern, tech in _BODY_FINGERPRINTS:
        if re.search(pattern, body, re.IGNORECASE):
            _add(tech, 0.5)

    # Cookie-based detection
    cookie_str = cookies_raw or headers.get("set-cookie", "")
    for cookie_name, tech in _COOKIE_FINGERPRINTS.items():
        if cookie_name.lower() in cookie_str.lower():
            _add(tech, 0.6)

    # Content-type based hints
    ct = headers.get("content-type", "")
    if "application/json" in ct:
        _add("api_json", 0.4)

    # Sort by confidence
    sorted_tech = sorted(detected.items(), key=lambda x: x[1], reverse=True)

    return {
        "technologies": {t: round(c, 2) for t, c in sorted_tech},
        "primary": sorted_tech[0][0] if sorted_tech else None,
        "all": [t for t, _ in sorted_tech],
    }


def recommend_categories(fingerprint: Dict[str, Any]) -> List[str]:
    """Map detected technologies to recommended payload categories."""
    seen: Dict[str, float] = {}
    techs = fingerprint.get("technologies", {})

    for tech, confidence in techs.items():
        categories = _TECH_PAYLOAD_MAP.get(tech, [])
        for i, cat in enumerate(categories):
            # Higher priority (lower index) + higher confidence = higher score
            score = confidence * (1.0 - i * 0.1)
            if cat not in seen or seen[cat] < score:
                seen[cat] = score

    # Sort by score, filter to categories that actually exist
    available = {d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")}
    ranked = sorted(seen.items(), key=lambda x: x[1], reverse=True)
    return [cat for cat, _ in ranked if cat in available]


# ── Full recon pipeline ──────────────────────────────────────────────────

def run_recon(url: str, timeout: int = 8) -> Dict[str, Any]:
    """Run full reconnaissance on a target URL."""
    host, path, port, use_ssl = _parse_url(url)

    result: Dict[str, Any] = {
        "target": url,
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "http": {},
        "tls": {},
        "headers": {},
        "cookies": {},
        "fingerprint": {},
        "recommended_categories": [],
    }

    # 1. HTTP check
    result["http"] = check_http(host, timeout=timeout)

    # 2. TLS audit (only if HTTPS target or port 443)
    if use_ssl or port == 443:
        result["tls"] = check_tls(host, port=port, timeout=timeout)

    # 3. Fetch page for headers + body fingerprinting
    status, headers, body = _http_get(host, port, path, use_ssl, timeout=timeout)
    result["page_status"] = status

    # 4. Security headers
    result["headers"] = check_security_headers(headers)

    # 5. Cookie security audit
    result["cookies"] = check_cookies(headers)

    # 6. App fingerprinting
    result["fingerprint"] = fingerprint_app(headers, body)

    # 7. Smart payload recommendation
    result["recommended_categories"] = recommend_categories(result["fingerprint"])

    return result


def print_recon(result: Dict[str, Any]) -> None:
    """Pretty-print recon results to terminal."""
    print(f"\n{Colors.BOLD}Fray Recon — Target Reconnaissance{Colors.END}")
    print(f"{Colors.DIM}{'━' * 60}{Colors.END}")
    print(f"  Target: {Colors.CYAN}{result['target']}{Colors.END}")
    print(f"  Host:   {result['host']}")
    print()

    # HTTP
    http = result.get("http", {})
    port80 = http.get("port_80_open", False)
    redir = http.get("redirects_to_https", False)
    p80_icon = f"{Colors.YELLOW}⚠️  OPEN{Colors.END}" if port80 else f"{Colors.DIM}closed{Colors.END}"
    redir_icon = f"{Colors.GREEN}✅{Colors.END}" if redir else (f"{Colors.RED}❌{Colors.END}" if port80 else f"{Colors.DIM}N/A{Colors.END}")
    print(f"  {Colors.BOLD}HTTP{Colors.END}")
    print(f"    Port 80:           {p80_icon}")
    print(f"    Redirects to HTTPS: {redir_icon}")
    if port80 and not redir:
        print(f"    {Colors.RED}⚠️  HTTP traffic is not redirected to HTTPS!{Colors.END}")
    print()

    # TLS
    tls = result.get("tls", {})
    if tls and not tls.get("error"):
        version = tls.get("tls_version", "?")
        version_color = Colors.GREEN if "1.3" in str(version) else (Colors.YELLOW if "1.2" in str(version) else Colors.RED)
        print(f"  {Colors.BOLD}TLS{Colors.END}")
        print(f"    Version:    {version_color}{version}{Colors.END}")
        print(f"    Cipher:     {tls.get('cipher', '?')} ({tls.get('cipher_bits', '?')} bits)")
        print(f"    Subject:    {tls.get('cert_subject', '?')}")
        print(f"    Issuer:     {tls.get('cert_issuer', '?')}")
        days = tls.get("cert_days_remaining")
        if days is not None:
            if days < 0:
                print(f"    Expiry:     {Colors.RED}EXPIRED ({abs(days)} days ago){Colors.END}")
            elif days < 30:
                print(f"    Expiry:     {Colors.YELLOW}{days} days remaining{Colors.END}")
            else:
                print(f"    Expiry:     {Colors.GREEN}{days} days remaining{Colors.END}")
        if tls.get("supports_tls_1_0"):
            print(f"    {Colors.RED}⚠️  TLS 1.0 supported (insecure, should be disabled){Colors.END}")
        if tls.get("supports_tls_1_1"):
            print(f"    {Colors.RED}⚠️  TLS 1.1 supported (deprecated, should be disabled){Colors.END}")
        print()
    elif tls and tls.get("error"):
        print(f"  {Colors.BOLD}TLS{Colors.END}")
        print(f"    {Colors.RED}Error: {tls['error']}{Colors.END}")
        print()

    # Security headers
    hdr = result.get("headers", {})
    score = hdr.get("score", 0)
    score_color = Colors.GREEN if score >= 70 else (Colors.YELLOW if score >= 40 else Colors.RED)
    print(f"  {Colors.BOLD}Security Headers{Colors.END} ({score_color}{score}%{Colors.END})")
    for name, info in hdr.get("present", {}).items():
        print(f"    {Colors.GREEN}✅{Colors.END} {name}: {Colors.DIM}{info['value'][:60]}{Colors.END}")
    for name, info in hdr.get("missing", {}).items():
        sev = info.get("severity", "low")
        sev_color = Colors.RED if sev == "high" else (Colors.YELLOW if sev == "medium" else Colors.DIM)
        print(f"    {Colors.RED}❌{Colors.END} {name} {sev_color}({sev}){Colors.END}")
    print()

    # Cookies
    ck = result.get("cookies", {})
    cookies = ck.get("cookies", [])
    issues = ck.get("issues", [])
    if cookies:
        ck_score = ck.get("score", 100)
        ck_color = Colors.GREEN if ck_score >= 80 else (Colors.YELLOW if ck_score >= 50 else Colors.RED)
        print(f"  {Colors.BOLD}Cookies{Colors.END} ({ck_color}{ck_score}%{Colors.END})")
        for c in cookies:
            flags = []
            if c.get("httponly"):
                flags.append(f"{Colors.GREEN}HttpOnly{Colors.END}")
            else:
                flags.append(f"{Colors.RED}HttpOnly{Colors.END}")
            if c.get("secure"):
                flags.append(f"{Colors.GREEN}Secure{Colors.END}")
            else:
                flags.append(f"{Colors.RED}Secure{Colors.END}")
            ss = c.get("samesite")
            if ss and ss is not True:
                flags.append(f"{Colors.GREEN}SameSite={ss}{Colors.END}")
            elif ss is True:
                flags.append(f"{Colors.GREEN}SameSite{Colors.END}")
            else:
                flags.append(f"{Colors.RED}SameSite{Colors.END}")
            print(f"    {c['name']:<30} {' | '.join(flags)}")
        if issues:
            print()
            for iss in issues:
                sev = iss["severity"]
                sev_color = Colors.RED if sev == "high" else Colors.YELLOW
                print(f"    {sev_color}⚠ {iss['cookie']}: {iss['issue']}{Colors.END}")
                print(f"      {Colors.DIM}{iss['risk']}{Colors.END}")
        print()

    # Fingerprint
    fp = result.get("fingerprint", {})
    techs = fp.get("technologies", {})
    if techs:
        print(f"  {Colors.BOLD}Detected Technologies{Colors.END}")
        for tech, conf in techs.items():
            bar_len = int(conf * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            conf_color = Colors.GREEN if conf >= 0.7 else (Colors.YELLOW if conf >= 0.4 else Colors.DIM)
            print(f"    {tech:<16} {conf_color}{bar} {conf:.0%}{Colors.END}")
        print()
    else:
        print(f"  {Colors.BOLD}Detected Technologies{Colors.END}")
        print(f"    {Colors.DIM}No technologies identified{Colors.END}")
        print()

    # Recommended categories
    cats = result.get("recommended_categories", [])
    if cats:
        print(f"  {Colors.BOLD}Recommended Payload Categories{Colors.END} (priority order)")
        for i, cat in enumerate(cats, 1):
            print(f"    {i}. {Colors.CYAN}{cat}{Colors.END}")
        print()
        print(f"  {Colors.DIM}Usage: fray test <target> -c {cats[0]} --smart{Colors.END}")
    else:
        print(f"  {Colors.BOLD}Recommended Payload Categories{Colors.END}")
        print(f"    {Colors.DIM}No specific recommendations — use --smart for adaptive testing{Colors.END}")
    print()
