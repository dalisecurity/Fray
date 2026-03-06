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
import time
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
    "php": ["command_injection", "ssti", "path_traversal", "sqli", "xss", "host_header_injection"],
    "node.js": ["ssti", "ssrf", "xss", "command_injection", "prototype_pollution", "host_header_injection"],
    "express": ["prototype_pollution", "ssti", "ssrf", "xss", "command_injection", "host_header_injection"],
    "python": ["ssti", "ssrf", "command_injection", "sqli", "host_header_injection"],
    "java": ["sqli", "xxe", "ssti", "ssrf", "command_injection", "host_header_injection"],
    ".net": ["sqli", "xss", "path_traversal", "xxe", "host_header_injection"],
    "ruby": ["ssti", "command_injection", "sqli", "ssrf", "host_header_injection"],
    "nginx": ["path_traversal", "ssrf"],
    "apache": ["path_traversal", "ssrf"],
    "iis": ["path_traversal", "xss", "sqli"],
    "api_json": ["sqli", "ssrf", "command_injection", "ssti", "prototype_pollution"],
    "react": ["xss"],
    "angular": ["xss", "ssti"],
    "vue": ["xss"],
}

# ── Fingerprint signatures ───────────────────────────────────────────────

_HEADER_FINGERPRINTS: Dict[str, Dict[str, str]] = {
    # header_name_lower -> {pattern: tech_name}
    "x-powered-by": {
        r"PHP": "php",
        r"Express": "express",
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
              timeout: int = 8, max_redirects: int = 5,
              extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
    """Make a raw HTTP GET, follow redirects, return (status, headers_dict, body)."""
    all_headers: Dict[str, str] = {}
    for _ in range(max_redirects + 1):
        try:
            req_headers = {
                "Host": host,
                "User-Agent": f"Fray/{__version__} Recon",
                "Accept": "text/html,application/json,*/*",
                "Connection": "close",
            }
            if extra_headers:
                req_headers.update(extra_headers)

            if use_ssl:
                # Try verified first, fallback to unverified on cert errors
                try:
                    ctx = _make_ssl_context(verify=True)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=req_headers)
                    resp = conn.getresponse()
                except ssl.SSLError:
                    ctx = _make_ssl_context(verify=False)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=req_headers)
                    resp = conn.getresponse()
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path, headers=req_headers)
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


# ── Extended recon checks ────────────────────────────────────────────────

def check_robots_sitemap(host: str, port: int, use_ssl: bool,
                         timeout: int = 8) -> Dict[str, Any]:
    """Parse robots.txt and sitemap.xml for hidden paths."""
    result: Dict[str, Any] = {
        "robots_txt": False,
        "disallowed_paths": [],
        "sitemaps": [],
        "interesting_paths": [],
    }

    # robots.txt
    status, _, body = _http_get(host, port, "/robots.txt", use_ssl, timeout=timeout)
    if status == 200 and body and "disallow" in body.lower():
        result["robots_txt"] = True
        interesting_keywords = ("admin", "api", "backup", "config", "dashboard",
                                "debug", "internal", "login", "manage", "panel",
                                "private", "secret", "staging", "test", "upload",
                                "wp-admin", "cgi-bin", ".env", "xmlrpc")
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    result["disallowed_paths"].append(path)
                    if any(kw in path.lower() for kw in interesting_keywords):
                        result["interesting_paths"].append(path)
            elif line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                result["sitemaps"].append(sm)

    # sitemap.xml (if no sitemaps found in robots.txt)
    if not result["sitemaps"]:
        status, _, body = _http_get(host, port, "/sitemap.xml", use_ssl, timeout=timeout)
        if status == 200 and body and "<urlset" in body.lower():
            result["sitemaps"].append(f"{'https' if use_ssl else 'http'}://{host}/sitemap.xml")

    return result


def check_dns(host: str) -> Dict[str, Any]:
    """Lookup DNS records for the host."""
    result: Dict[str, Any] = {
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "txt": [],
        "ns": [],
        "cdn_detected": None,
    }

    import subprocess

    # A records
    for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
        try:
            out = subprocess.run(
                ["dig", "+short", rtype, host],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip().rstrip(".") for l in out.stdout.strip().splitlines() if l.strip()]
            result[rtype.lower()] = lines
        except Exception:
            pass

    # CDN detection from CNAME / NS / A
    cdn_indicators = {
        "cloudflare": ["cloudflare", "cf-"],
        "cloudfront": ["cloudfront.net"],
        "akamai": ["akamai", "edgesuite", "edgekey"],
        "fastly": ["fastly"],
        "incapsula": ["incapsula", "imperva"],
        "sucuri": ["sucuri"],
        "stackpath": ["stackpath", "highwinds"],
        "azure_cdn": ["azureedge", "azure", "msecnd"],
        "google_cdn": ["googleusercontent", "googlevideo"],
    }
    all_dns_values = " ".join(
        result.get("cname", []) + result.get("ns", []) + result.get("a", [])
    ).lower()
    for cdn_name, patterns in cdn_indicators.items():
        if any(p in all_dns_values for p in patterns):
            result["cdn_detected"] = cdn_name
            break

    # SPF/DMARC from TXT records
    txt_joined = " ".join(result.get("txt", [])).lower()
    result["has_spf"] = "v=spf1" in txt_joined
    result["has_dmarc"] = False
    # DMARC is at _dmarc subdomain
    try:
        out = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{host}"],
            capture_output=True, text=True, timeout=5
        )
        if "v=dmarc1" in out.stdout.lower():
            result["has_dmarc"] = True
    except Exception:
        pass

    return result


def check_subdomains_crt(host: str, timeout: int = 10) -> Dict[str, Any]:
    """Enumerate subdomains via crt.sh certificate transparency logs."""
    result: Dict[str, Any] = {
        "subdomains": [],
        "count": 0,
        "error": None,
    }

    # Strip www. prefix for broader search
    search_domain = host.lstrip("www.")

    try:
        status, body = _follow_redirect(
            "crt.sh", f"/?q=%25.{search_domain}&output=json",
            timeout=timeout
        )
        if status == 200 and body:
            import json as _json
            entries = _json.loads(body.decode("utf-8", errors="replace"))
            subs = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and "*" not in line and line.endswith(search_domain):
                        subs.add(line)
            result["subdomains"] = sorted(subs)[:100]  # Cap at 100
            result["count"] = len(subs)
    except Exception as e:
        result["error"] = str(e)

    return result


def _follow_redirect(host: str, path: str, timeout: int = 10,
                     max_hops: int = 3) -> Tuple[int, bytes]:
    """Follow HTTPS redirects, return (status, body_bytes)."""
    for _ in range(max_hops + 1):
        try:
            ctx = _make_ssl_context(verify=True)
        except Exception:
            ctx = _make_ssl_context(verify=False)
        try:
            conn = http.client.HTTPSConnection(host, context=ctx, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": f"Fray/{__version__}"})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
            if status in (301, 302, 303, 307, 308):
                loc = hdrs.get("location", "")
                if loc.startswith("https://"):
                    parsed = urllib.parse.urlparse(loc)
                    host = parsed.hostname or host
                    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                    continue
            return status, body
        except Exception:
            return 0, b""
    return 0, b""


def check_cors(host: str, port: int, use_ssl: bool,
               timeout: int = 8) -> Dict[str, Any]:
    """Check for CORS misconfiguration."""
    result: Dict[str, Any] = {
        "cors_enabled": False,
        "allow_origin": None,
        "allow_credentials": False,
        "misconfigured": False,
        "issues": [],
    }

    scheme = "https" if use_ssl else "http"
    evil_origin = "https://evil.attacker.com"

    try:
        if use_ssl:
            try:
                ctx = _make_ssl_context(verify=True)
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
            except Exception:
                ctx = _make_ssl_context(verify=False)
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", "/", headers={
            "Host": host,
            "Origin": evil_origin,
            "User-Agent": f"Fray/{__version__} Recon",
        })
        resp = conn.getresponse()
        resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao:
            result["cors_enabled"] = True
            result["allow_origin"] = acao

            if acac == "true":
                result["allow_credentials"] = True

            # Check for dangerous configs
            if acao == "*":
                result["misconfigured"] = True
                result["issues"].append({
                    "issue": "Wildcard Access-Control-Allow-Origin",
                    "severity": "medium",
                    "risk": "Any website can read responses from this origin",
                })
            if acao == evil_origin:
                result["misconfigured"] = True
                result["issues"].append({
                    "issue": "Origin reflected without validation",
                    "severity": "high",
                    "risk": "Attacker-controlled origin is trusted — data theft possible",
                })
            if acao == evil_origin and acac == "true":
                result["issues"].append({
                    "issue": "Reflected origin + credentials allowed",
                    "severity": "critical",
                    "risk": "Full account takeover possible — attacker can read authenticated responses",
                })
            if acao == "null":
                result["misconfigured"] = True
                result["issues"].append({
                    "issue": "Access-Control-Allow-Origin: null",
                    "severity": "medium",
                    "risk": "Sandboxed iframes can exploit null origin",
                })
    except Exception:
        pass

    return result


def check_exposed_files(host: str, port: int, use_ssl: bool,
                        timeout: int = 5) -> Dict[str, Any]:
    """Probe for commonly exposed sensitive files."""
    result: Dict[str, Any] = {
        "exposed": [],
        "checked": 0,
    }

    probes = [
        ("/.env", "Environment variables (credentials, API keys)"),
        ("/.git/HEAD", "Git repository (source code exposure)"),
        ("/.git/config", "Git config (repo URL, credentials)"),
        ("/.svn/entries", "SVN repository metadata"),
        ("/wp-config.php.bak", "WordPress config backup (DB creds)"),
        ("/web.config", ".NET configuration file"),
        ("/.htaccess", "Apache configuration (may leak paths)"),
        ("/.htpasswd", "Apache password file"),
        ("/server-status", "Apache server status page"),
        ("/server-info", "Apache server info page"),
        ("/phpinfo.php", "PHP info page (full server details)"),
        ("/info.php", "PHP info page"),
        ("/debug", "Debug endpoint"),
        ("/actuator", "Spring Boot actuator (Java)"),
        ("/actuator/env", "Spring Boot environment variables"),
        ("/elmah.axd", ".NET error log"),
        ("/trace.axd", ".NET trace log"),
        ("/.well-known/security.txt", "Security contact info"),
        ("/crossdomain.xml", "Flash cross-domain policy"),
        ("/sitemap.xml.gz", "Compressed sitemap"),
        ("/backup.sql", "Database backup"),
        ("/dump.sql", "Database dump"),
        ("/db.sql", "Database file"),
        ("/.DS_Store", "macOS directory metadata"),
        ("/composer.json", "PHP dependency file (versions exposed)"),
        ("/package.json", "Node.js dependency file"),
        ("/Gemfile", "Ruby dependency file"),
        ("/requirements.txt", "Python dependency file"),
    ]

    for probe_path, description in probes:
        result["checked"] += 1
        try:
            status, headers, body = _http_get(
                host, port, probe_path, use_ssl, timeout=timeout, max_redirects=0
            )
            if status == 200 and len(body) > 0:
                # Verify it's not a generic 200 page (soft 404)
                is_real = False
                if probe_path == "/.git/HEAD" and body.strip().startswith("ref:"):
                    is_real = True
                elif probe_path == "/.git/config" and "[core]" in body:
                    is_real = True
                elif probe_path == "/.env" and "=" in body and len(body) < 50000:
                    is_real = True
                elif probe_path.endswith(".sql") and ("CREATE TABLE" in body or "INSERT INTO" in body):
                    is_real = True
                elif probe_path == "/phpinfo.php" and "phpinfo()" in body:
                    is_real = True
                elif probe_path == "/info.php" and "phpinfo()" in body:
                    is_real = True
                elif probe_path == "/actuator" and len(body) < 10000 and ('"_links"' in body or '"status"' in body):
                    is_real = True
                elif probe_path == "/actuator/env" and len(body) < 50000 and "propertySources" in body:
                    is_real = True
                elif probe_path == "/server-status" and "Apache Server Status" in body:
                    is_real = True
                elif probe_path == "/server-info" and "Apache Server Information" in body:
                    is_real = True
                elif probe_path == "/debug" and len(body) < 5000 and ("debug" in body.lower()[:200]):
                    is_real = True
                elif probe_path == "/.well-known/security.txt" and ("contact:" in body.lower() or "policy:" in body.lower()):
                    is_real = True
                elif probe_path == "/composer.json" and '"require"' in body:
                    is_real = True
                elif probe_path == "/package.json" and '"dependencies"' in body:
                    is_real = True
                elif probe_path == "/requirements.txt" and "==" in body:
                    is_real = True
                elif probe_path == "/Gemfile" and "gem " in body:
                    is_real = True
                # For other probes, be more cautious — skip if body is too large (likely custom 404)
                elif len(body) < 5000 and status == 200:
                    is_real = True

                if is_real:
                    severity = "critical"
                    if probe_path in ("/.well-known/security.txt", "/crossdomain.xml",
                                      "/sitemap.xml.gz"):
                        severity = "info"
                    elif probe_path in ("/composer.json", "/package.json",
                                        "/requirements.txt", "/Gemfile"):
                        severity = "medium"
                    result["exposed"].append({
                        "path": probe_path,
                        "description": description,
                        "status": status,
                        "size": len(body),
                        "severity": severity,
                    })
        except Exception:
            pass

    return result


def check_http_methods(host: str, port: int, use_ssl: bool,
                       timeout: int = 5) -> Dict[str, Any]:
    """Check allowed HTTP methods via OPTIONS request."""
    result: Dict[str, Any] = {
        "allowed_methods": [],
        "dangerous_methods": [],
        "issues": [],
    }

    try:
        if use_ssl:
            try:
                ctx = _make_ssl_context(verify=True)
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
            except Exception:
                ctx = _make_ssl_context(verify=False)
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("OPTIONS", "/", headers={
            "Host": host,
            "User-Agent": f"Fray/{__version__} Recon",
        })
        resp = conn.getresponse()
        resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        allow = headers.get("allow", headers.get("access-control-allow-methods", ""))
        if allow:
            methods = [m.strip().upper() for m in allow.split(",")]
            result["allowed_methods"] = methods

            dangerous = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
            found_dangerous = [m for m in methods if m in dangerous]
            result["dangerous_methods"] = found_dangerous

            if "TRACE" in found_dangerous:
                result["issues"].append({
                    "method": "TRACE",
                    "severity": "high",
                    "risk": "Cross-Site Tracing (XST) — can steal credentials via XSS",
                })
            if "PUT" in found_dangerous:
                result["issues"].append({
                    "method": "PUT",
                    "severity": "medium",
                    "risk": "File upload via PUT — may allow arbitrary file writes",
                })
            if "DELETE" in found_dangerous:
                result["issues"].append({
                    "method": "DELETE",
                    "severity": "medium",
                    "risk": "Resource deletion — may allow unauthorized deletions",
                })
    except Exception:
        pass

    return result


def check_error_page(host: str, port: int, use_ssl: bool,
                     timeout: int = 5) -> Dict[str, Any]:
    """Fetch a 404 page to fingerprint framework/version from error output."""
    result: Dict[str, Any] = {
        "status": 0,
        "server_header": None,
        "framework_hints": [],
        "version_leaks": [],
        "stack_trace": False,
    }

    random_path = f"/fray-recon-{int(datetime.now().timestamp())}-404"
    status, headers, body = _http_get(host, port, random_path, use_ssl, timeout=timeout)
    result["status"] = status
    result["server_header"] = headers.get("server")

    if not body:
        return result

    # Stack trace detection
    stack_patterns = [
        r"Traceback \(most recent call last\)",  # Python
        r"at\s+[\w.$]+\([\w.]+\.java:\d+\)",     # Java
        r"#\d+\s+[\w\\/:]+\.php\(\d+\)",          # PHP
        r"at\s+[\w.]+\s+in\s+[\w\\/:.]+:\d+",     # .NET
        r"Error:.*\n\s+at\s+",                     # Node.js
    ]
    for pat in stack_patterns:
        if re.search(pat, body):
            result["stack_trace"] = True
            break

    # Version leaks
    version_patterns = [
        (r"Apache/([\d.]+)", "Apache"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"Microsoft-IIS/([\d.]+)", "IIS"),
        (r"PHP/([\d.]+)", "PHP"),
        (r"X-Powered-By:\s*Express", "Express.js"),
        (r"Django.*?([\d.]+)", "Django"),
        (r"Laravel.*?([\d.]+)", "Laravel"),
        (r"Rails.*?([\d.]+)", "Rails"),
        (r"WordPress\s+([\d.]+)", "WordPress"),
        (r"Drupal\s+([\d.]+)", "Drupal"),
        (r"ASP\.NET\s+Version:([\d.]+)", "ASP.NET"),
        (r"Tomcat/([\d.]+)", "Tomcat"),
        (r"Jetty\(([\d.]+)", "Jetty"),
    ]
    combined = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
    for pat, name in version_patterns:
        m = re.search(pat, combined, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex else "detected"
            result["version_leaks"].append({"software": name, "version": version})

    # Framework hints from error page content
    hint_patterns = [
        (r"Whitelabel Error Page", "Spring Boot"),
        (r"Django Debug", "Django (DEBUG=True)"),
        (r"Laravel", "Laravel"),
        (r"Symfony\\Component", "Symfony"),
        (r"CakePHP", "CakePHP"),
        (r"CodeIgniter", "CodeIgniter"),
        (r"Werkzeug Debugger", "Flask/Werkzeug (debug mode)"),
        (r"Express</title>", "Express.js"),
        (r"<address>Apache", "Apache"),
        (r"<address>nginx", "nginx"),
        (r"IIS Windows Server", "IIS"),
        (r"Powered by.*WordPress", "WordPress"),
    ]
    for pat, name in hint_patterns:
        if re.search(pat, body, re.IGNORECASE):
            result["framework_hints"].append(name)

    return result


# ── GraphQL Introspection Probe ──────────────────────────────────────────

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
    "/graphiql",
    "/altair",
    "/playground",
]

_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name kind } } } } }"}'


def _post_json(url: str, body: str, timeout: int = 6,
               verify_ssl: bool = True,
               headers: Optional[Dict[str, str]] = None) -> tuple:
    """HTTP POST with JSON body — stdlib only, SSL fallback."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    if headers:
        req_headers.update(headers)

    encoded = body.encode("utf-8")

    if parsed.scheme == "https":
        port = port or 443
        # Try verified first, fall back to unverified
        for do_verify in ([True, False] if verify_ssl else [False]):
            try:
                ctx = ssl.create_default_context()
                if not do_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                conn.request("POST", path, body=encoded, headers=req_headers)
                resp = conn.getresponse()
                resp_body = resp.read(500_000).decode("utf-8", errors="replace")
                conn.close()
                return resp.status, resp_body
            except ssl.SSLError:
                continue
            except Exception:
                return 0, ""
        return 0, ""
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("POST", path, body=encoded, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read(500_000).decode("utf-8", errors="replace")
            return resp.status, resp_body
        except Exception:
            return 0, ""
        finally:
            conn.close()


def check_graphql_introspection(host: str, port: int, use_ssl: bool,
                                 timeout: int = 6,
                                 extra_headers: Optional[Dict[str, str]] = None,
                                 ) -> Dict[str, Any]:
    """Probe common GraphQL endpoints for introspection enabled.

    Exposed introspection reveals the entire API schema — high-value recon.
    """
    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    result: Dict[str, Any] = {
        "endpoints_found": [],
        "introspection_enabled": [],
        "types_found": [],
        "total_types": 0,
        "total_fields": 0,
    }

    for gql_path in _GRAPHQL_PATHS:
        url = f"{base}{gql_path}"

        # Directly POST introspection query — most reliable detection
        post_status, post_body = _post_json(url, _INTROSPECTION_QUERY,
                                             timeout=timeout,
                                             verify_ssl=True,
                                             headers=extra_headers)

        if post_status == 0:
            continue

        # Any meaningful response to a GraphQL query means endpoint exists
        is_graphql = False
        if post_body:
            lower = post_body.lower()
            if any(kw in lower for kw in ('"data"', '"errors"', '__schema',
                                           'graphql', 'must provide',
                                           '"message"')):
                is_graphql = True

        if not is_graphql:
            continue

        result["endpoints_found"].append(gql_path)

        if post_status == 200 and "__schema" in post_body:
            result["introspection_enabled"].append(gql_path)

            # Parse types from response
            try:
                data = json.loads(post_body)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                user_types = []
                total_fields = 0
                for t in types:
                    name = t.get("name", "")
                    # Skip built-in GraphQL types
                    if name.startswith("__") or name in ("String", "Int", "Float",
                                                          "Boolean", "ID", "DateTime"):
                        continue
                    fields = t.get("fields") or []
                    field_names = [f.get("name", "") for f in fields]
                    total_fields += len(field_names)
                    user_types.append({
                        "name": name,
                        "fields": field_names[:10],  # cap for display
                        "field_count": len(field_names),
                    })
                result["types_found"] = user_types[:20]
                result["total_types"] = len(user_types)
                result["total_fields"] = total_fields
            except (json.JSONDecodeError, AttributeError, KeyError):
                pass

            break  # Found introspection on one endpoint, no need to check others

    return result


# ── API Discovery ────────────────────────────────────────────────────────

# Common API spec / documentation paths
_API_SPEC_PATHS = [
    # OpenAPI / Swagger
    ("/swagger.json", "swagger"),
    ("/swagger/v1/swagger.json", "swagger"),
    ("/api/swagger.json", "swagger"),
    ("/v1/swagger.json", "swagger"),
    ("/v2/swagger.json", "swagger"),
    ("/v3/swagger.json", "swagger"),
    ("/openapi.json", "openapi"),
    ("/api/openapi.json", "openapi"),
    ("/v1/openapi.json", "openapi"),
    ("/v2/openapi.json", "openapi"),
    ("/v3/openapi.json", "openapi"),
    ("/openapi.yaml", "openapi"),
    ("/swagger-ui.html", "swagger-ui"),
    ("/swagger-ui/", "swagger-ui"),
    ("/swagger/", "swagger-ui"),
    ("/api-docs", "api-docs"),
    ("/api-docs/", "api-docs"),
    ("/docs", "docs"),
    ("/redoc", "redoc"),
    # Common API versioned roots
    ("/api/", "api-root"),
    ("/api/v1/", "api-root"),
    ("/api/v2/", "api-root"),
    ("/api/v3/", "api-root"),
    ("/v1/", "api-root"),
    ("/v2/", "api-root"),
    # Health / metadata endpoints
    ("/api/health", "health"),
    ("/health", "health"),
    ("/healthz", "health"),
    ("/api/status", "status"),
    ("/api/version", "version"),
    ("/api/info", "info"),
    # GraphQL docs (supplement to introspection probe)
    ("/graphql/schema", "graphql"),
    ("/graphql/explorer", "graphql"),
]


def check_api_discovery(host: str, port: int, use_ssl: bool,
                         timeout: int = 5,
                         extra_headers: Optional[Dict[str, str]] = None,
                         ) -> Dict[str, Any]:
    """Probe common API paths to discover specs, docs, and versioned endpoints.

    Swagger/OpenAPI specs expose every endpoint, parameter, and auth method.
    """
    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    found = []
    specs = []
    errors = []

    for api_path, category in _API_SPEC_PATHS:
        url = f"{base}{api_path}"
        try:
            status, body, resp_headers = _fetch_url(url, timeout=timeout,
                                                     verify_ssl=True,
                                                     headers=extra_headers)
            # SSL fallback
            if status == 0 and use_ssl:
                status, body, resp_headers = _fetch_url(url, timeout=timeout,
                                                         verify_ssl=False,
                                                         headers=extra_headers)
        except Exception:
            continue

        if status == 0 or status >= 400:
            continue

        # Validate it's a real API response (not a generic 200 page)
        ct = resp_headers.get("content-type", "")
        is_json = "json" in ct or "yaml" in ct
        is_html = "html" in ct

        entry = {
            "path": api_path,
            "status": status,
            "category": category,
            "content_type": ct.split(";")[0].strip(),
        }

        # Parse OpenAPI/Swagger spec if JSON
        if is_json and body and category in ("swagger", "openapi"):
            try:
                spec = json.loads(body)
                info = spec.get("info", {})
                paths = spec.get("paths", {})
                entry["spec"] = True
                entry["title"] = info.get("title", "")
                entry["version"] = info.get("version", "")
                entry["endpoints"] = len(paths)
                entry["methods"] = []
                # Extract endpoint + method pairs
                for ep_path, methods in list(paths.items())[:30]:
                    for method in methods:
                        if method.lower() in ("get", "post", "put", "patch", "delete", "options"):
                            entry["methods"].append(f"{method.upper()} {ep_path}")
                specs.append(entry)
            except (json.JSONDecodeError, AttributeError):
                pass

        # Swagger UI / docs pages (HTML)
        elif is_html and body and category in ("swagger-ui", "api-docs", "docs", "redoc"):
            lower = body.lower()
            if any(kw in lower for kw in ("swagger", "openapi", "api", "redoc",
                                           "endpoint", "schema", "try it out")):
                entry["spec"] = False
                entry["docs_page"] = True
                found.append(entry)
                continue

        # API root / health / version — just confirm it responds
        elif category in ("api-root", "health", "status", "version", "info"):
            # Validate it's not just a generic website page
            if is_json or (is_html and len(body) < 5000):
                found.append(entry)
                continue
            else:
                continue

        if entry.get("spec"):
            found.append(entry)
        elif category in ("swagger-ui", "api-docs", "docs", "redoc"):
            pass  # Already handled above
        else:
            found.append(entry)

    return {
        "endpoints_found": found,
        "specs_found": specs,
        "total": len(found),
        "has_spec": len(specs) > 0,
    }


# ── Host Header Injection ───────────────────────────────────────────────

# Headers that apps commonly trust for building URLs (password reset links,
# canonical URLs, redirect targets, cache keys).
_HOST_OVERRIDE_HEADERS = [
    ("X-Forwarded-Host", "evil.example.com"),
    ("X-Host", "evil.example.com"),
    ("X-Forwarded-Server", "evil.example.com"),
    ("Forwarded", "host=evil.example.com"),
    ("X-Original-URL", "/non-existent-hhi-test"),
    ("X-Rewrite-URL", "/non-existent-hhi-test"),
    ("X-Forwarded-Prefix", "/evil"),
]

# Sentinel value we inject — if it appears in the response body the app
# blindly trusts our injected header for building URLs.
_HHI_SENTINEL = "evil.example.com"


def check_host_header_injection(host: str, port: int, use_ssl: bool,
                                 timeout: int = 6,
                                 extra_headers: Optional[Dict[str, str]] = None,
                                 ) -> Dict[str, Any]:
    """Probe for Host Header Injection (password reset poisoning, cache poisoning, SSRF).

    Sends requests with manipulated Host/X-Forwarded-Host headers and checks
    if the injected value is reflected in the response body (links, redirects,
    meta tags, etc.).
    """
    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    result: Dict[str, Any] = {
        "vulnerable_headers": [],
        "reflected": False,
        "details": [],
    }

    # 1. Baseline request
    try:
        base_status, base_body, base_hdrs = _fetch_url(base + "/",
                                                         timeout=timeout,
                                                         verify_ssl=True,
                                                         headers=extra_headers)
        if base_status == 0 and use_ssl:
            base_status, base_body, base_hdrs = _fetch_url(base + "/",
                                                             timeout=timeout,
                                                             verify_ssl=False,
                                                             headers=extra_headers)
    except Exception:
        return result

    if base_status == 0:
        return result

    # 2. Test each override header
    for header_name, header_value in _HOST_OVERRIDE_HEADERS:
        test_headers = dict(extra_headers) if extra_headers else {}
        test_headers[header_name] = header_value

        try:
            status, body, hdrs = _fetch_url(base + "/",
                                             timeout=timeout,
                                             verify_ssl=True,
                                             headers=test_headers)
            if status == 0 and use_ssl:
                status, body, hdrs = _fetch_url(base + "/",
                                                 timeout=timeout,
                                                 verify_ssl=False,
                                                 headers=test_headers)
        except Exception:
            continue

        if status == 0:
            continue

        finding = {
            "header": header_name,
            "value": header_value,
            "reflected": False,
            "status_changed": status != base_status,
            "status": status,
        }

        # Check if our sentinel is reflected in body
        if body and _HHI_SENTINEL in body.lower():
            # Verify it wasn't in the baseline
            if not base_body or _HHI_SENTINEL not in base_body.lower():
                finding["reflected"] = True
                result["reflected"] = True
                result["vulnerable_headers"].append(header_name)

        # Check for redirect to our injected host
        location = hdrs.get("location", "")
        if _HHI_SENTINEL in location.lower():
            finding["reflected"] = True
            finding["redirect"] = location
            result["reflected"] = True
            if header_name not in result["vulnerable_headers"]:
                result["vulnerable_headers"].append(header_name)

        if finding["reflected"] or finding["status_changed"]:
            result["details"].append(finding)

    return result


# ── Admin Panel Discovery ───────────────────────────────────────────────

_ADMIN_PATHS = [
    # Generic
    ("/admin", "generic"),
    ("/admin/", "generic"),
    ("/administrator", "generic"),
    ("/administrator/", "generic"),
    ("/admin/login", "generic"),
    ("/admin/login.php", "generic"),
    ("/admin/index.php", "generic"),
    ("/adminpanel", "generic"),
    ("/admin-panel", "generic"),
    ("/admin.php", "generic"),
    # WordPress
    ("/wp-admin/", "wordpress"),
    ("/wp-login.php", "wordpress"),
    ("/wp-admin/admin-ajax.php", "wordpress"),
    # Joomla
    ("/administrator/index.php", "joomla"),
    # Drupal
    ("/user/login", "drupal"),
    ("/admin/config", "drupal"),
    # cPanel / hosting
    ("/cpanel", "cpanel"),
    ("/webmail", "cpanel"),
    ("/whm", "cpanel"),
    # phpMyAdmin
    ("/phpmyadmin/", "database"),
    ("/phpmyadmin/index.php", "database"),
    ("/pma/", "database"),
    ("/myadmin/", "database"),
    ("/dbadmin/", "database"),
    ("/adminer.php", "database"),
    ("/adminer/", "database"),
    # Dashboards
    ("/dashboard", "dashboard"),
    ("/dashboard/", "dashboard"),
    ("/panel", "dashboard"),
    ("/panel/", "dashboard"),
    ("/console", "dashboard"),
    ("/console/", "dashboard"),
    ("/manage", "dashboard"),
    ("/management", "dashboard"),
    ("/portal", "dashboard"),
    ("/controlpanel", "dashboard"),
    # Java / Spring / Tomcat
    ("/manager/html", "tomcat"),
    ("/manager/status", "tomcat"),
    ("/host-manager/html", "tomcat"),
    ("/actuator", "spring"),
    ("/actuator/env", "spring"),
    ("/actuator/health", "spring"),
    # Node / dev tools
    ("/_debugbar", "debug"),
    ("/__debug__/", "debug"),
    ("/debug/default/login", "debug"),
    ("/elmah.axd", "debug"),
    # Server status
    ("/server-status", "apache"),
    ("/server-info", "apache"),
    ("/nginx_status", "nginx"),
    # Other CMS / frameworks
    ("/admin/dashboard", "generic"),
    ("/backend", "generic"),
    ("/backend/", "generic"),
    ("/cms", "generic"),
    ("/cms/admin", "generic"),
    ("/siteadmin", "generic"),
    ("/webadmin", "generic"),
    ("/moderator", "generic"),
    ("/filemanager", "generic"),
    ("/filemanager/", "generic"),
    # API management
    ("/graphql", "api"),
    ("/graphiql", "api"),
    ("/playground", "api"),
]


def check_admin_panels(host: str, port: int, use_ssl: bool,
                        timeout: int = 5,
                        extra_headers: Optional[Dict[str, str]] = None,
                        ) -> Dict[str, Any]:
    """Probe common admin panel paths — saves manual enumeration every engagement.

    Checks 70 paths covering WordPress, Joomla, Drupal, phpMyAdmin, Tomcat,
    Spring actuator, debug tools, and generic admin panels.
    """
    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    found = []

    for admin_path, category in _ADMIN_PATHS:
        url = f"{base}{admin_path}"
        try:
            status, body, hdrs = _fetch_url(url, timeout=timeout,
                                             verify_ssl=True,
                                             headers=extra_headers)
            if status == 0 and use_ssl:
                status, body, hdrs = _fetch_url(url, timeout=timeout,
                                                 verify_ssl=False,
                                                 headers=extra_headers)
        except Exception:
            continue

        if status == 0 or status >= 404:
            continue

        # Skip generic soft-404 pages (large HTML pages that always return 200)
        ct = hdrs.get("content-type", "")
        is_html = "html" in ct

        # Validate it's actually an admin/login page, not a generic 200
        is_admin = False

        # 301/302 redirects to login pages are a strong signal
        if status in (301, 302, 303, 307, 308):
            location = hdrs.get("location", "").lower()
            if any(kw in location for kw in ("login", "auth", "signin", "admin", "sso")):
                is_admin = True
            else:
                is_admin = True  # Redirect to somewhere — still worth noting

        # 200 with login-related content
        elif status == 200 and body:
            lower = body.lower()
            admin_signals = (
                "login", "password", "username", "sign in", "log in",
                "authentication", "admin", "dashboard", "panel",
                "phpmyadmin", "adminer", "manager", "console",
                "actuator", "server-status", "debug", "configuration",
                '<input type="password"', 'type="submit"',
            )
            if any(sig in lower for sig in admin_signals):
                is_admin = True
            elif not is_html:
                # JSON/XML endpoints (actuator, api) — likely real
                is_admin = True

        # 401/403 = authenticated endpoint exists
        elif status in (401, 403):
            is_admin = True

        if not is_admin:
            continue

        entry = {
            "path": admin_path,
            "status": status,
            "category": category,
        }

        # Add redirect target if applicable
        if status in (301, 302, 303, 307, 308):
            entry["redirect"] = hdrs.get("location", "")

        # Flag auth-protected vs open
        if status in (401, 403):
            entry["protected"] = True
        elif status == 200:
            entry["protected"] = False

        found.append(entry)

    return {
        "panels_found": found,
        "total": len(found),
    }


# ── Historical URL Discovery ─────────────────────────────────────────────

# Path patterns interesting for WAF testing — old/dev/debug endpoints
_INTERESTING_PATH_RE = re.compile(
    r"(?:/api/|/v[1-9]\d*/|/admin|/debug|/internal|/graphql|/auth|/oauth|"
    r"/dev/|/staging/|/test/|/old/|/backup|/console|/swagger|/docs/api|"
    r"/wp-json|/xmlrpc|/cgi-bin|/\.env|/\.git|/phpinfo|/actuator|"
    r"/config|/secret|/token|/upload|/download|/export|/import|"
    r"/dashboard|/panel|/manage|/setup|/install)",
    re.IGNORECASE,
)

# Extensions to skip (static assets)
_STATIC_EXT_RE = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|tar|gz|"
    r"mp[34]|webp|avif|bmp|tiff?|wav|flac|ogg|avi|mov|wmv|swf|flv)$",
    re.IGNORECASE,
)


def _fetch_url(url: str, timeout: int = 12, verify_ssl: bool = True,
               headers: Optional[Dict[str, str]] = None) -> tuple:
    """Simple HTTP GET — independent of scanner's _fetch (no global backoff state)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        port = port or 443
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    try:
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read(1_000_000).decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, body, resp_headers
    except Exception:
        return 0, "", {}
    finally:
        conn.close()


def discover_historical_urls(url: str, timeout: int = 12,
                              verify_ssl: bool = True,
                              extra_headers: Optional[Dict[str, str]] = None,
                              ) -> Dict[str, Any]:
    """Discover historical URLs from Wayback Machine, sitemap.xml, and robots.txt.

    Old endpoints often have weaker WAF rules or none at all.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{host}"

    all_paths = {}   # path -> {sources, timestamps, ...}
    errors = []

    # ── 1. Wayback Machine CDX API ──
    wayback_urls = []
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={host}/*&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&filter=statuscode:200&collapse=urlkey&limit=500"
        )
        # Retry up to 3 times — CDX API is often flaky (503, timeouts)
        status, body = 0, ""
        import time as _time
        for _attempt in range(3):
            status, body, _ = _fetch_url(cdx_url, timeout=timeout, verify_ssl=False)
            if status == 200 and body:
                break
            _time.sleep(1 + _attempt)
        if status == 200 and body:
            import json as _json
            try:
                rows = _json.loads(body)
                # First row is header: ["timestamp","original","statuscode","mimetype"]
                for row in rows[1:]:
                    if len(row) < 4:
                        continue
                    ts, orig_url, sc, mime = row[0], row[1], row[2], row[3]
                    # Skip static assets
                    orig_parsed = urllib.parse.urlparse(orig_url)
                    path = orig_parsed.path.rstrip("/") or "/"
                    if _STATIC_EXT_RE.search(path):
                        continue
                    if path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if "wayback" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("wayback")
                    # Track oldest timestamp
                    if ts and (not all_paths[path]["first_seen"] or ts < all_paths[path]["first_seen"]):
                        all_paths[path]["first_seen"] = ts
                    wayback_urls.append(path)
            except (_json.JSONDecodeError, IndexError):
                pass
    except Exception as e:
        errors.append(f"Wayback: {e}")

    # ── 2. sitemap.xml (current + archived) ──
    sitemap_paths = []
    sitemap_urls_to_check = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap_index.xml",
        f"{base}/sitemap.xml.gz",
    ]
    for smap_url in sitemap_urls_to_check:
        try:
            status, body, _ = _fetch_url(smap_url, timeout=timeout,
                                         verify_ssl=verify_ssl,
                                         headers=extra_headers)
            if status == 200 and body:
                # Extract <loc> tags
                for m in re.finditer(r'<loc>\s*(.*?)\s*</loc>', body, re.IGNORECASE):
                    loc = m.group(1).strip()
                    loc_parsed = urllib.parse.urlparse(loc)
                    path = loc_parsed.path.rstrip("/") or "/"
                    if _STATIC_EXT_RE.search(path):
                        continue
                    if path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if "sitemap" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("sitemap")
                    sitemap_paths.append(path)
        except Exception:
            pass

    # ── 3. robots.txt (Disallow paths are gold) ──
    robots_paths = []
    try:
        robots_url = f"{base}/robots.txt"
        status, body, _ = _fetch_url(robots_url, timeout=timeout,
                                     verify_ssl=verify_ssl,
                                     headers=extra_headers)
        if status == 200 and body:
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if not path or path == "/":
                        continue
                    # Remove trailing wildcards
                    path = path.rstrip("*").rstrip("/") or path
                    if path and path not in all_paths:
                        all_paths[path] = {
                            "path": path,
                            "sources": [],
                            "first_seen": None,
                            "interesting": False,
                        }
                    if path and "robots.txt" not in all_paths[path]["sources"]:
                        all_paths[path]["sources"].append("robots.txt")
                    if path:
                        robots_paths.append(path)
                # Also grab Sitemap directives
                elif line.lower().startswith("sitemap:"):
                    smap = line.split(":", 1)[1].strip()
                    if smap and smap not in sitemap_urls_to_check:
                        sitemap_urls_to_check.append(smap)
    except Exception:
        pass

    # ── Mark interesting paths ──
    for path, info in all_paths.items():
        if _INTERESTING_PATH_RE.search(path):
            info["interesting"] = True

    # ── Sort: interesting first, then by path ──
    sorted_paths = sorted(
        all_paths.values(),
        key=lambda x: (0 if x["interesting"] else 1, x["path"]),
    )

    interesting_count = sum(1 for p in sorted_paths if p["interesting"])

    return {
        "urls": sorted_paths,
        "total": len(sorted_paths),
        "interesting": interesting_count,
        "sources": {
            "wayback": len(set(wayback_urls)),
            "sitemap": len(set(sitemap_paths)),
            "robots": len(set(robots_paths)),
        },
        "errors": errors,
    }


def print_historical_urls(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print historical URL discovery results."""
    from fray.output import console, print_header

    print_header("Fray Recon — Historical URL Discovery", target=target)

    total = result.get("total", 0)
    interesting = result.get("interesting", 0)
    src = result.get("sources", {})

    console.print(f"  URLs discovered: [cyan]{total}[/cyan]")
    console.print(f"  Interesting paths: [yellow]{interesting}[/yellow] (admin, API, debug, config, etc.)")
    console.print(f"  Sources: [green]{src.get('wayback', 0)}[/green] Wayback · "
                  f"[green]{src.get('sitemap', 0)}[/green] sitemap · "
                  f"[green]{src.get('robots', 0)}[/green] robots.txt")
    console.print()

    urls = result.get("urls", [])
    if urls:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Path", min_width=40)
        table.add_column("Sources", width=18, style="dim")
        table.add_column("First Seen", width=10, style="dim")

        for i, u in enumerate(urls[:40], 1):
            path = u["path"]
            if u["interesting"]:
                path_display = f"[yellow]{path}[/yellow]"
            else:
                path_display = path
            sources = ", ".join(u["sources"])
            ts = u.get("first_seen", "")
            if ts and len(ts) >= 8:
                ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
            else:
                ts = ""
            table.add_row(str(i), path_display, sources, ts)

        console.print(table)
        if len(urls) > 40:
            console.print(f"    [dim]... and {len(urls) - 40} more[/dim]")
        console.print()

        if interesting:
            console.print("  [bold yellow]⚠ Interesting paths — likely weaker WAF protection:[/bold yellow]")
            for u in urls:
                if u["interesting"]:
                    console.print(f"    [yellow]{u['path']}[/yellow]  ({', '.join(u['sources'])})")
            console.print()

        console.print(f"  [dim]Test old endpoints: fray scan {target} -c xss -m 3[/dim]")
    else:
        console.print("  [dim]No historical URLs found[/dim]")

    errors = result.get("errors", [])
    if errors:
        for err in errors:
            console.print(f"  [dim]⚠ {err}[/dim]")
    console.print()


# ── Parameter Mining (brute-force) ───────────────────────────────────────

# Curated wordlist — common hidden/undocumented parameters across web apps
_PARAM_WORDLIST = [
    # Auth & session
    "id", "user", "username", "login", "password", "pass", "email", "token",
    "session", "auth", "key", "api_key", "apikey", "secret", "access_token",
    # Routing & redirects
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "goto", "dest", "destination", "continue", "callback", "ref",
    # File & path
    "file", "filename", "path", "dir", "folder", "doc", "document", "template",
    "page", "include", "src", "source", "load", "read", "fetch", "download",
    # Data / CRUD
    "name", "value", "data", "content", "text", "body", "message", "comment",
    "title", "description", "type", "category", "status", "action", "cmd",
    "command", "exec", "query", "q", "search", "filter", "sort", "order",
    "limit", "offset", "count", "size", "from", "to", "start", "end",
    # ID variants
    "uid", "pid", "cid", "oid", "item", "item_id", "product", "product_id",
    "order_id", "account", "account_id", "customer_id", "invoice",
    # Debug & internal
    "debug", "test", "admin", "mode", "env", "verbose", "trace", "log",
    "config", "setting", "format", "output", "render", "view", "preview",
    "version", "v", "lang", "locale", "language",
    # SSRF / injection targets
    "host", "ip", "port", "domain", "proxy", "target", "site",
    # Upload & media
    "upload", "image", "img", "avatar", "photo", "attachment", "media",
    # Misc
    "callback", "jsonp", "method", "_method", "csrf", "nonce", "timestamp",
    "sign", "signature", "hash", "checksum", "role", "group", "permission",
]


def mine_params(url: str, timeout: int = 4, verify_ssl: bool = True,
                extra_headers: Optional[Dict[str, str]] = None,
                wordlist: Optional[List[str]] = None,
                quiet: bool = False,
                ) -> Dict[str, Any]:
    """Parameter brute-force mining.

    Probes each param name against the target URL and detects hidden parameters
    by comparing response differences (status, content-length, reflection).

    This is NOT directory fuzzing — it's parameter fuzzing.
    """
    import sys
    params_to_try = wordlist or _PARAM_WORDLIST

    parsed = urllib.parse.urlparse(url)
    from fray.scanner import _fetch, extract_links, _same_origin

    # Quick crawl to find testable endpoints (pages that accept input)
    endpoints = set()
    endpoints.add(url)

    status, body, resp_headers = _fetch(url, timeout=timeout,
                                        verify_ssl=verify_ssl,
                                        headers=extra_headers)
    if status and body:
        content_type = resp_headers.get("content-type", "")
        if "text/html" in content_type:
            for link in extract_links(url, body):
                if _same_origin(url, link):
                    endpoints.add(link.split("?")[0].split("#")[0])

    # Limit endpoints — 3 max keeps total requests under ~320
    test_endpoints = sorted(endpoints)[:3]

    found_params = []
    seen = set()
    total_probed = 0
    total_work = len(test_endpoints) * len(params_to_try)

    for ep_idx, ep_url in enumerate(test_endpoints):
        ep_path = urllib.parse.urlparse(ep_url).path or "/"
        if not quiet:
            sys.stderr.write(f"\r  Mining {ep_path} ... ({ep_idx+1}/{len(test_endpoints)})")
            sys.stderr.flush()

        # Baseline: request without any extra params
        base_status, base_body, _ = _fetch_url(ep_url, timeout=timeout,
                                                verify_ssl=verify_ssl,
                                                headers=extra_headers)
        if base_status == 0:
            continue
        base_len = len(base_body)

        for param in params_to_try:
            key = (ep_url.split("?")[0], param)
            if key in seen:
                continue

            test_value = "fray_test_1337"
            sep = "&" if "?" in ep_url else "?"
            probe_url = f"{ep_url}{sep}{param}={test_value}"
            total_probed += 1

            probe_status, probe_body, _ = _fetch_url(probe_url, timeout=timeout,
                                                      verify_ssl=verify_ssl,
                                                      headers=extra_headers)
            if probe_status == 0:
                continue

            # Detection: compare against baseline
            probe_len = len(probe_body)
            reflected = test_value in probe_body
            status_diff = probe_status != base_status
            # Significant size difference (>50 bytes and >5% change)
            size_diff = abs(probe_len - base_len) > 50 and abs(probe_len - base_len) / max(base_len, 1) > 0.05

            if reflected or status_diff or size_diff:
                seen.add(key)
                evidence = []
                if reflected:
                    evidence.append("reflected")
                if status_diff:
                    evidence.append(f"status {base_status}→{probe_status}")
                if size_diff:
                    diff = probe_len - base_len
                    evidence.append(f"size {'+' if diff > 0 else ''}{diff}b")

                # Classify risk
                risk = "info"
                if param in ("redirect", "redirect_url", "redirect_uri", "url",
                             "return", "return_url", "next", "goto", "dest",
                             "destination", "callback", "continue"):
                    risk = "high"  # Open redirect / SSRF
                elif param in ("file", "path", "dir", "include", "template",
                               "load", "read", "fetch", "doc", "source", "src"):
                    risk = "high"  # LFI / path traversal
                elif param in ("cmd", "command", "exec", "query", "action"):
                    risk = "high"  # Command injection / SQLi
                elif param in ("id", "uid", "user", "account", "account_id",
                               "customer_id", "order_id", "item_id"):
                    risk = "medium"  # IDOR
                elif param in ("debug", "test", "admin", "verbose", "trace",
                               "config", "env", "mode"):
                    risk = "medium"  # Debug/info disclosure
                elif reflected:
                    risk = "medium"  # XSS candidate

                ep_path = urllib.parse.urlparse(ep_url).path or "/"
                found_params.append({
                    "endpoint": ep_path,
                    "param": param,
                    "method": "GET",
                    "evidence": evidence,
                    "risk": risk,
                })

    if not quiet:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    # Sort by risk (high first)
    risk_order = {"high": 0, "medium": 1, "info": 2}
    found_params.sort(key=lambda x: (risk_order.get(x["risk"], 3), x["endpoint"], x["param"]))

    return {
        "params": found_params,
        "total_found": len(found_params),
        "total_probed": total_probed,
        "endpoints_tested": len(test_endpoints),
        "wordlist_size": len(params_to_try),
    }


def print_mined_params(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print parameter mining results."""
    from fray.output import console, print_header

    print_header("Fray Recon — Parameter Mining", target=target)

    total = result.get("total_found", 0)
    probed = result.get("total_probed", 0)
    eps = result.get("endpoints_tested", 0)

    console.print(f"  Parameters found: [cyan]{total}[/cyan]")
    console.print(f"  Probed: {probed} combinations ({eps} endpoints × {result.get('wordlist_size', 0)} params)")
    console.print()

    params = result.get("params", [])
    if params:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Endpoint", min_width=25)
        table.add_column("Param", min_width=15, style="cyan")
        table.add_column("Risk", width=8)
        table.add_column("Evidence", min_width=20, style="dim")

        risk_styles = {
            "high": "[red]HIGH[/red]",
            "medium": "[yellow]MED[/yellow]",
            "info": "[dim]info[/dim]",
        }

        for i, p in enumerate(params[:30], 1):
            risk_display = risk_styles.get(p["risk"], p["risk"])
            evidence = ", ".join(p["evidence"])
            table.add_row(str(i), p["endpoint"], p["param"], risk_display, evidence)

        console.print(table)
        if len(params) > 30:
            console.print(f"    [dim]... and {len(params) - 30} more[/dim]")
        console.print()

        # Summary by risk
        high = sum(1 for p in params if p["risk"] == "high")
        med = sum(1 for p in params if p["risk"] == "medium")
        if high:
            console.print(f"  [red]⚠ {high} HIGH risk params[/red] — test for SSRF, LFI, injection")
        if med:
            console.print(f"  [yellow]⚠ {med} MEDIUM risk params[/yellow] — test for XSS, IDOR, debug disclosure")
        console.print()
        console.print(f"  [dim]Test: fray scan {target} -c xss -m 3[/dim]")
    else:
        console.print("  [dim]No hidden parameters found[/dim]")
    console.print()


# ── JS Endpoint Extraction ───────────────────────────────────────────────

# Comprehensive regex patterns for JS endpoint discovery
_JS_ENDPOINT_PATTERNS = [
    # fetch / axios / xhr
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""axios\.[a-z]+\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    re.compile(r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE),
    # String literals that look like API paths
    re.compile(r"""['"`](/api/[^'"`\s]{2,})['"`]"""),
    re.compile(r"""['"`](/v[1-9]\d*/[^'"`\s]{2,})['"`]"""),
    re.compile(r"""['"`](/graphql[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/rest/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/internal/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/admin/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/auth/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/oauth/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/webhook[s]?/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/upload[s]?[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/download[s]?[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/socket[^'"`\s]*)['"`]""", re.IGNORECASE),
    re.compile(r"""['"`](/ws/[^'"`\s]{2,})['"`]""", re.IGNORECASE),
    # Template literal URLs: `${baseUrl}/endpoint`
    re.compile(r"""\$\{[^}]+\}(/[a-zA-Z0-9_/\-]+)"""),
    # URL concatenation: baseUrl + "/endpoint"
    re.compile(r"""\+\s*['"`](/[a-zA-Z0-9_/\-]{3,})['"`]"""),
]

# ── LinkFinder-style patterns for full URLs, hostnames, cloud buckets ──

# Full absolute URLs in JS string literals
_JS_FULL_URL_RE = re.compile(
    r"""['"`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,})['"`]""",
)

# Internal hostnames / subdomains referenced in JS
_JS_HOSTNAME_RE = re.compile(
    r"""['"`]((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"""
    r"""(?:com|org|net|io|dev|app|co|ai|cloud|internal|local|corp|intranet"""
    r"""|staging|test|qa|uat|prod|infra))['"`]""",
    re.IGNORECASE,
)

# Cloud storage buckets
_JS_CLOUD_BUCKET_PATTERNS = [
    # AWS S3: s3.amazonaws.com/bucket or bucket.s3.amazonaws.com or s3://bucket
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-]+\.s3[.\-]amazonaws\.com)[/'"` ]""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?s3[.\-]amazonaws\.com/([a-zA-Z0-9.\-]+)""", re.IGNORECASE),
    re.compile(r"""['"`]s3://([a-zA-Z0-9.\-]+)['"`]""", re.IGNORECASE),
    # Google Cloud Storage
    re.compile(r"""['"`](?:https?://)?storage\.googleapis\.com/([a-zA-Z0-9.\-_]+)""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-_]+\.storage\.googleapis\.com)""", re.IGNORECASE),
    re.compile(r"""['"`]gs://([a-zA-Z0-9.\-_]+)['"`]""", re.IGNORECASE),
    # Azure Blob Storage
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9]+\.blob\.core\.windows\.net)""", re.IGNORECASE),
    # Firebase
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9\-]+\.firebaseio\.com)""", re.IGNORECASE),
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9\-]+\.firebasestorage\.googleapis\.com)""", re.IGNORECASE),
    # DigitalOcean Spaces
    re.compile(r"""['"`](?:https?://)?([a-zA-Z0-9.\-]+\.digitaloceanspaces\.com)""", re.IGNORECASE),
]

# API keys and secrets (high-entropy strings with known prefixes)
_JS_SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key", re.compile(r"""(?:^|['"` ,=:])((AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?:['"` ,]|$)""")),
    # Google
    ("Google API Key", re.compile(r"""['"`](AIza[0-9A-Za-z\-_]{35})['"`]""")),
    ("Google OAuth", re.compile(r"""['"`](\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)['"`]""")),
    # GitHub
    ("GitHub Token", re.compile(r"""['"`](gh[pousr]_[A-Za-z0-9_]{36,})['"`]""")),
    # Stripe
    ("Stripe Key", re.compile(r"""['"`](sk_live_[A-Za-z0-9]{20,})['"`]""")),
    ("Stripe Publishable", re.compile(r"""['"`](pk_live_[A-Za-z0-9]{20,})['"`]""")),
    # Slack
    ("Slack Token", re.compile(r"""['"`](xox[bpoas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})['"`]""")),
    ("Slack Webhook", re.compile(r"""['"`](https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)['"`]""")),
    # Twilio
    ("Twilio Key", re.compile(r"""['"`](SK[a-f0-9]{32})['"`]""")),
    # SendGrid
    ("SendGrid Key", re.compile(r"""['"`](SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})['"`]""")),
    # Mailgun
    ("Mailgun Key", re.compile(r"""['"`](key-[a-f0-9]{32})['"`]""")),
    # Generic API key patterns (variable assignment context)
    ("API Key (generic)", re.compile(
        r"""(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"""
        r"""\s*[:=]\s*['"`]([a-zA-Z0-9\-_./+]{20,})['"`]""",
        re.IGNORECASE,
    )),
    # JWT tokens
    ("JWT Token", re.compile(r"""['"`](eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+/=]+)['"`]""")),
    # Private keys
    ("Private Key", re.compile(r"""(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)""")),
    # Bearer tokens in headers
    ("Bearer Token", re.compile(
        r"""['"](Bearer\s+[a-zA-Z0-9\-_./+]{20,})['"]""",
        re.IGNORECASE,
    )),
]

# Patterns to extract <script src="..."> tags
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def discover_js_endpoints(url: str, max_depth: int = 2, max_pages: int = 10,
                          timeout: int = 8, verify_ssl: bool = True,
                          extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Deep JS endpoint extraction (LinkFinder-style).

    Crawls HTML pages, finds all <script src="..."> tags, fetches external
    JS files, and extracts:
      - API endpoints (paths + full URLs)
      - Internal hostnames / subdomains
      - Cloud storage buckets (S3, GCS, Azure, Firebase, DO Spaces)
      - API keys and secrets (AWS, Google, GitHub, Stripe, Slack, JWT, etc.)
    """
    from fray.scanner import _fetch, extract_links, _same_origin, _normalize_url

    parsed_target = urllib.parse.urlparse(url)
    target_domain = parsed_target.netloc.split(":")[0].lower()

    visited_pages = set()
    visited_js = set()
    queue = [(url, 0)]
    endpoints = []   # list of dicts
    seen_paths = set()

    # LinkFinder-style collections
    full_urls = []       # absolute URLs found in JS
    seen_urls = set()
    hostnames = []       # internal hostnames / subdomains
    seen_hosts = set()
    cloud_buckets = []   # S3, GCS, Azure, Firebase, DO Spaces
    seen_buckets = set()
    secrets = []         # API keys, tokens, credentials
    seen_secrets = set()

    def _process_js(js_content: str, source_url: str) -> None:
        """Extract all intelligence from a JS source."""
        _extract_endpoints_from_js(js_content, source_url, endpoints, seen_paths)
        _extract_full_urls(js_content, source_url, target_domain,
                           full_urls, seen_urls)
        _extract_hostnames(js_content, source_url, target_domain,
                           hostnames, seen_hosts)
        _extract_cloud_buckets(js_content, source_url,
                               cloud_buckets, seen_buckets)
        _extract_secrets(js_content, source_url, secrets, seen_secrets)

    while queue and len(visited_pages) < max_pages:
        current_url, depth = queue.pop(0)
        canonical = current_url.split("?")[0].split("#")[0]
        if canonical in visited_pages:
            continue
        visited_pages.add(canonical)

        # Skip non-HTML resources
        lower = canonical.lower()
        if any(lower.endswith(ext) for ext in (
            ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
        )):
            continue

        status, body, resp_headers = _fetch(current_url, timeout=timeout,
                                            verify_ssl=verify_ssl,
                                            headers=extra_headers)
        if status == 0 or not body:
            continue

        # Follow redirects
        if status in (301, 302, 307, 308):
            loc = resp_headers.get("location", "")
            if loc:
                redir_url = urllib.parse.urljoin(current_url, loc)
                if _same_origin(url, redir_url) and redir_url.split("?")[0] not in visited_pages:
                    queue.append((redir_url, depth))
            continue

        content_type = resp_headers.get("content-type", "")

        # Extract endpoints from inline JS in HTML pages
        if "text/html" in content_type or "application/xhtml" in content_type:
            _process_js(body, current_url)

            # Find and fetch external JS files
            for m in _SCRIPT_SRC_RE.finditer(body):
                js_src = m.group(1).strip()
                js_url = _normalize_url(current_url, js_src)
                if not js_url or js_url in visited_js:
                    continue
                visited_js.add(js_url)

                js_status, js_body, _ = _fetch(js_url, timeout=timeout,
                                               verify_ssl=verify_ssl,
                                               headers=extra_headers)
                if js_status == 200 and js_body:
                    _process_js(js_body, js_url)

            # Follow links
            if depth < max_depth:
                for link in extract_links(current_url, body):
                    link_canon = link.split("?")[0].split("#")[0]
                    if link_canon not in visited_pages and _same_origin(url, link):
                        queue.append((link, depth + 1))

    # Sort: /api first, then /admin, then rest
    def _sort_key(ep):
        p = ep["path"]
        if "/api/" in p or "/graphql" in p: return (0, p)
        if "/admin/" in p or "/internal/" in p: return (1, p)
        if "/auth/" in p or "/oauth/" in p: return (2, p)
        return (3, p)
    endpoints.sort(key=_sort_key)

    return {
        "endpoints": endpoints,
        "total": len(endpoints),
        "pages_crawled": len(visited_pages),
        "js_files_parsed": len(visited_js),
        "categories": {
            "api": sum(1 for e in endpoints if "/api/" in e["path"] or "/v" in e["path"]),
            "graphql": sum(1 for e in endpoints if "graphql" in e["path"].lower()),
            "admin": sum(1 for e in endpoints if "/admin/" in e["path"] or "/internal/" in e["path"]),
            "auth": sum(1 for e in endpoints if "/auth/" in e["path"] or "/oauth/" in e["path"]),
            "other": sum(1 for e in endpoints if not any(
                x in e["path"].lower() for x in ("/api/", "/v1/", "/v2/", "/graphql", "/admin/", "/internal/", "/auth/", "/oauth/")
            )),
        },
        # LinkFinder-style intelligence
        "full_urls": full_urls,
        "hostnames": hostnames,
        "cloud_buckets": cloud_buckets,
        "secrets": secrets,
    }


def _extract_endpoints_from_js(js_content: str, source_url: str,
                                endpoints: List[Dict], seen_paths: set) -> None:
    """Extract API endpoints from JS content and append to endpoints list."""
    for pattern in _JS_ENDPOINT_PATTERNS:
        for m in pattern.finditer(js_content):
            path = m.group(1).strip()
            # Filter noise
            if len(path) < 3 or len(path) > 200:
                continue
            if not path.startswith("/"):
                continue
            # Skip obvious non-endpoints
            if any(path.endswith(ext) for ext in (
                ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".map", ".html", ".htm",
            )):
                continue
            # Normalize: strip trailing slashes, query strings for dedup
            clean = path.split("?")[0].split("#")[0].rstrip("/")
            if not clean or clean in seen_paths:
                continue
            seen_paths.add(clean)

            # Classify
            lower = clean.lower()
            if "/admin" in lower or "/internal" in lower:
                category = "admin"
            elif "/graphql" in lower:
                category = "graphql"
            elif "/api/" in lower or re.match(r"/v\d+/", lower):
                category = "api"
            elif "/auth" in lower or "/oauth" in lower:
                category = "auth"
            elif "/upload" in lower or "/download" in lower:
                category = "upload"
            elif "/ws/" in lower or "/socket" in lower:
                category = "websocket"
            else:
                category = "other"

            endpoints.append({
                "path": clean,
                "source": urllib.parse.urlparse(source_url).path or source_url,
                "category": category,
            })


def _extract_full_urls(js_content: str, source_url: str, target_domain: str,
                       full_urls: List[Dict], seen_urls: set) -> None:
    """Extract absolute URLs from JS content."""
    # Common noise domains to skip
    _NOISE_DOMAINS = {
        "w3.org", "schema.org", "xmlns.com", "purl.org", "google.com/recaptcha",
        "fonts.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com", "unpkg.com", "maps.googleapis.com",
        "www.googletagmanager.com", "www.google-analytics.com",
        "connect.facebook.net", "platform.twitter.com",
    }
    for m in _JS_FULL_URL_RE.finditer(js_content):
        raw_url = m.group(1).strip().rstrip("'\"`;,)")
        if raw_url in seen_urls:
            continue
        # Filter noise
        if len(raw_url) > 500:
            continue
        try:
            parsed = urllib.parse.urlparse(raw_url)
            host = parsed.netloc.split(":")[0].lower()
        except Exception:
            continue
        if not host or any(n in raw_url for n in _NOISE_DOMAINS):
            continue
        # Skip same-origin static assets
        if host == target_domain and any(raw_url.lower().endswith(ext) for ext in (
            ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff2",
        )):
            continue
        seen_urls.add(raw_url)
        # Classify
        is_same_org = target_domain in host or host in target_domain
        category = "same-origin" if is_same_org else "third-party"
        if any(kw in raw_url.lower() for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
            category = "api"
        elif any(kw in raw_url.lower() for kw in ("/admin", "/internal", "/debug")):
            category = "admin"
        full_urls.append({
            "url": raw_url,
            "host": host,
            "category": category,
            "source": urllib.parse.urlparse(source_url).path or source_url,
        })


def _extract_hostnames(js_content: str, source_url: str, target_domain: str,
                       hostnames: List[Dict], seen_hosts: set) -> None:
    """Extract internal hostnames and subdomains from JS content."""
    # Extract the base domain (last two parts) for matching related subdomains
    parts = target_domain.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else target_domain

    for m in _JS_HOSTNAME_RE.finditer(js_content):
        hostname = m.group(1).strip().lower()
        if hostname in seen_hosts:
            continue
        if len(hostname) < 5 or len(hostname) > 253:
            continue
        # Skip the target itself
        if hostname == target_domain:
            continue
        seen_hosts.add(hostname)
        # Classify: related subdomain vs third-party
        is_related = base_domain in hostname
        risk = "info"
        if is_related:
            if any(kw in hostname for kw in ("staging", "dev", "test", "internal", "admin", "debug")):
                risk = "medium"
            elif any(kw in hostname for kw in ("prod", "api", "db", "redis", "mongo", "mysql")):
                risk = "high"
        hostnames.append({
            "hostname": hostname,
            "related": is_related,
            "risk": risk,
            "source": urllib.parse.urlparse(source_url).path or source_url,
        })


def _extract_cloud_buckets(js_content: str, source_url: str,
                            cloud_buckets: List[Dict], seen_buckets: set) -> None:
    """Extract cloud storage bucket references from JS content."""
    _PROVIDER_MAP = {
        "s3": "AWS S3",
        "amazonaws": "AWS S3",
        "storage.googleapis": "Google Cloud Storage",
        "gs://": "Google Cloud Storage",
        "blob.core.windows": "Azure Blob",
        "firebaseio": "Firebase",
        "firebasestorage": "Firebase Storage",
        "digitaloceanspaces": "DigitalOcean Spaces",
    }
    for pattern in _JS_CLOUD_BUCKET_PATTERNS:
        for m in pattern.finditer(js_content):
            bucket = m.group(1).strip()
            if bucket in seen_buckets or len(bucket) < 3:
                continue
            seen_buckets.add(bucket)
            # Determine provider
            provider = "Unknown"
            for key, name in _PROVIDER_MAP.items():
                if key in bucket.lower() or key in pattern.pattern.lower():
                    provider = name
                    break
            cloud_buckets.append({
                "bucket": bucket,
                "provider": provider,
                "risk": "high",
                "source": urllib.parse.urlparse(source_url).path or source_url,
            })


def _extract_secrets(js_content: str, source_url: str,
                     secrets: List[Dict], seen_secrets: set) -> None:
    """Extract API keys, tokens, and credentials from JS content."""
    for label, pattern in _JS_SECRET_PATTERNS:
        for m in pattern.finditer(js_content):
            secret = m.group(1).strip()
            if secret in seen_secrets or len(secret) < 8:
                continue
            seen_secrets.add(secret)
            # Mask the secret for display (show first 8 chars + ...)
            masked = secret[:8] + "..." + secret[-4:] if len(secret) > 16 else secret[:8] + "..."
            secrets.append({
                "type": label,
                "value_masked": masked,
                "length": len(secret),
                "risk": "critical",
                "source": urllib.parse.urlparse(source_url).path or source_url,
            })


def print_js_endpoints(target: str, result: Dict[str, Any]) -> None:
    """Pretty-print JS endpoint extraction results."""
    from fray.output import console, print_header

    print_header("Fray Recon — JS Endpoint Extraction", target=target)

    eps = result.get("endpoints", [])
    cats = result.get("categories", {})
    console.print(f"  Pages crawled: {result.get('pages_crawled', 0)}")
    console.print(f"  JS files parsed: {result.get('js_files_parsed', 0)}")
    console.print(f"  Endpoints found: [cyan]{len(eps)}[/cyan]")
    console.print()

    if cats:
        parts = []
        for label, key in [("API", "api"), ("GraphQL", "graphql"), ("Admin", "admin"),
                           ("Auth", "auth"), ("Other", "other")]:
            count = cats.get(key, 0)
            if count:
                parts.append(f"{label}: {count}")
        if parts:
            console.print(f"  Categories: {' · '.join(parts)}")
            console.print()

    if eps:
        from rich.table import Table
        table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("#", width=4, style="dim")
        table.add_column("Endpoint", min_width=35, style="cyan")
        table.add_column("Category", width=10)
        table.add_column("Found in", min_width=20, style="dim")

        cat_styles = {
            "api": "[green]api[/green]", "graphql": "[magenta]graphql[/magenta]",
            "admin": "[red]admin[/red]", "auth": "[yellow]auth[/yellow]",
            "upload": "[yellow]upload[/yellow]", "websocket": "[blue]ws[/blue]",
            "other": "[dim]other[/dim]",
        }

        for i, ep in enumerate(eps[:30], 1):
            cat_display = cat_styles.get(ep["category"], ep["category"])
            table.add_row(str(i), ep["path"], cat_display, ep["source"])

        console.print(table)
        if len(eps) > 30:
            console.print(f"    [dim]... and {len(eps) - 30} more[/dim]")
        console.print()
    else:
        console.print("  [dim]No JS endpoints found[/dim]")
        console.print()

    # ── Full URLs ──
    urls = result.get("full_urls", [])
    if urls:
        console.print(f"  [bold]Full URLs[/bold] ({len(urls)})")
        url_cat_styles = {
            "api": "[green]api[/green]", "admin": "[red]admin[/red]",
            "same-origin": "[cyan]same-origin[/cyan]", "third-party": "[dim]3rd-party[/dim]",
        }
        for u in urls[:15]:
            style = url_cat_styles.get(u["category"], "[dim]other[/dim]")
            console.print(f"    {style} {u['url']}")
        if len(urls) > 15:
            console.print(f"    [dim]... +{len(urls) - 15} more[/dim]")
        console.print()

    # ── Hostnames ──
    hosts = result.get("hostnames", [])
    if hosts:
        related = [h for h in hosts if h["related"]]
        third = [h for h in hosts if not h["related"]]
        console.print(f"  [bold]Hostnames[/bold] ({len(hosts)}: {len(related)} related, {len(third)} third-party)")
        risk_styles = {
            "high": "[bold red]HIGH[/bold red]", "medium": "[yellow]MED[/yellow]",
            "info": "[dim]info[/dim]",
        }
        for h in sorted(hosts, key=lambda x: (0 if x["risk"] == "high" else 1 if x["risk"] == "medium" else 2))[:15]:
            risk = risk_styles.get(h["risk"], "[dim]info[/dim]")
            rel = " [cyan](related)[/cyan]" if h["related"] else ""
            console.print(f"    {risk} {h['hostname']}{rel}")
        if len(hosts) > 15:
            console.print(f"    [dim]... +{len(hosts) - 15} more[/dim]")
        console.print()

    # ── Cloud Buckets ──
    buckets = result.get("cloud_buckets", [])
    if buckets:
        console.print(f"  [bold red]Cloud Buckets[/bold red] ({len(buckets)})")
        for b in buckets[:10]:
            console.print(f"    [bold red]⚠[/bold red] {b['provider']}: [bold]{b['bucket']}[/bold]  [dim]({b['source']})[/dim]")
        console.print()

    # ── Secrets ──
    secs = result.get("secrets", [])
    if secs:
        console.print(f"  [bold red]⚠ Exposed Secrets[/bold red] ({len(secs)})")
        for s in secs[:10]:
            console.print(f"    [bold red]CRITICAL[/bold red] {s['type']}: [bold]{s['value_masked']}[/bold] ({s['length']} chars)  [dim]({s['source']})[/dim]")
        console.print()

    # Summary
    total_findings = len(eps) + len(urls) + len(hosts) + len(buckets) + len(secs)
    console.print(f"  [bold]{total_findings}[/bold] total findings across JS files")
    if secs or buckets:
        console.print(f"  [bold red]⚠ {len(secs)} secret(s) + {len(buckets)} bucket(s) require immediate attention[/bold red]")
    console.print(f"  [dim]Test these: fray scan {target} -c xss -m 3[/dim]")
    console.print()


# ── Rate Limit Fingerprinting ────────────────────────────────────────────

def check_rate_limits(host: str, port: int, use_ssl: bool,
                      timeout: int = 8,
                      extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Fingerprint the rate limit threshold — requests/second before 429.

    Sends escalating bursts of benign requests to map the exact threshold
    where the WAF/server starts returning 429 or block responses.

    Returns:
        Dict with threshold (req/s), burst_limit, retry_after policy,
        rate_limit_headers, and recommended_delay for safe testing.
    """
    result: Dict[str, Any] = {
        "threshold_rps": None,         # requests/sec before 429
        "burst_limit": None,           # max burst before first 429
        "retry_after_policy": None,    # value of Retry-After header
        "rate_limit_headers": {},      # X-RateLimit-* headers
        "lockout_duration": None,      # seconds until unlocked
        "recommended_delay": 0.5,      # safe delay for testing
        "detection_type": None,        # "fixed-window", "sliding-window", "token-bucket", "none"
        "error": None,
    }

    path = "/"
    req_headers = {
        "Host": host,
        "User-Agent": f"Fray/{__version__} Recon",
        "Accept": "text/html,*/*",
        "Connection": "close",
    }
    if extra_headers:
        req_headers.update(extra_headers)

    def _send_one() -> Tuple[int, Dict[str, str], float]:
        """Send a single benign GET and return (status, headers, elapsed)."""
        try:
            start = time.monotonic()
            if use_ssl:
                try:
                    ctx = _make_ssl_context(verify=True)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=req_headers)
                    resp = conn.getresponse()
                except ssl.SSLError:
                    ctx = _make_ssl_context(verify=False)
                    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=req_headers)
                    resp = conn.getresponse()
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path, headers=req_headers)
                resp = conn.getresponse()

            elapsed = time.monotonic() - start
            status = resp.status
            headers = {k.lower(): v for k, v in resp.getheaders()}
            resp.read(1024)  # Drain
            conn.close()
            return status, headers, elapsed
        except Exception:
            return 0, {}, 0.0

    # Phase 1: Baseline — single request to capture rate limit headers
    status, headers, _ = _send_one()
    if status == 0:
        result["error"] = "Target unreachable"
        return result

    # Capture any rate limit headers from the first response
    rl_headers = {}
    for key in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
                "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
                "retry-after"):
        if key in headers:
            rl_headers[key] = headers[key]
    result["rate_limit_headers"] = rl_headers

    # If we already see rate limit headers, extract the declared limit
    declared_limit = None
    for key in ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"):
        if key in rl_headers:
            try:
                declared_limit = int(rl_headers[key])
                break
            except (ValueError, TypeError):
                pass

    # Phase 2: Escalating burst test — find the actual threshold
    # Start with small bursts, double each round: 2, 4, 8, 16, 32
    burst_sizes = [2, 4, 8, 16, 32]
    first_429_at = None

    for burst_size in burst_sizes:
        blocked_count = 0
        for _ in range(burst_size):
            s, h, _ = _send_one()
            if s in (429, 503) or s == 0:
                blocked_count += 1
                if first_429_at is None:
                    first_429_at = burst_size
                # Capture retry-after from the 429 response
                if "retry-after" in h and result["retry_after_policy"] is None:
                    result["retry_after_policy"] = h["retry-after"]
                    try:
                        result["lockout_duration"] = int(h["retry-after"])
                    except (ValueError, TypeError):
                        pass
                break  # Stop this burst on first 429

        if blocked_count > 0:
            break

        # Small cooldown between bursts to avoid false positives
        time.sleep(0.3)

    # Phase 3: If we hit 429, do a binary search for the exact threshold
    if first_429_at is not None:
        result["burst_limit"] = first_429_at

        # Wait for lockout to expire before probing further
        lockout_wait = result["lockout_duration"] or 5
        time.sleep(min(lockout_wait, 10))

        # Binary search: probe between burst_size/2 and burst_size
        lo = max(1, first_429_at // 2)
        hi = first_429_at
        for _ in range(4):  # Max 4 iterations of binary search
            mid = (lo + hi) // 2
            if mid == lo:
                break
            time.sleep(min(lockout_wait, 5))  # Cooldown between probes
            hit_429 = False
            for _ in range(mid):
                s, _, _ = _send_one()
                if s in (429, 503):
                    hit_429 = True
                    break
            if hit_429:
                hi = mid
            else:
                lo = mid
        result["burst_limit"] = lo

        # Estimate RPS threshold: burst_limit / time_window (assume 1s window)
        result["threshold_rps"] = lo

        # Classify detection type
        if declared_limit:
            result["detection_type"] = "fixed-window"
            result["threshold_rps"] = declared_limit
        else:
            # Heuristic: if burst_limit is small (<5), likely token-bucket
            if lo <= 5:
                result["detection_type"] = "token-bucket"
            else:
                result["detection_type"] = "sliding-window"

        # Recommend a safe delay
        if result["threshold_rps"] and result["threshold_rps"] > 0:
            result["recommended_delay"] = round(1.0 / (result["threshold_rps"] * 0.6), 2)
        else:
            result["recommended_delay"] = 2.0
    else:
        # No rate limiting detected
        result["detection_type"] = "none"
        result["threshold_rps"] = None
        result["burst_limit"] = None
        result["recommended_delay"] = 0.2  # Fast testing is safe
        if declared_limit:
            result["threshold_rps"] = declared_limit
            result["detection_type"] = "declared-only"
            result["recommended_delay"] = round(1.0 / (declared_limit * 0.6), 2)

    return result


# ── Differential Response Analysis ──────────────────────────────────────

def check_differential_responses(host: str, port: int, use_ssl: bool,
                                  timeout: int = 8,
                                  extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Compare responses between benign and malicious requests to fingerprint WAF detection mode.

    Sends a benign request, then known-blocked payloads, and measures:
    - Status code differences
    - Response body length differences
    - Response time differences (timing side-channel)
    - Header differences (new headers added by WAF)
    - Body content differences (block page signatures)

    Determines if WAF uses signature-based or anomaly-based detection.
    """
    result: Dict[str, Any] = {
        "detection_mode": None,         # "signature", "anomaly", "hybrid", "none"
        "baseline": {},                 # benign response fingerprint
        "blocked_fingerprint": {},      # blocked response fingerprint
        "timing_delta_ms": None,        # avg blocked - avg benign (ms)
        "body_length_delta": None,      # blocked body len - benign body len
        "status_code_pattern": None,    # e.g. "200→403" or "200→200 (soft block)"
        "extra_headers_on_block": [],   # headers only present on blocked responses
        "block_page_signatures": [],    # WAF block page indicators found
        "signature_detection": [],      # payloads that triggered signature blocks
        "anomaly_detection": [],        # payloads that triggered anomaly blocks
        "error": None,
    }

    path = "/"
    req_template = (
        "{method} {path} HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "User-Agent: Fray/{version} Recon\r\n"
        "Accept: text/html,*/*\r\n"
        "{extra}"
        "Connection: close\r\n\r\n{body}"
    )
    extra_hdr_str = ""
    if extra_headers:
        extra_hdr_str = "".join(f"{k}: {v}\r\n" for k, v in extra_headers.items())

    def _send_raw(method: str, req_path: str, body: str = "") -> Tuple[int, Dict[str, str], str, float]:
        """Send raw request, return (status, headers, body, elapsed_ms)."""
        try:
            req = req_template.format(
                method=method, path=req_path, host=host,
                version=__version__, extra=extra_hdr_str, body=body,
            )
            start = time.monotonic()
            if use_ssl:
                try:
                    ctx = _make_ssl_context(verify=True)
                    sock = socket.create_connection((host, port), timeout=timeout)
                    conn = ctx.wrap_socket(sock, server_hostname=host)
                except ssl.SSLError:
                    ctx = _make_ssl_context(verify=False)
                    sock = socket.create_connection((host, port), timeout=timeout)
                    conn = ctx.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=timeout)

            conn.sendall(req.encode("utf-8", errors="replace"))
            resp = b""
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    resp += data
                    if len(resp) > 50000:
                        break
                except (socket.error, socket.timeout, OSError):
                    break
            conn.close()
            elapsed_ms = (time.monotonic() - start) * 1000

            resp_str = resp.decode("utf-8", errors="replace")
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", resp_str)
            status = int(status_match.group(1)) if status_match else 0

            headers = {}
            body_str = ""
            if "\r\n\r\n" in resp_str:
                header_section, body_str = resp_str.split("\r\n\r\n", 1)
                for line in header_section.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

            return status, headers, body_str, elapsed_ms
        except Exception as e:
            return 0, {}, str(e), 0.0

    # ── Phase 1: Baseline (benign requests) ──
    benign_statuses = []
    benign_lengths = []
    benign_times = []
    benign_headers_set = set()

    for _ in range(3):
        s, h, b, t = _send_raw("GET", path)
        if s == 0:
            continue
        benign_statuses.append(s)
        benign_lengths.append(len(b))
        benign_times.append(t)
        benign_headers_set.update(h.keys())
        time.sleep(0.2)

    if not benign_statuses:
        result["error"] = "Target unreachable for baseline"
        return result

    avg_benign_status = max(set(benign_statuses), key=benign_statuses.count)
    avg_benign_len = sum(benign_lengths) // len(benign_lengths) if benign_lengths else 0
    avg_benign_time = sum(benign_times) / len(benign_times) if benign_times else 0

    result["baseline"] = {
        "status": avg_benign_status,
        "body_length": avg_benign_len,
        "response_time_ms": round(avg_benign_time, 1),
        "headers": sorted(benign_headers_set),
    }

    # ── Phase 2: Signature-triggering payloads ──
    # URL-encoded payloads so they pass edge HTTP parsers and reach actual WAF rules.
    # Raw chars (<, ', ;) get 400'd by Cloudflare/CDN edge before the WAF sees them.
    signature_payloads = [
        ("XSS", "?input=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("SQLi", "?input=%27%20OR%201%3D1--"),
        ("Path Traversal", "?input=../../etc/passwd"),
        ("Command Injection", "?input=%3Bcat%20%2Fetc%2Fpasswd"),
        ("SSTI", "?input=%7B%7B7*7%7D%7D"),
    ]

    blocked_statuses = []
    blocked_lengths = []
    blocked_times = []
    blocked_headers_set = set()
    block_bodies = []

    def _is_blocked(s: int, b: str, sigs: tuple) -> bool:
        """Determine if a response indicates a WAF block vs normal page."""
        # Hard block: unambiguous status codes
        if s in (400, 403, 406, 429, 500, 503):
            return True
        # Empty body with different status = likely WAF drop/reset
        if s != avg_benign_status and (not b or len(b) == 0):
            return True
        # Dramatic body size change (>80% smaller) = block page replaced content
        if s != 0 and avg_benign_len > 100 and len(b) < avg_benign_len * 0.2:
            return True
        # Soft block: body must contain WAF signature AND differ
        # significantly from baseline (>20% body length delta)
        if s == avg_benign_status and b:
            body_len_ratio = abs(len(b) - avg_benign_len) / max(avg_benign_len, 1)
            if body_len_ratio < 0.2:
                # Response is same size as baseline — same page, not blocked
                return False
            b_lower = b.lower()
            if any(sig in b_lower for sig in sigs):
                return True
        elif b:
            # Different status code — check for block page content
            b_lower = b.lower()
            if any(sig in b_lower for sig in sigs):
                return True
        return False

    _sig_block_sigs = (
        "access denied", "blocked", "forbidden", "web application firewall",
        "captcha", "challenge", "error code:", "request blocked",
        "mod_security", "modsecurity", "attention required",
    )
    _anom_block_sigs = (
        "access denied", "blocked", "forbidden", "web application firewall",
        "captcha", "challenge",
    )

    for label, payload_path in signature_payloads:
        s, h, b, t = _send_raw("GET", path + payload_path)
        if s == 0:
            continue

        is_blocked = _is_blocked(s, b, _sig_block_sigs)

        if is_blocked:
            result["signature_detection"].append({
                "label": label,
                "payload": payload_path,
                "status": s,
                "response_time_ms": round(t, 1),
                "body_length": len(b),
            })
            blocked_statuses.append(s)
            blocked_lengths.append(len(b))
            blocked_times.append(t)
            blocked_headers_set.update(h.keys())
            block_bodies.append(b)
        time.sleep(0.3)

    # ── Phase 3: Anomaly-triggering payloads ──
    # These are syntactically valid but unusual — anomaly-based WAFs may flag them
    anomaly_payloads = [
        ("Long param", "?input=" + "A" * 2000),
        ("Unusual encoding", "?input=%00%0d%0a"),
        ("Unicode abuse", "?input=%ef%bc%9cscript%ef%bc%9e"),
        ("Double encoding", "?input=%253Cscript%253E"),
    ]

    for label, payload_path in anomaly_payloads:
        s, h, b, t = _send_raw("GET", path + payload_path)
        if s == 0:
            continue

        is_blocked = _is_blocked(s, b, _anom_block_sigs)

        if is_blocked:
            result["anomaly_detection"].append({
                "label": label,
                "payload": payload_path,
                "status": s,
                "response_time_ms": round(t, 1),
                "body_length": len(b),
            })
            blocked_statuses.append(s)
            blocked_lengths.append(len(b))
            blocked_times.append(t)
            blocked_headers_set.update(h.keys())
            block_bodies.append(b)
        time.sleep(0.3)

    # ── Phase 4: Analyze differences ──
    if blocked_statuses:
        avg_blocked_status = max(set(blocked_statuses), key=blocked_statuses.count)
        avg_blocked_len = sum(blocked_lengths) // len(blocked_lengths)
        avg_blocked_time = sum(blocked_times) / len(blocked_times)

        result["blocked_fingerprint"] = {
            "status": avg_blocked_status,
            "body_length": avg_blocked_len,
            "response_time_ms": round(avg_blocked_time, 1),
            "headers": sorted(blocked_headers_set),
        }

        result["timing_delta_ms"] = round(avg_blocked_time - avg_benign_time, 1)
        result["body_length_delta"] = avg_blocked_len - avg_benign_len

        # Status code pattern
        if avg_blocked_status != avg_benign_status:
            result["status_code_pattern"] = f"{avg_benign_status}→{avg_blocked_status}"
        else:
            result["status_code_pattern"] = f"{avg_benign_status}→{avg_blocked_status} (soft block)"

        # Extra headers on block
        extra_on_block = blocked_headers_set - benign_headers_set
        result["extra_headers_on_block"] = sorted(extra_on_block)

        # Block page signatures
        for body in block_bodies:
            b_lower = body.lower()
            for sig_name, sig_pattern in [
                ("Cloudflare", "cf-error-details"),
                ("Cloudflare Ray", "ray id:"),
                ("Akamai", "reference #"),
                ("Imperva", "incident id"),
                ("AWS WAF", "request blocked"),
                ("ModSecurity", "modsecurity"),
                ("F5 BIG-IP", "the requested url was rejected"),
                ("Sucuri", "sucuri"),
                ("Generic WAF", "web application firewall"),
                ("CAPTCHA", "captcha"),
            ]:
                if sig_pattern in b_lower and sig_name not in result["block_page_signatures"]:
                    result["block_page_signatures"].append(sig_name)

        # Determine detection mode
        has_sig = len(result["signature_detection"]) > 0
        has_anomaly = len(result["anomaly_detection"]) > 0

        if has_sig and has_anomaly:
            result["detection_mode"] = "hybrid"
        elif has_sig:
            result["detection_mode"] = "signature"
        elif has_anomaly:
            result["detection_mode"] = "anomaly"
        else:
            result["detection_mode"] = "none"

        # ── Phase 5: WAF intel lookup — recommend bypass techniques ──
        try:
            from fray import load_waf_intel
            intel = load_waf_intel()
            vendors_db = intel.get("vendors", {})
            technique_matrix = intel.get("technique_matrix", {})

            # Identify WAF vendor from block page signatures + headers
            detected_vendor = None
            block_sigs = result.get("block_page_signatures", [])
            extra_hdrs = result.get("extra_headers_on_block", [])

            vendor_hints = {
                "cloudflare": (["Cloudflare", "Cloudflare Ray", "CAPTCHA"], ["cf-mitigated", "cf-ray"]),
                "aws_waf": (["AWS WAF"], ["x-amzn-waf-action"]),
                "azure_waf": ([], ["x-azure-ref", "x-msedge-ref"]),
                "akamai": (["Akamai"], []),
                "imperva": (["Imperva"], ["x-iinfo"]),
                "f5_bigip": (["F5 BIG-IP"], []),
                "modsecurity": (["ModSecurity"], []),
                "sucuri": (["Sucuri"], ["x-sucuri-id"]),
                "fastly": ([], ["x-sigsci-requestid", "fastly-io-info"]),
            }

            for vkey, (sig_names, hdr_names) in vendor_hints.items():
                if any(s in block_sigs for s in sig_names):
                    detected_vendor = vkey
                    break
                if any(h in extra_hdrs for h in hdr_names):
                    detected_vendor = vkey
                    break

            if detected_vendor and detected_vendor in vendors_db:
                vdata = vendors_db[detected_vendor]
                effective = vdata.get("bypass_techniques", {}).get("effective", [])
                ineffective = vdata.get("bypass_techniques", {}).get("ineffective", [])
                gaps = vdata.get("detection_gaps", {})
                rec_cats = vdata.get("recommended_categories", [])

                result["waf_vendor"] = vdata.get("display_name", detected_vendor)
                result["recommended_bypasses"] = [
                    {"technique": t["technique"], "confidence": t.get("confidence", "?"),
                     "description": t["description"]}
                    for t in effective[:5]
                ]
                result["ineffective_techniques"] = [t["technique"] for t in ineffective]
                result["detection_gaps"] = {
                    "signature_misses": gaps.get("signature", {}).get("misses", []),
                    "anomaly_misses": gaps.get("anomaly", {}).get("misses", []),
                }
                result["recommended_categories"] = rec_cats
                result["recommended_delay"] = vdata.get("recommended_delay", 0.5)
        except Exception:
            pass  # Intel lookup is best-effort
    else:
        result["detection_mode"] = "none"
        result["blocked_fingerprint"] = {}

    return result


# ── WAF Rule Gap Analysis ─────────────────────────────────────────────────

def waf_gap_analysis(
    waf_vendor: Optional[str] = None,
    recon_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Cross-reference detected WAF vendor against waf_intel knowledge base.

    Produces a prioritised list of bypass techniques, detection gaps,
    and concrete payload recommendations specific to the identified vendor.

    Works in three tiers:
      1. Explicit *waf_vendor* argument (from detector.py or user input).
      2. Vendor inferred from differential analysis (recon_result["differential"]).
      3. Vendor inferred from response headers / DNS / cookies in *recon_result*.

    Returns a dict suitable for inclusion in recon output and print_recon display.
    """
    from fray import load_waf_intel

    result: Dict[str, Any] = {
        "waf_vendor": None,
        "vendor_key": None,
        "detection_mode": None,
        "block_behavior": {},
        "bypass_strategies": [],      # prioritised, with confidence
        "ineffective_techniques": [],  # skip these — save time
        "detection_gaps": {
            "signature_misses": [],
            "anomaly_misses": [],
        },
        "technique_matrix": [],       # ✅/❌ per technique for this vendor
        "recommended_categories": [],
        "recommended_delay": None,
        "risk_summary": None,
        "error": None,
    }

    intel = load_waf_intel()
    vendors_db = intel.get("vendors", {})
    technique_matrix = intel.get("technique_matrix", {})

    if not vendors_db:
        result["error"] = "waf_intel.json not found or empty"
        return result

    # ── Tier 1: explicit vendor name ──
    vendor_key = _resolve_vendor_key(waf_vendor, vendors_db) if waf_vendor else None

    # ── Tier 2: from differential analysis ──
    if not vendor_key and recon_result:
        diff = recon_result.get("differential", {})
        diff_vendor = diff.get("waf_vendor")
        if diff_vendor:
            vendor_key = _resolve_vendor_key(diff_vendor, vendors_db)

    # ── Tier 3: infer from headers / DNS / cookies ──
    if not vendor_key and recon_result:
        vendor_key = _infer_vendor_from_recon(recon_result, vendors_db)

    if not vendor_key:
        result["risk_summary"] = "No WAF vendor identified — gap analysis requires a known vendor"
        return result

    vdata = vendors_db[vendor_key]
    result["waf_vendor"] = vdata.get("display_name", vendor_key)
    result["vendor_key"] = vendor_key
    result["detection_mode"] = vdata.get("detection_mode")
    result["block_behavior"] = vdata.get("block_behavior", {})
    result["recommended_delay"] = vdata.get("recommended_delay")
    result["recommended_categories"] = vdata.get("recommended_categories", [])

    # ── Bypass strategies — merge intel with differential findings ──
    effective = vdata.get("bypass_techniques", {}).get("effective", [])
    ineffective = vdata.get("bypass_techniques", {}).get("ineffective", [])

    # Enrich with differential results if available
    diff_sigs = []
    diff_anoms = []
    if recon_result:
        diff = recon_result.get("differential", {})
        diff_sigs = [s["label"] for s in diff.get("signature_detection", [])]
        diff_anoms = [a["label"] for a in diff.get("anomaly_detection", [])]

    for tech in effective:
        entry = {
            "technique": tech["technique"],
            "confidence": tech.get("confidence", "unknown"),
            "description": tech["description"],
            "payload_example": tech.get("payload_example", ""),
            "notes": tech.get("notes", ""),
        }
        # Boost confidence if differential analysis confirmed the gap
        if tech["technique"] == "double_encoding" and not diff_anoms:
            entry["live_confirmed"] = True
            if entry["confidence"] == "medium":
                entry["confidence"] = "high"
        result["bypass_strategies"].append(entry)

    result["ineffective_techniques"] = [
        {"technique": t["technique"], "reason": t.get("description", "")}
        for t in ineffective
    ]

    # ── Detection gaps ──
    gaps = vdata.get("detection_gaps", {})
    sig_gaps = gaps.get("signature", {})
    anom_gaps = gaps.get("anomaly", {})

    result["detection_gaps"]["signature_misses"] = sig_gaps.get("misses", [])
    result["detection_gaps"]["anomaly_misses"] = anom_gaps.get("misses", [])

    # Cross-check: if differential analysis showed a payload category was NOT
    # blocked, and intel says it should be, flag as a configuration gap.
    sig_blocks = sig_gaps.get("blocks", [])
    config_gaps = []
    for label in ("XSS", "SQLi", "Path Traversal", "Command Injection", "SSTI"):
        if label in sig_blocks and label not in diff_sigs and diff_sigs:
            config_gaps.append(f"{label} expected to be blocked but was not — possible config gap")
    if config_gaps:
        result["detection_gaps"]["config_gaps"] = config_gaps

    # ── Technique matrix — ✅/❌ for this vendor ──
    for tech_name, tech_data in technique_matrix.items():
        if not isinstance(tech_data, dict):
            continue
        effective_against = tech_data.get("effective_against", [])
        blocked_by = tech_data.get("blocked_by", [])
        if vendor_key in effective_against:
            result["technique_matrix"].append({
                "technique": tech_name,
                "status": "effective",
                "notes": tech_data.get("notes", ""),
            })
        elif vendor_key in blocked_by:
            result["technique_matrix"].append({
                "technique": tech_name,
                "status": "blocked",
                "notes": tech_data.get("notes", ""),
            })
        else:
            result["technique_matrix"].append({
                "technique": tech_name,
                "status": "untested",
                "notes": tech_data.get("notes", ""),
            })

    # ── Risk summary ──
    n_effective = sum(1 for s in result["bypass_strategies"] if s["confidence"] in ("high", "medium"))
    n_sig_gaps = len(result["detection_gaps"]["signature_misses"])
    n_anom_gaps = len(result["detection_gaps"]["anomaly_misses"])
    n_config = len(result["detection_gaps"].get("config_gaps", []))

    if n_effective >= 3 or n_sig_gaps >= 2:
        result["risk_summary"] = f"HIGH — {n_effective} viable bypass techniques, {n_sig_gaps} signature gaps, {n_anom_gaps} anomaly gaps"
    elif n_effective >= 1 or n_sig_gaps >= 1:
        result["risk_summary"] = f"MEDIUM — {n_effective} viable bypass techniques, {n_sig_gaps + n_anom_gaps} detection gaps"
    else:
        result["risk_summary"] = f"LOW — no high-confidence bypasses identified, {n_sig_gaps + n_anom_gaps} potential gaps"
    if n_config:
        result["risk_summary"] += f", {n_config} config discrepancies"

    return result


def _resolve_vendor_key(vendor_name: str, vendors_db: Dict[str, Any]) -> Optional[str]:
    """Resolve a display name or alias to a waf_intel vendor key."""
    name_lower = vendor_name.lower()
    # Exact key match
    if name_lower.replace(" ", "_") in vendors_db:
        return name_lower.replace(" ", "_")
    # Substring match on key
    for key in vendors_db:
        if key.replace("_", " ") in name_lower or name_lower in key.replace("_", " "):
            return key
    # Match on display_name
    for key, data in vendors_db.items():
        if name_lower in data.get("display_name", "").lower():
            return key
    return None


def _infer_vendor_from_recon(recon: Dict[str, Any], vendors_db: Dict[str, Any]) -> Optional[str]:
    """Try to identify WAF vendor from response headers, DNS, and cookies."""
    # Check response headers
    headers = recon.get("headers", {})
    raw_headers = headers.get("raw_headers", {}) if isinstance(headers, dict) else {}

    # Flatten all header keys we've seen
    all_header_keys = set()
    if isinstance(raw_headers, dict):
        all_header_keys.update(k.lower() for k in raw_headers.keys())

    # Also check from the page fetch headers stored elsewhere
    page_headers = recon.get("page_headers", {})
    if isinstance(page_headers, dict):
        all_header_keys.update(k.lower() for k in page_headers.keys())

    # DNS/CDN info
    dns_info = recon.get("dns", {})
    cdn = dns_info.get("cdn_detected", "")
    cnames = dns_info.get("cname", [])
    cname_str = " ".join(cnames).lower() if cnames else ""

    # Cookie names
    cookies = recon.get("cookies", {})
    cookie_names = set()
    if isinstance(cookies, dict):
        for c in cookies.get("cookies", []):
            if isinstance(c, dict):
                cookie_names.add(c.get("name", "").lower())

    # Header-based vendor detection
    header_vendor_map = {
        "cloudflare": ["cf-ray", "cf-cache-status", "cf-mitigated"],
        "aws_waf": ["x-amzn-waf-action", "x-amz-cf-id", "x-amzn-requestid"],
        "azure_waf": ["x-azure-ref", "x-msedge-ref", "x-azure-fdid"],
        "akamai": ["akamai-origin-hop", "x-akamai-transformed"],
        "imperva": ["x-cdn", "x-iinfo"],
        "fastly": ["x-fastly-request-id", "fastly-io-info", "x-sigsci-requestid"],
        "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "f5_bigip": ["x-wa-info", "x-cnection"],
    }

    for vendor_key, hdr_indicators in header_vendor_map.items():
        if any(h in all_header_keys for h in hdr_indicators):
            if vendor_key in vendors_db:
                return vendor_key

    # Cookie-based detection
    cookie_vendor_map = {
        "cloudflare": ["__cfduid", "__cflb", "cf_clearance"],
        "aws_waf": ["awsalb", "awsalbcors"],
        "azure_waf": ["arr_affinity", "arraffinitysamesite"],
        "akamai": ["ak_bmsc", "bm_sv", "bm_sz"],
        "imperva": ["incap_ses", "visid_incap"],
        "f5_bigip": ["bigipserver", "f5_cspm"],
        "sucuri": ["sucuri_cloudproxy_uuid"],
    }

    for vendor_key, cookie_indicators in cookie_vendor_map.items():
        if any(c in cookie_names for c in cookie_indicators):
            if vendor_key in vendors_db:
                return vendor_key

    # CNAME / CDN based detection
    if cdn:
        cdn_lower = cdn.lower()
        if "cloudflare" in cdn_lower:
            return "cloudflare"
        if "cloudfront" in cdn_lower or "aws" in cdn_lower:
            return "aws_waf"
        if "akamai" in cdn_lower:
            return "akamai"
        if "azure" in cdn_lower:
            return "azure_waf"
        if "fastly" in cdn_lower:
            return "fastly"
        if "sucuri" in cdn_lower:
            return "sucuri"
        if "imperva" in cdn_lower or "incapsula" in cdn_lower:
            return "imperva"

    if "cloudflare" in cname_str:
        return "cloudflare"
    if "akamai" in cname_str:
        return "akamai"
    if "cloudfront" in cname_str:
        return "aws_waf"
    if "azureedge" in cname_str or "azurefd" in cname_str:
        return "azure_waf"

    return None


# ── Parameter Discovery ──────────────────────────────────────────────────

def discover_params(url: str, max_depth: int = 2, max_pages: int = 10,
                    timeout: int = 8, verify_ssl: bool = True,
                    extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Lightweight crawl + parameter extraction.

    Discovers injectable parameters from:
      - URL query strings
      - HTML form inputs (<input>, <textarea>, <select>)
      - JavaScript API endpoints (fetch, axios, XMLHttpRequest)

    Returns dict with params list and summary stats.
    """
    from fray.scanner import (
        _fetch, extract_links, extract_query_params,
        extract_forms, extract_js_endpoints, _same_origin,
    )

    parsed = urllib.parse.urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    visited = set()
    queue = [(url, 0)]
    all_params = []  # list of dicts
    seen = set()     # (url, param, method) dedup
    total_forms = 0
    total_js = 0

    while queue and len(visited) < max_pages:
        current_url, depth = queue.pop(0)
        canonical = current_url.split("?")[0].split("#")[0]
        if canonical in visited:
            continue
        visited.add(canonical)

        # Skip static resources
        lower = canonical.lower()
        if any(lower.endswith(ext) for ext in (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
            ".mp3", ".mp4", ".webp", ".avif",
        )):
            continue

        status, body, resp_headers = _fetch(current_url, timeout=timeout,
                                            verify_ssl=verify_ssl,
                                            headers=extra_headers)
        if status == 0 or not body:
            continue

        # Follow redirects
        if status in (301, 302, 307, 308):
            loc = resp_headers.get("location", "")
            if loc:
                redir_url = urllib.parse.urljoin(current_url, loc)
                if _same_origin(url, redir_url) and redir_url.split("?")[0] not in visited:
                    queue.append((redir_url, depth))
            continue

        content_type = resp_headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            continue

        # 1. Query parameters
        for pt in extract_query_params(current_url):
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "query",
                })

        # 2. HTML forms
        form_pts, fc = extract_forms(current_url, body)
        total_forms += fc
        for pt in form_pts:
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "form",
                })

        # 3. JavaScript endpoints
        js_pts, jc = extract_js_endpoints(current_url, body)
        total_js += jc
        for pt in js_pts:
            key = (pt.url, pt.param, pt.method)
            if key not in seen:
                seen.add(key)
                all_params.append({
                    "url": pt.url, "param": pt.param,
                    "method": pt.method, "source": "js",
                })

        # Follow links if not at max depth
        if depth < max_depth:
            for link in extract_links(current_url, body):
                link_canon = link.split("?")[0].split("#")[0]
                if link_canon not in visited and _same_origin(url, link):
                    queue.append((link, depth + 1))

    return {
        "params": all_params,
        "pages_crawled": len(visited),
        "total_params": len(all_params),
        "forms_found": total_forms,
        "js_endpoints": total_js,
        "sources": {
            "query": sum(1 for p in all_params if p["source"] == "query"),
            "form": sum(1 for p in all_params if p["source"] == "form"),
            "js": sum(1 for p in all_params if p["source"] == "js"),
        },
    }


# ── Full recon pipeline ──────────────────────────────────────────────────

def run_recon(url: str, timeout: int = 8,
              headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Run full reconnaissance on a target URL.

    Args:
        url: Target URL
        timeout: Request timeout in seconds
        headers: Extra HTTP headers for authenticated scanning (Cookie, Authorization, etc.)
    """
    host, path, port, use_ssl = _parse_url(url)

    result: Dict[str, Any] = {
        "target": url,
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "authenticated": bool(headers),
        "http": {},
        "tls": {},
        "headers": {},
        "csp": {},
        "cookies": {},
        "fingerprint": {},
        "dns": {},
        "robots": {},
        "cors": {},
        "exposed_files": {},
        "http_methods": {},
        "error_page": {},
        "subdomains": {},
        "recommended_categories": [],
    }

    # 1. HTTP check
    result["http"] = check_http(host, timeout=timeout)

    # 2. TLS audit (only if HTTPS target or port 443)
    if use_ssl or port == 443:
        result["tls"] = check_tls(host, port=port, timeout=timeout)

    # 3. Fetch page for headers + body fingerprinting (with auth headers)
    status, resp_headers, body = _http_get(host, port, path, use_ssl, timeout=timeout,
                                           extra_headers=headers)
    result["page_status"] = status

    # 4. Security headers
    result["headers"] = check_security_headers(resp_headers)

    # 5. CSP analysis
    from fray.csp import get_csp_from_headers, analyze_csp
    csp_value, csp_report_only = get_csp_from_headers(resp_headers)
    csp_analysis = analyze_csp(csp_value, report_only=csp_report_only)
    result["csp"] = {
        "present": csp_analysis.present,
        "report_only": csp_analysis.report_only,
        "score": csp_analysis.score,
        "weaknesses": [{"id": w.id, "severity": w.severity, "directive": w.directive,
                        "description": w.description} for w in csp_analysis.weaknesses],
        "bypass_techniques": csp_analysis.bypass_techniques,
        "recommendations": csp_analysis.recommendations,
    }

    # 6. Cookie security audit
    result["cookies"] = check_cookies(resp_headers)

    # 7. App fingerprinting
    result["fingerprint"] = fingerprint_app(resp_headers, body)

    # 7. DNS records + CDN detection
    result["dns"] = check_dns(host)

    # 8. robots.txt + sitemap.xml
    result["robots"] = check_robots_sitemap(host, port, use_ssl, timeout=timeout)

    # 9. CORS check
    result["cors"] = check_cors(host, port, use_ssl, timeout=timeout)

    # 10. Exposed files
    result["exposed_files"] = check_exposed_files(host, port, use_ssl, timeout=timeout)

    # 11. HTTP methods
    result["http_methods"] = check_http_methods(host, port, use_ssl, timeout=timeout)

    # 12. Error page fingerprinting
    result["error_page"] = check_error_page(host, port, use_ssl, timeout=timeout)

    # 13. Subdomain enumeration (crt.sh — can be slow)
    result["subdomains"] = check_subdomains_crt(host, timeout=timeout)

    # 14. Smart payload recommendation
    result["recommended_categories"] = recommend_categories(result["fingerprint"])

    # 15. Add csp_bypass to recommendations if weak CSP detected
    if csp_analysis.bypass_techniques:
        if "csp_bypass" not in result["recommended_categories"]:
            result["recommended_categories"].insert(0, "csp_bypass")

    # 16. Parameter discovery (lightweight crawl)
    verify = use_ssl  # match the target's SSL setting
    result["params"] = discover_params(url, max_depth=2, max_pages=10,
                                       timeout=timeout, verify_ssl=verify,
                                       extra_headers=headers)

    # 17. Historical URL discovery (Wayback, sitemap, robots)
    result["historical_urls"] = discover_historical_urls(url, timeout=timeout,
                                                         verify_ssl=verify,
                                                         extra_headers=headers)

    # 18. GraphQL introspection probe
    result["graphql"] = check_graphql_introspection(host, port, use_ssl,
                                                     timeout=timeout,
                                                     extra_headers=headers)
    # 19. API discovery (Swagger/OpenAPI specs, versioned roots, health)
    result["api_discovery"] = check_api_discovery(host, port, use_ssl,
                                                   timeout=timeout,
                                                   extra_headers=headers)

    # 20. Host Header Injection probe
    result["host_header_injection"] = check_host_header_injection(
        host, port, use_ssl, timeout=timeout, extra_headers=headers)

    # 21. Admin panel discovery
    result["admin_panels"] = check_admin_panels(host, port, use_ssl,
                                                 timeout=timeout,
                                                 extra_headers=headers)

    # 22. Rate limit fingerprinting
    result["rate_limits"] = check_rate_limits(host, port, use_ssl,
                                               timeout=timeout,
                                               extra_headers=headers)

    # 23. Differential response analysis (WAF detection mode)
    result["differential"] = check_differential_responses(host, port, use_ssl,
                                                           timeout=timeout,
                                                           extra_headers=headers)

    # 24. WAF rule gap analysis (cross-reference vendor against waf_intel)
    result["gap_analysis"] = waf_gap_analysis(recon_result=result)

    # Merge gap analysis recommended categories into main recommendations
    gap_cats = result.get("gap_analysis", {}).get("recommended_categories", [])
    for cat in gap_cats:
        if cat not in result["recommended_categories"]:
            result["recommended_categories"].append(cat)

    # Add prototype_pollution to recommendations if Node.js detected
    fp_techs = result.get("fingerprint", {}).get("technologies", {})
    if any(t in fp_techs for t in ("node.js", "express")):
        if "prototype_pollution" not in result["recommended_categories"]:
            result["recommended_categories"].append("prototype_pollution")

    return result


def print_recon(result: Dict[str, Any]) -> None:
    """Pretty-print recon results to terminal with rich formatting."""
    from fray.output import console, print_header, severity_style
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    def _score_color(score, max_val=100):
        pct = score / max_val * 100 if max_val else 0
        if pct >= 70: return "green"
        if pct >= 40: return "yellow"
        return "red"

    print_header("Fray Recon — Target Reconnaissance", target=result['target'])
    console.print(f"  Host: {result['host']}")
    console.print()

    # ── HTTP ──
    http = result.get("http", {})
    port80 = http.get("port_80_open", False)
    redir = http.get("redirects_to_https", False)
    console.print("  [bold]HTTP[/bold]")
    p80 = "[yellow]⚠ OPEN[/yellow]" if port80 else "[dim]closed[/dim]"
    redir_s = "[green]✅[/green]" if redir else ("[red]❌[/red]" if port80 else "[dim]N/A[/dim]")
    console.print(f"    Port 80:            {p80}")
    console.print(f"    Redirects to HTTPS: {redir_s}")
    if port80 and not redir:
        console.print("    [red]⚠ HTTP traffic is not redirected to HTTPS![/red]")
    console.print()

    # ── TLS ──
    tls = result.get("tls", {})
    if tls and not tls.get("error"):
        v = str(tls.get("tls_version", "?"))
        vc = "green" if "1.3" in v else ("yellow" if "1.2" in v else "red")
        console.print("  [bold]TLS[/bold]")
        console.print(f"    Version:  [{vc}]{v}[/{vc}]")
        console.print(f"    Cipher:   {tls.get('cipher', '?')} ({tls.get('cipher_bits', '?')} bits)")
        console.print(f"    Subject:  {tls.get('cert_subject', '?')}")
        console.print(f"    Issuer:   {tls.get('cert_issuer', '?')}")
        days = tls.get("cert_days_remaining")
        if days is not None:
            if days < 0:
                console.print(f"    Expiry:   [red]EXPIRED ({abs(days)} days ago)[/red]")
            elif days < 30:
                console.print(f"    Expiry:   [yellow]{days} days remaining[/yellow]")
            else:
                console.print(f"    Expiry:   [green]{days} days remaining[/green]")
        if tls.get("supports_tls_1_0"):
            console.print("    [red]⚠ TLS 1.0 supported (insecure)[/red]")
        if tls.get("supports_tls_1_1"):
            console.print("    [red]⚠ TLS 1.1 supported (deprecated)[/red]")
        console.print()
    elif tls and tls.get("error"):
        console.print("  [bold]TLS[/bold]")
        console.print(f"    [red]Error: {tls['error']}[/red]")
        console.print()

    # ── Security Headers ──
    hdr = result.get("headers", {})
    score = hdr.get("score", 0)
    sc = _score_color(score)
    console.print(f"  [bold]Security Headers[/bold] ([{sc}]{score}%[/{sc}])")

    hdr_table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    hdr_table.add_column("Icon", width=4)
    hdr_table.add_column("Header", min_width=30)
    hdr_table.add_column("Detail", min_width=20)

    for name, info in hdr.get("present", {}).items():
        hdr_table.add_row("[green]✅[/green]", name, f"[dim]{info['value'][:55]}[/dim]")
    for name, info in hdr.get("missing", {}).items():
        sev = info.get("severity", "low")
        hdr_table.add_row("[red]❌[/red]", name, f"[{severity_style(sev)}]({sev})[/{severity_style(sev)}]")

    console.print(hdr_table)
    console.print()

    # ── CSP Analysis ──
    csp = result.get("csp", {})
    if csp:
        csp_score = csp.get("score", 0)
        cc = _score_color(csp_score)
        label = "CSP Analysis"
        if csp.get("report_only"):
            label += " [yellow](report-only — NOT enforced)[/yellow]"
        console.print(f"  [bold]{label}[/bold] ([{cc}]{csp_score}/100[/{cc}])")
        if not csp.get("present"):
            console.print("    [red]❌ No Content-Security-Policy header[/red]")
        else:
            for w in csp.get("weaknesses", []):
                sev = w.get("severity", "low")
                ss = severity_style(sev)
                console.print(f"    [{ss}]⚠ \\[{w['directive']}] {w['description']}[/{ss}]")
            if csp.get("bypass_techniques"):
                console.print(f"    [cyan]Testable bypass techniques: {', '.join(csp['bypass_techniques'])}[/cyan]")
            for rec in csp.get("recommendations", []):
                console.print(f"    [dim]💡 {rec}[/dim]")
        console.print()

    # ── Cookies ──
    ck = result.get("cookies", {})
    cookies = ck.get("cookies", [])
    issues = ck.get("issues", [])
    if cookies:
        ck_score = ck.get("score", 100)
        ckc = _score_color(ck_score)
        console.print(f"  [bold]Cookies[/bold] ([{ckc}]{ck_score}%[/{ckc}])")

        cookie_table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
        cookie_table.add_column("Name", min_width=25)
        cookie_table.add_column("Flags", min_width=30)

        for c in cookies:
            flags = []
            flags.append(f"[green]HttpOnly[/green]" if c.get("httponly") else f"[red]HttpOnly[/red]")
            flags.append(f"[green]Secure[/green]" if c.get("secure") else f"[red]Secure[/red]")
            ss = c.get("samesite")
            if ss and ss is not True:
                flags.append(f"[green]SameSite={ss}[/green]")
            elif ss is True:
                flags.append(f"[green]SameSite[/green]")
            else:
                flags.append(f"[red]SameSite[/red]")
            cookie_table.add_row(f"    {c['name']}", " │ ".join(flags))

        console.print(cookie_table)
        if issues:
            console.print()
            for iss in issues:
                sev = iss["severity"]
                ss = severity_style(sev)
                console.print(f"    [{ss}]⚠ {iss['cookie']}: {iss['issue']}[/{ss}]")
                console.print(f"      [dim]{iss['risk']}[/dim]")
        console.print()

    # ── Fingerprint ──
    fp = result.get("fingerprint", {})
    techs = fp.get("technologies", {})
    console.print("  [bold]Detected Technologies[/bold]")
    if techs:
        from rich.progress_bar import ProgressBar
        for tech, conf in techs.items():
            bar_len = int(conf * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            bc = "green" if conf >= 0.7 else ("yellow" if conf >= 0.4 else "dim")
            console.print(f"    {tech:<16} [{bc}]{bar} {conf:.0%}[/{bc}]")
    else:
        console.print("    [dim]No technologies identified[/dim]")
    console.print()

    # ── DNS ──
    dns = result.get("dns", {})
    if dns and (dns.get("a") or dns.get("cname") or dns.get("ns")):
        console.print("  [bold]DNS[/bold]")
        if dns.get("a"):
            console.print(f"    A:     {', '.join(dns['a'][:5])}")
        if dns.get("aaaa"):
            console.print(f"    AAAA:  {', '.join(dns['aaaa'][:3])}")
        if dns.get("cname"):
            console.print(f"    CNAME: {', '.join(dns['cname'][:3])}")
        if dns.get("ns"):
            console.print(f"    NS:    {', '.join(dns['ns'][:4])}")
        if dns.get("mx"):
            console.print(f"    MX:    {', '.join(dns['mx'][:3])}")
        cdn = dns.get("cdn_detected")
        if cdn:
            console.print(f"    CDN:   [cyan]{cdn}[/cyan]")
        spf = dns.get("has_spf", False)
        dmarc = dns.get("has_dmarc", False)
        spf_i = "[green]✅[/green]" if spf else "[red]❌[/red]"
        dmarc_i = "[green]✅[/green]" if dmarc else "[red]❌[/red]"
        console.print(f"    SPF:   {spf_i}  DMARC: {dmarc_i}")
        console.print()

    # ── robots.txt ──
    robots = result.get("robots", {})
    if robots.get("robots_txt"):
        disallowed = robots.get("disallowed_paths", [])
        interesting = robots.get("interesting_paths", [])
        sitemaps = robots.get("sitemaps", [])
        console.print(f"  [bold]robots.txt[/bold] ({len(disallowed)} disallowed paths)")
        if interesting:
            console.print("    [yellow]Interesting paths:[/yellow]")
            for p in interesting[:10]:
                console.print(f"      [yellow]{p}[/yellow]")
        if sitemaps:
            console.print(f"    Sitemaps: {', '.join(sitemaps[:3])}")
        console.print()

    # ── CORS ──
    cors = result.get("cors", {})
    if cors.get("cors_enabled"):
        misc = cors.get("misconfigured", False)
        mc = "red" if misc else "green"
        ml = "MISCONFIGURED" if misc else "OK"
        console.print(f"  [bold]CORS[/bold] ([{mc}]{ml}[/{mc}])")
        console.print(f"    Allow-Origin: {cors.get('allow_origin', '?')}")
        if cors.get("allow_credentials"):
            console.print("    [yellow]Credentials: allowed[/yellow]")
        for iss in cors.get("issues", []):
            ss = severity_style(iss["severity"])
            console.print(f"    [{ss}]⚠ {iss['issue']}[/{ss}]")
            console.print(f"      [dim]{iss['risk']}[/dim]")
        console.print()

    # ── Exposed Files ──
    exposed = result.get("exposed_files", {})
    exposed_list = exposed.get("exposed", [])
    if exposed_list:
        crit_count = sum(1 for e in exposed_list if e["severity"] == "critical")
        ec = "red" if crit_count else "yellow"
        console.print(f"  [bold]Exposed Files[/bold] ([{ec}]{len(exposed_list)} found[/{ec}], {exposed.get('checked', 0)} checked)")
        for ef in exposed_list:
            sev = ef["severity"]
            ss = severity_style(sev)
            icon = "🚨" if sev == "critical" else "⚠"
            console.print(f"    [{ss}]{icon} {ef['path']}[/{ss}] — {ef['description']} ({ef['size']}b)")
        console.print()

    # ── HTTP Methods ──
    methods = result.get("http_methods", {})
    allowed = methods.get("allowed_methods", [])
    dangerous = methods.get("dangerous_methods", [])
    if allowed:
        console.print("  [bold]HTTP Methods[/bold]")
        safe_m = [m for m in allowed if m not in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
        line = f"    Allowed: [green]{', '.join(safe_m)}[/green]"
        if dangerous:
            line += f" [red]{', '.join(dangerous)}[/red]"
        console.print(line)
        for iss in methods.get("issues", []):
            ss = severity_style(iss["severity"])
            console.print(f"    [{ss}]⚠ {iss['method']}: {iss['risk']}[/{ss}]")
        console.print()

    # ── Error Page ──
    err = result.get("error_page", {})
    hints = err.get("framework_hints", [])
    leaks = err.get("version_leaks", [])
    has_trace = err.get("stack_trace", False)
    if hints or leaks or has_trace:
        console.print("  [bold]Error Page Analysis[/bold] (404)")
        if has_trace:
            console.print("    [red]🚨 Stack trace exposed in error page![/red]")
        for leak in leaks:
            console.print(f"    [yellow]⚠ Version leak: {leak['software']} {leak['version']}[/yellow]")
        for hint in hints:
            console.print(f"    Framework: [cyan]{hint}[/cyan]")
        if err.get("server_header"):
            console.print(f"    Server: [dim]{err['server_header']}[/dim]")
        console.print()

    # ── Subdomains ──
    subs = result.get("subdomains", {})
    sub_list = subs.get("subdomains", [])
    sub_count = subs.get("count", 0)
    if sub_list:
        console.print(f"  [bold]Subdomains[/bold] ([cyan]{sub_count} found[/cyan] via crt.sh)")
        for s in sub_list[:15]:
            console.print(f"    [dim]{s}[/dim]")
        if sub_count > 15:
            console.print(f"    [dim]... and {sub_count - 15} more[/dim]")
        console.print()

    # ── Parameter Discovery ──
    params_data = result.get("params", {})
    params_list = params_data.get("params", [])
    if params_list:
        src = params_data.get("sources", {})
        console.print(f"  [bold]Discovered Parameters[/bold] ([cyan]{len(params_list)} found[/cyan] across {params_data.get('pages_crawled', 0)} pages)")
        console.print(f"    Sources: [green]{src.get('query', 0)}[/green] query · [green]{src.get('form', 0)}[/green] form · [green]{src.get('js', 0)}[/green] JS")

        param_table = Table(show_header=True, box=None, pad_edge=False, padding=(0, 1))
        param_table.add_column("#", width=4, style="dim")
        param_table.add_column("Method", width=6)
        param_table.add_column("URL", min_width=35)
        param_table.add_column("Param", min_width=12, style="cyan")
        param_table.add_column("Source", width=6, style="dim")

        for i, p in enumerate(params_list[:20], 1):
            # Shorten URL for display
            disp_url = urllib.parse.urlparse(p["url"]).path or "/"
            param_table.add_row(str(i), p["method"], disp_url, p["param"], p["source"])
        console.print(param_table)
        if len(params_list) > 20:
            console.print(f"    [dim]... and {len(params_list) - 20} more[/dim]")
        console.print()
        console.print(f"  [dim]Test these: fray scan <target> -c xss -m 3[/dim]")
        console.print()
    elif params_data:
        console.print("  [bold]Discovered Parameters[/bold]")
        console.print(f"    [dim]No injectable parameters found ({params_data.get('pages_crawled', 0)} pages crawled)[/dim]")
        console.print()

    # ── Historical URLs ──
    hist = result.get("historical_urls", {})
    hist_urls = hist.get("urls", [])
    if hist_urls:
        hist_src = hist.get("sources", {})
        console.print(f"  [bold]Historical URLs[/bold] ([cyan]{len(hist_urls)} found[/cyan], "
                      f"[yellow]{hist.get('interesting', 0)} interesting[/yellow])")
        console.print(f"    Sources: [green]{hist_src.get('wayback', 0)}[/green] Wayback · "
                      f"[green]{hist_src.get('sitemap', 0)}[/green] sitemap · "
                      f"[green]{hist_src.get('robots', 0)}[/green] robots.txt")
        # Show only interesting paths in full recon (keep it compact)
        interesting_paths = [u for u in hist_urls if u["interesting"]]
        if interesting_paths:
            for u in interesting_paths[:10]:
                console.print(f"    [yellow]⚠ {u['path']}[/yellow]  [dim]({', '.join(u['sources'])})[/dim]")
            if len(interesting_paths) > 10:
                console.print(f"    [dim]... and {len(interesting_paths) - 10} more interesting paths[/dim]")
        console.print(f"    [dim]Full list: fray recon <target> --history[/dim]")
        console.print()
    elif hist:
        console.print("  [bold]Historical URLs[/bold]")
        console.print("    [dim]No historical URLs found[/dim]")
        console.print()

    # ── GraphQL Introspection ──
    gql = result.get("graphql", {})
    gql_endpoints = gql.get("endpoints_found", [])
    gql_introspection = gql.get("introspection_enabled", [])
    if gql_endpoints:
        if gql_introspection:
            console.print(f"  [bold red]GraphQL Introspection[/bold red] — [red]ENABLED[/red] ⚠")
            for ep in gql_introspection:
                console.print(f"    [red]⚠ {ep} — full schema exposed[/red]")
            total_t = gql.get("total_types", 0)
            total_f = gql.get("total_fields", 0)
            if total_t:
                console.print(f"    Schema: [cyan]{total_t} types[/cyan], [cyan]{total_f} fields[/cyan]")
                for t in gql.get("types_found", [])[:8]:
                    fields_str = ", ".join(t["fields"][:5])
                    if t["field_count"] > 5:
                        fields_str += f" (+{t['field_count'] - 5} more)"
                    console.print(f"    [yellow]{t['name']}[/yellow]: {fields_str}")
        else:
            console.print(f"  [bold]GraphQL[/bold] — endpoints found, introspection disabled")
            for ep in gql_endpoints:
                console.print(f"    [green]✓[/green] {ep} (introspection blocked)")
        console.print()

    # ── API Discovery ──
    api = result.get("api_discovery", {})
    api_found = api.get("endpoints_found", [])
    api_specs = api.get("specs_found", [])
    if api_found or api_specs:
        has_spec = api.get("has_spec", False)
        if has_spec:
            console.print(f"  [bold red]API Discovery[/bold red] — [red]OpenAPI/Swagger spec EXPOSED[/red] ⚠")
        else:
            console.print(f"  [bold]API Discovery[/bold] — [cyan]{len(api_found)} endpoints found[/cyan]")
        for spec in api_specs:
            title = spec.get("title", "Untitled")
            ver = spec.get("version", "")
            eps = spec.get("endpoints", 0)
            console.print(f"    [red]⚠ {spec['path']}[/red] — {title} v{ver} ({eps} endpoints)")
            for m in spec.get("methods", [])[:8]:
                console.print(f"      [dim]{m}[/dim]")
            if len(spec.get("methods", [])) > 8:
                console.print(f"      [dim]... and {len(spec['methods']) - 8} more[/dim]")
        for ep in api_found:
            if ep.get("spec"):
                continue  # Already shown above
            cat = ep.get("category", "")
            path = ep["path"]
            if ep.get("docs_page"):
                console.print(f"    [yellow]⚠ {path}[/yellow] — API docs page [dim]({cat})[/dim]")
            else:
                console.print(f"    [green]→[/green] {path} [dim]({cat})[/dim]")
        console.print()

    # ── Host Header Injection ──
    hhi = result.get("host_header_injection", {})
    if hhi.get("reflected"):
        console.print(f"  [bold red]Host Header Injection[/bold red] — [red]VULNERABLE[/red] ⚠")
        for v in hhi.get("vulnerable_headers", []):
            console.print(f"    [red]⚠ {v} — reflected in response (password reset poisoning / cache poisoning)[/red]")
        for d in hhi.get("details", []):
            if d.get("redirect"):
                console.print(f"    [red]⚠ {d['header']} → redirect to {d['redirect']}[/red]")
        console.print()
    elif hhi.get("details"):
        console.print(f"  [bold yellow]Host Header Injection[/bold yellow] — status changes detected")
        for d in hhi.get("details", []):
            console.print(f"    [yellow]⚠ {d['header']} → status {d['status']}[/yellow]")
        console.print()

    # ── Admin Panel Discovery ──
    admin = result.get("admin_panels", {})
    panels = admin.get("panels_found", [])
    if panels:
        open_panels = [p for p in panels if p.get("protected") is False]
        protected = [p for p in panels if p.get("protected") is True]
        redirects = [p for p in panels if "redirect" in p]
        if open_panels:
            console.print(f"  [bold red]Admin Panels[/bold red] — [red]{len(open_panels)} OPEN (no auth)[/red] ⚠")
        else:
            console.print(f"  [bold]Admin Panels[/bold] — [cyan]{len(panels)} found[/cyan]")
        for p in panels:
            path = p["path"]
            status = p["status"]
            cat = p["category"]
            if p.get("protected") is False:
                console.print(f"    [red]⚠ {path}[/red] — [red]200 OPEN[/red] [dim]({cat})[/dim]")
            elif p.get("protected") is True:
                console.print(f"    [yellow]🔒 {path}[/yellow] — {status} auth required [dim]({cat})[/dim]")
            elif p.get("redirect"):
                console.print(f"    [green]→[/green] {path} — {status} → {p['redirect']} [dim]({cat})[/dim]")
            else:
                console.print(f"    [green]→[/green] {path} — {status} [dim]({cat})[/dim]")
        console.print()

    # ── Rate Limits ──
    rl = result.get("rate_limits", {})
    if rl and not rl.get("error"):
        console.print("  [bold]Rate Limit Fingerprint[/bold]")
        det_type = rl.get("detection_type", "unknown")
        if det_type == "none":
            console.print("    [green]No rate limiting detected[/green] — fast testing safe")
        else:
            type_style = {"fixed-window": "yellow", "sliding-window": "yellow",
                          "token-bucket": "red", "declared-only": "cyan"}.get(det_type, "yellow")
            console.print(f"    Type:            [{type_style}]{det_type}[/{type_style}]")
            if rl.get("threshold_rps"):
                console.print(f"    Threshold:       [bold]{rl['threshold_rps']} req/s[/bold]")
            if rl.get("burst_limit"):
                console.print(f"    Burst limit:     {rl['burst_limit']} requests")
            if rl.get("lockout_duration"):
                console.print(f"    Lockout:         {rl['lockout_duration']}s")
            if rl.get("retry_after_policy"):
                console.print(f"    Retry-After:     {rl['retry_after_policy']}")
            console.print(f"    Safe delay:      [green]{rl['recommended_delay']}s[/green] between requests")
        if rl.get("rate_limit_headers"):
            hdrs = ", ".join(f"{k}={v}" for k, v in rl["rate_limit_headers"].items())
            console.print(f"    Headers:         [dim]{hdrs}[/dim]")
        console.print()

    # ── Differential Response Analysis ──
    diff = result.get("differential", {})
    if diff and not diff.get("error"):
        console.print("  [bold]WAF Detection Mode[/bold]")
        mode = diff.get("detection_mode", "unknown")
        mode_styles = {"signature": "yellow", "anomaly": "red", "hybrid": "bold red", "none": "green"}
        ms = mode_styles.get(mode, "dim")
        console.print(f"    Mode:            [{ms}]{mode}[/{ms}]")

        baseline = diff.get("baseline", {})
        blocked = diff.get("blocked_fingerprint", {})
        if baseline:
            console.print(f"    Baseline:        {baseline.get('status', '?')} · {baseline.get('body_length', '?')} bytes · {baseline.get('response_time_ms', '?')}ms")
        if blocked:
            console.print(f"    Blocked:         {blocked.get('status', '?')} · {blocked.get('body_length', '?')} bytes · {blocked.get('response_time_ms', '?')}ms")

        if diff.get("status_code_pattern"):
            console.print(f"    Status pattern:  {diff['status_code_pattern']}")
        if diff.get("timing_delta_ms") is not None:
            delta = diff["timing_delta_ms"]
            t_style = "red" if abs(delta) > 100 else "yellow" if abs(delta) > 30 else "dim"
            console.print(f"    Timing delta:    [{t_style}]{delta:+.1f}ms[/{t_style}]")
        if diff.get("body_length_delta") is not None:
            console.print(f"    Body Δ:          {diff['body_length_delta']:+d} bytes")
        if diff.get("extra_headers_on_block"):
            console.print(f"    Extra headers:   {', '.join(diff['extra_headers_on_block'])}")
        if diff.get("block_page_signatures"):
            console.print(f"    Block sigs:      {', '.join(diff['block_page_signatures'])}")

        sig_count = len(diff.get("signature_detection", []))
        anom_count = len(diff.get("anomaly_detection", []))
        if sig_count or anom_count:
            console.print(f"    Triggered:       {sig_count} signature · {anom_count} anomaly")
            for s in diff.get("signature_detection", []):
                console.print(f"      [yellow]SIG[/yellow]  {s['label']}: {s['status']} · {s['response_time_ms']}ms · {s['body_length']}B")
            for a in diff.get("anomaly_detection", []):
                console.print(f"      [red]ANOM[/red] {a['label']}: {a['status']} · {a['response_time_ms']}ms · {a['body_length']}B")

        # WAF intel-based recommendations
        if diff.get("waf_vendor"):
            console.print()
            console.print(f"  [bold]WAF Intel — {diff['waf_vendor']}[/bold]")
            for bp in diff.get("recommended_bypasses", [])[:5]:
                conf_style = {"high": "green", "medium": "yellow", "low": "red"}.get(bp["confidence"], "dim")
                console.print(f"    [{conf_style}]{bp['confidence'].upper():6s}[/{conf_style}] {bp['technique']}: {bp['description']}")
            ineff = diff.get("ineffective_techniques", [])
            if ineff:
                console.print(f"    [dim]Skip: {', '.join(ineff)}[/dim]")
            gaps = diff.get("detection_gaps", {})
            sig_misses = gaps.get("signature_misses", [])
            anom_misses = gaps.get("anomaly_misses", [])
            if sig_misses:
                console.print(f"    [green]Sig gaps:[/green]  {', '.join(sig_misses)}")
            if anom_misses:
                console.print(f"    [green]Anom gaps:[/green] {', '.join(anom_misses)}")
            rec_cats = diff.get("recommended_categories", [])
            if rec_cats:
                console.print(f"    [cyan]Try:[/cyan]       fray test <url> -c {rec_cats[0]} --smart")
        console.print()

    # ── WAF Rule Gap Analysis ──
    gap = result.get("gap_analysis", {})
    if gap and gap.get("waf_vendor"):
        risk = gap.get("risk_summary", "")
        risk_style = "red" if "HIGH" in risk else ("yellow" if "MEDIUM" in risk else "green")
        console.print(f"  [bold]WAF Rule Gap Analysis — {gap['waf_vendor']}[/bold]")
        console.print(f"    Risk:            [{risk_style}]{risk}[/{risk_style}]")
        console.print(f"    Detection mode:  {gap.get('detection_mode', '?')}")

        block = gap.get("block_behavior", {})
        if block.get("status_codes"):
            console.print(f"    Block codes:     {', '.join(str(c) for c in block['status_codes'])}")
        if block.get("timing_signature"):
            console.print(f"    Timing sig:      [dim]{block['timing_signature']}[/dim]")

        strategies = gap.get("bypass_strategies", [])
        if strategies:
            console.print()
            console.print("    [bold]Bypass Strategies[/bold] (prioritised)")
            for s in strategies:
                conf = s.get("confidence", "?")
                conf_style = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "dim")
                live = " [green]★ live-confirmed[/green]" if s.get("live_confirmed") else ""
                console.print(f"      [{conf_style}]{conf.upper():6s}[/{conf_style}] {s['technique']}: {s['description']}{live}")
                if s.get("payload_example"):
                    console.print(f"             [dim]e.g. {s['payload_example'][:80]}[/dim]")

        ineff = gap.get("ineffective_techniques", [])
        if ineff:
            console.print()
            console.print("    [bold]Skip These[/bold] (known ineffective)")
            for t in ineff:
                console.print(f"      [dim]✗ {t['technique']}: {t['reason'][:80]}[/dim]")

        det_gaps = gap.get("detection_gaps", {})
        sig_misses = det_gaps.get("signature_misses", [])
        anom_misses = det_gaps.get("anomaly_misses", [])
        config_gaps = det_gaps.get("config_gaps", [])
        if sig_misses or anom_misses or config_gaps:
            console.print()
            console.print("    [bold]Detection Gaps[/bold]")
            if sig_misses:
                console.print(f"      [green]Sig misses:[/green]   {', '.join(sig_misses)}")
            if anom_misses:
                console.print(f"      [green]Anom misses:[/green]  {', '.join(anom_misses)}")
            if config_gaps:
                console.print("      [yellow]Config issues:[/yellow]")
                for cg in config_gaps:
                    console.print(f"        [yellow]⚠ {cg}[/yellow]")

        # Technique matrix summary (compact)
        matrix = gap.get("technique_matrix", [])
        if matrix:
            eff_techs = [t["technique"] for t in matrix if t["status"] == "effective"]
            blk_techs = [t["technique"] for t in matrix if t["status"] == "blocked"]
            console.print()
            console.print("    [bold]Technique Matrix[/bold]")
            if eff_techs:
                console.print(f"      [green]✅ Effective:[/green] {', '.join(eff_techs)}")
            if blk_techs:
                console.print(f"      [red]❌ Blocked:[/red]   {', '.join(blk_techs)}")

        console.print()

    # ── Recommended Categories ──
    cats = result.get("recommended_categories", [])
    if cats:
        console.print("  [bold]Recommended Payload Categories[/bold] (priority order)")
        for i, cat in enumerate(cats, 1):
            console.print(f"    {i}. [cyan]{cat}[/cyan]")
        console.print()
        console.print(f"  [dim]Usage: fray test <target> -c {cats[0]} --smart[/dim]")
    else:
        console.print("  [bold]Recommended Payload Categories[/bold]")
        console.print("    [dim]No specific recommendations — use --smart for adaptive testing[/dim]")
    console.print()
