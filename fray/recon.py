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
    "node.js": ["ssti", "ssrf", "xss", "command_injection", "prototype_pollution"],
    "express": ["prototype_pollution", "ssti", "ssrf", "xss", "command_injection"],
    "python": ["ssti", "ssrf", "command_injection", "sqli"],
    "java": ["sqli", "xxe", "ssti", "ssrf", "command_injection"],
    ".net": ["sqli", "xss", "path_traversal", "xxe"],
    "ruby": ["ssti", "command_injection", "sqli", "ssrf"],
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

# Patterns to extract <script src="..."> tags
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def discover_js_endpoints(url: str, max_depth: int = 2, max_pages: int = 10,
                          timeout: int = 8, verify_ssl: bool = True,
                          extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Deep JS endpoint extraction.

    Crawls HTML pages, finds all <script src="..."> tags, fetches external
    JS files, and extracts API endpoints using comprehensive regex patterns.

    Finds hidden API routes, admin endpoints, GraphQL, internal paths.
    """
    from fray.scanner import _fetch, extract_links, _same_origin, _normalize_url

    visited_pages = set()
    visited_js = set()
    queue = [(url, 0)]
    endpoints = []   # list of dicts
    seen_paths = set()

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
            _extract_endpoints_from_js(body, current_url, endpoints, seen_paths)

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
                    _extract_endpoints_from_js(js_body, js_url, endpoints, seen_paths)

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
        console.print(f"  [dim]Test these: fray scan {target} -c xss -m 3[/dim]")
    else:
        console.print("  [dim]No JS endpoints found[/dim]")
    console.print()


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
