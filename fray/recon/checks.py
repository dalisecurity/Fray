"""Extended recon checks — CORS, exposed files, HTTP methods, error pages,
GraphQL introspection, API discovery, host header injection, admin panels,
rate limits, differential response analysis, and WAF gap analysis."""

import http.client
import json
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fray import __version__
from fray.recon.http import _http_get, _make_ssl_context


def check_robots_sitemap(host: str, port: int, use_ssl: bool,
                         timeout: int = 8, fast: bool = False) -> Dict[str, Any]:
    """Parse robots.txt and sitemap.xml for hidden paths and URL extraction.

    Phase 1: Parse robots.txt — extract Disallow paths, Sitemap references.
    Phase 2: Fetch and parse sitemap.xml — extract URLs, detect sub-sitemaps.
             Skipped in fast mode.
    """
    result: Dict[str, Any] = {
        "robots_txt": False,
        "disallowed_paths": [],
        "sitemaps": [],
        "interesting_paths": [],
        "sitemap_urls": [],
        "sitemap_url_count": 0,
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
                if sm:
                    result["sitemaps"].append(sm)

    # sitemap.xml (if no sitemaps found in robots.txt, try default location)
    if not result["sitemaps"]:
        status, _, body = _http_get(host, port, "/sitemap.xml", use_ssl, timeout=timeout)
        if status == 200 and body and "<urlset" in body.lower():
            result["sitemaps"].append(f"{'https' if use_ssl else 'http'}://{host}/sitemap.xml")

    # ── Phase 2: Parse sitemap.xml URLs (#180) ──
    # Skip in fast mode — sitemap URL extraction is slow for large sitemaps
    if fast:
        result["sitemap_url_count"] = 0
        # Flag interesting paths from robots disallowed paths only
        return result

    # Extract <loc> URLs from sitemaps (follow one level of sitemap index)
    _SM_PATHS = set()
    for sm_url in result["sitemaps"][:5]:  # Cap at 5 sitemaps
        # Determine path from URL
        try:
            parsed = urllib.parse.urlparse(sm_url)
            sm_path = parsed.path or "/sitemap.xml"
            sm_host = parsed.hostname or host
            sm_port = parsed.port or port
            sm_ssl = parsed.scheme == "https" if parsed.scheme else use_ssl
        except Exception:
            sm_path, sm_host, sm_port, sm_ssl = "/sitemap.xml", host, port, use_ssl

        s, _, sm_body = _http_get(sm_host, sm_port, sm_path, sm_ssl, timeout=timeout)
        if s != 200 or not sm_body:
            continue

        # Extract <loc>...</loc> tags
        locs = re.findall(r'<loc>\s*(.*?)\s*</loc>', sm_body, re.IGNORECASE)
        for loc in locs:
            loc = loc.strip()
            if not loc:
                continue
            # Sub-sitemap (sitemap index) — follow one level deep
            if loc.endswith(".xml") or "sitemap" in loc.lower():
                if loc not in _SM_PATHS and len(_SM_PATHS) < 10:
                    _SM_PATHS.add(loc)
                    try:
                        p2 = urllib.parse.urlparse(loc)
                        s2, _, b2 = _http_get(
                            p2.hostname or host, p2.port or port,
                            p2.path or "/", p2.scheme == "https" if p2.scheme else use_ssl,
                            timeout=timeout)
                        if s2 == 200 and b2:
                            sub_locs = re.findall(r'<loc>\s*(.*?)\s*</loc>', b2, re.IGNORECASE)
                            for sl in sub_locs[:200]:
                                sl = sl.strip()
                                if sl and not sl.endswith(".xml"):
                                    result["sitemap_urls"].append(sl)
                    except Exception:
                        pass
            else:
                result["sitemap_urls"].append(loc)

        # Cap total extracted URLs
        if len(result["sitemap_urls"]) > 500:
            result["sitemap_urls"] = result["sitemap_urls"][:500]
            break

    result["sitemap_url_count"] = len(result["sitemap_urls"])

    # Flag interesting sitemap URLs
    _sm_interesting = ("admin", "api", "login", "dashboard", "internal",
                       "staging", "debug", "graphql", "wp-json", "upload")
    for url in result["sitemap_urls"]:
        path = urllib.parse.urlparse(url).path.lower()
        if any(kw in path for kw in _sm_interesting):
            if url not in result["interesting_paths"]:
                result["interesting_paths"].append(url)

    return result


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
                        timeout: int = 5, fast: bool = False) -> Dict[str, Any]:
    """Probe for commonly exposed sensitive files."""
    result: Dict[str, Any] = {
        "exposed": [],
        "checked": 0,
    }

    # High-value probes — always checked
    _PROBES_CORE = [
        ("/.env", "Environment variables (credentials, API keys)"),
        ("/.git/HEAD", "Git repository (source code exposure)"),
        ("/.git/config", "Git config (repo URL, credentials)"),
        ("/wp-config.php.bak", "WordPress config backup (DB creds)"),
        ("/phpinfo.php", "PHP info page (full server details)"),
        ("/actuator", "Spring Boot actuator (Java)"),
        ("/actuator/env", "Spring Boot environment variables"),
        ("/.well-known/security.txt", "Security contact info"),
        ("/backup.sql", "Database backup"),
        ("/package.json", "Node.js dependency file"),
        ("/requirements.txt", "Python dependency file"),
        ("/server-status", "Apache server status page"),
    ]
    # Extended probes — skipped in fast mode
    _PROBES_EXTENDED = [
        ("/.svn/entries", "SVN repository metadata"),
        ("/web.config", ".NET configuration file"),
        ("/.htaccess", "Apache configuration (may leak paths)"),
        ("/.htpasswd", "Apache password file"),
        ("/server-info", "Apache server info page"),
        ("/info.php", "PHP info page"),
        ("/debug", "Debug endpoint"),
        ("/elmah.axd", ".NET error log"),
        ("/trace.axd", ".NET trace log"),
        ("/crossdomain.xml", "Flash cross-domain policy"),
        ("/sitemap.xml.gz", "Compressed sitemap"),
        ("/dump.sql", "Database dump"),
        ("/db.sql", "Database file"),
        ("/.DS_Store", "macOS directory metadata"),
        ("/composer.json", "PHP dependency file (versions exposed)"),
        ("/Gemfile", "Ruby dependency file"),
    ]

    probes = _PROBES_CORE if fast else _PROBES_CORE + _PROBES_EXTENDED

    import concurrent.futures

    def _probe_file(probe_path, description):
        try:
            status, headers, body = _http_get(
                host, port, probe_path, use_ssl, timeout=timeout, max_redirects=0
            )
            if status == 200 and len(body) > 0:
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
                    return {
                        "path": probe_path,
                        "description": description,
                        "status": status,
                        "size": len(body),
                        "severity": severity,
                    }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_file, p, d): p for p, d in probes}
        for future in concurrent.futures.as_completed(futures):
            result["checked"] += 1
            try:
                entry = future.result()
                if entry:
                    result["exposed"].append(entry)
            except Exception:
                pass

    return result


def check_http_methods(host: str, port: int, use_ssl: bool,
                       timeout: int = 5, fast: bool = False) -> Dict[str, Any]:
    """Check allowed HTTP methods via OPTIONS + individual probes.

    Phase 1: Send OPTIONS request to get Allow header.
    Phase 2: Probe dangerous methods individually (PUT, DELETE, TRACE, PATCH,
             CONNECT) since many servers omit them from OPTIONS but still accept them.
             Skipped in fast mode.
    """
    result: Dict[str, Any] = {
        "allowed_methods": [],
        "dangerous_methods": [],
        "options_status": 0,
        "probed_methods": {},
        "issues": [],
    }

    def _make_conn():
        if use_ssl:
            try:
                ctx = _make_ssl_context(verify=True)
                return http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
            except Exception:
                ctx = _make_ssl_context(verify=False)
                return http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    # Phase 1: OPTIONS
    try:
        conn = _make_conn()
        conn.request("OPTIONS", "/", headers={
            "Host": host,
            "User-Agent": f"Fray/{__version__} Recon",
        })
        resp = conn.getresponse()
        resp.read()
        result["options_status"] = resp.status
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        allow = headers.get("allow", headers.get("access-control-allow-methods", ""))
        if allow:
            methods = [m.strip().upper() for m in allow.split(",")]
            result["allowed_methods"] = methods
    except Exception:
        pass

    # Phase 2: Probe dangerous methods individually
    # Skipped in fast mode — OPTIONS result is sufficient
    if fast:
        _DANGEROUS = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"}
        found_dangerous = [m for m in result["allowed_methods"] if m in _DANGEROUS]
        result["dangerous_methods"] = found_dangerous
        return result

    _DANGEROUS = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"}
    # Only probe methods not already confirmed by OPTIONS
    confirmed = set(result["allowed_methods"])
    to_probe = _DANGEROUS - confirmed

    for method in sorted(to_probe):
        try:
            conn = _make_conn()
            conn.request(method, "/_fray_method_probe", headers={
                "Host": host,
                "User-Agent": f"Fray/{__version__} Recon",
                "Content-Length": "0",
            })
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            conn.close()
            result["probed_methods"][method] = status
            # 405 = Method Not Allowed → server rejects it (good)
            # 501 = Not Implemented → server doesn't support it (good)
            # Anything else (200, 201, 204, 301, 302, 400, 403) = method is accepted
            if status not in (405, 501):
                if method not in result["allowed_methods"]:
                    result["allowed_methods"].append(method)
        except Exception:
            result["probed_methods"][method] = 0

    # Classify dangerous
    found_dangerous = [m for m in result["allowed_methods"] if m in _DANGEROUS]
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
    if "PATCH" in found_dangerous:
        result["issues"].append({
            "method": "PATCH",
            "severity": "low",
            "risk": "PATCH method accepted — verify authorization controls",
        })

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


def check_graphql_introspection(host: str, port: int, use_ssl: bool,
                                 timeout: int = 6,
                                 extra_headers: Optional[Dict[str, str]] = None,
                                 ) -> Dict[str, Any]:
    """Probe common GraphQL endpoints for introspection enabled.

    Exposed introspection reveals the entire API schema — high-value recon.
    """
    from fray.recon.http import _post_json

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
                         fast: bool = False,
                         ) -> Dict[str, Any]:
    """Probe common API paths to discover specs, docs, and versioned endpoints.

    Swagger/OpenAPI specs expose every endpoint, parameter, and auth method.
    In fast mode, only probes the top 10 most common paths instead of all 30+.
    """
    from fray.recon.http import _fetch_url

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    import concurrent.futures

    found = []
    specs = []

    # In fast mode, only probe the most valuable paths (specs + docs)
    _paths = _API_SPEC_PATHS
    if fast:
        _fast_cats = {"swagger", "openapi", "swagger-ui", "api-docs", "redoc"}
        _paths = [(p, c) for p, c in _API_SPEC_PATHS if c in _fast_cats][:12]

    def _probe_api(api_path, category):
        url = f"{base}{api_path}"
        try:
            status, body, resp_headers = _fetch_url(url, timeout=timeout,
                                                     verify_ssl=True,
                                                     headers=extra_headers)
            if status == 0 and use_ssl:
                status, body, resp_headers = _fetch_url(url, timeout=timeout,
                                                         verify_ssl=False,
                                                         headers=extra_headers)
        except Exception:
            return None, None

        if status == 0 or status >= 400:
            return None, None

        ct = resp_headers.get("content-type", "")
        is_json = "json" in ct or "yaml" in ct
        is_html = "html" in ct

        entry = {
            "path": api_path,
            "status": status,
            "category": category,
            "content_type": ct.split(";")[0].strip(),
        }

        is_spec = False
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
                for ep_path, methods in list(paths.items())[:30]:
                    for method in methods:
                        if method.lower() in ("get", "post", "put", "patch", "delete", "options"):
                            entry["methods"].append(f"{method.upper()} {ep_path}")
                is_spec = True
            except (json.JSONDecodeError, AttributeError):
                pass

        elif is_html and body and category in ("swagger-ui", "api-docs", "docs", "redoc"):
            lower = body.lower()
            if any(kw in lower for kw in ("swagger", "openapi", "api", "redoc",
                                           "endpoint", "schema", "try it out")):
                entry["spec"] = False
                entry["docs_page"] = True
                return entry, None
            return None, None

        elif category in ("api-root", "health", "status", "version", "info"):
            if is_json or (is_html and len(body) < 5000):
                return entry, None
            return None, None

        if is_spec:
            return entry, entry
        elif category not in ("swagger-ui", "api-docs", "docs", "redoc"):
            return entry, None
        return None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_api, p, c): p for p, c in _paths}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry, spec_entry = future.result()
                if entry:
                    found.append(entry)
                if spec_entry:
                    specs.append(spec_entry)
            except Exception:
                pass

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
    from fray.recon.http import _fetch_url

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

    # 2. Test each override header (parallel for speed)
    import concurrent.futures

    def _probe_hhi(header_name, header_value):
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
            return None
        if status == 0:
            return None

        finding = {
            "header": header_name,
            "value": header_value,
            "reflected": False,
            "status_changed": status != base_status,
            "status": status,
        }
        if body and _HHI_SENTINEL in body.lower():
            if not base_body or _HHI_SENTINEL not in base_body.lower():
                finding["reflected"] = True
        location = hdrs.get("location", "")
        if _HHI_SENTINEL in location.lower():
            finding["reflected"] = True
            finding["redirect"] = location
        return finding

    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        futures = {pool.submit(_probe_hhi, h, v): h
                   for h, v in _HOST_OVERRIDE_HEADERS}
        for future in concurrent.futures.as_completed(futures):
            try:
                finding = future.result()
            except Exception:
                continue
            if finding is None:
                continue
            if finding["reflected"]:
                result["reflected"] = True
                if finding["header"] not in result["vulnerable_headers"]:
                    result["vulnerable_headers"].append(finding["header"])
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
    from fray.recon.http import _fetch_url

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    import concurrent.futures

    found = []

    def _probe_admin(admin_path, category):
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
            return None

        if status == 0 or status >= 404:
            return None

        ct = hdrs.get("content-type", "")
        is_html = "html" in ct
        is_admin = False

        if status in (301, 302, 303, 307, 308):
            is_admin = True
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
                is_admin = True
        elif status in (401, 403):
            is_admin = True

        if not is_admin:
            return None

        entry = {
            "path": admin_path,
            "status": status,
            "category": category,
        }
        if status in (301, 302, 303, 307, 308):
            entry["redirect"] = hdrs.get("location", "")
        if status in (401, 403):
            entry["protected"] = True
        elif status == 200:
            entry["protected"] = False

        return entry

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_admin, p, c): p for p, c in _ADMIN_PATHS}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
                if entry:
                    found.append(entry)
            except Exception:
                pass

    return {
        "panels_found": found,
        "total": len(found),
    }


_AUTH_PATHS = [
    # Login / Sign-in
    ("/login", "login"),
    ("/signin", "login"),
    ("/sign-in", "login"),
    ("/auth/login", "login"),
    ("/user/login", "login"),
    ("/users/sign_in", "login"),
    ("/accounts/login", "login"),
    ("/wp-login.php", "login"),
    ("/admin/login", "login"),
    # Registration
    ("/register", "registration"),
    ("/signup", "registration"),
    ("/sign-up", "registration"),
    ("/auth/register", "registration"),
    ("/user/register", "registration"),
    ("/users/sign_up", "registration"),
    ("/accounts/signup", "registration"),
    ("/join", "registration"),
    # OAuth / SSO
    ("/oauth/authorize", "oauth"),
    ("/oauth2/authorize", "oauth"),
    ("/auth/oauth", "oauth"),
    ("/.well-known/openid-configuration", "oauth"),
    ("/oauth/token", "oauth"),
    ("/api/oauth/token", "oauth"),
    ("/auth/saml", "sso"),
    ("/saml/login", "sso"),
    ("/sso/login", "sso"),
    # Password reset
    ("/forgot-password", "password_reset"),
    ("/password/reset", "password_reset"),
    ("/auth/forgot", "password_reset"),
    ("/users/password/new", "password_reset"),
    ("/accounts/password/reset", "password_reset"),
    # MFA / 2FA
    ("/2fa", "mfa"),
    ("/auth/2fa", "mfa"),
    ("/mfa", "mfa"),
    ("/totp", "mfa"),
    ("/auth/verify", "mfa"),
    # API authentication
    ("/api/auth", "api_auth"),
    ("/api/v1/auth", "api_auth"),
    ("/api/login", "api_auth"),
    ("/api/token", "api_auth"),
    ("/auth/token", "api_auth"),
    ("/api/v1/token", "api_auth"),
    # Session / Logout
    ("/logout", "session"),
    ("/signout", "session"),
    ("/auth/logout", "session"),
]


def check_auth_endpoints(host: str, port: int, use_ssl: bool,
                         timeout: int = 5,
                         extra_headers: Optional[Dict[str, str]] = None,
                         ) -> Dict[str, Any]:
    """Probe common login, registration, OAuth, MFA, and API auth endpoints.

    Returns categorized auth endpoints with status, protection flags,
    and auth-specific metadata (CSRF tokens, OAuth flows, etc.).
    """
    from fray.recon.http import _fetch_url

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    import concurrent.futures

    _LOGIN_SIGNALS = (
        "login", "password", "username", "sign in", "log in",
        "authenticate", "email", "credential",
        '<input type="password"', 'type="submit"',
    )
    _REGISTRATION_SIGNALS = (
        "register", "sign up", "create account", "join",
        "confirm password", "email", "username",
    )
    _OAUTH_SIGNALS = (
        "client_id", "redirect_uri", "response_type", "grant_type",
        "authorization_endpoint", "token_endpoint", "openid",
    )
    _MFA_SIGNALS = (
        "verification code", "authenticator", "2fa", "two-factor",
        "totp", "one-time", "mfa",
    )

    found = []

    def _probe_auth(auth_path, category):
        url = f"{base}{auth_path}"
        try:
            status, body, hdrs = _fetch_url(url, timeout=timeout,
                                             verify_ssl=True,
                                             headers=extra_headers)
            if status == 0 and use_ssl:
                status, body, hdrs = _fetch_url(url, timeout=timeout,
                                                 verify_ssl=False,
                                                 headers=extra_headers)
        except Exception:
            return None

        if status == 0 or status >= 500:
            return None
        if status == 404:
            return None

        lower = body.lower() if body else ""
        ct = hdrs.get("content-type", "")

        entry = {
            "path": auth_path,
            "status": status,
            "category": category,
        }

        # Redirect: follow and note destination
        if status in (301, 302, 303, 307, 308):
            loc = hdrs.get("location", "")
            entry["redirect"] = loc
            entry["accessible"] = True
            return entry

        # Protected (401/403) — endpoint exists but is guarded
        if status in (401, 403):
            entry["accessible"] = False
            entry["protected"] = True
            www_auth = hdrs.get("www-authenticate", "")
            if www_auth:
                entry["auth_scheme"] = www_auth.split()[0] if www_auth else None
            return entry

        # 200 — check if it's actually an auth-related page
        if status == 200 and body:
            is_auth_page = False

            if category == "login" and any(s in lower for s in _LOGIN_SIGNALS):
                is_auth_page = True
            elif category == "registration" and any(s in lower for s in _REGISTRATION_SIGNALS):
                is_auth_page = True
            elif category == "oauth" and any(s in lower for s in _OAUTH_SIGNALS):
                is_auth_page = True
                if "openid" in lower or "authorization_endpoint" in lower:
                    entry["openid_discovery"] = True
            elif category == "sso":
                if any(s in lower for s in ("saml", "sso", "single sign", "identity provider")):
                    is_auth_page = True
            elif category == "password_reset" and any(s in lower for s in ("reset", "forgot", "email", "recover")):
                is_auth_page = True
            elif category == "mfa" and any(s in lower for s in _MFA_SIGNALS):
                is_auth_page = True
            elif category == "api_auth":
                if "json" in ct or any(s in lower for s in ("token", "api_key", "unauthorized")):
                    is_auth_page = True
            elif category == "session":
                is_auth_page = True

            if not is_auth_page:
                return None

            entry["accessible"] = True

            # Check for CSRF token
            if re.search(r'name\s*=\s*["\']csrf|_token|authenticity_token', lower):
                entry["has_csrf"] = True

            # Check for rate limit headers
            for rl_h in ("x-ratelimit-limit", "x-rate-limit-limit", "retry-after", "ratelimit-limit"):
                if rl_h in hdrs:
                    entry["rate_limited"] = True
                    break

            return entry

        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_auth, p, c): p for p, c in _AUTH_PATHS}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
                if entry:
                    found.append(entry)
            except Exception:
                pass

    # Categorize results
    by_category = {}
    for e in found:
        by_category.setdefault(e["category"], []).append(e)

    return {
        "endpoints": sorted(found, key=lambda x: x["path"]),
        "total": len(found),
        "categories": {k: len(v) for k, v in by_category.items()},
        "has_login": any(e["category"] == "login" for e in found),
        "has_registration": any(e["category"] == "registration" for e in found),
        "has_oauth": any(e["category"] == "oauth" for e in found),
        "has_mfa": any(e["category"] == "mfa" for e in found),
        "has_sso": any(e["category"] == "sso" for e in found),
    }


_COMMON_WEB_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (2082, "cPanel"),
    (2083, "cPanel SSL"),
    (2086, "WHM"),
    (2087, "WHM SSL"),
    (3000, "Dev (Node/Grafana)"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (4443, "HTTPS Alt"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8000, "Dev/Django"),
    (8008, "HTTP Alt"),
    (8080, "HTTP Proxy"),
    (8443, "HTTPS Alt"),
    (8888, "HTTP Alt/Jupyter"),
    (9090, "Prometheus/Cockpit"),
    (9200, "Elasticsearch"),
    (9443, "HTTPS Alt"),
    (27017, "MongoDB"),
]


def check_open_ports(host: str, timeout: float = 2.0,
                     ports: Optional[List[Tuple[int, str]]] = None,
                     ) -> Dict[str, Any]:
    """Lightweight TCP port scan — connect() probe against common web ports.

    Returns:
      - open: list of {port, service, banner?}
      - closed: count of closed ports
      - filtered: count of filtered (timeout) ports
      - total_scanned: total ports probed
    """
    import concurrent.futures

    target_ports = ports or _COMMON_WEB_PORTS
    open_ports = []
    filtered = 0
    closed = 0

    def _probe_port(port_num: int, service_name: str):
        try:
            sock = socket.create_connection((host, port_num), timeout=timeout)
            # Try to grab a banner (50ms read timeout)
            banner = None
            try:
                sock.settimeout(0.3)
                data = sock.recv(1024)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, OSError):
                pass
            sock.close()
            return {"port": port_num, "service": service_name, "state": "open",
                    "banner": banner}
        except socket.timeout:
            return {"port": port_num, "service": service_name, "state": "filtered"}
        except (ConnectionRefusedError, OSError):
            return {"port": port_num, "service": service_name, "state": "closed"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_port, p, s): p for p, s in target_ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
                elif result["state"] == "filtered":
                    filtered += 1
                else:
                    closed += 1
            except Exception:
                closed += 1

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    # Classify risk
    risky_ports = []
    _RISKY = {21, 22, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
    for op in open_ports:
        if op["port"] in _RISKY:
            risky_ports.append(op)

    return {
        "open": open_ports,
        "open_count": len(open_ports),
        "closed": closed,
        "filtered": filtered,
        "total_scanned": len(target_ports),
        "risky_ports": risky_ports,
    }


_CRITICAL_PATHS = [
    "/admin", "/login", "/api", "/api/v1", "/graphql",
    "/wp-admin", "/wp-login.php", "/administrator",
    "/dashboard", "/console", "/phpmyadmin",
    "/.env", "/.git/config", "/server-status",
    "/actuator", "/actuator/health",
]


def check_rate_limits_critical(host: str, port: int, use_ssl: bool,
                               timeout: int = 6,
                               extra_headers: Optional[Dict[str, str]] = None,
                               subdomains: Optional[list] = None) -> Dict[str, Any]:
    """Lightweight rate-limit probe for critical paths only.

    Instead of full burst testing against every subdomain/endpoint,
    sends a single request to each critical path and checks for
    rate-limit headers. Fast enough to include in default recon.

    Args:
        host: Target hostname
        port: Target port
        use_ssl: Whether to use SSL
        timeout: Per-request timeout
        extra_headers: Additional headers
        subdomains: Optional list of subdomains to also probe

    Returns:
        Dict with per-path rate limit headers and a summary.
    """
    import concurrent.futures

    result: Dict[str, Any] = {
        "paths_checked": 0,
        "rate_limited_paths": [],
        "headers_by_path": {},
        "most_restrictive": None,
        "summary": "unknown",
    }

    req_headers = {
        "Host": host,
        "User-Agent": f"Fray/{__version__} Recon",
        "Accept": "text/html,*/*",
        "Connection": "close",
    }
    if extra_headers:
        req_headers.update(extra_headers)

    # Build probe targets: critical paths on main host + optional subdomains
    targets: list = [(host, p) for p in _CRITICAL_PATHS]
    if subdomains:
        # Only probe critical subdomains (admin, api, dev, staging)
        critical_prefixes = {"admin", "api", "dev", "staging", "test", "internal",
                             "dashboard", "console", "portal", "vpn", "sso", "auth"}
        for sub in subdomains[:50]:
            fqdn = sub if isinstance(sub, str) else sub.get("fqdn", "")
            if not fqdn:
                continue
            prefix = fqdn.split(".")[0].lower()
            if prefix in critical_prefixes:
                targets.append((fqdn, "/"))

    def _probe_one(target_host: str, path: str):
        """Single GET and return rate-limit headers if present."""
        try:
            hdrs = dict(req_headers)
            hdrs["Host"] = target_host
            if use_ssl:
                try:
                    ctx = _make_ssl_context(verify=True)
                    conn = http.client.HTTPSConnection(target_host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=hdrs)
                    resp = conn.getresponse()
                except ssl.SSLError:
                    ctx = _make_ssl_context(verify=False)
                    conn = http.client.HTTPSConnection(target_host, port, context=ctx, timeout=timeout)
                    conn.request("GET", path, headers=hdrs)
                    resp = conn.getresponse()
            else:
                conn = http.client.HTTPConnection(target_host, port, timeout=timeout)
                conn.request("GET", path, headers=hdrs)
                resp = conn.getresponse()

            status = resp.status
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            resp.read(512)
            conn.close()

            rl = {}
            for key in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
                        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
                        "x-rate-limit-limit", "x-rate-limit-remaining",
                        "retry-after"):
                if key in resp_headers:
                    rl[key] = resp_headers[key]

            return {
                "host": target_host,
                "path": path,
                "status": status,
                "rate_limit_headers": rl,
                "is_rate_limited": status == 429 or bool(rl),
            }
        except Exception:
            return None

    # Run probes concurrently (max 10 workers, polite)
    probed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_one, h, p): (h, p) for h, p in targets[:30]}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result()
                if r:
                    probed.append(r)
            except Exception:
                pass

    result["paths_checked"] = len(probed)

    # Aggregate findings
    rate_limited = [p for p in probed if p["is_rate_limited"]]
    result["rate_limited_paths"] = [
        {"host": p["host"], "path": p["path"], "status": p["status"],
         "headers": p["rate_limit_headers"]}
        for p in rate_limited
    ]

    # Find most restrictive limit
    min_limit = None
    for p in rate_limited:
        for key in ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"):
            val = p["rate_limit_headers"].get(key)
            if val:
                try:
                    limit_int = int(val)
                    if min_limit is None or limit_int < min_limit:
                        min_limit = limit_int
                        result["most_restrictive"] = {
                            "host": p["host"],
                            "path": p["path"],
                            "limit": limit_int,
                            "headers": p["rate_limit_headers"],
                        }
                except (ValueError, TypeError):
                    pass

    # Collect all headers by path for display
    for p in probed:
        if p["rate_limit_headers"]:
            key = f"{p['host']}{p['path']}"
            result["headers_by_path"][key] = p["rate_limit_headers"]

    if not rate_limited:
        result["summary"] = "No rate limiting detected on critical paths"
    elif len(rate_limited) == len(probed):
        result["summary"] = f"All {len(probed)} critical paths are rate-limited"
    else:
        result["summary"] = (f"{len(rate_limited)}/{len(probed)} critical paths "
                             f"have rate limiting")

    return result


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
        "status_code_pattern": None,    # e.g. "200->403" or "200->200 (soft block)"
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

    # ── Follow redirect: if baseline is 301/302, re-probe the redirect target ──
    # Sites like amazon.co.jp redirect to www.amazon.co.jp — the WAF is on the
    # final destination, not the redirect stub.
    redirect_host = None
    if avg_benign_status in (301, 302, 307, 308):
        # Extract Location from the last benign response
        last_s, last_h, last_b, last_t = _send_raw("GET", path)
        loc = last_h.get("location", "")
        if loc:
            import urllib.parse as _up
            parsed_loc = _up.urlparse(loc if loc.startswith("http") else f"https://{host}{loc}")
            redir_host = parsed_loc.hostname
            redir_path = parsed_loc.path or "/"
            redir_ssl = parsed_loc.scheme == "https"
            redir_port = parsed_loc.port or (443 if redir_ssl else 80)
            if redir_host and redir_host != host:
                redirect_host = redir_host
                result["redirect_followed"] = f"{host} -> {redir_host}"
                # Re-send baseline against redirect target
                _orig_host = host
                host = redir_host
                path = redir_path
                port = redir_port
                use_ssl = redir_ssl
                # Update request template with new host
                req_template = (
                    "{method} {path} HTTP/1.1\r\n"
                    "Host: {host}\r\n"
                    "User-Agent: Fray/{version} Recon\r\n"
                    "Accept: text/html,*/*\r\n"
                    "{extra}"
                    "Connection: close\r\n\r\n{body}"
                )

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

                if benign_statuses:
                    avg_benign_status = max(set(benign_statuses), key=benign_statuses.count)
                    avg_benign_len = sum(benign_lengths) // len(benign_lengths)
                    avg_benign_time = sum(benign_times) / len(benign_times)

    result["baseline"] = {
        "status": avg_benign_status,
        "body_length": avg_benign_len,
        "response_time_ms": round(avg_benign_time, 1),
        "headers": sorted(benign_headers_set),
    }
    if redirect_host:
        result["baseline"]["redirect_target"] = redirect_host

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

        is_blk = _is_blocked(s, b, _sig_block_sigs)

        if is_blk:
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

        is_blk = _is_blocked(s, b, _anom_block_sigs)

        if is_blk:
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
            result["status_code_pattern"] = f"{avg_benign_status}\u2192{avg_blocked_status}"
        else:
            result["status_code_pattern"] = f"{avg_benign_status}\u2192{avg_blocked_status} (soft block)"

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
        "technique_matrix": [],       # check/x per technique for this vendor
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
        result["risk_summary"] = "No WAF vendor identified \u2014 gap analysis requires a known vendor"
        return result

    vdata = vendors_db[vendor_key]
    result["waf_vendor"] = vdata.get("display_name", vendor_key)
    result["vendor_key"] = vendor_key
    result["detection_mode"] = (vdata.get("detection_mode") or "").lower() or None
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
            config_gaps.append(f"{label} expected to be blocked but was not \u2014 possible config gap")
    if config_gaps:
        result["detection_gaps"]["config_gaps"] = config_gaps

    # ── Technique matrix — check/x for this vendor ──
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
        result["risk_summary"] = f"HIGH \u2014 {n_effective} viable bypass techniques, {n_sig_gaps} signature gaps, {n_anom_gaps} anomaly gaps"
    elif n_effective >= 1 or n_sig_gaps >= 1:
        result["risk_summary"] = f"MEDIUM \u2014 {n_effective} viable bypass techniques, {n_sig_gaps + n_anom_gaps} detection gaps"
    else:
        result["risk_summary"] = f"LOW \u2014 no high-confidence bypasses identified, {n_sig_gaps + n_anom_gaps} potential gaps"
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

    # ── Strip headers injected by user's own ZT/VPN/SASE proxy ──
    # These are added by the scanning machine's security stack, NOT the target.
    # Treating them as target WAF indicators causes false positives.
    zt_proxy_headers = {
        # Cloudflare Zero Trust / WARP
        "cf-team", "cf-access-authenticated-user-email", "cf-access-jwt-assertion",
        "cf-warp-tag-id", "cf-connecting-ip",
        # Zscaler ZIA / ZPA
        "x-zscaler-client", "x-zscaler-transactionid", "z-forwarded-for",
        "x-zscaler-ia", "x-zscaler-sans",
        # Netskope
        "x-netskope-client", "x-netskope-transactionid", "ns-client-ip",
        "x-netskope-activity-id",
        # Palo Alto Prisma Access / GlobalProtect
        "x-pan-session-id", "x-panw-region", "x-prisma-access",
        # Cisco Umbrella / Secure Access
        "x-umbrella-orgid", "x-umbrella-identity",
        # Menlo Security
        "x-menlo-security", "x-menlo-client",
        # Generic proxy timing (often ZT-injected)
        "server-timing",  # cfReqDur, etc.
    }
    # Remove ZT headers from detection pool so they don't trigger false vendor match
    all_header_keys -= zt_proxy_headers

    # Also strip ZT-injected cookies
    zt_proxy_cookies = {
        "cf_bm",  # Cloudflare bot management (can be ZT-injected)
    }

    # Header-based vendor detection (ZT headers already excluded above)
    header_vendor_map = {
        "cloudflare": ["cf-ray", "cf-cache-status", "cf-mitigated"],
        "aws_waf": ["x-amzn-waf-action", "x-amz-cf-id", "x-amzn-requestid", "x-amz-cf-pop"],
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


# ---------------------------------------------------------------------------
# AI / LLM Endpoint Discovery
# ---------------------------------------------------------------------------

# Technique #1: Common AI API path patterns
_AI_API_PATHS: List[Tuple[str, str]] = [
    # OpenAI-compatible
    ("/v1/chat/completions", "openai_compat"),
    ("/v1/completions", "openai_compat"),
    ("/v1/embeddings", "openai_compat"),
    ("/v1/models", "openai_compat"),
    ("/v1/images/generations", "openai_compat"),
    ("/v1/audio/transcriptions", "openai_compat"),
    ("/v1/messages", "anthropic_compat"),
    # Common proxy / gateway paths
    ("/api/v1/chat", "ai_chat"),
    ("/api/v1/completions", "ai_chat"),
    ("/api/chat/completions", "ai_chat"),
    ("/api/chat", "ai_chat"),
    ("/api/ai/chat", "ai_chat"),
    ("/api/ai/generate", "ai_chat"),
    ("/api/ai/completions", "ai_chat"),
    ("/api/openai/v1/chat/completions", "openai_proxy"),
    ("/api/openai/chat/completions", "openai_proxy"),
    ("/proxy/openai/v1/chat/completions", "openai_proxy"),
    ("/api/anthropic/v1/messages", "anthropic_proxy"),
    ("/api/gpt/chat", "gpt_proxy"),
    ("/backend/llm", "llm_backend"),
    ("/backend/ai", "llm_backend"),
    # Ollama
    ("/api/generate", "ollama"),
    ("/api/chat", "ollama"),
    ("/api/tags", "ollama"),
    ("/api/show", "ollama"),
    # LiteLLM
    ("/chat/completions", "litellm"),
    ("/completions", "litellm"),
    ("/models", "litellm"),
    # OpenWebUI / LocalAI
    ("/api/v1/auths/signin", "openwebui"),
    ("/ollama/api/tags", "openwebui"),
    # LangServe / LangChain
    ("/invoke", "langserve"),
    ("/batch", "langserve"),
    ("/stream", "langserve"),
    # Generic AI/ML inference
    ("/ai/generate", "ai_inference"),
    ("/ai/predict", "ai_inference"),
    ("/ai/infer", "ai_inference"),
    ("/llm/query", "ai_inference"),
    ("/llm/generate", "ai_inference"),
    ("/predict", "ai_inference"),
    ("/infer", "ai_inference"),
    ("/generate", "ai_inference"),
    ("/embed", "ai_inference"),
    # Hugging Face / Gradio
    ("/api/predict", "huggingface"),
    ("/run/predict", "gradio"),
    ("/api/queue/push", "gradio"),
    # Vector DB endpoints
    ("/collections", "vector_db"),
    ("/points/search", "vector_db"),
    # Well-known AI config
    ("/.well-known/openid-configuration", "openid_ai"),
    ("/.well-known/ai-plugin.json", "chatgpt_plugin"),
]

# Technique #9: Fuzzing seeds — combined with path prefixes
_AI_FUZZ_SEEDS = [
    "completions", "chat", "generate", "infer", "predict", "embed",
    "query", "llm", "ai", "gpt", "claude", "prompt", "model", "models",
    "assistant", "agent", "copilot", "rag", "search",
]
_AI_FUZZ_PREFIXES = ["/api/", "/api/v1/", "/v1/", "/"]

# Technique #4: Response body fingerprints — indicators of LLM responses
_AI_RESPONSE_PATTERNS = [
    (re.compile(r'"choices"\s*:\s*\['), "openai_response"),
    (re.compile(r'"usage"\s*:\s*\{[^}]*"prompt_tokens"'), "openai_response"),
    (re.compile(r'"completion_tokens"\s*:\s*\d+'), "openai_response"),
    (re.compile(r'"model"\s*:\s*"(gpt-|claude-|llama|mistral|gemma|phi-)'), "llm_model"),
    (re.compile(r'"content"\s*:\s*\[.*?"type"\s*:\s*"text"'), "anthropic_response"),
    (re.compile(r'"stop_reason"\s*:\s*"end_turn"'), "anthropic_response"),
    (re.compile(r'"object"\s*:\s*"(chat\.completion|text_completion|embedding|list)"'), "openai_object"),
    (re.compile(r'data:\s*\{"id":"chatcmpl-'), "openai_streaming"),
    (re.compile(r'data:\s*\{"model"\s*:\s*"(gpt-|claude-)'), "llm_streaming"),
    (re.compile(r'"embedding"\s*:\s*\[[\d\.\-,\s]+\]'), "embedding_response"),
    (re.compile(r'"models"\s*:\s*\[.*?"name"\s*:\s*"'), "model_listing"),
    (re.compile(r'"modelfile"\s*:'), "ollama_response"),
    (re.compile(r'"done"\s*:\s*(true|false).*"total_duration"'), "ollama_response"),
    (re.compile(r'"response"\s*:\s*".*"done"'), "ollama_response"),
]

# Technique #8: AI-specific headers indicating proxy/gateway to AI backends
_AI_PROXY_HEADERS = {
    "openai-organization": "openai",
    "openai-model": "openai",
    "openai-processing-ms": "openai",
    "openai-version": "openai",
    "x-openai-thread-id": "openai",
    "anthropic-ratelimit-tokens-limit": "anthropic",
    "anthropic-ratelimit-requests-limit": "anthropic",
    "x-ratelimit-limit-tokens": "llm_api",
    "x-ratelimit-remaining-tokens": "llm_api",
    "x-ratelimit-limit-requests": "llm_api",
    "x-groq-id": "groq",
    "cf-aig-cache-status": "cloudflare_ai_gateway",
    "cf-aig-serving": "cloudflare_ai_gateway",
    "x-kong-upstream-latency": "ai_gateway",
    "x-kong-proxy-latency": "ai_gateway",
    "x-litellm-model-id": "litellm",
    "x-litellm-cache-key": "litellm",
    "x-model-id": "llm_api",
    "x-inference-time": "ai_inference",
    "x-model-version": "llm_api",
    "x-request-id": "_maybe_ai",  # common in AI APIs — checked with other signals
}

# Technique #7: Self-hosted AI service ports
_AI_PORTS: List[Tuple[int, str, str]] = [
    (11434, "/api/tags",          "ollama"),
    (11434, "/api/version",       "ollama"),
    (8080,  "/v1/models",         "localai"),
    (8080,  "/models",            "localai"),
    (3000,  "/v1/models",         "litellm"),
    (3000,  "/models",            "litellm"),
    (1234,  "/v1/models",         "lm_studio"),
    (1234,  "/v1/chat/completions", "lm_studio"),
    (5000,  "/v1/models",         "flask_ai"),
    (5000,  "/api/predict",       "flask_ai"),
    (8000,  "/v1/models",         "fastapi_ai"),
    (8000,  "/docs",              "fastapi_ai"),
    (7860,  "/api/predict",       "gradio"),
    (7860,  "/info",              "gradio"),
    (8501,  "/healthz",           "streamlit"),
    (9090,  "/v2/models",         "triton"),
    (8501,  "/_stcore/health",    "streamlit"),
]


def check_ai_endpoints(host: str, port: int, use_ssl: bool,
                       timeout: int = 5,
                       extra_headers: Optional[Dict[str, str]] = None,
                       origin_ips: Optional[List[str]] = None,
                       ) -> Dict[str, Any]:
    """Discover AI/LLM endpoints via path probing, response fingerprinting,
    header leakage detection, self-hosted port scanning, and fuzzing.

    Implements techniques:
      #1 — Common AI API path probing
      #2/#4 — Request/response fingerprinting
      #7 — Self-hosted AI port scanning (Ollama, LocalAI, LiteLLM, etc.)
      #8 — API gateway/proxy header leakage
      #9 — AI endpoint fuzzing with wordlist seeds

    Returns:
        Dict with 'endpoints', 'ai_headers', 'port_scan', 'technologies',
        and 'summary' keys.
    """
    from fray.recon.http import _fetch_url
    import concurrent.futures

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    found_endpoints: List[Dict[str, Any]] = []
    ai_headers_found: Dict[str, str] = {}  # header -> detected service
    technologies_detected: set = set()
    seen_paths: set = set()

    def _classify_response(status: int, body: str, hdrs: dict,
                           path: str, category: str) -> Optional[Dict[str, Any]]:
        """Analyze a response for AI/LLM indicators."""
        if status == 0 or status == 404 or status >= 500:
            return None

        lower_body = body.lower() if body else ""
        ct = hdrs.get("content-type", "")

        # Technique #8: Check response headers for AI proxy indicators
        path_ai_headers = {}
        for hdr_name, svc in _AI_PROXY_HEADERS.items():
            val = hdrs.get(hdr_name, "")
            if val:
                if hdr_name == "x-request-id" and svc == "_maybe_ai":
                    # x-request-id alone is not conclusive — only flag with other signals
                    continue
                path_ai_headers[hdr_name] = val
                ai_headers_found[hdr_name] = svc
                technologies_detected.add(svc)

        # Technique #4: Check body for AI response patterns
        body_signals = []
        for pat, sig_type in _AI_RESPONSE_PATTERNS:
            if pat.search(body or ""):
                body_signals.append(sig_type)
                technologies_detected.add(sig_type)

        # Check SSE streaming indicator
        is_sse = "text/event-stream" in ct
        if is_sse and ("data:" in (body or "")):
            body_signals.append("sse_streaming")

        # Determine if this is an AI endpoint
        is_ai = bool(body_signals) or bool(path_ai_headers)

        # Also accept 200 + JSON with model/chat-like content for known paths
        if not is_ai and status == 200 and "json" in ct:
            if any(k in lower_body for k in (
                '"model"', '"models"', '"prompt"', '"messages"',
                '"temperature"', '"max_tokens"', '"tokens"',
                '"embedding"', '"inference"',
            )):
                is_ai = True
                body_signals.append("json_ai_keywords")

        # Accept 401/403 on known AI paths — protected AI endpoint
        if not is_ai and status in (401, 403) and category != "fuzz":
            is_ai = True
            body_signals.append("protected")

        # Accept redirects on known AI paths
        if not is_ai and status in (301, 302, 303, 307, 308) and category != "fuzz":
            loc = hdrs.get("location", "")
            if any(k in loc.lower() for k in ("auth", "login", "sso", "oauth")):
                is_ai = True
                body_signals.append("auth_redirect")

        if not is_ai:
            return None

        entry: Dict[str, Any] = {
            "path": path,
            "status": status,
            "category": category,
            "signals": body_signals,
        }
        if path_ai_headers:
            entry["ai_headers"] = path_ai_headers
        if status in (401, 403):
            entry["protected"] = True
            www_auth = hdrs.get("www-authenticate", "")
            if www_auth:
                entry["auth_scheme"] = www_auth.split()[0]
        if status in (301, 302, 303, 307, 308):
            entry["redirect"] = hdrs.get("location", "")
        return entry

    def _probe_path(path: str, category: str) -> Optional[Dict[str, Any]]:
        """Probe a single path on the target."""
        if path in seen_paths:
            return None
        seen_paths.add(path)
        url = f"{base}{path}"
        try:
            status, body, hdrs = _fetch_url(url, timeout=timeout,
                                             verify_ssl=True,
                                             headers=extra_headers)
            if status == 0 and use_ssl:
                status, body, hdrs = _fetch_url(url, timeout=timeout,
                                                 verify_ssl=False,
                                                 headers=extra_headers)
        except Exception:
            return None
        return _classify_response(status, body, hdrs, path, category)

    # ── Phase 1: Probe known AI API paths (technique #1) ──
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(_probe_path, path, cat): (path, cat)
            for path, cat in _AI_API_PATHS
        }
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 4):
            try:
                result = f.result()
                if result:
                    found_endpoints.append(result)
            except Exception:
                pass

    # ── Phase 2: AI endpoint fuzzing (technique #9) ──
    # Only fuzz paths we haven't already probed
    fuzz_paths = []
    for prefix in _AI_FUZZ_PREFIXES:
        for seed in _AI_FUZZ_SEEDS:
            p = f"{prefix}{seed}"
            if p not in seen_paths:
                fuzz_paths.append(p)
    # Limit fuzz to avoid excessive requests
    fuzz_paths = fuzz_paths[:40]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_probe_path, p, "fuzz"): p
            for p in fuzz_paths
        }
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                result = f.result()
                if result:
                    found_endpoints.append(result)
            except Exception:
                pass

    # ── Phase 3: Self-hosted AI port scan (technique #7) ──
    port_scan_results: List[Dict[str, Any]] = []
    scan_targets: List[str] = []
    # Scan origin IPs if available (behind WAF/CDN)
    if origin_ips:
        for ip in origin_ips[:3]:
            scan_targets.append(ip)
    # Also try the host itself
    scan_targets.append(host)

    def _probe_port(target_ip: str, ai_port: int, probe_path: str,
                    svc_name: str) -> Optional[Dict[str, Any]]:
        """Try to connect to a self-hosted AI service port."""
        # Quick TCP check first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 3))
        try:
            sock.connect((target_ip, ai_port))
            sock.close()
        except (socket.error, OSError):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Port is open — try HTTP probe
        url = f"http://{target_ip}:{ai_port}{probe_path}"
        try:
            status, body, hdrs = _fetch_url(url, timeout=min(timeout, 3),
                                             verify_ssl=False)
        except Exception:
            return {"ip": target_ip, "port": ai_port, "service": svc_name,
                    "status": "open", "detail": "Port open, HTTP probe failed"}

        if status == 0:
            return {"ip": target_ip, "port": ai_port, "service": svc_name,
                    "status": "open", "detail": "Port open, no HTTP response"}

        entry = {"ip": target_ip, "port": ai_port, "service": svc_name,
                 "status": "confirmed" if status == 200 else f"http_{status}",
                 "path": probe_path, "http_status": status}

        # Check body for confirmation
        for pat, sig_type in _AI_RESPONSE_PATTERNS:
            if pat.search(body or ""):
                entry["confirmed"] = True
                entry["signal"] = sig_type
                technologies_detected.add(svc_name)
                break
        # Ollama version check
        if svc_name == "ollama" and status == 200:
            if "ollama" in (body or "").lower() or '"models"' in (body or ""):
                entry["confirmed"] = True
                technologies_detected.add("ollama")
        # Gradio/Streamlit check
        if svc_name in ("gradio", "streamlit") and status == 200:
            if svc_name in (body or "").lower():
                entry["confirmed"] = True
                technologies_detected.add(svc_name)
        # FastAPI docs check
        if probe_path == "/docs" and status == 200:
            if "swagger" in (body or "").lower() or "openapi" in (body or "").lower():
                entry["confirmed"] = True
                entry["signal"] = "fastapi_docs"

        return entry

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        port_futures = {}
        for target_ip in scan_targets:
            for ai_port, probe_path, svc_name in _AI_PORTS:
                f = pool.submit(_probe_port, target_ip, ai_port, probe_path, svc_name)
                port_futures[f] = (target_ip, ai_port, svc_name)
        for f in concurrent.futures.as_completed(port_futures, timeout=timeout * 3):
            try:
                result = f.result()
                if result:
                    port_scan_results.append(result)
            except Exception:
                pass

    # ── Phase 4: Technique #8 — Check main page headers for AI proxy leakage ──
    # Already captured during path probing; also check the main page
    try:
        status, body, hdrs = _fetch_url(f"{base}/", timeout=timeout,
                                         verify_ssl=True,
                                         headers=extra_headers)
        for hdr_name, svc in _AI_PROXY_HEADERS.items():
            val = hdrs.get(hdr_name, "")
            if val and svc != "_maybe_ai":
                ai_headers_found[hdr_name] = svc
                technologies_detected.add(svc)
        # Also look for AI JS SDK references in the main page body (technique #2)
        _JS_AI_PATTERNS = [
            (re.compile(r'openai\.com/v1|api\.openai\.com', re.I), "openai_js"),
            (re.compile(r'anthropic\.com/v1|api\.anthropic\.com', re.I), "anthropic_js"),
            (re.compile(r'api\.cohere\.ai|cohere\.com', re.I), "cohere_js"),
            (re.compile(r'api\.groq\.com|groq\.com/openai', re.I), "groq_js"),
            (re.compile(r'api\.mistral\.ai', re.I), "mistral_js"),
            (re.compile(r'generativelanguage\.googleapis\.com|ai\.google', re.I), "google_ai_js"),
            (re.compile(r'api\.replicate\.com', re.I), "replicate_js"),
            (re.compile(r'api\.together\.xyz|together\.ai', re.I), "together_js"),
            (re.compile(r'inference\.huggingface\.co|api-inference\.huggingface', re.I), "huggingface_js"),
            (re.compile(r'ollama\.(?:ai|com)|localhost:11434', re.I), "ollama_js"),
            (re.compile(r'litellm|\/chat\/completions', re.I), "litellm_js"),
            (re.compile(r'langchain|langserve|langsmith', re.I), "langchain_js"),
            (re.compile(r'pinecone\.io|pinecone-client', re.I), "pinecone_js"),
            (re.compile(r'weaviate\.io|weaviate-client', re.I), "weaviate_js"),
            (re.compile(r'qdrant\.tech|qdrant-js', re.I), "qdrant_js"),
        ]
        for pat, tech in _JS_AI_PATTERNS:
            if pat.search(body or ""):
                technologies_detected.add(tech)
    except Exception:
        pass

    # ── Build summary ──
    confirmed_endpoints = [e for e in found_endpoints if e.get("signals")]
    confirmed_ports = [p for p in port_scan_results if p.get("confirmed")]
    open_ai_ports = [p for p in port_scan_results
                     if p.get("status") in ("open", "confirmed") or
                     (isinstance(p.get("http_status"), int) and p["http_status"] < 500)]

    return {
        "endpoints": found_endpoints,
        "ai_headers": dict(ai_headers_found),
        "port_scan": port_scan_results,
        "open_ports": open_ai_ports,
        "confirmed_ports": confirmed_ports,
        "technologies": sorted(technologies_detected),
        "total_probed": len(seen_paths),
        "total_found": len(found_endpoints),
        "total_confirmed_ports": len(confirmed_ports),
        "summary": (f"{len(found_endpoints)} AI endpoint(s) found, "
                    f"{len(ai_headers_found)} AI header(s) detected, "
                    f"{len(open_ai_ports)} open AI port(s), "
                    f"{len(confirmed_ports)} confirmed self-hosted service(s)"),
    }


# ---------------------------------------------------------------------------
# Bot / Anti-Automation Detection (#52, #53, #54)
# Research-accurate per-vendor signatures from official docs and
# reverse-engineering analysis.  Each vendor entry documents:
#   - Detection method (cookie / JS / header / body pattern)
#   - How the vendor actually detects bots
# ---------------------------------------------------------------------------

# Per-vendor comprehensive detection profiles
# Each: (vendor_id, label, detection_method, cookies, js_patterns, header_keys, body_patterns)
_BOT_VENDORS = [
    # ── Cloudflare ─────────────────────────────────────────────────────
    # Ref: https://developers.cloudflare.com/fundamentals/reference/policies-compliances/cloudflare-cookies/
    # Detection: JS challenge (cf_clearance), bot score (__cf_bm), behavioral + TLS fingerprint
    # __cf_bm — Bot Management / Bot Fight Mode, 30min cookie, encrypted bot score
    # __cfseq — Sequence Analytics, tracks request order
    # cf_clearance — passed JS/managed/interactive challenge, stores JS detection result
    # _cfuvid — Rate Limiting Rules, visitor ID for shared-IP disambiguation
    # __cfruid — legacy Rate Limiting visitor ID
    # __cflb — Load Balancer session affinity
    # __cfwaitingroom — Waiting Room queue cookie
    # cf_chl_rc_i/ni/m — Challenge Platform interaction/non-interaction/managed cookies
    {
        "id": "cloudflare_bot_mgmt", "label": "Cloudflare Bot Management",
        "method": "JS challenge + behavioral analysis + TLS fingerprint + bot score",
        "cookies": ["__cf_bm"],
        "js_body": [re.compile(r'/cdn-cgi/challenge-platform', re.I)],
        "headers": [],
        "category": "bot_management",
    },
    {
        "id": "cloudflare_js_challenge", "label": "Cloudflare JS Challenge",
        "method": "Browser must execute JS to solve challenge; result stored in cf_clearance",
        "cookies": ["cf_clearance", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m"],
        "js_body": [
            re.compile(r'cf-browser-verification|cf_chl_opt', re.I),
            re.compile(r'jschl-answer|jschl_vc', re.I),
        ],
        "headers": ["cf-mitigated", "cf-chl-bypass"],
        "category": "js_challenge",
    },
    {
        "id": "cloudflare_rate_limit", "label": "Cloudflare Rate Limiting",
        "method": "Visitor ID cookie for per-user rate limits behind shared IPs (cf.unique_visitor_id)",
        "cookies": ["_cfuvid", "__cfruid"],
        "js_body": [],
        "headers": [],
        "category": "rate_limiting",
    },
    {
        "id": "cloudflare_sequence", "label": "Cloudflare Sequence Analytics",
        "method": "Tracks request order and timing via __cfseq cookie for sequence rule matching",
        "cookies": ["__cfseq"],
        "js_body": [],
        "headers": [],
        "category": "behavioral",
    },
    {
        "id": "cloudflare_waiting_room", "label": "Cloudflare Waiting Room",
        "method": "Queue-based access control; cookie required to proceed",
        "cookies": ["__cfwaitingroom"],
        "js_body": [],
        "headers": [],
        "category": "rate_limiting",
    },
    {
        "id": "cloudflare_turnstile", "label": "Cloudflare Turnstile",
        "method": "Non-interactive CAPTCHA widget; client-side JS challenge via challenges.cloudflare.com",
        "cookies": [],
        "js_body": [
            re.compile(r'challenges\.cloudflare\.com/turnstile', re.I),
            re.compile(r'cf-turnstile', re.I),
        ],
        "headers": [],
        "category": "captcha",
    },
    # ── Akamai ─────────────────────────────────────────────────────────
    # Detection: sensor_data JS payload → _abck cookie validation; ak_bmsc HTTP-only session
    # bm_sz — bot manager request size tracking; bm_sv — server-side validation
    # JS: akam-sw.js (service worker), bmctx (bot manager context)
    {
        "id": "akamai_bot_manager", "label": "Akamai Bot Manager",
        "method": "sensor_data JS fingerprint → _abck cookie; ak_bmsc HTTP-only session; "
                  "collects 150+ browser signals (canvas, WebGL, audio, fonts, screen, plugins)",
        "cookies": ["_abck", "ak_bmsc", "bm_sz", "bm_sv", "bm_mi"],
        "js_body": [
            re.compile(r'akam-sw\.js|akam/\d+/\w+', re.I),
            re.compile(r'bmctx|akamai.*sensor', re.I),
        ],
        "headers": [],
        "category": "bot_management",
    },
    # Akamai CDN/WAF (without full Bot Manager — WAF may block before JS is served)
    # AKA_A2 cookie, akamai-grn header, x-akam-sw-version header
    {
        "id": "akamai_cdn", "label": "Akamai CDN / WAF",
        "method": "Akamai edge platform detected (CDN/WAF layer); bot manager JS may not be served if WAF blocks first",
        "cookies": ["AKA_A2"],
        "js_body": [],
        "headers": ["akamai-grn", "x-akam-sw-version"],
        "category": "bot_management",
    },
    # ── Imperva / Incapsula ────────────────────────────────────────────
    # Detection: 2-phase JS challenge: ___utmvc (browser fingerprint via xorshift128 encoding)
    #   + reese84 (deep behavioral fingerprint with obfuscated key-value encoding)
    # Cookies: incap_ses_ (session), visid_incap_ (visitor ID), nlbi_ (load balancer)
    {
        "id": "imperva_bot", "label": "Imperva / Incapsula Bot Protection",
        "method": "2-phase JS fingerprint: ___utmvc (browser attrs via xorshift128) + "
                  "reese84 (behavioral fingerprint with obfuscated encoding); "
                  "validates cookies incap_ses_, visid_incap_",
        "cookies": ["reese84", "___utmvc", "incap_ses_", "visid_incap_", "nlbi_"],
        "js_body": [
            re.compile(r'incapsula|reese84|___utmvc', re.I),
            re.compile(r'/_Incapsula_Resource', re.I),
        ],
        "headers": ["x-iinfo", "x-cdn"],
        "category": "bot_management",
    },
    # ── PerimeterX / HUMAN Security ───────────────────────────────────
    # Detection: px.js collects device/browser properties → _px3 clearance cookie
    # _pxhd — device fingerprint hash; _pxvid — visitor ID; _pxde — data enrichment
    # POST to /<appId>/xhr/api/v2/collector for high-security sites
    # _px3 expires ~60 seconds — must be continuously refreshed
    {
        "id": "perimeterx", "label": "PerimeterX / HUMAN Security",
        "method": "px.js browser fingerprinting → _px3 clearance (60s TTL); "
                  "_pxhd device hash; behavioral biometrics (mouse, keyboard, touch); "
                  "POST to /xhr/api/v2/collector for validation",
        "cookies": ["_px3", "_px2", "_px", "_pxhd", "_pxvid", "_pxde"],
        "js_body": [
            re.compile(r'perimeterx\.com|/\w+/init\.js.*PX\w+', re.I),
            re.compile(r'px-captcha|px-block', re.I),
            re.compile(r'_pxAppId|window\._pxParam', re.I),
        ],
        "headers": ["x-px-cookies"],
        "category": "bot_management",
    },
    # ── DataDome ──────────────────────────────────────────────────────
    # Detection: JS tag collects Picasso fingerprint (canvas rendering + device class),
    #   browser signals, behavioral data → datadome cookie
    # API validation at api.datadome.co; x-datadome-* response headers
    {
        "id": "datadome", "label": "DataDome Bot Protection",
        "method": "JS tag → Picasso device fingerprint (canvas rendering for device class), "
                  "TLS fingerprint (JA3/JA4), behavioral analysis, IP reputation; "
                  "validates via api.datadome.co",
        "cookies": ["datadome"],
        "js_body": [
            re.compile(r'datadome\.co/|js\.datadome\.co', re.I),
            re.compile(r'window\.ddjskey|dd\.js|datadome\.js', re.I),
        ],
        "headers": ["x-datadome", "x-datadome-cid"],
        "category": "bot_management",
    },
    # ── Kasada ────────────────────────────────────────────────────────
    # Detection: Proof-of-Work JS challenge (client must solve computational puzzle);
    #   kasada.js generates KP_UIDz-ssn/KP_UIDz cookies
    # __kBT cookie for tracking; cd_kbt_ for session
    {
        "id": "kasada", "label": "Kasada Bot Protection",
        "method": "JavaScript Proof-of-Work challenge (computational puzzle); "
                  "sensor collection via kasada.js → KP_UIDz session cookies; "
                  "149+ device/browser signals",
        "cookies": ["KP_UIDz-ssn", "KP_UIDz", "__kBT", "cd_kbt_"],
        "js_body": [
            re.compile(r'kasada\.io|/ips\.js\?', re.I),
            re.compile(r'cd_kbt_|__kBT', re.I),
        ],
        "headers": ["x-kpsdk-ct", "x-kpsdk-cd", "x-kpsdk-v"],
        "category": "bot_management",
    },
    # ── F5 Shape Security ─────────────────────────────────────────────
    # Detection: Shape Defense Engine (L7 reverse proxy); Shape AI Cloud ML;
    #   f5_cspm.js client-side protection; encrypted JS signals
    {
        "id": "shape_security", "label": "F5 Shape Security",
        "method": "Shape Defense Engine (L7 reverse proxy) + Shape AI Cloud ML analysis; "
                  "f5_cspm.js client-side JS signals; real-time request classification",
        "cookies": ["f5_cspm", "TS01", "TSPD_101", "TSf5_cspm"],
        "js_body": [
            re.compile(r'f5_cspm\.js|f5aas|shapedetect', re.I),
            re.compile(r'shape\.com|shapesecurity', re.I),
        ],
        "headers": [],
        "category": "bot_management",
    },
    # ── Distil Networks (now part of Imperva) ─────────────────────────
    {
        "id": "distil", "label": "Distil Networks (Imperva Advanced Bot Protection)",
        "method": "JS fingerprint + behavioral analysis; device fingerprint + mouse/keyboard patterns",
        "cookies": ["D_IID", "D_SID", "D_ZID", "D_BDID", "D_HID"],
        "js_body": [re.compile(r'distil\.js|distilnetworks|d_biometric', re.I)],
        "headers": ["x-distil-cs"],
        "category": "bot_management",
    },
    # ── FingerprintJS (identification, not blocking) ──────────────────
    {
        "id": "fingerprintjs", "label": "FingerprintJS Pro",
        "method": "Browser fingerprinting SDK (canvas, WebGL, audio, fonts, screen); "
                  "generates stable visitorId across sessions; used for fraud detection",
        "cookies": ["_vid_t"],
        "js_body": [
            re.compile(r'fingerprintjs|fpjs\.io|fingerprint\.com', re.I),
            re.compile(r'FingerprintJS\.load|fpPromise', re.I),
        ],
        "headers": [],
        "category": "fingerprinting",
    },
    # ── CAPTCHA providers ─────────────────────────────────────────────
    {
        "id": "recaptcha_v2", "label": "Google reCAPTCHA v2",
        "method": "Visual challenge; requires user interaction (checkbox or image grid)",
        "cookies": [],
        "js_body": [re.compile(r'google\.com/recaptcha/api\.js(?!\S*enterprise)', re.I),
                    re.compile(r'g-recaptcha(?!.*invisible)', re.I)],
        "headers": [],
        "category": "captcha",
    },
    {
        "id": "recaptcha_v3", "label": "Google reCAPTCHA v3 (invisible)",
        "method": "Invisible behavioral scoring; no user interaction; score 0.0-1.0",
        "cookies": [],
        "js_body": [re.compile(r'grecaptcha\.execute\s*\(', re.I),
                    re.compile(r'recaptcha.*render.*=', re.I)],
        "headers": [],
        "category": "captcha",
    },
    {
        "id": "recaptcha_enterprise", "label": "Google reCAPTCHA Enterprise",
        "method": "Enterprise-grade scoring + risk analysis; custom thresholds",
        "cookies": [],
        "js_body": [re.compile(r'google\.com/recaptcha/enterprise\.js', re.I)],
        "headers": [],
        "category": "captcha",
    },
    {
        "id": "hcaptcha", "label": "hCaptcha",
        "method": "Privacy-focused CAPTCHA; visual challenge or passive mode",
        "cookies": [],
        "js_body": [re.compile(r'hcaptcha\.com/1/api\.js', re.I),
                    re.compile(r'h-captcha', re.I)],
        "headers": [],
        "category": "captcha",
    },
]


def check_bot_protection(host: str, port: int, use_ssl: bool,
                         timeout: int = 5,
                         extra_headers: Optional[Dict[str, str]] = None,
                         body: str = "", resp_headers: Optional[Dict[str, str]] = None,
                         ) -> Dict[str, Any]:
    """Detect bot protection / anti-automation mechanisms with research-accurate
    per-vendor cookie, JavaScript, and header signatures.

    Each detection includes the vendor's actual detection method so the report
    can explain *how* bots are detected, not just *what* product is present.
    """
    result: Dict[str, Any] = {
        "vendors": [],      # detailed per-vendor findings
        "captcha": [],
        "bot_management": [],
        "fingerprinting": [],
        "rate_limiting": [],
        "js_challenge": False,
        "summary": "",
    }
    hdrs = resp_headers or {}
    cookie_str = hdrs.get("set-cookie", "")
    detected_ids: set = set()

    for vendor in _BOT_VENDORS:
        vid = vendor["id"]
        if vid in detected_ids:
            continue

        signals: List[str] = []  # what we actually matched

        # Cookie detection
        for cname in vendor["cookies"]:
            if cname.lower() in cookie_str.lower():
                signals.append(f"cookie:{cname}")

        # JS/body pattern detection
        for pat in vendor["js_body"]:
            if pat.search(body):
                signals.append("js_body")
                break

        # Header detection
        for hdr_key in vendor["headers"]:
            if hdrs.get(hdr_key):
                signals.append(f"header:{hdr_key}")

        if not signals:
            continue

        detected_ids.add(vid)
        entry = {
            "id": vid,
            "label": vendor["label"],
            "category": vendor["category"],
            "method": vendor["method"],
            "signals": signals,
        }
        result["vendors"].append(entry)

        cat = vendor["category"]
        if cat == "captcha":
            result["captcha"].append(vendor["label"])
        elif cat == "bot_management":
            result["bot_management"].append(vendor["label"])
        elif cat == "fingerprinting":
            result["fingerprinting"].append(vendor["label"])
        elif cat == "rate_limiting":
            result["rate_limiting"].append(vendor["label"])
        elif cat == "js_challenge":
            result["js_challenge"] = True

    # Also keep backward-compatible "protections" key
    result["protections"] = result["vendors"]

    n = len(result["vendors"])
    parts = []
    if result["bot_management"]:
        parts.append(f"Bot mgmt: {', '.join(result['bot_management'])}")
    if result["captcha"]:
        parts.append(f"CAPTCHA: {', '.join(result['captcha'])}")
    if result["rate_limiting"]:
        parts.append(f"Rate limit: {', '.join(result['rate_limiting'])}")
    if result["fingerprinting"]:
        parts.append(f"Fingerprint: {', '.join(result['fingerprinting'])}")
    if result["js_challenge"]:
        parts.append("JS challenge active")
    result["summary"] = f"{n} bot protection(s): {'; '.join(parts)}" if n else "No bot protection detected"
    return result


# ---------------------------------------------------------------------------
# API Security Detection (#6, #7)
# ---------------------------------------------------------------------------

_API_SECURITY_PATHS = [
    # OpenAPI / Swagger spec discovery
    ("/swagger.json", "swagger"),
    ("/swagger/v1/swagger.json", "swagger"),
    ("/api-docs", "swagger_ui"),
    ("/api-docs.json", "swagger"),
    ("/swagger-ui.html", "swagger_ui"),
    ("/swagger-ui/", "swagger_ui"),
    ("/openapi.json", "openapi"),
    ("/openapi.yaml", "openapi"),
    ("/v1/openapi.json", "openapi"),
    ("/v2/openapi.json", "openapi"),
    ("/v3/api-docs", "openapi"),
    ("/docs", "fastapi_docs"),
    ("/redoc", "redoc"),
    # GraphQL
    ("/graphql", "graphql"),
    ("/graphiql", "graphiql"),
    ("/altair", "altair"),
    ("/playground", "graphql_playground"),
    # Health / metadata
    ("/health", "health"),
    ("/healthz", "health"),
    ("/ready", "health"),
    ("/status", "health"),
    ("/metrics", "metrics"),
    ("/actuator", "spring_actuator"),
    ("/actuator/health", "spring_actuator"),
    # Common API versioned paths
    ("/api/v1", "api"),
    ("/api/v2", "api"),
    ("/api", "api"),
]

_API_RATE_LIMIT_HEADERS = {
    # Standard & de facto rate limit headers
    "x-ratelimit-limit": "Rate limit ceiling",
    "x-ratelimit-remaining": "Remaining requests",
    "x-ratelimit-reset": "Reset timestamp",
    "ratelimit-limit": "IETF draft rate limit",
    "ratelimit-remaining": "IETF draft remaining",
    "ratelimit-reset": "IETF draft reset",
    "ratelimit-policy": "IETF draft policy",
    "retry-after": "Retry delay (seconds or date)",
    "x-rate-limit-limit": "Rate limit (alt format)",
    "x-rate-limit-remaining": "Remaining (alt format)",
    "x-rate-limit-reset": "Reset (alt format)",
    # Vendor-specific
    "x-github-request-limit": "GitHub rate limit",
    "x-shopify-shop-api-call-limit": "Shopify API limit",
}

_API_AUTH_HEADERS = {
    "www-authenticate": "Auth scheme required",
    "x-api-key": "API key header present",
    "authorization": "Auth header echoed",
}

_API_GATEWAY_HEADERS = {
    "x-amzn-requestid": "AWS API Gateway",
    "x-amz-apigw-id": "AWS API Gateway",
    "x-goog-api-client": "Google Cloud API Gateway",
    "x-kong-upstream-latency": "Kong API Gateway",
    "x-kong-proxy-latency": "Kong API Gateway",
    "x-envoy-upstream-service-time": "Envoy / Istio",
    "x-envoy-decorator-operation": "Envoy / Istio",
    "x-request-id": "API Gateway (generic)",
    "x-correlation-id": "API Gateway (generic)",
    "x-b3-traceid": "Zipkin / distributed tracing",
    "x-apigee-message-id": "Apigee API Gateway",
    "x-mashery-responder": "Mashery API Gateway",
    "x-azure-ref": "Azure API Management",
    "ocp-apim-trace-location": "Azure APIM (trace enabled!)",
}


def check_api_security(host: str, port: int, use_ssl: bool,
                       timeout: int = 5,
                       extra_headers: Optional[Dict[str, str]] = None,
                       ) -> Dict[str, Any]:
    """Detect API security posture: authentication, rate limiting,
    OpenAPI/Swagger exposure, API gateway, and common misconfigurations.

    Probes known API documentation paths, checks rate limit headers,
    detects auth requirements, and identifies API gateways.
    """
    from fray.recon.http import _fetch_url
    import concurrent.futures

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    specs_found: List[Dict[str, Any]] = []
    api_endpoints: List[Dict[str, Any]] = []
    rate_limit_info: Dict[str, Any] = {}
    auth_info: Dict[str, Any] = {}
    gateway_info: Dict[str, Any] = {}
    seen_paths: set = set()

    def _probe_api_path(path: str, category: str) -> Optional[Dict[str, Any]]:
        if path in seen_paths:
            return None
        seen_paths.add(path)
        url = f"{base}{path}"
        try:
            status, body, hdrs = _fetch_url(url, timeout=timeout, verify_ssl=True,
                                             headers=extra_headers)
            if status == 0 and use_ssl:
                status, body, hdrs = _fetch_url(url, timeout=timeout, verify_ssl=False,
                                                 headers=extra_headers)
        except Exception:
            return None

        if status == 0 or status == 404:
            return None

        entry: Dict[str, Any] = {"path": path, "status": status, "category": category}

        # Check for OpenAPI/Swagger spec content
        ct = hdrs.get("content-type", "")
        if status == 200 and category in ("swagger", "openapi"):
            if "json" in ct or "yaml" in ct or body.strip()[:1] in ("{", "o"):
                try:
                    spec = json.loads(body[:200000]) if "json" in ct or body.strip().startswith("{") else {}
                    if spec.get("openapi") or spec.get("swagger") or spec.get("info"):
                        entry["spec_version"] = spec.get("openapi", spec.get("swagger", "unknown"))
                        entry["title"] = spec.get("info", {}).get("title", "")
                        paths = spec.get("paths", {})
                        entry["endpoints_count"] = len(paths)
                        entry["endpoints_preview"] = list(paths.keys())[:10]
                        # Check for auth definitions
                        security = spec.get("securityDefinitions", spec.get("components", {}).get("securitySchemes", {}))
                        if security:
                            entry["auth_schemes"] = list(security.keys())
                        entry["severity"] = "high"
                        entry["is_spec"] = True
                except Exception:
                    entry["is_spec"] = body.strip().startswith("{") and len(body) > 100

        # Swagger UI / docs pages
        if status == 200 and category in ("swagger_ui", "fastapi_docs", "redoc", "graphiql", "altair", "graphql_playground"):
            lower = body.lower() if body else ""
            if any(k in lower for k in ("swagger", "openapi", "api-docs", "fastapi", "redoc", "graphiql", "altair", "playground")):
                entry["exposed_ui"] = True
                entry["severity"] = "medium"

        # GraphQL introspection
        if status == 200 and category == "graphql":
            if "graphql" in body.lower() or "query" in body.lower():
                entry["graphql_active"] = True

        # Spring Actuator (info disclosure)
        if status == 200 and category == "spring_actuator":
            entry["severity"] = "high"
            entry["actuator_exposed"] = True

        # Metrics endpoint (Prometheus, etc.)
        if status == 200 and category == "metrics":
            if "# HELP" in body or "# TYPE" in body or "process_" in body:
                entry["prometheus_exposed"] = True
                entry["severity"] = "high"

        # Auth detection: 401/403 = auth required
        if status in (401, 403):
            entry["auth_required"] = True
            www_auth = hdrs.get("www-authenticate", "")
            if www_auth:
                entry["auth_scheme"] = www_auth.split()[0] if www_auth else None
                entry["auth_detail"] = www_auth[:100]

        # Rate limit headers
        for rl_hdr, rl_desc in _API_RATE_LIMIT_HEADERS.items():
            val = hdrs.get(rl_hdr)
            if val:
                if "rate_limits" not in entry:
                    entry["rate_limits"] = {}
                entry["rate_limits"][rl_hdr] = val

        # API Gateway headers
        for gw_hdr, gw_desc in _API_GATEWAY_HEADERS.items():
            val = hdrs.get(gw_hdr)
            if val:
                if "gateway" not in entry:
                    entry["gateway"] = {}
                entry["gateway"][gw_hdr] = {"value": val[:80], "vendor": gw_desc}

        return entry

    # Probe all API paths concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_probe_api_path, path, cat): (path, cat)
            for path, cat in _API_SECURITY_PATHS
        }
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 4):
            try:
                r = f.result()
                if r:
                    if r.get("is_spec"):
                        specs_found.append(r)
                    elif r.get("exposed_ui") or r.get("actuator_exposed") or r.get("prometheus_exposed"):
                        specs_found.append(r)
                    api_endpoints.append(r)

                    # Aggregate rate limit info
                    if r.get("rate_limits"):
                        rate_limit_info.update(r["rate_limits"])
                    # Aggregate auth info
                    if r.get("auth_required"):
                        auth_info[r["path"]] = {
                            "scheme": r.get("auth_scheme"),
                            "detail": r.get("auth_detail", ""),
                        }
                    # Aggregate gateway info
                    if r.get("gateway"):
                        gateway_info.update(r["gateway"])
            except Exception:
                pass

    # Also check main page headers for rate limit / gateway signals
    try:
        status, body, hdrs = _fetch_url(f"{base}/", timeout=timeout, verify_ssl=True,
                                         headers=extra_headers)
        for rl_hdr in _API_RATE_LIMIT_HEADERS:
            val = hdrs.get(rl_hdr)
            if val and rl_hdr not in rate_limit_info:
                rate_limit_info[rl_hdr] = val
        for gw_hdr, gw_desc in _API_GATEWAY_HEADERS.items():
            val = hdrs.get(gw_hdr)
            if val and gw_hdr not in gateway_info:
                gateway_info[gw_hdr] = {"value": val[:80], "vendor": gw_desc}
    except Exception:
        pass

    # Determine gateway vendor
    gw_vendors = set()
    for gw_hdr, info in gateway_info.items():
        if isinstance(info, dict):
            gw_vendors.add(info["vendor"])

    return {
        "specs_found": specs_found,
        "api_endpoints": api_endpoints,
        "rate_limiting": {
            "detected": bool(rate_limit_info),
            "headers": rate_limit_info,
        },
        "authentication": {
            "detected": bool(auth_info),
            "endpoints": auth_info,
        },
        "api_gateway": {
            "detected": bool(gateway_info),
            "vendors": sorted(gw_vendors),
            "headers": {k: v for k, v in gateway_info.items()},
        },
        "total_specs": len(specs_found),
        "total_endpoints_probed": len(seen_paths),
        "total_endpoints_found": len(api_endpoints),
        "severity": ("critical" if any(s.get("severity") == "critical" for s in specs_found) else
                     "high" if specs_found else
                     "medium" if auth_info or rate_limit_info else "info"),
        "summary": (f"{len(specs_found)} API spec/doc(s) exposed, "
                    f"{len(auth_info)} auth-protected endpoint(s), "
                    f"{'rate limiting detected' if rate_limit_info else 'no rate limiting detected'}, "
                    f"gateway: {', '.join(gw_vendors) if gw_vendors else 'none detected'}"),
    }


# ---------------------------------------------------------------------------
# Secret / Credential Detection (#16, #17, #18, #19)
# ---------------------------------------------------------------------------

_API_KEY_PATTERNS = [
    # Cloud providers
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", "critical"),
    (re.compile(r'(?:aws_secret|AWS_SECRET)["\s:=]+[A-Za-z0-9/+=]{40}'), "aws_secret_key", "critical"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "google_api_key", "high"),
    (re.compile(r'ya29\.[0-9A-Za-z\-_]+'), "google_oauth_token", "critical"),
    # GitHub
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'), "github_token", "critical"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{22,255}'), "github_pat", "critical"),
    # Stripe
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "stripe_secret_key", "critical"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "stripe_publishable_key", "medium"),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}'), "stripe_restricted_key", "high"),
    # Twilio
    (re.compile(r'SK[0-9a-fA-F]{32}'), "twilio_api_key", "high"),
    # Slack
    (re.compile(r'xox[bpors]-[0-9]{10,13}-[0-9a-zA-Z-]{24,}'), "slack_token", "critical"),
    (re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'), "slack_webhook", "high"),
    # SendGrid / Mailgun
    (re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'), "sendgrid_api_key", "high"),
    (re.compile(r'key-[0-9a-zA-Z]{32}'), "mailgun_api_key", "high"),
    # Firebase
    (re.compile(r'(?:firebase|FIREBASE)["\s:=]*[A-Za-z0-9_-]{20,}'), "firebase_key", "medium"),
    # Generic patterns
    (re.compile(r'(?:api[_-]?key|apikey|api_secret|auth_token|access_token|secret_key|private_key)["\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "generic_api_key", "medium"),
    (re.compile(r'(?:password|passwd|pwd)["\s:=]+["\']([^\s"\']{8,})["\']', re.I), "hardcoded_password", "high"),
    # OpenAI / Anthropic
    (re.compile(r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}'), "openai_api_key", "critical"),
    (re.compile(r'sk-ant-[a-zA-Z0-9_-]{80,}'), "anthropic_api_key", "critical"),
    # Private keys
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "private_key", "critical"),
    (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "ssh_private_key", "critical"),
]


def check_secrets_in_response(body: str, url: str = "") -> Dict[str, Any]:
    """Scan response body for exposed API keys, tokens, and credentials (#16).

    Returns list of findings with type, severity, and masked value.
    """
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for pat, secret_type, severity in _API_KEY_PATTERNS:
        m = pat.search(body)
        if m and secret_type not in seen:
            seen.add(secret_type)
            value = m.group(0)
            # Mask the value — show first 8 and last 4 chars
            if len(value) > 16:
                masked = value[:8] + "…" + value[-4:]
            else:
                masked = value[:4] + "…"
            findings.append({
                "type": secret_type,
                "severity": severity,
                "masked_value": masked,
                "url": url,
            })

    return {
        "findings": findings,
        "total": len(findings),
        "has_critical": any(f["severity"] == "critical" for f in findings),
    }


def check_jwt_tokens(body: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Analyze JWT tokens found in response body or headers (#17).

    Checks for: weak/none algorithm, expired tokens, missing claims.
    """
    import base64 as _b64

    results: List[Dict[str, Any]] = []
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')

    # Search body and auth headers
    search_text = body or ""
    if headers:
        for h in ("authorization", "x-auth-token", "x-access-token", "set-cookie"):
            if headers.get(h):
                search_text += " " + headers[h]

    for m in jwt_pattern.finditer(search_text):
        token = m.group(0)
        parts = token.split(".")
        if len(parts) < 2:
            continue

        entry: Dict[str, Any] = {"token_preview": token[:40] + "…", "issues": []}

        # Decode header
        try:
            hdr_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
            hdr_json = json.loads(_b64.urlsafe_b64decode(hdr_pad))
            alg = hdr_json.get("alg", "")
            entry["algorithm"] = alg
            if alg.lower() == "none":
                entry["issues"].append({"issue": "none_algorithm", "severity": "critical",
                                        "description": "JWT uses 'none' algorithm — signature not verified"})
            elif alg.lower() in ("hs256", "hs384", "hs512"):
                entry["issues"].append({"issue": "symmetric_algorithm", "severity": "medium",
                                        "description": f"JWT uses symmetric algorithm ({alg}) — vulnerable to brute-force if secret is weak"})
        except Exception:
            pass

        # Decode payload
        try:
            payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(_b64.urlsafe_b64decode(payload_pad))
            entry["claims"] = list(payload.keys())[:10]

            # Check expiration
            exp = payload.get("exp")
            if exp:
                import time as _time
                if exp < _time.time():
                    entry["issues"].append({"issue": "expired", "severity": "medium",
                                            "description": "JWT token is expired"})
            elif "exp" not in payload:
                entry["issues"].append({"issue": "no_expiry", "severity": "medium",
                                        "description": "JWT has no expiration claim (exp)"})

            # Check for sensitive data in payload
            sensitive_keys = {"password", "secret", "ssn", "credit_card", "api_key"}
            exposed = [k for k in payload.keys() if k.lower() in sensitive_keys]
            if exposed:
                entry["issues"].append({"issue": "sensitive_data", "severity": "high",
                                        "description": f"JWT payload contains sensitive claims: {', '.join(exposed)}"})
        except Exception:
            pass

        # Empty signature (none alg exploitation)
        if len(parts) >= 3 and not parts[2]:
            entry["issues"].append({"issue": "empty_signature", "severity": "critical",
                                    "description": "JWT has empty signature — may be exploitable"})

        if entry.get("issues"):
            results.append(entry)

    return {
        "tokens_found": len(jwt_pattern.findall(search_text)),
        "vulnerable_tokens": results,
        "total_issues": sum(len(t["issues"]) for t in results),
    }


def check_source_maps(host: str, port: int, use_ssl: bool,
                      timeout: int = 5,
                      extra_headers: Optional[Dict[str, str]] = None,
                      body: str = "",
                      ) -> Dict[str, Any]:
    """Detect exposed JavaScript source maps (#19).

    Checks for .map file references in HTML and probes common paths.
    """
    from fray.recon.http import _fetch_url

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    found_maps: List[Dict[str, Any]] = []

    # 1. Extract sourceMappingURL references from body
    map_refs = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', body)
    # Also check for .js.map or .css.map links
    map_refs += re.findall(r'(?:src|href)=["\']([^"\']*\.(?:js|css)\.map)', body, re.I)

    # 2. Extract JS file paths and try .map suffix
    js_files = re.findall(r'(?:src)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I)
    for js in js_files[:10]:
        map_path = js.split("?")[0] + ".map"
        if map_path not in map_refs:
            map_refs.append(map_path)

    # 3. Probe each map file
    probed: set = set()
    for ref in map_refs[:15]:
        if ref.startswith("data:"):
            continue
        if ref.startswith("http"):
            url = ref
        elif ref.startswith("/"):
            url = f"{base}{ref}"
        else:
            url = f"{base}/{ref}"
        if url in probed:
            continue
        probed.add(url)

        try:
            status, map_body, hdrs = _fetch_url(url, timeout=timeout, verify_ssl=True,
                                                  headers=extra_headers)
            if status == 0 and use_ssl:
                status, map_body, hdrs = _fetch_url(url, timeout=timeout, verify_ssl=False,
                                                      headers=extra_headers)
        except Exception:
            continue

        if status == 200 and map_body:
            ct = hdrs.get("content-type", "")
            is_map = ("json" in ct or "sourcemap" in ct or
                      map_body.strip().startswith("{") and '"sources"' in map_body[:500])
            if is_map:
                # Extract source file list
                try:
                    map_data = json.loads(map_body[:100000])
                    sources = map_data.get("sources", [])
                    found_maps.append({
                        "url": url,
                        "sources_count": len(sources),
                        "sources_preview": sources[:5],
                        "size": len(map_body),
                    })
                except Exception:
                    found_maps.append({"url": url, "size": len(map_body)})

    return {
        "exposed": found_maps,
        "total": len(found_maps),
        "severity": "medium" if found_maps else "info",
        "description": "Source maps expose original source code, variable names, and internal paths" if found_maps else "",
    }


# ---------------------------------------------------------------------------
# Cloud Bucket Detection (#5, #130, #131, #132)
# ---------------------------------------------------------------------------

def check_cloud_buckets(host: str, timeout: int = 5,
                        extra_headers: Optional[Dict[str, str]] = None,
                        body: str = "",
                        ) -> Dict[str, Any]:
    """Enumerate and check permissions on cloud storage buckets (S3, Azure Blob, GCS).

    Discovers buckets from DNS, page content, and common naming patterns,
    then checks each for public read/list access.
    """
    from fray.recon.http import _fetch_url
    import concurrent.futures

    domain = host.replace("www.", "")
    base_name = domain.split(".")[0]  # e.g. "softbank" from "softbank.jp"

    found_buckets: List[Dict[str, Any]] = []
    seen: set = set()

    # Generate candidate bucket names
    candidates: List[Tuple[str, str, str]] = []  # (url, name, provider)

    # S3 patterns (#130)
    s3_names = [base_name, f"{base_name}-assets", f"{base_name}-static",
                f"{base_name}-media", f"{base_name}-backup", f"{base_name}-data",
                f"{base_name}-public", f"{base_name}-private", f"{base_name}-uploads",
                f"{base_name}-prod", f"{base_name}-staging", f"{base_name}-dev"]
    for name in s3_names:
        candidates.append((f"https://{name}.s3.amazonaws.com", name, "aws_s3"))
        candidates.append((f"https://s3.amazonaws.com/{name}", name, "aws_s3"))

    # Azure Blob patterns (#131)
    for name in [base_name, f"{base_name}storage", f"{base_name}data"]:
        candidates.append((f"https://{name}.blob.core.windows.net", name, "azure_blob"))
        candidates.append((f"https://{name}.blob.core.windows.net/$web", name, "azure_blob"))

    # GCS patterns (#132)
    for name in [base_name, f"{base_name}-assets", f"{base_name}-public"]:
        candidates.append((f"https://storage.googleapis.com/{name}", name, "gcs"))
        candidates.append((f"https://{name}.storage.googleapis.com", name, "gcs"))

    # Also check for bucket references in page body
    s3_refs = re.findall(r'([a-z0-9][a-z0-9.\-]{1,62})\.s3[.\-]amazonaws\.com', body, re.I)
    for ref in s3_refs[:5]:
        if ref not in seen:
            candidates.append((f"https://{ref}.s3.amazonaws.com", ref, "aws_s3"))
    azure_refs = re.findall(r'([a-z0-9]{3,24})\.blob\.core\.windows\.net', body, re.I)
    for ref in azure_refs[:5]:
        candidates.append((f"https://{ref}.blob.core.windows.net", ref, "azure_blob"))
    gcs_refs = re.findall(r'storage\.googleapis\.com/([a-z0-9][a-z0-9.\-_]{1,62})', body, re.I)
    for ref in gcs_refs[:5]:
        candidates.append((f"https://storage.googleapis.com/{ref}", ref, "gcs"))

    def _check_bucket(url: str, name: str, provider: str) -> Optional[Dict[str, Any]]:
        if url in seen:
            return None
        seen.add(url)
        try:
            status, resp_body, hdrs = _fetch_url(url, timeout=timeout, verify_ssl=True)
        except Exception:
            return None

        entry: Dict[str, Any] = {"name": name, "provider": provider, "url": url, "status": status}

        if status == 200:
            # Check if listing is enabled
            if "<ListBucketResult" in (resp_body or "") or "<EnumerationResults" in (resp_body or ""):
                entry["public_listing"] = True
                entry["severity"] = "critical"
                # Count objects
                keys = re.findall(r'<Key>([^<]+)</Key>', resp_body or "")
                entry["objects_preview"] = keys[:5]
                entry["objects_count"] = len(keys)
            else:
                entry["public_read"] = True
                entry["severity"] = "high"
            return entry
        elif status == 403:
            entry["exists"] = True
            entry["public_read"] = False
            entry["severity"] = "info"
            return entry
        # 404 = doesn't exist, skip
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_check_bucket, url, name, prov): (url, name, prov)
                   for url, name, prov in candidates}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 4):
            try:
                r = f.result()
                if r:
                    found_buckets.append(r)
            except Exception:
                pass

    public = [b for b in found_buckets if b.get("public_listing") or b.get("public_read")]
    return {
        "buckets": found_buckets,
        "total_found": len(found_buckets),
        "public_buckets": public,
        "total_public": len(public),
        "providers_checked": ["aws_s3", "azure_blob", "gcs"],
        "severity": "critical" if any(b.get("public_listing") for b in found_buckets) else
                    "high" if public else "info",
    }


# ---------------------------------------------------------------------------
# JS Analysis (#1, #8, #10)
# ---------------------------------------------------------------------------

_JS_ENDPOINT_PATTERNS = [
    # Fetch / axios / XMLHttpRequest calls
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`"']([/][^`"'\s]{3,})[`"']''', re.I),
    # String URLs
    re.compile(r'''["\'](/api/[^"'\s]{2,})["\']'''),
    re.compile(r'''["\'](/v[12]/[^"'\s]{2,})["\']'''),
    re.compile(r'''["\'](https?://[^"'\s]{10,})["\']'''),
    # Route definitions (React Router, Vue Router, Express)
    re.compile(r'''path\s*:\s*["\'](/[^"'\s]{2,})["\']'''),
    re.compile(r'''(?:app|router)\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["\']([/][^"'\s]{2,})["\']''', re.I),
    # GraphQL endpoints
    re.compile(r'''["\']([^"'\s]*graphql[^"'\s]*)["\']''', re.I),
    # WebSocket URLs
    re.compile(r'''["\']([^"'\s]*wss?://[^"'\s]+)["\']''', re.I),
]


def check_js_endpoints(host: str, port: int, use_ssl: bool,
                       timeout: int = 5,
                       extra_headers: Optional[Dict[str, str]] = None,
                       body: str = "",
                       ) -> Dict[str, Any]:
    """Extract endpoints from page source and linked JS files (#1).

    Finds API endpoints, routes, fetch calls, and hidden paths from
    HTML body and referenced JavaScript bundles.
    """
    from fray.recon.http import _fetch_url
    import concurrent.futures

    scheme = "https" if use_ssl else "http"
    port_str = "" if (use_ssl and port == 443) or (not use_ssl and port == 80) else f":{port}"
    base = f"{scheme}://{host}{port_str}"

    endpoints: set = set()
    websocket_urls: set = set()
    file_upload_forms: List[Dict[str, Any]] = []

    def _extract_from_source(source: str, source_url: str = ""):
        """Extract endpoints from a chunk of JS/HTML source."""
        for pat in _JS_ENDPOINT_PATTERNS:
            for m in pat.finditer(source):
                ep = m.group(1)
                if ep.startswith("ws://") or ep.startswith("wss://"):
                    websocket_urls.add(ep)
                else:
                    # Filter out obvious non-endpoints
                    if not any(ep.endswith(ext) for ext in (".png", ".jpg", ".gif", ".css", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")):
                        endpoints.add(ep)

    # Phase 1: Extract from main page body
    _extract_from_source(body, base)

    # Phase 1b: Check for file upload forms (#8)
    file_inputs = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
    for form in file_inputs:
        if re.search(r'type=["\']file["\']', form, re.I) or 'multipart/form-data' in form.lower():
            action = re.search(r'action=["\']([^"\']+)["\']', form, re.I)
            method = re.search(r'method=["\']([^"\']+)["\']', form, re.I)
            file_upload_forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "POST").upper(),
            })
    # Also check for JS-based file upload (Dropzone, etc.)
    if re.search(r'Dropzone|dropzone|FileReader|formData\.append.*file|input.*type.*file', body, re.I):
        file_upload_forms.append({"action": "(JS-based upload)", "method": "POST"})

    # Phase 1c: Check for WebSocket usage (#10)
    ws_patterns = [
        re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'(?:io|socket)\s*\(\s*["\']([^"\']+)["\']', re.I),  # Socket.IO
        re.compile(r'SockJS\s*\(\s*["\']([^"\']+)["\']', re.I),
    ]
    for pat in ws_patterns:
        for m in pat.finditer(body):
            websocket_urls.add(m.group(1))

    # Phase 2: Fetch and analyze linked JS files
    js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.I)
    # Prioritize first-party JS
    first_party = [s for s in js_srcs if host in s or s.startswith("/")]
    third_party = [s for s in js_srcs if s not in first_party]
    js_to_fetch = first_party[:8] + third_party[:2]  # Limit to 10 files

    def _fetch_js(src: str) -> str:
        if src.startswith("//"):
            url = f"{scheme}:{src}"
        elif src.startswith("/"):
            url = f"{base}{src}"
        elif src.startswith("http"):
            url = src
        else:
            url = f"{base}/{src}"
        try:
            status, js_body, _ = _fetch_url(url, timeout=timeout, verify_ssl=True,
                                              headers=extra_headers)
            if status == 0 and use_ssl:
                status, js_body, _ = _fetch_url(url, timeout=timeout, verify_ssl=False,
                                                  headers=extra_headers)
            return js_body if status == 200 else ""
        except Exception:
            return ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_fetch_js, src): src for src in js_to_fetch}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                js_body = f.result()
                if js_body:
                    _extract_from_source(js_body, futures[f])
            except Exception:
                pass

    # Categorize endpoints
    api_endpoints = sorted(ep for ep in endpoints if "/api" in ep.lower() or "/v1" in ep.lower() or "/v2" in ep.lower())
    internal_paths = sorted(ep for ep in endpoints if ep.startswith("/") and ep not in api_endpoints)
    external_urls = sorted(ep for ep in endpoints if ep.startswith("http"))

    return {
        "total_endpoints": len(endpoints),
        "api_endpoints": api_endpoints[:30],
        "internal_paths": internal_paths[:30],
        "external_urls": external_urls[:20],
        "websocket_urls": sorted(websocket_urls),
        "file_upload_forms": file_upload_forms,
        "js_files_analyzed": len(js_to_fetch),
        "has_websockets": bool(websocket_urls),
        "has_file_upload": bool(file_upload_forms),
    }
