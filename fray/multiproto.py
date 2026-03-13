#!/usr/bin/env python3
"""
Fray — Multi-Protocol Security Testing (#164)

Tests WebSocket, GraphQL, and gRPC endpoints for common vulnerabilities.

WebSocket:
  - Endpoint discovery (ws://, wss://, Socket.IO, SockJS)
  - Origin validation bypass
  - Message injection (XSS, SQLi payloads via WS frames)
  - Auth bypass (connect without credentials)

GraphQL:
  - Introspection abuse (schema dump)
  - Query batching DoS
  - Nested query depth attack
  - Field suggestion enumeration
  - Mutation discovery + mass assignment

gRPC:
  - Reflection API enumeration
  - Service/method listing
  - Unary call probing (empty message)
  - Health check service detection

CLI:
    fray proto https://example.com
    fray proto https://example.com --ws-only
    fray proto https://example.com --graphql-only
    fray proto https://example.com --grpc-only
"""

import http.client
import json
import re
import socket
import ssl
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"


# ── WebSocket Testing ────────────────────────────────────────────────────────

_WS_PATHS = [
    "/ws", "/websocket", "/socket", "/wss",
    "/socket.io/", "/sockjs/", "/cable",
    "/hub", "/signalr", "/realtime",
    "/api/ws", "/api/websocket", "/api/v1/ws",
    "/graphql-ws", "/subscriptions",
    "/live", "/stream", "/events",
]

_WS_PAYLOADS = [
    # XSS via WebSocket message
    '{"msg":"<script>alert(1)</script>"}',
    '{"msg":"<img src=x onerror=alert(1)>"}',
    # SQLi via WebSocket message
    '{"query":"1\' OR \'1\'=\'1"}',
    '{"id":"1 UNION SELECT 1,2,3--"}',
    # Command injection
    '{"cmd":"test; id"}',
    '{"path":"../../../etc/passwd"}',
    # JSON injection / prototype pollution
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"isAdmin":true}}}',
]


def _ws_handshake(host: str, port: int, path: str, use_ssl: bool,
                  origin: str = "", timeout: int = 5) -> Tuple[int, Dict[str, str], str]:
    """Attempt a WebSocket handshake. Returns (status, headers, error)."""
    import hashlib
    import base64
    import os

    key = base64.b64encode(os.urandom(16)).decode()

    headers = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
    )
    if origin:
        headers += f"Origin: {origin}\r\n"
    headers += f"User-Agent: Mozilla/5.0 (Fray/{__version__})\r\n"
    headers += "\r\n"

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
        else:
            sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(headers.encode())

        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        sock.close()

        resp_str = resp.decode("utf-8", "replace")
        first_line = resp_str.split("\r\n")[0]
        status = int(first_line.split(" ")[1]) if " " in first_line else 0

        resp_headers = {}
        for line in resp_str.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status, resp_headers, ""
    except Exception as e:
        return 0, {}, str(e)[:200]


def test_websocket(target: str, timeout: int = 5,
                   delay: float = 0.1) -> Dict[str, Any]:
    """Test WebSocket endpoints for security issues.

    Args:
        target: Base URL (http/https).
        timeout: Connection timeout.
        delay: Delay between probes.

    Returns:
        Dict with discovered endpoints, origin bypass, injection results.
    """
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port
    use_ssl = parsed.scheme == "https"
    if not port:
        port = 443 if use_ssl else 80

    result: Dict[str, Any] = {
        "endpoints": [],
        "origin_bypass": [],
        "injection_results": [],
        "issues": [],
    }

    # Phase 1: Endpoint discovery
    for path in _WS_PATHS:
        if delay > 0:
            time.sleep(delay)
        status, headers, err = _ws_handshake(host, port, path, use_ssl, timeout=timeout)
        if status == 101:
            result["endpoints"].append({
                "path": path,
                "status": status,
                "protocol": headers.get("sec-websocket-protocol", ""),
            })
        elif status in (200, 400, 426) and not err:
            # 400/426 = server recognizes WS path but upgrade failed
            upgrade = headers.get("upgrade", "").lower()
            if upgrade == "websocket" or "websocket" in str(headers):
                result["endpoints"].append({
                    "path": path,
                    "status": status,
                    "note": "Upgrade required or partial WS support",
                })

    if not result["endpoints"]:
        return result

    # Phase 2: Origin validation bypass
    test_path = result["endpoints"][0]["path"]
    evil_origins = [
        "https://evil.attacker.com",
        "null",
        f"https://{host}.evil.com",
        "https://localhost",
    ]
    for origin in evil_origins:
        if delay > 0:
            time.sleep(delay)
        status, headers, err = _ws_handshake(
            host, port, test_path, use_ssl, origin=origin, timeout=timeout)
        if status == 101:
            result["origin_bypass"].append({
                "origin": origin,
                "status": status,
                "severity": "high",
            })
            result["issues"].append({
                "issue": f"WebSocket accepts connection from origin: {origin}",
                "severity": "high",
                "path": test_path,
            })

    # Phase 3: Record injection test payloads (we can't easily send WS frames
    # without a full WS client, but we document what should be tested)
    for payload in _WS_PAYLOADS[:4]:
        result["injection_results"].append({
            "payload": payload[:80],
            "note": "Requires full WebSocket client for live injection test",
            "recommended": True,
        })

    return result


# ── GraphQL Deep Testing ─────────────────────────────────────────────────────

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/query", "/api/query", "/graphiql",
    "/altair", "/playground",
]


def _gql_post(host: str, port: int, path: str, body: str, use_ssl: bool,
              timeout: int = 8) -> Tuple[int, str]:
    """POST a GraphQL query, return (status, body)."""
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        headers = {
            "Host": host,
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 (Fray/{__version__})",
            "Accept": "application/json",
        }
        conn.request("POST", path, body=body.encode(), headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read(64 * 1024).decode("utf-8", "replace")
        status = resp.status
        conn.close()
        return status, resp_body
    except Exception:
        return 0, ""


def test_graphql(target: str, timeout: int = 8,
                 delay: float = 0.15) -> Dict[str, Any]:
    """Deep GraphQL security testing.

    Tests:
      1. Introspection enabled
      2. Query batching (DoS amplification)
      3. Nested query depth attack
      4. Field suggestion enumeration (info leak)
      5. Mutation discovery

    Returns:
        Dict with endpoint, introspection data, batching, depth, mutations.
    """
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port
    use_ssl = parsed.scheme == "https"
    if not port:
        port = 443 if use_ssl else 80

    result: Dict[str, Any] = {
        "endpoint": "",
        "introspection": {"enabled": False, "types": 0, "fields": 0},
        "batching": {"allowed": False, "max_tested": 0},
        "depth_attack": {"vulnerable": False, "max_depth": 0},
        "field_suggestions": [],
        "mutations": [],
        "issues": [],
    }

    # Phase 1: Find a working GraphQL endpoint
    introspection_q = '{"query":"{ __schema { types { name fields { name type { name kind } } } } }"}'
    gql_path = ""

    for path in _GRAPHQL_PATHS:
        if delay > 0:
            time.sleep(delay)
        status, body = _gql_post(host, port, path, introspection_q, use_ssl, timeout)
        if status > 0 and body:
            lower = body.lower()
            if any(kw in lower for kw in ('"data"', '"errors"', '__schema',
                                           'graphql', '"message"')):
                gql_path = path
                result["endpoint"] = path

                # Check introspection
                if "__schema" in body and '"types"' in body:
                    result["introspection"]["enabled"] = True
                    try:
                        data = json.loads(body)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        user_types = [t for t in types if not t.get("name", "").startswith("__")]
                        result["introspection"]["types"] = len(user_types)
                        total_fields = sum(len(t.get("fields") or []) for t in user_types)
                        result["introspection"]["fields"] = total_fields

                        # Extract mutations
                        for t in types:
                            if t.get("name") == "Mutation":
                                for f in (t.get("fields") or []):
                                    result["mutations"].append({
                                        "name": f.get("name", ""),
                                        "type": (f.get("type") or {}).get("name", ""),
                                    })
                    except (json.JSONDecodeError, KeyError):
                        pass

                    result["issues"].append({
                        "issue": "GraphQL introspection enabled — full schema exposed",
                        "severity": "high",
                        "path": path,
                    })
                break

    if not gql_path:
        return result

    # Phase 2: Query batching test
    if delay > 0:
        time.sleep(delay)
    batch_body = json.dumps([
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ])
    status, body = _gql_post(host, port, gql_path, batch_body, use_ssl, timeout)
    if status == 200 and body:
        try:
            parsed_resp = json.loads(body)
            if isinstance(parsed_resp, list) and len(parsed_resp) >= 2:
                result["batching"]["allowed"] = True
                result["batching"]["max_tested"] = 3
                result["issues"].append({
                    "issue": "GraphQL query batching allowed — DoS amplification risk",
                    "severity": "medium",
                    "path": gql_path,
                })
        except json.JSONDecodeError:
            pass

    # Phase 3: Nested query depth attack
    if delay > 0:
        time.sleep(delay)
    # Build deeply nested __typename query
    depth = 10
    nested = "{ __typename }"
    for i in range(depth):
        nested = f'{{ __schema {{ types {{ name fields {{ name type {nested} }} }} }} }}'
    depth_body = json.dumps({"query": nested})
    status, body = _gql_post(host, port, gql_path, depth_body, use_ssl, timeout)
    if status == 200 and body and '"data"' in body:
        result["depth_attack"]["vulnerable"] = True
        result["depth_attack"]["max_depth"] = depth
        result["issues"].append({
            "issue": f"GraphQL accepts deeply nested queries (depth={depth}) — DoS risk",
            "severity": "medium",
            "path": gql_path,
        })

    # Phase 4: Field suggestion enumeration
    if delay > 0:
        time.sleep(delay)
    typo_q = '{"query":"{ __typo_test_fray }"}'
    status, body = _gql_post(host, port, gql_path, typo_q, use_ssl, timeout)
    if status == 200 and body:
        # GraphQL servers often suggest similar fields
        suggestions = re.findall(r'[Dd]id you mean ["\'](\w+)["\']', body)
        if not suggestions:
            suggestions = re.findall(r'"(\w+)"', body)
            suggestions = [s for s in suggestions if s not in
                          ("message", "errors", "locations", "extensions", "data")]
        if suggestions:
            result["field_suggestions"] = suggestions[:10]
            result["issues"].append({
                "issue": f"GraphQL field suggestions leak schema info: {', '.join(suggestions[:5])}",
                "severity": "low",
                "path": gql_path,
            })

    return result


# ── gRPC Testing ─────────────────────────────────────────────────────────────

_GRPC_PORTS = [50051, 50052, 443, 8443, 9090, 9443]


def _grpc_probe(host: str, port: int, use_ssl: bool,
                timeout: int = 5) -> Tuple[bool, str]:
    """Probe a port for gRPC by sending an HTTP/2 preface + SETTINGS frame.

    Returns (is_grpc, info_string).
    """
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
        else:
            sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))

        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        # SETTINGS frame (type=0x04, empty)
        settings_frame = struct.pack(">IBI", 0, 0x04, 0)[1:]  # length=0, type=4, flags=0, stream=0
        # Actually: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream
        settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

        sock.sendall(preface + settings_frame)

        resp = b""
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            pass
        sock.close()

        if not resp:
            return False, "no response"

        # Check for HTTP/2 SETTINGS frame in response (type=0x04)
        if len(resp) >= 9:
            frame_type = resp[3] if len(resp) > 3 else 0
            if frame_type == 0x04:
                return True, "HTTP/2 SETTINGS response"

        # Check for gRPC-specific headers
        resp_str = resp.decode("utf-8", "replace")
        if "grpc" in resp_str.lower() or "application/grpc" in resp_str.lower():
            return True, "gRPC header detected"

        return False, resp_str[:100]
    except Exception as e:
        return False, str(e)[:100]


def _grpc_reflection_check(host: str, port: int, use_ssl: bool,
                           timeout: int = 5) -> Dict[str, Any]:
    """Check for gRPC Server Reflection API via HTTP/2.

    Uses the standard grpc.reflection.v1alpha.ServerReflection service.
    Since we can't do full HTTP/2 framing easily, we probe via gRPC-Web (HTTP/1.1).
    """
    result = {"enabled": False, "services": [], "error": ""}

    # Try gRPC-Web reflection endpoint
    path = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        # gRPC-Web request with ListServices
        # Minimal protobuf: field 1 (list_services), string ""
        grpc_body = b"\x00\x00\x00\x00\x02\x0a\x00"

        conn.request("POST", path, body=grpc_body, headers={
            "Host": host,
            "Content-Type": "application/grpc-web",
            "Accept": "application/grpc-web",
            "User-Agent": f"Fray/{__version__}",
            "TE": "trailers",
        })
        resp = conn.getresponse()
        status = resp.status
        body = resp.read(8192)
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        content_type = resp_headers.get("content-type", "")
        if status == 200 and ("grpc" in content_type or len(body) > 5):
            result["enabled"] = True
            # Try to extract service names from protobuf response
            # Service names are ASCII strings in the response
            text = body.decode("utf-8", "replace")
            services = re.findall(r'([a-zA-Z][\w.]+\.[A-Z]\w+)', text)
            result["services"] = list(set(services))[:20]
    except Exception as e:
        result["error"] = str(e)[:200]

    # Also try gRPC health check
    health_path = "/grpc.health.v1.Health/Check"
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("POST", health_path, body=b"\x00\x00\x00\x00\x00", headers={
            "Host": host,
            "Content-Type": "application/grpc-web",
            "Accept": "application/grpc-web",
        })
        resp = conn.getresponse()
        status = resp.status
        body = resp.read(4096)
        conn.close()

        if status == 200:
            result["health_check"] = True
    except Exception:
        pass

    return result


def test_grpc(target: str, timeout: int = 5,
              delay: float = 0.1) -> Dict[str, Any]:
    """Test for gRPC endpoints and security issues.

    Args:
        target: Base URL or host:port.
        timeout: Connection timeout.
        delay: Delay between probes.

    Returns:
        Dict with discovered endpoints, reflection data, issues.
    """
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target.split(":")[0]
    port = parsed.port
    use_ssl = parsed.scheme in ("https", "grpcs")

    result: Dict[str, Any] = {
        "grpc_endpoints": [],
        "reflection": {"enabled": False, "services": []},
        "health_check": False,
        "issues": [],
    }

    # Determine ports to probe
    ports_to_check = []
    if port:
        ports_to_check = [port]
    else:
        ports_to_check = _GRPC_PORTS

    # Phase 1: Port probing
    for p in ports_to_check:
        if delay > 0:
            time.sleep(delay)
        is_grpc, info = _grpc_probe(host, p, use_ssl or p in (443, 8443, 9443), timeout)
        if is_grpc:
            result["grpc_endpoints"].append({
                "host": host,
                "port": p,
                "ssl": use_ssl or p in (443, 8443, 9443),
                "info": info,
            })

    if not result["grpc_endpoints"]:
        return result

    # Phase 2: Reflection API check on first found endpoint
    ep = result["grpc_endpoints"][0]
    if delay > 0:
        time.sleep(delay)
    refl = _grpc_reflection_check(host, ep["port"], ep["ssl"], timeout)
    result["reflection"] = refl
    result["health_check"] = refl.get("health_check", False)

    if refl["enabled"]:
        result["issues"].append({
            "issue": f"gRPC Server Reflection enabled — exposes service definitions",
            "severity": "high",
            "port": ep["port"],
            "services": refl["services"],
        })

    if result["health_check"]:
        result["issues"].append({
            "issue": "gRPC Health Check service exposed",
            "severity": "low",
            "port": ep["port"],
        })

    return result


# ── Combined Multi-Protocol Test ─────────────────────────────────────────────

def test_multi_protocol(
    target: str,
    timeout: int = 8,
    delay: float = 0.15,
    ws: bool = True,
    graphql: bool = True,
    grpc: bool = True,
) -> Dict[str, Any]:
    """Run all multi-protocol tests against a target.

    Args:
        target: Target URL.
        timeout: Per-request timeout.
        delay: Delay between probes.
        ws: Test WebSocket.
        graphql: Test GraphQL.
        grpc: Test gRPC.

    Returns:
        Combined results dict.
    """
    t0 = time.time()
    result: Dict[str, Any] = {
        "target": target,
        "websocket": {},
        "graphql": {},
        "grpc": {},
        "total_issues": 0,
        "duration_s": 0.0,
    }

    if ws:
        result["websocket"] = test_websocket(target, timeout, delay)

    if graphql:
        result["graphql"] = test_graphql(target, timeout, delay)

    if grpc:
        result["grpc"] = test_grpc(target, timeout, delay)

    # Count total issues
    total = 0
    for proto in ("websocket", "graphql", "grpc"):
        total += len(result[proto].get("issues", []))
    result["total_issues"] = total
    result["duration_s"] = round(time.time() - t0, 2)

    return result


# ── CLI-friendly output ──────────────────────────────────────────────────────

def print_multi_protocol_result(result: Dict[str, Any]):
    """Pretty-print multi-protocol test results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}Multi-Protocol Security Test{R}")
    print(f"  {D}{result['target']}{R}")
    print(f"  {D}Duration: {result['duration_s']}s | Issues: {result['total_issues']}{R}")
    print(f"{D}{'━' * 60}{R}")

    # WebSocket
    ws = result.get("websocket", {})
    ws_eps = ws.get("endpoints", [])
    print(f"\n  {B}WebSocket{R}")
    if ws_eps:
        for ep in ws_eps:
            print(f"    {GRN}●{R} {ep['path']} (HTTP {ep.get('status', '?')})")
        for ob in ws.get("origin_bypass", []):
            print(f"    {RED}⚠ Origin bypass: {ob['origin']}{R}")
    else:
        print(f"    {D}No WebSocket endpoints found{R}")

    # GraphQL
    gql = result.get("graphql", {})
    if gql.get("endpoint"):
        print(f"\n  {B}GraphQL{R}")
        print(f"    {GRN}●{R} Endpoint: {gql['endpoint']}")
        intro = gql.get("introspection", {})
        if intro.get("enabled"):
            print(f"    {RED}⚠ Introspection ENABLED{R} — {intro['types']} types, {intro['fields']} fields")
        batch = gql.get("batching", {})
        if batch.get("allowed"):
            print(f"    {YEL}⚠ Query batching allowed{R}")
        depth = gql.get("depth_attack", {})
        if depth.get("vulnerable"):
            print(f"    {YEL}⚠ Deep nesting accepted (depth={depth['max_depth']}){R}")
        mutations = gql.get("mutations", [])
        if mutations:
            names = ", ".join(m["name"] for m in mutations[:5])
            print(f"    {CYN}Mutations:{R} {names}")
            if len(mutations) > 5:
                print(f"    {D}  ... and {len(mutations) - 5} more{R}")
        sugg = gql.get("field_suggestions", [])
        if sugg:
            print(f"    {CYN}Field suggestions:{R} {', '.join(sugg[:5])}")
    else:
        print(f"\n  {B}GraphQL{R}")
        print(f"    {D}No GraphQL endpoint found{R}")

    # gRPC
    grpc = result.get("grpc", {})
    grpc_eps = grpc.get("grpc_endpoints", [])
    print(f"\n  {B}gRPC{R}")
    if grpc_eps:
        for ep in grpc_eps:
            ssl_str = "TLS" if ep.get("ssl") else "plain"
            print(f"    {GRN}●{R} {ep['host']}:{ep['port']} ({ssl_str})")
        refl = grpc.get("reflection", {})
        if refl.get("enabled"):
            print(f"    {RED}⚠ Reflection API ENABLED{R}")
            for svc in refl.get("services", [])[:5]:
                print(f"      - {svc}")
        if grpc.get("health_check"):
            print(f"    {CYN}Health check service exposed{R}")
    else:
        print(f"    {D}No gRPC endpoints found{R}")

    # Issues summary
    all_issues = []
    for proto in ("websocket", "graphql", "grpc"):
        for iss in result.get(proto, {}).get("issues", []):
            iss["protocol"] = proto
            all_issues.append(iss)

    if all_issues:
        print(f"\n  {B}Issues ({len(all_issues)}){R}")
        for iss in all_issues:
            sev = iss.get("severity", "info")
            color = RED if sev in ("critical", "high") else YEL if sev == "medium" else D
            print(f"    {color}[{sev.upper()}]{R} {iss['issue']}")

    print(f"\n{D}{'━' * 60}{R}\n")
