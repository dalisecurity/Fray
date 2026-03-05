#!/usr/bin/env python3
"""
Fray Graph — Attack Surface Visualization.

Usage:
    fray graph example.com
    fray graph example.com --deep
    fray graph example.com --json
    fray graph example.com -o graph.json

Generates a visual tree of the target's attack surface:
  - Subdomains (via crt.sh certificate transparency)
  - DNS records (A, AAAA, CNAME, MX, NS)
  - Technologies detected (server, framework, CMS)
  - Open admin panels
  - API endpoints (Swagger, OpenAPI, versioned roots)
  - GraphQL endpoints
  - Exposed files (.env, .git, etc.)
  - Historical URLs (Wayback Machine)
  - Injection points (parameters)
  - WAF / CDN detected
"""

import json
import socket
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


@dataclass
class GraphNode:
    """A node in the attack surface graph."""
    label: str
    type: str  # domain, subdomain, ip, tech, endpoint, file, param, waf, cdn, dns
    risk: str = ""  # high, medium, low, info
    children: List["GraphNode"] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"label": self.label, "type": self.type}
        if self.risk:
            d["risk"] = self.risk
        if self.meta:
            d["meta"] = self.meta
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


def build_graph(target: str, recon: Dict[str, Any],
                js_endpoints: Optional[Dict] = None,
                historical: Optional[Dict] = None) -> GraphNode:
    """Build an attack surface graph from recon data.

    Args:
        target: The target URL or domain
        recon: Full recon result dict from run_recon()
        js_endpoints: Optional JS endpoint discovery result
        historical: Optional historical URL discovery result
    """
    host = recon.get("host", target)
    root = GraphNode(label=host, type="domain", meta={"url": target})

    # ── Subdomains ──
    subs = recon.get("subdomains", {})
    sub_list = subs.get("subdomains", [])
    if sub_list:
        sub_node = GraphNode(label=f"Subdomains ({len(sub_list)})", type="group")
        for s in sub_list[:50]:
            risk = "medium" if s.startswith("admin") or s.startswith("staging") or s.startswith("dev") or s.startswith("test") or s.startswith("internal") else "info"
            sub_node.children.append(GraphNode(label=s, type="subdomain", risk=risk))
        root.children.append(sub_node)

    # ── DNS ──
    dns = recon.get("dns", {})
    if any(dns.get(k) for k in ["a", "aaaa", "cname", "mx", "ns"]):
        dns_node = GraphNode(label="DNS Records", type="group")
        for rtype in ["a", "aaaa", "cname", "mx", "ns"]:
            records = dns.get(rtype, [])
            for r in records:
                dns_node.children.append(GraphNode(
                    label=f"{rtype.upper()}: {r}", type="dns",
                    risk="info",
                ))
        if dns.get("cdn_detected"):
            dns_node.children.append(GraphNode(
                label=f"CDN: {dns['cdn_detected']}", type="cdn", risk="info",
            ))
        root.children.append(dns_node)

    # ── WAF ──
    fp = recon.get("fingerprint", {})
    waf = fp.get("waf")
    if waf:
        root.children.append(GraphNode(label=f"WAF: {waf}", type="waf", risk="info"))

    # ── Technologies ──
    techs = fp.get("technologies", {})
    if techs:
        tech_node = GraphNode(label="Technologies", type="group")
        for tech, conf in sorted(techs.items(), key=lambda x: -x[1]):
            tech_node.children.append(GraphNode(
                label=f"{tech} ({conf}%)", type="tech", risk="info",
                meta={"confidence": conf},
            ))
        root.children.append(tech_node)

    # ── TLS ──
    tls = recon.get("tls", {})
    if tls and tls.get("version"):
        tls_risk = "info"
        if tls.get("expires_days") is not None and tls["expires_days"] < 30:
            tls_risk = "medium"
        if tls.get("version") in ("TLSv1.0", "TLSv1.1"):
            tls_risk = "high"
        tls_node = GraphNode(
            label=f"TLS: {tls['version']}", type="tls", risk=tls_risk,
            meta={k: v for k, v in tls.items() if k in ("issuer", "expires_days", "subject")},
        )
        root.children.append(tls_node)

    # ── Admin Panels ──
    admin = recon.get("admin_panels", {})
    panels = admin.get("panels_found", [])
    if panels:
        admin_node = GraphNode(label=f"Admin Panels ({len(panels)})", type="group")
        for p in panels:
            is_open = p.get("protected") is False
            risk = "high" if is_open else "medium"
            label = f"{p['path']} [{p['status']}]"
            if is_open:
                label += " OPEN"
            admin_node.children.append(GraphNode(
                label=label, type="endpoint", risk=risk,
                meta={"category": p.get("category", "")},
            ))
        root.children.append(admin_node)

    # ── API Endpoints ──
    api = recon.get("api_discovery", {})
    api_eps = api.get("endpoints_found", [])
    if api_eps:
        api_node = GraphNode(label=f"API Endpoints ({len(api_eps)})", type="group")
        for ep in api_eps:
            if isinstance(ep, dict):
                label = f"{ep.get('path', ep.get('url', '?'))} [{ep.get('status', '?')}]"
                api_node.children.append(GraphNode(label=label, type="endpoint", risk="medium"))
            else:
                api_node.children.append(GraphNode(label=str(ep), type="endpoint", risk="medium"))
        root.children.append(api_node)

    # ── GraphQL ──
    gql = recon.get("graphql", {})
    if gql.get("introspection_enabled"):
        gql_node = GraphNode(
            label=f"GraphQL: {gql.get('endpoint', '/graphql')} (introspection OPEN)",
            type="endpoint", risk="high",
            meta={"types": gql.get("type_count", 0), "queries": gql.get("query_count", 0)},
        )
        root.children.append(gql_node)

    # ── Exposed Files ──
    exposed = recon.get("exposed_files", {})
    found = exposed.get("found", [])
    if found:
        file_node = GraphNode(label=f"Exposed Files ({len(found)})", type="group")
        for f in found:
            risk = "high" if any(s in str(f) for s in [".env", ".git", "wp-config", "config.php"]) else "medium"
            label = f if isinstance(f, str) else f.get("path", str(f))
            file_node.children.append(GraphNode(label=label, type="file", risk=risk))
        root.children.append(file_node)

    # ── CORS Issues ──
    cors = recon.get("cors", {})
    if cors.get("misconfigured"):
        issues = cors.get("issues", [])
        cors_node = GraphNode(
            label=f"CORS Misconfigured ({len(issues)} issue(s))",
            type="vuln", risk="high",
        )
        for issue in issues:
            cors_node.children.append(GraphNode(label=str(issue), type="detail", risk="high"))
        root.children.append(cors_node)

    # ── Host Header Injection ──
    hhi = recon.get("host_header_injection", {})
    if hhi.get("vulnerable"):
        hhi_node = GraphNode(
            label="Host Header Injectable", type="vuln", risk="high",
            meta={"headers": hhi.get("vulnerable_headers", [])},
        )
        root.children.append(hhi_node)

    # ── Parameters (injection points) ──
    params = recon.get("params", {})
    discovered_params = params.get("discovered", [])
    if discovered_params:
        param_node = GraphNode(label=f"Parameters ({len(discovered_params)})", type="group")
        for p in discovered_params[:20]:
            if isinstance(p, dict):
                label = f"?{p.get('name', '?')}= [{p.get('method', 'GET')}]"
                param_node.children.append(GraphNode(label=label, type="param", risk="info"))
            else:
                param_node.children.append(GraphNode(label=f"?{p}=", type="param", risk="info"))
        if len(discovered_params) > 20:
            param_node.children.append(GraphNode(
                label=f"... +{len(discovered_params) - 20} more", type="detail", risk="info"))
        root.children.append(param_node)

    # ── JS Endpoints ──
    if js_endpoints:
        js_eps = js_endpoints.get("endpoints", [])
        if js_eps:
            js_node = GraphNode(label=f"JS Endpoints ({len(js_eps)})", type="group")
            for ep in js_eps[:15]:
                if isinstance(ep, dict):
                    label = ep.get("url", ep.get("path", str(ep)))
                else:
                    label = str(ep)
                js_node.children.append(GraphNode(label=label, type="endpoint", risk="info"))
            if len(js_eps) > 15:
                js_node.children.append(GraphNode(
                    label=f"... +{len(js_eps) - 15} more", type="detail", risk="info"))
            root.children.append(js_node)

        # JS-discovered hostnames
        js_hosts = js_endpoints.get("hostnames", [])
        if js_hosts:
            host_node = GraphNode(label=f"JS Hostnames ({len(js_hosts)})", type="group")
            for h in sorted(js_hosts, key=lambda x: (0 if x.get("risk") == "high" else 1 if x.get("risk") == "medium" else 2))[:15]:
                risk = h.get("risk", "info")
                rel = " (related)" if h.get("related") else ""
                host_node.children.append(GraphNode(
                    label=f"{h['hostname']}{rel}", type="subdomain", risk=risk))
            root.children.append(host_node)

        # JS-discovered cloud buckets
        js_buckets = js_endpoints.get("cloud_buckets", [])
        if js_buckets:
            bucket_node = GraphNode(label=f"Cloud Buckets ({len(js_buckets)})", type="group")
            for b in js_buckets:
                bucket_node.children.append(GraphNode(
                    label=f"{b['provider']}: {b['bucket']}", type="file", risk="high"))
            root.children.append(bucket_node)

        # JS-discovered secrets
        js_secrets = js_endpoints.get("secrets", [])
        if js_secrets:
            sec_node = GraphNode(label=f"Exposed Secrets ({len(js_secrets)})", type="group")
            for s in js_secrets:
                sec_node.children.append(GraphNode(
                    label=f"{s['type']}: {s['value_masked']}", type="vuln", risk="high",
                    meta={"length": s["length"]},
                ))
            root.children.append(sec_node)

    # ── Historical URLs ──
    if historical:
        wayback = historical.get("wayback_urls", [])
        if wayback:
            hist_node = GraphNode(label=f"Historical URLs ({len(wayback)})", type="group")
            for u in wayback[:10]:
                hist_node.children.append(GraphNode(label=str(u), type="endpoint", risk="info"))
            if len(wayback) > 10:
                hist_node.children.append(GraphNode(
                    label=f"... +{len(wayback) - 10} more", type="detail", risk="info"))
            root.children.append(hist_node)

    # ── Recommended Attack Categories ──
    recs = recon.get("recommended_categories", [])
    if recs:
        rec_node = GraphNode(label="Recommended Attacks", type="group")
        for r in recs:
            rec_node.children.append(GraphNode(label=r, type="attack_cat", risk="info"))
        root.children.append(rec_node)

    return root


def print_graph(root: GraphNode) -> None:
    """Print the attack surface graph as a rich tree."""
    from rich.tree import Tree
    from rich.text import Text
    from fray.output import console, print_header

    risk_style = {
        "high": "bold red",
        "medium": "bold yellow",
        "low": "cyan",
        "info": "dim",
    }

    type_icon = {
        "domain": "🌐",
        "subdomain": "🔗",
        "dns": "📡",
        "cdn": "☁️",
        "waf": "🛡️",
        "tech": "⚙️",
        "tls": "🔒",
        "endpoint": "📍",
        "file": "📄",
        "param": "🎯",
        "vuln": "⚠️",
        "attack_cat": "⚔️",
        "group": "📂",
        "detail": "  ",
    }

    def _build_tree(node: GraphNode, tree: Tree) -> None:
        for child in node.children:
            icon = type_icon.get(child.type, "•")
            style = risk_style.get(child.risk, "")
            label = Text(f"{icon} {child.label}", style=style)

            if child.children:
                branch = tree.add(label)
                _build_tree(child, branch)
            else:
                tree.add(label)

    print_header("Fray Graph — Attack Surface", target=root.label)

    root_icon = type_icon.get(root.type, "🌐")
    tree = Tree(Text(f"{root_icon} {root.label}", style="bold bright_cyan"))
    _build_tree(root, tree)

    console.print(tree)
    console.print()

    # Summary line
    total_nodes = _count_nodes(root)
    high_risk = _count_risk(root, "high")
    medium_risk = _count_risk(root, "medium")

    summary_parts = [f"  [bold]{total_nodes}[/bold] nodes"]
    if high_risk:
        summary_parts.append(f"[bold red]{high_risk} high-risk[/bold red]")
    if medium_risk:
        summary_parts.append(f"[bold yellow]{medium_risk} medium-risk[/bold yellow]")

    console.print(" · ".join(summary_parts))
    console.print()

    if high_risk:
        console.print("  [bold red]⚠ High-risk items found.[/bold red] Run:")
        console.print(f"    fray scan {root.meta.get('url', root.label)} --ai")
    console.print()


def _count_nodes(node: GraphNode) -> int:
    return 1 + sum(_count_nodes(c) for c in node.children)


def _count_risk(node: GraphNode, risk: str) -> int:
    count = 1 if node.risk == risk else 0
    return count + sum(_count_risk(c, risk) for c in node.children)
