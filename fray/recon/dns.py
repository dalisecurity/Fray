"""DNS reconnaissance — DNS lookups, subdomain enumeration, origin IP discovery."""

import http.client
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

from fray import __version__


# ── Active subdomain brute-force wordlist ──────────────────────────────
_SUBDOMAIN_WORDLIST = [
    # Infrastructure / DevOps
    "api", "api2", "api3", "dev", "dev2", "staging", "stage", "stg",
    "admin", "administrator", "internal", "intranet", "corp",
    "test", "testing", "qa", "uat", "sandbox", "demo", "beta", "alpha",
    "preview", "canary", "preprod", "pre-prod", "production", "prod",
    # Web / App
    "app", "app2", "web", "www2", "www3", "portal", "dashboard",
    "login", "auth", "sso", "accounts", "account", "signup",
    "cms", "blog", "shop", "store", "pay", "payment", "checkout",
    # Backend / Services
    "backend", "service", "services", "gateway", "proxy", "edge",
    "graphql", "grpc", "ws", "websocket", "socket", "realtime",
    "queue", "worker", "cron", "scheduler", "jobs",
    # Data
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "elasticsearch", "kibana", "grafana", "prometheus", "influx",
    # Storage / CDN
    "cdn", "static", "assets", "media", "images", "img", "files",
    "upload", "uploads", "storage", "s3", "backup", "backups",
    # CI/CD / Monitoring
    "ci", "cd", "jenkins", "gitlab", "github", "drone", "argo",
    "monitor", "monitoring", "status", "health", "healthcheck",
    "logs", "logging", "sentry", "apm", "trace", "tracing",
    # Mail / Communication
    "mail", "email", "smtp", "imap", "pop", "mx", "exchange",
    "chat", "slack", "webhook", "webhooks", "notify", "notifications",
    # Network / Security
    "vpn", "remote", "bastion", "jump", "ssh", "ftp", "sftp",
    "ns1", "ns2", "dns", "dns1", "dns2",
    # Cloud / Infra
    "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
    "registry", "vault", "consul", "nomad",
    # Misc
    "old", "new", "legacy", "v1", "v2", "v3", "next", "m", "mobile",
    "docs", "doc", "wiki", "help", "support", "jira", "confluence",
]

# Extended wordlist for --deep mode (~300 words)
_SUBDOMAIN_WORDLIST_DEEP = _SUBDOMAIN_WORDLIST + [
    # Additional infrastructure
    "api-v1", "api-v2", "api-internal", "api-staging", "api-dev", "api-test",
    "dev-api", "staging-api", "internal-api", "private-api",
    "origin", "origin-www", "direct", "real", "backend-api",
    # Regional / geo
    "us", "eu", "ap", "us-east", "us-west", "eu-west", "ap-southeast",
    "us1", "us2", "eu1", "eu2", "jp", "sg", "au", "uk", "de", "fr",
    # Environment variants
    "dev1", "dev2", "dev3", "stg1", "stg2", "staging2", "staging3",
    "test1", "test2", "test3", "qa1", "qa2", "uat2", "perf", "load",
    "integration", "release", "rc", "nightly", "experimental",
    # Services / microservices
    "auth-api", "user-api", "payment-api", "search-api", "notification-api",
    "identity", "iam", "oauth", "sso-dev", "sso-staging",
    "cache", "memcached", "session", "token",
    "event", "events", "stream", "kafka", "rabbitmq", "nats",
    "cron-api", "task", "batch", "pipeline",
    # DevOps / tooling
    "argocd", "rancher", "portainer", "traefik", "nginx", "haproxy",
    "sonar", "sonarqube", "nexus", "artifactory", "harbor",
    "terraform", "ansible", "puppet", "chef",
    "pagerduty", "opsgenie", "datadog", "newrelic", "splunk",
    # Database / analytics
    "clickhouse", "cassandra", "couchdb", "neo4j", "timescale",
    "metabase", "superset", "tableau", "looker", "redash",
    "warehouse", "dw", "etl", "airflow", "dagster",
    # Mail / comms extended
    "mail2", "smtp2", "webmail", "owa", "autodiscover", "mta",
    "postfix", "roundcube", "horde", "zimbra",
    # Security / compliance
    "waf", "firewall", "ids", "siem", "scan", "scanner",
    "pentest", "security", "compliance", "audit",
    # Misc infrastructure
    "proxy2", "lb", "lb1", "lb2", "loadbalancer", "gateway2",
    "edge2", "cdn2", "static2", "assets2", "media2",
    "git", "svn", "hg", "repo", "code", "review",
    "crm", "erp", "hr", "finance", "billing",
    "embed", "widget", "sdk", "client", "partner", "vendor",
    "sandbox2", "playground", "lab", "research",
]

# Known CDN/WAF IP ranges (CIDR prefixes for quick matching)
_CDN_IP_PREFIXES = {
    "cloudflare": [
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "172.70.", "172.71.",
        "162.158.", "162.159.",
        "141.101.", "108.162.", "190.93.", "188.114.",
        "197.234.", "198.41.",
        "173.245.",
        "103.21.", "103.22.", "103.31.",
        "131.0.72.",
        "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:",
    ],
    "cloudfront": ["13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.",
                   "13.227.", "13.249.", "18.64.", "18.154.", "18.160.",
                   "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.",
                   "99.84.", "99.86.", "143.204.", "205.251."],
    "akamai": ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
               "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.",
               "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.",
               "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.",
               "23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.",
               "23.62.", "23.63.", "23.64.", "23.65.", "23.66.", "23.67.",
               "2.16.", "2.17.", "2.18.", "2.19.", "2.20.", "2.21.",
               "72.246.", "72.247.", "96.16.", "96.17.", "184.24.", "184.25.",
               "184.26.", "184.27.", "184.28.", "184.29.", "184.30.", "184.31.",
               "184.50.", "184.51."],
    "fastly": ["151.101.", "199.232."],
    "incapsula": ["199.83.", "198.143.", "149.126.", "185.11."],
    "sucuri": ["192.124.", "185.93."],
    "azure_cdn": ["13.107.", "150.171."],
    "google_cdn": ["34.120.", "34.149.", "35.186.", "35.190.", "35.201.", "35.227."],
}


def _ip_is_cdn(ip: str) -> Optional[str]:
    """Check if an IP belongs to a known CDN/WAF provider. Returns provider name or None."""
    for provider, prefixes in _CDN_IP_PREFIXES.items():
        for prefix in prefixes:
            if ip.startswith(prefix):
                return provider
    return None


def _resolve_hostname(hostname: str, timeout: float = 3.0) -> List[str]:
    """Resolve a hostname to IP addresses via socket.getaddrinfo (A + AAAA)."""
    ips = []
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return ips


def check_dns(host: str, deep: bool = False) -> Dict[str, Any]:
    """Lookup DNS records for the host.

    Args:
        deep: If True, also query SOA, CAA, SRV, and PTR records.
    """
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

    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    if deep:
        record_types += ["SOA", "CAA"]

    for rtype in record_types:
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

    # Deep mode: PTR lookups for A records (reveals real hostnames behind IPs)
    if deep:
        ptrs = {}
        for ip in result.get("a", [])[:5]:
            try:
                out = subprocess.run(
                    ["dig", "+short", "-x", ip],
                    capture_output=True, text=True, timeout=5
                )
                ptr = out.stdout.strip().rstrip(".")
                if ptr:
                    ptrs[ip] = ptr
            except Exception:
                pass
        if ptrs:
            result["ptr"] = ptrs

        # SRV records for common services
        srv_results = []
        srv_prefixes = [
            "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp",
            "_http._tcp", "_https._tcp", "_ldap._tcp", "_kerberos._tcp",
            "_autodiscover._tcp", "_imaps._tcp", "_submission._tcp",
        ]
        for prefix in srv_prefixes:
            try:
                out = subprocess.run(
                    ["dig", "+short", "SRV", f"{prefix}.{host}"],
                    capture_output=True, text=True, timeout=3
                )
                lines = [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
                for line in lines:
                    srv_results.append({"service": prefix, "record": line.rstrip(".")})
            except Exception:
                pass
        if srv_results:
            result["srv"] = srv_results

    return result


def check_subdomains_crt(host: str, timeout: int = 10) -> Dict[str, Any]:
    """Enumerate subdomains via multiple passive OSINT sources.

    Sources (all free, no API key required):
      1. crt.sh — Certificate Transparency logs
      2. HackerTarget — hostsearch API
      3. AlienVault OTX — passive DNS
      4. URLScan.io — indexed scan results
      5. RapidDNS — subdomain database

    Returns same structure as before for backwards compatibility.
    """
    import concurrent.futures
    import json as _json
    import re as _re

    search_domain = host.lstrip("www.") if host.startswith("www.") else host
    all_subs: set = set()
    sources: Dict[str, int] = {}
    errors: list = []

    def _valid_sub(name: str) -> bool:
        """Check if a string is a valid subdomain of search_domain."""
        name = name.strip().lower()
        if not name or "*" in name or " " in name:
            return False
        if not name.endswith(search_domain):
            return False
        # Must be a proper subdomain (not the domain itself)
        if name == search_domain:
            return False
        # Basic sanity: no weird chars
        if not _re.match(r'^[a-z0-9._-]+$', name):
            return False
        return True

    def _crt_sh() -> set:
        """Certificate Transparency logs via crt.sh."""
        subs = set()
        try:
            from fray.recon.http import _follow_redirect
            status, body = _follow_redirect(
                "crt.sh", f"/?q=%25.{search_domain}&output=json",
                timeout=timeout
            )
            if status == 200 and body:
                entries = _json.loads(body.decode("utf-8", errors="replace"))
                for entry in entries:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if _valid_sub(line):
                            subs.add(line)
        except Exception as e:
            errors.append(f"crt.sh: {e}")
        return subs

    def _hackertarget() -> set:
        """HackerTarget hostsearch API (free, no key)."""
        subs = set()
        try:
            conn = http.client.HTTPSConnection("api.hackertarget.com", timeout=timeout)
            conn.request("GET", f"/hostsearch/?q={search_domain}",
                         headers={"User-Agent": f"Fray/{__version__}"})
            resp = conn.getresponse()
            if resp.status == 200:
                body = resp.read().decode("utf-8", errors="replace")
                if "error" not in body.lower() and "api count" not in body.lower():
                    for line in body.strip().splitlines():
                        parts = line.split(",")
                        if parts:
                            name = parts[0].strip().lower()
                            if _valid_sub(name):
                                subs.add(name)
            conn.close()
        except Exception as e:
            errors.append(f"hackertarget: {e}")
        return subs

    def _alienvault_otx() -> set:
        """AlienVault OTX passive DNS (free, no key)."""
        subs = set()
        try:
            conn = http.client.HTTPSConnection("otx.alienvault.com", timeout=timeout)
            conn.request("GET",
                         f"/api/v1/indicators/domain/{search_domain}/passive_dns",
                         headers={"User-Agent": f"Fray/{__version__}"})
            resp = conn.getresponse()
            if resp.status == 200:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
                for record in data.get("passive_dns", []):
                    name = record.get("hostname", "").strip().lower()
                    if _valid_sub(name):
                        subs.add(name)
            conn.close()
        except Exception as e:
            errors.append(f"alienvault: {e}")
        return subs

    def _urlscan() -> set:
        """URLScan.io indexed results (free, no key)."""
        subs = set()
        try:
            conn = http.client.HTTPSConnection("urlscan.io", timeout=timeout)
            conn.request("GET",
                         f"/api/v1/search/?q=domain:{search_domain}&size=1000",
                         headers={"User-Agent": f"Fray/{__version__}"})
            resp = conn.getresponse()
            if resp.status == 200:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
                for result_item in data.get("results", []):
                    page = result_item.get("page", {})
                    domain_val = page.get("domain", "").strip().lower()
                    if _valid_sub(domain_val):
                        subs.add(domain_val)
            conn.close()
        except Exception as e:
            errors.append(f"urlscan: {e}")
        return subs

    def _rapiddns() -> set:
        """RapidDNS subdomain database (free, no key)."""
        subs = set()
        try:
            conn = http.client.HTTPSConnection("rapiddns.io", timeout=timeout)
            conn.request("GET", f"/subdomain/{search_domain}?full=1#result",
                         headers={"User-Agent": f"Fray/{__version__}",
                                  "Accept": "text/html"})
            resp = conn.getresponse()
            if resp.status == 200:
                body = resp.read().decode("utf-8", errors="replace")
                # Parse subdomains from HTML table
                for match in _re.finditer(
                    r'<td>([a-z0-9._-]+\.' + _re.escape(search_domain) + r')</td>',
                    body, _re.I
                ):
                    name = match.group(1).strip().lower()
                    if _valid_sub(name):
                        subs.add(name)
            conn.close()
        except Exception as e:
            errors.append(f"rapiddns: {e}")
        return subs

    # Run all sources concurrently
    source_fns = {
        "crt.sh": _crt_sh,
        "hackertarget": _hackertarget,
        "alienvault": _alienvault_otx,
        "urlscan": _urlscan,
        "rapiddns": _rapiddns,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(fn): name for name, fn in source_fns.items()}
        for future in concurrent.futures.as_completed(futures):
            src_name = futures[future]
            try:
                subs = future.result()
                if subs:
                    sources[src_name] = len(subs)
                    all_subs.update(subs)
            except Exception:
                pass

    result: Dict[str, Any] = {
        "subdomains": sorted(all_subs)[:500],
        "count": len(all_subs),
        "sources": sources,
        "error": "; ".join(errors) if errors else None,
    }
    return result


def check_subdomains_bruteforce(host: str, timeout: float = 3.0,
                                 parent_ips: Optional[List[str]] = None,
                                 parent_cdn: Optional[str] = None,
                                 wordlist: Optional[List[str]] = None,
                                 ) -> Dict[str, Any]:
    """Active DNS brute-force subdomain enumeration with WAF-bypass detection.

    Resolves each candidate subdomain and checks whether it routes through
    the same CDN/WAF as the parent domain — subdomains that resolve to
    non-CDN IPs likely bypass the WAF entirely.

    Args:
        host: Base domain (e.g. example.com)
        timeout: DNS resolution timeout per query
        parent_ips: IP addresses of the parent domain (for comparison)
        parent_cdn: CDN provider of the parent domain (e.g. 'cloudflare')
        wordlist: Custom wordlist (defaults to built-in 130+ entries)
    """
    import concurrent.futures

    words = wordlist or _SUBDOMAIN_WORDLIST
    # Strip www. for base domain
    base_domain = host.lstrip("www.") if host.startswith("www.") else host

    # Resolve parent if not provided
    if parent_ips is None:
        parent_ips = _resolve_hostname(base_domain)
    if parent_cdn is None:
        for ip in parent_ips:
            parent_cdn = _ip_is_cdn(ip)
            if parent_cdn:
                break

    result: Dict[str, Any] = {
        "discovered": [],
        "waf_bypass": [],
        "count": 0,
        "waf_bypass_count": 0,
        "wordlist_size": len(words),
        "parent_cdn": parent_cdn,
        "parent_ips": parent_ips,
    }

    def _probe(word):
        fqdn = f"{word}.{base_domain}"
        ips = _resolve_hostname(fqdn, timeout=timeout)
        if not ips:
            return None
        # Determine CDN for this subdomain
        sub_cdn = None
        for ip in ips:
            sub_cdn = _ip_is_cdn(ip)
            if sub_cdn:
                break

        bypasses_waf = False
        bypass_reason = None
        if parent_cdn and not sub_cdn:
            # Parent is behind CDN/WAF but this subdomain is NOT → direct IP bypass
            bypasses_waf = True
            bypass_reason = f"resolves to non-{parent_cdn} IP (direct origin)"
        elif parent_cdn and sub_cdn and sub_cdn != parent_cdn:
            # Different CDN — might have weaker rules
            bypasses_waf = True
            bypass_reason = f"different CDN ({sub_cdn} vs parent {parent_cdn})"

        return {
            "subdomain": fqdn,
            "ips": ips,
            "cdn": sub_cdn,
            "bypasses_waf": bypasses_waf,
            "bypass_reason": bypass_reason,
        }

    # Parallel DNS resolution (cap at 20 threads to avoid DNS flood)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe, w): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
                if entry:
                    result["discovered"].append(entry)
                    if entry["bypasses_waf"]:
                        result["waf_bypass"].append(entry)
            except Exception:
                pass

    # Sort by name for consistent output
    result["discovered"].sort(key=lambda e: e["subdomain"])
    result["waf_bypass"].sort(key=lambda e: e["subdomain"])
    result["count"] = len(result["discovered"])
    result["waf_bypass_count"] = len(result["waf_bypass"])

    return result


def _parse_spf_for_origins(spf_record: str, domain: str,
                           add_fn, timeout: float,
                           depth: int = 0, max_depth: int = 3):
    """Recursively parse SPF record for origin IPs."""
    import subprocess
    import re as _re

    if depth > max_depth:
        return

    # ip4: mechanisms → direct IPs
    for match in _re.finditer(r'ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', spf_record, _re.I):
        ip = match.group(1).split("/")[0]  # Strip CIDR
        add_fn(ip, "spf_ip4", "")

    # ip6: mechanisms
    for match in _re.finditer(r'ip6:([0-9a-fA-F:]+(?:/\d+)?)', spf_record, _re.I):
        ip = match.group(1).split("/")[0]
        add_fn(ip, "spf_ip6", "")

    # a: mechanisms → resolve hostnames
    for match in _re.finditer(r'\ba:(\S+)', spf_record, _re.I):
        hostname = match.group(1).rstrip(".")
        for ip in _resolve_hostname(hostname, timeout=timeout):
            add_fn(ip, "spf_a", hostname)

    # a mechanism (bare) → resolve domain itself
    if " a " in f" {spf_record} " or spf_record.strip().endswith(" a"):
        for ip in _resolve_hostname(domain, timeout=timeout):
            add_fn(ip, "spf_a", domain)

    # include: → recurse into referenced domain's SPF
    for match in _re.finditer(r'include:(\S+)', spf_record, _re.I):
        include_domain = match.group(1).rstrip(".")
        try:
            out = subprocess.run(
                ["dig", "+short", "TXT", include_domain],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.strip().splitlines():
                line = line.strip().strip('"')
                if "v=spf1" in line.lower():
                    _parse_spf_for_origins(line, include_domain, add_fn,
                                           timeout, depth + 1, max_depth)
        except Exception:
            pass

    # mx mechanism → resolve domain's MX
    if " mx " in f" {spf_record} " or " mx:" in spf_record.lower():
        try:
            out = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.strip().splitlines():
                parts = line.strip().split()
                mx_host = parts[-1].rstrip(".")
                for ip in _resolve_hostname(mx_host, timeout=timeout):
                    add_fn(ip, "spf_mx", mx_host)
        except Exception:
            pass


def _extract_cert_sans(host: str, port: int = 443,
                       timeout: float = 5.0) -> List[str]:
    """Extract Subject Alternative Names from TLS certificate.

    getpeercert() only returns SANs when verify_mode != CERT_NONE,
    so we use a verified connection first, falling back to unverified.
    """
    sans = []
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
            decoded = ssock.getpeercert()
            ssock.close()

            if decoded:
                for entry_type, entry_value in decoded.get("subjectAltName", ()):
                    if entry_type == "DNS" and entry_value not in sans:
                        sans.append(entry_value)
            if sans:
                break
        except Exception:
            continue

    return sans


def _securitytrails_history(domain: str, api_key: str,
                            timeout: float = 10.0) -> List[str]:
    """Fetch historical A records from SecurityTrails API."""
    ips = []
    try:
        conn = http.client.HTTPSConnection("api.securitytrails.com", timeout=timeout)
        conn.request("GET", f"/v1/history/{domain}/dns/a",
                     headers={
                         "APIKEY": api_key,
                         "Accept": "application/json",
                     })
        resp = conn.getresponse()
        if resp.status == 200:
            import json as _json
            data = _json.loads(resp.read().decode())
            for record in data.get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip", "")
                    if ip and ip not in ips:
                        ips.append(ip)
        conn.close()
    except Exception:
        pass
    return ips


def _verify_origin_ips(candidate_ips: List[str], host: str,
                       timeout: float = 5.0) -> List[Dict[str, Any]]:
    """Verify origin IP candidates by sending HTTP request with Host header.

    If the server responds with a valid page (not default/error), the origin
    is confirmed as accessible directly — bypassing the WAF.
    """
    import concurrent.futures
    import re as _re

    verified = []

    def _probe_ip(ip: str):
        """Send GET / to the IP with Host: header, check response."""
        for use_ssl in (True, False):
            try:
                port = 443 if use_ssl else 80
                if use_ssl:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(
                        ip, port, context=ctx, timeout=timeout)
                else:
                    conn = http.client.HTTPConnection(ip, port, timeout=timeout)

                conn.request("GET", "/", headers={
                    "Host": host,
                    "User-Agent": f"Fray/{__version__}",
                    "Connection": "close",
                })
                resp = conn.getresponse()
                status = resp.status
                body = resp.read(4096).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()

                # Check if this looks like a real response (not default page)
                server = headers.get("server", "")
                title_match = _re.search(r"<title[^>]*>([^<]+)</title>", body, _re.I)
                title = title_match.group(1).strip() if title_match else ""

                # Signals that this is the real origin:
                # - 200 response with non-empty body
                # - Server header present and not a CDN edge
                # - Title matches something reasonable (not "IIS default" etc.)
                is_valid = (
                    status in (200, 301, 302, 403) and
                    len(body) > 100 and
                    "welcome to nginx" not in body.lower() and
                    "iis windows server" not in body.lower() and
                    "test page" not in body.lower()
                )

                if is_valid:
                    return {
                        "ip": ip,
                        "port": port,
                        "ssl": use_ssl,
                        "status_code": status,
                        "server": server,
                        "title": title,
                        "body_length": len(body),
                        "confirmed": True,
                    }
            except Exception:
                continue
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe_ip, ip): ip for ip in candidate_ips[:20]}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
                if entry:
                    verified.append(entry)
            except Exception:
                pass

    return verified


def discover_origin_ip(host: str, timeout: float = 5.0,
                       dns_data: Optional[Dict[str, Any]] = None,
                       tls_data: Optional[Dict[str, Any]] = None,
                       parent_cdn: Optional[str] = None,
                       securitytrails_key: Optional[str] = None,
                       ) -> Dict[str, Any]:
    """Discover the origin IP behind a CDN/WAF.

    If the origin is exposed, all WAF testing becomes moot — the attacker
    can hit the server directly and bypass the entire protection stack.

    Techniques:
        1. MX records → resolve mail servers, check if non-CDN
        2. SPF record → parse include: chains, ip4:, a: mechanisms
        3. TLS certificate SANs → resolve alternate names
        4. mail./webmail./smtp./direct. subdomains → resolve
        5. Historical DNS via SecurityTrails API (optional)
        6. Verify: HTTP request to candidate IP with Host: header
    """
    import subprocess
    import concurrent.futures
    import re as _re
    import os

    base_domain = host.lstrip("www.") if host.startswith("www.") else host

    # Use provided DNS data or resolve fresh
    if dns_data is None:
        dns_data = check_dns(base_domain)

    # Determine parent CDN from IPs if not provided
    if parent_cdn is None:
        for ip in dns_data.get("a", []):
            parent_cdn = _ip_is_cdn(ip)
            if parent_cdn:
                break

    result: Dict[str, Any] = {
        "origin_ips": [],
        "candidates": [],
        "verified": [],
        "parent_cdn": parent_cdn,
        "techniques_used": [],
        "origin_exposed": False,
    }

    # Skip if no CDN/WAF detected — origin IS the direct IP
    if not parent_cdn:
        result["skip_reason"] = "no CDN/WAF detected — target already resolves to origin"
        return result

    candidate_ips: Dict[str, Dict[str, Any]] = {}  # ip -> {source, hostname, ...}

    def _add_candidate(ip: str, source: str, hostname: str = ""):
        """Add a non-CDN IP as an origin candidate."""
        if not ip or ip.startswith("0.") or ip.startswith("127."):
            return
        cdn = _ip_is_cdn(ip)
        if cdn:
            return  # This IP belongs to a CDN, not origin
        if ip not in candidate_ips:
            candidate_ips[ip] = {"source": source, "hostname": hostname, "cdn": cdn}
        else:
            # Append source if new
            existing = candidate_ips[ip]["source"]
            if source not in existing:
                candidate_ips[ip]["source"] = f"{existing}, {source}"

    # ── 1. MX records ──
    mx_records = dns_data.get("mx", [])
    if mx_records:
        result["techniques_used"].append("mx_records")
        for mx in mx_records:
            # MX format: "10 mail.example.com" or just "mail.example.com"
            parts = mx.strip().split()
            mx_host = parts[-1].rstrip(".")
            # Only consider MX hosts on the same domain or IP
            mx_ips = _resolve_hostname(mx_host, timeout=timeout)
            for ip in mx_ips:
                _add_candidate(ip, "mx_record", mx_host)

    # ── 2. SPF record → parse include chains, ip4:, a: ──
    txt_records = dns_data.get("txt", [])
    spf_record = ""
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            spf_record = txt
            break

    if spf_record:
        result["techniques_used"].append("spf_record")
        _parse_spf_for_origins(spf_record, base_domain, _add_candidate, timeout)

    # ── 3. TLS certificate SANs ──
    san_names = []
    if tls_data:
        # Extract SANs from cert if available
        san_names = tls_data.get("cert_san", [])

    # Also fetch SANs directly if not already in tls_data
    if not san_names:
        san_names = _extract_cert_sans(base_domain, timeout=timeout)

    if san_names:
        result["techniques_used"].append("certificate_san")
        for san in san_names:
            if san.startswith("*."):
                continue  # Skip wildcards
            san_ips = _resolve_hostname(san, timeout=timeout)
            for ip in san_ips:
                _add_candidate(ip, "cert_san", san)

    # ── 4. Common mail/origin subdomains ──
    origin_subdomains = [
        "mail", "webmail", "smtp", "imap", "pop", "pop3", "mx",
        "email", "exchange", "autodiscover", "autoconfig",
        "direct", "origin", "origin-www", "direct-connect",
        "cpanel", "whm", "plesk", "ftp", "sftp",
    ]
    result["techniques_used"].append("mail_subdomains")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futures = {}
        for sub in origin_subdomains:
            fqdn = f"{sub}.{base_domain}"
            futures[pool.submit(_resolve_hostname, fqdn, timeout)] = (sub, fqdn)

        for future in concurrent.futures.as_completed(futures):
            sub, fqdn = futures[future]
            try:
                ips = future.result()
                for ip in ips:
                    _add_candidate(ip, f"subdomain:{sub}", fqdn)
            except Exception:
                pass

    # ── 5. Historical DNS (SecurityTrails API — optional) ──
    st_key = securitytrails_key or os.environ.get("SECURITYTRAILS_API_KEY")
    if st_key:
        result["techniques_used"].append("securitytrails_history")
        hist_ips = _securitytrails_history(base_domain, st_key, timeout=timeout)
        for ip in hist_ips:
            _add_candidate(ip, "historical_dns", "")

    # ── Build candidates list ──
    for ip, info in candidate_ips.items():
        result["candidates"].append({
            "ip": ip,
            "source": info["source"],
            "hostname": info["hostname"],
            "verified": False,
        })

    result["origin_ips"] = list(candidate_ips.keys())

    # ── 6. Verify: HTTP request with Host header ──
    # Prioritize: SPF ip4/a > mail subdomains > MX (skip known mail providers)
    _mail_providers = {"google.com", "googlemail.com", "outlook.com", "office365",
                       "pphosted.com", "mimecast", "proofpoint", "barracuda",
                       "messagelabs", "mailgun", "sendgrid", "zendesk",
                       "hubspot", "amazonaws.com", "sparkpost"}
    # Known third-party SPF IP ranges (Google, Microsoft, etc.) — not origin
    _third_party_prefixes = [
        "74.125.", "64.233.", "66.102.", "66.249.", "72.14.", "108.177.",
        "142.250.", "172.217.", "173.194.", "209.85.", "216.58.", "216.239.",
        "192.178.",  # Google
        "40.92.", "40.93.", "40.94.", "40.107.", "52.100.", "52.101.",
        "104.47.",  # Microsoft
        "103.151.192.", "185.12.80.",  # SendGrid / HubSpot
        "198.2.128.", "198.2.176.", "198.2.180.",  # Zendesk
    ]
    priority_ips = []
    secondary_ips = []
    for ip, info in candidate_ips.items():
        src = info.get("source", "")
        hostname = info.get("hostname", "").lower()
        # Skip known third-party mail services (by hostname)
        if any(mp in hostname for mp in _mail_providers):
            continue
        # Skip known third-party IP ranges
        if any(ip.startswith(p) for p in _third_party_prefixes):
            continue
        # Skip network addresses (.0) and IPv6 (not probed well via HTTP)
        if ip.endswith(".0") or ":" in ip:
            continue
        if "spf_ip4" in src or "spf_a" in src or "subdomain:" in src:
            priority_ips.append(ip)
        else:
            secondary_ips.append(ip)
    verify_targets = (priority_ips + secondary_ips)[:15]

    if verify_targets:
        result["techniques_used"].append("http_host_verification")
        verified = _verify_origin_ips(verify_targets, base_domain, timeout=2.0)
        for v in verified:
            result["verified"].append(v)
            # Update candidate entry
            for c in result["candidates"]:
                if c["ip"] == v["ip"]:
                    c["verified"] = True
                    c["status_code"] = v.get("status_code")
                    c["server"] = v.get("server")
                    c["title"] = v.get("title")

    result["origin_exposed"] = len(result["verified"]) > 0

    return result


# ── Subdomain takeover detection ────────────────────────────────────────

# Known services vulnerable to subdomain takeover via dangling CNAME.
# Format: pattern → (service_name, fingerprint_in_response, severity)
_TAKEOVER_SIGNATURES: Dict[str, tuple] = {
    "github.io":           ("GitHub Pages",   "There isn't a GitHub Pages site here",     "high"),
    "herokuapp.com":       ("Heroku",         "no such app",                               "high"),
    "herokudns.com":       ("Heroku DNS",     "no such app",                               "high"),
    "s3.amazonaws.com":    ("AWS S3",         "NoSuchBucket",                              "high"),
    "s3-website":          ("AWS S3 Website", "NoSuchBucket",                              "high"),
    "azurewebsites.net":   ("Azure App Svc",  "not found",                                 "high"),
    "cloudapp.net":        ("Azure Cloud",    "",                                           "medium"),
    "trafficmanager.net":  ("Azure TM",       "",                                           "medium"),
    "blob.core.windows.net": ("Azure Blob",   "BlobNotFound",                              "high"),
    "shopify.com":         ("Shopify",        "Sorry, this shop is currently unavailable",  "high"),
    "ghost.io":            ("Ghost",          "The thing you were looking for is no longer", "medium"),
    "pantheon.io":         ("Pantheon",       "404 error unknown site",                     "medium"),
    "zendesk.com":         ("Zendesk",        "Help Center Closed",                         "medium"),
    "readme.io":           ("ReadMe",         "Project doesnt exist",                       "medium"),
    "surge.sh":            ("Surge.sh",       "project not found",                          "medium"),
    "bitbucket.io":        ("Bitbucket",      "Repository not found",                       "medium"),
    "netlify.app":         ("Netlify",        "Not Found - Request ID",                     "medium"),
    "netlify.com":         ("Netlify",        "Not Found - Request ID",                     "medium"),
    "fly.dev":             ("Fly.io",         "404 Not Found",                              "medium"),
    "unbouncepages.com":   ("Unbounce",       "The requested URL was not found",            "medium"),
    "helpjuice.com":       ("Helpjuice",      "We could not find what you're looking for",  "medium"),
    "helpscoutdocs.com":   ("HelpScout",      "No settings were found",                     "medium"),
    "cargocollective.com": ("Cargo",          "404 Not Found",                              "low"),
    "feedpress.me":        ("FeedPress",      "The feed has not been found",                "low"),
    "freshdesk.com":       ("Freshdesk",      "There is no helpdesk here",                  "medium"),
    "tictail.com":         ("Tictail",        "to target URL",                              "medium"),
    "smartling.com":       ("Smartling",      "",                                           "low"),
    "aftership.com":       ("AfterShip",      "Oops.</h2>",                                 "medium"),
    "wp.com":              ("WordPress.com",  "Do you want to register",                    "medium"),
}


def check_subdomain_takeover(subdomains: List[str],
                              timeout: float = 4.0) -> Dict[str, Any]:
    """Check a list of subdomains for dangling CNAME records pointing to
    services known to be vulnerable to subdomain takeover.

    Args:
        subdomains: List of FQDNs to check (e.g. from crt.sh + bruteforce).
        timeout: DNS / HTTP timeout per subdomain.

    Returns:
        Dict with 'vulnerable', 'checked', 'count' keys.
    """
    import concurrent.futures
    import subprocess

    result: Dict[str, Any] = {
        "vulnerable": [],
        "checked": 0,
        "count": 0,
    }

    def _check_one(fqdn: str):
        """Resolve CNAME for fqdn and check for takeover signatures."""
        try:
            out = subprocess.run(
                ["dig", "+short", "CNAME", fqdn],
                capture_output=True, text=True, timeout=timeout
            )
            cnames = [l.strip().rstrip(".").lower()
                      for l in out.stdout.strip().splitlines() if l.strip()]
        except Exception:
            return None

        if not cnames:
            return None

        cname = cnames[0]
        for pattern, (service, fingerprint, severity) in _TAKEOVER_SIGNATURES.items():
            if pattern in cname:
                # Confirm: try resolving the CNAME target — NXDOMAIN = dangling
                dangling = False
                try:
                    ips = _resolve_hostname(fqdn, timeout=timeout)
                    if not ips:
                        dangling = True
                except Exception:
                    dangling = True

                # If it resolves, optionally check HTTP fingerprint
                http_confirmed = False
                if not dangling and fingerprint:
                    try:
                        from fray.recon.http import _http_get
                        status, _, body = _http_get(
                            fqdn, 443 if True else 80, "/", True,
                            timeout=timeout)
                        if fingerprint.lower() in body.lower():
                            http_confirmed = True
                    except Exception:
                        pass

                if dangling or http_confirmed:
                    return {
                        "subdomain": fqdn,
                        "cname": cname,
                        "service": service,
                        "severity": severity,
                        "dangling": dangling,
                        "http_confirmed": http_confirmed,
                    }
        return None

    # Check up to 100 subdomains in parallel
    candidates = list(subdomains)[:100]
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(_check_one, s): s for s in candidates}
        for future in concurrent.futures.as_completed(futures):
            try:
                entry = future.result()
                if entry:
                    result["vulnerable"].append(entry)
            except Exception:
                pass

    result["checked"] = len(candidates)
    result["vulnerable"].sort(key=lambda e: e["subdomain"])
    result["count"] = len(result["vulnerable"])

    return result


# ── DNSSEC validation (#47) ───────────────────────────────────────────

def check_dnssec(host: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Check whether a domain has valid DNSSEC signatures.

    Uses ``dig +dnssec`` and inspects the AD (Authenticated Data) flag
    as well as the presence of RRSIG / DNSKEY records.

    Returns:
        Dict with 'enabled', 'validated', 'has_dnskey', 'has_rrsig',
        'ds_records', 'nsec_type' keys.
    """
    import subprocess

    result: Dict[str, Any] = {
        "enabled": False,
        "validated": False,
        "has_dnskey": False,
        "has_rrsig": False,
        "ds_records": [],
        "nsec_type": None,
    }

    # 1. Query with +dnssec — check AD flag in header
    try:
        out = subprocess.run(
            ["dig", "+dnssec", "+noall", "+comments", "+answer", "A", host],
            capture_output=True, text=True, timeout=timeout,
        )
        header_lines = out.stdout
        # AD flag in the ;; flags: line means the resolver validated DNSSEC
        if "flags:" in header_lines and " ad" in header_lines.lower().split("flags:")[1].split(";")[0]:
            result["validated"] = True
        # RRSIG in answer section means zone is signed
        if "RRSIG" in header_lines:
            result["has_rrsig"] = True
            result["enabled"] = True
    except Exception:
        pass

    # 2. Check for DNSKEY records
    try:
        out = subprocess.run(
            ["dig", "+short", "DNSKEY", host],
            capture_output=True, text=True, timeout=timeout,
        )
        if out.stdout.strip():
            result["has_dnskey"] = True
            result["enabled"] = True
    except Exception:
        pass

    # 3. Check DS records at parent (proves chain of trust)
    try:
        out = subprocess.run(
            ["dig", "+short", "DS", host],
            capture_output=True, text=True, timeout=timeout,
        )
        lines = [l.strip() for l in out.stdout.strip().splitlines() if l.strip()]
        if lines:
            result["ds_records"] = lines[:5]
            result["enabled"] = True
    except Exception:
        pass

    # 4. Detect NSEC vs NSEC3 (zone walking protection)
    try:
        out = subprocess.run(
            ["dig", "+dnssec", "+noall", "+authority", f"nonexistent-dnssec-test.{host}"],
            capture_output=True, text=True, timeout=timeout,
        )
        body = out.stdout
        if "NSEC3" in body:
            result["nsec_type"] = "NSEC3"
        elif "NSEC" in body:
            result["nsec_type"] = "NSEC"
    except Exception:
        pass

    return result


# ── Zone transfer attempt (#48) ───────────────────────────────────────

def check_zone_transfer(host: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Attempt AXFR zone transfer against all NS servers for the domain.

    A successful zone transfer reveals every record in the DNS zone —
    a critical misconfiguration.

    Returns:
        Dict with 'vulnerable', 'ns_tested', 'ns_vulnerable',
        'records_leaked', 'sample_records' keys.
    """
    import subprocess

    result: Dict[str, Any] = {
        "vulnerable": False,
        "ns_tested": [],
        "ns_vulnerable": [],
        "records_leaked": 0,
        "sample_records": [],
    }

    # Get NS servers
    try:
        out = subprocess.run(
            ["dig", "+short", "NS", host],
            capture_output=True, text=True, timeout=5,
        )
        nameservers = [l.strip().rstrip(".") for l in out.stdout.strip().splitlines()
                       if l.strip()]
    except Exception:
        return result

    if not nameservers:
        return result

    for ns in nameservers[:6]:
        result["ns_tested"].append(ns)
        try:
            out = subprocess.run(
                ["dig", "AXFR", f"@{ns}", host],
                capture_output=True, text=True, timeout=timeout,
            )
            # A successful AXFR has multiple records; failed ones have
            # "; Transfer failed." or very short output with only SOA
            lines = [l for l in out.stdout.strip().splitlines()
                     if l.strip() and not l.startswith(";")]
            # Need more than just the trailing SOA to count as success
            if len(lines) > 2:
                result["vulnerable"] = True
                result["ns_vulnerable"].append(ns)
                result["records_leaked"] = max(result["records_leaked"], len(lines))
                # Keep a sample (first 20 records, redact if very long)
                if not result["sample_records"]:
                    result["sample_records"] = [l[:200] for l in lines[:20]]
        except Exception:
            pass

    return result


# ── Wildcard DNS detection (#51) ──────────────────────────────────────

def check_wildcard_dns(host: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect wildcard DNS by resolving random non-existent subdomains.

    If multiple random labels all resolve to the same IP(s), a wildcard
    A record is configured — this affects subdomain brute-force accuracy.

    Returns:
        Dict with 'wildcard', 'wildcard_ips', 'tested' keys.
    """
    import hashlib
    import time

    result: Dict[str, Any] = {
        "wildcard": False,
        "wildcard_ips": [],
        "tested": 0,
    }

    # Generate 3 random-looking subdomains (deterministic from host + time seed)
    seed = f"{host}-{int(time.time()) // 60}"
    probes = []
    for i in range(3):
        token = hashlib.md5(f"{seed}-{i}".encode()).hexdigest()[:12]
        probes.append(f"fray-wc-{token}.{host}")

    resolved: List[set] = []
    for fqdn in probes:
        ips = _resolve_hostname(fqdn, timeout=timeout)
        result["tested"] += 1
        if ips:
            resolved.append(set(ips))

    # If at least 2 random names resolve, and they share IPs → wildcard
    if len(resolved) >= 2:
        common = resolved[0]
        for s in resolved[1:]:
            common = common & s
        if common:
            result["wildcard"] = True
            result["wildcard_ips"] = sorted(common)

    return result
