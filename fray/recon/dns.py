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
               "72.246.", "72.247.", "96.16.", "96.17.",
               "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.",
               "104.70.", "104.71.", "104.72.", "104.73.", "104.74.", "104.75.",
               "104.76.", "104.77.", "104.78.", "104.79.", "104.80.", "104.81.",
               "104.82.", "104.83.", "104.84.", "104.85.", "104.86.", "104.87.",
               "104.88.", "104.89.", "104.90.", "104.91.", "104.92.", "104.93.",
               "104.94.", "104.95.", "104.96.", "104.97.", "104.98.", "104.99.",
               "104.100.", "104.101.", "104.102.", "104.103.", "104.104.",
               "104.105.", "104.106.", "104.107.", "104.108.", "104.109.",
               "104.110.", "104.111.", "104.112.", "104.113.", "104.114.",
               "104.115.", "104.116.", "104.117.", "104.118.", "104.119.",
               "104.120.", "104.121.", "104.122.", "104.123.", "104.124.",
               "104.125.", "104.126.", "104.127.",
               "166.117.", "184.24.", "184.25.",
               "184.26.", "184.27.", "184.28.", "184.29.", "184.30.", "184.31.",
               "184.50.", "184.51."],
    "fastly": ["151.101.", "199.232.", "198.252."],
    "incapsula": ["199.83.", "198.143.", "149.126.", "185.11.",
                  "45.60.", "170.248."],
    "sucuri": ["192.124.", "185.93."],
    "azure_cdn": ["13.107.", "150.171."],
    "google_cdn": ["34.120.", "34.149.", "35.186.", "35.190.", "35.201.", "35.227.",
                   "142.250.", "142.251.", "172.217.", "172.253.",
                   "74.125.", "216.58.", "216.239."],
    "vercel":     ["76.76.", "198.169.", "216.230."],
    "netlify":    ["75.2.", "99.83.", "15.197.", "3.33."],
    "flyio":      ["37.16.", "66.241.", "137.66.", "168.220."],
    "render":     ["216.24."],
    "ddos_guard": ["186.2.", "77.222.", "190.115."],
    "qrator":     ["185.104."],
    "arvancloud": ["185.143."],
    "gcore":      ["92.223.", "95.85.", "2.56."],
    "alibaba_cdn": ["47.88.", "47.246.", "47.254.", "198.11.", "149.129.",
                    "161.117.", "47.74.", "47.89.", "47.90.", "47.91."],
    "tencent_cdn": ["43.174.", "129.226.", "162.62.", "43.132.", "43.154.",
                    "43.152.", "43.159.", "101.32.", "101.33."],
    "bunnycdn":   ["138.199.", "185.245."],
    "keycdn":     ["185.172."],
    "stackpath":  ["151.139.", "104.35.", "69.16."],
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

    # NS and MX are on the apex domain, not www subdomain
    apex = host
    if apex.startswith("www."):
        apex = apex[4:]
    for rtype in ["NS", "MX"]:
        if not result.get(rtype.lower()):
            try:
                out = subprocess.run(
                    ["dig", "+short", rtype, apex],
                    capture_output=True, text=True, timeout=5
                )
                lines = [l.strip().rstrip(".") for l in out.stdout.strip().splitlines() if l.strip()]
                if rtype == "MX":
                    # MX returns "priority hostname" — extract just hostname, sort by priority
                    mx_parsed = []
                    for l in lines:
                        parts = l.split()
                        if len(parts) >= 2:
                            mx_parsed.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                        else:
                            mx_parsed.append({"priority": 0, "host": l.rstrip(".")})
                    mx_parsed.sort(key=lambda x: x["priority"])
                    result["mx"] = [m["host"] for m in mx_parsed]
                    result["mx_raw"] = mx_parsed
                else:
                    result[rtype.lower()] = lines
            except Exception:
                pass
    # Also fetch TXT for apex if host was www
    if apex != host and not result.get("txt"):
        try:
            out = subprocess.run(
                ["dig", "+short", "TXT", apex],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip().strip('"') for l in out.stdout.strip().splitlines() if l.strip()]
            result["txt"] = lines
        except Exception:
            pass

    # SPF/DMARC from TXT records
    txt_joined = " ".join(result.get("txt", [])).lower()
    result["has_spf"] = "v=spf1" in txt_joined
    result["spf"] = ""
    for t in result.get("txt", []):
        if "v=spf1" in t.lower():
            result["spf"] = t.strip('"')
            break
    result["has_dmarc"] = False
    result["dmarc"] = ""
    # DMARC is at _dmarc subdomain
    for dmarc_host in [f"_dmarc.{apex}", f"_dmarc.{host}"]:
        try:
            out = subprocess.run(
                ["dig", "+short", "TXT", dmarc_host],
                capture_output=True, text=True, timeout=5
            )
            if "v=dmarc1" in out.stdout.lower():
                result["has_dmarc"] = True
                result["dmarc"] = out.stdout.strip().strip('"')
                break
        except Exception:
            pass

    # Email provider detection from MX records
    _EMAIL_PROVIDERS = {
        "google": "Google Workspace",
        "googlemail": "Google Workspace",
        "gmail": "Google Workspace",
        "outlook": "Microsoft 365",
        "microsoft": "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "pphosted": "Proofpoint",
        "proofpoint": "Proofpoint",
        "mimecast": "Mimecast",
        "barracuda": "Barracuda",
        "messagelabs": "Broadcom (Symantec)",
        "fireeyecloud": "Trellix (FireEye)",
        "iphmx": "Cisco IronPort",
        "ironport": "Cisco IronPort",
        "ess.symantec": "Broadcom (Symantec)",
        "sendgrid": "SendGrid",
        "mailgun": "Mailgun",
        "postmark": "Postmark",
        "amazonses": "Amazon SES",
        "zoho": "Zoho Mail",
        "yandex": "Yandex Mail",
        "secureserver": "GoDaddy",
        "kundenserver": "IONOS",
        "qq.com": "Tencent QQ Mail",
        "sakura": "Sakura Internet",
        "iij": "IIJ",
        "softbank": "SoftBank",
        "ntt": "NTT",
    }
    email_providers = []
    mx_hosts = result.get("mx", [])
    mx_lower = " ".join(mx_hosts).lower()
    for kw, provider in _EMAIL_PROVIDERS.items():
        if kw in mx_lower and provider not in email_providers:
            email_providers.append(provider)
    result["email_providers"] = email_providers

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


def check_ct_monitor(host: str, days: int = 30,
                     timeout: int = 10,
                     baseline: Optional[Dict] = None) -> Dict[str, Any]:
    """Monitor Certificate Transparency logs for recently issued certificates (#128).

    Queries multiple CT sources (crt.sh, Certspotter), detects suspicious
    patterns (shadow certs, unexpected issuers, short-lived, pre-certs),
    and diffs against a baseline to find new certificates.

    Args:
        host: Domain to monitor.
        days: Look-back window in days (default 30).
        timeout: HTTP timeout per source.
        baseline: Previous CT monitor result for diffing (optional).

    Returns:
        Dict with 'recent_certs', 'new_subdomains', 'wildcard_certs',
        'issuers', 'alerts', 'diff' (vs baseline), 'sources'.
    """
    import json as _json
    import re as _re
    from datetime import datetime, timedelta

    result: Dict[str, Any] = {
        "domain": host,
        "days": days,
        "recent_certs": [],
        "total_recent": 0,
        "new_subdomains": [],
        "wildcard_certs": [],
        "issuers": {},
        "alerts": [],
        "sources": {},
        "diff": None,
        "error": None,
    }

    search_domain = host.lstrip("www.") if host.startswith("www.") else host
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    now_str = datetime.utcnow().strftime("%Y-%m-%d")

    # Known legitimate issuers (common CAs)
    _KNOWN_CAS = {
        "let's encrypt", "r3", "r10", "r11", "e5", "e6",
        "digicert", "geotrust", "rapidssl", "thawte",
        "sectigo", "comodo", "usertrust",
        "google trust services", "gts ca",
        "amazon", "starfield",
        "cloudflare", "ssl.com",
        "globalsign", "entrust", "godaddy",
        "microsoft", "baltimore", "zerossl",
    }

    all_entries: List[Dict] = []

    # ── Source 1: crt.sh ──────────────────────────────────────────────────
    try:
        from fray.recon.http import _follow_redirect
        status, body = _follow_redirect(
            "crt.sh",
            f"/?q=%25.{search_domain}&output=json",
            timeout=timeout,
        )
        if status == 200 and body:
            entries = _json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(entries, list):
                all_entries.extend(entries)
                result["sources"]["crt.sh"] = len(entries)
        else:
            result["sources"]["crt.sh"] = f"error:{status}"
    except Exception as e:
        result["sources"]["crt.sh"] = f"error:{e}"

    # ── Source 2: Certspotter (SSLMate) ───────────────────────────────────
    try:
        conn = http.client.HTTPSConnection("api.certspotter.com", timeout=timeout)
        conn.request("GET", f"/v1/issuances?domain={search_domain}&include_subdomains=true&expand=dns_names&expand=issuer",
                     headers={"User-Agent": f"Fray/{__version__}"})
        resp = conn.getresponse()
        if resp.status == 200:
            cs_body = resp.read().decode("utf-8", errors="replace")
            cs_entries = _json.loads(cs_body)
            if isinstance(cs_entries, list):
                # Normalize Certspotter format → crt.sh-like
                for cs in cs_entries:
                    dns_names = cs.get("dns_names", [])
                    issuer_info = cs.get("issuer", {})
                    issuer_name = issuer_info.get("name", "") if isinstance(issuer_info, dict) else str(issuer_info)
                    not_before = cs.get("not_before", "")[:10]
                    not_after = cs.get("not_after", "")[:10]
                    all_entries.append({
                        "id": cs.get("id", ""),
                        "not_before": not_before,
                        "not_after": not_after,
                        "name_value": "\n".join(dns_names),
                        "issuer_name": issuer_name,
                        "_source": "certspotter",
                    })
                result["sources"]["certspotter"] = len(cs_entries)
        else:
            result["sources"]["certspotter"] = f"error:{resp.status}"
        conn.close()
    except Exception as e:
        result["sources"]["certspotter"] = f"error:{e}"

    if not all_entries:
        result["error"] = "No CT data from any source"
        return result

    # ── Process & deduplicate ─────────────────────────────────────────────
    seen_names: set = set()
    seen_ids: set = set()
    seen_fingerprints: set = set()  # (name_set, not_before) for cross-source dedup

    for entry in all_entries:
        cert_id = str(entry.get("id", ""))
        if cert_id and cert_id in seen_ids:
            continue
        if cert_id:
            seen_ids.add(cert_id)

        not_before = (entry.get("not_before") or "")[:10]
        not_after = (entry.get("not_after") or "")[:10]
        if not_before and not_before < cutoff:
            continue

        name_value = entry.get("name_value", "")
        issuer = entry.get("issuer_name", "")
        names = sorted(set(n.strip().lower() for n in name_value.split("\n") if n.strip()))

        # Cross-source dedup by (names, date)
        fp = (tuple(names[:5]), not_before)
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        cert_info = {
            "id": cert_id,
            "not_before": not_before,
            "not_after": not_after,
            "names": names[:10],
            "issuer": issuer,
        }
        result["recent_certs"].append(cert_info)

        # Track issuers
        issuer_short = issuer.split(",")[0].strip() if issuer else "Unknown"
        result["issuers"][issuer_short] = result["issuers"].get(issuer_short, 0) + 1

        # ── Suspicious pattern detection ──────────────────────────────────

        issuer_lower = issuer.lower()

        # 1. Unexpected/unknown issuer
        if issuer and not any(ca in issuer_lower for ca in _KNOWN_CAS):
            result["alerts"].append({
                "severity": "medium",
                "type": "unexpected_issuer",
                "message": f"Certificate from uncommon CA: {issuer_short}",
                "names": names[:3],
                "not_before": not_before,
            })

        # 2. Short-lived certificate (< 7 days) — potential phishing/staging
        if not_before and not_after:
            try:
                nb = datetime.strptime(not_before, "%Y-%m-%d")
                na = datetime.strptime(not_after, "%Y-%m-%d")
                lifetime_days = (na - nb).days
                if 0 < lifetime_days < 7:
                    result["alerts"].append({
                        "severity": "high",
                        "type": "short_lived_cert",
                        "message": f"Short-lived cert ({lifetime_days}d): possible staging/phishing",
                        "names": names[:3],
                        "not_before": not_before,
                        "lifetime_days": lifetime_days,
                    })
                # 3. Already expired
                if not_after < now_str:
                    result["alerts"].append({
                        "severity": "low",
                        "type": "expired_cert",
                        "message": f"Recently expired cert (expired {not_after})",
                        "names": names[:3],
                        "not_after": not_after,
                    })
            except ValueError:
                pass

        # 4. Shadow subdomain — subdomain not in the org's known pattern
        for name in names:
            if name.startswith("*."):
                if name not in seen_names:
                    result["wildcard_certs"].append({"name": name, "not_before": not_before, "issuer": issuer_short})
                    seen_names.add(name)
            elif name.endswith(f".{search_domain}") and name not in seen_names:
                result["new_subdomains"].append({"name": name, "not_before": not_before, "issuer": issuer_short})
                seen_names.add(name)

                # 5. Suspicious subdomain names (login, account, secure, verify — phishing patterns)
                sub_part = name.replace(f".{search_domain}", "")
                _phishing_patterns = (
                    "login", "signin", "sign-in", "account", "secure",
                    "verify", "confirm", "update", "banking", "support",
                    "helpdesk", "billing", "invoice", "password", "reset",
                )
                if any(pp in sub_part for pp in _phishing_patterns):
                    result["alerts"].append({
                        "severity": "high",
                        "type": "phishing_subdomain",
                        "message": f"Potential phishing subdomain: {name}",
                        "not_before": not_before,
                        "issuer": issuer_short,
                    })

    # 6. Excessive wildcard certs (>3 from different issuers → shadow infra)
    if len(result["wildcard_certs"]) > 3:
        wc_issuers = set(w.get("issuer", "") for w in result["wildcard_certs"])
        if len(wc_issuers) > 1:
            result["alerts"].append({
                "severity": "medium",
                "type": "excessive_wildcards",
                "message": f"{len(result['wildcard_certs'])} wildcard certs from {len(wc_issuers)} issuers",
            })

    # 7. Certificate volume spike — if way more certs than expected
    if len(result["recent_certs"]) > 50:
        result["alerts"].append({
            "severity": "medium",
            "type": "cert_volume_spike",
            "message": f"{len(result['recent_certs'])} certificates in {days} days — unusually high",
        })

    result["total_recent"] = len(result["recent_certs"])

    # ── Baseline diff (#128) ──────────────────────────────────────────────
    if baseline:
        prev_names = set()
        for cert in baseline.get("recent_certs", []):
            for n in cert.get("names", []):
                prev_names.add(n.lower())

        curr_names = set()
        for cert in result["recent_certs"]:
            for n in cert.get("names", []):
                curr_names.add(n.lower())

        new_names = sorted(curr_names - prev_names)
        removed_names = sorted(prev_names - curr_names)

        prev_issuers = set(baseline.get("issuers", {}).keys())
        curr_issuers = set(result["issuers"].keys())
        new_issuers = sorted(curr_issuers - prev_issuers)

        result["diff"] = {
            "new_names": new_names[:50],
            "removed_names": removed_names[:50],
            "new_issuers": new_issuers,
            "prev_total": baseline.get("total_recent", 0),
            "curr_total": result["total_recent"],
            "delta": result["total_recent"] - baseline.get("total_recent", 0),
        }

        # Alert on new issuers
        for ni in new_issuers:
            result["alerts"].append({
                "severity": "medium",
                "type": "new_issuer",
                "message": f"New certificate issuer detected: {ni}",
            })

        # Alert on large delta
        if result["diff"]["delta"] > 10:
            result["alerts"].append({
                "severity": "high",
                "type": "cert_spike_vs_baseline",
                "message": f"{result['diff']['delta']} more certs than previous scan",
            })

    # Sort alerts by severity
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result["alerts"].sort(key=lambda a: _sev_order.get(a.get("severity", "low"), 9))

    # Cap output size
    result["recent_certs"] = result["recent_certs"][:50]
    result["new_subdomains"] = result["new_subdomains"][:100]
    result["wildcard_certs"] = result["wildcard_certs"][:20]
    result["alerts"] = result["alerts"][:30]

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


# ── DNS hygiene scoring (#74) ─────────────────────────────────────────

def score_dns_hygiene(dns_data: Dict[str, Any],
                      dnssec_data: Optional[Dict[str, Any]] = None,
                      zone_transfer_data: Optional[Dict[str, Any]] = None,
                      wildcard_data: Optional[Dict[str, Any]] = None,
                      takeover_data: Optional[Dict[str, Any]] = None,
                      ) -> Dict[str, Any]:
    """Score DNS hygiene based on collected recon data (0–100, higher = better).

    Scoring rubric (100-point deduction model):
      - SPF record present:         +15
      - DMARC record present:       +15
      - DNSSEC enabled:             +15  (+5 bonus if validated)
      - CAA record present:         +10
      - No zone transfer (AXFR):    +15  (0 if vulnerable)
      - No wildcard DNS:            +10  (0 if wildcard detected)
      - No dangling CNAMEs:         +15  (0 if takeover vulnerable)
      - NS redundancy (≥2 NS):      +5

    Args:
        dns_data: Output from check_dns().
        dnssec_data: Output from check_dnssec() (optional).
        zone_transfer_data: Output from check_zone_transfer() (optional).
        wildcard_data: Output from check_wildcard_dns() (optional).
        takeover_data: Output from check_subdomain_takeover() (optional).

    Returns:
        Dict with 'score', 'grade', 'checks', 'recommendations'.
    """
    checks: List[Dict[str, Any]] = []
    score = 0

    # ── SPF (+15) ──
    has_spf = dns_data.get("has_spf", False)
    if has_spf:
        score += 15
        checks.append({"check": "SPF", "pass": True, "points": 15,
                        "detail": "SPF record found"})
    else:
        checks.append({"check": "SPF", "pass": False, "points": 0,
                        "detail": "No SPF record — email spoofing possible"})

    # ── DMARC (+15) ──
    has_dmarc = dns_data.get("has_dmarc", False)
    if has_dmarc:
        score += 15
        checks.append({"check": "DMARC", "pass": True, "points": 15,
                        "detail": "DMARC record found"})
    else:
        checks.append({"check": "DMARC", "pass": False, "points": 0,
                        "detail": "No DMARC record — no email authentication policy"})

    # ── DNSSEC (+15, +5 bonus) ──
    if dnssec_data:
        enabled = dnssec_data.get("enabled", False)
        validated = dnssec_data.get("validated", False)
        if enabled:
            pts = 15
            detail = "DNSSEC enabled"
            if validated:
                pts += 5
                detail += " and validated"
            score += pts
            checks.append({"check": "DNSSEC", "pass": True, "points": pts,
                            "detail": detail})
        else:
            checks.append({"check": "DNSSEC", "pass": False, "points": 0,
                            "detail": "DNSSEC not enabled — DNS responses can be spoofed"})
    else:
        checks.append({"check": "DNSSEC", "pass": False, "points": 0,
                        "detail": "DNSSEC not checked"})

    # ── CAA (+10) ──
    caa = dns_data.get("caa", [])
    if caa:
        score += 10
        checks.append({"check": "CAA", "pass": True, "points": 10,
                        "detail": f"CAA record(s) present ({len(caa)})"})
    else:
        checks.append({"check": "CAA", "pass": False, "points": 0,
                        "detail": "No CAA records — any CA can issue certificates"})

    # ── Zone transfer (+15) ──
    if zone_transfer_data:
        if zone_transfer_data.get("vulnerable", False):
            checks.append({"check": "Zone Transfer", "pass": False, "points": 0,
                            "detail": f"AXFR allowed on {', '.join(zone_transfer_data.get('ns_vulnerable', [])[:3])}"})
        else:
            score += 15
            checks.append({"check": "Zone Transfer", "pass": True, "points": 15,
                            "detail": "AXFR denied on all nameservers"})
    else:
        score += 15  # Assume safe if not tested
        checks.append({"check": "Zone Transfer", "pass": True, "points": 15,
                        "detail": "Not tested (assumed safe)"})

    # ── Wildcard DNS (+10) ──
    if wildcard_data:
        if wildcard_data.get("wildcard", False):
            wc_ips = ", ".join(wildcard_data.get("wildcard_ips", [])[:3])
            checks.append({"check": "Wildcard DNS", "pass": False, "points": 0,
                            "detail": f"Wildcard detected — all subs resolve to {wc_ips}"})
        else:
            score += 10
            checks.append({"check": "Wildcard DNS", "pass": True, "points": 10,
                            "detail": "No wildcard DNS"})
    else:
        score += 10
        checks.append({"check": "Wildcard DNS", "pass": True, "points": 10,
                        "detail": "Not tested (assumed safe)"})

    # ── Dangling CNAMEs / takeover (+15) ──
    if takeover_data:
        n_vuln = takeover_data.get("count", 0)
        if n_vuln > 0:
            names = [v["subdomain"] for v in takeover_data.get("vulnerable", [])[:3]]
            checks.append({"check": "Subdomain Takeover", "pass": False, "points": 0,
                            "detail": f"{n_vuln} dangling CNAME(s): {', '.join(names)}"})
        else:
            score += 15
            checks.append({"check": "Subdomain Takeover", "pass": True, "points": 15,
                            "detail": f"No dangling CNAMEs ({takeover_data.get('checked', 0)} checked)"})
    else:
        score += 15
        checks.append({"check": "Subdomain Takeover", "pass": True, "points": 15,
                        "detail": "Not tested (assumed safe)"})

    # ── NS redundancy (+5) ──
    ns_count = len(dns_data.get("ns", []))
    if ns_count >= 2:
        score += 5
        checks.append({"check": "NS Redundancy", "pass": True, "points": 5,
                        "detail": f"{ns_count} nameservers"})
    else:
        checks.append({"check": "NS Redundancy", "pass": False, "points": 0,
                        "detail": f"Only {ns_count} nameserver(s) — no redundancy"})

    # Cap at 100 (bonus can push above)
    score = min(score, 100)

    # Grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Recommendations (from failed checks)
    recommendations = [c["detail"] for c in checks if not c["pass"]]

    return {
        "score": score,
        "max_score": 105,  # 100 base + 5 DNSSEC validation bonus
        "grade": grade,
        "checks": checks,
        "passed": sum(1 for c in checks if c["pass"]),
        "failed": sum(1 for c in checks if not c["pass"]),
        "total_checks": len(checks),
        "recommendations": recommendations,
    }


# ── DNS rebinding detection (#49) ─────────────────────────────────────

# RFC 1918 / loopback / link-local prefixes — should never appear in
# public DNS A records.  Their presence enables DNS rebinding attacks.
_PRIVATE_PREFIXES = (
    "10.", "127.", "0.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.",
    "::1", "fc00:", "fd00:", "fe80:",
)


def check_dns_rebinding(host: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect DNS rebinding by checking if any A/AAAA record resolves to
    a private, loopback, or link-local IP address.

    Returns:
        Dict with 'vulnerable', 'private_ips', 'all_ips'.
    """
    result: Dict[str, Any] = {
        "vulnerable": False,
        "private_ips": [],
        "all_ips": [],
    }

    ips = _resolve_hostname(host, timeout=timeout)
    result["all_ips"] = ips

    for ip in ips:
        if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
            result["vulnerable"] = True
            result["private_ips"].append(ip)

    return result


# ── Subdomain sprawl detection (#76) ──────────────────────────────────

def detect_subdomain_sprawl(subdomains: List[str],
                             host: str) -> Dict[str, Any]:
    """Analyze subdomain count and composition for sprawl indicators.

    Flags:
      - Total count thresholds: >50 moderate, >100 high, >200 critical
      - Staging/dev/test environments exposed externally
      - Numeric-suffix patterns (app1, app2, ...) suggesting unmanaged growth

    Args:
        subdomains: Merged list of discovered subdomain FQDNs.
        host: Parent domain.

    Returns:
        Dict with 'total', 'severity', 'staging_envs', 'numeric_patterns',
        'sprawl_score'.
    """
    import re

    total = len(subdomains)

    # Severity by count
    if total >= 200:
        severity = "critical"
    elif total >= 100:
        severity = "high"
    elif total >= 50:
        severity = "medium"
    else:
        severity = "low"

    # Detect staging/dev/test subdomains
    staging_keywords = ("dev", "staging", "stage", "test", "qa", "uat",
                        "sandbox", "beta", "alpha", "preprod", "demo",
                        "internal", "debug", "canary", "preview")
    staging_envs = []
    for sub in subdomains:
        name = sub.lower().replace(f".{host.lower()}", "")
        for kw in staging_keywords:
            if kw in name:
                staging_envs.append(sub)
                break

    # Detect numeric suffix patterns (app1, app2, api3, web01, ...)
    numeric_re = re.compile(r"^([a-z]+-?[a-z]*)\d{1,3}\." + re.escape(host) + r"$", re.I)
    numeric_groups: Dict[str, List[str]] = {}
    for sub in subdomains:
        m = numeric_re.match(sub)
        if m:
            base = m.group(1).rstrip("-")
            numeric_groups.setdefault(base, []).append(sub)
    # Only flag groups with 3+ instances
    numeric_patterns = {k: v for k, v in numeric_groups.items() if len(v) >= 3}

    # Sprawl score (0-100, higher = more sprawl)
    score = min(100, (total // 2) + len(staging_envs) * 5 + sum(len(v) for v in numeric_patterns.values()) * 3)

    return {
        "total": total,
        "severity": severity,
        "staging_envs": staging_envs[:20],
        "staging_count": len(staging_envs),
        "numeric_patterns": {k: len(v) for k, v in numeric_patterns.items()},
        "numeric_pattern_count": len(numeric_patterns),
        "sprawl_score": score,
    }


# ── Cloud provider distribution (#77) ─────────────────────────────────

# Extended cloud/hosting provider IP prefixes for distribution analysis
_CLOUD_PROVIDERS = {
    **_CDN_IP_PREFIXES,
    "aws_ec2":      ["3.0.", "3.1.", "3.2.", "3.3.", "3.4.", "3.5.",
                     "13.52.", "13.56.", "13.57.", "13.112.", "13.113.",
                     "18.188.", "18.191.", "18.216.", "18.217.", "18.218.",
                     "34.192.", "34.193.", "34.194.", "34.195.", "34.196.",
                     "35.153.", "35.154.", "35.155.", "35.160.", "35.161.",
                     "44.192.", "44.193.", "44.194.", "44.195.",
                     "50.16.", "50.17.", "52.0.", "52.1.", "52.2.",
                     "52.4.", "52.5.", "52.6.", "52.7.", "52.20.",
                     "54.80.", "54.81.", "54.82.", "54.83.", "54.84.",
                     "54.160.", "54.161.", "54.162.", "54.163.", "54.164.",
                     "54.196.", "54.197.", "54.198.", "54.199.",
                     "54.200.", "54.201.", "54.202.", "54.203.", "54.204.",
                     "54.210.", "54.211.", "54.212.", "54.213.", "54.214.",
                     "100.20.", "100.21."],
    "gcp":          ["34.64.", "34.65.", "34.66.", "34.67.", "34.68.",
                     "34.69.", "34.70.", "34.71.", "34.72.", "34.80.",
                     "34.81.", "34.82.", "34.83.", "34.84.", "34.85.",
                     "35.184.", "35.185.", "35.186.", "35.187.", "35.188.",
                     "35.189.", "35.190.", "35.191.", "35.192.", "35.193.",
                     "35.194.", "35.195.", "35.196.", "35.197.", "35.198.",
                     "35.199.", "35.200.", "35.201.", "35.202.", "35.203.",
                     "35.204.", "35.205.", "35.206.", "35.207.",
                     "35.220.", "35.221.", "35.222.", "35.223.", "35.224.",
                     "35.225.", "35.226.", "35.227.", "35.228.", "35.229.",
                     "35.230.", "35.231.", "35.232.", "35.233.", "35.234.",
                     "35.235.", "35.236.", "35.237.", "35.238.", "35.239.",
                     "35.240.", "35.241.", "35.242.", "35.243.", "35.244.",
                     "35.245.", "35.246.", "35.247.",
                     "104.196.", "104.197.", "104.198.", "104.199.",
                     "130.211.", "146.148."],
    "azure":        ["13.64.", "13.65.", "13.66.", "13.67.", "13.68.",
                     "13.69.", "13.70.", "13.71.", "13.72.", "13.73.",
                     "13.74.", "13.75.", "13.76.", "13.77.", "13.78.",
                     "13.79.", "13.80.", "13.81.", "13.82.", "13.83.",
                     "13.84.", "13.85.", "13.86.", "13.87.", "13.88.",
                     "13.89.", "13.90.", "13.91.", "13.92.", "13.93.",
                     "13.94.", "13.95.",
                     "20.36.", "20.37.", "20.38.", "20.39.", "20.40.",
                     "20.41.", "20.42.", "20.43.", "20.44.", "20.45.",
                     "20.46.", "20.47.", "20.48.", "20.49.", "20.50.",
                     "20.51.", "20.52.", "20.53.",
                     "40.64.", "40.65.", "40.66.", "40.67.", "40.68.",
                     "40.69.", "40.70.", "40.71.", "40.74.", "40.75.",
                     "40.76.", "40.77.", "40.78.", "40.79.", "40.80.",
                     "40.81.", "40.82.", "40.83.", "40.84.", "40.85.",
                     "40.86.", "40.87.", "40.88.", "40.89.", "40.90.",
                     "40.91.", "40.112.", "40.113.", "40.114.", "40.115.",
                     "40.116.", "40.117.", "40.118.", "40.119.", "40.120.",
                     "40.121.", "40.122.", "40.123.", "40.124.", "40.125.",
                     "40.126.", "40.127.",
                     "51.104.", "51.105.", "51.120.", "51.124.",
                     "52.136.", "52.137.", "52.138.", "52.139.",
                     "52.140.", "52.141.", "52.142.", "52.143.",
                     "52.146.", "52.147.", "52.148.", "52.149.",
                     "52.150.", "52.151.", "52.152.", "52.153.",
                     "52.154.", "52.155.", "52.156.", "52.157.",
                     "52.158.", "52.159.", "52.160.", "52.161.",
                     "52.162.", "52.163.", "52.164.", "52.165.",
                     "52.166.", "52.167.", "52.168.", "52.169.",
                     "52.170.", "52.171.", "52.172.", "52.173.",
                     "52.174.", "52.175.", "52.176.", "52.177.",
                     "52.178.", "52.179.", "52.180.",
                     "104.40.", "104.41.", "104.42.", "104.43.",
                     "104.44.", "104.45.", "104.46.", "104.47.",
                     "104.208.", "104.209.", "104.210.", "104.211.",
                     "104.214.", "104.215."],
    "digitalocean": ["64.225.", "134.122.", "134.209.", "137.184.",
                     "138.68.", "138.197.", "139.59.", "142.93.",
                     "143.110.", "143.198.", "144.126.", "146.190.",
                     "147.182.", "157.230.", "157.245.", "159.65.",
                     "159.89.", "159.203.", "161.35.", "162.243.",
                     "163.47.", "164.90.", "164.92.", "165.22.",
                     "165.227.", "167.71.", "167.99.", "167.172.",
                     "170.64.", "174.138.", "178.62.", "178.128.",
                     "188.166.", "192.241.", "206.189.", "209.97."],
    "hetzner":      ["5.75.", "5.161.", "23.88.", "49.12.", "49.13.",
                     "65.21.", "65.108.", "65.109.", "78.46.", "78.47.",
                     "85.10.", "88.198.", "88.99.", "95.216.",
                     "116.202.", "116.203.", "128.140.", "135.181.",
                     "136.243.", "138.201.", "142.132.", "144.76.",
                     "148.251.", "157.90.", "159.69.", "162.55.",
                     "167.235.", "168.119.", "176.9.", "178.63.",
                     "188.34.", "195.201.", "213.133.", "213.239."],
    "ovh":          ["51.38.", "51.68.", "51.75.", "51.77.", "51.79.",
                     "51.81.", "51.83.", "51.89.", "51.91.", "51.161.",
                     "51.178.", "51.195.", "51.210.", "51.222.",
                     "54.36.", "54.37.", "54.38.", "54.39.",
                     "135.125.", "137.74.", "141.94.", "141.95.",
                     "142.4.", "144.217.", "145.239.", "147.135.",
                     "148.113.", "149.56.", "149.202.", "151.80.",
                     "158.69.", "164.132.", "167.114.", "176.31.",
                     "178.32.", "178.33.", "185.12.", "188.165.",
                     "192.95.", "192.99.", "193.70.", "198.27.",
                     "198.50.", "198.100.", "198.245.", "209.126."],
    "linode":       ["45.33.", "45.56.", "45.79.", "50.116.", "66.175.",
                     "66.228.", "69.164.", "72.14.", "74.207.",
                     "96.126.", "97.107.", "139.144.", "139.162.",
                     "143.42.", "170.187.", "172.104.", "172.105.",
                     "173.230.", "173.255.", "178.79.", "192.46.",
                     "192.155.", "194.195.", "198.58.", "198.74.",
                     "209.123."],
}


# WAF/CDN fingerprint signatures.
# "waf" and "cdn" indicate what to label when matched.
# Many CDN providers bundle WAF (Akamai Kona, Azure Front Door WAF,
# AWS WAF+CloudFront, Cloudflare WAF) — we detect them as both.
_WAF_CDN_SIGNATURES = [
    # ═══════════════════════════════════════════════════════════════════
    # WAF + CDN Combo Products (detect both WAF and CDN)
    # ═══════════════════════════════════════════════════════════════════

    # ── Cloudflare ──
    {"name": "Cloudflare", "waf": "Cloudflare", "cdn": "Cloudflare",
     "headers": {"server": "cloudflare", "cf-ray": "", "cf-cache-status": ""},
     "cname_hints": ["cloudflare"]},

    # ── Akamai (Kona Site Defender / App & API Protector) ──
    {"name": "Akamai", "waf": "Akamai (Kona/AAP)", "cdn": "Akamai",
     "headers": {"server": "akamaighost", "x-akamai-transformed": "",
                 "x-akamai-session-info": "", "x-akamai-request-id": ""},
     "server_contains": ["akamai"],
     "cname_hints": ["akamai", "edgesuite", "edgekey", "akamaized",
                     "akamaiedge", "akamaitechnologies"]},
    {"name": "Akamai NetStorage", "waf": None, "cdn": "Akamai",
     "headers": {"server": "akamainetstorage"},
     "server_contains": ["akamainetstorag"],
     "cname_hints": ["netstorage"]},
    {"name": "Akamai Bot Manager", "waf": "Akamai Bot Manager", "cdn": "Akamai",
     "headers": {"x-akamai-session-info": ""},
     "cname_hints": []},

    # ── AWS CloudFront + WAF ──
    {"name": "CloudFront", "waf": "AWS WAF", "cdn": "CloudFront",
     "headers": {"x-amz-cf-id": "", "x-amz-cf-pop": "", "via": "cloudfront",
                 "x-cache": ""},
     "cname_hints": ["cloudfront.net"]},
    {"name": "AWS WAF", "waf": "AWS WAF", "cdn": None,
     "headers": {"x-amzn-waf-action": ""},
     "cname_hints": ["awswaf"]},
    {"name": "AWS Shield", "waf": "AWS Shield", "cdn": None,
     "headers": {"x-amzn-ddos-protection": ""},
     "cname_hints": []},

    # ── Azure ──
    {"name": "Azure Front Door", "waf": "Azure Front Door WAF", "cdn": "Azure Front Door",
     "headers": {"x-azure-ref": ""},
     "cname_hints": ["azurefd", "afd.", "trafficmanager.net"]},
    {"name": "Azure CDN", "waf": None, "cdn": "Azure CDN",
     "headers": {"x-msedge-ref": "", "x-ec-custom-error": ""},
     "cname_hints": ["azureedge", "msecnd"]},
    {"name": "Azure Application Gateway", "waf": "Azure App Gateway WAF", "cdn": None,
     "headers": {"server": "microsoft-azure-application-gateway"},
     "cname_hints": []},

    # ── Google Cloud ──
    {"name": "Google Cloud Armor", "waf": "Google Cloud Armor", "cdn": "Google CDN",
     "headers": {"via": "google", "x-goog-": ""},
     "server_contains": ["gws", "gfe"],
     "cname_hints": ["googleusercontent", "googlevideo", "withgoogle", "google.com"]},
    {"name": "Google Cloud CDN", "waf": None, "cdn": "Google CDN",
     "headers": {"x-goog-hash": ""},
     "cname_hints": ["storage.googleapis.com"]},

    # ── Imperva / Incapsula ──
    {"name": "Imperva", "waf": "Imperva", "cdn": "Imperva",
     "headers": {"x-iinfo": "", "x-cdn": "imperva", "x-iinfo-origin-env": ""},
     "cookie_hints": ["visid_incap_", "incap_ses_", "x-mapping-"],
     "cname_hints": ["incapsula", "imperva"]},
    {"name": "Imperva Advanced Bot Protection", "waf": "Imperva ABP", "cdn": "Imperva",
     "headers": {"x-cdn": "incapsula"},
     "cname_hints": []},

    # ── Fastly ──
    {"name": "Fastly", "waf": "Fastly (Signal Sciences)", "cdn": "Fastly",
     "headers": {"x-served-by": "", "x-fastly-request-id": "", "x-cache-hits": ""},
     "cname_hints": ["fastly", "fastlylb"]},
    {"name": "Fastly Next-Gen WAF", "waf": "Fastly (Signal Sciences)", "cdn": "Fastly",
     "headers": {"x-sigsci-decision": ""},
     "cname_hints": []},

    # ── Sucuri ──
    {"name": "Sucuri", "waf": "Sucuri", "cdn": "Sucuri",
     "headers": {"x-sucuri-id": "", "x-sucuri-cache": "",
                 "x-gateway-request-id": "", "x-gateway-cache-status": ""},
     "cname_hints": ["sucuri"]},

    # ── Verizon / Edgecast ──
    {"name": "Verizon Digital Media / Edgecast", "waf": "Verizon WAF", "cdn": "Edgecast",
     "headers": {"server": "ecacc", "x-ec-custom-error": ""},
     "server_contains": ["ecacc", "ecd"],
     "cname_hints": ["edgecast"]},

    # ── StackPath / MaxCDN ──
    {"name": "StackPath", "waf": "StackPath WAF", "cdn": "StackPath",
     "headers": {"x-sp-waf-id": "", "server": "stackpath"},
     "cname_hints": ["stackpath", "stackpathdns"]},
    {"name": "MaxCDN", "waf": None, "cdn": "MaxCDN/StackPath",
     "headers": {"x-cdn": "maxcdn"},
     "cname_hints": ["maxcdn"]},

    # ── KeyCDN ──
    {"name": "KeyCDN", "waf": None, "cdn": "KeyCDN",
     "headers": {"server": "keycdn"},
     "cname_hints": ["kxcdn"]},

    # ── CDN77 ──
    {"name": "CDN77", "waf": None, "cdn": "CDN77",
     "headers": {"server": "cdn77", "x-cdn77-cache": ""},
     "cname_hints": ["cdn77"]},

    # ── BunnyCDN ──
    {"name": "BunnyCDN", "waf": None, "cdn": "BunnyCDN",
     "headers": {"server": "bunnycdn", "cdn-pullzone": "", "cdn-uid": ""},
     "cname_hints": ["b-cdn.net", "bunny"]},

    # ── Limelight / Edgio ──
    {"name": "Limelight / Edgio", "waf": "Edgio WAF", "cdn": "Limelight",
     "headers": {"server": "globalredir", "x-cdn": "llnw"},
     "cname_hints": ["limelight", "llnw", "edgio", "edgecast"]},

    # ── Alibaba Cloud CDN / WAF ──
    {"name": "Alibaba Cloud WAF", "waf": "Alibaba Cloud WAF", "cdn": "Alibaba CDN",
     "headers": {"server": "tengine", "eagleid": ""},
     "cname_hints": ["alicdn", "aliyuncs", "alicloudccp"]},

    # ── Tencent Cloud CDN / WAF ──
    {"name": "Tencent Cloud WAF", "waf": "Tencent Cloud WAF", "cdn": "Tencent CDN",
     "headers": {"x-nws-log-uuid": "", "server": "tencent"},
     "cname_hints": ["tencent", "dnsv1"]},

    # ── Baidu Cloud CDN / WAF ──
    {"name": "Baidu Cloud WAF", "waf": "Baidu Yundun", "cdn": "Baidu CDN",
     "headers": {"server": "yunjiasu-nginx"},
     "cname_hints": ["yunjiasu", "baidustatic", "bdstatic"]},

    # ── Huawei Cloud CDN / WAF ──
    {"name": "Huawei Cloud WAF", "waf": "Huawei Cloud WAF", "cdn": "Huawei CDN",
     "headers": {"x-hw-id": ""},
     "cname_hints": ["huaweicloud", "myhuaweicloud"]},

    # ── ChinaCache ──
    {"name": "ChinaCache", "waf": None, "cdn": "ChinaCache",
     "headers": {"server": "chinacache"},
     "cname_hints": ["chinacache", "ccgslb"]},

    # ── CDNetworks ──
    {"name": "CDNetworks", "waf": "CDNetworks WAF", "cdn": "CDNetworks",
     "headers": {"x-cdn-origin": "", "server": "cdnetworks"},
     "cname_hints": ["cdnetworks", "cdnple"]},

    # ── BitNinja ──
    {"name": "BitNinja", "waf": "BitNinja", "cdn": None,
     "headers": {"server": "bitninja"},
     "cname_hints": []},

    # ── Vercel / Next.js Edge ──
    {"name": "Vercel", "waf": "Vercel Firewall", "cdn": "Vercel Edge",
     "headers": {"server": "vercel", "x-vercel-id": "", "x-vercel-cache": ""},
     "cname_hints": ["vercel", "vercel-dns"]},

    # ── Netlify ──
    {"name": "Netlify", "waf": None, "cdn": "Netlify",
     "headers": {"server": "netlify", "x-nf-request-id": ""},
     "cname_hints": ["netlify"]},

    # ── Fly.io ──
    {"name": "Fly.io", "waf": None, "cdn": "Fly.io",
     "headers": {"server": "fly/", "fly-request-id": ""},
     "cname_hints": ["fly.dev", "fly.io"]},

    # ── Render ──
    {"name": "Render", "waf": None, "cdn": "Render",
     "headers": {"server": "render", "rndr-id": "", "x-render-origin-server": ""},
     "cname_hints": ["onrender"]},

    # ── Railway ──
    {"name": "Railway", "waf": None, "cdn": "Railway",
     "headers": {"server": "railway"},
     "cname_hints": ["railway.app"]},

    # ═══════════════════════════════════════════════════════════════════
    # Standalone WAFs (no CDN)
    # ═══════════════════════════════════════════════════════════════════

    # ── F5 BIG-IP ASM / Advanced WAF ──
    {"name": "F5 BIG-IP", "waf": "F5 BIG-IP ASM", "cdn": None,
     "headers": {"server": "big-ip", "x-cnection": "", "x-wa-info": ""},
     "cname_hints": []},

    # ── Barracuda WAF ──
    {"name": "Barracuda", "waf": "Barracuda WAF", "cdn": None,
     "headers": {"server": "barracuda"},
     "cname_hints": ["barracuda"]},

    # ── FortiWeb ──
    {"name": "FortiWeb", "waf": "FortiWeb", "cdn": None,
     "headers": {"server": "fortiweb"},
     "cname_hints": []},

    # ── Citrix NetScaler / ADC ──
    {"name": "Citrix NetScaler", "waf": "Citrix NetScaler", "cdn": None,
     "headers": {"via": "ns-cache", "cneonction": "", "x-nsprotect": ""},
     "cname_hints": []},

    # ── ModSecurity ──
    {"name": "ModSecurity", "waf": "ModSecurity", "cdn": None,
     "headers": {"server": "mod_security", "x-modsecurity-id": ""},
     "cname_hints": []},

    # ── NAXSI (nginx) ──
    {"name": "NAXSI", "waf": "NAXSI", "cdn": None,
     "headers": {"x-naxsi-sig": ""},
     "cname_hints": []},

    # ── WebKnight (IIS) ──
    {"name": "WebKnight", "waf": "WebKnight", "cdn": None,
     "headers": {"server": "webknight"},
     "cname_hints": []},

    # ── Wallarm ──
    {"name": "Wallarm", "waf": "Wallarm", "cdn": None,
     "headers": {"x-wallarm-waf-check": "", "server": "wallarm"},
     "cname_hints": ["wallarm"]},

    # ── Radware AppWall / DefensePro ──
    {"name": "Radware", "waf": "Radware AppWall", "cdn": None,
     "headers": {"x-sl-compstate": "", "server": "radware"},
     "cname_hints": ["radware"]},

    # ── DenyAll / Rohde & Schwarz ──
    {"name": "DenyAll", "waf": "DenyAll / R&S WAF", "cdn": None,
     "headers": {"server": "denyall", "x-denyall-id": ""},
     "cname_hints": []},

    # ── SonicWall WAF ──
    {"name": "SonicWall WAF", "waf": "SonicWall WAF", "cdn": None,
     "headers": {"server": "sonicwall"},
     "cname_hints": ["sonicwall"]},

    # ── Comodo / Sectigo WAF ──
    {"name": "Comodo WAF", "waf": "Comodo WAF", "cdn": None,
     "headers": {"server": "comodo", "x-cwaf-detected": "", "x-beluga-cache-status": ""},
     "server_contains": ["comodo", "nucdn"],
     "cname_hints": []},

    # ── Wordfence (WordPress) ──
    {"name": "Wordfence", "waf": "Wordfence", "cdn": None,
     "headers": {"x-wf-log": ""},
     "cname_hints": []},

    # ── Shield Security (WordPress) ──
    {"name": "Shield Security", "waf": "Shield Security", "cdn": None,
     "headers": {"x-shield-security": ""},
     "cname_hints": []},

    # ── NinjaFirewall (WordPress) ──
    {"name": "NinjaFirewall", "waf": "NinjaFirewall", "cdn": None,
     "headers": {"x-ninjafirewall": ""},
     "cname_hints": []},

    # ── Palo Alto Prisma Cloud / WAAS ──
    {"name": "Prisma Cloud WAAS", "waf": "Prisma Cloud WAAS", "cdn": None,
     "headers": {"x-prisma-event-id": ""},
     "cname_hints": []},

    # ── Check Point CloudGuard ──
    {"name": "Check Point CloudGuard", "waf": "Check Point CloudGuard", "cdn": None,
     "headers": {"x-checkpoint-id": "", "server": "cloudguard"},
     "cname_hints": []},

    # ── Sophos UTM / XG WAF ──
    {"name": "Sophos WAF", "waf": "Sophos WAF", "cdn": None,
     "headers": {"server": "sophos"},
     "cname_hints": []},

    # ── Juniper Web App Secure ──
    {"name": "Juniper WAS", "waf": "Juniper WAS", "cdn": None,
     "headers": {"x-was-id": ""},
     "cname_hints": []},

    # ── Airlock (Ergon) ──
    {"name": "Airlock", "waf": "Airlock WAF", "cdn": None,
     "headers": {"server": "airlock", "al-req-id": ""},
     "cname_hints": []},

    # ── Fortinet FortiADC ──
    {"name": "FortiADC", "waf": "FortiADC", "cdn": None,
     "headers": {"server": "fortiadc"},
     "cname_hints": []},

    # ── A10 Thunder / vThunder WAF ──
    {"name": "A10 Thunder", "waf": "A10 Thunder WAF", "cdn": None,
     "headers": {"server": "a10"},
     "cname_hints": []},

    # ── Qualys WAF ──
    {"name": "Qualys WAF", "waf": "Qualys WAF", "cdn": None,
     "headers": {"x-qualys-waf": ""},
     "cname_hints": []},

    # ── Reblaze ──
    {"name": "Reblaze", "waf": "Reblaze", "cdn": None,
     "headers": {"x-reblaze-id": "", "server": "reblaze"},
     "cname_hints": ["reblaze"]},

    # ── PerimeterX / HUMAN ──
    {"name": "PerimeterX / HUMAN", "waf": "PerimeterX", "cdn": None,
     "headers": {"x-px-id": "", "x-px-block-score": ""},
     "cname_hints": ["perimeterx", "human"]},

    # ── DataDome ──
    {"name": "DataDome", "waf": "DataDome", "cdn": None,
     "headers": {"x-datadome": "", "x-datadome-cid": "", "x-dd-b": "", "server": "datadome"},
     "cname_hints": ["datadome"]},

    # ── Kasada ──
    {"name": "Kasada", "waf": "Kasada", "cdn": None,
     "headers": {"x-kpsdk-cd": "", "x-kpsdk-ct": ""},
     "cname_hints": []},

    # ── Shape Security (F5 Distributed Cloud) ──
    {"name": "Shape Security", "waf": "Shape Security", "cdn": None,
     "headers": {"x-distil-cs": ""},
     "cname_hints": ["shape"]},

    # ── ThreatX ──
    {"name": "ThreatX", "waf": "ThreatX", "cdn": None,
     "headers": {"x-threatx-id": ""},
     "cname_hints": ["threatx"]},

    # ── AppTrana (Indusface) ──
    {"name": "AppTrana", "waf": "AppTrana", "cdn": None,
     "headers": {"x-apptrana-id": "", "server": "apptrana"},
     "cname_hints": ["apptrana", "indusface"]},

    # ── Prophaze WAF ──
    {"name": "Prophaze", "waf": "Prophaze WAF", "cdn": None,
     "headers": {"server": "prophaze"},
     "cname_hints": ["prophaze"]},

    # ── AWS Elastic Load Balancer (not WAF, but infra detection) ──
    {"name": "AWS ELB", "waf": None, "cdn": None,
     "headers": {"server": "awselb"},
     "server_contains": ["awselb"],
     "cname_hints": ["elb.amazonaws.com"]},

    # ── LiteSpeed (with built-in WAF) ──
    {"name": "LiteSpeed", "waf": "LiteSpeed WAF", "cdn": None,
     "headers": {"server": "litespeed"},
     "cname_hints": []},

    # ── OpenResty (nginx + Lua WAF capabilities) ──
    {"name": "OpenResty", "waf": "OpenResty", "cdn": None,
     "headers": {"server": "openresty"},
     "cname_hints": []},

    # ── Zenedge (Oracle / Dyn) ──
    {"name": "Zenedge", "waf": "Zenedge", "cdn": None,
     "headers": {"x-zen-fury": ""},
     "cname_hints": ["zenedge"]},

    # ── DDoS-Guard ──
    {"name": "DDoS-Guard", "waf": "DDoS-Guard", "cdn": "DDoS-Guard",
     "headers": {"server": "ddos-guard"},
     "cookie_hints": ["__ddg8_", "__ddg9_", "__ddg10_", "__ddgid_", "__ddgmark_"],
     "cname_hints": ["ddos-guard"]},

    # ── Qrator ──
    {"name": "Qrator", "waf": "Qrator", "cdn": None,
     "headers": {"x-qrator-request-id": ""},
     "server_contains": ["qrator"],
     "cookie_hints": ["qrator_msid"],
     "cname_hints": ["qrator"]},

    # ── StormWall ──
    {"name": "StormWall", "waf": "StormWall", "cdn": None,
     "headers": {"server": "stormwall"},
     "server_contains": ["stormwall", "sw"],
     "cname_hints": ["stormwall"]},

    # ── ArvanCloud ──
    {"name": "ArvanCloud", "waf": "ArvanCloud WAF", "cdn": "ArvanCloud",
     "headers": {"server": "arvancloud", "x-arvan-cache": ""},
     "cname_hints": ["arvancloud"]},

    # ── Section.io ──
    {"name": "Section.io", "waf": "Section.io", "cdn": "Section.io",
     "headers": {"section-io-id": ""},
     "cname_hints": ["section.io"]},

    # ── CacheFly ──
    {"name": "CacheFly", "waf": None, "cdn": "CacheFly",
     "headers": {"server": "cachefly"},
     "cname_hints": ["cachefly"]},

    # ── Highwinds / StackPath Legacy ──
    {"name": "Highwinds", "waf": None, "cdn": "Highwinds",
     "headers": {"x-hw": ""},
     "cname_hints": ["hwcdn"]},

    # ── Incapsula Legacy ──
    {"name": "Incapsula", "waf": "Incapsula", "cdn": "Incapsula",
     "headers": {"x-cdn": "incapsula"},
     "cname_hints": ["incapsula"]},

    # ── Yottaa ──
    {"name": "Yottaa", "waf": None, "cdn": "Yottaa",
     "headers": {"x-yottaa-optimizations": ""},
     "cname_hints": ["yottaa"]},

    # ── Instart Logic ──
    {"name": "Instart", "waf": "Instart", "cdn": "Instart",
     "headers": {"x-instart-request-id": ""},
     "cname_hints": ["instart"]},

    # ── GCore CDN ──
    {"name": "GCore", "waf": None, "cdn": "GCore",
     "headers": {"server": "gcore", "x-gc-cache": "", "x-id-fe": "", "x-id": ""},
     "cname_hints": ["gcore", "gcdn"]},

    # ── Webscale Networks ──
    {"name": "Webscale", "waf": "Webscale WAF", "cdn": "Webscale",
     "headers": {"x-webscale-id": ""},
     "cname_hints": ["webscale"]},

    # ── Bot Protection Only ──
    {"name": "FingerprintJS", "waf": "FingerprintJS Bot Protection", "cdn": None,
     "headers": {"x-fp-botd": ""},
     "cname_hints": []},

    # ── Sqreen (now DataDog) ──
    {"name": "Sqreen / DataDog ASM", "waf": "DataDog ASM", "cdn": None,
     "headers": {"x-sqreen-request-id": "", "x-dd-version": ""},
     "cname_hints": []},

    # ── Contrast Security RASP ──
    {"name": "Contrast Security", "waf": "Contrast RASP", "cdn": None,
     "headers": {"x-contrast-security": ""},
     "cname_hints": []},

    # ── Signal Sciences (standalone, before Fastly acquisition) ──
    {"name": "Signal Sciences", "waf": "Signal Sciences", "cdn": None,
     "headers": {"x-sigsci-tags": ""},
     "cname_hints": ["sigsci"]},
]


def _fingerprint_waf_cdn(fqdn: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Quick HTTP HEAD probe to fingerprint WAF/CDN from response headers + CNAME.

    Returns:
        Dict with 'waf', 'cdn', 'cname', 'ip', 'headers_matched'.
    """
    import http.client
    import ssl as _ssl
    import subprocess

    result: Dict[str, Any] = {
        "waf": None,
        "cdn": None,
        "cname": None,
        "ip": None,
        "server": None,
        "status": None,
        "cache_status": None,     # HIT / MISS / DYNAMIC / EXPIRED / etc.
        "cache_age": None,        # Age header value (seconds)
        "cache_control": None,    # Cache-Control header
        "headers_matched": [],
    }

    # 1. Resolve CNAME (for CDN hints)
    try:
        out = subprocess.run(
            ["dig", "+short", "CNAME", fqdn],
            capture_output=True, text=True, timeout=timeout,
        )
        cname = out.stdout.strip().rstrip(".").lower()
        if cname:
            result["cname"] = cname
    except Exception:
        pass

    # 2. Resolve A record
    ips = _resolve_hostname(fqdn, timeout=timeout)
    if ips:
        result["ip"] = ips[0]

    # 3. HTTP GET probe (GET, not HEAD — many CDNs strip cache headers on HEAD)
    #    Probe / first for WAF/server detection, then /robots.txt for cache status
    resp_headers: Dict[str, str] = {}
    _ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def _http_get(host: str, path: str, tout: float) -> Tuple[int, Dict[str, str]]:
        for scheme, pn in [("https", 443), ("http", 80)]:
            try:
                if scheme == "https":
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    c = http.client.HTTPSConnection(host, pn, timeout=tout, context=ctx)
                else:
                    c = http.client.HTTPConnection(host, pn, timeout=tout)
                c.request("GET", path, headers={"User-Agent": _ua, "Accept": "*/*"})
                r = c.getresponse()
                r.read(8192)
                hdrs = {}
                for k, v in r.getheaders():
                    kl = k.lower()
                    vl = v.lower()
                    if kl == "set-cookie" and kl in hdrs:
                        hdrs[kl] = hdrs[kl] + "; " + vl
                    else:
                        hdrs[kl] = vl
                c.close()
                return r.status, hdrs
            except Exception:
                continue
        return 0, {}

    # Primary probe: /
    status, resp_headers = _http_get(fqdn, "/", timeout)
    result["server"] = resp_headers.get("server", None)
    result["status"] = status

    # Secondary probe: /robots.txt (static, more likely to show cache HIT)
    cache_probed = False
    _cache_keys = ("cf-cache-status", "x-cache", "x-akamai-cache-status")
    if not any(k in resp_headers for k in _cache_keys):
        st2, hdrs2 = _http_get(fqdn, "/robots.txt", timeout)
        if any(k in hdrs2 for k in _cache_keys):
            # Merge cache headers from /robots.txt into results
            for ck in _cache_keys:
                if ck in hdrs2 and ck not in resp_headers:
                    resp_headers[ck] = hdrs2[ck]
            if "age" in hdrs2:
                resp_headers["age"] = hdrs2["age"]
            cache_probed = True
        # Also use /robots.txt server header if missing
        if not result["server"] and hdrs2.get("server"):
            result["server"] = hdrs2.get("server")
            resp_headers["server"] = hdrs2["server"]

    # 5. Extract CDN cache headers
    # Cloudflare: cf-cache-status (HIT/MISS/DYNAMIC/EXPIRED/REVALIDATED)
    # Akamai: x-cache (TCP_HIT/TCP_MISS), x-akamai-cache-status, x-true-cache-key
    # CloudFront: x-cache (Hit from cloudfront / Miss from cloudfront)
    # Azure: x-cache (HIT/MISS), x-azure-ref
    # Fastly: x-cache (HIT/MISS), x-cache-hits
    # Generic: age header (seconds since cached)
    cache_hdrs = {
        "cf-cache-status": resp_headers.get("cf-cache-status"),
        "x-cache": resp_headers.get("x-cache"),
        "x-akamai-cache-status": resp_headers.get("x-akamai-cache-status"),
        "x-cache-hits": resp_headers.get("x-cache-hits"),
        "age": resp_headers.get("age"),
        "cache-control": resp_headers.get("cache-control"),
    }
    # Determine cache status from available headers
    cs = None
    if cache_hdrs["cf-cache-status"]:
        cs = cache_hdrs["cf-cache-status"].upper()
    elif cache_hdrs["x-cache"]:
        xc = cache_hdrs["x-cache"].upper()
        if "HIT" in xc:
            cs = "HIT"
        elif "MISS" in xc:
            cs = "MISS"
        else:
            cs = xc[:20]
    elif cache_hdrs["x-akamai-cache-status"]:
        cs = cache_hdrs["x-akamai-cache-status"].upper()

    result["cache_status"] = cs
    result["cache_age"] = cache_hdrs["age"]
    result["cache_control"] = cache_hdrs["cache-control"]

    # 4. Match against WAF/CDN signatures
    detected_wafs = []
    detected_cdns = []
    server_hdr = resp_headers.get("server", "").lower()

    for sig in _WAF_CDN_SIGNATURES:
        matched = False
        # Check response headers
        for hdr_key, hdr_val in sig["headers"].items():
            if hdr_key in resp_headers:
                if not hdr_val or hdr_val in resp_headers[hdr_key]:
                    matched = True
                    result["headers_matched"].append(f"{sig['name']}:{hdr_key}")
                    break
        # Check server header substring (e.g. "akamai" in "akamaighost")
        if not matched and server_hdr and "server_contains" in sig:
            for fragment in sig["server_contains"]:
                if fragment in server_hdr:
                    matched = True
                    result["headers_matched"].append(f"{sig['name']}:server~{fragment}")
                    break
        # Check cookie hints (from set-cookie header)
        if not matched and "cookie_hints" in sig:
            cookie_hdr = resp_headers.get("set-cookie", "")
            for cookie_pat in sig["cookie_hints"]:
                if cookie_pat.lower() in cookie_hdr:
                    matched = True
                    result["headers_matched"].append(f"{sig['name']}:cookie~{cookie_pat}")
                    break
        # Check CNAME hints
        if not matched and result["cname"]:
            for hint in sig.get("cname_hints", []):
                if hint in result["cname"]:
                    matched = True
                    result["headers_matched"].append(f"{sig['name']}:cname={hint}")
                    break
        if matched:
            if sig["waf"] and sig["waf"] not in detected_wafs:
                detected_wafs.append(sig["waf"])
            if sig["cdn"] and sig["cdn"] not in detected_cdns:
                detected_cdns.append(sig["cdn"])

    result["waf"] = detected_wafs[0] if detected_wafs else None
    result["cdn"] = detected_cdns[0] if detected_cdns else None
    result["waf_all"] = detected_wafs
    result["cdn_all"] = detected_cdns

    # IP-based fallback for CDN only (if no header/CNAME match)
    if not result["cdn"] and result["ip"]:
        for provider, prefixes in _CLOUD_PROVIDERS.items():
            for prefix in prefixes:
                if result["ip"].startswith(prefix):
                    result["cdn"] = provider
                    break
            if result["cdn"]:
                break

    return result


def analyze_cloud_distribution(subdomains: List[str],
                                dns_data: Dict[str, Any],
                                timeout: float = 3.0) -> Dict[str, Any]:
    """Map subdomain IPs to cloud/CDN providers and fingerprint WAF per subdomain.

    Performs both IP-based classification and HTTP header fingerprinting
    to detect WAF vendor, CDN provider, and CNAME chain per subdomain.

    Args:
        subdomains: List of discovered subdomain FQDNs.
        dns_data: Output from check_dns() (uses A records for parent domain).
        timeout: Resolution + HTTP timeout per subdomain.

    Returns:
        Dict with 'per_subdomain', 'waf_distribution', 'cdn_distribution',
        'multi_waf', 'multi_cdn', 'providers', 'primary_provider'.
    """
    import concurrent.futures

    per_subdomain: List[Dict[str, Any]] = []
    waf_counts: Dict[str, int] = {}
    cdn_counts: Dict[str, int] = {}

    # Resolve subdomains in parallel (cap at 200 for better coverage)
    candidates = list(subdomains)[:200]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fingerprint_waf_cdn, s, timeout): s
                   for s in candidates}
        for f in concurrent.futures.as_completed(futures):
            fqdn = futures[f]
            try:
                info = f.result()
                entry = {
                    "subdomain": fqdn,
                    "ip": info.get("ip"),
                    "cname": info.get("cname"),
                    "waf": info.get("waf"),
                    "cdn": info.get("cdn"),
                    "server": info.get("server"),
                    "status": info.get("status"),
                    "cache_status": info.get("cache_status"),
                    "cache_age": info.get("cache_age"),
                }
                per_subdomain.append(entry)

                waf = info.get("waf")
                cdn = info.get("cdn")
                if waf:
                    waf_counts[waf] = waf_counts.get(waf, 0) + 1
                if cdn:
                    cdn_counts[cdn] = cdn_counts.get(cdn, 0) + 1
            except Exception:
                pass

    # Sort per_subdomain by name
    per_subdomain.sort(key=lambda x: x["subdomain"])

    total = len(per_subdomain)
    sorted_wafs = sorted(waf_counts.items(), key=lambda x: -x[1])
    sorted_cdns = sorted(cdn_counts.items(), key=lambda x: -x[1])

    waf_dist = {}
    for name, count in sorted_wafs:
        pct = round(count / total * 100, 1) if total else 0
        waf_dist[name] = {"count": count, "pct": pct}

    cdn_dist = {}
    for name, count in sorted_cdns:
        pct = round(count / total * 100, 1) if total else 0
        cdn_dist[name] = {"count": count, "pct": pct}

    return {
        "per_subdomain": per_subdomain,
        "total_probed": total,
        "waf_distribution": waf_dist,
        "cdn_distribution": cdn_dist,
        "waf_vendors": [w[0] for w in sorted_wafs],
        "cdn_vendors": [c[0] for c in sorted_cdns],
        "multi_waf": len(sorted_wafs) > 1,
        "multi_cdn": len(sorted_cdns) > 1,
        "primary_waf": sorted_wafs[0][0] if sorted_wafs else None,
        "primary_cdn": sorted_cdns[0][0] if sorted_cdns else None,
    }
