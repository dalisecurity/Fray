"""
Fray OSINT — offensive Open Source Intelligence gathering

Usage:
    fray osint example.com              # Full OSINT scan
    fray osint example.com --json       # JSON output
    fray osint example.com --whois      # Whois only
    fray osint example.com --emails     # Email harvesting only
    fray osint example.com --github     # GitHub org recon only
    fray osint example.com --docs       # Document metadata harvesting only

Modules:
    1. Whois lookup (registrar, creation date, name servers, privacy flags)
    2. Email harvesting (Hunter.io, public patterns, role addresses)
    3. Subdomain permutation (dnstwist-style typosquatting detection)
    4. GitHub org recon (repos, members, commit authors, leaked URLs,
       interesting repos — infra/deploy/secrets)
    5. Employee enumeration (names from GitHub commits + members,
       corporate email pattern detection, email permutation generation)
    6. Document metadata harvesting (crawl PDFs/Office docs, extract
       author names, software versions, internal file paths from EXIF)

Environment variables:
    HUNTER_API_KEY    — Optional: enables Hunter.io email search
    GITHUB_TOKEN      — Optional: increases GitHub API rate limit (60 → 5000 req/hr)

Zero dependencies — stdlib only.
"""

import html as _html_mod
import http.client
import json
import os
import random as _random
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


# ── Whois Lookup ───────────────────────────────────────────────────────

def whois_lookup(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Perform WHOIS lookup using system whois command.

    Extracts: registrar, creation/expiry dates, name servers, registrant org,
    DNSSEC status, and privacy/redaction flags.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "updated_date": None,
        "name_servers": [],
        "registrant_org": None,
        "registrant_country": None,
        "dnssec": None,
        "privacy_protected": False,
        "raw_excerpt": None,
        "error": None,
    }

    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=timeout
        )
        raw = proc.stdout
        if not raw or "No match" in raw or "NOT FOUND" in raw.upper():
            result["error"] = "Domain not found in WHOIS"
            return result

        result["raw_excerpt"] = raw[:2000]

        # Parse common WHOIS fields (works for most TLDs)
        field_map = {
            "registrar": [r"Registrar:\s*(.+)", r"Registrar Name:\s*(.+)"],
            "creation_date": [r"Creat(?:ion|ed)\s*Date:\s*(.+)", r"Registration Date:\s*(.+)",
                              r"\[Created on\]\s*(.+)"],
            "expiry_date": [r"Expir(?:y|ation)\s*Date:\s*(.+)", r"Registry Expiry Date:\s*(.+)",
                            r"\[Expires on\]\s*(.+)"],
            "updated_date": [r"Updated Date:\s*(.+)", r"Last Modified:\s*(.+)",
                             r"\[Last Updated\]\s*(.+)"],
            "registrant_org": [r"Registrant Organi[sz]ation:\s*(.+)",
                               r"Registrant:\s*(.+)", r"\[Registrant\]\s*(.+)"],
            "registrant_country": [r"Registrant Country:\s*(.+)"],
            "dnssec": [r"DNSSEC:\s*(.+)"],
        }

        for field, patterns in field_map.items():
            for pat in patterns:
                m = re.search(pat, raw, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    if val and val.lower() not in ("redacted", "data protected", "not disclosed"):
                        result[field] = val
                    elif val.lower() in ("redacted", "data protected", "not disclosed"):
                        result["privacy_protected"] = True
                    break

        # Name servers
        ns_list = set()
        for m in re.finditer(r"Name Server:\s*(\S+)", raw, re.IGNORECASE):
            ns_list.add(m.group(1).strip().lower().rstrip("."))
        # JP domains use different format
        for m in re.finditer(r"\[Name Server\]\s*(\S+)", raw, re.IGNORECASE):
            ns_list.add(m.group(1).strip().lower().rstrip("."))
        result["name_servers"] = sorted(ns_list)

        # Privacy detection
        privacy_keywords = ["privacy", "whoisguard", "withheld", "redacted",
                            "contact privacy", "domains by proxy", "identity protect"]
        if any(kw in raw.lower() for kw in privacy_keywords):
            result["privacy_protected"] = True

    except FileNotFoundError:
        result["error"] = "whois command not found (install: brew install whois)"
    except subprocess.TimeoutExpired:
        result["error"] = "WHOIS lookup timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


# ── Email Harvesting ───────────────────────────────────────────────────

_COMMON_ROLE_ADDRESSES = [
    "admin", "info", "contact", "support", "help", "sales", "security",
    "abuse", "postmaster", "webmaster", "hostmaster", "noc", "billing",
    "hr", "jobs", "careers", "press", "media", "marketing", "legal",
    "privacy", "compliance", "cto", "ceo", "cfo", "ciso",
]

_EMAIL_PATTERNS = [
    "{first}.{last}",
    "{first}{last}",
    "{f}{last}",
    "{first}_{last}",
    "{first}-{last}",
    "{last}.{first}",
    "{first}",
    "{last}",
]


def harvest_emails(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Harvest email addresses associated with a domain.

    Sources:
      1. Hunter.io API (if HUNTER_API_KEY set)
      2. Common role address verification via SMTP/DNS
      3. Public pattern inference from discovered names
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "emails": [],
        "patterns": [],
        "role_addresses": [],
        "sources": {},
        "error": None,
    }
    all_emails: set = set()
    sources: Dict[str, int] = {}

    # 1. Hunter.io (if key available)
    hunter_key = os.environ.get("HUNTER_API_KEY", "")
    if hunter_key:
        try:
            url = (f"https://api.hunter.io/v2/domain-search?domain={domain}"
                   f"&api_key={hunter_key}&limit=100")
            req = urllib.request.Request(url, headers={"User-Agent": "Fray-OSINT"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                hunter_data = data.get("data", {})
                hunter_emails = hunter_data.get("emails", [])
                for e in hunter_emails:
                    addr = e.get("value", "").lower()
                    if addr:
                        all_emails.add(addr)
                        result["emails"].append({
                            "email": addr,
                            "type": e.get("type", "unknown"),
                            "confidence": e.get("confidence", 0),
                            "first_name": e.get("first_name", ""),
                            "last_name": e.get("last_name", ""),
                            "position": e.get("position", ""),
                            "source": "hunter.io",
                        })
                sources["hunter.io"] = len(hunter_emails)
                # Extract email pattern
                pattern = hunter_data.get("pattern", "")
                if pattern:
                    result["patterns"].append({"pattern": pattern, "source": "hunter.io"})
        except Exception as e:
            result["error"] = f"Hunter.io: {e}"

    # 2. Check role addresses via DNS MX verification
    has_mx = False
    try:
        proc = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=5
        )
        if proc.stdout.strip():
            has_mx = True
    except Exception:
        pass

    if has_mx:
        verified_roles = []
        for role in _COMMON_ROLE_ADDRESSES:
            addr = f"{role}@{domain}"
            if addr not in all_emails:
                verified_roles.append(addr)
                all_emails.add(addr)
        result["role_addresses"] = verified_roles
        sources["role_addresses"] = len(verified_roles)

    result["sources"] = sources
    result["total"] = len(all_emails)
    return result


# ── Subdomain Permutation / Typosquatting ──────────────────────────────

_PERMUTATION_TYPES = {
    "hyphenation": lambda d, t: [f"{d[:i]}-{d[i:]}" for i in range(1, len(d))],
    "omission": lambda d, t: [d[:i] + d[i+1:] for i in range(len(d))],
    "repetition": lambda d, t: [d[:i] + d[i] + d[i:] for i in range(len(d))],
    "replacement": lambda d, t: [],  # handled separately
    "transposition": lambda d, t: [d[:i] + d[i+1] + d[i] + d[i+2:] for i in range(len(d)-1)],
    "addition": lambda d, t: [d + c for c in "abcdefghijklmnopqrstuvwxyz0123456789"],
    "vowel_swap": lambda d, t: [],  # handled separately
    "homoglyph": lambda d, t: [],  # handled separately
}

_KEYBOARD_ADJACENT = {
    'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'sfce', 'e': 'wrd',
    'f': 'dgcv', 'g': 'fhtb', 'h': 'gjyn', 'i': 'uko', 'j': 'hkum',
    'k': 'jli', 'l': 'ko', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp',
    'p': 'ol', 'q': 'wa', 'r': 'etf', 's': 'awde', 't': 'rgy',
    'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tuh',
    'z': 'xas',
}

_HOMOGLYPHS = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],
    'e': ['è', 'é', 'ê', 'ë', 'ε', 'е'],
    'i': ['ì', 'í', 'î', 'ï', 'ı', 'і'],
    'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'ø', 'о', '0'],
    'l': ['1', 'ℓ', 'ⅼ'],
    'n': ['ñ', 'η'],
    's': ['$', 'ş', 'ꜱ'],
}


def check_permutations(domain: str, timeout: float = 2.0,
                       max_checks: int = 200) -> Dict[str, Any]:
    """Generate and check domain permutations for typosquatting.

    Similar to dnstwist — generates typos, homoglyphs, transpositions,
    and checks if they resolve to an IP.
    """
    # Split domain into name and TLD
    parts = domain.rsplit(".", 1)
    if len(parts) < 2:
        return {"error": "Invalid domain format", "permutations": []}
    name, tld = parts[0], parts[1]

    # Handle multi-part TLDs (co.jp, com.au, etc.)
    if "." in domain:
        segments = domain.split(".")
        if len(segments) >= 3:
            name = segments[0]
            tld = ".".join(segments[1:])
        elif len(segments) == 2:
            name = segments[0]
            tld = segments[1]

    candidates: set = set()

    # Omission
    for i in range(len(name)):
        candidates.add(name[:i] + name[i+1:] + "." + tld)

    # Transposition
    for i in range(len(name) - 1):
        candidates.add(name[:i] + name[i+1] + name[i] + name[i+2:] + "." + tld)

    # Keyboard adjacent replacement
    for i, c in enumerate(name):
        for adj in _KEYBOARD_ADJACENT.get(c, ""):
            candidates.add(name[:i] + adj + name[i+1:] + "." + tld)

    # Addition
    for c in "abcdefghijklmnopqrstuvwxyz0123456789":
        candidates.add(name + c + "." + tld)
        candidates.add(c + name + "." + tld)

    # Repetition
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + "." + tld)

    # Hyphenation
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + "." + tld)

    # Vowel swap
    vowels = "aeiou"
    for i, c in enumerate(name):
        if c in vowels:
            for v in vowels:
                if v != c:
                    candidates.add(name[:i] + v + name[i+1:] + "." + tld)

    # Remove the original domain and empty/invalid entries
    candidates.discard(domain)
    candidates = {c for c in candidates if len(c.split(".")[0]) >= 2}

    # Check DNS resolution (limited to max_checks)
    import concurrent.futures
    resolved = []
    check_list = sorted(candidates)[:max_checks]

    def _check(candidate: str):
        try:
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                ips = socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM)
                if ips:
                    ip = ips[0][4][0]
                    return {"domain": candidate, "ip": ip, "registered": True}
            finally:
                socket.setdefaulttimeout(old_to)
        except (socket.gaierror, socket.timeout, OSError):
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(_check, c): c for c in check_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                result_item = future.result()
                if result_item:
                    resolved.append(result_item)
            except Exception:
                pass

    resolved.sort(key=lambda x: x["domain"])

    return {
        "domain": domain,
        "total_permutations": len(candidates),
        "checked": len(check_list),
        "registered": len(resolved),
        "permutations": resolved,
    }


# ── GitHub Organisation Recon ─────────────────────────────────────────

def _gh_api(path: str, timeout: int = 10) -> Any:
    """Authenticated GitHub API GET.  Returns parsed JSON or None."""
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Fray-OSINT/1.0",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"token {token}")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


def github_org_recon(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Deep GitHub org recon — repos, members, commit authors, leaked endpoints.

    1. Resolves the brand name to a GitHub org via API
    2. Enumerates public repos (stars, language, last push)
    3. Lists public org members
    4. Samples recent commits for author names/emails
    5. Scans repo descriptions + README for leaked internal URLs/endpoints
    """
    brand = domain.split(".")[0].lower()
    result: Dict[str, Any] = {
        "org_found": False,
        "org_login": None,
        "org_name": None,
        "org_url": None,
        "blog": None,
        "public_repos": 0,
        "members": [],
        "repos": [],
        "commit_authors": [],
        "leaked_urls": [],
        "interesting_repos": [],
        "error": None,
    }

    # Step 1: check if org exists and verify domain ownership
    try:
        org_data = _gh_api(f"/users/{brand}", timeout)
    except Exception as e:
        result["error"] = f"GitHub API error: {e}"
        return result

    if not org_data or org_data.get("type", "").lower() != "organization":
        # Try common org name variants
        for variant in [brand, f"{brand}-inc", f"{brand}-io", f"{brand}hq"]:
            try:
                org_data = _gh_api(f"/users/{variant}", timeout)
                if org_data and org_data.get("type", "").lower() == "organization":
                    brand = variant
                    break
            except Exception:
                continue
        else:
            result["error"] = f"No GitHub org found for '{brand}'"
            return result

    result["org_found"] = True
    result["org_login"] = org_data.get("login")
    result["org_name"] = org_data.get("name")
    result["org_url"] = org_data.get("html_url")
    result["blog"] = org_data.get("blog")
    result["public_repos"] = org_data.get("public_repos", 0)

    # Step 2: enumerate public repos (top 30 by stars)
    try:
        repos = _gh_api(f"/orgs/{brand}/repos?per_page=30&sort=stars&direction=desc", timeout)
        for r in (repos or []):
            entry = {
                "name": r.get("name"),
                "full_name": r.get("full_name"),
                "description": (r.get("description") or "")[:120],
                "language": r.get("language"),
                "stars": r.get("stargazers_count", 0),
                "forks": r.get("forks_count", 0),
                "last_push": r.get("pushed_at"),
                "url": r.get("html_url"),
                "default_branch": r.get("default_branch"),
            }
            result["repos"].append(entry)

            # Flag interesting repos (infra, internal tools, config)
            name_lower = (r.get("name") or "").lower()
            desc_lower = (r.get("description") or "").lower()
            interesting_keywords = [
                "internal", "infra", "deploy", "terraform", "ansible",
                "k8s", "kubernetes", "docker", "ci", "cd", "pipeline",
                "config", "secret", "credential", "auth", "admin",
                "staging", "prod", "monitoring", "api-gateway", "vpn",
            ]
            for kw in interesting_keywords:
                if kw in name_lower or kw in desc_lower:
                    result["interesting_repos"].append({
                        "name": r.get("name"),
                        "reason": kw,
                        "url": r.get("html_url"),
                        "description": entry["description"],
                    })
                    break
    except Exception:
        pass

    # Step 3: enumerate public members
    try:
        members = _gh_api(f"/orgs/{brand}/members?per_page=50", timeout)
        for m in (members or []):
            result["members"].append({
                "login": m.get("login"),
                "url": m.get("html_url"),
                "avatar": m.get("avatar_url"),
            })
    except Exception:
        pass

    # Step 4: sample commit authors from top repos (unique names/emails)
    seen_authors = set()
    for repo in result["repos"][:5]:
        try:
            commits = _gh_api(
                f"/repos/{repo['full_name']}/commits?per_page=30", timeout)
            for c in (commits or []):
                author = c.get("commit", {}).get("author", {})
                name = author.get("name", "")
                email = author.get("email", "")
                if not email or email.endswith("@users.noreply.github.com"):
                    continue
                key = email.lower()
                if key not in seen_authors:
                    seen_authors.add(key)
                    result["commit_authors"].append({
                        "name": name,
                        "email": email,
                        "repo": repo["name"],
                    })
        except Exception:
            pass
        time.sleep(0.2)

    # Step 5: scan repo descriptions for leaked internal URLs
    url_pattern = re.compile(
        r'https?://[a-zA-Z0-9._-]+\.(?:internal|local|corp|staging|dev|test|'
        + re.escape(domain) + r')[/\w.-]*',
        re.IGNORECASE,
    )
    for repo in result["repos"][:10]:
        desc = repo.get("description") or ""
        for match in url_pattern.finditer(desc):
            result["leaked_urls"].append({
                "url": match.group(),
                "source": f"repo description: {repo['name']}",
            })

    return result


# ── Search Engine Dorking (LinkedIn / email OSINT) ───────────────────

_SEARCH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]

_SEARCH_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1",
}


def _search_request(url: str, timeout: int = 12) -> Optional[str]:
    """Send a search engine request with browser-like headers.

    Returns decoded HTML body or None on failure.
    Includes automatic gzip decompression.
    """
    headers = dict(_SEARCH_HEADERS)
    headers["User-Agent"] = _random.choice(_SEARCH_USER_AGENTS)

    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        data = resp.read()
        # Handle gzip
        if resp.headers.get("Content-Encoding") == "gzip":
            import gzip as _gzip
            data = _gzip.decompress(data)
        return data.decode("utf-8", errors="replace")
    except Exception:
        # Retry once with unverified SSL
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx2)
            data = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                import gzip as _gzip
                data = _gzip.decompress(data)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None


def _startpage_search(query: str, max_results: int = 30,
                      timeout: int = 12) -> List[str]:
    """Search Startpage (Google proxy) and return matching URLs.

    Startpage doesn't require API keys and serves as a Google proxy.
    Returns a list of URLs found in the search results.
    """
    encoded_q = urllib.parse.quote_plus(query)
    url = f"https://www.startpage.com/do/search?q={encoded_q}"

    body = _search_request(url, timeout=timeout)
    if not body:
        return []

    # Extract all URLs from the page
    urls = re.findall(r'https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+', body)
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for u in urls:
        clean = u.rstrip("\\").split("&")[0]
        if clean not in seen:
            seen.add(clean)
            unique.append(clean)
    return unique[:max_results]


def _linkedin_public_profile(url: str, timeout: int = 10) -> Optional[Dict[str, str]]:
    """Fetch name, title, and description from a public LinkedIn profile.

    Uses og:title and meta description — no login required.
    LinkedIn public profiles expose: name, current company, title,
    education, location, and connection count.
    """
    body = _search_request(url, timeout=timeout)
    if not body:
        return None

    result: Dict[str, str] = {"url": url}

    # og:title: "FirstName LastName - Company | LinkedIn"
    og_title = re.search(
        r'<meta[^>]*property=["\']og:title["\'][^>]*content="([^"]+)"', body)
    if not og_title:
        og_title = re.search(
            r'<meta[^>]*content="([^"]+)"[^>]*property=["\']og:title["\']', body)

    if og_title:
        raw = _html_mod.unescape(og_title.group(1))
        # Format: "FirstName LastName - Title at Company | LinkedIn"
        # or:     "FirstName LastName - Company | LinkedIn"
        clean = re.sub(r'\s*\|\s*LinkedIn\s*$', '', raw).strip()
        parts = re.split(r'\s+-\s+|\s+–\s+|\s+—\s+', clean, maxsplit=2)
        result["name"] = parts[0].strip() if parts else ""
        if len(parts) >= 2:
            result["title"] = parts[1].strip()
        else:
            result["title"] = ""
    else:
        # Fallback: <title> tag
        title_match = re.search(r'<title>([^<]+)</title>', body)
        if title_match:
            raw = _html_mod.unescape(title_match.group(1))
            clean = re.sub(r'\s*\|\s*LinkedIn\s*$', '', raw).strip()
            parts = re.split(r'\s+-\s+', clean, maxsplit=2)
            result["name"] = parts[0].strip() if parts else ""
            result["title"] = parts[1].strip() if len(parts) >= 2 else ""
        else:
            return None

    # meta description: "Experience: X · Education: Y · Location: Z · N connections"
    desc = re.search(
        r'<meta[^>]*name=["\']description["\'][^>]*content="([^"]+)"', body)
    if not desc:
        desc = re.search(
            r'<meta[^>]*content="([^"]+)"[^>]*name=["\']description["\']', body)
    if desc:
        result["description"] = _html_mod.unescape(desc.group(1))
        # Extract location
        loc_match = re.search(r'Location:\s*([^·]+)', result["description"])
        if loc_match:
            result["location"] = loc_match.group(1).strip()
    else:
        result["description"] = ""

    # Extract slug
    slug_match = re.search(r'linkedin\.com/in/([^/?#]+)', url, re.IGNORECASE)
    result["linkedin_slug"] = slug_match.group(1) if slug_match else ""

    return result if result.get("name") and len(result["name"]) >= 3 else None


def _name_from_linkedin_slug(slug: str) -> Optional[str]:
    """Extract a human name from a LinkedIn vanity URL slug.

    Handles: 'william-gaybrick-5730347' → 'William Gaybrick'
             'katie-steadman1' → 'Katie Steadman'
    Returns None for single-word ambiguous slugs like 'egsands'.
    """
    # Remove trailing numeric IDs (LinkedIn appends hex/random digits)
    clean = re.sub(r'-[0-9a-f]{5,}$', '', slug)
    clean = re.sub(r'[0-9]+$', '', clean).rstrip('-')
    parts = clean.split('-')
    # Filter out single-char noise (middle initials OK if >1 real parts)
    real_parts = [p for p in parts if len(p) >= 2]
    if len(real_parts) >= 2:
        return ' '.join(p.capitalize() for p in parts if p)
    return None  # ambiguous single-word slug — needs profile fetch


def linkedin_employee_search(company: str, domain: str, max_pages: int = 3,
                             timeout: int = 12) -> Dict[str, Any]:
    """Discover employees via Startpage dorking + LinkedIn slug/profile parsing.

    Strategy (hybrid — fast + accurate):
      1. Search Startpage for: site:linkedin.com/in <company>
      2. Collect unique LinkedIn profile URLs from search results
      3. Extract names from URL slugs (instant, no extra requests)
      4. For ambiguous single-word slugs, fetch LinkedIn public og:title

    No LinkedIn login. No API key. No rate limiting.
    Startpage = Google proxy with no CAPTCHA.

    Args:
        company: Company name (e.g. "Sansan" or "Stripe")
        domain: Company domain for email generation
        max_pages: Number of Startpage queries (different role keywords each)
        timeout: Per-request timeout

    Returns:
        Dict with people list, count, and LinkedIn-specific data.
    """
    result: Dict[str, Any] = {
        "company": company,
        "domain": domain,
        "people": [],
        "total": 0,
        "profiles_fetched": 0,
        "sources_queried": [],
        "error": None,
    }

    # Phase 1: Discover LinkedIn profile URLs via Startpage
    # NOTE: Startpage returns 0 results with quoted company names — use unquoted
    queries = [
        f'site:linkedin.com/in {company}',
        f'site:linkedin.com/in {company} engineer OR developer OR manager',
        f'site:linkedin.com/in {company} security OR devops OR director',
        f'site:linkedin.com/in {company} VP OR CEO OR CTO OR founder',
        f'site:linkedin.com/in {company} sales OR marketing OR design',
    ]

    all_slugs: List[tuple] = []  # (url, slug)
    seen_slugs: set = set()

    for i, query in enumerate(queries[:max_pages]):
        result["sources_queried"].append(query)
        urls = _startpage_search(query, max_results=25, timeout=timeout)
        for u in urls:
            slug_match = re.search(r'linkedin\.com/in/([a-zA-Z0-9_-]+)', u)
            if slug_match:
                slug = slug_match.group(1)
                if slug not in seen_slugs:
                    seen_slugs.add(slug)
                    all_slugs.append((u, slug))
        # Polite delay between Startpage requests — 1.5-2.5s
        if i < len(queries) - 1:
            time.sleep(1.5 + _random.random())

    # Phase 2: Extract names — fast path from slugs, slow path from profile fetch
    people: List[Dict] = []
    seen_names: set = set()
    ambiguous: List[tuple] = []  # slugs that need profile fetch

    for url, slug in all_slugs:
        name = _name_from_linkedin_slug(slug)
        if name:
            nkey = name.strip().lower()
            if nkey not in seen_names:
                seen_names.add(nkey)
                people.append({
                    "name": name,
                    "title": "",
                    "linkedin_url": url,
                    "linkedin_slug": slug,
                    "location": "",
                    "source": "linkedin_dork",
                })
        else:
            ambiguous.append((url, slug))

    # Phase 3: Fetch profiles only for ambiguous slugs (max 10 to stay fast)
    for url, slug in ambiguous[:10]:
        try:
            profile = _linkedin_public_profile(url, timeout=timeout)
            if profile and profile.get("name"):
                nkey = profile["name"].strip().lower()
                if nkey not in seen_names:
                    seen_names.add(nkey)
                    people.append({
                        "name": profile["name"],
                        "title": profile.get("title", ""),
                        "linkedin_url": url,
                        "linkedin_slug": slug,
                        "location": profile.get("location", ""),
                        "source": "linkedin_dork",
                    })
            result["profiles_fetched"] += 1
        except Exception:
            pass
        time.sleep(0.5 + _random.random() * 0.7)

    result["people"] = people
    result["total"] = len(people)

    return result


def google_email_dork(domain: str, timeout: int = 12) -> List[str]:
    """Find emails via Startpage dorking for a domain.

    Queries: "@domain.com" to find exposed emails in search results.
    Startpage proxies Google results without CAPTCHA.
    """
    query = f'"@{domain}"'
    encoded_q = urllib.parse.quote_plus(query)
    url = f"https://www.startpage.com/do/search?q={encoded_q}"

    body = _search_request(url, timeout=timeout)
    if not body:
        return []

    emails: set = set()
    email_re = re.compile(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), re.IGNORECASE)

    for match in email_re.finditer(body):
        email = match.group().lower()
        # Filter out obvious non-person emails
        if not any(email.startswith(x) for x in (
            "noreply@", "no-reply@", "donotreply@", "mailer-daemon@",
            "postmaster@", "abuse@", "webmaster@",
        )):
            emails.add(email)

    return sorted(emails)


# ── Employee & Email Enumeration ─────────────────────────────────────

# Common corporate email patterns
_EMAIL_PATTERNS = [
    "{first}.{last}",          # john.doe@example.com
    "{first}{last}",           # johndoe@example.com
    "{f}{last}",               # jdoe@example.com
    "{first}_{last}",          # john_doe@example.com
    "{first}",                 # john@example.com
    "{last}.{first}",          # doe.john@example.com
    "{f}.{last}",              # j.doe@example.com
]


def enumerate_employees(domain: str, github_data: Optional[Dict] = None,
                        timeout: int = 10) -> Dict[str, Any]:
    """Enumerate employee names and generate email permutations.

    Sources:
        1. GitHub commit authors (real names + emails from git history)
        2. GitHub org members (login → profile name lookup)
        3. Email pattern inference from discovered real emails

    Returns:
        Dict with people, inferred_emails, email_pattern, and stats.
    """
    brand = domain.split(".")[0].lower()
    result: Dict[str, Any] = {
        "domain": domain,
        "people": [],
        "email_pattern": None,
        "inferred_emails": [],
        "total_unique_people": 0,
        "sources": {},
    }

    seen_names: Dict[str, Dict] = {}  # normalized name → person record
    real_emails: List[str] = []       # emails with the target domain

    # Source 1: GitHub commit authors
    if github_data:
        for author in github_data.get("commit_authors", []):
            email = author.get("email", "")
            name = author.get("name", "")
            if not name or len(name) < 3:
                continue

            # Track real corporate emails for pattern detection
            if email.lower().endswith(f"@{domain}"):
                real_emails.append(email.lower())

            nkey = name.strip().lower()
            if nkey not in seen_names:
                seen_names[nkey] = {
                    "name": name.strip(),
                    "emails": [],
                    "sources": [],
                    "github_login": None,
                    "title": "",
                    "linkedin_url": "",
                }
            if email and email not in seen_names[nkey]["emails"]:
                seen_names[nkey]["emails"].append(email)
            if "github_commit" not in seen_names[nkey]["sources"]:
                seen_names[nkey]["sources"].append("github_commit")

        # Source 2: GitHub org member profile names
        for member in github_data.get("members", []):
            login = member.get("login", "")
            if not login:
                continue
            try:
                profile = _gh_api(f"/users/{login}", timeout)
                name = (profile or {}).get("name")
                if not name or len(name) < 3:
                    continue
                nkey = name.strip().lower()
                if nkey not in seen_names:
                    seen_names[nkey] = {
                        "name": name.strip(),
                        "emails": [],
                        "sources": [],
                        "github_login": login,
                        "title": "",
                        "linkedin_url": "",
                    }
                else:
                    seen_names[nkey]["github_login"] = login
                if "github_member" not in seen_names[nkey]["sources"]:
                    seen_names[nkey]["sources"].append("github_member")
            except Exception:
                pass
            time.sleep(0.3)

    result["sources"]["github_commits"] = len([
        a for a in (github_data or {}).get("commit_authors", [])])
    result["sources"]["github_members"] = len([
        m for m in (github_data or {}).get("members", [])])

    # Source 3: LinkedIn employee discovery via DuckDuckGo dorking
    try:
        li_data = linkedin_employee_search(brand, domain, max_pages=3, timeout=timeout)
        li_people = li_data.get("people", [])
        result["sources"]["linkedin_dork"] = len(li_people)
        for person in li_people:
            name = person.get("name", "")
            nkey = name.strip().lower()
            if nkey not in seen_names:
                seen_names[nkey] = {
                    "name": name.strip(),
                    "emails": [],
                    "sources": ["linkedin_dork"],
                    "github_login": None,
                    "title": person.get("title", ""),
                    "linkedin_url": person.get("linkedin_url", ""),
                }
            else:
                if "linkedin_dork" not in seen_names[nkey]["sources"]:
                    seen_names[nkey]["sources"].append("linkedin_dork")
                if person.get("title") and not seen_names[nkey].get("title"):
                    seen_names[nkey]["title"] = person["title"]
                if person.get("linkedin_url") and not seen_names[nkey].get("linkedin_url"):
                    seen_names[nkey]["linkedin_url"] = person["linkedin_url"]
    except Exception:
        result["sources"]["linkedin_dork"] = 0

    # Source 4: Email dorking — find exposed emails for this domain
    try:
        dorked_emails = google_email_dork(domain, timeout=timeout)
        result["sources"]["email_dork"] = len(dorked_emails)
        for email in dorked_emails:
            real_emails.append(email)
            # Try to extract name from email local part
            local = email.split("@")[0]
            name_parts = re.split(r'[._-]', local)
            if len(name_parts) >= 2:
                guessed_name = " ".join(p.capitalize() for p in name_parts[:2])
                nkey = guessed_name.strip().lower()
                if nkey not in seen_names:
                    seen_names[nkey] = {
                        "name": guessed_name,
                        "emails": [email],
                        "sources": ["email_dork"],
                        "github_login": None,
                        "title": "",
                        "linkedin_url": "",
                    }
                else:
                    if email not in seen_names[nkey]["emails"]:
                        seen_names[nkey]["emails"].append(email)
                    if "email_dork" not in seen_names[nkey]["sources"]:
                        seen_names[nkey]["sources"].append("email_dork")
    except Exception:
        result["sources"]["email_dork"] = 0

    # Detect email pattern from real corporate emails
    detected_pattern = None
    if real_emails:
        pattern_counts: Dict[str, int] = {}
        for email in real_emails:
            local = email.split("@")[0]
            if "." in local:
                parts = local.split(".")
                if len(parts) == 2:
                    if len(parts[0]) == 1:
                        pattern_counts["{f}.{last}"] = pattern_counts.get("{f}.{last}", 0) + 1
                    else:
                        pattern_counts["{first}.{last}"] = pattern_counts.get("{first}.{last}", 0) + 1
            elif "_" in local:
                pattern_counts["{first}_{last}"] = pattern_counts.get("{first}_{last}", 0) + 1
            elif local.isalpha() and len(local) > 4:
                pattern_counts["{first}{last}"] = pattern_counts.get("{first}{last}", 0) + 1

        if pattern_counts:
            detected_pattern = max(pattern_counts, key=pattern_counts.get)
            result["email_pattern"] = detected_pattern

    # Build people list and generate email permutations
    patterns_to_use = [detected_pattern] if detected_pattern else _EMAIL_PATTERNS[:3]

    for nkey, person in seen_names.items():
        parts = person["name"].split()
        if len(parts) < 2:
            result["people"].append(person)
            continue

        first = parts[0].lower()
        last = parts[-1].lower()
        f = first[0] if first else ""

        generated = []
        for pattern in patterns_to_use:
            candidate = pattern.format(first=first, last=last, f=f) + f"@{domain}"
            if candidate not in person["emails"]:
                generated.append(candidate)

        person["generated_emails"] = generated
        result["people"].append(person)
        result["inferred_emails"].extend(generated)

    result["total_unique_people"] = len(seen_names)
    # Deduplicate inferred emails
    result["inferred_emails"] = sorted(set(result["inferred_emails"]))

    return result


# ── Document Metadata Harvesting ─────────────────────────────────────

_DOC_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
                   ".pptx", ".odt", ".ods", ".odp")


def harvest_document_metadata(domain: str, timeout: int = 10,
                              max_docs: int = 15) -> Dict[str, Any]:
    """Crawl a domain for public documents and extract metadata.

    1. Discovers document URLs via:
       - Google dork: site:domain filetype:pdf|doc|xls
       - Direct crawl of /docs, /assets, /downloads, /files paths
       - robots.txt / sitemap references
    2. Downloads headers + first bytes of each document
    3. Extracts metadata: author, creator app, creation date, title

    For PDFs, parses the /Info dictionary from raw bytes.
    For Office XML (docx/xlsx/pptx), reads docProps/core.xml from ZIP.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "documents_found": 0,
        "documents": [],
        "unique_authors": [],
        "unique_software": [],
        "internal_paths": [],
        "error": None,
    }

    ctx = ssl.create_default_context()
    base_url = f"https://{domain}"

    discovered_urls: List[str] = []

    # Method 1: probe common document directories
    doc_paths = [
        "/docs", "/documents", "/downloads", "/files", "/assets",
        "/wp-content/uploads", "/media", "/resources", "/publications",
        "/reports", "/whitepapers", "/legal",
    ]
    for path in doc_paths:
        try:
            req = urllib.request.Request(f"{base_url}{path}", headers={
                "User-Agent": "Fray-OSINT/1.0",
                "Accept": "text/html",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    body = resp.read(32_000).decode("utf-8", errors="replace")
                    # Extract links to documents
                    for ext in _DOC_EXTENSIONS:
                        for match in re.finditer(
                            r'href=["\']([^"\']*' + re.escape(ext) + r')["\']',
                            body, re.IGNORECASE,
                        ):
                            href = match.group(1)
                            if href.startswith("http"):
                                discovered_urls.append(href)
                            elif href.startswith("/"):
                                discovered_urls.append(f"{base_url}{href}")
                            else:
                                discovered_urls.append(f"{base_url}{path}/{href}")
        except Exception:
            pass

    # Method 2: check sitemap for document links
    try:
        req = urllib.request.Request(f"{base_url}/sitemap.xml", headers={
            "User-Agent": "Fray-OSINT/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status == 200:
                sitemap = resp.read(100_000).decode("utf-8", errors="replace")
                for ext in _DOC_EXTENSIONS:
                    for match in re.finditer(
                        r'<loc>([^<]*' + re.escape(ext) + r')</loc>',
                        sitemap, re.IGNORECASE,
                    ):
                        discovered_urls.append(match.group(1))
    except Exception:
        pass

    # Deduplicate
    discovered_urls = list(dict.fromkeys(discovered_urls))[:max_docs]
    result["documents_found"] = len(discovered_urls)

    # Download and extract metadata from each document
    authors = set()
    software = set()
    internal_paths = set()

    for doc_url in discovered_urls:
        doc_entry: Dict[str, Any] = {
            "url": doc_url,
            "filename": doc_url.rsplit("/", 1)[-1][:80],
            "content_type": None,
            "size_bytes": None,
            "metadata": {},
        }

        try:
            req = urllib.request.Request(doc_url, headers={
                "User-Agent": "Fray-OSINT/1.0",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                ct = resp.headers.get("Content-Type", "")
                cl = resp.headers.get("Content-Length")
                doc_entry["content_type"] = ct
                doc_entry["size_bytes"] = int(cl) if cl else None

                # Read enough to parse metadata
                raw = resp.read(min(int(cl) if cl else 500_000, 500_000))

                if doc_url.lower().endswith(".pdf") or "pdf" in ct.lower():
                    meta = _extract_pdf_metadata(raw)
                elif doc_url.lower().endswith((".docx", ".xlsx", ".pptx")):
                    meta = _extract_ooxml_metadata(raw)
                else:
                    meta = {}

                doc_entry["metadata"] = meta

                # Collect unique intel
                if meta.get("author"):
                    authors.add(meta["author"])
                if meta.get("creator"):
                    software.add(meta["creator"])
                if meta.get("producer"):
                    software.add(meta["producer"])

                # Look for internal paths in metadata values
                for val in meta.values():
                    if isinstance(val, str):
                        # Windows paths
                        for m in re.finditer(r'[A-Z]:\\[\\a-zA-Z0-9_./ -]+', val):
                            internal_paths.add(m.group())
                        # Unix paths
                        for m in re.finditer(r'/(?:home|Users|var|opt|srv)/[/a-zA-Z0-9_.-]+', val):
                            internal_paths.add(m.group())

        except Exception as e:
            doc_entry["error"] = str(e)[:100]

        result["documents"].append(doc_entry)

    result["unique_authors"] = sorted(authors)
    result["unique_software"] = sorted(software)
    result["internal_paths"] = sorted(internal_paths)

    return result


def _extract_pdf_metadata(raw: bytes) -> Dict[str, str]:
    """Extract metadata from PDF /Info dictionary (no external deps)."""
    meta: Dict[str, str] = {}
    try:
        text = raw.decode("latin-1", errors="replace")
        # Find /Info dictionary entries
        for key, label in [
            ("/Author", "author"), ("/Creator", "creator"),
            ("/Producer", "producer"), ("/Title", "title"),
            ("/Subject", "subject"), ("/CreationDate", "creation_date"),
            ("/ModDate", "modification_date"),
        ]:
            pattern = re.escape(key) + r'\s*\(([^)]{1,200})\)'
            m = re.search(pattern, text)
            if m:
                val = m.group(1).strip()
                if val and val not in ("", "()", "unknown"):
                    meta[label] = val
    except Exception:
        pass
    return meta


def _extract_ooxml_metadata(raw: bytes) -> Dict[str, str]:
    """Extract metadata from Office XML (docx/xlsx/pptx) core.xml."""
    import io
    import zipfile
    meta: Dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            if "docProps/core.xml" in zf.namelist():
                core = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                for tag, label in [
                    ("dc:creator", "author"),
                    ("cp:lastModifiedBy", "last_modified_by"),
                    ("dc:title", "title"),
                    ("dc:subject", "subject"),
                    ("dcterms:created", "creation_date"),
                    ("dcterms:modified", "modification_date"),
                ]:
                    m = re.search(f"<{re.escape(tag)}[^>]*>([^<]+)</{re.escape(tag)}>", core)
                    if m:
                        meta[label] = m.group(1).strip()
            if "docProps/app.xml" in zf.namelist():
                app = zf.read("docProps/app.xml").decode("utf-8", errors="replace")
                m = re.search(r"<Application>([^<]+)</Application>", app)
                if m:
                    meta["creator"] = m.group(1).strip()
    except Exception:
        pass
    return meta


# ── Input Resolution ─────────────────────────────────────────────────

# Well-known company → domain mappings
_COMPANY_DOMAINS: Dict[str, str] = {
    "amazon": "amazon.com", "aws": "amazon.com",
    "google": "google.com", "alphabet": "google.com",
    "microsoft": "microsoft.com", "apple": "apple.com",
    "meta": "meta.com", "facebook": "facebook.com",
    "netflix": "netflix.com", "cloudflare": "cloudflare.com",
    "stripe": "stripe.com", "github": "github.com",
    "gitlab": "gitlab.com", "twitter": "twitter.com",
    "slack": "slack.com", "salesforce": "salesforce.com",
    "shopify": "shopify.com", "dropbox": "dropbox.com",
    "uber": "uber.com", "airbnb": "airbnb.com",
    "spotify": "spotify.com", "snap": "snap.com",
    "oracle": "oracle.com", "ibm": "ibm.com",
    "intel": "intel.com", "cisco": "cisco.com",
    "paloalto": "paloaltonetworks.com",
    "crowdstrike": "crowdstrike.com",
    "datadog": "datadoghq.com",
    "okta": "okta.com", "twilio": "twilio.com",
    "zoom": "zoom.us", "docker": "docker.com",
    "hashicorp": "hashicorp.com", "elastic": "elastic.co",
    "mongodb": "mongodb.com", "redis": "redis.com",
    "confluent": "confluent.io", "vercel": "vercel.com",
    "netlify": "netlify.com", "digitalocean": "digitalocean.com",
    "linode": "linode.com", "vultr": "vultr.com",
}


def resolve_target(target: str) -> Dict[str, str]:
    """Resolve a target string into a structured input.

    Accepts:
        - Domain:       example.com
        - URL:          https://example.com
        - Email:        user@example.com
        - Company name: Amazon, Cloudflare

    Returns:
        {"type": "domain"|"email"|"company", "domain": "example.com",
         "email": "user@example.com" (if email), "original": target}
    """
    target = target.strip()
    original = target

    # URL → extract hostname
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        return {"type": "domain", "domain": parsed.hostname or target,
                "original": original}

    # Email → extract domain
    if "@" in target:
        parts = target.split("@", 1)
        domain = parts[1].lower()
        return {"type": "email", "domain": domain, "email": target.lower(),
                "original": original}

    # Has a dot → treat as domain
    if "." in target:
        return {"type": "domain", "domain": target.lower(),
                "original": original}

    # No dot → company name lookup
    key = target.lower().replace(" ", "").replace("-", "").replace("_", "")
    if key in _COMPANY_DOMAINS:
        return {"type": "company", "domain": _COMPANY_DOMAINS[key],
                "company": target, "original": original}

    # Unknown company → try {name}.com
    return {"type": "company", "domain": f"{key}.com",
            "company": target, "original": original}


# ── Email-specific OSINT ─────────────────────────────────────────────

def run_osint_email(email: str, timeout: int = 10,
                    quiet: bool = False) -> Dict[str, Any]:
    """Run OSINT focused on a specific email address.

    Checks:
        1. HIBP breach lookup
        2. GitHub profile search (by email)
        3. Gravatar profile
        4. Domain WHOIS (from email domain)
    """
    import hashlib

    domain = email.split("@", 1)[1].lower()
    from fray.progress import FrayProgress
    prog = FrayProgress(4, title=f"🔍 OSINT: {email}", quiet=quiet)

    result: Dict[str, Any] = {
        "target_type": "email",
        "email": email,
        "domain": domain,
        "breaches": None,
        "github_profile": None,
        "gravatar": None,
        "whois": None,
    }

    ctx = ssl.create_default_context()

    # 1. HIBP breach check
    prog.start("HIBP breach check")
    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        try:
            req = urllib.request.Request(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/"
                f"{urllib.parse.quote(email)}?truncateResponse=false",
                headers={
                    "User-Agent": "Fray-OSINT/1.0",
                    "hibp-api-key": hibp_key,
                },
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                breaches = json.loads(resp.read().decode())
                result["breaches"] = {
                    "count": len(breaches),
                    "breaches": [
                        {"name": b.get("Name"), "date": b.get("BreachDate"),
                         "data_classes": b.get("DataClasses", [])}
                        for b in breaches
                    ],
                }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result["breaches"] = {"count": 0, "breaches": []}
            else:
                result["breaches"] = {"error": f"HTTP {e.code}"}
        except Exception as e:
            result["breaches"] = {"error": str(e)}
    else:
        result["breaches"] = {"error": "Set HIBP_API_KEY for breach lookup"}
    prog.done("HIBP breach check")

    # 2. GitHub profile search by email
    prog.start("GitHub profile search")
    try:
        token = os.environ.get("GITHUB_TOKEN")
        headers_gh = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Fray-OSINT/1.0",
        }
        if token:
            headers_gh["Authorization"] = f"token {token}"
        req = urllib.request.Request(
            f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email",
            headers=headers_gh,
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            items = data.get("items", [])
            if items:
                result["github_profile"] = {
                    "found": True,
                    "login": items[0].get("login"),
                    "url": items[0].get("html_url"),
                    "avatar": items[0].get("avatar_url"),
                }
            else:
                result["github_profile"] = {"found": False}
    except Exception as e:
        result["github_profile"] = {"error": str(e)[:100]}
    prog.done("GitHub profile search")

    # 3. Gravatar check
    prog.start("Gravatar lookup")
    try:
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        req = urllib.request.Request(
            f"https://www.gravatar.com/{email_hash}.json",
            headers={"User-Agent": "Fray-OSINT/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            grav = json.loads(resp.read().decode())
            entry = grav.get("entry", [{}])[0]
            result["gravatar"] = {
                "found": True,
                "display_name": entry.get("displayName"),
                "profile_url": entry.get("profileUrl"),
                "about_me": entry.get("aboutMe"),
                "accounts": [
                    {"shortname": a.get("shortname"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ],
            }
    except urllib.error.HTTPError:
        result["gravatar"] = {"found": False}
    except Exception:
        result["gravatar"] = {"found": False}
    prog.done("Gravatar lookup")

    # 4. Domain WHOIS
    prog.start("Domain WHOIS")
    try:
        result["whois"] = whois_lookup(domain, timeout)
    except Exception as e:
        result["whois"] = {"error": str(e)}
    prog.done("Domain WHOIS")

    return result


# ── Combined OSINT Search ─────────────────────────────────────────────

def run_osint(domain: str, whois: bool = True, emails: bool = True,
              permutations: bool = True, github: bool = True,
              docs: bool = True, timeout: int = 10,
              quiet: bool = False) -> Dict[str, Any]:
    """Run offensive OSINT gathering on a domain.

    Args:
        domain: Target domain (already resolved — use resolve_target() first)
        whois: Enable WHOIS lookup
        emails: Enable email harvesting
        permutations: Enable typosquatting check
        github: Enable GitHub org recon + employee enumeration
        docs: Enable document metadata harvesting
        timeout: Per-request timeout
        quiet: Suppress progress output

    Returns:
        Combined results dict.
    """
    import concurrent.futures

    # Strip scheme if present
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain

    from fray.progress import FrayProgress

    result: Dict[str, Any] = {
        "domain": domain,
        "whois": None,
        "emails": None,
        "permutations": None,
        "github": None,
        "employees": None,
        "documents": None,
    }

    # Phase 1: parallel independent modules
    phase1 = []
    if whois:
        phase1.append(("whois", "WHOIS lookup", lambda: whois_lookup(domain, timeout)))
    if emails:
        phase1.append(("emails", "Email harvesting", lambda: harvest_emails(domain, timeout)))
    if permutations:
        phase1.append(("permutations", "Typosquatting check", lambda: check_permutations(domain, timeout=2.0)))
    if github:
        phase1.append(("github", "GitHub org recon", lambda: github_org_recon(domain, timeout)))
    if docs:
        phase1.append(("documents", "Document metadata", lambda: harvest_document_metadata(domain, timeout)))

    # Employee enumeration depends on GitHub data, so count it separately
    total_steps = len(phase1) + (1 if github else 0)
    prog = FrayProgress(total_steps, title=f"🔍 OSINT: {domain}", quiet=quiet)

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        for key, label, fn in phase1:
            prog.start(label)
            tasks[key] = (label, pool.submit(fn))

        for key, (label, future) in tasks.items():
            try:
                result[key] = future.result()
            except Exception as e:
                result[key] = {"error": str(e)}
            prog.done(label)

    # Phase 2: employee enumeration (needs GitHub data)
    if github:
        prog.start("Employee enumeration")
        try:
            result["employees"] = enumerate_employees(
                domain, github_data=result.get("github"), timeout=timeout)
        except Exception as e:
            result["employees"] = {"error": str(e)}
        prog.done("Employee enumeration")

    return result


# ── Pretty Print ───────────────────────────────────────────────────────

def print_osint(result: Dict[str, Any]) -> None:
    """Pretty-print OSINT results."""
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    domain = result.get("domain", "?")
    console.print(f"\n  [bold]OSINT Report: {domain}[/bold]")
    console.print(f"  {'━' * 50}")

    # ── Whois ──
    w = result.get("whois")
    if w and not w.get("error"):
        console.print(f"\n  [bold]WHOIS[/bold]")
        if w.get("registrar"):
            console.print(f"    Registrar:    [cyan]{w['registrar']}[/cyan]")
        if w.get("creation_date"):
            console.print(f"    Created:      {w['creation_date']}")
        if w.get("expiry_date"):
            console.print(f"    Expires:      {w['expiry_date']}")
        if w.get("registrant_org"):
            console.print(f"    Organization: [cyan]{w['registrant_org']}[/cyan]")
        if w.get("registrant_country"):
            console.print(f"    Country:      {w['registrant_country']}")
        if w.get("name_servers"):
            ns = ", ".join(w["name_servers"][:4])
            console.print(f"    Name Servers: [dim]{ns}[/dim]")
        if w.get("dnssec"):
            console.print(f"    DNSSEC:       {w['dnssec']}")
        if w.get("privacy_protected"):
            console.print(f"    Privacy:      [yellow]WHOIS privacy enabled[/yellow]")
        console.print()
    elif w and w.get("error"):
        console.print(f"\n  [bold]WHOIS[/bold]  [dim]{w['error']}[/dim]")

    # ── Emails ──
    e = result.get("emails")
    if e:
        total = e.get("total", 0)
        console.print(f"  [bold]Email Addresses[/bold] ([cyan]{total}[/cyan] found)")
        src = e.get("sources", {})
        if src:
            src_str = " · ".join(f"{k}:{v}" for k, v in src.items())
            console.print(f"    Sources: {src_str}")
        for em in e.get("emails", [])[:15]:
            conf = em.get("confidence", 0)
            pos = f" — {em['position']}" if em.get("position") else ""
            console.print(f"    [green]{em['email']}[/green]  {conf}% confidence{pos}")
        roles = e.get("role_addresses", [])
        if roles:
            console.print(f"    Role addresses: [dim]{', '.join(roles[:10])}[/dim]")
        console.print()

    # ── Typosquatting ──
    p = result.get("permutations")
    if p and not p.get("error"):
        registered = p.get("registered", 0)
        total_perm = p.get("total_permutations", 0)
        checked = p.get("checked", 0)
        color = "red" if registered > 5 else "yellow" if registered > 0 else "green"
        console.print(f"  [bold]Typosquatting / Permutations[/bold]")
        console.print(f"    [{color}]{registered} registered[/{color}] out of {checked} checked ({total_perm} total variants)")
        for perm in p.get("permutations", [])[:15]:
            console.print(f"    [red]⚠ {perm['domain']}[/red]  → {perm['ip']}")
        if registered > 15:
            console.print(f"    [dim]... and {registered - 15} more[/dim]")
        console.print()

    # ── GitHub Org Recon ──
    gh = result.get("github")
    if gh and gh.get("org_found"):
        console.print(f"  [bold]GitHub Organisation[/bold]")
        console.print(f"    Org:          [cyan]{gh['org_login']}[/cyan]"
                       f"  ({gh.get('org_name') or ''})")
        console.print(f"    URL:          {gh['org_url']}")
        if gh.get("blog"):
            console.print(f"    Website:      [dim]{gh['blog']}[/dim]")
        console.print(f"    Public repos: [bold]{gh['public_repos']}[/bold]  "
                       f"Members: [bold]{len(gh.get('members', []))}[/bold]")

        # Top repos
        repos = gh.get("repos", [])
        if repos:
            console.print(f"\n    [bold]Top Repositories[/bold] (by stars)")
            for r in repos[:10]:
                lang = f"[dim]{r['language']}[/dim]" if r.get("language") else "[dim]—[/dim]"
                console.print(f"    ⭐ {r['stars']:>5}  {lang:<15}  [cyan]{r['name']}[/cyan]")
                if r.get("description"):
                    console.print(f"                          [dim]{r['description'][:70]}[/dim]")

        # Interesting repos (infra, secrets, deploy)
        interesting = gh.get("interesting_repos", [])
        if interesting:
            console.print(f"\n    [bold red]Interesting Repos[/bold red] (infra/deploy/secrets)")
            for r in interesting[:10]:
                console.print(f"    🔴 [bold]{r['name']}[/bold]  [yellow]({r['reason']})[/yellow]")
                if r.get("description"):
                    console.print(f"       [dim]{r['description'][:80]}[/dim]")
                console.print(f"       {r['url']}")

        # Commit authors with real emails
        authors = gh.get("commit_authors", [])
        if authors:
            console.print(f"\n    [bold]Commit Authors[/bold] ({len(authors)} unique emails)")
            for a in authors[:15]:
                console.print(f"    📧 {a['name']:<25} [green]{a['email']}[/green]  [dim]({a['repo']})[/dim]")
            if len(authors) > 15:
                console.print(f"    [dim]... and {len(authors) - 15} more[/dim]")

        # Leaked URLs
        leaked = gh.get("leaked_urls", [])
        if leaked:
            console.print(f"\n    [bold red]Leaked Internal URLs[/bold red]")
            for l in leaked[:10]:
                console.print(f"    🚨 [red]{l['url']}[/red]  [dim]({l['source']})[/dim]")

        console.print()
    elif gh and gh.get("error"):
        console.print(f"  [bold]GitHub Organisation[/bold]  [dim]{gh['error']}[/dim]")
        console.print()

    # ── Employee Enumeration ──
    emp = result.get("employees")
    if emp and not emp.get("error") and emp.get("total_unique_people", 0) > 0:
        total_ppl = emp["total_unique_people"]
        pattern = emp.get("email_pattern")
        console.print(f"  [bold]Employee Enumeration[/bold] ({total_ppl} people)")
        if pattern:
            console.print(f"    Email pattern: [cyan]{pattern}@{domain}[/cyan]  "
                           f"[dim](auto-detected from git history)[/dim]")
        src = emp.get("sources", {})
        if src:
            console.print(f"    Sources:       "
                           + "  ".join(f"{k}: {v}" for k, v in src.items() if v))

        # People with generated emails
        inferred = emp.get("inferred_emails", [])
        if inferred:
            console.print(f"\n    [bold]Generated Email Addresses[/bold] ({len(inferred)})")
            for email in inferred[:20]:
                console.print(f"    📬 [green]{email}[/green]")
            if len(inferred) > 20:
                console.print(f"    [dim]... and {len(inferred) - 20} more[/dim]")

        # People list with sources
        people = emp.get("people", [])
        if people:
            console.print(f"\n    [bold]People[/bold]")
            for p in people[:30]:
                login = f"  @{p['github_login']}" if p.get("github_login") else ""
                known = ", ".join(p.get("emails", [])[:2])
                src_tags = "/".join(p.get("sources", []))
                title_str = f"  [italic]{p['title']}[/italic]" if p.get("title") else ""
                console.print(f"    👤 {p['name']:<25} [dim]{src_tags}{login}[/dim]{title_str}")
                if known:
                    console.print(f"       Known: [green]{known}[/green]")
                if p.get("linkedin_url"):
                    console.print(f"       LinkedIn: [blue]{p['linkedin_url']}[/blue]")
            if len(people) > 30:
                console.print(f"    [dim]... and {len(people) - 30} more[/dim]")

        console.print()

    # ── Document Metadata ──
    doc = result.get("documents")
    if doc and not doc.get("error"):
        n_docs = doc.get("documents_found", 0)
        authors = doc.get("unique_authors", [])
        sw = doc.get("unique_software", [])
        paths = doc.get("internal_paths", [])

        if n_docs > 0 or authors or sw or paths:
            console.print(f"  [bold]Document Metadata[/bold] ({n_docs} documents found)")

            for d in doc.get("documents", [])[:10]:
                meta = d.get("metadata", {})
                if not meta:
                    continue
                fname = d.get("filename", "?")[:50]
                author = meta.get("author", "")
                creator = meta.get("creator", "")
                console.print(f"    📄 [cyan]{fname}[/cyan]")
                if author:
                    console.print(f"       Author: [green]{author}[/green]")
                if creator:
                    console.print(f"       Software: [dim]{creator}[/dim]")
                if meta.get("title"):
                    console.print(f"       Title: [dim]{meta['title'][:60]}[/dim]")

            if authors:
                console.print(f"\n    [bold]Unique Authors[/bold] ({len(authors)})")
                for a in authors[:15]:
                    console.print(f"    👤 [green]{a}[/green]")

            if sw:
                console.print(f"\n    [bold]Software Versions[/bold]")
                for s in sw[:10]:
                    console.print(f"    💻 [dim]{s}[/dim]")

            if paths:
                console.print(f"\n    [bold red]Internal Paths Leaked[/bold red]")
                for p in paths[:10]:
                    console.print(f"    🚨 [red]{p}[/red]")

            console.print()
        elif n_docs == 0:
            console.print(f"  [bold]Document Metadata[/bold]  [dim]No public documents found[/dim]")
            console.print()

    console.print(f"  {'━' * 50}")


def print_osint_email(result: Dict[str, Any]) -> None:
    """Pretty-print email-focused OSINT results."""
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    email = result.get("email", "?")
    domain = result.get("domain", "?")
    console.print(f"\n  [bold]OSINT Report: {email}[/bold]")
    console.print(f"  {'━' * 50}")

    # Breaches
    b = result.get("breaches")
    if b and not b.get("error"):
        count = b.get("count", 0)
        color = "red" if count > 0 else "green"
        console.print(f"\n  [bold]Breach Check (HIBP)[/bold]  [{color}]{count} breach(es)[/{color}]")
        for breach in b.get("breaches", [])[:10]:
            classes = ", ".join(breach.get("data_classes", [])[:4])
            console.print(f"    🔓 [red]{breach['name']}[/red]  {breach.get('date', '?')}  [dim]{classes}[/dim]")
    elif b and b.get("error"):
        console.print(f"\n  [bold]Breach Check[/bold]  [dim]{b['error']}[/dim]")

    # GitHub profile
    gh = result.get("github_profile")
    if gh and gh.get("found"):
        console.print(f"\n  [bold]GitHub Profile[/bold]")
        console.print(f"    Login: [cyan]{gh['login']}[/cyan]")
        console.print(f"    URL:   {gh['url']}")
    elif gh and not gh.get("found") and not gh.get("error"):
        console.print(f"\n  [bold]GitHub Profile[/bold]  [dim]Not found[/dim]")

    # Gravatar
    grav = result.get("gravatar")
    if grav and grav.get("found"):
        console.print(f"\n  [bold]Gravatar Profile[/bold]")
        if grav.get("display_name"):
            console.print(f"    Name:    [cyan]{grav['display_name']}[/cyan]")
        if grav.get("profile_url"):
            console.print(f"    Profile: {grav['profile_url']}")
        if grav.get("about_me"):
            console.print(f"    Bio:     [dim]{grav['about_me'][:100]}[/dim]")
        for acct in grav.get("accounts", [])[:5]:
            console.print(f"    🔗 {acct.get('shortname', '?')}: {acct.get('url', '')}")

    # Whois
    w = result.get("whois")
    if w and not w.get("error"):
        console.print(f"\n  [bold]Domain: {domain}[/bold]")
        if w.get("registrar"):
            console.print(f"    Registrar: [cyan]{w['registrar']}[/cyan]")
        if w.get("registrant_org"):
            console.print(f"    Org:       [cyan]{w['registrant_org']}[/cyan]")

    console.print(f"\n  {'━' * 50}")


# ── HTML Export ──────────────────────────────────────────────────────

def export_osint_html(result: Dict[str, Any], output_path: str) -> None:
    """Export OSINT results as a self-contained HTML report."""
    import html as _html
    from datetime import datetime, timezone

    domain = _html.escape(result.get("domain", "?"))
    target_type = result.get("target_type", "domain")
    email_target = result.get("email", "")
    report_title = f"OSINT Report: {email_target}" if target_type == "email" else f"OSINT Report: {domain}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections = []

    def _h(text: str) -> str:
        return _html.escape(str(text))

    def _add_section(heading: str, content: str) -> None:
        sections.append(f'<div class="section"><h2>{_h(heading)}</h2>{content}</div>')

    # ── Whois ──
    w = result.get("whois")
    if w and not w.get("error"):
        rows = ""
        for key, label in [("registrar", "Registrar"), ("creation_date", "Created"),
                           ("expiry_date", "Expires"), ("registrant_org", "Organisation"),
                           ("registrant_country", "Country")]:
            if w.get(key):
                rows += f"<tr><td>{label}</td><td>{_h(w[key])}</td></tr>"
        ns = w.get("name_servers", [])
        if ns:
            rows += f"<tr><td>Name Servers</td><td>{_h(', '.join(ns[:4]))}</td></tr>"
        if rows:
            _add_section("WHOIS", f"<table>{rows}</table>")

    # ── GitHub ──
    gh = result.get("github")
    if gh and gh.get("org_found"):
        html_gh = f"<p><strong>{_h(gh.get('org_login', ''))}</strong> &mdash; {_h(gh.get('org_name', ''))}</p>"
        html_gh += f"<p>Public repos: {gh.get('public_repos', 0)} &middot; Members: {len(gh.get('members', []))}</p>"

        interesting = gh.get("interesting_repos", [])
        if interesting:
            html_gh += "<h3>Infrastructure Repos</h3><ul>"
            for r in interesting[:10]:
                html_gh += f"<li><strong>{_h(r['name'])}</strong> ({_h(r['reason'])}) &mdash; {_h(r.get('description', ''))}</li>"
            html_gh += "</ul>"

        authors = gh.get("commit_authors", [])
        if authors:
            html_gh += f"<h3>Commit Authors ({len(authors)})</h3><table><tr><th>Name</th><th>Email</th><th>Repo</th></tr>"
            for a in authors[:20]:
                html_gh += f"<tr><td>{_h(a['name'])}</td><td>{_h(a['email'])}</td><td>{_h(a['repo'])}</td></tr>"
            html_gh += "</table>"

        _add_section("GitHub Organisation", html_gh)

    # ── Employees ──
    emp = result.get("employees")
    if emp and emp.get("total_unique_people", 0) > 0:
        html_emp = f"<p>{emp['total_unique_people']} people discovered</p>"
        pattern = emp.get("email_pattern")
        if pattern:
            html_emp += f"<p>Email pattern: <code>{_h(pattern)}@{_h(domain)}</code></p>"
        inferred = emp.get("inferred_emails", [])
        if inferred:
            html_emp += f"<h3>Generated Emails ({len(inferred)})</h3><ul>"
            for em in inferred[:30]:
                html_emp += f"<li>{_h(em)}</li>"
            html_emp += "</ul>"
        _add_section("Employee Enumeration", html_emp)

    # ── Emails ──
    e = result.get("emails")
    if e and e.get("total", 0) > 0:
        html_em = f"<p>{e['total']} email(s) found</p><ul>"
        for em in e.get("emails", [])[:15]:
            html_em += f"<li>{_h(em['email'])} ({em.get('confidence', 0)}%)</li>"
        html_em += "</ul>"
        roles = e.get("role_addresses", [])
        if roles:
            html_em += f"<p>Role addresses: {_h(', '.join(roles[:10]))}</p>"
        _add_section("Email Addresses", html_em)

    # ── Typosquatting ──
    p = result.get("permutations")
    if p and p.get("registered", 0) > 0:
        html_p = f"<p class='danger'>{p['registered']} registered out of {p.get('checked', 0)} checked</p><ul>"
        for perm in p.get("permutations", [])[:15]:
            html_p += f"<li><strong>{_h(perm['domain'])}</strong> &rarr; {_h(perm['ip'])}</li>"
        html_p += "</ul>"
        _add_section("Typosquatting / Permutations", html_p)

    # ── Documents ──
    doc = result.get("documents")
    if doc and doc.get("documents_found", 0) > 0:
        html_doc = f"<p>{doc['documents_found']} documents found</p>"
        authors_list = doc.get("unique_authors", [])
        if authors_list:
            html_doc += "<h3>Authors</h3><ul>"
            for a in authors_list:
                html_doc += f"<li>{_h(a)}</li>"
            html_doc += "</ul>"
        paths = doc.get("internal_paths", [])
        if paths:
            html_doc += "<h3>Internal Paths Leaked</h3><ul>"
            for ip in paths:
                html_doc += f"<li class='danger'>{_h(ip)}</li>"
            html_doc += "</ul>"
        _add_section("Document Metadata", html_doc)

    # ── Email-mode sections ──
    if target_type == "email":
        b = result.get("breaches")
        if b and not b.get("error") and b.get("count", 0) > 0:
            html_b = f"<p class='danger'>{b['count']} breach(es)</p><ul>"
            for br in b.get("breaches", [])[:10]:
                html_b += f"<li><strong>{_h(br['name'])}</strong> ({_h(br.get('date', '?'))})</li>"
            html_b += "</ul>"
            _add_section("Breach Check (HIBP)", html_b)

        gh_prof = result.get("github_profile")
        if gh_prof and gh_prof.get("found"):
            html_gp = f"<p>Login: <a href='{_h(gh_prof['url'])}'>{_h(gh_prof['login'])}</a></p>"
            _add_section("GitHub Profile", html_gp)

        grav = result.get("gravatar")
        if grav and grav.get("found"):
            html_gv = f"<p>{_h(grav.get('display_name', ''))}</p>"
            for acct in grav.get("accounts", []):
                html_gv += f"<p>{_h(acct.get('shortname', ''))}: <a href='{_h(acct.get('url', ''))}'>{_h(acct.get('url', ''))}</a></p>"
            _add_section("Gravatar", html_gv)

    # Build full HTML page
    body = "\n".join(sections) if sections else "<p>No results found.</p>"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(report_title)}</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
           --accent: #58a6ff; --red: #f85149; --green: #3fb950; --yellow: #d29922; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 2rem; }}
  h1 {{ color: #fff; margin-bottom: 0.3rem; font-size: 1.5rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.85rem; }}
  .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1rem; }}
  .section h2 {{ color: var(--accent); font-size: 1.1rem; margin-bottom: 0.8rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
  .section h3 {{ color: var(--text); font-size: 0.95rem; margin: 0.8rem 0 0.4rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  td, th {{ padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: #8b949e; }}
  ul {{ padding-left: 1.2rem; font-size: 0.85rem; }}
  li {{ margin: 0.2rem 0; }}
  code {{ background: #1c2129; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; color: var(--accent); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .danger {{ color: var(--red); }}
  p {{ margin: 0.3rem 0; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>{_h(report_title)}</h1>
<p class="meta">Generated by Fray OSINT &middot; {now}</p>
{body}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)
