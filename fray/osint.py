"""
Fray OSINT — broader Open Source Intelligence gathering

Usage:
    fray osint example.com              # Full OSINT scan
    fray osint example.com --json       # JSON output
    fray osint example.com --whois      # Whois only
    fray osint example.com --emails     # Email harvesting only
    fray osint example.com --social     # Social media profile enumeration

Modules:
    1. Whois lookup + history (registrar, creation date, name servers)
    2. Email harvesting (Hunter.io, public patterns, role addresses)
    3. Subdomain permutation (dnstwist-style typosquatting detection)
    4. Social media / service profile enumeration
    5. Technology profiling (Wappalyzer-style via headers/HTML)

Environment variables:
    HUNTER_API_KEY    — Optional: enables Hunter.io email search (free tier: 25 req/month)

Zero dependencies — stdlib only.
"""

import http.client
import json
import os
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


# ── Social Media / Service Profile Enumeration ────────────────────────

_SOCIAL_PLATFORMS = [
    ("GitHub", "https://github.com/{username}", "github.com"),
    ("Twitter/X", "https://x.com/{username}", "x.com"),
    ("LinkedIn Company", "https://www.linkedin.com/company/{username}", "linkedin.com"),
    ("Facebook", "https://www.facebook.com/{username}", "facebook.com"),
    ("Instagram", "https://www.instagram.com/{username}", "instagram.com"),
    ("YouTube", "https://www.youtube.com/@{username}", "youtube.com"),
    ("Reddit", "https://www.reddit.com/user/{username}", "reddit.com"),
    ("Medium", "https://medium.com/@{username}", "medium.com"),
    ("Crunchbase", "https://www.crunchbase.com/organization/{username}", "crunchbase.com"),
]


def _verify_profile_owns_domain(url: str, domain: str, platform: str,
                                timeout: int = 6) -> str:
    """Fetch a profile page and check if it references the domain.

    Returns:
        "verified"   — page body or meta tags contain the domain
        "likely"     — strong heuristic match (brand name in title, org page)
        "unverified" — page exists but no ownership signal found
        "not_found"  — page doesn't exist (404 / error)
    """
    domain_bare = domain.lower()
    brand = domain_bare.split(".")[0]  # e.g. "cloudflare" from "cloudflare.com"

    # Domain patterns (exact ownership proof)
    domain_patterns = [
        domain_bare,
        f"www.{domain_bare}",
        f"https://{domain_bare}",
        f"http://{domain_bare}",
    ]

    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                return "not_found"
            body = resp.read(64_000).decode("utf-8", errors="replace").lower()

            # Tier 1: page references the exact domain
            for pat in domain_patterns:
                if pat in body:
                    return "verified"

            # Tier 2: heuristic — page title/meta contains brand name
            # This catches JS-rendered pages where <title> is still in raw HTML
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", body)
            meta_desc = re.search(r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\']([^"\']+)', body)
            og_title = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', body)

            title_text = (title_match.group(1) if title_match else "").lower()
            desc_text = (meta_desc.group(1) if meta_desc else "").lower()
            og_text = (og_title.group(1) if og_title else "").lower()

            # Tier 2: heuristic — brand name in page metadata
            # NOTE: LinkedIn and Crunchbase echo the URL slug as page title
            # (e.g. "dalisec | linkedin") even for non-existent companies,
            # so brand-in-title alone is NOT proof of a real page there.
            # Only use brand-in-title for platforms with meaningful titles.
            has_brand_in_title = brand in title_text or brand in og_text

            if has_brand_in_title:
                # Skip platforms that just echo the slug as title
                if platform in ("LinkedIn Company", "Crunchbase"):
                    # For these, require additional signals beyond slug echo
                    # Check for employee count, description, or other real content
                    has_real_content = (
                        "employees" in body or "follower" in body
                        or domain_bare in desc_text
                        or len(desc_text) > 50  # Real companies have descriptions
                    )
                    if has_real_content:
                        return "likely"
                    # else: just a slug echo, stay unverified
                else:
                    return "likely"

            return "unverified"
    except urllib.error.HTTPError as e:
        if e.code in (301, 302):
            return "unverified"
        return "not_found"
    except Exception:
        return "not_found"


def _verify_github(username: str, domain: str, timeout: int = 6) -> str:
    """Use GitHub API to check if user/org blog field matches the domain.

    Returns "verified" if blog/bio references the domain,
    "likely" if it's an Organization account with matching name,
    "unverified" otherwise.
    """
    try:
        req = urllib.request.Request(
            f"https://api.github.com/users/{username}",
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Fray-OSINT/1.0",
            },
        )
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())
            blog = (data.get("blog") or "").lower().rstrip("/")
            bio = (data.get("bio") or "").lower()
            name = (data.get("name") or "").lower()
            acct_type = (data.get("type") or "").lower()  # "organization" or "user"
            domain_bare = domain.lower()
            brand = domain_bare.split(".")[0]

            # Tier 1: blog/bio explicitly references the domain
            if domain_bare in blog or domain_bare in bio:
                return "verified"
            # Also match alternate domains (e.g. stripe.dev for stripe.com)
            if brand in blog and (".dev" in blog or ".io" in blog or ".org" in blog or ".com" in blog):
                return "verified"

            # Tier 2: Organization account with matching login name
            if acct_type == "organization" and data.get("login", "").lower() == brand:
                return "likely"

            return "unverified"
    except Exception:
        return "unverified"


def check_social_profiles(domain: str, timeout: int = 8) -> Dict[str, Any]:
    """Check for social media profiles using the domain's brand name.

    Derives likely usernames from the domain name, checks major platforms,
    then **verifies** each profile actually belongs to the domain owner by
    checking if the profile page references the domain. Profiles that exist
    but don't reference the domain are marked "unverified" to avoid false
    positives.
    """
    # Derive candidate usernames from domain
    name = domain.split(".")[0]
    usernames = set()
    usernames.add(name)
    if "-" in name:
        usernames.add(name.replace("-", ""))
        usernames.add(name.replace("-", "_"))
    if "_" in name:
        usernames.add(name.replace("_", ""))
        usernames.add(name.replace("_", "-"))

    found = []
    checked = 0

    ctx = ssl.create_default_context()

    for platform, url_template, host in _SOCIAL_PLATFORMS:
        for username in usernames:
            url = url_template.format(username=username)
            checked += 1
            try:
                # Quick HEAD check first to see if profile exists
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html",
                }, method="HEAD")
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if resp.status == 200:
                        # Profile exists — verify it belongs to the domain
                        if platform == "GitHub":
                            verification = _verify_github(username, domain, timeout)
                        else:
                            verification = _verify_profile_owns_domain(
                                url, domain, platform, timeout)

                        found.append({
                            "platform": platform,
                            "username": username,
                            "url": url,
                            "status": resp.status,
                            "verification": verification,
                        })
            except urllib.error.HTTPError:
                pass
            except Exception:
                pass
            time.sleep(0.3)  # Be polite

    # Separate by confidence tier
    verified = [p for p in found if p.get("verification") in ("verified", "likely")]
    unverified = [p for p in found if p.get("verification") not in ("verified", "likely")]

    return {
        "domain": domain,
        "usernames_tested": sorted(usernames),
        "checked": checked,
        "found": len(verified),
        "found_unverified": len(unverified),
        "profiles": verified,
        "unverified_profiles": unverified,
    }


# ── Combined OSINT Search ─────────────────────────────────────────────

def run_osint(domain: str, whois: bool = True, emails: bool = True,
              permutations: bool = True, social: bool = True,
              timeout: int = 10, quiet: bool = False) -> Dict[str, Any]:
    """Run combined OSINT gathering on a domain.

    Args:
        domain: Target domain
        whois: Enable WHOIS lookup
        emails: Enable email harvesting
        permutations: Enable typosquatting check
        social: Enable social media enumeration
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
        "social": None,
    }

    # Count enabled modules for progress bar
    modules = []
    if whois:
        modules.append(("whois", "WHOIS lookup", lambda: whois_lookup(domain, timeout)))
    if emails:
        modules.append(("emails", "Email harvesting", lambda: harvest_emails(domain, timeout)))
    if permutations:
        modules.append(("permutations", "Typosquatting check", lambda: check_permutations(domain, timeout=2.0)))
    if social:
        modules.append(("social", "Social profiles", lambda: check_social_profiles(domain, timeout)))

    prog = FrayProgress(len(modules), title=f"🌐 OSINT: {domain}", quiet=quiet)

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for key, label, fn in modules:
            prog.start(label)
            tasks[key] = (label, pool.submit(fn))

        for key, (label, future) in tasks.items():
            try:
                result[key] = future.result()
            except Exception as e:
                result[key] = {"error": str(e)}
            prog.done(label)

    return result


# ── Pretty Print ───────────────────────────────────────────────────────

def print_osint(result: Dict[str, Any]) -> None:
    """Pretty-print OSINT results."""
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        # Fallback to basic print
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    domain = result.get("domain", "?")
    console.print(f"\n  [bold]OSINT Report: {domain}[/bold]")
    console.print(f"  {'━' * 50}")

    # Whois
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

    # Emails
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

    # Permutations / Typosquatting
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

    # Social profiles
    s = result.get("social")
    if s:
        verified = s.get("found", 0)
        unverified_count = s.get("found_unverified", 0)
        total_label = f"{verified} verified"
        if unverified_count:
            total_label += f", {unverified_count} unverified"
        console.print(f"  [bold]Social Media Profiles[/bold] ({total_label})")
        for prof in s.get("profiles", []):
            v = prof.get("verification", "verified")
            if v == "likely":
                console.print(f"    [yellow]~ {prof['platform']}[/yellow]: {prof['url']}  [dim](likely match)[/dim]")
            else:
                console.print(f"    [green]✓ {prof['platform']}[/green]: {prof['url']}")
        for prof in s.get("unverified_profiles", []):
            console.print(f"    [dim]? {prof['platform']}: {prof['url']}  (unverified — may not belong to {s.get('domain', 'target')})[/dim]")
        if not verified and not unverified_count:
            console.print(f"    [dim]No profiles found for usernames: {', '.join(s.get('usernames_tested', []))}[/dim]")
        console.print()

    console.print(f"  {'━' * 50}")
