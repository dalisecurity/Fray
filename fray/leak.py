"""
Fray Leak Search — GitHub code search + Have I Been Pwned breach lookup

Usage:
    fray leak example.com                    # Search GitHub + HIBP for leaks
    fray leak example.com --github-only      # GitHub code search only
    fray leak example.com --hibp-only        # HIBP breach lookup only
    fray leak example.com --json             # JSON output
    fray leak user@example.com               # Check specific email in HIBP

Environment variables:
    GITHUB_TOKEN      — Required for GitHub code search (personal access token)
    HIBP_API_KEY      — Optional: enables domain-wide HIBP search (haveibeenpwned.com/API/Key)

Zero dependencies — stdlib only (urllib.request, json, ssl).
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


# ── GitHub Code Search ──────────────────────────────────────────────────

# Sensitive patterns to search for alongside the target domain
_GITHUB_PATTERNS = [
    "password",
    "api_key",
    "apikey",
    "api-key",
    "secret_key",
    "secret",
    "token",
    "access_token",
    "private_key",
    "client_secret",
    "aws_access_key_id",
    "aws_secret_access_key",
    "database_url",
    "db_password",
    "smtp_password",
    "authorization",
    "bearer",
]


def _github_api_request(url: str, token: str, timeout: int = 10) -> Optional[dict]:
    """Make an authenticated GitHub API request."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Fray-Leak-Scanner",
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # Rate limit
            reset = e.headers.get("X-RateLimit-Reset", "")
            if reset:
                wait = max(int(reset) - int(time.time()), 1)
                return {"error": f"GitHub rate limit exceeded. Resets in {wait}s.", "rate_limited": True}
            return {"error": "GitHub API rate limit exceeded.", "rate_limited": True}
        elif e.code == 401:
            return {"error": "Invalid GITHUB_TOKEN. Check your token permissions.", "auth_error": True}
        elif e.code == 422:
            return {"error": f"GitHub search validation error (HTTP 422).", "total_count": 0}
        return {"error": f"GitHub API error: HTTP {e.code}", "total_count": 0}
    except Exception as e:
        return {"error": f"GitHub API request failed: {e}", "total_count": 0}


def search_github(domain: str, token: str, max_patterns: int = 10,
                  timeout: int = 10) -> Dict[str, Any]:
    """Search GitHub code for leaked credentials mentioning the target domain.

    Uses GitHub Code Search API to find public repos containing
    passwords, API keys, tokens, etc. alongside the domain name.

    Args:
        domain: Target domain (e.g. 'example.com')
        token: GitHub personal access token
        max_patterns: Max number of patterns to search (rate limit friendly)
        timeout: Request timeout in seconds

    Returns:
        Dict with 'results' list and 'summary' stats.
    """
    results = []
    total_matches = 0
    errors = []
    rate_limited = False

    patterns_to_search = _GITHUB_PATTERNS[:max_patterns]

    for i, pattern in enumerate(patterns_to_search):
        if rate_limited:
            break

        # GitHub code search: "domain" + "pattern" in file contents
        query = f'"{domain}" "{pattern}"'
        encoded = urllib.parse.quote(query)
        url = f"https://api.github.com/search/code?q={encoded}&per_page=5&sort=indexed&order=desc"

        data = _github_api_request(url, token, timeout)
        if not data:
            continue

        if data.get("rate_limited"):
            errors.append(data["error"])
            rate_limited = True
            break

        if data.get("auth_error"):
            errors.append(data["error"])
            break

        if data.get("error"):
            errors.append(data["error"])
            continue

        count = data.get("total_count", 0)
        items = data.get("items", [])

        if count > 0:
            total_matches += count
            for item in items[:3]:  # Top 3 per pattern
                repo = item.get("repository", {})
                results.append({
                    "pattern": pattern,
                    "total_matches": count,
                    "file": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file_url": item.get("html_url", ""),
                    "score": item.get("score", 0),
                })

        # Rate limit: GitHub allows 10 code searches per minute for authenticated users
        if i < len(patterns_to_search) - 1:
            time.sleep(2)  # Conservative delay between searches

    # Deduplicate by repo
    seen_repos = {}
    for r in results:
        repo = r["repo"]
        if repo not in seen_repos:
            seen_repos[repo] = {
                "repo": repo,
                "repo_url": r["repo_url"],
                "patterns_found": [],
                "files": [],
            }
        if r["pattern"] not in seen_repos[repo]["patterns_found"]:
            seen_repos[repo]["patterns_found"].append(r["pattern"])
        seen_repos[repo]["files"].append({
            "path": r["file"],
            "pattern": r["pattern"],
            "url": r["file_url"],
        })

    return {
        "source": "github",
        "domain": domain,
        "total_matches": total_matches,
        "repos_with_leaks": len(seen_repos),
        "patterns_searched": len(patterns_to_search),
        "rate_limited": rate_limited,
        "errors": errors,
        "repos": list(seen_repos.values()),
    }


# ── Have I Been Pwned ───────────────────────────────────────────────────

def _hibp_request(url: str, api_key: Optional[str] = None,
                  timeout: int = 10) -> Optional[Any]:
    """Make HIBP API request."""
    headers = {
        "User-Agent": "Fray-Leak-Scanner",
    }
    if api_key:
        headers["hibp-api-key"] = api_key

    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # Not found = clean
        elif e.code == 401:
            return {"error": "HIBP API key required for this endpoint. Set HIBP_API_KEY env var."}
        elif e.code == 429:
            retry = e.headers.get("Retry-After", "2")
            return {"error": f"HIBP rate limited. Retry after {retry}s."}
        return {"error": f"HIBP API error: HTTP {e.code}"}
    except Exception as e:
        return {"error": f"HIBP request failed: {e}"}


def search_hibp_email(email: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if a specific email appears in HIBP breaches.

    This endpoint is free and does not require an API key.
    """
    encoded = urllib.parse.quote(email)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"

    data = _hibp_request(url, timeout=timeout)

    if data is None:
        return {
            "source": "hibp",
            "email": email,
            "breached": False,
            "breach_count": 0,
            "breaches": [],
        }

    if isinstance(data, dict) and data.get("error"):
        return {
            "source": "hibp",
            "email": email,
            "breached": False,
            "error": data["error"],
            "breaches": [],
        }

    breaches = []
    for b in data if isinstance(data, list) else []:
        breaches.append({
            "name": b.get("Name", ""),
            "domain": b.get("Domain", ""),
            "date": b.get("BreachDate", ""),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "is_verified": b.get("IsVerified", False),
            "is_sensitive": b.get("IsSensitive", False),
        })

    return {
        "source": "hibp",
        "email": email,
        "breached": len(breaches) > 0,
        "breach_count": len(breaches),
        "breaches": breaches,
    }


def search_hibp_domain(domain: str, api_key: str,
                       timeout: int = 10) -> Dict[str, Any]:
    """Search HIBP for all breached emails on a domain.

    Requires a paid HIBP API key (haveibeenpwned.com/API/Key).
    """
    encoded = urllib.parse.quote(domain)
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{encoded}"

    data = _hibp_request(url, api_key=api_key, timeout=timeout)

    if data is None:
        return {
            "source": "hibp",
            "domain": domain,
            "breached": False,
            "total_emails": 0,
            "emails": [],
        }

    if isinstance(data, dict) and data.get("error"):
        return {
            "source": "hibp",
            "domain": domain,
            "breached": False,
            "error": data["error"],
            "emails": [],
        }

    # Domain search returns {alias: [breach_names]}
    emails = []
    if isinstance(data, dict):
        for alias, breach_names in data.items():
            emails.append({
                "email": f"{alias}@{domain}",
                "breaches": breach_names,
                "breach_count": len(breach_names),
            })

    # Sort by breach count descending
    emails.sort(key=lambda x: x["breach_count"], reverse=True)

    return {
        "source": "hibp",
        "domain": domain,
        "breached": len(emails) > 0,
        "total_emails": len(emails),
        "total_breaches": sum(e["breach_count"] for e in emails),
        "emails": emails,
    }


# ── Combined search ─────────────────────────────────────────────────────

def search_leaks(target: str, github: bool = True, hibp: bool = True,
                 timeout: int = 10) -> Dict[str, Any]:
    """Run combined leak search across GitHub and HIBP.

    Args:
        target: Domain (example.com) or email (user@example.com)
        github: Enable GitHub code search
        hibp: Enable HIBP breach lookup
        timeout: Request timeout

    Returns:
        Combined results dict with 'github' and 'hibp' keys.
    """
    is_email = "@" in target
    domain = target.split("@")[1] if is_email else target

    # Strip scheme if present
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain

    result = {
        "target": target,
        "domain": domain,
        "is_email": is_email,
        "github": None,
        "hibp": None,
        "summary": {},
    }

    # GitHub code search
    if github and not is_email:
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        if gh_token:
            result["github"] = search_github(domain, gh_token, timeout=timeout)
        else:
            result["github"] = {
                "source": "github",
                "error": "GITHUB_TOKEN not set. Export your GitHub personal access token to enable code search.",
                "skipped": True,
            }

    # HIBP
    if hibp:
        hibp_key = os.environ.get("HIBP_API_KEY", "")

        if is_email:
            # Single email lookup (free, no key needed)
            result["hibp"] = search_hibp_email(target, timeout=timeout)
        elif hibp_key:
            # Domain-wide search (paid API key)
            result["hibp"] = search_hibp_domain(domain, hibp_key, timeout=timeout)
        else:
            result["hibp"] = {
                "source": "hibp",
                "note": "Set HIBP_API_KEY for domain-wide breach search. "
                        "Or use: fray leak user@example.com (free, no key).",
                "skipped": True,
            }

    # Summary
    gh = result.get("github") or {}
    hb = result.get("hibp") or {}

    risk_factors = []
    if gh.get("repos_with_leaks", 0) > 0:
        risk_factors.append(f"{gh['repos_with_leaks']} GitHub repos with leaked credentials")
    if hb.get("breached"):
        if hb.get("total_emails"):
            risk_factors.append(f"{hb['total_emails']} emails in {hb.get('total_breaches', 0)} breaches")
        elif hb.get("breach_count"):
            risk_factors.append(f"{hb['breach_count']} breaches found")

    result["summary"] = {
        "github_repos_with_leaks": gh.get("repos_with_leaks", 0),
        "hibp_breached": hb.get("breached", False),
        "risk_factors": risk_factors,
        "risk_level": "high" if risk_factors else "low",
    }

    return result


# ── Pretty-print ────────────────────────────────────────────────────────

def print_leak_results(result: Dict[str, Any]) -> None:
    """Pretty-print leak search results."""
    target = result.get("target", "?")
    domain = result.get("domain", "?")

    print(f"\n{'═' * 60}")
    print(f"  🔍 Leak Search — {target}")
    print(f"{'═' * 60}")

    # ── GitHub results ──
    gh = result.get("github")
    if gh:
        print(f"\n  📁 GitHub Code Search")
        print(f"  {'─' * 40}")

        if gh.get("skipped"):
            print(f"  ⚠️  {gh.get('error', 'Skipped')}")
        elif gh.get("error") and not gh.get("repos"):
            print(f"  ❌ {gh['error']}")
        else:
            repos = gh.get("repos", [])
            total = gh.get("total_matches", 0)
            print(f"  Patterns searched: {gh.get('patterns_searched', 0)}")
            print(f"  Total matches:     {total}")
            print(f"  Repos with leaks:  {len(repos)}")

            if repos:
                print()
                for repo in repos[:10]:  # Show top 10 repos
                    patterns = ", ".join(repo["patterns_found"][:5])
                    print(f"  🔴 {repo['repo']}")
                    print(f"     Patterns: {patterns}")
                    for f in repo["files"][:3]:
                        print(f"     → {f['path']}")
                    print(f"     {repo['repo_url']}")
                    print()
            else:
                print(f"  ✅ No leaked credentials found on GitHub")

            if gh.get("rate_limited"):
                print(f"  ⚠️  Search was rate-limited. Re-run later for full results.")

            if gh.get("errors"):
                for err in gh["errors"]:
                    print(f"  ⚠️  {err}")

    # ── HIBP results ──
    hb = result.get("hibp")
    if hb:
        print(f"\n  🔓 Have I Been Pwned")
        print(f"  {'─' * 40}")

        if hb.get("skipped"):
            print(f"  ⚠️  {hb.get('note', hb.get('error', 'Skipped'))}")
        elif hb.get("error"):
            print(f"  ❌ {hb['error']}")
        elif result.get("is_email"):
            # Single email result
            if hb.get("breached"):
                print(f"  ❌ {hb['email']} found in {hb['breach_count']} breach(es):")
                print()
                for b in hb.get("breaches", [])[:10]:
                    verified = "✓" if b.get("is_verified") else "?"
                    data = ", ".join(b.get("data_classes", [])[:5])
                    print(f"  [{verified}] {b['name']} ({b['date']}) — {b['pwn_count']:,} accounts")
                    if data:
                        print(f"      Data: {data}")
            else:
                print(f"  ✅ {hb.get('email', target)} — not found in any breaches")
        else:
            # Domain result
            if hb.get("breached"):
                print(f"  ❌ {hb['total_emails']} email(s) from {domain} found in breaches")
                print(f"     Total breach entries: {hb.get('total_breaches', 0)}")
                print()
                for e in hb.get("emails", [])[:15]:
                    print(f"  • {e['email']} — {e['breach_count']} breach(es): {', '.join(e['breaches'][:3])}")
            else:
                print(f"  ✅ No breached emails found for {domain}")

    # ── Summary ──
    summary = result.get("summary", {})
    risk = summary.get("risk_level", "low")
    factors = summary.get("risk_factors", [])

    print(f"\n  {'─' * 40}")
    risk_icon = "🔴" if risk == "high" else "🟢"
    print(f"  {risk_icon} Risk Level: {risk.upper()}")
    if factors:
        for f in factors:
            print(f"     • {f}")
    print(f"{'═' * 60}\n")
