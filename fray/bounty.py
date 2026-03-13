#!/usr/bin/env python3
"""
Fray Bounty — Bug Bounty Platform Integration

Usage:
    fray bounty --platform hackerone --program <handle>
    fray bounty --platform bugcrowd --program <handle>
    fray bounty --urls urls.txt
    fray bounty --program <handle> --categories xss,sqli --max 20

Integrates with HackerOne and Bugcrowd to:
    1. Fetch public program scope (in-scope URLs/domains) — NO API KEY NEEDED
    2. Auto-detect WAF on each target
    3. Run payload tests across scope
    4. Generate consolidated bounty report

HackerOne: Uses public GraphQL API (no auth for public programs)
Bugcrowd: Uses public program page API (no auth for public programs)

Zero external dependencies — stdlib only.
"""

import http.client
import json
import re
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── API Clients (stdlib only) ────────────────────────────────────────────────

# GraphQL query for HackerOne public program scope
_H1_SCOPE_QUERY = """query PolicySearchStructuredScopesQuery($handle: String!) {
  team(handle: $handle) {
    id
    name
    structured_scopes(first: 100, archived: false) {
      edges {
        node {
          asset_type
          asset_identifier
          eligible_for_submission
          eligible_for_bounty
          instruction
        }
      }
    }
  }
}"""


class HackerOnePublic:
    """Fetch public HackerOne program scope via GraphQL — NO API KEY NEEDED."""

    HOST = "hackerone.com"

    def _request(self, body: bytes) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.HOST, 443, context=ctx, timeout=30)
        conn.request("POST", "/graphql", body=body, headers={
            "Content-Type": "application/json",
            "User-Agent": f"Fray/{__version__}",
        })
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope assets for a public HackerOne program."""
        body = json.dumps({
            "operationName": "PolicySearchStructuredScopesQuery",
            "variables": {"handle": handle},
            "query": _H1_SCOPE_QUERY,
        }).encode("utf-8")

        status, data = self._request(body)

        if status != 200:
            return False, [{"error": f"HTTP {status}"}]

        team = data.get("data", {}).get("team")
        if not team:
            errors = data.get("errors", [])
            msg = errors[0].get("message", "Program not found") if errors else "Program not found"
            return False, [{"error": msg}]

        scopes = []
        edges = team.get("structured_scopes", {}).get("edges", [])

        for edge in edges:
            node = edge.get("node", {})
            if not node.get("eligible_for_submission", False):
                continue
            asset_type = node.get("asset_type", "")
            identifier = node.get("asset_identifier", "")
            instruction = node.get("instruction", "")
            bounty = node.get("eligible_for_bounty", False)
            scopes.append({
                "type": asset_type,
                "identifier": identifier,
                "bounty": bounty,
                "instruction": (instruction or "")[:1000],
                "eligible": True,
            })

        return True, scopes


class BugcrowdPublic:
    """Fetch public Bugcrowd program scope — NO API KEY NEEDED (#113)."""

    HOST = "bugcrowd.com"

    def _request(self, path: str) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.HOST, 443, context=ctx, timeout=30)
        conn.request("GET", path, headers={
            "Accept": "application/json",
            "User-Agent": f"Fray/{__version__}",
        })
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope targets for a public Bugcrowd program.

        Enhanced (#113): extracts out-of-scope, reward tiers, and
        all target group categories (not just web).
        """
        path = f"/{handle}.json"
        status, data = self._request(path)

        if status != 200:
            return False, [{"error": f"Program '{handle}' not found (HTTP {status})"}]

        scopes = []
        out_of_scope = []

        # Extract program metadata
        program_name = data.get("name", handle)
        max_payout = data.get("max_payout", 0)
        min_payout = data.get("min_payout", 0)
        program_url = f"https://bugcrowd.com/{handle}"

        target_groups = data.get("target_groups", [])
        if not target_groups:
            # Try alternate structure
            targets = data.get("targets", data.get("scope", []))
            if isinstance(targets, list):
                for t in targets:
                    name = t.get("name", t.get("uri", ""))
                    category = t.get("category", t.get("type", ""))
                    in_scope = t.get("in_scope", True)
                    if name:
                        entry = {
                            "type": category.upper() if category else "URL",
                            "identifier": name,
                            "bounty": True,
                            "instruction": "",
                            "eligible": in_scope,
                        }
                        if in_scope:
                            scopes.append(entry)
                        else:
                            out_of_scope.append(entry)
            if scopes and out_of_scope:
                scopes.append({"_out_of_scope": out_of_scope})
            if scopes and max_payout:
                scopes.append({"_reward_range": f"${min_payout}-${max_payout}",
                               "_program_url": program_url})
            return bool(scopes), scopes

        for group in target_groups:
            group_in_scope = group.get("in_scope", True)
            targets = group.get("targets", [])
            for target in targets:
                name = target.get("name", "")
                uri = target.get("uri", "")
                category = target.get("category", "")
                desc = target.get("description", "")
                target_in_scope = target.get("in_scope", group_in_scope)

                entry = {
                    "type": category.upper() or "URL",
                    "identifier": uri or name,
                    "bounty": True,
                    "instruction": desc[:1000] if desc else "",
                    "eligible": target_in_scope,
                }

                if target_in_scope:
                    # Accept all categories for scope awareness, not just web
                    scopes.append(entry)
                else:
                    out_of_scope.append(entry)

        # Attach out-of-scope and reward metadata
        if out_of_scope:
            scopes.append({"_out_of_scope": out_of_scope})
        if max_payout:
            scopes.append({"_reward_range": f"${min_payout}-${max_payout}",
                           "_program_url": program_url})

        return bool(scopes), scopes

    def search_programs(self, query: str = "", sort: str = "promoted") -> List[Dict]:
        """Search Bugcrowd programs directory (#113).

        Args:
            query: Search term (company name, domain, etc.)
            sort:  Sort order: promoted, newest, oldest

        Returns:
            List of program summaries with handle, name, max_payout.
        """
        path = f"/programs.json?sort[]={sort}&hidden[]={0}"
        if query:
            path += f"&search={urllib.parse.quote(query)}"

        status, data = self._request(path)
        if status != 200:
            return []

        programs = []
        for p in data.get("programs", data) if isinstance(data, dict) else data:
            if isinstance(p, dict):
                programs.append({
                    "handle": p.get("code", p.get("handle", "")),
                    "name": p.get("name", ""),
                    "max_payout": p.get("max_payout", 0),
                    "url": f"https://bugcrowd.com/{p.get('code', p.get('handle', ''))}",
                })
        return programs[:20]


# ── Scope Analysis ────────────────────────────────────────────────────────────

# What Fray can do per asset type
_ASSET_CAPABILITY = {
    # FULL: Fray can WAF-detect + payload-test
    "URL": {
        "level": "full",
        "label": "Web URL",
        "help": "WAF detection + payload testing (XSS, SQLi, SSTI, etc.)",
    },
    "DOMAIN": {
        "level": "full",
        "label": "Domain",
        "help": "WAF detection + payload testing",
    },
    "WILDCARD": {
        "level": "partial",
        "label": "Wildcard Domain",
        "help": "WAF detection + payload testing on root domain. Subdomain enum not included — use tools like subfinder/amass first",
    },
    # PARTIAL: Fray can help with some aspects
    "CIDR": {
        "level": "partial",
        "label": "IP Range (CIDR)",
        "help": "Fray can test individual IPs if they serve HTTP. Use nmap/masscan to find web services first",
    },
    "OTHER": {
        "level": "partial",
        "label": "Other Asset",
        "help": "May contain web URLs — check instructions. Fray can test any HTTP endpoint",
    },
    "SMART_CONTRACT": {
        "level": "partial",
        "label": "Smart Contract",
        "help": "If the contract has a web frontend, Fray can test WAF on it. Contract audit requires Slither/Mythril",
    },
    # NONE: Fray cannot help
    "APPLE_STORE_APP_ID": {
        "level": "none",
        "label": "iOS App",
        "help": "Mobile app testing — use Burp Suite/Frida for API interception, then feed endpoints to Fray",
    },
    "GOOGLE_PLAY_APP_ID": {
        "level": "none",
        "label": "Android App",
        "help": "Mobile app testing — use Burp Suite/Frida for API interception, then feed endpoints to Fray",
    },
    "DOWNLOADABLE_EXECUTABLES": {
        "level": "none",
        "label": "Desktop App",
        "help": "Binary analysis — use Ghidra/IDA for reverse engineering, intercept HTTP traffic with mitmproxy",
    },
    "SOURCE_CODE": {
        "level": "none",
        "label": "Source Code",
        "help": "Code review — use Semgrep/CodeQL for SAST. If repo has a web app, deploy locally and test with Fray",
    },
    "HARDWARE": {
        "level": "none",
        "label": "Hardware/Appliance",
        "help": "Requires physical/network access. If it has a web admin panel, Fray can test that endpoint",
    },
    "WINDOWS_APP_STORE_APP_ID": {
        "level": "none",
        "label": "Windows Store App",
        "help": "Desktop app testing — intercept HTTP traffic with Burp/mitmproxy, then feed endpoints to Fray",
    },
}


def analyze_scope(scopes: List[Dict], program_handle: str = "") -> Dict:
    """Analyze scope entries and classify by Fray capability.

    Returns a dict with 'full', 'partial', 'none' lists and summary stats.
    """
    analysis = {
        "full": [],      # Fray can fully test
        "partial": [],   # Fray can partially help
        "none": [],      # Outside Fray's capabilities
        "total": len(scopes),
        "testable_count": 0,
    }

    for scope in scopes:
        asset_type = scope.get("type", "OTHER")
        identifier = scope.get("identifier", "")
        bounty = scope.get("bounty", False)
        instruction = scope.get("instruction", "")

        cap = _ASSET_CAPABILITY.get(asset_type, _ASSET_CAPABILITY["OTHER"])
        level = cap["level"]

        # For web-testable types, check domain safety
        safe = True
        safety_note = ""
        if level in ("full", "partial") and asset_type in ("URL", "DOMAIN", "WILDCARD"):
            # Normalize to URL for safety check
            test_id = identifier
            if test_id.startswith("*."):
                test_id = test_id[2:]
            if not test_id.startswith(("http://", "https://")):
                test_id = f"https://{test_id}"
            safe, reason = is_safe_target(test_id, program_handle)
            if not safe:
                safety_note = f" [SHARED: {reason}]"

        # Check for special instructions
        notes = []
        if instruction:
            inst_lower = instruction.lower()
            if "vpn" in inst_lower:
                notes.append("VPN required")
            if "user-agent" in inst_lower:
                notes.append("Custom User-Agent required")
            if any(w in inst_lower for w in ("test account", "credentials", "password")):
                notes.append("Test credentials provided")
            if any(w in inst_lower for w in ("fake id", "cnp", "rijksregister")):
                notes.append("Fake ID/registration needed")

        entry = {
            "type": asset_type,
            "identifier": identifier,
            "bounty": bounty,
            "level": level,
            "label": cap["label"],
            "help": cap["help"],
            "safe": safe,
            "safety_note": safety_note,
            "notes": notes,
            "instruction": instruction,
        }

        analysis[level].append(entry)

    analysis["testable_count"] = len(analysis["full"]) + len(analysis["partial"])
    return analysis


def print_scope_analysis(analysis: Dict, program: str):
    """Print formatted scope analysis report."""
    total = analysis["total"]
    full = analysis["full"]
    partial = analysis["partial"]
    none_list = analysis["none"]

    print(f"\n  {Colors.BOLD}Scope Analysis for {program}{Colors.END}")
    print(f"  {Colors.DIM}{'─' * 60}{Colors.END}")
    print(f"  Total scope entries: {total}")
    print(f"  {Colors.GREEN}Full support:    {len(full):>3}{Colors.END}  (WAF detect + payload test)")
    print(f"  {Colors.YELLOW}Partial support: {len(partial):>3}{Colors.END}  (Fray can help with parts)")
    print(f"  {Colors.DIM}Not supported:   {len(none_list):>3}{Colors.END}  (outside Fray's scope)")

    # Full support
    if full:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}✓ Full Fray Support{Colors.END}")
        for e in full:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            safe_tag = "" if e["safe"] else f" {Colors.RED}⚠ SHARED{Colors.END}"
            notes_str = f" {Colors.DIM}({', '.join(e['notes'])}){Colors.END}" if e["notes"] else ""
            print(f"    {bounty_tag}{Colors.END} {e['type']:<10} {e['identifier']}{safe_tag}{notes_str}")

    # Partial support
    if partial:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}◐ Partial Fray Support{Colors.END}")
        for e in partial:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            safe_tag = "" if e["safe"] else f" {Colors.RED}⚠ SHARED{Colors.END}"
            notes_str = f" {Colors.DIM}({', '.join(e['notes'])}){Colors.END}" if e["notes"] else ""
            print(f"    {bounty_tag}{Colors.END} {e['label']:<20} {e['identifier']}")
            print(f"       {Colors.DIM}→ {e['help']}{Colors.END}{safe_tag}{notes_str}")

    # Not supported
    if none_list:
        print(f"\n  {Colors.DIM}{Colors.BOLD}✗ Outside Fray's Scope{Colors.END}")
        for e in none_list:
            bounty_tag = f"{Colors.GREEN}$$" if e["bounty"] else f"{Colors.DIM}--"
            print(f"    {bounty_tag}{Colors.END} {e['label']:<20} {e['identifier']}")
            print(f"       {Colors.DIM}→ {e['help']}{Colors.END}")

    # Actionable summary
    safe_full = [e for e in full if e["safe"]]
    safe_partial = [e for e in partial if e["safe"] and e["type"] in ("WILDCARD", "OTHER")]
    testable = len(safe_full) + len(safe_partial)

    print(f"\n  {Colors.DIM}{'─' * 60}{Colors.END}")
    print(f"  {Colors.BOLD}Ready to test: {testable} target(s){Colors.END}")
    if none_list:
        print(f"  {Colors.DIM}Tip: For mobile apps, intercept API traffic with Burp Suite,")
        print(f"  then feed the API endpoints to: fray bounty --urls api_endpoints.txt{Colors.END}")
    print()


# ── Domain Safety & Ownership Validation ─────────────────────────────────────

# Shared platforms: domains owned by major providers, NOT the bounty program.
# Attacking these means attacking the provider, not the target company.
SHARED_PLATFORMS = {
    # Code hosting
    "github.com", "github.io", "githubusercontent.com", "gitlab.com",
    "bitbucket.org", "bitbucket.io",
    # Cloud providers
    "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "s3.amazonaws.com", "execute-api.amazonaws.com",
    "azurewebsites.net", "azure.com", "blob.core.windows.net",
    "cloudapp.azure.com", "trafficmanager.net",
    "googleapis.com", "appspot.com", "firebaseapp.com",
    "cloudfunctions.net", "run.app", "web.app",
    # CDN / Hosting
    "cloudflare.com", "workers.dev", "pages.dev",
    "herokuapp.com", "herokucdn.com",
    "vercel.app", "netlify.app", "netlify.com",
    "surge.sh", "now.sh", "render.com",
    # SaaS / Third-party
    "zendesk.com", "freshdesk.com", "intercom.io",
    "salesforce.com", "force.com",
    "hubspot.com", "marketo.com", "mailchimp.com",
    "google.com", "youtube.com", "goo.gl",
    "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "t.co",
    "linkedin.com", "apple.com",
    # Documentation / Wiki
    "readthedocs.io", "gitbook.io", "notion.so",
    "confluence.atlassian.net", "atlassian.net",
    "jira.com", "trello.com",
    # Container / Registry
    "docker.io", "docker.com", "gcr.io", "quay.io",
    # Package registries
    "npmjs.com", "npmjs.org", "pypi.org", "rubygems.org",
    "crates.io", "nuget.org", "packagist.org",
    # Other shared infra
    "slack.com", "zoom.us", "teams.microsoft.com",
    "wordpress.com", "wpengine.com", "shopify.com",
}

# Programs that OWN these domains (handle → set of domains they actually own)
# github program owns github.com, shopify owns shopify.com, etc.
_PROGRAM_OWNED_OVERRIDES: Dict[str, set] = {
    "github": {"github.com", "github.io", "githubusercontent.com", "github.net",
               "githubapp.com", "npmjs.com", "npmjs.org"},
    "shopify": {"shopify.com", "shopifycs.com", "shopify.io", "shopifykloud.com"},
    "gitlab": {"gitlab.com", "gitlab.net", "gitlab.org"},
    "slack": {"slack.com", "slackb.com", "slack-edge.com", "slack-imgs.com",
              "slack-files.com", "slack-core.com", "slack-redir.net"},
    "automattic": {"wordpress.com", "tumblr.com", "gravatar.com"},
    "cloudflare": {"cloudflare.com", "workers.dev", "pages.dev"},
    "google": {"google.com", "googleapis.com", "youtube.com"},
}


def is_safe_target(url: str, program_handle: str = "") -> Tuple[bool, str]:
    """Check if a URL is safe to test (not shared infrastructure).

    Returns (is_safe, reason).
    """
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "invalid URL"

    # Check program-owned overrides first
    program_owned = _PROGRAM_OWNED_OVERRIDES.get(program_handle.lower(), set())
    for owned_domain in program_owned:
        if hostname == owned_domain or hostname.endswith("." + owned_domain):
            return True, "program-owned domain"

    # Check against shared platforms
    for shared in SHARED_PLATFORMS:
        if hostname == shared or hostname.endswith("." + shared):
            return False, f"shared platform ({shared})"

    return True, "ok"


def filter_safe_targets(urls: List[str], program_handle: str = "") -> Tuple[List[str], List[Dict]]:
    """Filter URLs to only safe-to-test targets.

    Returns (safe_urls, skipped_entries).
    """
    safe = []
    skipped = []
    for url in urls:
        ok, reason = is_safe_target(url, program_handle)
        if ok:
            safe.append(url)
        else:
            skipped.append({"url": url, "reason": reason})
    return safe, skipped


def normalize_scope_to_urls(scopes: List[Dict]) -> List[str]:
    """Convert scope entries to testable URLs."""
    _WEB_TYPES = {"URL", "DOMAIN", "WILDCARD"}
    urls = []
    for scope in scopes:
        # Skip non-web asset types
        if scope.get("type", "") not in _WEB_TYPES:
            continue

        identifier = scope.get("identifier", "").strip()
        if not identifier:
            continue

        # Skip wildcard-only entries
        if identifier in ("*", "*."):
            continue

        # Handle wildcard domains: *.example.com → https://example.com
        if identifier.startswith("*."):
            identifier = identifier[2:]

        # Add scheme if missing
        if not identifier.startswith(("http://", "https://")):
            identifier = f"https://{identifier}"

        # Clean up trailing paths
        parsed = urllib.parse.urlparse(identifier)
        if parsed.hostname:
            url = f"{parsed.scheme}://{parsed.hostname}"
            if parsed.port and parsed.port not in (80, 443):
                url += f":{parsed.port}"
            urls.append(url)

    return sorted(set(urls))


def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from a text file (one per line)."""
    urls = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith(("http://", "https://")):
                        line = f"https://{line}"
                    urls.append(line)
    except (FileNotFoundError, OSError) as e:
        print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.END}")
    return urls


# ── Bounty Testing ───────────────────────────────────────────────────────────

def extract_custom_headers(scopes: List[Dict]) -> Dict[str, str]:
    """Extract required custom headers from scope instructions.

    Looks for User-Agent requirements like:
      'User-agent: hackerone'
      'Add the following User-Agent header ... User-agent: hackerone'
    """
    headers: Dict[str, str] = {}
    for scope in scopes:
        instruction = scope.get("instruction", "") or ""
        if not instruction:
            continue
        # Look for User-Agent requirement
        # Matches patterns like:
        #   'User-agent: hackerone'
        #   'User-agent: hackerone -'
        #   'User-Agent header ... User-agent: hackerone'
        ua_match = re.search(
            r'[Uu]ser[-\s]?[Aa]gent:\s*([a-zA-Z0-9_./-]+)',
            instruction
        )
        if ua_match:
            ua_val = ua_match.group(1).strip().rstrip('.-')
            # Skip generic words that aren't actual UA values
            if ua_val and ua_val.lower() not in ("header", "the", "your", "when", "string"):
                headers["User-Agent"] = ua_val
                break  # Use first found
    return headers


def scan_target(url: str, categories: List[str], max_payloads: int = 10,
                timeout: int = 8, delay: float = 0.5,
                custom_headers: Optional[Dict[str, str]] = None,
                smart: bool = True) -> Dict:
    """Run WAF detection and payload tests on a single target.

    Args:
        smart: Use adaptive payload evolution (default True for bounty).
               Probes WAF first, scores payloads, skips redundant ones.
    """
    result = {
        "url": url,
        "waf": None,
        "waf_confidence": 0,
        "categories": {},
        "total_tested": 0,
        "total_blocked": 0,
        "total_passed": 0,
        "block_rate": 0.0,
        "evolve_stats": None,
    }

    # WAF detection
    try:
        from fray.detector import WAFDetector
        detector = WAFDetector()
        detection = detector.detect_waf(url)
        result["waf"] = detection.get("waf", "None")
        result["waf_confidence"] = detection.get("confidence", 0)
    except Exception as e:
        result["waf"] = f"Error: {e}"

    # Payload tests per category
    from fray.tester import WAFTester
    for cat in categories:
        cat_dir = PAYLOADS_DIR / cat
        if not cat_dir.exists():
            continue

        tester = WAFTester(target=url, timeout=timeout, delay=delay,
                           custom_headers=custom_headers)
        all_payloads = []
        for pf in sorted(cat_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))

        if not all_payloads:
            continue

        # Adaptive mode: probe → score → test → mutate
        if smart:
            from fray.evolve import adaptive_test
            test_results, evolve_stats, profile = adaptive_test(
                tester, all_payloads, max_payloads=max_payloads, verbose=False
            )
            result["evolve_stats"] = {
                "probes_sent": evolve_stats.probes_sent,
                "payloads_skipped": evolve_stats.payloads_skipped,
                "payloads_tested": evolve_stats.payloads_tested,
                "mutations_tested": evolve_stats.mutations_tested,
                "mutations_bypassed": evolve_stats.mutations_bypassed,
                "efficiency_gain": evolve_stats.efficiency_gain,
                "waf_strictness": profile.strictness,
                "blocked_tags": sorted(profile.blocked_tags),
                "allowed_tags": sorted(profile.allowed_tags),
            }
        else:
            test_results = tester.test_payloads(all_payloads, max_payloads=max_payloads)

        blocked = sum(1 for r in test_results if r.get("blocked"))
        passed = len(test_results) - blocked
        rate = (blocked / len(test_results) * 100) if test_results else 0.0

        bypassed = [
            {
                "payload": r.get("payload", ""),
                "status": r.get("status", 0),
                "final_url": r.get("final_url", ""),
                "redirects": r.get("redirects", 0),
                "reflected": r.get("reflected", False),
                "reflection_context": r.get("reflection_context", ""),
                "response_length": r.get("response_length", 0),
                "security_headers": r.get("security_headers", {}),
            }
            for r in test_results if not r.get("blocked")
        ]

        # Collect security headers from first non-blocked response
        cat_sec_headers = {}
        for r in test_results:
            if not r.get("blocked") and r.get("security_headers"):
                cat_sec_headers = r["security_headers"]
                break

        result["categories"][cat] = {
            "total": len(test_results),
            "blocked": blocked,
            "passed": passed,
            "block_rate": round(rate, 1),
            "bypassed": bypassed,
            "security_headers": cat_sec_headers,
        }
        result["total_tested"] += len(test_results)
        result["total_blocked"] += blocked
        result["total_passed"] += passed

    if result["total_tested"] > 0:
        result["block_rate"] = round(result["total_blocked"] / result["total_tested"] * 100, 1)

    return result


# ── Report ───────────────────────────────────────────────────────────────────

def print_bounty_report(targets: List[Dict], program: str, platform: str):
    """Print formatted bounty test report."""
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}")
    print(f"\n  {Colors.BOLD}Fray Bug Bounty Report{Colors.END}")
    print(f"  {Colors.DIM}Program: {program} ({platform}){Colors.END}")
    print(f"  {Colors.DIM}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{Colors.END}")
    print(f"  {Colors.DIM}Fray v{__version__}{Colors.END}")

    # Per-target summary
    print(f"\n  {Colors.BOLD}Target Results{Colors.END}")
    print(f"  {'Target':<35} {'WAF':<16} {'Block Rate':>10} {'Bypassed':>10}")
    print(f"  {'─' * 71}")

    total_bypassed = 0
    interesting_targets = []

    for t in targets:
        waf = t.get("waf", "None") or "None"
        rate = t.get("block_rate", 0.0)
        passed = t.get("total_passed", 0)
        total_bypassed += passed

        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        url_short = t["url"][:33] + ".." if len(t["url"]) > 35 else t["url"]
        waf_short = waf[:14] + ".." if len(waf) > 16 else waf

        print(f"  {url_short:<35} {waf_short:<16} {rc}{rate:>9.1f}%{Colors.END} {passed:>10}")

        if passed > 0:
            interesting_targets.append(t)

    # Bypass details with reflection status
    if interesting_targets:
        print(f"\n  {Colors.RED}{Colors.BOLD}Potential Findings{Colors.END}")
        for t in interesting_targets:
            print(f"\n  {Colors.CYAN}{t['url']}{Colors.END} — {t.get('waf', 'Unknown') or 'No'} WAF")
            for cat, cr in t.get("categories", {}).items():
                if cr.get("passed", 0) > 0:
                    reflected_count = sum(1 for bp in cr.get("bypassed", []) if bp.get("reflected"))
                    print(f"    {Colors.RED}{cat}:{Colors.END} {cr['passed']} unblocked, "
                          f"{Colors.RED}{reflected_count} reflected{Colors.END}" if reflected_count
                          else f"    {Colors.RED}{cat}:{Colors.END} {cr['passed']} unblocked, "
                          f"{Colors.DIM}0 reflected{Colors.END}")
                    for bp in cr.get("bypassed", [])[:3]:
                        ref_tag = f" {Colors.RED}REFLECTED{Colors.END}" if bp.get("reflected") else ""
                        print(f"      HTTP {bp.get('status', '?')}: {bp.get('payload', '')[:55]}{ref_tag}")

    # Summary
    total_tested = sum(t.get("total_tested", 0) for t in targets)
    total_blocked = sum(t.get("total_blocked", 0) for t in targets)
    overall_rate = (total_blocked / total_tested * 100) if total_tested > 0 else 0
    total_reflected = sum(
        sum(1 for bp in cr.get("bypassed", []) if bp.get("reflected"))
        for t in targets for cr in t.get("categories", {}).values()
    )

    print(f"\n  {Colors.DIM}{'─' * 65}{Colors.END}")
    print(f"  {Colors.BOLD}Summary{Colors.END}")
    print(f"  Targets scanned:  {len(targets)}")
    print(f"  Payloads tested:  {total_tested}")
    print(f"  Overall block:    {overall_rate:.1f}%")
    print(f"  Total unblocked:  {Colors.RED if total_bypassed > 0 else Colors.GREEN}"
          f"{total_bypassed}{Colors.END}")
    print(f"  Reflected (PoC):  {Colors.RED if total_reflected > 0 else Colors.GREEN}"
          f"{total_reflected}{Colors.END}")
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}")

    # Security-researcher-quality report for findings
    if interesting_targets:
        print(f"\n{'=' * 72}")
        print(f"  {Colors.BOLD}Vulnerability Report — Ready to Submit{Colors.END}")
        print(f"{'=' * 72}")
        for idx, t in enumerate(interesting_targets, 1):
            _print_h1_finding(t, idx, program, platform)
        print(f"{'=' * 72}\n")


# ── Category metadata for professional reports ──────────────────────────────

_VULN_META = {
    "xss": {
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "owasp": "A03:2021 — Injection",
        "cvss_base": "6.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity": "Medium",
        "title_verb": "Cross-Site Scripting (Reflected)",
        "impact": [
            "Session hijacking via stolen cookies (`document.cookie` exfiltration)",
            "Account takeover by injecting credential-harvesting forms into the trusted domain",
            "Phishing attacks hosted on the legitimate domain, bypassing user suspicion",
            "Client-side keylogging and form data interception",
            "Defacement of the application for targeted users",
        ],
        "attack_scenario": (
            "An attacker crafts a URL containing a malicious {cat} payload in the `input` "
            "parameter and sends it to a victim (e.g., via email or social media). When the "
            "victim clicks the link, the payload executes in their browser session within "
            "the trusted `{url}` origin. This allows the attacker to steal the victim's "
            "session token, redirect them to a phishing page, or perform actions on their behalf."
        ),
        "remediation": [
            "Implement context-aware output encoding (HTML entity, JavaScript, URL encoding depending on the injection point)",
            "Deploy a strict Content-Security-Policy (CSP) header — at minimum: `script-src 'self'` — to prevent inline script execution",
            "Set `HttpOnly` and `Secure` flags on session cookies to limit the impact of XSS",
            "Use a templating engine that auto-escapes output by default (e.g., Jinja2 with autoescape, React JSX)",
            "Review and harden WAF rules to detect common XSS patterns including obfuscated variants",
        ],
    },
    "sqli": {
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "owasp": "A03:2021 — Injection",
        "cvss_base": "8.6",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "severity": "High",
        "title_verb": "SQL Injection",
        "impact": [
            "Full database extraction including user credentials, PII, and payment data",
            "Authentication bypass via crafted `OR 1=1` or `UNION`-based queries",
            "Privilege escalation from regular user to database administrator",
            "Data manipulation or deletion through `UPDATE`/`DELETE` injection",
            "In some configurations, remote code execution via `xp_cmdshell` or `LOAD_FILE()`",
        ],
        "attack_scenario": (
            "An attacker submits a crafted SQL payload through the `input` parameter on `{url}`. "
            "Because the WAF does not filter the payload and the server-side query likely "
            "concatenates user input directly, the attacker can exfiltrate sensitive data "
            "using `UNION SELECT` or blind techniques (time-based, boolean-based). "
            "In the worst case, this provides full read access to the database."
        ),
        "remediation": [
            "Use parameterized queries (prepared statements) for ALL database interactions — this is the primary fix",
            "Implement an allowlist for expected input formats where possible",
            "Apply the principle of least privilege to database accounts (no admin privileges for web app users)",
            "Update WAF rules to detect SQLi patterns including inline comments, encoding bypasses, and second-order injection",
            "Enable database query logging and set up alerts for suspicious query patterns",
        ],
    },
    "ssti": {
        "cwe": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
        "owasp": "A03:2021 — Injection",
        "cvss_base": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "Critical",
        "title_verb": "Server-Side Template Injection",
        "impact": [
            "Remote Code Execution (RCE) on the application server",
            "Full server compromise including file system read/write access",
            "Lateral movement to internal infrastructure",
            "Data exfiltration from the server environment including secrets and API keys",
        ],
        "attack_scenario": (
            "An attacker injects a template expression (e.g., `{{7*7}}`) through user input on `{url}`. "
            "If the server evaluates this and returns `49`, SSTI is confirmed. The attacker can "
            "then escalate to RCE using engine-specific payloads (e.g., Jinja2 `__class__.__mro__` chains)."
        ),
        "remediation": [
            "Never pass user input directly into template rendering functions",
            "Use a sandboxed template engine or restrict the template context",
            "Implement strict input validation with allowlisted characters",
            "Update WAF rules to block template expression patterns (`{{`, `${`, `<%`)",
        ],
    },
    "cmdi": {
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "owasp": "A03:2021 — Injection",
        "cvss_base": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "Critical",
        "title_verb": "OS Command Injection",
        "impact": [
            "Full remote code execution on the server",
            "Complete server compromise — read/write/delete any file",
            "Pivoting to internal network services",
            "Installation of backdoors or cryptocurrency miners",
        ],
        "attack_scenario": (
            "An attacker injects shell metacharacters (`;`, `|`, `$()`) through user input on `{url}`. "
            "The application passes this unsanitized input to a system command, allowing the attacker "
            "to execute arbitrary OS commands with the web server's privileges."
        ),
        "remediation": [
            "Avoid calling OS commands from user input entirely — use language-native libraries instead",
            "If OS commands are unavoidable, use strict allowlisting of expected values",
            "Never use shell=True or string concatenation for command construction",
            "Run the application with minimal OS privileges (non-root, restricted filesystem)",
        ],
    },
    "ssrf": {
        "cwe": "CWE-918: Server-Side Request Forgery",
        "owasp": "A10:2021 — Server-Side Request Forgery (SSRF)",
        "cvss_base": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "severity": "High",
        "title_verb": "Server-Side Request Forgery",
        "impact": [
            "Access to internal services (databases, admin panels) not exposed to the internet",
            "Cloud metadata endpoint access (e.g., `169.254.169.254`) to steal IAM credentials",
            "Port scanning of internal infrastructure",
            "Bypassing network-level access controls",
        ],
        "attack_scenario": (
            "An attacker provides an internal URL (e.g., `http://169.254.169.254/latest/meta-data/`) "
            "through a URL parameter on `{url}`. The server fetches this URL on behalf of the attacker, "
            "potentially leaking cloud provider credentials or internal service data."
        ),
        "remediation": [
            "Implement an allowlist of permitted destination hosts/URLs",
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
            "Disable HTTP redirects in server-side HTTP clients",
            "Use network-level segmentation to prevent the application from reaching sensitive internal services",
        ],
    },
}

# Default fallback for categories not in _VULN_META
_VULN_META_DEFAULT = {
    "cwe": "CWE-20: Improper Input Validation",
    "owasp": "A03:2021 — Injection",
    "cvss_base": "5.3",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "severity": "Medium",
    "title_verb": "Input Validation Bypass",
    "impact": [
        "Unfiltered payloads reach the application backend, increasing attack surface",
        "Potential for exploitation depending on server-side handling of the input",
    ],
    "attack_scenario": (
        "An attacker sends crafted payloads through user-controlled input on `{url}`. "
        "The WAF fails to block these payloads, allowing them to reach the backend application."
    ),
    "remediation": [
        "Implement server-side input validation with strict allowlisting",
        "Review and update WAF rules for the relevant attack patterns",
        "Apply defense-in-depth: do not rely solely on the WAF for input filtering",
    ],
}


def _print_h1_finding(target: Dict, finding_num: int, program: str, platform: str):
    """Print a single finding in security-researcher-quality report format.

    Includes: verified reflection, security header analysis, CVSS scoring,
    CWE/OWASP mapping, realistic attack scenario, and actionable remediation.
    """
    url = target["url"]
    waf = target.get("waf", "None") or "None"

    # Collect all bypasses across categories
    all_bypasses = []
    for cat, cr in target.get("categories", {}).items():
        for bp in cr.get("bypassed", []):
            all_bypasses.append({**bp, "category": cat})

    if not all_bypasses:
        return

    top_cat = all_bypasses[0].get("category", "xss")
    meta = _VULN_META.get(top_cat, _VULN_META_DEFAULT)

    # Analyze reflection evidence
    reflected_payloads = [bp for bp in all_bypasses if bp.get("reflected")]
    unreflected_payloads = [bp for bp in all_bypasses if not bp.get("reflected")]

    # Determine verified severity
    if reflected_payloads:
        severity = meta["severity"]
        verification_status = "Verified — Payload Reflected in Response"
    else:
        # Lower severity if no reflection
        severity_downgrade = {"Critical": "High", "High": "Medium", "Medium": "Low"}
        severity = severity_downgrade.get(meta["severity"], meta["severity"])
        verification_status = "Unverified — Payload accepted but not reflected (manual verification recommended)"

    # Collect security headers
    sec_headers = {}
    for cr in target.get("categories", {}).values():
        if cr.get("security_headers"):
            sec_headers = cr["security_headers"]
            break

    # ── Title ────────────────────────────────────────────────────────────
    print(f"""
{'─' * 72}
## Finding #{finding_num}: {meta['title_verb']} — {url}
{'─' * 72}

**Title:** {meta['title_verb']} via WAF bypass on {url}
**Severity:** {severity} ({meta['cvss_base']} — {meta['cvss_vector']})
**Weakness:** {meta['cwe']}
**OWASP:** {meta['owasp']}
**Asset:** `{url}`
**Verification:** {verification_status}""")

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"""
### Summary

During authorized security testing of the `{program}` program on {platform}, I identified that `{url}` does not adequately filter {top_cat.upper()} payloads. Out of {target.get('total_tested', 0)} payloads tested, {len(all_bypasses)} were accepted by the server without being blocked by the {"WAF (" + waf + ")" if waf != "None" else "application (no WAF detected)"}.""")

    if reflected_payloads:
        print(f"""
**Critically, {len(reflected_payloads)} payload(s) were reflected in the HTTP response body**, confirming the application echoes unsanitized user input back to the client. This is a strong indicator of exploitable {meta['title_verb']}.""")
    else:
        print(f"""
Note: While {len(all_bypasses)} payload(s) passed through without WAF blocking (HTTP {all_bypasses[0].get('status', '?')}), I did not observe direct reflection in the response body during this automated scan. Manual testing is recommended to:
- Identify the specific injection points (query parameters, form fields, headers)
- Confirm whether payloads are reflected in other response contexts (JavaScript, HTML attributes, JSON)
- Check for stored/persistent injection""")

    # ── Steps to Reproduce ───────────────────────────────────────────────
    print(f"""
### Steps to Reproduce

1. Open a browser or HTTP client (e.g., `curl`, Burp Suite)
2. Send the following request to `{url}`""")

    # Show reflected payloads first (strongest evidence), then unreflected
    show_payloads = reflected_payloads[:3] if reflected_payloads else unreflected_payloads[:3]
    for i, bp in enumerate(show_payloads, 1):
        final_url_note = ""
        if bp.get("redirects", 0) > 0:
            final_url_note = f"\n   (Server redirected {bp['redirects']}x → final: `{bp.get('final_url', '')}`)"

        print(f"""
**Payload {i}:**
```
GET {url}?input={urllib.parse.quote(bp.get('payload', ''), safe='')} HTTP/1.1
Host: {urllib.parse.urlparse(url).hostname}
User-Agent: hackerone
```{final_url_note}

**Response:** HTTP {bp.get('status', '?')} — Payload was **not blocked** by the WAF""")

        if bp.get("reflected"):
            ctx = bp.get("reflection_context", "")
            print(f"""
**Evidence of Reflection** — the payload appears in the response body:
```html
{ctx}
```
This confirms the server echoes the unsanitized input back to the client.""")

    # ── Security Header Analysis ─────────────────────────────────────────
    print(f"""
### Security Header Analysis

| Header | Value | Assessment |
|--------|-------|------------|""")

    important_headers = {
        "content-security-policy": ("CSP", "Limits which scripts can execute"),
        "x-xss-protection": ("X-XSS-Protection", "Legacy browser XSS filter"),
        "x-content-type-options": ("X-Content-Type-Options", "Prevents MIME sniffing"),
        "x-frame-options": ("X-Frame-Options", "Prevents clickjacking"),
        "strict-transport-security": ("HSTS", "Enforces HTTPS"),
    }
    missing_critical = []
    for hdr_key, (display_name, desc) in important_headers.items():
        val = sec_headers.get(hdr_key, "")
        if val:
            print(f"| `{display_name}` | `{val[:50]}` | Present |")
        else:
            print(f"| `{display_name}` | *Missing* | **Not set** — {desc} |")
            missing_critical.append(display_name)

    server_val = sec_headers.get("server", "")
    if server_val:
        print(f"| `Server` | `{server_val}` | Consider removing to reduce information leakage |")

    if missing_critical:
        print(f"\n**{len(missing_critical)} critical security header(s) missing:** {', '.join(missing_critical)}")

    # ── Attack Scenario ──────────────────────────────────────────────────
    scenario = meta["attack_scenario"].format(cat=top_cat.upper(), url=url)
    print(f"""
### Attack Scenario

{scenario}""")

    # ── Impact ───────────────────────────────────────────────────────────
    print(f"""
### Impact
""")
    for imp in meta["impact"]:
        print(f"- {imp}")

    # ── Remediation ──────────────────────────────────────────────────────
    print(f"""
### Remediation
""")
    for i, fix in enumerate(meta["remediation"], 1):
        print(f"{i}. {fix}")

    # ── References ───────────────────────────────────────────────────────
    print(f"""
### Supporting Material / References

- {meta['cwe']}: https://cwe.mitre.org/data/definitions/{meta['cwe'].split('-')[1].split(':')[0]}.html
- {meta['owasp']}: https://owasp.org/Top10/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1#{meta['cvss_vector']}
- Testing methodology: Fray v{__version__} (https://github.com/dalisecurity/fray)
- Scan date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
- Payloads tested: {target.get('total_tested', 0)} across {', '.join(target.get('categories', {}).keys())}""")


# ── Bounty Report Template Generator (#118) ──────────────────────────────────

def generate_bounty_report_md(
    target: str,
    results: List[Dict],
    program: str = "",
    platform: str = "hackerone",
    waf_vendor: str = "",
    category: str = "",
) -> str:
    """Generate a Markdown bounty report from scan results.

    Can be used standalone with `fray test --json` output or from
    `fray bounty --report`.

    Args:
        target:     Target URL.
        results:    List of test_payload result dicts.
        program:    Bug bounty program handle.
        platform:   Platform name (hackerone, bugcrowd).
        waf_vendor: Detected WAF vendor.
        category:   Vulnerability category (xss, sqli, etc.).

    Returns:
        Markdown string ready for HackerOne/Bugcrowd submission.
    """
    bypasses = [r for r in results if not r.get("blocked") and r.get("bypass_confidence", 0) > 0]
    reflected = [r for r in bypasses if r.get("reflected")]
    total = len(results)
    blocked = sum(1 for r in results if r.get("blocked"))

    # Auto-detect category from results
    if not category:
        cats = [r.get("category", "") for r in bypasses if r.get("category")]
        category = cats[0] if cats else "xss"

    meta = _VULN_META.get(category, _VULN_META_DEFAULT)

    # Adjust severity based on reflection
    if reflected:
        severity = meta["severity"]
        verification = "Verified — Payload Reflected in Response"
    else:
        _down = {"Critical": "High", "High": "Medium", "Medium": "Low"}
        severity = _down.get(meta["severity"], meta["severity"])
        verification = "Unverified — Payload accepted but not reflected"

    waf_label = waf_vendor if waf_vendor and waf_vendor != "None" else "no WAF detected"
    hostname = urllib.parse.urlparse(target).hostname or target
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# {meta['title_verb']} — {target}\n")
    lines.append(f"**Title:** {meta['title_verb']} via WAF bypass on {target}")
    lines.append(f"**Severity:** {severity} ({meta['cvss_base']} — {meta['cvss_vector']})")
    lines.append(f"**Weakness:** {meta['cwe']}")
    lines.append(f"**OWASP:** {meta['owasp']}")
    lines.append(f"**Asset:** `{target}`")
    lines.append(f"**Verification:** {verification}\n")

    # Summary
    lines.append("## Summary\n")
    prog_str = f"the `{program}` program on {platform}" if program else "the target"
    lines.append(
        f"During authorized security testing of {prog_str}, I identified that "
        f"`{target}` does not adequately filter {category.upper()} payloads. "
        f"Out of {total} payloads tested, {len(bypasses)} were accepted by the "
        f"server without being blocked by the {waf_label}. "
        f"{blocked} payloads were correctly blocked."
    )
    if reflected:
        lines.append(
            f"\n**{len(reflected)} payload(s) were reflected in the HTTP response body**, "
            f"confirming exploitable {meta['title_verb']}."
        )
    lines.append("")

    # Steps to Reproduce
    lines.append("## Steps to Reproduce\n")
    lines.append("1. Open a browser or HTTP client (e.g., `curl`, Burp Suite)")
    lines.append(f"2. Send the following request(s) to `{target}`\n")

    show = (reflected or bypasses)[:3]
    for i, bp in enumerate(show, 1):
        payload = bp.get("payload", "")
        enc = urllib.parse.quote(payload, safe="")
        param = "input"
        lines.append(f"**Payload {i}:**")
        lines.append("```")
        lines.append(f"GET {target}?{param}={enc} HTTP/1.1")
        lines.append(f"Host: {hostname}")
        lines.append("```")
        lines.append(f"**Response:** HTTP {bp.get('status', '?')} — Payload was **not blocked**\n")
        if bp.get("reflected") and bp.get("reflection_context"):
            lines.append("**Evidence of Reflection:**")
            lines.append("```html")
            lines.append(bp["reflection_context"][:200])
            lines.append("```\n")

    # Impact
    lines.append("## Impact\n")
    for imp in meta["impact"]:
        lines.append(f"- {imp}")
    lines.append("")

    # Attack Scenario
    lines.append("## Attack Scenario\n")
    lines.append(meta["attack_scenario"].format(cat=category.upper(), url=target))
    lines.append("")

    # Remediation
    lines.append("## Remediation\n")
    for i, fix in enumerate(meta["remediation"], 1):
        lines.append(f"{i}. {fix}")
    lines.append("")

    # References
    cwe_id = meta["cwe"].split("-")[1].split(":")[0]
    lines.append("## References\n")
    lines.append(f"- {meta['cwe']}: https://cwe.mitre.org/data/definitions/{cwe_id}.html")
    lines.append(f"- {meta['owasp']}: https://owasp.org/Top10/")
    lines.append(f"- CVSS: https://www.first.org/cvss/calculator/3.1#{meta['cvss_vector']}")
    lines.append(f"- Tool: Fray v{__version__} (https://github.com/dalisecurity/fray)")
    lines.append(f"- Date: {now}")
    lines.append(f"- Payloads tested: {total} ({category})")

    return "\n".join(lines)


def generate_report_from_json(json_path: str, output: str = "",
                               program: str = "", platform: str = "hackerone") -> str:
    """Generate a bounty report from a fray test JSON output file.

    Args:
        json_path: Path to JSON file from `fray test --json -o results.json`.
        output:    If set, write Markdown to this file.
        program:   Bug bounty program handle.
        platform:  Platform name.

    Returns:
        Markdown string.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both {results: [...]} and bare list
    if isinstance(data, dict):
        results = data.get("results", data.get("payloads", []))
        target = data.get("target", data.get("url", ""))
        waf = data.get("waf_vendor", data.get("waf", ""))
        category = data.get("category", "")
    elif isinstance(data, list):
        results = data
        target = results[0].get("target", "") if results else ""
        waf = ""
        category = results[0].get("category", "") if results else ""
    else:
        results = []
        target = ""
        waf = ""
        category = ""

    md = generate_bounty_report_md(
        target=target, results=results, program=program,
        platform=platform, waf_vendor=waf, category=category,
    )

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(md)

    return md


# ── Entry Point ──────────────────────────────────────────────────────────────

def run_bounty(
    platform: Optional[str] = None,
    program: Optional[str] = None,
    urls_file: Optional[str] = None,
    categories: Optional[List[str]] = None,
    max_payloads: int = 10,
    timeout: int = 8,
    delay: float = 0.5,
    output: Optional[str] = None,
    scope_only: bool = False,
    force: bool = False,
    smart: bool = True,
    workers: int = 1,
):
    """Main entry point for fray bounty."""
    print(f"\n{Colors.BOLD}Fray Bounty v{__version__}{Colors.END}")
    print(f"{Colors.DIM}{'━' * 60}{Colors.END}")

    test_categories = categories or ["xss", "sqli"]
    # Filter to existing categories
    available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    test_categories = [c for c in test_categories if c in available]

    urls: List[str] = []
    scopes: List[Dict] = []

    # ── Fetch scope from platform ────────────────────────────────────────
    if urls_file:
        print(f"  Loading URLs from: {urls_file}")
        urls = load_urls_from_file(urls_file)
        platform = platform or "file"
        program = program or urls_file

    elif platform and program:
        platform = platform.lower()
        # Normalize platform aliases
        if platform in ("h1", "hackerone", "hacker-one"):
            platform = "hackerone"
        elif platform in ("bc", "bugcrowd", "bug-crowd"):
            platform = "bugcrowd"

        print(f"  Platform: {platform}")
        print(f"  Program:  {program}")

        if platform == "hackerone":
            print(f"{Colors.DIM}  Fetching public scope from HackerOne...{Colors.END}")
            api = HackerOnePublic()
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                print(f"  {Colors.DIM}Make sure '{program}' is a valid public program handle.{Colors.END}")
                print(f"  {Colors.DIM}Find programs at: https://hackerone.com/directory{Colors.END}\n")
                return

            # Analyze full scope first
            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")

        elif platform == "bugcrowd":
            print(f"{Colors.DIM}  Fetching public scope from Bugcrowd...{Colors.END}")
            api = BugcrowdPublic()
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                print(f"  {Colors.DIM}Make sure '{program}' is a valid public program handle.{Colors.END}")
                print(f"  {Colors.DIM}Find programs at: https://bugcrowd.com/programs{Colors.END}\n")
                return

            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")

        else:
            print(f"  {Colors.RED}Unknown platform: {platform}{Colors.END}")
            print(f"  {Colors.DIM}Supported: hackerone (h1), bugcrowd (bc){Colors.END}")
            return

    elif program:
        # Auto-detect: try HackerOne first, then Bugcrowd
        print(f"  Program: {program}")
        print(f"{Colors.DIM}  Auto-detecting platform...{Colors.END}")

        api = HackerOnePublic()
        ok, scopes = api.get_program_scope(program)
        if ok and scopes:
            platform = "hackerone"
            print(f"  {Colors.GREEN}Found on HackerOne!{Colors.END}")

            analysis = analyze_scope(scopes, program)
            print_scope_analysis(analysis, program)

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")
        else:
            api_bc = BugcrowdPublic()
            ok, scopes = api_bc.get_program_scope(program)
            if ok and scopes:
                platform = "bugcrowd"
                print(f"  {Colors.GREEN}Found on Bugcrowd!{Colors.END}")

                analysis = analyze_scope(scopes, program)
                print_scope_analysis(analysis, program)

                urls = normalize_scope_to_urls(scopes)
                print(f"  {Colors.GREEN}{len(urls)} testable web URL(s) extracted{Colors.END}")
            else:
                print(f"  {Colors.RED}Program '{program}' not found on HackerOne or Bugcrowd.{Colors.END}")
                print(f"  {Colors.DIM}Try: fray bounty --platform hackerone --program <handle>{Colors.END}\n")
                return
    else:
        print(f"  {Colors.RED}Provide --program <handle>, or --urls file{Colors.END}")
        print(f"  {Colors.DIM}Examples:{Colors.END}")
        print(f"    fray bounty --program github")
        print(f"    fray bounty --platform hackerone --program github")
        print(f"    fray bounty --urls targets.txt")
        return

    if not urls:
        print(f"\n  {Colors.YELLOW}No testable URLs found in scope.{Colors.END}\n")
        return

    # ── Extract required headers from scope instructions ───────────────
    scope_headers: Dict[str, str] = extract_custom_headers(scopes) if scopes else {}
    if scope_headers:
        print(f"\n  {Colors.CYAN}{Colors.BOLD}Required Headers (from program instructions):{Colors.END}")
        for k, v in scope_headers.items():
            print(f"    {k}: {v}")

    # ── Domain safety check ──────────────────────────────────────────────
    prog_handle = program or ""
    safe_urls, skipped = filter_safe_targets(urls, prog_handle)

    if skipped:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}Skipped (shared platforms — not owned by {prog_handle}):{Colors.END}")
        for s in skipped:
            print(f"    {Colors.DIM}SKIP{Colors.END}  {s['url']:<40} {Colors.DIM}{s['reason']}{Colors.END}")

    if not force:
        urls = safe_urls
    else:
        print(f"  {Colors.YELLOW}--force: testing ALL URLs including shared platforms{Colors.END}")

    if not urls:
        print(f"\n  {Colors.YELLOW}No safe targets to test after filtering shared platforms.{Colors.END}")
        print(f"  {Colors.DIM}Use --force to override safety checks.{Colors.END}\n")
        return

    # ── Scope-only mode ──────────────────────────────────────────────────
    if scope_only:
        print(f"\n  {Colors.BOLD}Safe Testable URLs ({len(urls)}):{Colors.END}")
        for u in urls:
            print(f"    {Colors.CYAN}{u}{Colors.END}")
        print(f"\n  {Colors.DIM}Remove --scope-only to run payload tests on these targets.{Colors.END}\n")
        return

    mode_label = f"{Colors.CYAN}Adaptive{Colors.END}" if smart else "Brute-force"
    effective_workers = min(workers, len(urls))
    parallel_label = f" | {Colors.CYAN}{effective_workers} workers{Colors.END}" if effective_workers > 1 else ""
    print(f"\n  {Colors.BOLD}Testing {len(urls)} target(s) × {len(test_categories)} categories × {max_payloads} payloads{Colors.END}")
    print(f"  {Colors.DIM}Categories: {', '.join(test_categories)}{Colors.END}")
    print(f"  Mode: {mode_label}{parallel_label}\n")

    # ── Run tests ────────────────────────────────────────────────────────
    def _print_result(i, url, result):
        waf = result.get("waf", "None") or "None"
        rate = result.get("block_rate", 0.0)
        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        es = result.get("evolve_stats")
        evolve_info = ""
        if es:
            evolve_info = (f" | {Colors.DIM}Adaptive: {es.get('efficiency_gain', 0)}% fewer requests, "
                          f"WAF={es.get('waf_strictness', '?')}{Colors.END}")
        print(f"  {Colors.DIM}[{i}/{len(urls)}]{Colors.END} {Colors.CYAN}{url}{Colors.END}")
        print(f"    WAF: {waf} | Block rate: {rc}{rate:.1f}%{Colors.END}{evolve_info}")

    all_results = []
    if effective_workers > 1:
        # Parallel execution
        futures = {}
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            for i, url in enumerate(urls, 1):
                fut = pool.submit(scan_target, url, test_categories,
                                  max_payloads=max_payloads, timeout=timeout,
                                  delay=delay, custom_headers=scope_headers or None,
                                  smart=smart)
                futures[fut] = (i, url)
            for fut in as_completed(futures):
                i, url = futures[fut]
                result = fut.result()
                all_results.append((i, result))
                _print_result(i, url, result)
        # Sort by original order
        all_results.sort(key=lambda x: x[0])
        all_results = [r for _, r in all_results]
    else:
        # Sequential execution (original behavior)
        for i, url in enumerate(urls, 1):
            result = scan_target(url, test_categories, max_payloads=max_payloads,
                                 timeout=timeout, delay=delay,
                                 custom_headers=scope_headers or None,
                                 smart=smart)
            all_results.append(result)
            _print_result(i, url, result)

    # ── Report ───────────────────────────────────────────────────────────
    print_bounty_report(all_results, program, platform)

    # Save output
    if output:
        report = {
            "platform": platform,
            "program": program,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fray_version": __version__,
            "categories": test_categories,
            "targets": all_results,
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  {Colors.GREEN}Report saved: {output}{Colors.END}\n")
