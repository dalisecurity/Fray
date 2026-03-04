#!/usr/bin/env python3
"""
Fray Submit-Payload — Community payload contribution via CLI

Workflow:
    1. User provides payload, category, description, and contributor info
    2. Payload is validated and formatted with contributor credit
    3. A GitHub Pull Request is automatically created via the GitHub API

Usage:
    fray submit-payload                          Interactive mode
    fray submit-payload --payload '<svg/onload=alert(1)>' --category xss
    fray submit-payload --file my_payloads.json  Bulk submission

Requires:
    GITHUB_TOKEN environment variable (personal access token with repo scope)

Zero external dependencies — uses stdlib http.client + json.
"""

import http.client
import json
import os
import re
import ssl
import sys
import base64
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR

REPO_OWNER = "dalisecurity"
REPO_NAME = "Fray"
API_HOST = "api.github.com"


class Colors:
    """Terminal colors"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── Payload Validation ───────────────────────────────────────────────────────

def get_valid_categories() -> List[str]:
    """Get list of valid payload categories from the payloads directory."""
    if not PAYLOADS_DIR.exists():
        return []
    return sorted([
        d.name for d in PAYLOADS_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])


def validate_payload(payload: str) -> Tuple[bool, str]:
    """Validate a payload string."""
    if not payload or not payload.strip():
        return False, "Payload cannot be empty"
    if len(payload) > 10000:
        return False, "Payload exceeds 10,000 character limit"
    return True, ""


def validate_category(category: str) -> Tuple[bool, str]:
    """Validate category exists."""
    valid = get_valid_categories()
    if category not in valid:
        return False, f"Unknown category '{category}'. Valid: {', '.join(valid)}"
    return True, ""


def generate_payload_id(category: str) -> str:
    """Generate a unique payload ID based on category and timestamp."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{category}-contrib-{ts}"


def build_payload_entry(
    payload: str,
    category: str,
    subcategory: str,
    description: str,
    technique: str,
    contributor_name: str,
    contributor_github: str,
    tags: Optional[List[str]] = None,
    tested_against: Optional[List[str]] = None,
    notes: str = "",
) -> Dict:
    """Build a payload JSON entry with embedded contributor credit."""
    entry = {
        "id": generate_payload_id(category),
        "category": category,
        "subcategory": subcategory or "community",
        "payload": payload,
        "description": description,
        "technique": technique or "direct_injection",
        "source": "community",
        "contributed_by": {
            "name": contributor_name,
            "github": contributor_github,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
    }
    if tags:
        entry["tags"] = tags
    if tested_against:
        entry["tested_against"] = tested_against
    if notes:
        entry["notes"] = notes
    return entry


# ── GitHub API (stdlib only) ─────────────────────────────────────────────────

class GitHubAPI:
    """Minimal GitHub API client using stdlib http.client."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": f"Fray/{__version__} (+https://github.com/{REPO_OWNER}/{REPO_NAME})",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Tuple[int, Dict]:
        """Make an API request to GitHub."""
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(API_HOST, 443, context=ctx, timeout=30)

        encoded_body = json.dumps(body).encode("utf-8") if body else None

        conn.request(method, path, body=encoded_body, headers=self.headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()

        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"raw": data[:500]}

        return resp.status, parsed

    def get_authenticated_user(self) -> Tuple[bool, str]:
        """Verify the token and get the username."""
        status, data = self._request("GET", "/user")
        if status == 200:
            return True, data.get("login", "unknown")
        return False, data.get("message", f"HTTP {status}")

    def fork_repo(self) -> Tuple[bool, str]:
        """Fork the Fray repo to the authenticated user's account."""
        status, data = self._request("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/forks")
        if status in (200, 202):
            return True, data.get("full_name", "")
        return False, data.get("message", f"HTTP {status}")

    def get_default_branch_sha(self, owner: str) -> Tuple[bool, str]:
        """Get the SHA of the default branch HEAD."""
        status, data = self._request("GET", f"/repos/{owner}/{REPO_NAME}/git/ref/heads/hugo")
        if status == 200:
            return True, data["object"]["sha"]
        # Try 'main' as fallback
        status, data = self._request("GET", f"/repos/{owner}/{REPO_NAME}/git/ref/heads/main")
        if status == 200:
            return True, data["object"]["sha"]
        return False, data.get("message", f"HTTP {status}")

    def create_branch(self, owner: str, branch_name: str, sha: str) -> Tuple[bool, str]:
        """Create a new branch from the given SHA."""
        status, data = self._request("POST", f"/repos/{owner}/{REPO_NAME}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": sha,
        })
        if status in (200, 201):
            return True, ""
        return False, data.get("message", f"HTTP {status}")

    def create_or_update_file(
        self, owner: str, branch: str, file_path: str, content: str, message: str
    ) -> Tuple[bool, str]:
        """Create or update a file in the repo."""
        # Check if file exists to get its SHA
        encoded_path = urllib.parse.quote(file_path, safe="/")
        status, data = self._request(
            "GET", f"/repos/{owner}/{REPO_NAME}/contents/{encoded_path}?ref={branch}"
        )
        existing_sha = data.get("sha") if status == 200 else None

        body = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if existing_sha:
            body["sha"] = existing_sha

        status, data = self._request(
            "PUT", f"/repos/{owner}/{REPO_NAME}/contents/{encoded_path}", body
        )
        if status in (200, 201):
            return True, ""
        return False, data.get("message", f"HTTP {status}")

    def create_pull_request(
        self, from_owner: str, branch: str, title: str, body: str
    ) -> Tuple[bool, str]:
        """Create a pull request from fork to upstream."""
        status, data = self._request("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls", {
            "title": title,
            "body": body,
            "head": f"{from_owner}:{branch}",
            "base": "hugo",
        })
        if status in (200, 201):
            return True, data.get("html_url", "")
        return False, data.get("message", f"HTTP {status}")


# ── Interactive Prompts ──────────────────────────────────────────────────────

def _prompt(label: str, default: str = "", required: bool = True) -> str:
    """Prompt user for input."""
    suffix = f" [{default}]" if default else ""
    suffix += ": " if required else " (optional): "
    while True:
        value = input(f"  {Colors.BLUE}{label}{suffix}{Colors.END}").strip()
        if not value and default:
            return default
        if not value and required:
            print(f"  {Colors.RED}Required field.{Colors.END}")
            continue
        return value


def _prompt_choice(label: str, options: List[str]) -> str:
    """Prompt user to pick from a list."""
    print(f"\n  {Colors.BLUE}{label}:{Colors.END}")
    for i, opt in enumerate(options, 1):
        print(f"    {i}. {opt}")
    while True:
        choice = input(f"  {Colors.BLUE}Select [1-{len(options)}]: {Colors.END}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print(f"  {Colors.RED}Invalid choice.{Colors.END}")


def interactive_collect() -> Optional[Dict]:
    """Interactively collect payload submission details."""
    print(f"\n{Colors.BOLD}Fray Submit-Payload v{__version__}{Colors.END}")
    print(f"{Colors.DIM}{'─' * 50}{Colors.END}")
    print(f"{Colors.DIM}Submit a payload to the Fray community database.{Colors.END}")
    print(f"{Colors.DIM}A GitHub PR will be created automatically.{Colors.END}\n")

    # Category
    categories = get_valid_categories()
    if not categories:
        print(f"{Colors.RED}Error: No payload categories found.{Colors.END}")
        return None
    category = _prompt_choice("Payload category", categories)

    # Subcategory
    cat_dir = PAYLOADS_DIR / category
    subcategories = sorted([f.stem for f in cat_dir.glob("*.json")])
    if subcategories:
        subcategories.append("community")
        subcategory = _prompt_choice("Subcategory (target file)", subcategories)
    else:
        subcategory = "community"

    # Payload
    print()
    payload = _prompt("Payload string")
    valid, err = validate_payload(payload)
    if not valid:
        print(f"  {Colors.RED}{err}{Colors.END}")
        return None

    # Description
    description = _prompt("Description (what does this payload do?)")

    # Technique
    techniques = [
        "direct_injection", "encoding_bypass", "waf_bypass",
        "obfuscation", "polyglot", "smuggling", "mutation", "other"
    ]
    technique = _prompt_choice("Technique", techniques)

    # Tags
    tags_raw = _prompt("Tags (comma-separated)", required=False)
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

    # Tested against
    wafs_raw = _prompt("Tested against WAFs (comma-separated, e.g. cloudflare,aws_waf)", required=False)
    tested_against = [w.strip() for w in wafs_raw.split(",") if w.strip()] if wafs_raw else []

    # Notes
    notes = _prompt("Additional notes", required=False)

    # Contributor info
    print(f"\n{Colors.DIM}── Contributor Credit ──{Colors.END}")
    contributor_name = _prompt("Your name / handle")
    contributor_github = _prompt("Your GitHub username")

    entry = build_payload_entry(
        payload=payload,
        category=category,
        subcategory=subcategory,
        description=description,
        technique=technique,
        contributor_name=contributor_name,
        contributor_github=contributor_github,
        tags=tags,
        tested_against=tested_against,
        notes=notes,
    )

    # Preview
    print(f"\n{Colors.DIM}── Preview ──{Colors.END}")
    print(json.dumps(entry, indent=2, ensure_ascii=False))

    confirm = input(f"\n  {Colors.BLUE}Submit this payload? [Y/n]: {Colors.END}").strip().lower()
    if confirm in ("n", "no"):
        print(f"\n{Colors.YELLOW}Submission cancelled.{Colors.END}")
        return None

    return entry


def load_bulk_payloads(filepath: str) -> Optional[List[Dict]]:
    """Load payloads from a JSON file for bulk submission."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError) as e:
        print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.END}")
        return None

    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "payloads" in data:
        return data["payloads"]
    else:
        print(f"{Colors.RED}Invalid format: expected a list of payloads or {{\"payloads\": [...]}}{Colors.END}")
        return None


# ── Submit Flow ──────────────────────────────────────────────────────────────

def submit_to_github(entries: List[Dict], category: str, subcategory: str) -> bool:
    """Submit payload entries by creating a GitHub PR."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print(f"\n{Colors.RED}Error: GITHUB_TOKEN environment variable not set.{Colors.END}")
        print(f"{Colors.DIM}Create a token at: https://github.com/settings/tokens{Colors.END}")
        print(f"{Colors.DIM}Required scope: 'repo' (or 'public_repo' for public repos){Colors.END}")
        print(f"{Colors.DIM}Then: export GITHUB_TOKEN=ghp_xxxx{Colors.END}")

        # Save locally as fallback
        return _save_local_fallback(entries, category, subcategory)

    api = GitHubAPI(token)

    # Step 1: Verify token
    print(f"\n{Colors.DIM}Authenticating...{Colors.END}")
    ok, username = api.get_authenticated_user()
    if not ok:
        print(f"{Colors.RED}Authentication failed: {username}{Colors.END}")
        return _save_local_fallback(entries, category, subcategory)
    print(f"  {Colors.GREEN}Authenticated as @{username}{Colors.END}")

    # Step 2: Fork repo
    print(f"{Colors.DIM}Forking {REPO_OWNER}/{REPO_NAME}...{Colors.END}")
    ok, fork_name = api.fork_repo()
    if not ok:
        print(f"{Colors.RED}Fork failed: {fork_name}{Colors.END}")
        return _save_local_fallback(entries, category, subcategory)
    print(f"  {Colors.GREEN}Fork ready: {fork_name}{Colors.END}")

    # Step 3: Create branch
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch_name = f"payload/{category}-{timestamp}"

    print(f"{Colors.DIM}Creating branch: {branch_name}...{Colors.END}")
    ok, base_sha = api.get_default_branch_sha(username)
    if not ok:
        print(f"{Colors.RED}Failed to get base SHA: {base_sha}{Colors.END}")
        return _save_local_fallback(entries, category, subcategory)

    ok, err = api.create_branch(username, branch_name, base_sha)
    if not ok:
        print(f"{Colors.RED}Branch creation failed: {err}{Colors.END}")
        return _save_local_fallback(entries, category, subcategory)
    print(f"  {Colors.GREEN}Branch created{Colors.END}")

    # Step 4: Build the file content
    file_path = f"fray/payloads/{category}/{subcategory}.json"

    # Try to load existing file content from the fork
    encoded_fp = urllib.parse.quote(file_path, safe="/")
    _, existing_data = api._request(
        "GET", f"/repos/{username}/{REPO_NAME}/contents/{encoded_fp}?ref={branch_name}"
    )

    existing_payloads = []
    if existing_data.get("content"):
        try:
            raw = base64.b64decode(existing_data["content"]).decode("utf-8")
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "payloads" in parsed:
                existing_payloads = parsed["payloads"]
            elif isinstance(parsed, list):
                existing_payloads = parsed
        except Exception:
            pass

    merged = existing_payloads + entries
    file_content = json.dumps({
        "category": category,
        "subcategory": subcategory,
        "count": len(merged),
        "payloads": merged,
    }, indent=2, ensure_ascii=False) + "\n"

    # Step 5: Commit file
    contributor = entries[0].get("contributed_by", {}).get("name", "community") if entries else "community"
    commit_msg = f"feat(payloads): add {len(entries)} {category} payload(s) by {contributor}"

    print(f"{Colors.DIM}Committing {len(entries)} payload(s)...{Colors.END}")
    ok, err = api.create_or_update_file(username, branch_name, file_path, file_content, commit_msg)
    if not ok:
        print(f"{Colors.RED}Commit failed: {err}{Colors.END}")
        return _save_local_fallback(entries, category, subcategory)
    print(f"  {Colors.GREEN}Committed to {file_path}{Colors.END}")

    # Step 6: Create PR
    contributor_gh = entries[0].get("contributed_by", {}).get("github", "") if entries else ""
    pr_title = f"[Community] Add {len(entries)} {category} payload(s)"
    pr_body = _build_pr_body(entries, category, subcategory, contributor_gh)

    print(f"{Colors.DIM}Opening Pull Request...{Colors.END}")
    ok, pr_url = api.create_pull_request(username, branch_name, pr_title, pr_body)
    if not ok:
        print(f"{Colors.RED}PR creation failed: {pr_url}{Colors.END}")
        print(f"{Colors.DIM}You can manually create a PR from: "
              f"https://github.com/{username}/{REPO_NAME}/tree/{branch_name}{Colors.END}")
        return False

    print(f"\n  {Colors.GREEN}{Colors.BOLD}Pull Request created!{Colors.END}")
    print(f"  {Colors.BLUE}{pr_url}{Colors.END}\n")
    return True


def _build_pr_body(entries: List[Dict], category: str, subcategory: str, contributor_gh: str) -> str:
    """Build the PR description body."""
    count = len(entries)
    payload_previews = ""
    for e in entries[:5]:
        p = e.get("payload", "")[:80]
        desc = e.get("description", "")[:60]
        payload_previews += f"- `{p}` — {desc}\n"
    if count > 5:
        payload_previews += f"- ... and {count - 5} more\n"

    contributor_credit = ""
    if contributor_gh:
        contributor_credit = f"\n## Contributor\n@{contributor_gh}\n"

    return f"""## Payload Submission

**Category:** `{category}`
**Subcategory:** `{subcategory}`
**Payloads:** {count}

### Preview

{payload_previews}
{contributor_credit}
### Checklist
- [x] Payload is original or properly attributed
- [x] Category and technique are accurate
- [x] Contributor credit embedded in JSON

---
*Submitted via `fray submit-payload` CLI v{__version__}*
"""


def _save_local_fallback(entries: List[Dict], category: str, subcategory: str) -> bool:
    """Save payloads locally when GitHub submission is not possible."""
    filename = f"fray_submission_{category}_{subcategory}.json"
    data = {
        "category": category,
        "subcategory": subcategory,
        "count": len(entries),
        "payloads": entries,
    }
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n  {Colors.YELLOW}Saved locally: {filename}{Colors.END}")
        print(f"  {Colors.DIM}You can submit this file manually via GitHub PR.{Colors.END}")
        print(f"  {Colors.DIM}Or set GITHUB_TOKEN and run: fray submit-payload --file {filename}{Colors.END}\n")
        return True
    except OSError as e:
        print(f"{Colors.RED}Failed to save locally: {e}{Colors.END}")
        return False


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def run_submit_payload(
    payload: Optional[str] = None,
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
    description: Optional[str] = None,
    technique: Optional[str] = None,
    contributor_name: Optional[str] = None,
    contributor_github: Optional[str] = None,
    file: Optional[str] = None,
    dry_run: bool = False,
):
    """Main entry point for submit-payload command."""

    # Bulk mode: load from file
    if file:
        entries = load_bulk_payloads(file)
        if not entries:
            sys.exit(1)
        # Ensure contributor credit is present
        for e in entries:
            if "contributed_by" not in e:
                name = contributor_name or _prompt("Contributor name for bulk payloads")
                gh = contributor_github or _prompt("GitHub username")
                e["contributed_by"] = {
                    "name": name,
                    "github": gh,
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                }
                break  # Only prompt once, apply to all
        # Apply contributor to all entries missing it
        credit = entries[0].get("contributed_by", {})
        for e in entries:
            if "contributed_by" not in e:
                e["contributed_by"] = credit

        cat = entries[0].get("category", category or "other")
        sub = entries[0].get("subcategory", subcategory or "community")

        print(f"\n{Colors.BOLD}Bulk submission: {len(entries)} payload(s){Colors.END}")
        print(f"Category: {cat} / {sub}")

        if dry_run:
            print(f"\n{Colors.YELLOW}Dry run — no PR created.{Colors.END}")
            print(json.dumps(entries[:3], indent=2, ensure_ascii=False))
            if len(entries) > 3:
                print(f"... and {len(entries) - 3} more")
            return

        submit_to_github(entries, cat, sub)
        return

    # Single payload via CLI args
    if payload and category:
        valid_p, err_p = validate_payload(payload)
        if not valid_p:
            print(f"{Colors.RED}{err_p}{Colors.END}")
            sys.exit(1)
        valid_c, err_c = validate_category(category)
        if not valid_c:
            print(f"{Colors.RED}{err_c}{Colors.END}")
            sys.exit(1)

        name = contributor_name or os.environ.get("GITHUB_USER", "")
        gh = contributor_github or os.environ.get("GITHUB_USER", "")
        if not name:
            name = _prompt("Contributor name")
        if not gh:
            gh = _prompt("GitHub username")

        entry = build_payload_entry(
            payload=payload,
            category=category,
            subcategory=subcategory or "community",
            description=description or "",
            technique=technique or "direct_injection",
            contributor_name=name,
            contributor_github=gh,
        )

        if dry_run:
            print(f"\n{Colors.YELLOW}Dry run — no PR created.{Colors.END}")
            print(json.dumps(entry, indent=2, ensure_ascii=False))
            return

        submit_to_github([entry], category, subcategory or "community")
        return

    # Interactive mode
    entry = interactive_collect()
    if not entry:
        return

    if dry_run:
        print(f"\n{Colors.YELLOW}Dry run — no PR created.{Colors.END}")
        return

    submit_to_github(
        [entry],
        entry.get("category", "other"),
        entry.get("subcategory", "community"),
    )
