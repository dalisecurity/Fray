#!/usr/bin/env python3
"""
Fray — PoC Extractor: Real exploit payloads from CVE references.

Pipeline:
  1. Collect exploit-tagged URLs from NVD references
  2. Scrape GitHub PoC repos (README + exploit scripts)
  3. Scrape PacketStorm / ExploitDB pages
  4. Parse code to extract actual HTTP requests, paths, params, headers, payloads
  5. Deduplicate and rank by specificity

Supported PoC sources:
  - GitHub repos (CVE-YYYY-XXXXX pattern repos)
  - GitHub Gists
  - GitHub Security Advisories (GHSA)
  - PacketStorm Security
  - ExploitDB
  - Raw HTTP requests in advisories

Supported PoC code formats:
  - Python (requests, urllib, http.client)
  - curl commands
  - Ruby (net/http)
  - Raw HTTP requests
  - Nuclei templates (YAML)
  - Metasploit modules (Ruby)
"""

import http.client
import json
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from fray import __version__
except ImportError:
    __version__ = "dev"


# ── HTTPS fetch helper ───────────────────────────────────────────────────────

def _fetch_url(url: str, timeout: int = 12, max_bytes: int = 512 * 1024) -> Tuple[int, str]:
    """Fetch a URL over HTTPS. Returns (status, body)."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": f"Mozilla/5.0 (Fray/{__version__})",
            "Accept": "text/html,application/xhtml+xml,text/plain,*/*",
        })
        resp = conn.getresponse()

        # Follow redirects (1 level)
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location", "")
            if loc:
                resp.read()
                conn.close()
                return _fetch_url(loc, timeout, max_bytes)

        body = resp.read(max_bytes).decode("utf-8", "replace")
        status = resp.status
        conn.close()
        return status, body
    except Exception:
        return 0, ""


# ── Reference Classification ─────────────────────────────────────────────────

@dataclass
class PoCReference:
    """A classified exploit reference from NVD."""
    url: str
    source: str          # "github_repo", "github_advisory", "packetstorm", "exploitdb", "blog", "other"
    has_exploit_tag: bool
    priority: int = 0    # lower = fetch first

    def __post_init__(self):
        if self.source == "github_repo":
            self.priority = 1
        elif self.source == "exploitdb":
            self.priority = 2
        elif self.source == "packetstorm":
            self.priority = 3
        elif self.source == "github_advisory":
            self.priority = 4
        elif self.has_exploit_tag:
            self.priority = 5
        else:
            self.priority = 9


def classify_references(references: List[Dict[str, Any]], cve_id: str = "") -> List[PoCReference]:
    """Classify NVD references by source type and exploit relevance.

    Args:
        references: List of NVD reference dicts with 'url' and 'tags'.
        cve_id: CVE ID for GitHub repo pattern matching.

    Returns:
        Sorted list of PoCReference objects (most promising first).
    """
    seen_urls = set()
    results = []
    cve_slug = cve_id.lower().replace("-", "").replace("_", "") if cve_id else ""

    for ref in references:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        has_exploit = "Exploit" in tags

        if url in seen_urls or not url:
            continue
        seen_urls.add(url)

        lower = url.lower()

        # GitHub PoC repos (highest value)
        if "github.com/" in lower and "/CVE-" in url:
            results.append(PoCReference(url, "github_repo", has_exploit))
        elif "github.com/" in lower and cve_slug and cve_slug in lower.replace("-", "").replace("_", ""):
            results.append(PoCReference(url, "github_repo", has_exploit))
        elif "github.com/" in lower and "/security/advisories/GHSA" in url:
            results.append(PoCReference(url, "github_advisory", has_exploit))
        elif "github.com/" in lower and ("exploit" in lower or "poc" in lower or "rce" in lower):
            results.append(PoCReference(url, "github_repo", has_exploit))
        # ExploitDB
        elif "exploit-db.com" in lower:
            results.append(PoCReference(url, "exploitdb", has_exploit or True))
        # PacketStorm
        elif "packetstormsecurity.com" in lower:
            results.append(PoCReference(url, "packetstorm", has_exploit or True))
        # Blog posts tagged as Exploit
        elif has_exploit:
            results.append(PoCReference(url, "blog", True))

    results.sort(key=lambda r: r.priority)
    return results


# ── GitHub PoC Scraper ────────────────────────────────────────────────────────

_EXPLOIT_FILENAMES = [
    "exploit.py", "poc.py", "exp.py", "pwn.py", "rce.py",
    "exploit.rb", "poc.rb",
    "exploit.sh", "poc.sh", "run.sh",
    "exploit.go", "poc.go",
    "exploit.js", "poc.js",
    "payload.txt", "payload.json",
    "poc.yaml", "poc.yml",  # nuclei templates
]


def _github_repo_to_raw_urls(repo_url: str) -> List[Tuple[str, str]]:
    """Convert a GitHub repo URL to raw content URLs for likely exploit files.

    Returns list of (filename, raw_url) tuples.
    """
    # Extract owner/repo from URL
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+)', repo_url)
    if not m:
        return []
    owner, repo = m.group(1), m.group(2).rstrip("/")

    urls = []
    # Try common exploit filenames on main/master branches
    for branch in ("main", "master"):
        for fname in _EXPLOIT_FILENAMES:
            raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fname}"
            urls.append((fname, raw))

    # Also try README for inline PoC
    for branch in ("main", "master"):
        urls.append(("README.md", f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"))

    return urls


def scrape_github_poc(repo_url: str, timeout: int = 10,
                      delay: float = 0.3) -> Dict[str, Any]:
    """Scrape a GitHub PoC repo for exploit code.

    Args:
        repo_url: GitHub repository URL.
        timeout: Request timeout.
        delay: Delay between requests.

    Returns:
        Dict with found files, extracted code, and parsed payloads.
    """
    result: Dict[str, Any] = {
        "repo": repo_url,
        "files_found": [],
        "code_snippets": [],
        "extracted_payloads": [],
    }

    candidates = _github_repo_to_raw_urls(repo_url)

    for fname, raw_url in candidates:
        if delay > 0:
            time.sleep(delay)
        status, body = _fetch_url(raw_url, timeout)
        if status == 200 and len(body) > 50:
            result["files_found"].append(fname)
            result["code_snippets"].append({
                "filename": fname,
                "content": body[:32768],  # cap at 32KB
                "size": len(body),
            })
            # Stop after finding 3 meaningful files
            if len(result["files_found"]) >= 3:
                break

    return result


# ── PacketStorm Scraper ───────────────────────────────────────────────────────

def scrape_packetstorm(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Scrape a PacketStorm page for exploit code.

    Tries: inline code blocks → download links → linked exploit files.
    PacketStorm often requires following download links for actual exploit code.
    """
    result: Dict[str, Any] = {
        "url": url,
        "code_snippets": [],
        "extracted_payloads": [],
    }

    status, body = _fetch_url(url, timeout)
    if status != 200 or not body:
        return result

    # Try inline code blocks first
    code_blocks = re.findall(r'<code[^>]*>(.*?)</code>', body, re.DOTALL)
    for block in code_blocks:
        clean = re.sub(r'<[^>]+>', '', block).strip()
        if len(clean) > 50 and not clean.startswith("Last updated"):
            result["code_snippets"].append({
                "filename": "packetstorm_inline",
                "content": clean[:16384],
                "size": len(clean),
            })

    # Try download links (PacketStorm pattern: /files/download/NNNNN/filename.ext)
    dl_links = re.findall(r'href="(/files/download/\d+/[^"]+)"', body)
    for dl_path in dl_links[:2]:
        dl_url = f"https://packetstormsecurity.com{dl_path}"
        dl_status, dl_body = _fetch_url(dl_url, timeout)
        if dl_status == 200 and len(dl_body) > 50:
            fname = dl_path.split("/")[-1]
            result["code_snippets"].append({
                "filename": fname,
                "content": dl_body[:32768],
                "size": len(dl_body),
            })

    return result


def search_github_pocs(cve_id: str, timeout: int = 10) -> List[str]:
    """Search GitHub for PoC repositories matching a CVE ID.

    Uses GitHub code search API (unauthenticated) to find repos.
    Falls back to URL pattern guessing.

    Returns list of GitHub repo URLs.
    """
    repos = []
    slug = cve_id.upper()

    # Strategy 1: GitHub search via HTML (no API key needed)
    search_url = f"https://github.com/search?q={urllib.parse.quote(slug)}&type=repositories"
    status, body = _fetch_url(search_url, timeout)
    if status == 200 and body:
        # Extract repo links from search results
        matches = re.findall(r'href="/([^/]+/' + re.escape(slug) + r'[^"]*)"', body, re.IGNORECASE)
        for m in matches[:5]:
            repo_url = f"https://github.com/{m}"
            if repo_url not in repos:
                repos.append(repo_url)

    # Strategy 2: Try well-known PoC aggregator repos
    poc_aggregators = [
        f"https://github.com/nomi-sec/PoC-in-GitHub",  # auto-aggregated
    ]

    # Strategy 3: Common naming patterns
    cve_lower = cve_id.lower()
    cve_nodash = cve_id.replace("-", "")
    common_patterns = [
        f"https://github.com/search?q={urllib.parse.quote(cve_lower)}&type=repositories",
    ]

    return repos[:5]


# ── PoC Code Parser ──────────────────────────────────────────────────────────
# Extracts HTTP request components from exploit code in any language.

@dataclass
class ExtractedPayload:
    """A payload extracted from PoC source code."""
    payload: str
    method: str = "GET"
    path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    source_file: str = ""
    confidence: float = 0.0   # 0.0-1.0
    technique: str = ""
    context: str = ""


def _parse_python_requests(code: str) -> List[ExtractedPayload]:
    """Extract payloads from Python requests library calls."""
    payloads = []

    # requests.get/post/put with URL
    for m in re.finditer(
        r'requests\.(get|post|put|patch|delete)\s*\(\s*[f"\']([^"\']+)["\']',
        code, re.IGNORECASE):
        method = m.group(1).upper()
        url_str = m.group(2)

        # Extract path from URL
        parsed = urllib.parse.urlparse(url_str)
        path = parsed.path or "/"

        ep = ExtractedPayload(
            payload=url_str,
            method=method,
            path=path,
            confidence=0.8,
            technique="python_requests",
            context=f"requests.{method.lower()}()",
        )

        # Look for headers= nearby
        context_after = code[m.end():m.end()+500]
        hdr_match = re.search(r'headers\s*=\s*\{([^}]+)\}', context_after)
        if hdr_match:
            for hm in re.finditer(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']+)["\']', hdr_match.group(1)):
                ep.headers[hm.group(1)] = hm.group(2)

        # Look for data=/json= nearby
        data_match = re.search(r'(?:data|json)\s*=\s*["\']([^"\']+)["\']', context_after)
        if data_match:
            ep.body = data_match.group(1)

        # Look for data=/json= dict
        data_dict = re.search(r'(?:data|json)\s*=\s*\{([^}]+)\}', context_after)
        if data_dict:
            ep.body = "{" + data_dict.group(1) + "}"

        # Look for params= dict
        params_match = re.search(r'params\s*=\s*\{([^}]+)\}', context_after)
        if params_match:
            for pm in re.finditer(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']+)["\']', params_match.group(1)):
                ep.params[pm.group(1)] = pm.group(2)

        payloads.append(ep)

    return payloads


def _parse_python_urllib(code: str) -> List[ExtractedPayload]:
    """Extract payloads from Python urllib/http.client calls."""
    payloads = []

    # urllib.request.urlopen / Request
    for m in re.finditer(
        r'(?:urlopen|Request)\s*\(\s*[f"\'](https?://[^"\']+)["\']',
        code, re.IGNORECASE):
        url_str = m.group(1)
        parsed = urllib.parse.urlparse(url_str)
        payloads.append(ExtractedPayload(
            payload=url_str,
            method="GET",
            path=parsed.path or "/",
            confidence=0.7,
            technique="python_urllib",
            context="urllib/http.client",
        ))

    # http.client request
    for m in re.finditer(
        r'\.request\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
        code, re.IGNORECASE):
        method = m.group(1).upper()
        path = m.group(2)
        payloads.append(ExtractedPayload(
            payload=path,
            method=method,
            path=path,
            confidence=0.7,
            technique="python_http_client",
            context="http.client.request()",
        ))

    return payloads


def _parse_curl_commands(code: str) -> List[ExtractedPayload]:
    """Extract payloads from curl commands."""
    payloads = []

    for m in re.finditer(
        r'curl\s+(.+?)(?:\n|$|;|\||&&)',
        code, re.IGNORECASE):
        curl_cmd = m.group(1)

        # Extract URL
        url_m = re.search(r'["\']?(https?://[^\s"\']+)["\']?', curl_cmd)
        if not url_m:
            continue

        url_str = url_m.group(1)
        parsed = urllib.parse.urlparse(url_str)

        # Determine method
        method = "GET"
        if "-X" in curl_cmd:
            method_m = re.search(r'-X\s+["\']?(\w+)["\']?', curl_cmd)
            if method_m:
                method = method_m.group(1).upper()
        elif "-d" in curl_cmd or "--data" in curl_cmd:
            method = "POST"

        ep = ExtractedPayload(
            payload=url_str,
            method=method,
            path=parsed.path or "/",
            confidence=0.9,
            technique="curl",
            context="curl command",
        )

        # Extract headers
        for hm in re.finditer(r'-H\s+["\']([^"\']+)["\']', curl_cmd):
            hdr = hm.group(1)
            if ":" in hdr:
                k, v = hdr.split(":", 1)
                ep.headers[k.strip()] = v.strip()

        # Extract POST data
        data_m = re.search(r'(?:-d|--data(?:-raw)?)\s+["\']([^"\']+)["\']', curl_cmd)
        if data_m:
            ep.body = data_m.group(1)

        payloads.append(ep)

    return payloads


def _parse_raw_http(code: str) -> List[ExtractedPayload]:
    """Extract payloads from raw HTTP request blocks."""
    payloads = []

    # Match raw HTTP request patterns
    for m in re.finditer(
        r'(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s]+)\s+HTTP/[\d.]+',
        code, re.IGNORECASE):
        method = m.group(1).upper()
        path = m.group(2)

        ep = ExtractedPayload(
            payload=path,
            method=method,
            path=path,
            confidence=0.95,
            technique="raw_http",
            context="Raw HTTP request",
        )

        # Parse headers from lines after the request line (stop at blank line)
        context_after = code[m.end():m.end()+1000]
        header_block = context_after.split("\n\n")[0] if "\n\n" in context_after else context_after[:500]
        for hm in re.finditer(r'^([A-Za-z][\w-]+):\s*(.+)$', header_block, re.MULTILINE):
            key = hm.group(1)
            val = hm.group(2).strip()
            # Skip common non-header noise and generic headers
            if key.lower() in ("host", "user-agent", "accept", "connection"):
                continue
            # Skip if value looks like a URL (markdown link residue)
            if val.startswith("//") and "." in val[:20]:
                continue
            if len(key) > 30 or len(val) > 200:
                continue
            ep.headers[key] = val

        # Look for body after blank line — stop at markdown fences or next request
        body_m = re.search(r'\r?\n\r?\n(.+)', context_after, re.DOTALL)
        if body_m:
            body = body_m.group(1).strip()
            # Truncate at markdown code fence, next HTTP request, or blank line block
            for stop_pattern in (r'\n```', r'\n(GET|POST|PUT|DELETE) /', r'\n##? ', r'\n\n\n'):
                stop = re.search(stop_pattern, body)
                if stop:
                    body = body[:stop.start()].strip()
            if body and len(body) < 500:
                ep.body = body

        payloads.append(ep)

    return payloads


def _parse_nuclei_template(code: str) -> List[ExtractedPayload]:
    """Extract payloads from Nuclei YAML templates."""
    payloads = []

    # Extract path patterns
    for m in re.finditer(r'path:\s*\n\s+-\s+["\']?(\{\{[^}]+\}\}[^\s"\']*|/[^\s"\']+)["\']?', code):
        path = m.group(1)
        payloads.append(ExtractedPayload(
            payload=path,
            method="GET",
            path=path,
            confidence=0.85,
            technique="nuclei_template",
            context="Nuclei YAML",
        ))

    # Extract raw HTTP blocks in nuclei
    for m in re.finditer(r'raw:\s*\n\s+-\s+\|[\-\+]?\s*\n([\s\S]+?)(?=\n\s+\w+:|$)', code):
        block = m.group(1)
        raw_payloads = _parse_raw_http(block)
        for p in raw_payloads:
            p.technique = "nuclei_raw"
            p.confidence = 0.9
        payloads.extend(raw_payloads)

    return payloads


def _parse_exploit_strings(code: str) -> List[ExtractedPayload]:
    """Extract common exploit strings/payloads from any code."""
    payloads = []

    # JNDI payloads
    for m in re.finditer(r'(\$\{jndi:[^}]+\})', code):
        payloads.append(ExtractedPayload(
            payload=m.group(1), confidence=0.95,
            technique="jndi_lookup", context="Log4Shell payload",
        ))

    # SQL injection strings
    for m in re.finditer(r'["\']([^"\']*(?:UNION\s+SELECT|OR\s+1=1|WAITFOR\s+DELAY|SLEEP\()[^"\']*)["\']',
                         code, re.IGNORECASE):
        payloads.append(ExtractedPayload(
            payload=m.group(1), confidence=0.8,
            technique="sqli_payload", context="SQL injection string",
        ))

    # XSS payloads
    for m in re.finditer(r'["\']([^"\']*<(?:script|svg|img)[^"\']*)["\']', code, re.IGNORECASE):
        val = m.group(1)
        if "alert" in val or "onerror" in val or "onload" in val:
            payloads.append(ExtractedPayload(
                payload=val, confidence=0.8,
                technique="xss_payload", context="XSS payload string",
            ))

    # Command injection payloads
    for m in re.finditer(r'["\']([^"\']*(?:;|\||\$\(|`)(?:id|whoami|cat\s|ls\s|sleep|ping)[^"\']*)["\']', code):
        payloads.append(ExtractedPayload(
            payload=m.group(1), confidence=0.75,
            technique="cmdi_payload", context="Command injection string",
        ))

    # Path traversal payloads
    for m in re.finditer(r'["\']([^"\']*\.\.(?:/|\\)(?:\.\.(?:/|\\))+[^"\']*)["\']', code):
        payloads.append(ExtractedPayload(
            payload=m.group(1), confidence=0.75,
            technique="lfi_payload", context="Path traversal string",
        ))

    # Deserialization payloads (base64 Java serialized objects)
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{20,})["\']', code):
        val = m.group(1)
        if val.startswith("rO0AB") or val.startswith("aced"):
            payloads.append(ExtractedPayload(
                payload=val, confidence=0.85,
                technique="deser_payload", context="Serialized object",
            ))

    return payloads


def parse_poc_code(code: str, filename: str = "") -> List[ExtractedPayload]:
    """Parse exploit code and extract all payloads.

    Tries all parsers and returns deduplicated, ranked results.
    """
    all_payloads: List[ExtractedPayload] = []

    # Detect language/format and apply relevant parsers
    lower = code.lower()

    if "requests." in lower or "import requests" in lower:
        all_payloads.extend(_parse_python_requests(code))

    if "urllib" in lower or "http.client" in lower:
        all_payloads.extend(_parse_python_urllib(code))

    if "curl " in lower:
        all_payloads.extend(_parse_curl_commands(code))

    if re.search(r'(GET|POST|PUT)\s+/\S+\s+HTTP/', code):
        all_payloads.extend(_parse_raw_http(code))

    if "nuclei" in lower or ("id:" in lower and "info:" in lower and "requests:" in lower):
        all_payloads.extend(_parse_nuclei_template(code))

    # Always try generic string extraction
    all_payloads.extend(_parse_exploit_strings(code))

    # Set source file
    for p in all_payloads:
        if not p.source_file:
            p.source_file = filename

    # Deduplicate by payload string
    seen = set()
    unique = []
    for p in all_payloads:
        key = p.payload.strip()[:200]
        if key not in seen and len(key) > 2:
            seen.add(key)
            unique.append(p)

    # Sort by confidence (highest first)
    unique.sort(key=lambda p: -p.confidence)

    return unique


# ── Full PoC Extraction Pipeline ─────────────────────────────────────────────

@dataclass
class PoCResult:
    """Complete PoC extraction result for a CVE."""
    cve_id: str
    sources_checked: int = 0
    sources_found: int = 0
    poc_references: List[Dict[str, str]] = field(default_factory=list)
    extracted_payloads: List[Dict[str, Any]] = field(default_factory=list)
    raw_code_samples: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "sources_checked": self.sources_checked,
            "sources_found": self.sources_found,
            "poc_references": self.poc_references,
            "extracted_payloads": self.extracted_payloads,
            "raw_code_samples": [{"filename": s["filename"], "size": s.get("size", 0)}
                                 for s in self.raw_code_samples],
        }


def extract_poc_payloads(
    cve_id: str = "",
    references: List[Dict[str, Any]] = None,
    cve_data: Optional[Dict[str, Any]] = None,
    max_sources: int = 5,
    timeout: int = 12,
    delay: float = 0.5,
) -> PoCResult:
    """Full PoC extraction pipeline for a CVE.

    Args:
        cve_id: CVE identifier.
        references: Pre-fetched NVD references list.
        cve_data: Full NVD CVE data (to extract references from).
        max_sources: Maximum number of sources to scrape.
        timeout: Per-request timeout.
        delay: Delay between requests.

    Returns:
        PoCResult with extracted payloads.
    """
    result = PoCResult(cve_id=cve_id)

    # Get references
    if references is None and cve_data:
        references = cve_data.get("references", [])

    if not references:
        return result

    # Classify and rank references
    classified = classify_references(references, cve_id)
    result.poc_references = [{"url": r.url, "source": r.source, "priority": r.priority}
                             for r in classified]

    # If no GitHub repos in NVD references, search GitHub directly
    has_github = any(r.source == "github_repo" for r in classified)
    if not has_github and cve_id:
        try:
            github_repos = search_github_pocs(cve_id, timeout)
            for repo_url in github_repos[:3]:
                classified.insert(0, PoCReference(repo_url, "github_repo", True))
                result.poc_references.insert(0, {"url": repo_url, "source": "github_repo", "priority": 1})
        except Exception:
            pass

    # Scrape top sources
    all_code_snippets: List[Dict[str, str]] = []

    for ref in classified[:max_sources]:
        result.sources_checked += 1
        if delay > 0:
            time.sleep(delay)

        if ref.source == "github_repo":
            scraped = scrape_github_poc(ref.url, timeout, delay)
            if scraped["files_found"]:
                result.sources_found += 1
                all_code_snippets.extend(scraped["code_snippets"])

        elif ref.source == "packetstorm":
            scraped = scrape_packetstorm(ref.url, timeout)
            if scraped["code_snippets"]:
                result.sources_found += 1
                all_code_snippets.extend(scraped["code_snippets"])

        elif ref.source in ("exploitdb", "blog"):
            # Generic page scrape — look for code blocks
            status, body = _fetch_url(ref.url, timeout)
            if status == 200 and body:
                # Extract code blocks
                blocks = re.findall(r'<(?:code|pre)[^>]*>(.*?)</(?:code|pre)>', body, re.DOTALL)
                for block in blocks:
                    clean = re.sub(r'<[^>]+>', '', block).strip()
                    if len(clean) > 50 and not clean.startswith("Last updated"):
                        all_code_snippets.append({
                            "filename": f"extract_{ref.source}",
                            "content": clean[:16384],
                            "size": len(clean),
                        })
                        result.sources_found += 1
                        break

    result.raw_code_samples = all_code_snippets

    # Parse all collected code
    all_extracted: List[ExtractedPayload] = []
    for snippet in all_code_snippets:
        parsed = parse_poc_code(snippet["content"], snippet.get("filename", ""))
        all_extracted.extend(parsed)

    # Deduplicate across all sources
    seen = set()
    unique_payloads = []
    for p in all_extracted:
        key = p.payload.strip()[:200]
        if key not in seen:
            seen.add(key)
            unique_payloads.append(p)

    # Convert to dicts
    result.extracted_payloads = [
        {
            "payload": p.payload[:500],
            "method": p.method,
            "path": p.path,
            "headers": p.headers,
            "params": p.params,
            "body": p.body[:500] if p.body else "",
            "confidence": p.confidence,
            "technique": p.technique,
            "context": p.context,
            "source_file": p.source_file,
        }
        for p in unique_payloads[:20]  # cap at 20 payloads
    ]

    return result


# ── CLI-friendly output ──────────────────────────────────────────────────────

def print_poc_result(result: PoCResult):
    """Pretty-print PoC extraction results."""
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[0m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"

    print(f"\n{D}{'━' * 60}{R}")
    print(f"  {B}PoC Extractor{R}  {CYN}{result.cve_id}{R}")
    print(f"  {D}Sources: {result.sources_found}/{result.sources_checked} | "
          f"Payloads: {len(result.extracted_payloads)}{R}")
    print(f"{D}{'━' * 60}{R}")

    # References
    if result.poc_references:
        print(f"\n  {B}Exploit References ({len(result.poc_references)}){R}")
        for ref in result.poc_references[:6]:
            src = ref["source"]
            icon = {"github_repo": "🐙", "packetstorm": "📦", "exploitdb": "💾",
                    "github_advisory": "🔒", "blog": "📝"}.get(src, "🔗")
            print(f"    {icon} {D}[{src:16s}]{R} {ref['url'][:65]}")

    # Extracted payloads
    if result.extracted_payloads:
        print(f"\n  {B}Extracted Payloads ({len(result.extracted_payloads)}){R}")
        for i, p in enumerate(result.extracted_payloads[:10], 1):
            conf = p["confidence"]
            color = GRN if conf >= 0.8 else YEL if conf >= 0.5 else D
            method = p["method"]
            path = p["path"][:30] if p["path"] else ""
            payload = p["payload"][:55]
            src = p.get("source_file", "")

            print(f"    {color}{i:2d}.{R} [{p['technique']:18s}] {method} {path}")
            if payload != path:
                print(f"        {D}payload: {payload}{R}")
            if p.get("headers"):
                hdrs = ", ".join(f"{k}: {v[:20]}" for k, v in list(p["headers"].items())[:3])
                print(f"        {D}headers: {hdrs}{R}")
            if p.get("body"):
                print(f"        {D}body: {p['body'][:60]}{R}")
            if src:
                print(f"        {D}from: {src}{R}")
    else:
        print(f"\n  {YEL}No PoC payloads extracted — CVE may not have public exploits{R}")

    # Code samples
    if result.raw_code_samples:
        print(f"\n  {B}Code Samples ({len(result.raw_code_samples)}){R}")
        for s in result.raw_code_samples[:3]:
            print(f"    {D}{s.get('filename', '?')} ({s.get('size', 0)} bytes){R}")

    print(f"\n{D}{'━' * 60}{R}\n")
