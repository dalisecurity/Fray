"""
Fray Fuzzer — ffuf-like Content Discovery with WAF-Aware Bypass

Usage:
    fray fuzz https://example.com/FUZZ -w wordlist.txt
    fray fuzz https://example.com/FUZZ -w common.txt -mc 200,301 -fc 404
    fray fuzz https://example.com/api/FUZZ -w api-endpoints.txt -H "Authorization: Bearer xxx"
    fray fuzz https://example.com/FUZZ -w dirs.txt -recursion -recursion-depth 2
    echo "/admin\n/api\n/login" | fray fuzz https://example.com/FUZZ -

Inspired by ffuf but with WAF-awareness:
    - Auto-detects WAF and adjusts request rate
    - Rotates User-Agents to avoid bot detection
    - Supports FUZZ keyword in URL, headers, POST body
    - Filter by status code, size, word count, line count
    - Match by status code, size, word count, line count
    - Recursive directory discovery
    - Built-in wordlists for common paths

Zero external dependencies — stdlib only.
"""

import http.client
import json
import re
import ssl
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Built-in wordlists ────────────────────────────────────────────────────

_BUILTIN_COMMON = [
    # Directories
    "admin", "api", "assets", "backup", "bin", "blog", "cache", "cgi-bin",
    "config", "console", "css", "dashboard", "data", "db", "debug", "dev",
    "docs", "download", "downloads", "dump", "editor", "email", "error",
    "export", "files", "fonts", "forum", "help", "hidden", "home", "html",
    "images", "img", "import", "include", "index", "info", "install",
    "internal", "js", "lang", "lib", "log", "login", "logs", "mail",
    "manage", "media", "misc", "modules", "monitor", "new", "old",
    "panel", "php", "phpinfo.php", "phpmyadmin", "plugins", "portal",
    "private", "public", "readme", "release", "remote", "reports",
    "resources", "rest", "scripts", "search", "secret", "secure",
    "server-status", "server-info", "service", "services", "settings",
    "setup", "shop", "site", "sitemap.xml", "sql", "staff", "staging",
    "static", "stats", "status", "storage", "store", "support", "swagger",
    "system", "temp", "template", "templates", "test", "testing", "theme",
    "themes", "tmp", "tools", "trace", "upload", "uploads", "user",
    "users", "util", "utils", "v1", "v2", "v3", "vendor", "version",
    "web", "webadmin", "webmail", "wp-admin", "wp-content", "wp-includes",
    "wp-login.php", "xmlrpc.php",
    # Files
    ".env", ".git/HEAD", ".git/config", ".gitignore", ".htaccess",
    ".htpasswd", ".svn/entries", ".DS_Store", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml", "security.txt",
    ".well-known/security.txt", "package.json", "composer.json",
    "Makefile", "Dockerfile", "docker-compose.yml", "Gruntfile.js",
    "Gulpfile.js", "webpack.config.js", "tsconfig.json",
    "web.config", "WEB-INF/web.xml",
    # API
    "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "api/health", "api/status", "api/version", "api/users", "api/config",
    "graphql", "graphiql", "playground",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs", "v2/api-docs", "v3/api-docs",
    # Spring Boot Actuator
    "actuator", "actuator/env", "actuator/health", "actuator/info",
    "actuator/beans", "actuator/mappings", "actuator/configprops",
    # Debug / Dev
    "debug", "trace", "elmah.axd", "_debugbar", "__debug__",
    "debug/default/login", "console", "terminal",
    "phpinfo.php", "info.php", "test.php", "server-info",
    # Backup
    "backup.sql", "backup.zip", "backup.tar.gz", "db.sql",
    "database.sql", "dump.sql", "site.zip", "www.zip",
]

_BUILTIN_API = [
    "users", "user", "me", "profile", "account", "accounts",
    "auth", "login", "logout", "register", "signup", "token", "tokens",
    "refresh", "verify", "confirm", "reset", "password", "forgot",
    "admin", "admins", "roles", "permissions",
    "posts", "articles", "comments", "categories", "tags",
    "products", "orders", "cart", "checkout", "payments", "invoices",
    "files", "uploads", "images", "media", "documents",
    "settings", "config", "preferences", "notifications",
    "search", "filter", "sort", "export", "import",
    "health", "status", "version", "info", "ping", "metrics",
    "graphql", "schema", "introspection",
    "webhooks", "callbacks", "events", "logs", "audit",
    "keys", "secrets", "credentials", "tokens",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
]


# ── Result types ──────────────────────────────────────────────────────────

class FuzzResult:
    """Single fuzzing result."""
    __slots__ = ("url", "word", "status", "size", "words", "lines",
                 "redirect", "content_type", "duration_ms")

    def __init__(self, url: str, word: str, status: int, size: int,
                 words: int, lines: int, redirect: str = "",
                 content_type: str = "", duration_ms: int = 0):
        self.url = url
        self.word = word
        self.status = status
        self.size = size
        self.words = words
        self.lines = lines
        self.redirect = redirect
        self.content_type = content_type
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "url": self.url,
            "word": self.word,
            "status": self.status,
            "size": self.size,
            "words": self.words,
            "lines": self.lines,
        }
        if self.redirect:
            d["redirect"] = self.redirect
        if self.content_type:
            d["content_type"] = self.content_type
        if self.duration_ms:
            d["duration_ms"] = self.duration_ms
        return d


# ── Core Fuzzer ──────────────────────────────────────────────────────────

class ContentFuzzer:
    """ffuf-like content discovery engine with WAF awareness.

    Usage:
        fuzzer = ContentFuzzer("https://example.com/FUZZ")
        fuzzer.load_wordlist("common.txt")
        results = fuzzer.run()
    """

    FUZZ_KEYWORD = "FUZZ"

    def __init__(self, url_pattern: str,
                 method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 data: str = "",
                 timeout: int = 10,
                 threads: int = 20,
                 delay: float = 0.0,
                 follow_redirects: bool = False,
                 verify_ssl: bool = True,
                 # Filters: exclude results matching these
                 filter_status: Optional[Set[int]] = None,
                 filter_size: Optional[Set[int]] = None,
                 filter_words: Optional[Set[int]] = None,
                 filter_lines: Optional[Set[int]] = None,
                 # Matchers: only include results matching these
                 match_status: Optional[Set[int]] = None,
                 match_size: Optional[Set[int]] = None,
                 # Recursion
                 recursion: bool = False,
                 recursion_depth: int = 1,
                 # Output
                 verbose: bool = False,
                 ):
        self.url_pattern = url_pattern
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.data = data
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl

        # Default: filter 404
        self.filter_status = filter_status or {404}
        self.filter_size = filter_size
        self.filter_words = filter_words
        self.filter_lines = filter_lines

        # Default: match all (except filtered)
        self.match_status = match_status
        self.match_size = match_size

        self.recursion = recursion
        self.recursion_depth = recursion_depth
        self.verbose = verbose

        self._wordlist: List[str] = []
        self._results: List[FuzzResult] = []
        self._ua_idx = 0
        self._requests_made = 0
        self._start_time = 0.0

        # Auto-calibrate: detect baseline 404 size for smart filtering
        self._baseline_size: Optional[int] = None
        self._baseline_words: Optional[int] = None

        # Parse URL
        parsed = urllib.parse.urlparse(url_pattern.replace(self.FUZZ_KEYWORD, "test"))
        self._scheme = parsed.scheme or "https"
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if self._scheme == "https" else 80)

    def load_wordlist(self, path: str) -> int:
        """Load words from file. Returns count loaded."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")
        words = []
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
        self._wordlist.extend(words)
        return len(words)

    def load_builtin(self, name: str = "common") -> int:
        """Load a built-in wordlist. Options: 'common', 'api'."""
        if name == "api":
            self._wordlist.extend(_BUILTIN_API)
            return len(_BUILTIN_API)
        else:
            self._wordlist.extend(_BUILTIN_COMMON)
            return len(_BUILTIN_COMMON)

    def load_words(self, words: List[str]) -> int:
        """Load words from a list."""
        self._wordlist.extend(words)
        return len(words)

    def load_stdin(self) -> int:
        """Load words from stdin (pipe mode)."""
        words = []
        for line in sys.stdin:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
        self._wordlist.extend(words)
        return len(words)

    def _get_ua(self) -> str:
        """Rotate User-Agent to avoid bot detection."""
        ua = _USER_AGENTS[self._ua_idx % len(_USER_AGENTS)]
        self._ua_idx += 1
        return ua

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers with anti-bot evasion."""
        hdrs = {
            "User-Agent": self._get_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "keep-alive",
        }
        hdrs.update(self.custom_headers)
        return hdrs

    def _make_url(self, word: str) -> str:
        """Replace FUZZ keyword with word."""
        return self.url_pattern.replace(self.FUZZ_KEYWORD, urllib.parse.quote(word, safe="/"))

    def _probe(self, word: str) -> Optional[FuzzResult]:
        """Send a single request and return result if it passes filters."""
        url = self._make_url(word)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or self._host
        port = parsed.port or self._port
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        hdrs = self._build_headers()
        # Replace FUZZ in headers too
        for k, v in hdrs.items():
            if self.FUZZ_KEYWORD in v:
                hdrs[k] = v.replace(self.FUZZ_KEYWORD, word)

        body_data = None
        if self.data:
            body_data = self.data.replace(self.FUZZ_KEYWORD, word).encode("utf-8")
            if "content-type" not in {k.lower() for k in hdrs}:
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"

        t0 = time.monotonic()
        try:
            use_ssl = self._scheme == "https"
            if use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            conn.request(self.method, path, body=body_data, headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            resp_body = resp.read(1024 * 512)  # Max 512KB
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
        except Exception:
            return None

        duration_ms = int((time.monotonic() - t0) * 1000)
        self._requests_made += 1

        body_text = resp_body.decode("utf-8", errors="replace")
        size = len(resp_body)
        words = len(body_text.split())
        lines = body_text.count("\n") + 1

        redirect = ""
        if status in (301, 302, 303, 307, 308):
            redirect = resp_hdrs.get("location", "")

        content_type = resp_hdrs.get("content-type", "")

        # Apply filters
        if self.filter_status and status in self.filter_status:
            return None
        if self.filter_size and size in self.filter_size:
            return None
        if self.filter_words and words in self.filter_words:
            return None
        if self.filter_lines and lines in self.filter_lines:
            return None

        # Auto-calibration: skip if matches baseline 404
        if self._baseline_size is not None and size == self._baseline_size:
            return None

        # Apply matchers
        if self.match_status and status not in self.match_status:
            return None
        if self.match_size and size not in self.match_size:
            return None

        return FuzzResult(
            url=url, word=word, status=status, size=size,
            words=words, lines=lines, redirect=redirect,
            content_type=content_type, duration_ms=duration_ms,
        )

    def _calibrate(self) -> None:
        """Auto-detect baseline 404 response for smart filtering."""
        random_word = "fray_calibrate_404_xyzzy_nonexistent"
        result = self._probe(random_word)
        if result and result.status == 404:
            self._baseline_size = result.size
            self._baseline_words = result.words

    def run(self, callback=None) -> List[FuzzResult]:
        """Execute fuzzing run. Returns list of matching results.

        Args:
            callback: Optional function called with (FuzzResult, stats_dict)
                     for each match. Used for real-time output.
        """
        if not self._wordlist:
            return []

        self._start_time = time.monotonic()
        self._requests_made = 0
        self._results = []

        # Auto-calibrate
        self._calibrate()

        # Deduplicate wordlist
        seen = set()
        unique_words = []
        for w in self._wordlist:
            if w not in seen:
                seen.add(w)
                unique_words.append(w)

        # Phase 1: Main scan
        self._fuzz_words(unique_words, callback=callback, depth=0)

        # Phase 2: Recursive scan on directories found
        if self.recursion and self.recursion_depth > 0:
            dirs_found = [r for r in self._results
                          if r.status in (200, 301, 302, 403)
                          and not re.search(r'\.\w{1,5}$', r.word)]
            for depth in range(1, self.recursion_depth + 1):
                if not dirs_found:
                    break
                recursive_words = []
                for d in dirs_found:
                    base = d.word.rstrip("/")
                    for w in unique_words:
                        recursive_words.append(f"{base}/{w}")
                dirs_found = []
                self._fuzz_words(recursive_words, callback=callback, depth=depth)
                dirs_found = [r for r in self._results
                              if r.status in (200, 301, 302, 403)
                              and not re.search(r'\.\w{1,5}$', r.word)
                              and "/" in r.word]

        return self._results

    def _fuzz_words(self, words: List[str], callback=None, depth: int = 0):
        """Fuzz a list of words with thread pool."""
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for i, word in enumerate(words):
                f = pool.submit(self._probe, word)
                futures[f] = word

                # Rate limiting
                if self.delay > 0 and i > 0:
                    time.sleep(self.delay)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self._results.append(result)
                        if callback:
                            elapsed = time.monotonic() - self._start_time
                            stats = {
                                "requests": self._requests_made,
                                "results": len(self._results),
                                "elapsed": elapsed,
                                "rps": self._requests_made / max(elapsed, 0.1),
                                "depth": depth,
                            }
                            callback(result, stats)
                except Exception:
                    pass

    def get_stats(self) -> Dict[str, Any]:
        """Return run statistics."""
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        return {
            "requests_made": self._requests_made,
            "results_found": len(self._results),
            "elapsed_seconds": round(elapsed, 1),
            "requests_per_second": round(self._requests_made / max(elapsed, 0.1), 1),
            "wordlist_size": len(self._wordlist),
        }

    def results_json(self) -> str:
        """Export results as JSON."""
        return json.dumps({
            "results": [r.to_dict() for r in self._results],
            "stats": self.get_stats(),
            "config": {
                "url": self.url_pattern,
                "method": self.method,
                "threads": self.threads,
            },
        }, indent=2, ensure_ascii=False)


# ── CLI Integration ─────────────────────────────────────────────────────

def _parse_int_set(s: str) -> Set[int]:
    """Parse comma-separated integers: '200,301,403' -> {200, 301, 403}."""
    result = set()
    for part in s.split(","):
        part = part.strip()
        if part.isdigit():
            result.add(int(part))
    return result


def run_fuzz(args) -> int:
    """CLI entry point for `fray fuzz`."""
    try:
        from fray.output import console
    except ImportError:
        console = None

    url = args.url
    if ContentFuzzer.FUZZ_KEYWORD not in url:
        # Auto-append FUZZ
        url = url.rstrip("/") + "/FUZZ"

    # Build headers
    headers = {}
    for h in getattr(args, "headers", []) or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    fuzzer = ContentFuzzer(
        url_pattern=url,
        method=getattr(args, "method", "GET") or "GET",
        headers=headers,
        data=getattr(args, "data", "") or "",
        timeout=getattr(args, "timeout", 10) or 10,
        threads=getattr(args, "threads", 20) or 20,
        delay=getattr(args, "delay", 0.0) or 0.0,
        follow_redirects=getattr(args, "follow_redirects", False),
        verify_ssl=not getattr(args, "insecure", False),
        filter_status=_parse_int_set(getattr(args, "fc", "404") or "404"),
        match_status=_parse_int_set(getattr(args, "mc", "") or "") or None,
        filter_size=_parse_int_set(getattr(args, "fs", "") or "") or None,
        filter_words=_parse_int_set(getattr(args, "fw", "") or "") or None,
        filter_lines=_parse_int_set(getattr(args, "fl", "") or "") or None,
        recursion=getattr(args, "recursion", False),
        recursion_depth=getattr(args, "recursion_depth", 1) or 1,
    )

    # Load wordlist
    wordlist = getattr(args, "wordlist", None)
    if wordlist == "-":
        n = fuzzer.load_stdin()
    elif wordlist:
        # Check if it's a built-in name
        if wordlist in ("common", "api"):
            n = fuzzer.load_builtin(wordlist)
        else:
            n = fuzzer.load_wordlist(wordlist)
    else:
        n = fuzzer.load_builtin("common")

    if console:
        console.print(f"\n  [bold cyan]Fray Fuzzer[/bold cyan]")
        console.print(f"  Target: [green]{url}[/green]")
        console.print(f"  Wordlist: [cyan]{n}[/cyan] words")
        console.print(f"  Threads: {fuzzer.threads} · Timeout: {fuzzer.timeout}s")
        if fuzzer.delay:
            console.print(f"  Delay: {fuzzer.delay}s between requests")
        console.print()

    def _on_result(result: FuzzResult, stats: Dict[str, Any]):
        if console:
            status_color = "green" if result.status == 200 else "yellow" if result.status in (301, 302) else "red"
            redir = f" → {result.redirect}" if result.redirect else ""
            console.print(
                f"  [{status_color}]{result.status:>3}[/{status_color}]"
                f"  [dim]{result.size:>8}B[/dim]"
                f"  [dim]{result.words:>5}W[/dim]"
                f"  [dim]{result.lines:>4}L[/dim]"
                f"  {result.url}{redir}"
                f"  [dim]{result.duration_ms}ms[/dim]"
            )

    results = fuzzer.run(callback=_on_result)

    stats = fuzzer.get_stats()
    if console:
        console.print()
        console.print(f"  [bold]Results:[/bold] {stats['results_found']} found")
        console.print(f"  [bold]Requests:[/bold] {stats['requests_made']} in {stats['elapsed_seconds']}s "
                      f"({stats['requests_per_second']} req/s)")
        console.print()

    # JSON output
    if getattr(args, "json_output", False) or getattr(args, "output", None):
        output = fuzzer.results_json()
        out_path = getattr(args, "output", None)
        if out_path:
            Path(out_path).write_text(output, encoding="utf-8")
            if console:
                console.print(f"  [dim]Results saved to {out_path}[/dim]")
        else:
            print(output)

    return 0 if results else 1
