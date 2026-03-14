# Fray CLI Reference

> **61 commands** across 12 categories.
> Generated from `fray/cli.py` — the single source of truth.

---

## Command Map

```
fray
├── 🚀 Getting Started
│   ├── go <url>                     # Guided pipeline: recon → test → report (RECOMMENDED)
│   ├── wizard / init                # Interactive scan wizard (Q&A guided)
│   └── demo [url]                   # Quick showcase (great for GIFs)
│
├── 🔍 Reconnaissance
│   ├── recon <url>                  # Full recon: HTTP, TLS, headers, fingerprinting
│   ├── detect <url>                 # WAF vendor detection
│   ├── crawl <url>                  # Injection point discovery (forms, params, JS routes)
│   ├── graph <url>                  # Visualize attack surface (subdomains, DNS, tech)
│   └── waf-reverse <url>           # Reverse-engineer WAF rules (tags, events, keywords)
│
├── ⚔️ Testing
│   ├── test <url>                   # Test WAF with payloads (core command)
│   ├── scan <url>                   # Auto: crawl → discover → inject
│   ├── bypass <url>                 # WAF bypass scoring with scorecard
│   ├── ai-bypass <url>              # LLM-generated adaptive bypass
│   ├── agent <url>                  # Self-improving probe → mutate → learn agent
│   └── auto <url>                   # Full pipeline: recon → scan → ai-bypass
│
├── 🧪 Specialized Testing
│   ├── smuggle <url>                # HTTP request smuggling (CL.TE / TE.CL)
│   ├── race <url>                   # Race condition (TOCTOU) testing
│   ├── proto <url>                  # Multi-protocol: WebSocket, GraphQL, gRPC
│   ├── compare <url>                # A/B TLS fingerprint bypass analysis
│   └── validate <url>              # Blue team WAF config validation
│
├── 🔐 Authentication & Sessions
│   ├── session list                 # List saved auth sessions
│   ├── session login <url>          # Login and save session cookies
│   ├── session delete <name>        # Delete a saved session
│   └── solve <url>                  # Solve WAF challenges (Turnstile, CAPTCHA)
│
├── 🕵️ OSINT & Intelligence
│   ├── osint <domain>               # Whois, emails, typosquatting, GitHub, docs
│   ├── leak <domain|email>          # GitHub code + HIBP breach search
│   ├── cred <login-url>             # Credential stuffing test
│   ├── ct <domain>                  # Certificate Transparency monitoring
│   └── feed                         # Threat intel feed (CVE, advisories, research)
│
├── 🧬 CVE & Payloads
│   ├── cve-payload <CVE-ID>         # Generate payloads from CVE
│   ├── poc-recheck                  # Re-check CVEs for new PoC exploits
│   ├── payloads                     # List available payload categories
│   ├── stats                        # Payload database statistics
│   └── submit-payload               # Submit payload to community via GitHub PR
│
├── 📊 Reporting
│   ├── report -i <json>             # Generate HTML security report
│   ├── company-report --company <d> # Automated company security report
│   ├── waf-report                   # Corporate WAF coverage report
│   ├── posture <jsonl>              # Industry-level posture comparison
│   ├── diff <old> <new>             # Compare two recon reports
│   ├── explain <CVE|json>           # Human-readable findings + remediation
│   └── export-nuclei <json>         # Generate Nuclei YAML templates
│
├── 🔄 Operations
│   ├── monitor <domain>             # Continuous monitoring + alerting
│   ├── batch <file>                 # Batch recon across domain lists
│   ├── bounty                       # Bug bounty platform integration
│   ├── scope <file>                 # Validate scope file
│   └── harden <url>                 # OWASP Top 10 + header hardening audit
│
├── ⚙️ Configuration
│   ├── config init                  # Create .fray.toml
│   ├── config show                  # Display current config
│   ├── config validate              # Validate config
│   ├── config targets               # List targets from config
│   ├── config profiles              # List available profiles
│   ├── plugin list                  # List loaded plugins
│   ├── plugin init --name <n>       # Scaffold a new plugin
│   ├── plugin install <file>        # Install plugin to ~/.fray/plugins/
│   ├── plugin hooks                 # List all hook types
│   ├── cache show|clear|export      # Manage adaptive payload cache
│   └── completions [bash|zsh|fish]  # Shell completion scripts
│
├── 🔗 Integrations
│   ├── ci init                      # Generate GitHub Actions workflow
│   ├── mcp                          # Start MCP server (AI assistant)
│   ├── dashboard                    # Launch local web dashboard
│   ├── update                       # Pull latest payload database
│   └── sync --push|--pull           # Cloud sync payloads (R2 + GitHub)
│
└── 📚 Utilities
    ├── ask <query>                  # Natural language query over data
    ├── learn [topic]                # Interactive CTF-style tutorial
    ├── doctor [--fix]               # Check environment + auto-fix
    ├── version                      # Show version
    ├── help                         # Friendly command guide
    ├── smoke                        # QA test suite
    └── todo                         # Internal TODO list
```

---

## Duplicate / Overlap Analysis

| Issue | Commands | Recommendation |
|-------|----------|----------------|
| **Pipeline overlap** | `go`, `auto`, `scan`, `wizard`/`init`, `demo` | `go` = recommended default. `auto` = legacy (keep for backward compat). `scan` = crawl-first (different flow). `wizard`/`init` = interactive Q&A. `demo` = quick showcase. **No true duplicates.** |
| **Config init duplicate** | `config init` vs `init-config` | `init-config` is redundant — `config init` does the same. **Deprecate `init-config`.** |
| **Wizard alias** | `wizard` vs `init` | `init` is intentional alias for `wizard`. **Keep both** (users expect `init`). |
| **Test vs Bypass** | `test` vs `bypass` | `test` = core payload tester. `bypass` = evasion-optimized with scorecard + mutations. **Different purpose, keep both.** |
| **Update vs Sync** | `update` vs `sync` | `update` = simple pull. `sync` = push/pull/configure/leaderboard. `update` is subset. **Keep both** (simpler UX for common case). |
| **Report variants** | `report`, `company-report`, `waf-report`, `posture` | Each has distinct input/output. `report` = generic HTML. `company-report` = per-domain summary. `waf-report` = WAF coverage. `posture` = industry comparison. **Keep all.** |
| **Stats overlap** | `stats --waf-report` flag vs `waf-report` command | `stats --waf-report` duplicates `waf-report`. **Remove flag from stats.** |

### Verdict: 61 commands → 60 actionable (deprecate `init-config`)

---

## Workflow Chains — "What Runs Next?"

```
First time?
  fray wizard              → asks questions → runs recon → suggests test

Quick assessment:
  fray go <url>            → recon → smart test → report (one command)

Manual deep-dive:
  fray recon <url>         → fray test <url> -c xss     → fray report -i results.json
       │                          │
       ├→ fray crawl <url>        ├→ fray bypass <url>   → fray export-nuclei results.json
       ├→ fray detect <url>       ├→ fray ai-bypass <url>
       ├→ fray waf-reverse <url>  └→ fray agent <url>    → learns, improves over runs
       └→ fray graph <url>

Bug bounty workflow:
  fray scope scope.txt     → fray bounty --urls targets.txt → fray company-report --company example.com

Continuous security:
  fray monitor <url>       → periodic recon + diff + leak → webhook alerts
  fray ct <domain>         → cert transparency monitoring
  fray feed --auto-add     → ingest new CVE payloads → auto-test

CI/CD pipeline:
  fray ci init             → generates .github/workflows/fray.yml
  fray go <url> --ci --fail-on high --sarif → exit(1) on findings

Enterprise batch:
  fray batch domains.txt   → fray posture results.jsonl → fray waf-report
```

---

## Common Global Flags

These flags work on most commands that make HTTP requests:

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --timeout N` | Request timeout (seconds) | `8` |
| `-d, --delay N` | Delay between requests (seconds) | `0.5` |
| `-o, --output FILE` | Save results to file | — |
| `--json` | Output as JSON to stdout | off |
| `--insecure` | Skip TLS certificate verification | off |
| `--cookie VALUE` | Cookie header for auth | — |
| `--bearer TOKEN` | Bearer token for auth | — |
| `-H, --header 'K: V'` | Custom header (repeatable) | — |
| `--stealth` | Stealth mode (random UA, jitter, TLS spoof) | off |
| `--impersonate BROWSER` | TLS fingerprint spoofing (chrome/firefox/safari) | — |
| `--scope FILE` | Restrict to domains in scope file | — |
| `-v, --verbose` | Verbose/debug output | off |
| `-q, --quiet` | Suppress non-essential output | off |
| `--profile PRESET` | Scan preset: quick/standard/deep/stealth/api/bounty | — |
| `--login-flow 'URL,k=v'` | Form login with auto CSRF detection | — |
| `--load-session NAME` | Load saved session from ~/.fray/sessions/ | — |
| `--save-session NAME` | Save session cookies/tokens for reuse | — |
| `--auth-profile FILE` | Auth profile JSON (~/.fray/auth/*.json) | — |
| `--notify WEBHOOK` | Slack/Discord/Teams notification on completion | — |
| `--sarif` | Output SARIF 2.1.0 for GitHub Security tab | off |
| `--ci` | CI mode: minimal output, JSON, non-zero exit on findings | off |
| `--fail-on SEVERITY` | Exit code 1 if findings >= severity (implies --ci) | — |
| `--plugin FILE` | Load plugin file(s) | — |
| `--rate-limit N` | Max requests per second | unlimited |
| `--jitter N` | Random delay variance (seconds) | `0` |

---

## Full Command Reference

### `fray go` — Guided Pipeline ⭐ Recommended

```
fray go <url> [options]
```

Recon → smart payload test → HTML report. Zero-knowledge, one command.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-t, --timeout` | Request timeout (default: 8) |
| `--deep` | Extended DNS, 300 subdomains, Wayback 500 |
| `--stealth` | Slower, randomized requests, TLS impersonation |
| `--impersonate BROWSER` | TLS fingerprint spoofing |
| `-o, --output FILE` | Save pipeline JSON |
| `--output-dir DIR` | Output directory for report + JSON |
| `--json` | Output as JSON |
| `--cookie / --bearer / -H` | Authentication |
| `--login-flow` | Form login |
| `--load-session / --save-session` | Session persistence |
| `--ci` | CI/CD mode |
| `--fail-on SEVERITY` | Exit 1 on findings >= severity |
| `--sarif` | SARIF output |
| `--solve-challenge` | Auto-solve WAF challenges (Playwright) |

---

### `fray recon` — Reconnaissance

```
fray recon <url> [options]
```

Full reconnaissance: HTTP fingerprinting, TLS analysis, security headers, technology detection, subdomain enumeration, DNS records, attack surface mapping.

| Flag | Description |
|------|-------------|
| `target` | Target URL (or pipe: `cat domains.txt \| fray recon`) |
| `-t, --timeout` | Request timeout (default: 8) |
| `--json / --ai` | JSON output / AI-ready structured output |
| `-o, --output` | Save recon JSON to file |
| `--profile` | Preset: quick/standard/deep/stealth/api/bounty |
| `--fast` | Fast mode (~15s): skip historical URLs, admin panels |
| `--deep` | Deep mode (~45s): extended DNS, 300-word subdomain list |
| `--stealth` | Stealth mode: 3 threads, 0.5-1.5s jitter |
| `--js` | JS endpoint extraction from JavaScript files |
| `--history` | Historical URLs: Wayback Machine, sitemap, robots.txt |
| `--params` | Parameter mining: brute-force hidden URL params |
| `--leak` | Include GitHub code + HIBP breach search |
| `--retirejs` | Fetch Retire.js DB for frontend CVE coverage |
| `--compare [FILE]` | Compare with previous scan |
| `--export-dir DIR` | Export structured results |
| `--no-export` | Disable auto-export |
| `--ai-summary` | AI-powered summary (needs API key) |
| `--no-interactive` | Skip interactive menu after recon |
| `--parallel N` | Parallel workers for multi-target |
| `--sarif / --ci / --fail-on` | CI/CD integration |
| `--notify WEBHOOK` | Notifications |
| Auth flags | `--cookie`, `--bearer`, `-H`, `--login-flow`, `--load-session`, `--save-session` |

---

### `fray detect` — WAF Detection

```
fray detect <url> [options]
```

Detect WAF vendor with multi-signal confidence scoring.

| Flag | Description |
|------|-------------|
| `target` | Target URL (or pipe) |
| `--insecure` | Skip TLS verification |
| Auth flags | `--cookie`, `--bearer`, `-H`, `--login-flow`, `--load-session`, `--save-session` |
| `-q / -v` | Quiet / verbose |

---

### `fray test` — Payload Testing

```
fray test <url> -c xss [options]
```

Core payload testing against WAF.

| Flag | Description |
|------|-------------|
| `target` | Target URL (or pipe) |
| `-c, --category` | Payload category (xss, sqli, ssrf, cmdi, etc.) |
| `-p, --payload-file` | Custom payload file |
| `--all` | Test all categories |
| `-m, --max N` | Max payloads to test |
| `--smart` | Adaptive evolution: probe WAF, skip redundant, mutate |
| `--mutate [N]` | Auto-mutate blocked payloads (default: 10 variants) |
| `--blind` | Blind injection detection (time-based + OOB DNS) |
| `--oob-server DOMAIN` | OOB callback server (e.g. oast.fun) |
| `--concurrency N` | Parallel workers (default: 1) |
| `--resume` | Resume from checkpoint |
| `--from-crawl FILE` | Load endpoints from crawl JSON |
| `--solve-challenge` | Auto-solve JS challenges via Playwright |
| `--auto-throttle` | Fingerprint rate limits first |
| `--no-follow-redirects` | Don't follow 3xx redirects |
| `--redirect-limit N` | Max redirects (default: 5) |
| `--report-format html` | Auto-generate report after testing |
| `-y, --yes` | Skip interactive prompt in --smart mode |
| `--sarif / --ai / --json` | Output formats |
| Auth flags | `--cookie`, `--bearer`, `-H`, `--login-flow`, `--auth-profile`, `--load-session`, `--save-session` |
| `--stealth`, `--impersonate` | Anti-detection |
| `--rate-limit`, `--jitter` | Rate control |
| `--notify WEBHOOK` | Notifications |

---

### `fray scan` — Auto Scan

```
fray scan <url> [options]
```

Automatic: crawl → parameter discovery → payload injection.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-c, --category` | Payload category (default: xss) |
| `-m, --max N` | Max payloads per injection point (default: 5) |
| `--depth N` | Max crawl depth (default: 3) |
| `--max-pages N` | Max pages to crawl (default: 30) |
| `-w, --workers N` | Concurrent workers (default: 1) |
| `--parallel N` | Parallel payload testing per point |
| `--browser` | Playwright for JS-heavy SPAs |
| `--baseline` | Capture baseline for false positive reduction |
| `--follow-redirects` | Follow 3xx for redirect-based WAF blocks |
| `--blind / --oob-server` | Blind injection detection |
| `--resume` | Resume from checkpoint |
| `--auto-throttle` | Auto rate limit detection |
| `--burp FILE` | Export as Burp Suite XML |
| `--zap FILE` | Export as ZAP alerts JSON |
| `--nuclei-export DIR` | Export as Nuclei YAML templates |
| `--burp-import FILE` | Import Burp request file |
| `--sarif / --ai / --json` | Output formats |
| Auth flags | Full auth support |
| Anti-detection | `--stealth`, `--impersonate`, `--rate-limit`, `--jitter` |
| `--notify WEBHOOK` | Notifications |

---

### `fray bypass` — WAF Bypass Scoring

```
fray bypass <url> [options]
```

Evasion-optimized payload testing with detailed scorecard.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-c, --category` | Category (default: xss) |
| `--param` | URL parameter to inject (default: input) |
| `--mutations N` | Max mutations per bypass (default: 5) |
| `--mutation-budget N` | Total mutation budget (default: 30) |
| `--list-wafs` | List supported WAF targets and exit |
| `--burp / --zap / --nuclei-export` | Tool exports |
| `--share` | Share results |
| Auth + anti-detection flags | Full support |

---

### `fray ai-bypass` — AI-Assisted Bypass

```
fray ai-bypass <url> [options]
```

LLM-generated payloads with adaptive feedback loop.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-c, --category` | Category (default: xss) |
| `--param` | URL parameter (default: input) |
| `--rounds N` | Adaptive generation rounds (default: 3) |
| `--max-per-round N` | Max payloads per round (default: 10) |
| `--no-headers` | Skip HTTP header injection |

---

### `fray agent` — Self-Improving Agent

```
fray agent <url> -c xss [options]
```

Iterative probe → mutate → learn loop with persistent cache.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-c, --category` | Category (default: xss) |
| `--rounds N` | Max mutation rounds (default: 5) |
| `--budget N` | Total request budget (default: 100) |
| `--ai` | Use LLM for mutation guidance |
| `--no-cache` | Disable learning cache |
| `--notify WEBHOOK` | Notifications |

---

### `fray crawl` — Injection Point Discovery

```
fray crawl <url> [options]
```

Discover forms, URL parameters, JS API routes, GraphQL endpoints.

| Flag | Description |
|------|-------------|
| `target` | Target URL |
| `-m, --max N` | Max pages (default: 50) |
| `--depth N` | Max depth (default: 3) |
| `--browser` | Playwright for JS-rendered SPAs |

---

### `fray smuggle` — HTTP Smuggling

```
fray smuggle <url> [options]
```

Test CL.TE, TE.CL, TE.TE request smuggling vectors.

---

### `fray race` — Race Condition Testing

```
fray race <url> [options]
```

| Flag | Description |
|------|-------------|
| `target` | Target URL (e.g. /api/redeem) |
| `--method` | HTTP method (default: GET) |
| `--body` | Request body |
| `-n, --concurrency` | Simultaneous requests (default: 10) |
| `--rounds N` | Test rounds (default: 1) |

---

### `fray proto` — Multi-Protocol Testing

```
fray proto <url> [options]
```

| Flag | Description |
|------|-------------|
| `--ws-only` | WebSocket only |
| `--graphql-only` | GraphQL only |
| `--grpc-only` | gRPC only |

---

### `fray waf-reverse` — WAF Rule Reverse Engineering

```
fray waf-reverse <url> [options]
```

| Flag | Description |
|------|-------------|
| `--skip-encodings` | Skip encoding bypass probing (faster) |
| `--skip-contexts` | Skip context enforcement probing (faster) |

---

### `fray compare` — A/B TLS Analysis

```
fray compare <url> [options]
```

Compare raw vs TLS-impersonated requests to classify WAF blocks.

| Flag | Description |
|------|-------------|
| `-m, --max N` | Max payloads (each tested twice, default: 20) |
| `-p, --param` | Query parameter (default: q) |
| `--impersonate BROWSER` | Browser to impersonate (default: chrome) |

---

### `fray validate` — Blue Team WAF Validation

```
fray validate <url> [options]
```

| Flag | Description |
|------|-------------|
| `--waf` | Expected WAF vendor |
| `--categories` | Comma-separated categories to test |

---

### `fray session` — Auth Session Management

```
fray session list
fray session login <url> --name <name> [--cookie|--bearer|--auth-profile]
fray session delete <name>
```

---

### `fray solve` — WAF Challenge Solver

```
fray solve <url> [options]
```

| Flag | Description |
|------|-------------|
| `--type` | Force type: cloudflare_js, cloudflare_turnstile, recaptcha_v2, hcaptcha |
| `--no-headless` | Show browser window (manual solving) |
| `--save-session NAME` | Save solved cookies |

---

### `fray osint` — Offensive OSINT

```
fray osint <domain> [options]
```

| Flag | Description |
|------|-------------|
| `--whois` | Whois only |
| `--emails` | Email harvesting only |
| `--github` | GitHub org recon only |
| `--docs` | Document metadata only |
| `--permutations` | Typosquatting only |

---

### `fray leak` — Credential Leak Search

```
fray leak <domain|email> [options]
```

| Flag | Description |
|------|-------------|
| `--github-only` | Only search GitHub code |
| `--hibp-only` | Only search Have I Been Pwned |

---

### `fray cred` — Credential Stuffing Test

```
fray cred <login-url> --pairs <file> [options]
```

| Flag | Description |
|------|-------------|
| `--pairs FILE` | File with email:password pairs |
| `--username-field` | Override username field name |
| `--password-field` | Override password field name |
| `--content-type` | Override: form or json |
| `--rate N` | Max req/s (default: 1) |
| `--proxy URL` | HTTP/HTTPS proxy |
| `--dry-run` | Preview without sending |

---

### `fray ct` — Certificate Transparency

```
fray ct <domain> [options]
```

| Flag | Description |
|------|-------------|
| `--days N` | Look-back window (default: 30) |
| `--save` | Save baseline for future diffing |

---

### `fray feed` — Threat Intelligence Feed

```
fray feed [options]
```

| Flag | Description |
|------|-------------|
| `--sources` | Comma-separated: nvd, cisa, github, exploitdb, rss, nuclei |
| `--since PERIOD` | Time window (default: 7d) |
| `-c, --category` | Filter by category |
| `--auto-add` | Auto-add payloads to database |
| `--test-target URL` | Auto-test new payloads against target |
| `--dry-run` | Preview without adding |
| `--list-sources` | List available sources |
| `--warm-cache` | Pre-cache threat intel data |
| `--no-poc` | Skip PoC extraction |
| `--enrich` | Enrich with additional metadata |

---

### `fray cve-payload` — CVE → Payloads

```
fray cve-payload CVE-2024-12345 [options]
```

| Flag | Description |
|------|-------------|
| `--description TEXT` | Free-text description (alt to CVE ID) |
| `--file FILE` | JSONL for batch processing |
| `-T, --test-target URL` | Test generated payloads |
| `--mutate` | Auto-generate variants |
| `-i, --interactive` | Interactive selection mode |
| `--no-poc` | Skip PoC extraction |

---

### `fray monitor` — Continuous Monitoring

```
fray monitor <domain> [options]
```

| Flag | Description |
|------|-------------|
| `--interval` | Scan interval: 30m, 6h, 12h, 24h, 7d (default: 24h) |
| `--webhook URL` | Alert webhook |
| `--email ADDR` | Email alerts (needs RESEND_API_KEY) |
| `--leak` | Also run leak search each cycle |
| `--once` | Single cycle and exit |
| `--list` | List previous snapshots |

---

### `fray batch` — Batch Recon

```
fray batch domains.txt [options]
```

| Flag | Description |
|------|-------------|
| `--nikkei225` | Use built-in Nikkei 225 domain list |
| `-w, --workers N` | Parallel workers (default: 4) |
| `--profile` | quick/standard/deep (default: quick) |
| `--no-resume` | Rescan all (ignore previous) |

---

### `fray bounty` — Bug Bounty Integration

```
fray bounty --platform hackerone --program <handle> [options]
```

| Flag | Description |
|------|-------------|
| `--platform` | hackerone or bugcrowd |
| `--program` | Program handle |
| `--urls FILE` | URL file |
| `--scope-only` | Show scope only, no tests |
| `--force` | Test ALL URLs including shared platforms |
| `--no-smart` | Disable adaptive evolution |
| `--report FILE` | Generate bounty report from results |

---

### Reporting Commands

```
fray report -i results.json [-o report.html] [--format html|markdown] [--sample]
fray company-report --company example.com [-o report.md] [--json]
fray waf-report [--company example.com] [-o report.md] [--json]
fray posture results.jsonl [-o report.md] [--json]
fray diff old.json new.json [--json]
fray explain CVE-2021-44228 [--max 5] [--json]
fray export-nuclei results.json [-o ./nuclei] [-c xss] [--waf cloudflare]
```

---

### Configuration Commands

```
fray config init [--force] [--path FILE]    # Create .fray.toml
fray config show                            # Display current config
fray config validate                        # Validate .fray.toml
fray config targets                         # List targets from config
fray config profiles                        # List available profiles
```

---

### Plugin Commands

```
fray plugin list                            # Show loaded plugins + metadata
fray plugin hooks                           # List all 10 hook types
fray plugin init --name my_plugin           # Scaffold a new plugin
fray plugin install my_plugin.py            # Install to ~/.fray/plugins/
fray plugin load my_plugin.py               # Manually load
```

---

### Cache Commands

```
fray cache show [domain]                    # Cache summary
fray cache clear [domain]                   # Clear cache
fray cache stats [domain]                   # Raw cache JSON
fray cache export [-o file.json] [domain]   # Export portable JSON
fray cache import file.json [--replace]     # Import cache
```

---

### Integration Commands

```
fray ci init [--target URL] [--fail-on-bypass]   # Generate GitHub Actions workflow
fray mcp                                          # Start MCP server for AI assistants
fray dashboard [--port 8337] [--no-open]          # Launch local web dashboard
fray update [--source auto]                       # Pull latest payload database
fray sync --push|--pull [--tag TAG]               # Cloud sync (R2 + GitHub)
fray completions [bash|zsh|fish]                   # Shell completions
```

---

### Utility Commands

```
fray ask "what WAFs did we find?"           # Natural language query
fray learn [xss|sqli|ssrf|cmdi]             # CTF-style tutorial
fray doctor [--fix] [-v]                    # Environment check
fray version                                # Show version
fray help                                   # Friendly guide
fray demo [url]                             # Quick showcase
fray smoke [--quick|--full]                 # QA test suite
fray wizard / fray init                     # Interactive scan wizard
fray scope scope.txt [--check URL]          # Validate scope file
fray harden <url>                           # OWASP misconfig + header audit
fray graph <url> [--deep]                   # Attack surface visualization
fray stats [--waf-market] [--trend DOMAIN]  # Payload DB stats
fray payloads                               # List payload categories
fray submit-payload --payload '...' -c xss  # Submit to community
fray todo                                   # Internal TODO list
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `FRAY_PLUGINS=a.py,b.py` | Load plugins on startup |
| `FRAY_TIMEOUT=15` | Default timeout |
| `FRAY_DELAY=1.0` | Default delay |
| `FRAY_CATEGORY=sqli` | Default category |
| `GITHUB_TOKEN` | Required for leak search, GitHub code search |
| `OPENAI_API_KEY` | For AI features (--ai-summary, ask) |
| `ANTHROPIC_API_KEY` | Alternative AI provider |
| `RESEND_API_KEY` | For email alerts in monitor |
| `NO_COLOR=1` | Disable color output |
| `FORCE_COLOR=1` | Force color output |

---

## Data Directories

| Path | Purpose |
|------|---------|
| `~/.fray/plugins/` | Auto-loaded plugins |
| `~/.fray/sessions/` | Saved auth sessions |
| `~/.fray/checkpoints/` | Scan resume checkpoints |
| `~/.fray/auth/` | Auth profiles (OAuth2, form login) |
| `~/.fray/recon/` | Exported recon results |
| `~/.fray/ct_baselines/` | CT monitoring baselines |
| `~/.fray/learned_patterns.json` | Agent learning cache |
| `~/.fray/subdomain_cache.json` | Subdomain cache |
| `~/.fray/todo.json` | TODO list |
| `.fray.toml` | Project config file |

---

## Quick Start Examples

```bash
# First time — guided wizard
fray wizard

# One-command full assessment
fray go https://example.com

# Deep stealth recon
fray recon https://example.com --deep --stealth

# Test XSS payloads with adaptive evolution
fray test https://example.com -c xss --smart --mutate

# Auto-scan: crawl + test all endpoints
fray scan https://example.com -c xss --browser --blind

# Self-improving agent (learns over runs)
fray agent https://example.com -c xss --rounds 5 --budget 100

# Authenticated testing
fray session login https://example.com/login --name mysite --cookie "sid=abc"
fray test https://example.com -c sqli --load-session mysite

# CI/CD integration
fray go https://staging.example.com --ci --fail-on high --sarif

# Batch enterprise assessment
fray batch domains.txt -w 8 --profile deep -o results.jsonl
fray posture results.jsonl -o posture_report.md

# Continuous monitoring
fray monitor example.com --interval 6h --webhook https://hooks.slack.com/...

# Create and use a plugin
fray plugin init --name slack_notifier
# edit ~/.fray/plugins/slack_notifier.py
fray test https://example.com -c xss  # plugin auto-loads
```
