# Fray — WAF Bypass & Security Testing Toolkit

**🌐 Language:** **English** | [日本語](README.ja.md)

### ⚔️ *Open-source penetration testing tool for web application firewalls — recon, scan, bypass, harden*

Fray is a fast, open-source **web application security** scanner and **WAF bypass** toolkit for penetration testers, bug bounty hunters, and DevSecOps teams. It combines a 6,300+ payload database, 27-check reconnaissance, AI-assisted WAF evasion, and OWASP hardening audits into a single `pip install` with zero dependencies.

[![Total Payloads](https://img.shields.io/badge/Payloads-6300+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF_Vendors-25+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/Recon_Checks-27-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![OWASP Coverage](https://img.shields.io/badge/OWASP-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/fray)

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> **FOR AUTHORIZED SECURITY TESTING ONLY** — Only test systems you own or have explicit written permission to test.

---

## Why Fray?

Most payload collections are static text files. Fray is a **complete workflow**:

- **`fray auto`** — Full pipeline: recon → scan → ai-bypass in one command *(new)*
- **`fray scan`** — Auto crawl → param discovery → payload injection
- **`fray recon`** — 27 automated checks (TLS, headers, DNS, CORS, params, JS, history, GraphQL, API, Host injection, admin panels)
- **`fray ai-bypass`** — LLM-assisted adaptive bypass with response diffing + header manipulation *(new)*
- **`fray bypass`** — 5-phase WAF evasion scorer with mutation feedback loop
- **`fray harden`** — OWASP Top 10 misconfig checks + security header audit with fix snippets *(new)*
- **`fray detect`** — Fingerprint 25 WAF vendors
- **`fray test`** — 6,300+ payloads across 24 OWASP categories
- **Zero dependencies** — pure Python stdlib, `pip install fray` and go

## Who Uses Fray?

- **Bug Bounty Hunters** — Discover hidden params, old endpoints, bypass Cloudflare/AWS WAF/Akamai, file reports
- **Pentesters** — Full reconnaissance + automated vulnerability scanning with client-ready HTML reports
- **Blue Teams** — Validate WAF rules, regression test after config changes
- **DevSecOps** — DAST in CI/CD pipelines, fail builds on WAF bypasses
- **Security Researchers** — Find WAF evasion techniques, contribute payloads
- **Students** — Interactive CTF tutorials, learn OWASP Top 10 attack vectors hands-on

---

## Quick Start

```bash
pip install fray                # PyPI (all platforms)
sudo apt install fray            # Kali Linux / Debian
brew install fray                # macOS
```

```bash
fray auto https://example.com                    # Full pipeline: recon → scan → bypass
fray scan https://example.com                    # Auto scan (crawl + inject)
fray recon https://example.com                   # 27-check reconnaissance
fray ai-bypass https://example.com               # AI-assisted adaptive bypass
fray bypass https://example.com -c xss           # WAF evasion scorer
fray harden https://example.com                  # OWASP hardening audit
fray test https://example.com --smart            # Smart payload testing
fray detect https://example.com                  # WAF detection
fray explain CVE-2021-44228                      # CVE intelligence
```

---

## Command Summary

| Command | What it does |
|---------|-------------|
| **`fray auto`** | Full pipeline: recon → scan → ai-bypass with recommendations between phases |
| **`fray scan`** | Crawl → discover params → inject payloads → detect reflection |
| **`fray recon`** | 27 checks: TLS, headers, DNS, subdomains, CORS, params, JS, API, admin panels, WAF intel |
| **`fray ai-bypass`** | Adaptive bypass: probe WAF → generate payloads (LLM or local) → test → mutate → header tricks |
| **`fray bypass`** | 5-phase WAF evasion: probe → rank → test → mutate blocked → brute-force fallback |
| **`fray harden`** | Security headers audit (A-F grade) + OWASP Top 10 misconfig checks + fix snippets |
| **`fray test`** | Test 6,300+ payloads across 24 categories with adaptive throttling |
| **`fray detect`** | Fingerprint 25 WAF vendors |
| **`fray report`** | HTML/Markdown reports from scan results |
| **`fray explain`** | CVE intelligence with payloads, or human-readable findings |
| **`fray diff`** | Before/after regression testing (CI/CD gate) |
| **`fray graph`** | Visual attack surface tree |

---

## `fray auto` — Full Pipeline

```bash
fray auto https://example.com -c xss
fray auto https://example.com --skip-recon       # Skip recon, run scan + bypass only
fray auto https://example.com --json -o report.json
```

```
───── Phase 1: Reconnaissance ─────
  Risk: HIGH (56/100)  WAF: Cloudflare  Subdomains: 186
  → Recommended: fray test target -c csp_bypass

───── Phase 2: WAF Scan ─────
  [1/20] BLOCKED  403 │ Async/await exfiltration
  [2/20] BLOCKED  403 │ Promise-based XSS
  → 100% blocked: AI bypass will try adaptive mutations

───── Phase 3: AI Bypass ─────
  BLOCKED  403 │ local:url_encode
  BLOCKED  403 │ local:double_url_encode
  SKIP     400 │ Transfer-Encoding: chunked (not a real bypass)

───── Pipeline Complete ─────
╭── Pipeline Summary ──╮
│ Recon Risk   HIGH    │
│ WAF          CF      │
│ Scan         0/20    │
│ AI Bypass    0/8     │
│ Header       0       │
╰──────────────────────╯
  Next steps:
    fray test target -c csp_bypass --max 50
    fray bypass target -c xss --mutation-budget 50
    fray harden target
```

---

## `fray scan` — Automated Attack Surface Mapping

One command: crawl your target, discover injection points, test payloads, report results.

```bash
fray scan https://example.com -c xss -m 3 -w 4
```

```
──────────────────── Crawling https://example.com ────────────────────
  [  1] https://example.com
  [  2] https://example.com/search
  [  3] https://example.com/guestbook.php
  ✓ Crawled 10 pages, found 7 injection points (3 forms, 1 JS endpoints)

──────────────────────── Payload Injection ───────────────────────────
  [1/7] POST /guestbook.php ?name= (form)
      BLOCKED   403 │ <script>alert(1)</script>
      PASSED    200 │ <img src=x onerror=alert(1)>    ↩ REFLECTED
  [2/7] GET  /search ?q= (form)
      BLOCKED   403 │ <script>alert(1)</script>
      PASSED    200 │ <img src=x onerror=alert(1)>    ↩ REFLECTED

╭──────────── Scan Summary ────────────╮
│ Total Tested      21                 │
│ Blocked           15  (71.4%)        │
│ Passed             6                 │
│ Reflected          4  ← confirmed    │
╰──────────────────────────────────────╯
```

Reflected payloads are highlighted with `↩ REFLECTED` — confirmed injection where the payload appears verbatim in the response body.

**What it does:**
1. **Crawls** — BFS spider, follows same-origin links, seeds from `robots.txt` + `sitemap.xml`
2. **Discovers** — Extracts params from URLs, HTML forms, and JavaScript API calls
3. **Injects** — Tests each parameter with payloads from your chosen category
4. **Detects reflection** — Confirms when payloads appear verbatim in the response body
5. **Auto-backoff** — Handles 429 rate limits with exponential backoff

```bash
# Scope-restricted scan (bug bounty)
fray scan https://target.com --scope scope.txt -w 4

# Authenticated scan with stealth
fray scan https://app.target.com --cookie "session=abc" --stealth

# Deep scan with SQLi payloads
fray scan https://target.com -c sqli --depth 5 --max-pages 100

# JSON output for CI pipelines
fray scan https://target.com --json -o results.json
```

[Full scan options + examples →](docs/scanning-guide.md)

---

## `fray recon` — 27 Automated Checks

```bash
fray recon https://example.com
fray recon https://example.com --js       # JS endpoint extraction
fray recon https://example.com --history  # Historical URL discovery
fray recon https://example.com --params   # Parameter brute-force mining
```

| Check | What It Finds |
|-------|---------------|
| **Parameter Discovery** | Query strings, form inputs, JS API endpoints |
| **Parameter Mining** | Brute-force 136 common param names, detect hidden `?id=`, `?file=`, `?redirect=` |
| **JS Endpoint Extraction** | LinkFinder-style: hidden APIs, hostnames, cloud buckets (S3/GCS/Azure), API keys, secrets |
| **Historical URLs** | Old endpoints via Wayback Machine, sitemap.xml, robots.txt |
| **GraphQL Introspection** | Probe 10 common endpoints, detect exposed schema (types, fields, mutations) |
| **API Discovery** | Swagger/OpenAPI specs, `/api/v1/`, `/api-docs`, health endpoints — exposes every route & param |
| **Host Header Injection** | Password reset poisoning, cache poisoning, SSRF via `Host:` / `X-Forwarded-Host` manipulation |
| **Admin Panel Discovery** | 70 paths: `/admin`, `/wp-admin`, `/phpmyadmin`, `/actuator`, `/console`, debug tools |
| **TLS** | Version, cipher, cert expiry |
| **Security Headers** | HSTS, CSP, X-Frame-Options (scored) |
| **Cookies** | HttpOnly, Secure, SameSite flags |
| **Fingerprinting** | WordPress, PHP, Node.js, nginx, Apache, Java, .NET |
| **DNS** | A/CNAME/MX/TXT, CDN detection, SPF/DMARC |
| **CORS** | Wildcard, reflected origin, credentials misconfig |
| **Rate Limit Fingerprint** | Map threshold (req/s before 429), burst limit, lockout duration, safe delay |
| **WAF Detection Mode** | Signature vs anomaly vs hybrid — body diff, timing diff, header diff |
| **WAF Rule Gap Analysis** | Cross-reference vendor against known bypasses, detection gaps, technique matrix |

Plus: 28 exposed file probes (`.env`, `.git`, phpinfo, actuator) · subdomains via crt.sh

`--js` parses inline and external JavaScript files — LinkFinder-style extraction of `fetch()`, `axios`, `XMLHttpRequest` calls, full absolute URLs, internal hostnames/subdomains, cloud storage buckets (AWS S3, GCS, Azure Blob, Firebase, DO Spaces), and leaked secrets (AWS keys, Google API keys, GitHub tokens, Stripe keys, Slack webhooks, JWTs, Bearer tokens, generic API keys).

`--history` queries Wayback Machine CDX API, sitemap.xml, and robots.txt Disallow paths. Old endpoints often have weaker WAF rules.

`--params` brute-forces 136 common parameter names against discovered endpoints. Detects hidden params by response diff (status, size, reflection). Risk-rated: HIGH (SSRF/LFI/injection), MEDIUM (XSS/IDOR).

GraphQL introspection runs automatically during full recon. Probes `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/playground`, etc.

API discovery probes 30+ common paths: `swagger.json`, `openapi.json`, `/api-docs`, `/swagger-ui/`, versioned API roots. Parses specs to extract every endpoint, method, and auth scheme.

**New to Fray?** Run `fray help` for a friendly guide to every command.

[Recon guide →](docs/quickstart.md)

---

## `fray ai-bypass` — AI-Assisted Adaptive Bypass

```bash
fray ai-bypass https://example.com -c xss --rounds 3
OPENAI_API_KEY=sk-... fray ai-bypass https://example.com   # LLM mode
```

| Phase | What happens |
|-------|--------------|
| **Probe** | Learn WAF behavior: blocked tags, events, keywords, strictness |
| **Generate** | LLM or smart local engine creates targeted payloads |
| **Test + Diff** | Response diffing: soft blocks, challenges, reflection |
| **Adapt** | Feed results back → re-generate smarter payloads |
| **Headers** | X-Forwarded-For, Transfer-Encoding, Content-Type confusion |

**Providers:** OpenAI (`OPENAI_API_KEY`), Anthropic (`ANTHROPIC_API_KEY`), or local (no key needed).

## `fray harden` — OWASP Hardening Audit

```bash
fray harden https://example.com
fray harden https://example.com --json -o audit.json
```

Checks security headers (HSTS, CSP, COOP, CORP, Permissions-Policy, rate-limit headers) with **A-F grade**, plus OWASP Top 10 misconfiguration checks (A01 Access Control, A02 Crypto, A05 Misconfig, A06 Components, A07 Auth). Outputs copy-paste fix snippets for **nginx, Apache, Cloudflare Workers, and Next.js**.

## `fray detect` — 25 WAF Vendors

```bash
fray detect https://example.com
```

Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, Fastly, Azure WAF, Google Cloud Armor, Sucuri, Fortinet, Wallarm, Vercel, and 13 more. Identifies signature-based, anomaly-based, and hybrid WAF modes — essential for choosing the right bypass strategy.

[Detection signatures →](docs/waf-detection-guide.md)

---

## Key Features

| Feature | How | Example |
|---------|-----|---------|
| **Scope Enforcement** | Restrict to permitted domains/IPs/CIDRs | `--scope scope.txt` |
| **Concurrent Scanning** | Parallelize crawl + injection (~3x faster) | `-w 4` |
| **Stealth Mode** | Randomized UA, jitter, throttle — one flag | `--stealth` |
| **Authenticated Scanning** | Cookie, Bearer, custom headers | `--cookie "session=abc"` |
| **CI/CD** | GitHub Actions with PR comments + fail-on-bypass | `fray ci init` |

[Auth guide →](docs/authentication-guide.md) · [Scan options →](docs/scanning-guide.md) · [CI guide →](docs/quickstart.md)

---

## 6,300+ Payloads · 24 Categories · 162 CVEs

The largest open-source WAF payload database — curated for real-world penetration testing and bug bounty hunting.

| Category | Count | Category | Count |
|----------|-------|----------|-------|
| XSS (Cross-Site Scripting) | 851 | SSRF | 71 |
| SQL Injection | 141 | SSTI | 205 |
| Command Injection (RCE) | 118 | XXE | 151 |
| Path Traversal (LFI/RFI) | 277 | AI/LLM Prompt Injection | 370 |

```bash
fray explain log4shell    # CVE intelligence with payloads
fray explain results.json # Human-readable findings: impact, remediation, next steps
fray payloads             # List all 24 payload categories
```

[Payload database →](docs/payload-database-coverage.md) · [CVE coverage →](docs/cve-real-world-bypasses.md)

---

## AI-Ready Output — `--ai` Flag

```bash
fray scan target.com --ai           # LLM-optimized JSON for AI agents
fray test target.com -c xss --ai    # Pipe into any AI workflow
fray recon target.com --ai           # Structured recon for Claude, GPT, etc.

# Example pipeline:
fray scan target.com --ai | ai analyze
```

Output: structured JSON with technologies, vulnerabilities (CWE-tagged, confidence-scored), security posture, and suggested next actions — ready for direct LLM consumption.

## Attack Surface Graph

```bash
fray graph example.com          # Visual tree of the entire attack surface
fray graph example.com --deep   # + JS endpoints + Wayback historical URLs
fray graph example.com --json   # Machine-readable graph
```

Output:
```
🌐 example.com
├── 📂 Subdomains (8)
│   ├── 🔗 api.example.com
│   ├── 🔗 admin.example.com
│   └── 🔗 cdn.example.com
├── 🛡️ WAF: Cloudflare
├── 📂 Technologies
│   ├── ⚙️ nginx (95%)
│   └── ⚙️ wordpress (70%)
├── 📂 Admin Panels (2)
│   └── 📍 /admin/ [200] OPEN
├── 📍 GraphQL: /graphql (introspection OPEN)
├── 📂 Exposed Files (3)
│   ├── 📄 .env
│   └── 📄 .git/config
└── 📂 Recommended Attacks
    ├── ⚔️ xss
    └── ⚔️ sqli
```

Aggregates all 27 recon checks into a single tree view — subdomains (crt.sh), DNS, WAF/CDN, technologies, admin panels, API endpoints, GraphQL, exposed files, CORS issues, parameters, and recommended attack categories.

## SARIF Output — GitHub Security Tab

```bash
fray scan target.com --sarif -o results.sarif    # SARIF 2.1.0 from scan
fray test target.com -c xss --sarif -o results.sarif  # SARIF from test

# Upload to GitHub:
gh code-scanning upload-sarif --sarif results.sarif
```

Fray findings appear directly in GitHub's **Security** tab alongside CodeQL and Semgrep. Each finding includes CWE tags, severity levels, and payload details.

## Diff — Visual Regression Testing

```bash
fray diff before.json after.json        # Color-coded visual diff
fray diff before.json after.json --json # Machine-readable diff
```

Git-style visual output: regressions in **red** (`- BLOCKED → + BYPASS`), improvements in **green** (`- BYPASS → + BLOCKED`), with per-category breakdown table. Exit code 1 on regressions — perfect for CI/CD gates.

## MCP Server — AI Agent Integration

Fray exposes 14 tools via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — use Fray as an AI security agent from Claude Desktop, Claude Code, ChatGPT, Cursor, or any MCP-compatible client.

```bash
pip install 'fray[mcp]'
```

### Claude Desktop — One-Liner Setup

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fray": {
      "command": "python",
      "args": ["-m", "fray.mcp_server"]
    }
  }
}
```

Restart Claude Desktop. Ask: *"What XSS payloads bypass Cloudflare?"* → Fray's 14 MCP tools are called directly.

### 14 MCP Tools

| Tool | What it does |
|------|-------------|
| `list_payload_categories` | List all 24 attack categories |
| `get_payloads` | Retrieve payloads by category |
| `search_payloads` | Full-text search across 6,300+ payloads |
| `get_waf_signatures` | WAF fingerprints for 25 vendors |
| `get_cve_details` | CVE lookup with payloads and severity |
| `suggest_payloads_for_waf` | Best bypass payloads for a specific WAF |
| `analyze_scan_results` | Risk assessment from scan/test JSON |
| `generate_bypass_strategy` | Mutation strategies for blocked payloads |
| `explain_vulnerability` | Beginner-friendly payload explanation |
| `create_custom_payload` | Generate payloads from natural language |
| `ai_suggest_payloads` | Context-aware payload generation with WAF intel |
| `analyze_response` | False negative detection: soft blocks, challenges, reflection |
| `hardening_check` | Security headers audit with grade + rate-limit check |
| `owasp_misconfig_check` | OWASP A01/A02/A03/A05/A06/A07 checks |

[Claude Code guide →](docs/claude-code-guide.md) · [ChatGPT guide →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

---

## Project Structure

```
fray/
├── fray/
│   ├── cli.py              # CLI entry point (auto, scan, recon, bypass, harden, ...)
│   ├── scanner.py           # Auto scan: crawl → inject
│   ├── ai_bypass.py         # AI-assisted adaptive bypass engine
│   ├── bypass.py            # 5-phase WAF evasion scorer
│   ├── mutator.py           # 20-strategy payload mutation engine
│   ├── recon/               # 27-check reconnaissance pipeline
│   ├── detector.py          # WAF detection (25 vendors)
│   ├── tester.py            # Payload testing + adaptive throttle
│   ├── reporter.py          # HTML + Markdown reports
│   ├── mcp_server.py        # MCP server (14 tools)
│   └── payloads/            # 6,300+ payloads (24 categories)
├── tests/                   # 846 tests
├── docs/                    # 30 guides
├── mcp.json                 # MCP manifest
└── pyproject.toml           # pip install fray
```

---

## Roadmap

- [x] Full pipeline: `fray auto` (recon → scan → ai-bypass)
- [x] AI-assisted bypass with LLM integration (OpenAI/Anthropic)
- [x] 5-phase WAF evasion scorer with mutation feedback loop
- [x] OWASP hardening checks + security header audit
- [x] 20-strategy payload mutation engine
- [x] Auto scan: crawl → discover → inject (`fray scan`)
- [x] 27-check reconnaissance, smart mode, WAF detection
- [x] 14 MCP tools, HTML/Markdown reports, SARIF output
- [ ] HackerOne API integration (auto-submit findings)
- [ ] Web-based report dashboard

---

## How Fray Compares

| | Fray | Nuclei | XSStrike | wafw00f | sqlmap |
|-|------|--------|----------|---------|--------|
| **WAF bypass engine** | ✅ AI + mutation | ❌ | Partial | ❌ | Tamper scripts |
| **WAF detection** | 25 vendors + mode | Via templates | Basic | 150+ vendors | Basic |
| **Recon pipeline** | 27 checks | Separate tools | Crawl only | ❌ | ❌ |
| **Payload database** | 6,300+ built-in | Community templates | XSS only | ❌ | SQLi only |
| **OWASP hardening** | ✅ A-F grade | ❌ | ❌ | ❌ | ❌ |
| **MCP / AI agent** | 14 tools | ❌ | ❌ | ❌ | ❌ |
| **Zero dependencies** | ✅ stdlib only | Go binary | pip | pip | pip |

Fray is not a replacement for these tools — it fills the gap between WAF detection (wafw00f) and exploitation (sqlmap/XSStrike) with a complete **detect → recon → bypass → harden** workflow.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Legal

**MIT License** — See [LICENSE](LICENSE). Only test systems you own or have explicit authorization to test.

**Security issues:** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 All Documentation (30 guides)](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**

<!-- mcp-name: io.github.dalisecurity/fray -->
