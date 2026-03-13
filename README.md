<div align="center">

# Fray

### Vibe security — just point and scan.

Open-source security testing that figures out the rest.<br>
One command. Full pipeline. Zero config.

```
pip install fray && fray go target.com
```

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Downloads](https://img.shields.io/pypi/dm/fray?color=6366f1)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Payloads](https://img.shields.io/badge/Payloads-5%2C600+-red)](docs/payload-database-coverage.md)
[![WAFs](https://img.shields.io/badge/WAFs-98_vendors-orange)](docs/quickstart.md)
[![Checks](https://img.shields.io/badge/Recon-35%2B_checks-green)](docs/quickstart.md)
[![VS Code](https://img.shields.io/visual-studio-marketplace/v/DaliSecurity.fray-security?label=VS%20Code&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

**[Documentation](https://dalisec.io/docs/)** · **[Quick Start](#quick-start)** · **[Discussions](https://github.com/dalisecurity/fray/discussions)** · **[dalisec.io](https://dalisec.io/fray/)**

**🌐** **English** | [日本語](README.ja.md)

</div>

---

> **FOR AUTHORIZED SECURITY TESTING ONLY** — Only test systems you own or have explicit written permission to test.

<p align="center">
  <img src="docs/demo.gif" alt="fray go — full security audit in one command" width="720">
</p>

## Why Vibe Security?

Security testing used to mean installing five tools, learning each one's flags, writing config files, and manually correlating results. That's not how it should work.

**Vibe security is the idea that security testing should be as easy as vibe coding made development** — describe what you want, and the tool handles the rest. Fray embodies this:

- **One command does everything** — `fray go` runs recon, finds vulnerabilities, tests them, and generates a report. Zero config.
- **You don't need to be a security expert** — Fray picks the right checks and payloads based on what it discovers about your target.
- **AI-native** — built-in MCP server for Claude, ChatGPT, and Cursor. Ask questions in natural language, get security answers.
- **Smart, not noisy** — adaptive cache learns across scans. Blocked payloads are never re-sent. Each run gets smarter.

### Before Fray vs. With Fray

| Traditional Security Testing | Vibe Security with Fray |
|---|---|
| Install 5+ tools (nmap, wafw00f, sqlmap, nikto, nuclei) | `pip install fray` |
| Learn each tool's flags and config formats | `fray go target.com` |
| Manually correlate findings across tools | Automatic pipeline: recon → test → report |
| Write custom scripts to chain tools together | Built-in: 35 checks, 6 deep scan modules, 5,600+ payloads |
| Read hundreds of pages of documentation | Zero config — smart defaults, interactive menus |
| Security expertise required | Built for anyone who ships web apps |

---

## Quick Start

```bash
pip install fray
```

**The only command you need:**

```bash
fray go https://target.com        # Full pipeline: recon → vuln test → report
```

That's it. Fray scans your target, identifies the tech stack and WAF, finds vulnerabilities, tests them, and generates an HTML report — all automatically.

**Want more control?** Use individual commands:

```bash
fray recon https://target.com          # 35-check reconnaissance
fray test https://target.com --smart   # Smart payload selection from recon findings
fray detect https://target.com         # Fingerprint WAF/CDN vendor (98 vendors)
fray fuzz https://target.com/FUZZ      # Content discovery (ffuf-like)
fray harden https://target.com         # OWASP hardening audit (A-F grade)
```

---

## Who is Fray for?

- **Developers & founders** — shipping a web app? Run `fray go` before launch. Done.
- **Bug bounty hunters** — 5,600+ payloads, WAF bypass intelligence, adaptive learning.
- **Pentesters** — full recon pipeline, 6 deep scan modules, stealth mode, auth support.
- **DevSecOps** — GitHub Action, CI/CD integration, SARIF output, `--json` for pipelines.
- **Security teams** — MCP server for AI agents, VS Code extension, batch scanning.

---

## What's New

**v3.4 — March 2026**
- **GitHub Action** — test your WAF on every PR (`uses: dalisecurity/fray@v1`)
- **MCP Server** — Claude Code & ChatGPT integration (`pip install fray[mcp]`)
- **35-check recon** — TLS, CORS, VPN gateways, AI/LLM endpoints, cloud buckets, secrets
- **6 deep scan modules** — XSS, SQLi, CMDi, cache poisoning, mass assignment, deserialization
- **Interactive post-recon menu** — findings-driven next steps, not random payloads

**Coming up:** Race condition testing · WAF rule reverse engineering · batch recon · NL queries
→ [Full changelog](CHANGELOG.md)

---

## Core Commands

### `fray go` — Full Pipeline

The hero command. Runs everything automatically: reconnaissance → vulnerability testing → report generation.

```bash
fray go https://target.com              # Automatic full pipeline
fray go https://target.com --deep       # Deep mode with subdomain brute-force
fray go https://target.com --stealth    # Rate-limited, randomized UA
```

### `fray recon` — Reconnaissance

35+ checks in one command: TLS, DNS, subdomains, CORS, security headers, admin panels, VPN gateways, AI/LLM endpoints, cloud buckets, secrets, JS endpoint extraction, and more. Outputs JSON, HTML report, or interactive menu.

```bash
fray recon https://target.com --deep   # Full depth with subdomain brute-force
```

### `fray test --smart` — Vulnerability Testing

Reads recon findings and selects the right payloads automatically. Six deep modules: `XSSScanner`, `SQLiInjector`, `CMDiScanner`, `CachePoisonScanner`, `MassAssignScanner`, `DeserScanner`.

```bash
fray test https://target.com --smart -c xss   # Context-aware XSS testing
```

### `fray detect` — WAF Fingerprinting

Identifies 98 WAF/CDN vendors via headers, CNAME records, cookies, and response signatures.

```bash
fray detect https://target.com --json
```

### `fray report` — Reporting

Generate HTML or Markdown reports from scan results. Unified v11 dark theme across all report types.

```bash
fray report --company example.com -o report.md
```

[All commands →](docs/quickstart.md) · [Scan guide →](docs/scanning-guide.md)

---

## Auth & Stealth

```bash
fray test https://target.com --cookie "session=abc123"     # Cookie auth
fray test https://target.com --bearer eyJhbG...             # Bearer token
fray test https://target.com --stealth -d 0.5               # Randomized UA + jitter
fray recon https://target.com --scope scope.txt             # In-scope enforcement
```

Session profiles, OAuth2 client credentials, and multi-step form login are supported. [Auth guide →](docs/authentication-guide.md)

---

## CI/CD

```yaml
# .github/workflows/waf.yml
- uses: dalisecurity/fray@v1
  with:
    target: https://staging.example.com
    categories: xss,sqli
```

Fray exits non-zero on bypass findings, integrates with GitHub Security tab via SARIF, and supports `--json` for pipeline consumption. [CI/CD guide →](docs/github-action-guide.md)

---

## Payload Coverage

5,600+ payloads across 24 categories, 175 CVEs (2020-2026):

| Category | Count | Category | Count |
|----------|-------|----------|-------|
| Web Shells | 944 | AI/LLM Prompt Injection | 370 |
| WordPress | 914 | Path Traversal | 241 |
| XSS | 807 | SSTI | 166 |
| LLM Testing | 650 | SQL Injection | 141 |
| Modern Bypasses | 137 | XXE | 127 |
| Command Injection | 118 | SSRF | 71 |

[Full payload database →](docs/payload-database-coverage.md) · [CVE coverage →](docs/cve-real-world-bypasses.md)

---

## MCP Server — AI Agent Integration

Fray exposes 14 tools via [MCP](https://modelcontextprotocol.io/) for Claude, ChatGPT, Cursor, and other AI clients.

```bash
pip install 'fray[mcp]'
```

```json
{ "mcpServers": { "fray": { "command": "python", "args": ["-m", "fray.mcp_server"] } } }
```

Ask *"What XSS payloads bypass Cloudflare?"* and Fray's tools (`suggest_payloads_for_waf`, `generate_bypass_strategy`, `search_payloads`, `analyze_response`, `hardening_check`, [+9 more](docs/claude-code-guide.md)) are called directly.

[Claude Code guide →](docs/claude-code-guide.md) · [ChatGPT guide →](docs/chatgpt-guide.md)

---

## VS Code Extension

[![Install](https://img.shields.io/badge/Install-VS%20Code%20Marketplace-007ACC?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)

11 commands, right-click scan, inline diagnostics, HTML report panel (`Cmd+Shift+R`), activity bar sidebar. [Extension docs →](vscode-fray/README.md)

---

## Built with Fray

Real-world security research powered by Fray:

- **[Nikkei 225 DNS Security Audit](https://dalisec.io/research/blog-nikkei225-dns-audit.html)** — DNS infrastructure analysis of all 225 companies in Japan's premier stock index
- **[Nikkei 225 Recon](https://dalisec.io/research/blog-nikkei225-recon.html)** — Attack surface reconnaissance across Japan's largest enterprises
- **[HackerOne Disclosed Vulnerabilities](https://dalisec.io/research/)** — Subdomain takeovers at Takeda, Toyota, NEC, ROHM, and Recruit

---

## Community

**Have a question? Found a bug? Want to contribute?**

- **[Discussions](https://github.com/dalisecurity/fray/discussions)** — ask questions, share ideas, show what you built
- **[Issues](https://github.com/dalisecurity/fray/issues)** — bug reports and feature requests
- **[Contributing](CONTRIBUTING.md)** — PRs welcome. For AI coding agents, see [AGENTS.md](AGENTS.md)

---

## Legal

**MIT License** — See [LICENSE](LICENSE). Only test systems you own or have explicit authorization to test.

**Security issues:** soc@dalisec.io · [SECURITY.md](SECURITY.md)

<div align="center">

**[dalisec.io](https://dalisec.io/)** · Built by hunters. For defenders.

</div>

<!-- mcp-name: io.github.dalisecurity/fray -->
