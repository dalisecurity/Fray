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
fray scan https://target.com           # Auto crawl → discover → inject
fray monitor https://target.com        # Continuous monitoring with alerts
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

**v3.5 — March 2026**
- **Dashboard live reload** — SSE file watcher, timeline view, side-by-side diff of any two runs
- **`fray init`** — scaffold `.fray.toml`, auth profile, and scope file in one command
- **`--dry-run`** — preview destructive commands before executing (`fray cache clear --dry-run`)
- **`--quiet` / `--summary`** — suppress educational output or get a quick overview
- **`fray help <cmd> --man`** — generate man pages from help text
- **Config validation** — warns about unknown keys in `.fray.toml` on startup
- **`fray doctor`** — checks core module imports and environment health

**v3.4 — March 2026**
- **GitHub Action** — test your WAF on every PR (`uses: dalisecurity/fray@v1`)
- **MCP Server** — Claude Code & ChatGPT integration (`pip install fray[mcp]`)
- **35-check recon** — TLS, CORS, VPN gateways, AI/LLM endpoints, cloud buckets, secrets
- **6 deep scan modules** — XSS, SQLi, CMDi, cache poisoning, mass assignment, deserialization
- **Interactive post-recon menu** — findings-driven next steps, not random payloads

**Coming up:** TLS fingerprint spoofing · YAML template DSL · race condition testing · NL queries
→ [Full changelog](CHANGELOG.md)

---

## Commands

Fray has 20 commands organized into 6 groups. Run `fray --help` or `fray help` for full details.

### Core — Security testing workflow

```bash
fray go <url>              # ★ Full assessment: recon → smart test → report
fray recon <url>           # Reconnaissance & fingerprinting (35+ checks)
fray test <url>            # Test WAF with payloads (-c xss --smart --blind)
fray scan <url>            # Auto crawl → discover → inject (--bounty)
fray monitor <url>         # Continuous monitoring with alerts
```

`fray <url>` is a shortcut for `fray go <url>` — just point and scan.

### Data — Reports & intelligence

```bash
fray report <sub>          # generate, company, waf, posture, diff, explain
fray intel <sub>           # feed, cve, poc-recheck, leak, osint, ct
fray auth <sub>            # session, solve, cred
fray export <sub>          # nuclei, ci
```

### Manage — Configuration & data

```bash
fray init                  # Scaffold .fray.toml + auth profile + scope file
fray config                # .fray.toml configuration
fray plugin                # Plugin system
fray cache                 # Payload cache & stats (--dry-run for clear)
fray update                # Update payload database
```

### Integrations

```bash
fray dashboard             # Web UI (live reload, timeline, diff)
fray mcp                   # AI assistant MCP server
fray completions           # Shell completions (bash/zsh/fish)
```

### Learn & help

```bash
fray ask <query>           # Natural language query
fray learn [topic]         # Interactive security tutorial
fray doctor [--fix]        # Check environment & core imports
fray help [cmd] [--man]    # Full command guide (or man page)
```

[Quick start →](docs/quickstart.md) · [Scan guide →](docs/scanning-guide.md)

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
