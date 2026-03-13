# Fray — WAF Bypass & Security Testing Toolkit

**🌐 Language:** **English** | [日本語](README.ja.md)

### ⚔️ *Open-source WAF bypass toolkit — recon, scan, bypass, harden. Zero dependencies.*

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/DaliSecurity.fray-security?label=VS%20Code&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=DaliSecurity.fray-security)
[![Docs](https://img.shields.io/badge/Docs-dalisec.io-6366f1)](https://dalisec.io/docs/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> **FOR AUTHORIZED SECURITY TESTING ONLY** — Only test systems you own or have explicit written permission to test.

Fray is the missing link between [wafw00f](https://github.com/EnableSecurity/wafw00f) (detection) and [sqlmap](https://github.com/sqlmapproject/sqlmap) (exploitation) — a complete **recon → bypass → harden** pipeline in one `pip install`.

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

## Why Fray?

- **All-in-one** — recon, scan, bypass, harden, fuzz, and report in a single tool
- **Smart, not noisy** — adaptive cache learns across domains; blocked payloads are never re-sent
- **Zero dependencies** — pure Python stdlib; `pip install fray` and go
- **4,000+ payloads** — 23 categories, 175 CVEs, continuously updated from live threat feeds

---

## Quick Start

```bash
pip install fray
```

```bash
fray recon https://target.com          # 35-check reconnaissance
fray test https://target.com --smart   # Smart payload selection from recon findings
fray detect https://target.com         # Fingerprint WAF/CDN vendor (98 vendors)
fray auto https://target.com           # Full pipeline: recon → scan → bypass
fray fuzz https://target.com/FUZZ      # Content discovery (ffuf-like)
fray harden https://target.com         # OWASP hardening audit (A-F grade)
```

<p align="center">
  <img src="docs/demo.gif" alt="Fray demo — WAF detection and XSS bypass" width="720">
</p>

---

## Core Commands

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

4,000+ payloads across 23 categories, 175 CVEs (2020-2026):

| Category | Count | Category | Count |
|----------|-------|----------|-------|
| XSS | 1,209 | SSRF | 122 |
| SQL Injection | 248 | SSTI | 122 |
| Command Injection | 200 | XXE | 84 |
| AI/LLM Prompt Injection | 370 | Path Traversal | 109 |
| Modern Bypasses | 137 | CSP Bypass | 104 |
| API Security | 130 | Prototype Pollution | 110 |

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

## Docs & Links

**[📖 Documentation](docs/)** · **[Quickstart](docs/quickstart.md)** · **[PyPI](https://pypi.org/project/fray/)** · **[Issues](https://github.com/dalisecurity/fray/issues)** · **[Discussions](https://github.com/dalisecurity/fray/discussions)**

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For AI coding agents, see [AGENTS.md](AGENTS.md).

## Legal

**MIT License** — See [LICENSE](LICENSE). Only test systems you own or have explicit authorization to test.

**Security issues:** soc@dalisec.io · [SECURITY.md](SECURITY.md)

<!-- mcp-name: io.github.dalisecurity/fray -->
