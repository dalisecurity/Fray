# Fray — WAF Bypass & Security Testing Toolkit

**🌐 Language:** **English** | [日本語](README.ja.md)

### ⚔️ *Open-source WAF bypass toolkit — recon, scan, bypass, harden. Zero dependencies.*

[![PyPI](https://img.shields.io/pypi/v/fray.svg)](https://pypi.org/project/fray/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dalisecurity/fray?style=social)](https://github.com/dalisecurity/fray/stargazers)

> **FOR AUTHORIZED SECURITY TESTING ONLY** — Only test systems you own or have explicit written permission to test.

Fray is the missing link between [wafw00f](https://github.com/EnableSecurity/wafw00f) (detection) and [sqlmap](https://github.com/sqlmapproject/sqlmap) (exploitation) — a complete **recon → bypass → harden** pipeline in one `pip install`.

---

## How Fray Compares

| | Fray | Nuclei | XSStrike | wafw00f | sqlmap |
|-|------|--------|----------|---------|--------|
| **WAF bypass engine** | ✅ AI + mutation | ❌ | Partial | ❌ | Tamper scripts |
| **WAF detection** | 25 vendors + mode | Via templates | Basic | 150+ vendors | Basic |
| **Recon pipeline** | 27 checks | Separate tools | Crawl only | ❌ | ❌ |
| **Payload database** | 2,900+ built-in | Community templates | XSS only | ❌ | SQLi only |
| **OWASP hardening** | ✅ A-F grade | ❌ | ❌ | ❌ | ❌ |
| **MCP / AI agent** | 14 tools | ❌ | ❌ | ❌ | ❌ |
| **Zero dependencies** | ✅ stdlib only | Go binary | pip | pip | pip |

Most payload collections are static text files. Fray is a complete **detect → recon → scan → bypass → harden** workflow in one `pip install`.

---

## Quick Start

```bash
pip install fray                # PyPI (all platforms)
sudo apt install fray            # Kali Linux / Debian
brew install fray                # macOS
```

```bash
fray auto https://example.com          # Full pipeline: recon → scan → bypass
fray scan https://example.com          # Auto crawl → inject → detect reflection
fray recon https://example.com         # 27-check reconnaissance
```

<p align="center">
  <img src="docs/demo.gif" alt="Fray demo — WAF detection and XSS bypass" width="720">
</p>

If Fray helped your recon workflow, please [⭐ star the repo](https://github.com/dalisecurity/fray) — it helps others find it.

---

## What Fray Does

| Command | What it does |
|---------|-------------|
| **`fray auto`** | Full pipeline: recon → scan → ai-bypass in one command |
| **`fray scan`** | Crawl → discover params → inject payloads → detect reflection |
| **`fray recon`** | 27 checks: TLS, DNS, subdomains, CORS, params, JS, API, admin panels, WAF intel |
| **`fray ai-bypass`** | Probe WAF → LLM generates payloads → test → mutate → header tricks |
| **`fray bypass`** | 5-phase WAF evasion scorer with mutation feedback loop |
| **`fray harden`** | Security headers (A-F grade) + OWASP Top 10 misconfig checks + fix snippets |
| **`fray detect`** | Fingerprint 25 WAF vendors (signature / anomaly / hybrid) |
| **`fray test`** | 2,900+ payloads across 23 categories with adaptive throttling |
| **`fray graph`** | Visual attack surface tree |

<p align="center">
  <img src="docs/screenshot-scan.png" alt="Fray scan — crawl, inject, detect XSS reflections" width="720">
</p>

**Built-in options:** `--scope` (scope enforcement) · `--stealth` (randomized UA, jitter) · `-w 4` (concurrent) · `--cookie` / `--bearer` (auth) · `--sarif` (GitHub Security tab) · `--json` · `--ai` (LLM output)

[Scan guide →](docs/scanning-guide.md) · [Recon guide →](docs/quickstart.md) · [Auth guide →](docs/authentication-guide.md) · [CI/CD guide →](docs/quickstart.md)

---

## MCP Server — AI Agent Integration

Fray exposes **14 tools** via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — use Fray as an AI security agent from Claude Desktop, Claude Code, ChatGPT, Cursor, or any MCP-compatible client.

```bash
pip install 'fray[mcp]'
```

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

Ask: *"What XSS payloads bypass Cloudflare?"* → Fray's 14 MCP tools are called directly.

[Claude Code guide →](docs/claude-code-guide.md) · [ChatGPT guide →](docs/chatgpt-guide.md) · [mcp.json →](mcp.json)

| Tool | What it does |
|------|-------------|
| `suggest_payloads_for_waf` | Best bypass payloads for a specific WAF |
| `generate_bypass_strategy` | Mutation strategies for blocked payloads |
| `search_payloads` | Full-text search across 2,900+ payloads |
| `analyze_response` | False negative detection: soft blocks, challenges |
| `hardening_check` | Security headers audit with grade + rate-limit check |

[See all 14 MCP tools →](docs/claude-code-guide.md)

---

## 2,900+ Payloads · 23 Categories · 175 CVEs

The largest open-source WAF payload database — curated for real-world penetration testing and bug bounty hunting.

| Category | Count | Category | Count |
|----------|-------|----------|-------|
| XSS (Cross-Site Scripting) | 989 | SSRF | 72 |
| SQL Injection | 148 | SSTI | 62 |
| Command Injection (RCE) | 125 | XXE | 34 |
| AI/LLM Prompt Injection | 370 | Path Traversal (LFI/RFI) | 59 |
| Modern Bypasses | 137 | CSP Bypass | 64 |
| API Security | 80 | Prototype Pollution | 75 |

[Payload database →](docs/payload-database-coverage.md) · [CVE coverage →](docs/cve-real-world-bypasses.md)

---

## Advanced Usage

```bash
fray graph example.com --deep       # Visual attack surface tree (27 checks)
fray ai-bypass target.com -c xss    # AI-assisted adaptive bypass (LLM or local)
fray harden target.com              # OWASP hardening audit (A-F grade + fix snippets)
fray explain log4shell              # CVE intelligence with payloads
fray diff before.json after.json    # Regression testing (exit 1 on bypass)
fray report results.json --html     # Client-ready HTML report
```

<p align="center">
  <img src="docs/screenshot-graph.png" alt="Fray graph — visual attack surface tree" width="720">
</p>

[WAF detection guide →](docs/waf-detection-guide.md) · [All documentation (30 guides) →](docs/)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For AI coding agents, see [AGENTS.md](AGENTS.md).

Questions? [Open a Discussion](https://github.com/dalisecurity/fray/discussions) or [browse the docs](docs/).

## Legal

**MIT License** — See [LICENSE](LICENSE). Only test systems you own or have explicit authorization to test.

**Security issues:** soc@dalisec.io · [SECURITY.md](SECURITY.md)

---

**[📖 Docs](docs/) · [Roadmap](docs/roadmap.md) · [PyPI](https://pypi.org/project/fray/) · [Issues](https://github.com/dalisecurity/fray/issues) · [Discussions](https://github.com/dalisecurity/fray/discussions)**

## Related Projects

- [wafw00f](https://github.com/EnableSecurity/wafw00f) — WAF fingerprinting and detection (150+ vendors)
- [WhatWaf](https://github.com/Ekultek/WhatWaf) — WAF detection and bypass tool
- [XSStrike](https://github.com/s0md3v/XSStrike) — Advanced XSS scanner with WAF evasion
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQL injection detection and exploitation
- [Nuclei](https://github.com/projectdiscovery/nuclei) — Template-based vulnerability scanner
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Web security payloads and bypasses
- [SecLists](https://github.com/danielmiessler/SecLists) — Security assessment wordlists
- [Awesome WAF](https://github.com/0xInfection/Awesome-WAF) — Curated list of WAF tools and bypasses

<!-- mcp-name: io.github.dalisecurity/fray -->
