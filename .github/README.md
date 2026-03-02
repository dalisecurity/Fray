# SecurityForge

### ⚔️ *Open-source WAF security testing — 4,000+ payloads, 25 WAF detections, structured for AI workflows*

**The open-source offensive security toolkit** • 4,025+ Payloads • 25 WAF Fingerprints • Zero-Config • AI-Compatible

[![Total Payloads](https://img.shields.io/badge/Total_Payloads-4025+-brightgreen.svg?style=for-the-badge)](https://github.com/dalisecurity/securityforge)
[![OWASP Coverage](https://img.shields.io/badge/OWASP_Coverage-100%25-success.svg?style=for-the-badge&logo=owasp)](https://github.com/dalisecurity/securityforge)
[![WAF Detection](https://img.shields.io/badge/WAF_Vendors-25+-blue.svg?style=for-the-badge&logo=cloudflare)](https://github.com/dalisecurity/securityforge)
[![AI Powered](https://img.shields.io/badge/AI_Powered-Claude_+_ChatGPT-purple.svg?style=for-the-badge&logo=openai)](https://github.com/dalisecurity/securityforge)

[![PyPI](https://img.shields.io/pypi/v/securityforge.svg)](https://pypi.org/project/securityforge/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## ⚡ Why SecurityForge?

Most payload collections are just static text files. **SecurityForge is different** — it's a structured toolkit that lets you **detect, test, and report** in seconds:

- 🤖 **AI-compatible** — structured JSON payloads work well with Claude Code & ChatGPT
- 🔍 **Auto-detect which WAF** you're facing — 25 vendors fingerprinted instantly
- 📊 **One-command reports** — professional HTML output with vuln analysis
- 🎯 **4,025+ battle-tested payloads** — XSS, SQLi, SSRF, SSTI, LLM jailbreaks, and more
- ⚡ **Zero config** — `pip install securityforge` and you're testing

### 🔥 Built For

- **Bug bounty hunters** — ready-made payloads from real-world disclosures + 120 CVEs
- **Red teamers & pentesters** — WAF detection → payload selection → report, all in one tool
- **Security researchers** — structured payloads for bypass research and analysis
- **Blue teams** — validate your WAF config against 4,000+ real attack patterns
- **Students** — learn offensive security with guided AI workflows

### �️ WAF Vendor Detection — 25 Vendors Supported

SecurityForge detects and fingerprints **25 major WAF vendors** using header analysis, cookie inspection, response patterns, and error signatures.

| # | WAF Vendor | Detection Method | Key Signatures |
|---|-----------|-----------------|----------------|
| 1 | **Cloudflare** | Headers, Cookies, Error Page | `cf-ray`, `__cfduid`, Ray ID pattern |
| 2 | **Akamai** | Headers, Cookies, Bot Manager | `akamai-grn`, `ak_bmsc`, Reference # |
| 3 | **AWS WAF** | Headers, Cookies, Response Body | `x-amzn-waf-action`, `awsalb`, CloudFront |
| 4 | **Imperva (Incapsula)** | Headers, Cookies, Challenge | `x-iinfo`, `incap_ses`, Incident ID |
| 5 | **F5 BIG-IP** | Headers, Cookies, Error Page | `x-wa-info`, `bigipserver`, Support ID |
| 6 | **Fastly (Signal Sciences)** | Headers, Cookies, Server | `x-sigsci-requestid`, `x-served-by` |
| 7 | **Microsoft Azure WAF** | Headers, Cookies, Front Door | `x-azure-fdid`, `x-azure-ref`, `arr_affinity` |
| 8 | **Google Cloud Armor** | Headers, Server, reCAPTCHA | `x-cloud-trace-context`, `gfe`, Cloud Armor |
| 9 | **Barracuda** | Headers, Cookies, Server | `x-barracuda-url`, `barra_counter_session` |
| 10 | **Citrix NetScaler** | Headers, Cookies, Server | `citrix-transactionid`, `nsc_`, NetScaler |
| 11 | **Radware** | Headers, Response Text | `x-protected-by`, AppWall |
| 12 | **Palo Alto (Prisma Cloud)** | Headers, Response Text | `x-pan-`, `x-prisma` |
| 13 | **Check Point** | Headers, Response Text | `x-checkpoint`, Check Point |
| 14 | **Trustwave (ModSecurity)** | Headers, Server, Response | `x-mod-security`, ModSecurity |
| 15 | **Qualys WAF** | Headers, Response Text | `x-qualys` |
| 16 | **Penta Security (WAPPLES)** | Headers, Cookies | `x-wapples`, `wapples` |
| 17 | **StackPath** | Headers, Server | `x-stackpath-shield`, StackPath |
| 18 | **Sophos** | Headers, Response Text | `x-sophos`, UTM |
| 19 | **Scutum** | Headers, Response Text | `x-scutum` |
| 20 | **Rohde & Schwarz** | Headers, Response Text | `x-rs-` |
| 21 | **Sucuri** | Headers, Cookies, Server | `x-sucuri-id`, `sucuri_cloudproxy_uuid` |
| 22 | **Fortinet FortiWeb** | Headers, Cookies, Server | `x-fortiweb`, `fortiwafsid` |
| 23 | **Wallarm** | Headers, Server | `x-wallarm-waf-check`, `nginx-wallarm` |
| 24 | **Reblaze** | Headers, Cookies, Server | `x-reblaze-protection`, `rbzid` |
| 25 | **Vercel** | Headers, Server | `x-vercel-id`, `x-vercel-cache` |

## ⚡ Quick Start

```bash
# Install from PyPI
pip install securityforge

# Detect WAF vendor
securityforge detect https://example.com

# Test with XSS payloads
securityforge test https://example.com -c xss --max 10

# List all payload categories
securityforge payloads

# Or clone and use directly
git clone https://github.com/dalisecurity/securityforge.git
cd securityforge
python3 waf_tester.py -i
```

## 📚 Documentation

- [Quick Start Guide](docs/quickstart.md)
- [Full Documentation](README.md)
- [Docker Usage](docs/docker.md)
- [OWASP Coverage](docs/owasp-complete-coverage.md)

## 🤖 MCP Server — AI Integration

SecurityForge includes an MCP server that AI assistants can call directly:

```bash
pip install securityforge[mcp]
securityforge mcp
```

**6 MCP tools:** `list_payload_categories`, `get_payloads`, `search_payloads`, `get_waf_signatures`, `get_cve_details`, `suggest_payloads_for_waf`

Configure Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "securityforge": {
      "command": "python",
      "args": ["-m", "securityforge.mcp_server"]
    }
  }
}
```

### CLI
```bash
securityforge detect https://example.com
securityforge test https://example.com -c xss --max 10
securityforge payloads
```

## 📊 Complete OWASP Coverage

**4,025+ total payloads across 40+ categories:**

### OWASP Top 10:2021 (Web) - 1,690+ Payloads
- A01: Broken Access Control (150+)
- A02: Cryptographic Failures (50+)
- A03: Injection (500+ - XSS, SQLi, XXE, SSTI, Command Injection)
- A04: Insecure Design (80+)
- A05: Security Misconfiguration (100+)
- A06: Vulnerable Components (450+ - WordPress CVEs)
- A07: Authentication Failures (200+)
- A08: Software/Data Integrity (70+)
- A09: Logging/Monitoring (30+)
- A10: SSRF (60+)

### OWASP Mobile Top 10:2024 - 575+ Payloads
- M1-M10: Complete mobile security coverage (Android & iOS)

### OWASP LLM Top 10 - 300+ Payloads
- LLM01: Prompt Injection (100+)
- LLM02-LLM10: AI/ML security testing

### OWASP API Security Top 10 - 520+ Payloads
- API1-API10: Complete API security coverage (REST, GraphQL, SOAP)

### WordPress Security - 450+ Payloads
- REST API auth bypass & user enumeration (150+)
- File upload bypass & web shell detection (200+)
- XML-RPC amplification & brute force (100+)

### Additional Attack Vectors - 490+ Payloads
- XSS, SQLi, SSRF, Path Traversal, LDAP, XPath, CRLF, and more

See [docs/owasp-complete-coverage.md](docs/owasp-complete-coverage.md) for detailed breakdown.

## 🔒 Legal & Ethical Use

**IMPORTANT**: Only test systems you own or have explicit permission to test. See [LICENSE](LICENSE) for full legal disclaimer.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

**⭐ Star this repo if you find it useful!**

📚 **Documentation**: [docs/](docs/) | [PyPI](https://pypi.org/project/securityforge/) | [Blog](https://dalisec.io/research/blog-securityforge-launch.html)
