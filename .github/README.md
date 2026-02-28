# WAF Payload Arsenal

> 🛡️ Your arsenal for WAF security testing - 2,155+ comprehensive payloads for Claude Code, ChatGPT, and security professionals

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 🎯 AI Skill for Security Testing

This is an **AI-powered security testing skill** that enables:
- Automated WAF (Web Application Firewall) testing
- XSS, SQLi, SSRF, and other vulnerability testing
- Interactive CLI for easy use
- Comprehensive payload database (2,155+ payloads)

Perfect for use with **Claude Code**, **ChatGPT**, **Codex CLI**, and security automation workflows.

## ⚡ Quick Start

```bash
# Clone and run
git clone https://github.com/dalisecurity/waf-payload-arsenal.git
cd waf-payload-arsenal
python3 waf_tester.py -i
```

## 🚀 Features

- ✅ **Interactive Mode**: Guided testing for beginners
- ✅ **CLI Mode**: Automation-ready for experts
- ✅ **2,155 Payloads**: Organized by 12 attack types
- ✅ **No Dependencies**: Pure Python standard library
- ✅ **Docker Support**: Portable containerized testing
- ✅ **JSON Reports**: Detailed, shareable results
- ✅ **Team Collaboration**: Easy to share and contribute

## 📚 Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Full Documentation](README.md)
- [Docker Usage](DOCKER.md)
- [Team Sharing](SHARE_WITH_TEAM.md)

## 🤖 Use with AI Assistants

### Claude Code
```
Use the WAF Payload Database to test our staging environment
```

### ChatGPT
```
Run WAF tests using the payload database against https://example.com
```

### Codex CLI
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json
```

## 📊 Payload Categories

**2,155 total payloads across 12 attack types:**

### XSS (681 payloads - 31.6%)
- Basic, SVG-based, Advanced, Event Handlers
- DOM-based, Encoded, Obfuscated, Mutation, Polyglot

### SQL Injection (148 payloads - 6.9%)
- PostgreSQL, MySQL, MSSQL, Oracle, SQLite, NoSQL
- Union, Boolean, Time-based, Error-based, Stacked queries

### Command Injection (125 payloads - 5.8%)
- Reverse shells (Bash, Netcat, Python, Perl, Ruby, PHP, PowerShell)
- Encoding bypass, Time-based detection

### SSRF (72 payloads - 3.3%)
- Cloud metadata (AWS, GCP, Azure), Protocol smuggling
- DNS rebinding, IPv6, Port scanning

### SSTI (62 payloads - 2.9%)
- Jinja2, Twig, Freemarker, Velocity
- RCE techniques, Sandbox escape

### Path Traversal (59 payloads - 2.7%)
### LDAP Injection (55 payloads - 2.6%)
### XPath Injection (54 payloads - 2.5%)
### CRLF Injection (54 payloads - 2.5%)
### Open Redirect (51 payloads - 2.4%)
### XXE (34 payloads - 1.6%)
### Other/Mixed (760 payloads - 35.3%)

See [PAYLOAD_CLASSIFICATION.md](PAYLOAD_CLASSIFICATION.md) for detailed breakdown.

## 🔒 Legal & Ethical Use

**IMPORTANT**: Only test systems you own or have explicit permission to test. See [LICENSE](LICENSE) for full legal disclaimer.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

**⭐ Star this repo if you find it useful!**

[View on SkillsLLM.com](https://skillsllm.com/skill/waf-payload-arsenal) (coming soon)
