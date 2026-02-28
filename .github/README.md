# WAF Payload Database

> 🛡️ Comprehensive WAF testing tool with 1,423+ security payloads for Claude Code, ChatGPT, and security professionals

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

## 🎯 AI Skill for Security Testing

This is an **AI-powered security testing skill** that enables:
- Automated WAF (Web Application Firewall) testing
- XSS, SQLi, SSRF, and other vulnerability testing
- Interactive CLI for easy use
- Comprehensive payload database (1,423+ payloads)

Perfect for use with **Claude Code**, **ChatGPT**, **Codex CLI**, and security automation workflows.

## ⚡ Quick Start

```bash
# Clone and run
git clone https://github.com/YOUR_USERNAME/waf-payload-database.git
cd waf-payload-database
python3 waf_tester.py -i
```

## 🚀 Features

- ✅ **Interactive Mode**: Guided testing for beginners
- ✅ **CLI Mode**: Automation-ready for experts
- ✅ **1,423+ Payloads**: Organized by attack type
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

- **XSS**: 631 payloads (basic, SVG, encoded, obfuscated, mutation, DOM-based, polyglot)
- **SQL Injection**: 13 payloads
- **SSRF**: 7 payloads
- **XXE**: 3 payloads
- **SSTI**: 8 payloads
- **Other**: 760+ payloads

## 🔒 Legal & Ethical Use

**IMPORTANT**: Only test systems you own or have explicit permission to test. See [LICENSE](LICENSE) for full legal disclaimer.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

**⭐ Star this repo if you find it useful!**

[View on SkillsLLM.com](https://skillsllm.com/skill/waf-payload-database) (coming soon)
