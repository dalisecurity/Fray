# WAF Payload Arsenal

> ⚠️ **FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**  
> This tool is designed for security professionals, researchers, and students to learn about WAF bypass techniques and test systems they own or have explicit permission to test. Unauthorized testing is illegal.

**Your arsenal for WAF security testing** - A comprehensive collection of **2,155 Web Application Firewall (WAF) bypass payloads** tested against Cloudflare WAF, organized by attack type and technique. Extracted and classified from 24,700+ original test cases.

## 📊 Project Overview

This repository contains the results of extensive WAF testing conducted over 100 rounds, systematically testing various attack vectors, encoding methods, and bypass techniques. All payloads were tested against a Cloudflare-protected endpoint to document WAF detection capabilities.

### Statistics

- **Total Payloads**: 2,155 (organized and classified)
- **Attack Types**: 12 categories
- **Testing Rounds**: 100
- **Original Tests**: 24,705 payloads
- **Block Rate**: 99.9%
- **Bypasses Found**: 0 (demonstrating WAF effectiveness)

## 🎯 Purpose

This database serves multiple purposes:

1. **Security Research**: Comprehensive payload collection for WAF testing
2. **Educational Resource**: Learn about various attack vectors and bypass techniques
3. **WAF Benchmarking**: Test and validate WAF effectiveness
4. **Penetration Testing**: Reference for security assessments
5. **Defense Development**: Help security teams understand attack patterns

## � Why WAF Payload Arsenal?

### The First Purpose-Built WAF Testing Tool

Unlike general payload collections (SecLists, PayloadsAllTheThings) or complex security frameworks (OWASP ZAP, Metasploit), WAF Payload Arsenal is **100% focused on WAF bypass testing**.

| Feature | WAF Arsenal | SecLists | PayloadsAll | OWASP ZAP | Metasploit |
|---------|-------------|----------|-------------|-----------|------------|
| **WAF-Specific** | ✅ 100% | ⚠️ ~10% | ⚠️ ~15% | ⚠️ Partial | ❌ No |
| **Interactive CLI** | ✅ Yes | ❌ Files only | ❌ Wiki | ⚠️ GUI | ⚠️ Complex |
| **Setup Time** | ✅ 30 sec | ⚠️ 5 min | ⚠️ Manual | ❌ 10+ min | ❌ 15+ min |
| **AI Compatible** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| **Team Ready** | ✅ Docker | ⚠️ Manual | ⚠️ Manual | ❌ Complex | ❌ Complex |

### 🚀 Key Advantages

1. **⚡ Fast**: Start testing in 30 seconds with interactive mode
2. **🎯 Focused**: 2,155 payloads specifically for WAF testing (not buried in 10,000+ files)
3. **🤖 AI-Native**: First tool built for Claude Code, ChatGPT, and AI-augmented workflows
4. **📦 Team-Ready**: Docker support + documentation = easy sharing
5. **📊 Organized**: 12 clear categories vs scattered files or wiki pages
6. **🎓 Educational**: Built for learning, not exploitation

**Perfect for:** Bug bounty hunters, penetration testers, security researchers, and teams who need **focused WAF testing** without the complexity of enterprise tools.

See [VALUE_PROPOSITION.md](VALUE_PROPOSITION.md) for detailed comparison.

## �📁 Repository Structure

```
waf-payload-database/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── CONTRIBUTING.md                    # Contribution guidelines
├── payloads/
│   ├── xss/                          # XSS payloads
│   │   ├── basic.json                # Basic XSS vectors
│   │   ├── encoded.json              # Encoded XSS payloads
│   │   ├── obfuscated.json           # Obfuscated XSS
│   │   ├── polyglot.json             # Polyglot XSS
│   │   ├── mutation.json             # Mutation XSS (mXSS)
│   │   ├── dom-based.json            # DOM-based XSS
│   │   ├── svg-based.json            # SVG XSS vectors
│   │   ├── event-handlers.json       # Event handler XSS
│   │   └── advanced.json             # Advanced techniques
│   ├── sqli/                         # SQL Injection
│   │   ├── basic.json
│   │   ├── blind.json
│   │   ├── time-based.json
│   │   └── error-based.json
│   ├── command-injection/            # Command Injection
│   ├── ssrf/                         # Server-Side Request Forgery
│   ├── xxe/                          # XML External Entity
│   ├── path-traversal/               # Path Traversal
│   ├── ssti/                         # Server-Side Template Injection
│   ├── open-redirect/                # Open Redirect
│   ├── encoding/                     # Various encoding techniques
│   └── research/                     # Research-based payloads
├── tools/
│   ├── payload_tester.py             # Automated payload testing tool
│   ├── classifier.py                 # Payload classification tool
│   └── analyzer.py                   # Results analysis tool
├── docs/
│   ├── methodology.md                # Testing methodology
│   ├── analysis.md                   # Detailed analysis
│   ├── techniques.md                 # Bypass techniques explained
│   └── results.md                    # Complete test results
└── scripts/
    └── extract_payloads.py           # Extract payloads from test files
```

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/waf-payload-arsenal.git
cd waf-payload-arsenal
pip install -r requirements.txt
```

### Usage

#### Load Payloads

```python
import json

# Load XSS payloads
with open('payloads/xss/basic.json', 'r') as f:
    xss_payloads = json.load(f)

for payload in xss_payloads:
    print(f"Category: {payload['category']}")
    print(f"Payload: {payload['payload']}")
    print(f"Description: {payload['description']}")
```

#### Test Against Your WAF

```python
from tools.payload_tester import WAFTester

tester = WAFTester(target_url="https://your-target.com")
results = tester.test_payloads('payloads/xss/basic.json')
tester.generate_report(results)
```

## 📚 Payload Categories

### 1. Cross-Site Scripting (XSS) - 681 payloads (31.6%)

- **Basic XSS** (412): Standard script tags and event handlers
- **SVG-based XSS** (175): SVG onload, animation, namespace abuse
- **Advanced XSS** (15): ES6+, WebAssembly, Service Workers
- **Event Handlers** (35): Rare events (onbounce, media events)
- **DOM-based XSS** (24): Client-side manipulation
- **Encoded XSS** (12): URL, HTML entity, Unicode encoding
- **Obfuscated XSS** (3): Case variation, whitespace, comments
- **Mutation XSS** (4): Browser parsing mutations
- **Polyglot XSS** (1): Multi-context payloads

### 2. SQL Injection - 148 payloads (6.9%)

- **Comprehensive SQLi** (120): Union, Boolean, Time-based, Error-based, Stacked queries
- **Database-specific**: PostgreSQL, MySQL, MSSQL, Oracle, SQLite
- **NoSQL injection**: MongoDB, CouchDB
- Blind SQLi, Out-of-band exfiltration

### 3. Command Injection - 125 payloads (5.8%)

- **Comprehensive** (115): Reverse shells, Command substitution, Encoding bypass
- **Shells**: Bash, Netcat, Python, Perl, Ruby, PHP, PowerShell
- **Time-based detection**: Sleep, Ping, Timeout
- **File operations**: Cat, Ls, Find, Grep

### 4. Server-Side Request Forgery (SSRF) - 72 payloads (3.3%)

- **Cloud metadata**: AWS, GCP, Azure (multiple endpoints)
- **Protocol smuggling**: Gopher, Dict, FTP, TFTP
- **DNS rebinding**, IPv6, IP encoding (decimal, hex, octal)
- **Port scanning**: Common ports (80, 443, 8080, 3306, 6379, 27017)

### 5. Server-Side Template Injection (SSTI) - 62 payloads (2.9%)

- **Jinja2/Flask**: Config access, RCE, Sandbox escape
- **Twig**: Filter callback exploitation
- **Freemarker**: Execute utility, Classloader
- **Velocity**: Runtime exploitation

### 6. Path Traversal - 59 payloads (2.7%)

- **Encoding variations**: Unicode, UTF-8, Double URL encoding
- **Multiple depths**: 1-10 levels deep
- **Target files**: /etc/passwd, /etc/shadow, Windows config files
- **Null byte bypass**, Zip slip

### 7. LDAP Injection - 55 payloads (2.6%)

- **Wildcard injection**: *, *)(uid=*
- **Boolean bypass**: AND, OR, NOT operators
- **Authentication bypass**: Multiple username variations

### 8. XPath Injection - 54 payloads (2.5%)

- **Boolean bypass**: OR/AND conditions
- **Function exploitation**: name(), substring(), string-length()
- **Data extraction**: Multiple value testing

### 9. CRLF Injection - 54 payloads (2.5%)

- **Header injection**: Set-Cookie, Location, Content-Type
- **Encoding variations**: %0d%0a, %0a, \r\n
- **Response splitting**: Double CRLF for XSS

### 10. Open Redirect - 51 payloads (2.4%)

- **Protocol variations**: http://, https://, //, javascript:
- **Multiple domains**: evil.com, attacker.com, phishing.com
- **@ symbol bypass**: example.com@evil.com

### 11. XML External Entity (XXE) - 34 payloads (1.6%)

- **File disclosure**: Multiple system files
- **SSRF via XXE**: Internal network access
- **Parameter entities**: OOB data exfiltration
- **PHP wrappers**: Base64 encoding, Expect wrapper

### 12. Other/Mixed - 760 payloads (35.3%)

- Experimental payloads
- Multi-vector attacks
- Fuzzing patterns
- Edge cases

## 🔬 Testing Methodology

Our testing approach:

1. **Systematic Coverage**: 100 rounds of testing across all major attack vectors
2. **Multiple Delivery Methods**: GET, POST (urlencoded/JSON), multipart, HTTP/2
3. **Encoding Variations**: All common encoding methods tested
4. **Browser Automation**: Playwright-based testing for client-side execution
5. **Reverse Engineering**: Pattern analysis and hypothesis-driven testing

See [docs/methodology.md](docs/methodology.md) for detailed methodology.

## 📊 Key Findings

### WAF Effectiveness

- **Detection Rate**: 99.9% of malicious payloads blocked
- **False Positives**: Minimal (benign requests passed)
- **Encoding Normalization**: All encoding methods detected
- **Context-Aware**: Understands HTML structure and JavaScript context

### Bypass Attempts

- ✗ Traditional obfuscation (case, whitespace, encoding)
- ✗ Advanced techniques (mXSS, polyglots, DOM clobbering)
- ✗ Parameter smuggling and header injection
- ✗ Browser-specific quirks and mutations
- ✗ Charset confusion and protocol variations

**Result**: No exploitable bypasses found, demonstrating robust WAF implementation.

## 🛠️ Tools

### Payload Tester

Automated tool for testing payloads against WAFs:

```bash
python tools/payload_tester.py --target https://example.com --payloads payloads/xss/basic.json
```

### Classifier

Classify and organize payloads by technique:

```bash
python tools/classifier.py --input raw_payloads.txt --output classified/
```

### Analyzer

Analyze test results and generate reports:

```bash
python tools/analyzer.py --results results.json --output report.html
```

## 📖 Documentation

- [Methodology](docs/methodology.md) - Detailed testing methodology
- [Analysis](docs/analysis.md) - In-depth analysis of results
- [Techniques](docs/techniques.md) - Bypass techniques explained
- [Results](docs/results.md) - Complete test results and statistics

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ways to contribute:
- Add new payloads
- Improve classification
- Add testing tools
- Enhance documentation
- Report issues

## ⚖️ Legal Disclaimer

**IMPORTANT**: This repository is for **educational and research purposes only**.

- Only test against systems you own or have explicit permission to test
- Unauthorized testing is illegal and unethical
- The authors are not responsible for misuse of this information
- Always follow responsible disclosure practices
- Respect bug bounty program rules and scope

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- PortSwigger Web Security Academy
- OWASP Testing Guide
- Cloudflare Security Team
- Security research community
- All contributors

## 📞 Contact

- Issues: [GitHub Issues](https://github.com/yourusername/waf-payload-database/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/waf-payload-database/discussions)

## 🔗 Related Projects

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [XSS Payloads](https://github.com/pgaijin66/XSS-Payloads)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📈 Roadmap

- [ ] Add more payload categories
- [ ] Implement machine learning classification
- [ ] Create web-based payload browser
- [ ] Add payload effectiveness scoring
- [ ] Integrate with popular security tools
- [ ] Add multi-WAF comparison testing

---

**Star ⭐ this repository if you find it useful!**
