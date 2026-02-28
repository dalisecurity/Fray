# Quick Start Guide

Get started with WAF Tester in 5 minutes!

## 🚀 Installation

### Option 1: Clone from GitHub (Recommended)

```bash
git clone https://github.com/dalisecurity/waf-payload-arsenal.git
cd waf-payload-arsenal
chmod +x waf_tester.py
```

### Option 2: Download ZIP

1. Download the repository as ZIP
2. Extract to your desired location
3. Navigate to the directory

## 📋 Prerequisites

- Python 3.7+
- No additional dependencies required (uses standard library only!)

## 🎯 Usage

### Interactive Mode (Easiest!)

```bash
python3 waf_tester.py -i
```

Follow the prompts:
1. Enter target URL
2. Select payload category
3. Choose HTTP method
4. Set max payloads (optional)
5. Watch the results!

### Command Line Mode

#### Test XSS Payloads
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json
```

#### Test SQL Injection
```bash
python3 waf_tester.py -t https://example.com -p payloads/sqli/general.json
```

#### Test with POST Method
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json -m POST
```

#### Limit Number of Payloads
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json --max 10
```

#### Test All XSS Payloads
```bash
python3 waf_tester.py -t https://example.com -p payloads/xss/
```

## 📊 Understanding Results

### Output Example
```
[1/10] BLOCKED  | Status: 403 | basic script tag
[2/10] BLOCKED  | Status: 403 | img onerror
[3/10] PASSED   | Status: 200 | benign input
```

- **BLOCKED** (Red): WAF detected and blocked the payload
- **PASSED** (Green): Payload was not blocked
- **Status**: HTTP response code (403 = blocked, 200 = passed)

### Report File

After testing, a JSON report is generated:

```json
{
  "target": "https://example.com",
  "timestamp": "2026-02-28T15:30:00",
  "summary": {
    "total": 100,
    "blocked": 98,
    "passed": 2,
    "block_rate": "98.00%"
  },
  "results": [...]
}
```

## 🎓 Common Use Cases

### 1. Quick WAF Check
```bash
# Test 10 basic XSS payloads
python3 waf_tester.py -t https://your-site.com -p payloads/xss/basic.json --max 10
```

### 2. Comprehensive XSS Test
```bash
# Test all XSS categories
python3 waf_tester.py -t https://your-site.com -p payloads/xss/
```

### 3. Multi-Vector Test
```bash
# Test XSS
python3 waf_tester.py -t https://your-site.com -p payloads/xss/basic.json -o xss_report.json

# Test SQLi
python3 waf_tester.py -t https://your-site.com -p payloads/sqli/general.json -o sqli_report.json

# Test SSRF
python3 waf_tester.py -t https://your-site.com -p payloads/ssrf/general.json -o ssrf_report.json
```

### 4. Custom Parameter Testing
```bash
# Test with custom parameter name
python3 waf_tester.py -t https://your-site.com -p payloads/xss/basic.json --param search
```

## ⚙️ Advanced Options

```bash
python3 waf_tester.py --help
```

Options:
- `-t, --target`: Target URL
- `-p, --payloads`: Payload file or directory
- `-m, --method`: HTTP method (GET/POST)
- `-i, --interactive`: Interactive mode
- `--param`: Parameter name (default: input)
- `--max`: Max payloads to test
- `--delay`: Delay between requests (default: 0.5s)
- `--timeout`: Request timeout (default: 8s)
- `-o, --output`: Output report file

## 🔒 Important Notes

### Authorization Required
**ONLY test systems you own or have explicit permission to test!**

Unauthorized testing is:
- ✗ Illegal
- ✗ Unethical
- ✗ May result in criminal charges

### Responsible Use
- Get written permission before testing
- Follow bug bounty program rules
- Respect rate limits
- Don't cause harm or disruption

## 🐛 Troubleshooting

### Connection Errors
```bash
# Increase timeout
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json --timeout 15
```

### Rate Limiting
```bash
# Increase delay between requests
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json --delay 2
```

### SSL Certificate Errors
The tool automatically ignores SSL certificate validation for testing purposes.

## 📚 Payload Categories

Available payload files:

### XSS
- `payloads/xss/basic.json` - 412 basic XSS payloads
- `payloads/xss/svg_based.json` - 175 SVG-based XSS
- `payloads/xss/encoded.json` - 12 encoded XSS
- `payloads/xss/obfuscated.json` - 3 obfuscated XSS
- `payloads/xss/mutation.json` - 4 mutation XSS
- `payloads/xss/dom_based.json` - 24 DOM-based XSS
- `payloads/xss/polyglot.json` - 1 polyglot XSS

### Other
- `payloads/sqli/general.json` - 13 SQL injection
- `payloads/ssrf/general.json` - 7 SSRF payloads
- `payloads/xxe/general.json` - 3 XXE payloads
- `payloads/ssti/general.json` - 8 SSTI payloads

## 🎬 Video Tutorial

Coming soon! Check the repository for updates.

## 💬 Getting Help

- **Issues**: [GitHub Issues](https://github.com/dalisecurity/waf-payload-database/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dalisecurity/waf-payload-database/discussions)
- **Documentation**: See `/docs` folder

## 🚀 Next Steps

1. ✅ Run your first test in interactive mode
2. 📖 Read the [full documentation](README.md)
3. 🔬 Explore the [methodology](docs/methodology.md)
4. 🤝 [Contribute](CONTRIBUTING.md) your own payloads

---

**Happy (ethical) testing! 🎯**
