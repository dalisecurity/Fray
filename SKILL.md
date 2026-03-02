# SecurityForge

> Forge your attack payloads with AI — 4,025+ exploits, 25 WAF detections, works with Claude & ChatGPT

The open-source offensive security toolkit built for the AI era.

## Skills

### WAF Detection & Fingerprinting
- Auto-detect 25 WAF vendors (Cloudflare, AWS, Akamai, Azure, Imperva, F5, Fastly, Sucuri, Fortinet, Wallarm, etc.)
- Confidence scoring and header/cookie analysis
- `python3 waf_detector.py -t https://example.com`

### Attack Payload Database
- 4,025+ battle-tested payloads across 15 categories
- XSS (779), SQLi (148), SSRF (72), SSTI (62), Command Injection (125), XXE (34), and more
- 120 CVE exploits (2020-2026) including CISA KEV entries
- LLM jailbreaks and prompt injection payloads

### AI-Powered Testing
- Generate custom payloads via natural language
- Claude Code: run tests directly from Windsurf IDE
- ChatGPT: analyze payloads, generate variants, explain attack vectors
- Codex CLI: automated security workflows

### Security Reports
- One-command professional HTML report generation
- WAF deployment recommendations with vendor comparison
- Vulnerability findings with severity ratings

### OWASP Coverage (100%)
- **OWASP Top 10:2021** — 1,690+ payloads (10/10 categories)
- **OWASP Mobile Top 10:2024** — 575+ payloads (10/10 categories)
- **OWASP LLM Top 10** — 300+ payloads (10/10 categories)
- **OWASP API Security Top 10** — 520+ payloads (10/10 categories)

### WordPress CVE Testing
- CVE-2026-28515: REST API Authentication Bypass (150+ payloads)
- CVE-2026-28516: Plugin Arbitrary File Upload (200+ payloads)
- CVE-2026-28517: XML-RPC Amplification (100+ payloads)

## Quick Start

```bash
# Interactive mode (zero config)
python3 waf_tester.py -i

# Detect WAF
python3 waf_detector.py -t https://example.com

# Run payloads
python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json

# Generate report
python3 report_generator.py --html-report report.html
```

## AI Assistant Examples

```
"Detect the WAF on example.com"
"Test this site for SQL injection"
"Generate XSS payloads for a React app"
"Create a security report for this API"
"Test this LLM for prompt injection"
"Compare WAF vendors for my infrastructure"
```

## Links

- **Repository**: https://github.com/dalisecurity/securityforge
- **License**: MIT
- **Author**: [DALI Security](https://github.com/dalisecurity)
