# Homebrew Tap for Fray

Official [Homebrew](https://brew.sh) tap for **Fray** — AI-Powered WAF Security Testing Platform.

## Installation

```bash
brew tap dalisecurity/tap
brew install fray
```

## Upgrade

```bash
brew update
brew upgrade fray
```

## Usage

```bash
fray detect https://example.com        # WAF detection
fray recon https://example.com --fast   # Reconnaissance
fray test https://example.com -c xss    # Payload testing
fray auto https://example.com           # Full pipeline
```

## About

Fray is an open-source offensive security toolkit with:
- 4,000+ attack payloads across 23 categories
- 25 WAF vendor fingerprints
- AI-assisted bypass generation (OpenAI/Anthropic)
- Beautiful CLI output with actionable recommendations

**GitHub:** [dalisecurity/fray](https://github.com/dalisecurity/fray)  
**PyPI:** [fray](https://pypi.org/project/fray/)  
**Website:** [dalisec.io](https://dalisec.io)
