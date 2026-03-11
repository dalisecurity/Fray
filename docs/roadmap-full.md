# Fray Full Roadmap — 222 Items Across 27 Layers

**Status:** 68 done · 154 pending  
**Last updated:** 2026-03-11

---

## L1 — Core Discovery (5 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 1 | JavaScript endpoint extraction from page source | HIGH | pending |
| 2 | Wayback Machine historical URL discovery | HIGH | pending |
| 3 | Parameter mining from HTML forms + JS | HIGH | pending |
| 4 | Technology stack fingerprinting (Wappalyzer-level) | HIGH | pending |
| 5 | Cloud asset enumeration (S3, Azure Blob, GCS) | MEDIUM | pending |

## L2 — Endpoint Classification (8 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 6 | API endpoint auto-classification (REST/GraphQL/gRPC) | HIGH | pending |
| 7 | Authentication endpoint detection | MEDIUM | pending |
| 8 | File upload endpoint detection | MEDIUM | pending |
| 9 | Admin panel fingerprinting | MEDIUM | pending |
| 10 | WebSocket endpoint discovery | MEDIUM | pending |
| 11 | Server-Sent Events (SSE) endpoint detection | LOW | pending |
| 12 | Health/status endpoint enumeration | LOW | done |
| 13 | OpenAPI/Swagger spec auto-discovery | HIGH | done |

## L3 — Secret/Credential Detection (6 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 14 | Exposed .env / config file detection | HIGH | done |
| 15 | Git repository exposure (.git/HEAD) | HIGH | done |
| 16 | API key pattern matching in responses | HIGH | pending |
| 17 | JWT token analysis (weak signing, expired, none alg) | MEDIUM | pending |
| 18 | Hardcoded credential detection in JS bundles | MEDIUM | pending |
| 19 | Source map detection and analysis | LOW | pending |

## L4 — New Attack Classes / OWASP 2025 (10 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 20 | Server-Side Request Forgery (SSRF) deep testing | HIGH | pending |
| 21 | Insecure Deserialization payloads | HIGH | pending |
| 22 | Mass Assignment / parameter pollution | MEDIUM | pending |
| 23 | GraphQL-specific attacks (batching, introspection abuse) | MEDIUM | pending |
| 24 | Race condition testing (TOCTOU) | MEDIUM | pending |
| 25 | Business logic bypass templates | MEDIUM | pending |
| 26 | HTTP/2 specific attacks (HPACK bomb, etc.) | LOW | pending |
| 27 | Cache poisoning via headers | MEDIUM | pending |
| 28 | Web cache deception | MEDIUM | pending |
| 29 | Client-side prototype pollution verification | LOW | pending |

## L5 — Supply Chain Pipeline (3 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 30 | Dependency confusion detection | HIGH | pending |
| 31 | Subdomain takeover verification | HIGH | done |
| 32 | Third-party script integrity (SRI) audit | MEDIUM | done |

## L6 — OSINT (6 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 33 | Whois + registration history | MEDIUM | done |
| 34 | Email harvesting (hunter.io pattern) | MEDIUM | done |
| 35 | GitHub org reconnaissance | HIGH | done |
| 36 | Document metadata extraction | MEDIUM | done |
| 37 | Typosquatting / domain permutation check | MEDIUM | done |
| 38 | Employee enumeration via LinkedIn patterns | LOW | done |

## L7 — Cache + D1 Sync (8 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 39 | Adaptive payload cache (cross-domain WAF learning) | HIGH | done |
| 40 | R2 payload bundle distribution | HIGH | done |
| 41 | D1 community bypass sharing | MEDIUM | done |
| 42 | Cache invalidation on WAF config change | MEDIUM | pending |
| 43 | Cache size limits + eviction policy | LOW | pending |
| 44 | Cache export/import for offline use | LOW | pending |
| 45 | Community leaderboard from D1 data | MEDIUM | pending |
| 46 | Cache warming from threat intel feed | LOW | pending |

## L8 — DNS Recon Phase 2 (5 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 47 | DNSSEC validation check | MEDIUM | done |
| 48 | Zone transfer attempt (AXFR) | MEDIUM | done |
| 49 | DNS rebinding detection | LOW | done |
| 50 | Dangling CNAME / subdomain takeover via DNS | HIGH | done |
| 51 | Wildcard DNS detection | LOW | done |

## L9 — Bot Detection (5 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 52 | Cloudflare Turnstile detection | MEDIUM | pending |
| 53 | reCAPTCHA v2/v3 detection | MEDIUM | pending |
| 54 | Browser fingerprint challenge detection | MEDIUM | pending |
| 55 | JavaScript challenge solver integration | LOW | pending |
| 56 | Anti-bot header rotation (Sec-Fetch-*, etc.) | HIGH | done |

## L10 — Dashboard / Web UI (13 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 57 | `fray dashboard` — local web server | HIGH | pending |
| 58 | Recon results viewer (interactive) | HIGH | pending |
| 59 | Attack surface graph visualization | MEDIUM | pending |
| 60 | Scan history timeline | MEDIUM | pending |
| 61 | Finding detail drilldown | MEDIUM | pending |
| 62 | Export from dashboard (PDF, CSV) | LOW | pending |
| 63 | Real-time scan progress | MEDIUM | pending |
| 64 | Multi-target comparison view | LOW | pending |
| 65 | Dark/light theme toggle | LOW | pending |
| 66 | Dashboard auth (local password) | LOW | pending |
| 67 | REST API for dashboard data | MEDIUM | pending |
| 68 | WebSocket live scan feed | LOW | pending |
| 69 | Dashboard mobile responsive design | LOW | pending |

## L11 — Nikkei 225 Bugs + Features (10 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 70 | Batch recon for Fortune 500 / Nikkei 225 | HIGH | pending |
| 71 | Corporate WAF coverage report | MEDIUM | pending |
| 72 | Industry-level security posture comparison | MEDIUM | pending |
| 73 | Automated report generation per company | MEDIUM | pending |
| 74 | DNS hygiene scoring | LOW | done |
| 75 | Certificate transparency monitoring | MEDIUM | pending |
| 76 | Subdomain sprawl detection | LOW | done |
| 77 | Cloud provider distribution analysis | LOW | done |
| 78 | WAF market share from scan data | MEDIUM | pending |
| 79 | Historical trend tracking | LOW | pending |

## L12 — Integrations (4 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 80 | Burp Suite XML import/export | MEDIUM | done |
| 81 | ZAP alerts JSON import/export | MEDIUM | done |
| 82 | Nuclei YAML template export | MEDIUM | done |
| 83 | SARIF output for GitHub Security tab | HIGH | done |

## L13 — GitHub Repos (12 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 84 | homebrew-tap repo | HIGH | done |
| 85 | VS Code extension on Marketplace | HIGH | done |
| 86 | GitHub Action (action.yml) | HIGH | done |
| 87 | Chrome extension for Fray | MEDIUM | pending |
| 88 | Fray landing page on dalisec.io | HIGH | pending |
| 89 | docs.dalisec.io hosted documentation | HIGH | pending |
| 90 | Demo video/GIF refresh | MEDIUM | pending |
| 91 | Docker image (Dockerfile) | HIGH | pending |
| 92 | PyPI package optimization | LOW | pending |
| 93 | Kali Linux package (apt) | MEDIUM | pending |
| 94 | CONTRIBUTING.md + AGENTS.md | LOW | done |
| 95 | SECURITY.md + .well-known/security.txt | LOW | done |

## L14 — Growth / GitHub Stars (16 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 96 | README badges + comparison table | HIGH | done |
| 97 | Awesome lists submission (Awesome WAF, etc.) | HIGH | pending |
| 98 | HackerNews / Reddit launch post | HIGH | pending |
| 99 | Security conference talk proposal | MEDIUM | pending |
| 100 | YouTube tutorial series | MEDIUM | pending |
| 101 | Blog post: "How Fray bypasses Cloudflare" | HIGH | pending |
| 102 | Blog post: "Fray vs Nuclei vs sqlmap" | HIGH | pending |
| 103 | Twitter/X security community engagement | MEDIUM | pending |
| 104 | Discord/Slack community server | MEDIUM | pending |
| 105 | GitHub Discussions enabled | LOW | done |
| 106 | Issue templates (bug, feature, payload) | LOW | done |
| 107 | Sponsor button / OpenCollective | LOW | pending |
| 108 | Stickers / swag design | LOW | pending |
| 109 | Product Hunt launch | MEDIUM | pending |
| 110 | Security newsletter mentions | MEDIUM | pending |
| 111 | CTF challenge using Fray | LOW | pending |

## L15 — Bug Bounty Enhancement (11 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 112 | HackerOne API scope auto-fetch | HIGH | pending |
| 113 | Bugcrowd API scope auto-fetch | MEDIUM | pending |
| 114 | Auto-submit findings to HackerOne | MEDIUM | pending |
| 115 | Bounty program recommendation engine | LOW | pending |
| 116 | Scope validation + out-of-scope detection | HIGH | done |
| 117 | Multi-target batch bounty testing | MEDIUM | done |
| 118 | Bounty report template generator | MEDIUM | pending |
| 119 | Duplicate finding detection (cross-program) | LOW | pending |
| 120 | Payout tracking / statistics | LOW | pending |
| 121 | VDP (Vulnerability Disclosure Policy) parser | LOW | pending |
| 122 | Bounty prioritization by $/severity | MEDIUM | pending |

## L16 — Credential Exposure OSINT (13 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 123 | GitHub code search for leaked secrets | HIGH | done |
| 124 | HIBP breach check | HIGH | done |
| 125 | Paste site monitoring (Pastebin, etc.) | MEDIUM | pending |
| 126 | Telegram channel monitoring | LOW | pending |
| 127 | Dark web mention check (via API) | LOW | pending |
| 128 | Certificate transparency log monitoring | MEDIUM | pending |
| 129 | Exposed database detection (Shodan-like) | MEDIUM | pending |
| 130 | S3 bucket permission check | MEDIUM | pending |
| 131 | Azure Blob public access check | MEDIUM | pending |
| 132 | GCS bucket permission check | MEDIUM | pending |
| 133 | Docker registry exposure | LOW | pending |
| 134 | NPM package typosquatting detection | LOW | pending |
| 135 | PyPI package typosquatting detection | LOW | pending |

## L17 — Interactive + Self-Learning (18 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 136 | CTF-style learning modules | MEDIUM | done |
| 137 | Adaptive payload agent (probe → mutate → learn) | HIGH | done |
| 138 | WAF profile caching across sessions | HIGH | done |
| 139 | Payload effectiveness scoring per WAF | HIGH | done |
| 140 | Auto-mutation feedback loop | HIGH | done |
| 141 | LLM-assisted bypass generation | HIGH | done |
| 142 | Natural language query for findings | MEDIUM | pending |
| 143 | Interactive scan wizard (guided mode) | MEDIUM | pending |
| 144 | Payload creation from CVE description | MEDIUM | pending |
| 145 | Auto-remediation suggestion engine | MEDIUM | done |
| 146 | Continuous learning from community results | LOW | pending |
| 147 | Benchmark mode (test against known-vulnerable apps) | LOW | pending |
| 148 | Payload similarity clustering | LOW | pending |
| 149 | WAF rule reverse engineering | MEDIUM | pending |
| 150 | Attack chain suggestion (multi-step exploits) | LOW | pending |
| 151 | Payload obfuscation scoring | LOW | pending |
| 152 | False positive reduction via ML | LOW | pending |
| 153 | Scan result confidence scoring | LOW | pending |

## L18 — Competitive Parity / Surpass (16 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 154 | YAML Template DSL (Nuclei-like with WAF bypass logic) | HIGH | pending |
| 155 | Template Bounty Program ($25-100 per template) | HIGH | pending |
| 156 | Deep SQLi Module (sqlmap-level: 6 techniques, 34+ DBMS) | HIGH | pending |
| 157 | Deep XSS Module (XSStrike-level: context-aware, DOM verify) | HIGH | pending |
| 158 | Deep CMDi Module (commix-level: auto-shell) | MEDIUM | pending |
| 159 | Content Discovery / Fuzzing (ffuf-like FUZZ keyword) | HIGH | pending |
| 160 | Stdin/Stdout Pipeline (cat | fray recon -) | HIGH | done |
| 161 | WAF Fingerprint DB Expansion (30→150+ WAFs) | HIGH | pending |
| 162 | Vulnerability Verification/Proof (dump data, screenshot XSS) | HIGH | pending |
| 163 | Plugin / Extension API (Python hooks, marketplace) | MEDIUM | pending |
| 164 | Multi-Protocol (WebSocket, GraphQL, gRPC testing) | MEDIUM | pending |
| 165 | SARIF + Standard Formats (JUnit XML, CSV, JSONL) | HIGH | done |
| 166 | Headless Browser Engine (Playwright SPA, DOM XSS) | HIGH | pending |
| 167 | Scan Profile Presets (--profile quick/standard/deep) | HIGH | done |
| 168 | Performance Benchmark Suite (vs Nuclei/ZAP/Nikto) | MEDIUM | pending |
| 169 | i18n / Multilingual (JP/CN/KR/ES/PT docs + CLI) | MEDIUM | pending |

## L19 — Recently Completed (Session Items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 170 | Exit code based on severity (#190) | HIGH | done |
| 171 | Scan duration + stats summary (#189) | HIGH | done |
| 172 | Finding deduplication (#182) | MEDIUM | done |
| 173 | Finding grouping by category (#183) | MEDIUM | done |
| 174 | --quiet / --verbose log levels (#188) | MEDIUM | done |
| 175 | Environment variable override for all flags (#186) | MEDIUM | done |
| 176 | Rate limit auto-detection (#192) | MEDIUM | done |
| 177 | Markdown report output (#193) | MEDIUM | done |
| 178 | HTTP method enumeration (#179) | MEDIUM | done |
| 179 | robots.txt + sitemap.xml parser (#180) | MEDIUM | done |

## L20 — Performance + UX
| # | Item | Priority | Status |
|---|------|----------|--------|
| 180 | Fast mode optimization (42s→28s) | HIGH | done |
| 181 | Shell completions (bash/zsh/fish) | MEDIUM | done |
| 182 | Parallel multi-target recon | MEDIUM | pending |
| 183 | Progress bar improvements (ETA, speed) | LOW | pending |
| 184 | Color theme customization | LOW | pending |
| 185 | Config file validation (JSON Schema) | LOW | pending |

## L21 — Packaging + Distribution
| # | Item | Priority | Status |
|---|------|----------|--------|
| 186 | Homebrew formula (brew install fray) | HIGH | done |
| 187 | Docker image (Dockerfile) | HIGH | done |
| 188 | Kali Linux / Debian package | MEDIUM | pending |
| 189 | Windows installer (MSI/exe) | LOW | pending |
| 190 | Arch Linux AUR package | LOW | pending |
| 191 | Nix package | LOW | pending |

## L22 — Documentation + Marketing
| # | Item | Priority | Status |
|---|------|----------|--------|
| 192 | docs.dalisec.io hosted documentation | HIGH | pending |
| 193 | Fray landing page on dalisec.io | HIGH | pending |
| 194 | Demo video/GIF refresh | MEDIUM | pending |
| 195 | API reference docs (auto-generated) | MEDIUM | pending |
| 196 | Cookbook: 50 real-world recipes | MEDIUM | pending |
| 197 | Comparison guide (vs Nuclei/sqlmap/ZAP) | HIGH | pending |

## L23 — Chrome / VS Code Extensions
| # | Item | Priority | Status |
|---|------|----------|--------|
| 198 | VS Code extension (on Marketplace) | HIGH | done |
| 199 | Chrome extension for Fray | MEDIUM | pending |
| 200 | VS Code: inline security annotations | LOW | pending |
| 201 | Chrome: one-click recon from browser | MEDIUM | pending |
| 202 | Chrome: response header analyzer | LOW | pending |

## L24 — Monitoring + Alerting
| # | Item | Priority | Status |
|---|------|----------|--------|
| 203 | Continuous monitoring (fray monitor) | HIGH | done |
| 204 | Email alerts (Resend integration) | MEDIUM | done |
| 205 | PagerDuty / OpsGenie integration | LOW | pending |

## L25 — AI Intelligence Pipeline (5 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 206 | AI Payload Intelligence Engine (CVE→LLM→staged payloads) | HIGH | pending |
| 207 | fray ask — natural language interface over Fray data | MEDIUM | pending |
| 208 | Payload mutation feedback loop (blocked→LLM bypass→retry) | HIGH | pending |
| 209 | Recon interpretation (LLM→attack narrative) | MEDIUM | pending |
| 210 | AI research pipeline (NVD+arxiv+blogs→extract→generate) | LOW | pending |

## L26 — Cloudflare Workers AI Gateway (7 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 211 | CF Worker — AI Gateway + Payload API (worker.js) | HIGH | pending |
| 212 | Payload Mutation Endpoint (blocked→LLM→5 bypass variants) | HIGH | pending |
| 213 | CVE Extraction Endpoint (CVE text→payloads+metadata) | MEDIUM | pending |
| 214 | Recon Interpretation Endpoint (findings→risk narrative) | MEDIUM | pending |
| 215 | D1 Schema (mutations, cve_cache, payload_staging, scan_results) | HIGH | pending |
| 216 | Python Client (fray/intelligence/cf_client.py) | HIGH | pending |
| 217 | LLM Provider Abstraction (cloudflare/ollama/openai dispatch) | MEDIUM | pending |

## L27 — Architecture + Code Quality (5 items)
| # | Item | Priority | Status |
|---|------|----------|--------|
| 218 | Parallel/async request execution (asyncio + aiohttp) | HIGH | pending |
| 219 | Response diffing / false positive reduction | MEDIUM | pending |
| 220 | Redirect chain following in testing | MEDIUM | pending |
| 221 | --resume flag for interrupted scan checkpoint | MEDIUM | pending |
| 222 | Test coverage expansion (pytest, >80%) | LOW | pending |

---

## Summary

| Layer | Items | Done | Pending |
|-------|-------|------|---------|
| L1 Core Discovery | 5 | 0 | 5 |
| L2 Endpoint Classification | 8 | 2 | 6 |
| L3 Secret/Credential Detection | 6 | 2 | 4 |
| L4 New Attack Classes | 10 | 0 | 10 |
| L5 Supply Chain | 3 | 2 | 1 |
| L6 OSINT | 6 | 6 | 0 |
| L7 Cache + D1 Sync | 8 | 3 | 5 |
| L8 DNS Recon Phase 2 | 5 | 5 | 0 |
| L9 Bot Detection | 5 | 1 | 4 |
| L10 Dashboard / Web UI | 13 | 0 | 13 |
| L11 Nikkei 225 | 10 | 3 | 7 |
| L12 Integrations | 4 | 4 | 0 |
| L13 GitHub Repos | 12 | 6 | 6 |
| L14 Growth / Stars | 16 | 3 | 13 |
| L15 Bug Bounty | 11 | 2 | 9 |
| L16 Credential OSINT | 13 | 2 | 11 |
| L17 Interactive + Self-Learning | 18 | 7 | 11 |
| L18 Competitive Parity | 16 | 3 | 13 |
| L19 Recent Session | 10 | 10 | 0 |
| L20 Performance + UX | 6 | 2 | 4 |
| L21 Packaging | 6 | 2 | 4 |
| L22 Docs + Marketing | 6 | 0 | 6 |
| L23 Extensions | 5 | 1 | 4 |
| L24 Monitoring | 3 | 2 | 1 |
| L25 AI Intelligence | 5 | 0 | 5 |
| L26 CF Workers AI Gateway | 7 | 0 | 7 |
| L27 Architecture + Quality | 5 | 0 | 5 |
| **TOTAL** | **222** | **68** | **154** |
