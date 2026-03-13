# AGENTS.md — Coding Agent Guidelines for Fray

This file provides context for AI coding agents (Claude Code, Cursor, Copilot, etc.) working on the Fray codebase.

## Project Overview

Fray is an open-source security testing toolkit — **"vibe security"**: just point and scan. One command (`fray go`) runs a full security audit automatically: reconnaissance → vulnerability testing → reporting. Zero config, zero external dependencies (pure Python stdlib).

The philosophy is that security testing should be as easy as vibe coding made development. Users shouldn't need to be security experts — Fray figures out what to test based on what it discovers.

**Repository:** [github.com/dalisecurity/fray](https://github.com/dalisecurity/fray)
**Package:** [pypi.org/project/fray](https://pypi.org/project/fray/)
**Website:** [dalisec.io](https://dalisec.io/)

## Architecture

```
fray/
├── __init__.py            # Package init, DATA_DIR, CATEGORIES, load helpers
├── __main__.py            # Entry point
├── cli.py                 # CLI (argparse) — all fray commands routed here
│
├── # ── Core Pipeline ──
├── interactive.py         # GuidedPipeline (fray go), ReconInteractive, next_steps()
├── tester.py              # Core payload testing engine, anti-bot evasion (browser headers)
├── scanner.py             # Auto-crawl + injection scanner
├── bypass.py              # 5-phase WAF evasion scorer
├── ai_bypass.py           # AI-assisted adaptive bypass (LLM + local)
├── agent.py               # Self-improving payload agent with learning cache
├── detector.py            # WAF/CDN vendor fingerprinting (98 vendors)
│
├── # ── Deep Scan Modules (6) ──
├── xss.py                 # XSSScanner — context-aware, DOM verification
├── sqli.py                # SQLiInjector — multi-technique SQL injection
├── cmdi.py                # CMDiScanner — command injection (results/time/OOB)
├── cache_poison.py        # CachePoisonScanner — web cache poisoning
├── massassign.py          # MassAssignScanner — mass assignment testing
├── deser.py               # DeserScanner — insecure deserialization
│
├── # ── Additional Attack Modules ──
├── blind.py               # Blind injection (time-based + OOB DNS callbacks)
├── ssrf.py                # SSRF testing
├── smuggling.py           # HTTP request smuggling
├── race.py                # Race condition testing
├── csp.py                 # CSP analysis and bypass
├── proto_pollution.py     # Prototype pollution
├── fuzzer.py              # Content discovery (ffuf-like FUZZ keyword)
│
├── # ── Reconnaissance ──
├── recon/
│   ├── pipeline.py        # 35+ check recon orchestrator, attack prioritization
│   ├── checks.py          # 28 recon check implementations
│   ├── dns.py             # DNS recon, subdomain discovery, takeover detection
│   ├── fingerprint.py     # Tech fingerprinting (10 layers + Wappalyzer 7,500+ techs)
│   ├── discovery.py       # Endpoint and asset discovery
│   ├── http.py            # HTTP-level checks
│   ├── supply_chain.py    # Supply chain analysis
│   └── history.py         # Recon history/diff tracking
│
├── # ── Mutation & Payloads ──
├── mutation.py            # 20-strategy payload mutation engine
├── mutator.py             # Genetic/ML-based payload mutator
├── evolve.py              # Evolutionary payload optimization
├── payload_creator.py     # Custom payload generation
├── payload_generator.py   # Template-based payload generation
├── cve_payload.py         # CVE-to-payload extraction and mapping
├── poc_extractor.py       # PoC extraction from 6 sources (GitHub, NVD, etc.)
├── threat_intel.py        # Threat intel feeds (NVD, CISA, ExploitDB, nuclei)
│
├── # ── Intelligence & Learning ──
├── adaptive_cache.py      # Per-domain learning cache, WAF leaderboard
├── learn.py               # Cross-scan learning engine
├── recommender.py         # Payload recommendation engine
├── cloud_sync.py          # GitHub + Cloudflare R2/D1 sync
│
├── # ── Auth & Stealth ──
├── auth.py                # Auth profiles (cookie, bearer, OAuth2, form login)
├── scope.py               # In-scope enforcement
│
├── # ── Reporting & Output ──
├── reporter.py            # Report orchestrator (HTML/Markdown/SARIF)
├── _report_builder.py     # v11 HTML report builder (dark theme)
├── _report_css.py         # Report CSS variables, SVG helpers
├── ui.py                  # CLI design system (brand palette, pills, banners)
├── output.py              # Rich theme (hex colors, severity styles)
├── diff.py                # Differential reports
├── waf_report.py          # WAF-specific reporting
├── company_report.py      # Company-level report aggregation
│
├── # ── Integrations ──
├── mcp_server.py          # MCP server (17 tools for Claude/ChatGPT/Cursor)
├── ci.py                  # CI/CD integration helpers
├── interop.py             # Burp Suite / ZAP export/import
├── webhook.py             # Webhook notifications
├── templates.py           # YAML template DSL engine
├── plugins.py             # Plugin system for custom checks
├── completions.py         # Shell completions (bash/zsh/fish)
│
├── # ── Other ──
├── config.py              # Config file support (fray.toml)
├── stats.py               # Scan statistics
├── validate.py            # Payload validation
├── verify.py              # Finding verification
├── monitor.py             # Continuous monitoring
├── batch.py               # Batch/multi-target scanning
├── osint.py               # OSINT intelligence gathering
├── leak.py                # Credential leak detection
├── bounty.py              # Bug bounty workflow helpers
├── submit.py              # Bug bounty report submission
├── wizard.py              # Interactive setup wizard
├── welcome.py             # First-run welcome experience
├── doctor.py              # Self-diagnostic (fray doctor)
├── progress.py            # Progress bar helpers
├── checkpoint.py          # Scan checkpoint/resume
├── graph.py               # Attack graph visualization
├── headless.py            # Headless browser (Playwright) integration
├── browser.py             # Browser-based scanning
├── multiproto.py          # Multi-protocol testing (WebSocket, GraphQL, gRPC)
├── posture.py             # Security posture scoring
├── themes.py              # Report theme customization
├── update.py              # Self-update mechanism
├── async_engine.py        # Async request execution engine
├── waf_reverse.py         # WAF rule reverse engineering
├── cred.py                # Credential/secret detection
├── ask.py                 # Natural language query interface (fray ask)
├── differ.py              # Response diffing / false positive reduction
│
├── payloads/              # 5,600+ payloads in JSON+TXT (24 categories)
│   ├── xss/               # 807 payloads
│   ├── ai_prompt_injection/ # 370 payloads
│   ├── sqli/              # 141 payloads
│   ├── command_injection/
│   ├── ssrf/, ssti/, xxe/, path_traversal/, ...
│   └── (24 category directories)
│
├── data/
│   └── waf_intel.json     # Per-vendor bypass strategies
│
├── docs/                  # 38 documentation guides
└── tests/                 # 24 test files
```

## Key Design Principles

1. **Vibe security** — `fray go <url>` should do the right thing with zero configuration. New features should work automatically within the guided pipeline. Don't require users to read docs to get value.
2. **Zero dependencies** — Only Python stdlib. No `requests`, no `aiohttp`, no third-party packages. Use `urllib.request`, `http.client`, `ssl`, `json`, `concurrent.futures`.
3. **Single pip install** — Everything ships in the package. Payloads are bundled in `fray/payloads/`.
4. **CLI-first** — All features accessible via `fray <command>`. No web UI required.
5. **Smart defaults** — Adaptive cache learns across domains; blocked payloads are never re-sent. Each scan gets smarter.
6. **Defensive coding** — Every network call must handle timeouts, connection errors, and rate limiting (429 backoff).
7. **Scope enforcement** — Never send requests to hosts outside `--scope`. Check before every request.
8. **No hardcoded test targets** — Never hardcode real domains in code or tests. Use `--test-target` or `FRAY_TEST_TARGET` env var.

## Key CLI Commands

```bash
fray go <url>              # Full guided pipeline: recon → test → report (hero command)
fray recon <url>           # 35+ check reconnaissance
fray test <url> --smart    # Smart payload selection from recon findings
fray detect <url>          # WAF/CDN fingerprinting (98 vendors)
fray harden <url>          # OWASP hardening audit (A-F grade)
fray fuzz <url>/FUZZ       # Content discovery
fray agent <url>           # Self-improving bypass agent with learning cache
fray report                # Generate HTML/Markdown/SARIF reports
```

## Development Commands

```bash
# Install in dev mode
pip install -e '.[dev]'

# Run tests
pytest tests/ -v

# Run a specific test
pytest tests/test_tester.py -v

# Type checking
mypy fray/ --ignore-missing-imports

# Lint
ruff check fray/

# Build package
python -m build
```

## Common Tasks

### Adding a new payload category
1. Create `fray/payloads/<category>/` directory with JSON payload files following the existing schema
2. Add category to `CATEGORIES` in `fray/__init__.py`
3. Update payload counts in README badges if total changes

### Adding a new WAF signature
1. Update `detector.py` with detection logic (headers, CNAME, cookies, response patterns)
2. Add vendor to `data/waf_intel.json` if bypass strategies are known
3. Update the WAF count badge in README if total changes (currently 98)

### Adding a new recon check
1. Implement `check_<name>()` in `fray/recon/checks.py`
2. Wire into the appropriate tier in `fray/recon/pipeline.py`
3. Ensure positive findings auto-create attack vectors
4. Update the check count in README badges if total changes (currently 35+)

### Adding a new deep scan module
1. Create `fray/<module>.py` with a scanner class (e.g. `class MyScanner`)
2. Wire into `fray/interactive.py` `_run_module()` for the guided pipeline
3. Add keyword classification in `_classify_findings()` so recon findings trigger it
4. Register the module in `fray/cli.py` `cmd_test()`

### Adding a new MCP tool
1. Add async handler function in `fray/mcp_server.py`
2. Register as an `@server.tool()` decorated function with proper type hints
3. Update tool count in README if total changes (currently 17)

### Adding a new `fray go` pipeline phase
1. Modify `GuidedPipeline` class in `fray/interactive.py`
2. Use `phase_header()` from `fray/ui.py` for consistent styling
3. Ensure the phase works with `--deep`, `--stealth`, and auth flags

## Code Style

- Python 3.8+ compatible (no walrus operator in hot paths, use `typing` for type hints)
- PEP 8 with 120-char line length
- Docstrings for public functions (Google style)
- Use `logging` module, not `print()` for debug output
- CLI output uses the centralized design system in `fray/ui.py`:
  - `brand()`, `bold()`, `dim()`, `success()`, `error()`, `warning()` — text wrappers
  - `pill()`, `severity_pill()` — colored badges
  - `banner()`, `phase_header()`, `section_title()` — section headers
  - `cmd_hint()` — branded command suggestions
  - `summary_line()`, `result_line()` — formatted output rows
- Brand palette: primary `#6366f1` (indigo), secondary `#a78bfa` (violet), accent `#818cf8`
- Severity colors: critical=red, high=orange, medium=yellow, low=blue

## Testing

- Tests in `tests/` — 24 test files covering core modules
- Use `pytest` fixtures for common setup (mock HTTP responses)
- Network calls in tests must be mocked — no real HTTP requests in CI
- Payload validation tests ensure all JSON files parse correctly
- Never delete or weaken existing tests without explicit direction

## Important Constraints

- **Never add external dependencies** to the core package. Optional extras (like `fray[mcp]`) may use `mcp` package.
- **Never remove payloads** — only add or recategorize.
- **Never weaken security checks** in `harden.py` without explicit direction.
- **Always preserve backward compatibility** in CLI arguments and JSON output schema.
- **Authorized testing only** — all docs and examples must use `example.com` or explicitly mention authorization requirements.
- **No hardcoded test targets** — never put real domain names in source code or tests. Always require explicit `--test-target` or `FRAY_TEST_TARGET` env var.
- **Payload bundling** — payloads live in `fray/payloads/`, data in `fray/data/`. Both are shipped with the package.

## Commit Convention

```
feat: Add 50 new SVG-based XSS payloads
fix: Correct classification of polyglot payloads
docs: Update methodology documentation
refactor: Improve payload classifier performance
test: Add unit tests for analyzer tool
chore: Maintenance tasks
```

## Contact

- **Security issues:** soc@dalisec.io
- **General questions:** [GitHub Discussions](https://github.com/dalisecurity/fray/discussions)
