#!/usr/bin/env python3
"""
Fray Shell Completions — bash, zsh, and fish tab completion scripts.

Usage:
    fray completions bash > ~/.bash_completion.d/fray
    fray completions zsh > ~/.zfunc/_fray
    fray completions fish > ~/.config/fish/completions/fray.fish

    # Or eval directly:
    eval "$(fray completions bash)"
    eval "$(fray completions zsh)"
    fray completions fish | source
"""

# ── Subcommands and their descriptions ──────────────────────────────────────

# Visible top-level commands (shown in fray --help / fray help)
_VISIBLE_COMMANDS = {
    "go": "Full pipeline: recon + smart test + report",
    "recon": "Reconnaissance & fingerprinting (35+ checks)",
    "test": "Test WAF with payloads",
    "scan": "Auto crawl, discover, inject",
    "monitor": "Continuous monitoring with alerts",
    "report": "Reports (generate, company, waf, posture, diff, explain)",
    "intel": "Threat intelligence (feed, cve, poc-recheck, leak, osint, ct)",
    "auth": "Authentication (session, solve, cred)",
    "export": "Export (nuclei, ci)",
    "config": "Manage .fray.toml configuration",
    "plugin": "Plugin system",
    "cache": "Adaptive payload cache & stats",
    "update": "Update payload database",
    "dashboard": "Launch local web dashboard",
    "mcp": "Start MCP server for AI assistants",
    "completions": "Generate shell completion scripts",
    "ask": "Natural language query",
    "learn": "Interactive security tutorial",
    "doctor": "Check environment & auto-fix issues",
    "help": "Show friendly guide to all commands",
}

# All subcommands (including hidden/deprecated, for backward-compat completion)
_SUBCOMMANDS = {
    **_VISIBLE_COMMANDS,
    "detect": "Detect WAF vendor on target URL",
    "bypass": "WAF bypass scoring with evasion scorecard",
    "ai-bypass": "AI-assisted WAF bypass with LLM-generated payloads",
    "agent": "Self-improving payload agent: probe, mutate, learn",
    "feed": "Threat intelligence feed: auto-discover CVEs and attack vectors",
    "sync": "Cloud sync: publish or pull payload database",
    "todo": "Internal TODO list",
    "harden": "OWASP hardening audit with security header checks",
    "auto": "Full pipeline: recon, scan, ai-bypass in one command",
    "diff": "Compare two scan results and surface regressions",
    "smuggle": "HTTP request smuggling detection",
    "payloads": "List available payload categories",
    "graph": "Visualize attack surface tree",
    "stats": "Show payload database statistics",
    "version": "Show version",
    "submit-payload": "Submit payload to community database via GitHub PR",
    "validate": "Validate WAF configuration (blue team report)",
    "bounty": "Bug bounty platform integration",
    "ci": "Generate GitHub Actions workflow for WAF testing",
    "init-config": "Create sample .fray.toml config file",
    "init": "Initialize project: .fray.toml + auth template + scope file",
    "template": "Run YAML security check templates (nuclei-like DSL)",
    "explain": "Explain a CVE or scan results",
    "scope": "Inspect or validate a scope file",
    "leak": "Search for leaked credentials on GitHub and HIBP",
    "osint": "Offensive OSINT: whois, emails, GitHub org recon",
    "cred": "Credential stuffing test against login endpoints",
    "demo": "Quick showcase: detect WAF + XSS scan",
}

# Namespace subcommand completions
_NAMESPACE_SUBS = {
    "report": ["generate", "company", "waf", "posture", "diff", "explain"],
    "intel": ["feed", "cve", "poc-recheck", "leak", "osint", "ct"],
    "auth": ["session", "solve", "cred"],
    "export": ["nuclei", "ci"],
    "cache": ["show", "clear", "stats", "export", "import"],
    "config": ["init", "show", "validate", "set", "get"],
    "template": ["run", "list", "validate", "new"],
}

# ── Common flags per subcommand ─────────────────────────────────────────────

_GLOBAL_FLAGS = [
    "--help", "-h",
]

_TARGET_COMMANDS = {
    "recon", "detect", "test", "bypass", "ai-bypass", "agent", "scan",
    "graph", "harden", "auto", "smuggle", "validate", "leak", "osint",
    "cred", "monitor", "demo", "explain",
}

_COMMON_FLAGS = {
    "recon": [
        "--fast", "--deep", "--stealth", "--timeout", "--json", "--output",
        "--cookie", "--bearer", "--header", "--insecure", "--quiet", "--verbose",
        "--profile", "--retirejs", "--history", "--js", "--params", "--leak",
        "--notify", "--ai-summary",
    ],
    "detect": [
        "--timeout", "--json", "--insecure", "--cookie", "--bearer", "--header",
        "--quiet", "--verbose",
    ],
    "test": [
        "--category", "--payload-file", "--timeout", "--delay", "--profile",
        "--all", "--max", "--output", "--smart", "--webhook", "--insecure",
        "--cookie", "--bearer", "--header", "--verbose", "--json", "--ai",
        "--sarif", "--mutate", "--blind", "--oob-server", "--auth-profile",
        "--stealth", "--rate-limit", "--jitter", "--quiet", "--resume",
        "--report-format", "--scope", "--notify", "--param", "--context",
        "--content-type", "--from-crawl", "--concurrency",
    ],
    "bypass": [
        "--waf", "--category", "--max", "--mutations", "--mutation-budget",
        "--param", "--timeout", "--delay", "--output", "--json", "--insecure",
        "--verbose", "--list-wafs", "--scope", "--cookie", "--bearer",
        "--header", "--stealth", "--rate-limit", "--jitter",
        "--burp", "--zap", "--nuclei-export", "--share",
    ],
    "ai-bypass": [
        "--category", "--param", "--rounds", "--max-per-round", "--no-headers",
        "--timeout", "--delay", "--output", "--json", "--insecure", "--cookie",
        "--bearer", "--header", "--stealth", "--rate-limit", "--jitter", "--scope",
    ],
    "agent": [
        "--category", "--param", "--rounds", "--budget", "--ai", "--no-cache",
        "--timeout", "--delay", "--output", "--json", "--insecure", "--cookie",
        "--bearer", "--header", "--stealth", "--rate-limit", "--jitter",
        "--scope", "--notify",
    ],
    "scan": [
        "--category", "--max", "--depth", "--max-pages", "--timeout", "--delay",
        "--output", "--json", "--ai", "--sarif", "--insecure", "--cookie",
        "--bearer", "--header", "--stealth", "--rate-limit", "--jitter",
        "--scope", "--workers", "--auto-throttle", "--browser", "--burp",
        "--zap", "--nuclei-export", "--burp-import", "--blind", "--oob-server",
        "--auth-profile", "--notify",
    ],
    "auto": [
        "--category", "--param", "--max", "--rounds", "--timeout", "--delay",
        "--output", "--json", "--insecure", "--cookie", "--bearer", "--header",
        "--stealth", "--scope", "--skip-recon", "--skip-scan", "--skip-bypass",
    ],
    "graph": [
        "--deep", "--timeout", "--json", "--output", "--cookie", "--bearer",
        "--header",
    ],
    "feed": [
        "--sources", "--since", "--category", "--auto-add", "--dry-run",
        "--list-sources", "--test-target", "--delay", "--timeout", "--insecure",
        "--json", "--output", "--notify",
    ],
    "diff": ["--output", "--json"],
    "report": ["--input", "--output", "--sample", "--format"],
    "smuggle": ["--timeout", "--delay", "--output", "--json", "--insecure"],
    "harden": ["--json", "--output"],
    "stats": ["--json"],
    "validate": [
        "--waf", "--categories", "--max", "--output", "--timeout", "--delay",
        "--verbose",
    ],
    "bounty": [
        "--platform", "--program", "--urls", "--categories", "--max",
        "--timeout", "--delay", "--output", "--scope-only", "--force",
        "--no-smart", "--workers",
    ],
    "leak": [
        "--github-only", "--hibp-only", "--json", "--output", "--timeout",
        "--notify",
    ],
    "osint": [
        "--json", "--output", "--timeout", "--whois", "--emails", "--github",
        "--docs", "--permutations", "--notify",
    ],
    "cred": [
        "--pairs", "--username-field", "--password-field", "--content-type",
        "--rate", "--delay", "--max", "--proxy", "--dry-run", "--timeout",
        "--json", "--output", "--cookie", "--bearer", "--header", "--notify",
    ],
    "monitor": [
        "--interval", "--notify", "--email", "--leak", "--once", "--list",
        "--timeout", "--json", "--output",
    ],
    "go": [
        "--category", "--deep", "--stealth", "--profile", "--output",
        "--json", "--timeout", "--delay", "--cookie", "--bearer", "--header",
        "--sarif", "--fail-on", "--solve-challenge", "--impersonate",
    ],
    "dashboard": ["--port", "--no-open", "--json", "--summary"],
    "ask": ["--json"],
    "help": ["--all", "--man"],
    "update": ["--source", "--json"],
    "sync": ["--push", "--pull", "--source", "--tag", "--configure", "--status", "--json"],
    "doctor": ["--fix", "--verbose", "--json"],
    "ci": ["--target", "--categories", "--max", "--notify", "--fail-on-bypass", "--no-comment", "--minimal", "--output-dir"],
    "learn": ["--level", "--list", "--reset"],
    "explain": ["--max", "--json", "--output"],
    "scope": ["--check", "--json"],
    "submit-payload": [
        "--payload", "--category", "--subcategory", "--description",
        "--technique", "--name", "--github", "--file", "--dry-run",
    ],
}

_WAF_VENDORS = [
    "cloudflare", "akamai", "aws_waf", "imperva", "f5", "fastly",
    "modsecurity", "sucuri", "barracuda", "fortiweb", "radware",
    "citrix", "wallarm", "reblaze", "stackpath", "edgecast",
    "azure_front_door", "google_cloud_armor", "squarespace", "wordfence",
]

_CATEGORIES = [
    "xss", "sqli", "ssrf", "ssti", "xxe", "command_injection",
    "path_traversal", "open_redirect", "crlf_injection", "ldap_injection",
    "nosql_injection", "prototype_pollution", "csp_bypass", "cors",
    "api_security", "ai_prompt_injection", "modern_bypasses",
    "unicode_bypass", "encoding_bypass", "waf_bypass",
]

_PROFILES = ["quick", "standard", "deep", "stealth", "api", "bounty"]

_REPORT_FORMATS = ["html", "markdown"]

_SYNC_SOURCES = ["auto", "r2", "github"]

_LEARN_TOPICS = ["xss", "sqli", "ssrf", "cmdi"]

_SHELLS = ["bash", "zsh", "fish"]


# ── Bash Completion ─────────────────────────────────────────────────────────

def generate_bash() -> str:
    subcmds = " ".join(sorted(_SUBCOMMANDS.keys()))
    lines = [
        '# Fray bash completion — generated by `fray completions bash`',
        '# Add to ~/.bashrc: eval "$(fray completions bash)"',
        '',
        '_fray_completions() {',
        '    local cur prev subcmd',
        '    COMPREPLY=()',
        '    cur="${COMP_WORDS[COMP_CWORD]}"',
        '    prev="${COMP_WORDS[COMP_CWORD-1]}"',
        '',
        '    # Find subcommand',
        '    subcmd=""',
        '    for ((i=1; i<COMP_CWORD; i++)); do',
        '        case "${COMP_WORDS[i]}" in',
        f'            {"|".join(sorted(_SUBCOMMANDS.keys()))})',
        '                subcmd="${COMP_WORDS[i]}"',
        '                break',
        '                ;;',
        '        esac',
        '    done',
        '',
        '    # Complete subcommand',
        '    if [[ -z "$subcmd" ]]; then',
        f'        COMPREPLY=($(compgen -W "{subcmds}" -- "$cur"))',
        '        return 0',
        '    fi',
        '',
        '    # Complete --waf values',
        '    case "$prev" in',
        '        --waf)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_WAF_VENDORS)}" -- "$cur"))',
        '            return 0',
        '            ;;',
        '        -c|--category)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_CATEGORIES)}" -- "$cur"))',
        '            return 0',
        '            ;;',
        '        --profile)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_PROFILES)}" -- "$cur"))',
        '            return 0',
        '            ;;',
        '        --format|--report-format)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_REPORT_FORMATS)}" -- "$cur"))',
        '            return 0',
        '            ;;',
        '        --source)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_SYNC_SOURCES)}" -- "$cur"))',
        '            return 0',
        '            ;;',
        '    esac',
        '',
        '    # Complete flags per subcommand',
        '    case "$subcmd" in',
    ]

    for cmd in sorted(_COMMON_FLAGS.keys()):
        if cmd in _NAMESPACE_SUBS:
            continue  # handled below with subcommand-aware logic
        flags = " ".join(_COMMON_FLAGS[cmd] + _GLOBAL_FLAGS)
        lines.append(f'        {cmd})')
        lines.append(f'            COMPREPLY=($(compgen -W "{flags}" -- "$cur"))')
        lines.append('            ;;')

    # Namespace subcommand completions (fray report <tab>, fray intel <tab>, etc.)
    for ns, subs in sorted(_NAMESPACE_SUBS.items()):
        lines.append(f'        {ns})')
        lines.append(f'            if [[ $COMP_CWORD -eq 2 ]]; then')
        lines.append(f'                COMPREPLY=($(compgen -W "{" ".join(subs)}" -- "$cur"))')
        lines.append(f'            else')
        ns_flags = " ".join(_COMMON_FLAGS.get(ns, []) + _GLOBAL_FLAGS)
        if ns_flags.strip():
            lines.append(f'                COMPREPLY=($(compgen -W "{ns_flags}" -- "$cur"))')
        lines.append(f'            fi')
        lines.append('            ;;')

    lines += [
        '        completions)',
        f'            COMPREPLY=($(compgen -W "{" ".join(_SHELLS)}" -- "$cur"))',
        '            ;;',
        '    esac',
        '    return 0',
        '}',
        '',
        'complete -o default -F _fray_completions fray',
        '',
    ]
    return "\n".join(lines)


# ── Zsh Completion ──────────────────────────────────────────────────────────

def generate_zsh() -> str:
    lines = [
        '#compdef fray',
        '# Fray zsh completion — generated by `fray completions zsh`',
        '# Add to ~/.zshrc: eval "$(fray completions zsh)"',
        '# Or save to: ~/.zfunc/_fray (add fpath=(~/.zfunc $fpath) before compinit)',
        '',
        '_fray() {',
        '    local -a commands',
        '    commands=(',
    ]

    for cmd in sorted(_SUBCOMMANDS.keys()):
        desc = _SUBCOMMANDS[cmd].replace("'", "\\'")
        lines.append(f"        '{cmd}:{desc}'")

    lines += [
        '    )',
        '',
        '    _arguments -C \\',
        "        '1:command:->command' \\",
        "        '*::arg:->args'",
        '',
        '    case $state in',
        '        command)',
        '            _describe "fray command" commands',
        '            ;;',
        '        args)',
        '            case $words[1] in',
    ]

    for cmd in sorted(_COMMON_FLAGS.keys()):
        if cmd in _NAMESPACE_SUBS:
            continue  # handled below with subcommand-aware logic
        flags = _COMMON_FLAGS[cmd]
        lines.append(f'                {cmd})')
        lines.append('                    _arguments \\')
        for i, flag in enumerate(flags):
            sep = " \\" if i < len(flags) - 1 else ""
            lines.append(f"                        '{flag}'{sep}")
        if cmd in _TARGET_COMMANDS:
            lines.append("                        ':target:_urls'")
        lines.append('                    ;;')

    # Namespace subcommand completions (fray report <tab>, fray intel <tab>, etc.)
    for ns, subs in sorted(_NAMESPACE_SUBS.items()):
        lines.append(f'                {ns})')
        lines.append('                    if (( CURRENT == 2 )); then')
        subs_str = " ".join(f"'{s}'" for s in subs)
        lines.append(f'                        _values "subcommand" {subs_str}')
        lines.append('                    else')
        ns_flags = _COMMON_FLAGS.get(ns, [])
        if ns_flags:
            lines.append('                        _arguments \\')
            for i, flag in enumerate(ns_flags):
                sep = " \\" if i < len(ns_flags) - 1 else ""
                lines.append(f"                            '{flag}'{sep}")
        lines.append('                    fi')
        lines.append('                    ;;')

    lines += [
        '                completions)',
        f'                    _values "shell" {" ".join(_SHELLS)}',
        '                    ;;',
        '            esac',
        '            ;;',
        '    esac',
        '}',
        '',
        '_fray',
        '',
    ]
    return "\n".join(lines)


# ── Fish Completion ─────────────────────────────────────────────────────────

def generate_fish() -> str:
    lines = [
        '# Fray fish completion — generated by `fray completions fish`',
        '# Save to: ~/.config/fish/completions/fray.fish',
        '# Or eval: fray completions fish | source',
        '',
        '# Disable file completion by default',
        'complete -c fray -f',
        '',
        '# Subcommands',
    ]

    for cmd in sorted(_SUBCOMMANDS.keys()):
        desc = _SUBCOMMANDS[cmd].replace("'", "\\'")
        lines.append(
            f"complete -c fray -n '__fish_use_subcommand' "
            f"-a '{cmd}' -d '{desc}'"
        )

    lines.append('')
    lines.append('# Flags per subcommand')

    for cmd in sorted(_COMMON_FLAGS.keys()):
        for flag in _COMMON_FLAGS[cmd]:
            short = flag.lstrip('-')
            # Handle short flags
            if flag.startswith('--'):
                lines.append(
                    f"complete -c fray -n '__fish_seen_subcommand_from {cmd}' "
                    f"-l '{short}'"
                )
            else:
                lines.append(
                    f"complete -c fray -n '__fish_seen_subcommand_from {cmd}' "
                    f"-s '{short}'"
                )

    lines.append('')
    lines.append('# --waf values')
    for v in _WAF_VENDORS:
        lines.append(
            f"complete -c fray -n '__fish_seen_subcommand_from bypass validate' "
            f"-l waf -ra '{v}'"
        )

    lines.append('')
    lines.append('# --category values')
    for v in _CATEGORIES:
        lines.append(
            f"complete -c fray -n '__fish_seen_subcommand_from test bypass ai-bypass agent scan auto feed' "
            f"-s c -l category -ra '{v}'"
        )

    lines.append('')
    lines.append('# --profile values')
    for v in _PROFILES:
        lines.append(
            f"complete -c fray -n '__fish_seen_subcommand_from recon test' "
            f"-l profile -ra '{v}'"
        )

    lines.append('')
    lines.append('# Namespace subcommands (fray report <tab>, fray intel <tab>, etc.)')
    for ns, subs in sorted(_NAMESPACE_SUBS.items()):
        for sub in subs:
            lines.append(
                f"complete -c fray -n '__fish_seen_subcommand_from {ns}' "
                f"-a '{sub}'"
            )

    lines.append('')
    lines.append('# completions subcommand')
    for s in _SHELLS:
        lines.append(
            f"complete -c fray -n '__fish_seen_subcommand_from completions' "
            f"-a '{s}'"
        )

    lines.append('')
    return "\n".join(lines)


# ── Public API ──────────────────────────────────────────────────────────────

def generate_completion(shell: str) -> str:
    """Generate shell completion script for the given shell."""
    generators = {
        "bash": generate_bash,
        "zsh": generate_zsh,
        "fish": generate_fish,
    }
    fn = generators.get(shell)
    if not fn:
        raise ValueError(f"Unsupported shell: {shell}. Use: {', '.join(generators)}")
    return fn()
