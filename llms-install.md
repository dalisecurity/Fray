# Fray MCP Server — Installation Guide for AI Agents

## Quick Install

```bash
pip install 'fray[mcp]'
```

## Verify Installation

```bash
python -m fray.mcp_server --help
```

## Configure MCP Client

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "fray": {
      "command": "python",
      "args": ["-m", "fray.mcp_server"]
    }
  }
}
```

## Requirements

- Python 3.9+
- No API keys required
- No environment variables required
- Zero external dependencies (pure Python stdlib)

## What Fray Provides

10 MCP tools for WAF security testing:

1. **list_payload_categories** — List all 24 attack categories
2. **get_payloads** — Retrieve payloads by category (xss, sqli, ssrf, etc.)
3. **search_payloads** — Full-text search across 5,500+ payloads
4. **get_waf_signatures** — WAF fingerprints for 25 vendors
5. **get_cve_details** — CVE lookup with payloads and severity
6. **suggest_payloads_for_waf** — Best bypass payloads for a specific WAF
7. **analyze_scan_results** — Risk assessment from scan/test JSON
8. **generate_bypass_strategy** — Mutation strategies for blocked payloads
9. **explain_vulnerability** — Beginner-friendly payload explanation
10. **create_custom_payload** — Generate payloads from natural language

## Troubleshooting

If `python` doesn't resolve, try `python3`:

```json
{
  "mcpServers": {
    "fray": {
      "command": "python3",
      "args": ["-m", "fray.mcp_server"]
    }
  }
}
```

Or use `uvx` (no install needed):

```json
{
  "mcpServers": {
    "fray": {
      "command": "uvx",
      "args": ["fray"]
    }
  }
}
```
