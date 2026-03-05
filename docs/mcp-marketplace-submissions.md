# Fray — MCP Marketplace Submission Guide

Checklist of all MCP directories, registries, and marketplaces where Fray should be listed.

## ✅ Already Listed

### 1. Official MCP Registry
- **URL:** https://registry.modelcontextprotocol.io
- **Status:** ✅ Listed
- **Listing:** `io-github-dalisecurity-fray`
- **How it got there:** Published via the official MCP Registry process

### 2. MCP Marketplace (mcp-marketplace.io)
- **URL:** https://mcp-marketplace.io/server/io-github-dalisecurity-fray
- **Status:** ✅ Listed (auto-synced from Official MCP Registry)
- **Action needed:** Claim ownership at https://mcp-marketplace.io/signup?claim=io-github-dalisecurity-fray
- **Note:** Set GitHub org avatar at https://github.com/organizations/dalisecurity/settings to fix the profile image

---

## ⬜ Pending Submissions

### 3. Smithery.ai
- **URL:** https://smithery.ai
- **Submit:** https://smithery.ai/new (sign in with GitHub)
- **Requirements:**
  - GitHub repo URL
  - `smithery.yaml` in repo root (✅ already created)
- **Steps:**
  1. Go to https://smithery.ai/new
  2. Sign in with the `dalisecurity` GitHub account
  3. Select the `dalisecurity/fray` repository
  4. Smithery reads `smithery.yaml` automatically
  5. Confirm and publish

### 4. Glama.ai
- **URL:** https://glama.ai/mcp/servers
- **How:** Auto-indexes from GitHub. May already be indexed.
- **Steps:**
  1. Search for "fray" at https://glama.ai/mcp/servers
  2. If not listed, it should auto-appear within days
  3. Claim ownership if needed to update metadata
- **Note:** Glama scrapes GitHub and the official MCP registry. No manual submission required.

### 5. PulseMCP
- **URL:** https://www.pulsemcp.com/servers
- **How:** Ingests from the Official MCP Registry daily, processes weekly.
- **Steps:**
  1. Since Fray is on the Official MCP Registry, PulseMCP should auto-ingest it
  2. If not listed after a week, email hello@pulsemcp.com
  3. Or submit manually at https://www.pulsemcp.com/submit

### 6. mcp.so
- **URL:** https://mcp.so
- **How:** Community-driven directory
- **Steps:**
  1. Check if already listed: https://mcp.so search "fray"
  2. If not, submit via GitHub or their submission process
  3. Check their site for a submit/add button

### 7. Cline MCP Marketplace
- **URL:** https://github.com/cline/mcp-marketplace
- **Submit:** Open a new issue at https://github.com/cline/mcp-marketplace/issues/new?template=mcp-server-submission.yml
- **Requirements:**
  - GitHub Repo URL: `https://github.com/dalisecurity/fray`
  - Logo Image: 400×400 PNG → `.github/fray-icon.png` (✅ already created, 512×512 — resize to 400×400)
  - Reason for addition
  - Confirm Cline can install using README.md / llms-install.md
- **Steps:**
  1. Go to the issue template link above
  2. Fill in:
     - **GitHub Repo URL:** `https://github.com/dalisecurity/fray`
     - **Logo:** Upload `.github/fray-icon.png`
     - **Reason:** "Fray is an open-source WAF security testing toolkit with 5,500+ payloads, 25 WAF fingerprints, and 10 MCP tools. It enables AI assistants to search attack payloads, generate bypass strategies, analyze scan results, and explain vulnerabilities — all without API keys or external dependencies."
  3. Confirm that `llms-install.md` is in the repo (✅ done)
  4. Submit

### 8. awesome-mcp-servers (GitHub)
- **URL:** https://github.com/punkpeye/awesome-mcp-servers
- **How:** Submit a Pull Request
- **Steps:**
  1. Fork the repo
  2. Add Fray to the Security section:
     ```markdown
     - [Fray](https://github.com/dalisecurity/fray) 🐍 - WAF security testing: 5,500+ payloads, 25 WAF fingerprints, bypass strategies, vulnerability explanations
     ```
  3. Open PR

### 9. mcp.run
- **URL:** https://www.mcp.run/registry
- **Note:** mcp.run is WASM-based. Fray is a Python stdlib project — **not compatible** unless wrapped.
- **Status:** ⬜ Skip for now

---

## Submission Copy (reuse across platforms)

### Short Description (one-liner)
WAF security testing: 5,500+ payloads, 25 WAF fingerprints, 21 recon checks, bypass AI

### Medium Description
Open-source WAF security testing toolkit with 5,500+ attack payloads, 25 WAF fingerprints, and 10 MCP tools. Search payloads, get bypass strategies, analyze scan results, explain vulnerabilities, and generate custom payloads — all from your AI assistant.

### Tags / Categories
`security`, `penetration-testing`, `web-security`, `waf`, `xss`, `sqli`, `ssrf`, `payloads`, `owasp`, `bypass`, `vulnerability`, `cybersecurity`, `cve`

### Install Command
```bash
pip install 'fray[mcp]'
```

### MCP Config
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

### Logo
`.github/fray-icon.png` (512×512 purple F on dark navy)
Raw URL: `https://raw.githubusercontent.com/dalisecurity/fray/hugo/.github/fray-icon.png`
