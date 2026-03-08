# Fray Security Scanner — VS Code Extension

Run [Fray](https://github.com/dalisecurity/Fray) WAF/security scans directly from your editor. Scan, test, recon, and OSINT any URL without leaving VS Code.

<!-- ![Fray VS Code Extension](media/fray-icon.png) -->

## Features

- **Scan URL** — Crawl + param discovery + payload injection (`fray scan`)
- **Test URL** — Fire payloads against a specific endpoint (`fray test`)
- **Recon URL** — Reconnaissance: tech stack, headers, DNS, certs (`fray recon`)
- **OSINT Domain** — OSINT: whois, emails, GitHub org, typosquatting (`fray osint`)
- **Leak Search** — Search leaked credentials on GitHub + HIBP (`fray leak`)
- **Right-click** — Select a URL in any file and scan it from the context menu
- **Auto-detect** — Extracts URLs from the current line or selection
- **Inline diagnostics** — Bypass findings appear as warnings/errors in the editor
- **Results sidebar** — Browse findings in the Fray activity bar panel
- **Scan history** — View past scans with timestamps and finding counts
- **Status bar** — Shows scan progress with a spinning indicator
- **Webhook alerts** — Configure Slack/Discord/Teams notifications in settings

## Quick Start

1. Install the extension
2. Make sure Fray is installed: `pip install fray-security`
3. Open the command palette (`Cmd+Shift+P`) and type **Fray**
4. Select a command and enter a target URL

Or: select a URL in any file, right-click, and choose **Fray: Scan Selected URL**.

## Commands

| Command | Description | Keybinding |
|---------|-------------|------------|
| `Fray: Run Command...` | Quick pick menu for all Fray commands | `Cmd+Shift+F` |
| `Fray: Scan URL` | Full automated scan | — |
| `Fray: Test Payloads Against URL` | Payload injection test | — |
| `Fray: Recon URL` | Reconnaissance scan | — |
| `Fray: OSINT Domain` | OSINT intelligence gathering | — |
| `Fray: Leak Search` | Credential leak search | — |
| `Fray: Scan Selected URL` | Scan URL from text selection | Right-click menu |
| `Fray: Stop Running Scan` | Kill active scan | — |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `fray.pythonPath` | `python` | Path to Python interpreter with Fray installed |
| `fray.defaultCategory` | `xss` | Default payload category (`xss`, `sqli`, `rce`, `ssrf`, etc.) |
| `fray.maxPayloads` | `5` | Max payloads per injection point |
| `fray.timeout` | `8` | HTTP request timeout (seconds) |
| `fray.delay` | `0.5` | Delay between requests (seconds) |
| `fray.autoThrottle` | `false` | Auto-detect rate limits and adjust speed |
| `fray.stealth` | `false` | Randomize User-Agent, add jitter |
| `fray.browserMode` | `false` | Use Playwright for JS-heavy SPAs |
| `fray.notifyWebhook` | `""` | Slack/Discord/Teams webhook URL |
| `fray.showInlineFindings` | `true` | Show findings as editor diagnostics |

## Sidebar

The **Fray Security** activity bar icon opens two panels:

- **Scan Results** — Current scan findings grouped by bypasses and blocked payloads. Each finding shows bypass confidence, false positive score, and detailed tooltip.
- **History** — Recent scans with timestamps and result counts.

## Inline Diagnostics

When a scan completes, bypass findings appear as inline diagnostics:

- **Error** (red) — High-confidence bypass (confidence >= 70%)
- **Warning** (yellow) — Medium-confidence bypass
- **Info** (blue) — Likely false positive (FP score > 50%)

## Requirements

- [Fray](https://github.com/dalisecurity/Fray) installed (`pip install fray-security`)
- Python 3.8+
- Optional: [Playwright](https://playwright.dev/) for `--browser` mode

## Development

```bash
cd vscode-fray
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

To package for marketplace:

```bash
npm run package
# produces fray-security-0.1.0.vsix
```

## License

MIT — [DALI Security](https://github.com/dalisecurity)
