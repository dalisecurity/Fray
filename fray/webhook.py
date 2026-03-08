#!/usr/bin/env python3
"""
Fray Webhook — Send scan notifications to Slack, Discord, and Microsoft Teams

Usage:
    fray test https://target.com --webhook https://hooks.slack.com/services/xxx
    fray test https://target.com --webhook https://discord.com/api/webhooks/xxx
    fray test https://target.com --webhook https://outlook.office.com/webhook/xxx

Auto-detects the platform from the URL and formats the message accordingly.
Uses only Python stdlib (http.client + json) — zero dependencies.
"""

import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse
from typing import Dict, Optional


class Colors:
    """Terminal colors"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    DIM = '\033[2m'
    END = '\033[0m'


def detect_platform(webhook_url: str) -> str:
    """Auto-detect webhook platform from URL."""
    url_lower = webhook_url.lower()
    if "hooks.slack.com" in url_lower or "slack.com/api" in url_lower:
        return "slack"
    elif "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
        return "discord"
    elif "office.com" in url_lower or "webhook.office" in url_lower or "microsoft" in url_lower:
        return "teams"
    else:
        return "generic"


def _build_slack_payload(report: Dict) -> Dict:
    """Build Slack Block Kit message."""
    summary = report.get("summary", {})
    target = report.get("target", "unknown")
    total = summary.get("total", 0)
    blocked = summary.get("blocked", 0)
    passed = summary.get("passed", 0)
    block_rate = summary.get("block_rate", "N/A")
    duration = report.get("duration", "N/A")

    status_emoji = ":white_check_mark:" if passed == 0 else ":warning:"
    if total > 0 and passed / total > 0.3:
        status_emoji = ":rotating_light:"

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Fray Scan Complete",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{duration}"},
                    {"type": "mrkdwn", "text": f"*Total Payloads:*\n{total}"},
                    {"type": "mrkdwn", "text": f"*Block Rate:*\n{block_rate}"},
                    {"type": "mrkdwn", "text": f"*Blocked:*\n:shield: {blocked}"},
                    {"type": "mrkdwn", "text": f"*Bypassed:*\n:unlock: {passed}"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Powered by <https://github.com/dalisecurity/fray|Fray> — DALI Security"
                    }
                ]
            }
        ]
    }


def _build_discord_payload(report: Dict) -> Dict:
    """Build Discord embed message."""
    summary = report.get("summary", {})
    target = report.get("target", "unknown")
    total = summary.get("total", 0)
    blocked = summary.get("blocked", 0)
    passed = summary.get("passed", 0)
    block_rate = summary.get("block_rate", "N/A")
    duration = report.get("duration", "N/A")

    color = 0x22C55E if passed == 0 else (0xEF4444 if total > 0 and passed / total > 0.3 else 0xEAB308)

    return {
        "embeds": [
            {
                "title": "Fray Scan Complete",
                "color": color,
                "fields": [
                    {"name": "Target", "value": f"`{target}`", "inline": False},
                    {"name": "Total Payloads", "value": str(total), "inline": True},
                    {"name": "Blocked", "value": str(blocked), "inline": True},
                    {"name": "Bypassed", "value": str(passed), "inline": True},
                    {"name": "Block Rate", "value": block_rate, "inline": True},
                    {"name": "Duration", "value": duration, "inline": True},
                ],
                "footer": {
                    "text": "Fray — DALI Security | github.com/dalisecurity/fray"
                }
            }
        ]
    }


def _build_teams_payload(report: Dict) -> Dict:
    """Build Microsoft Teams Adaptive Card message."""
    summary = report.get("summary", {})
    target = report.get("target", "unknown")
    total = summary.get("total", 0)
    blocked = summary.get("blocked", 0)
    passed = summary.get("passed", 0)
    block_rate = summary.get("block_rate", "N/A")
    duration = report.get("duration", "N/A")

    status = "All Blocked" if passed == 0 else f"{passed} Bypassed"

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "22C55E" if passed == 0 else "EF4444",
        "summary": f"Fray Scan: {target}",
        "sections": [
            {
                "activityTitle": "Fray Scan Complete",
                "activitySubtitle": target,
                "facts": [
                    {"name": "Total Payloads", "value": str(total)},
                    {"name": "Blocked", "value": str(blocked)},
                    {"name": "Bypassed", "value": str(passed)},
                    {"name": "Block Rate", "value": block_rate},
                    {"name": "Duration", "value": duration},
                    {"name": "Status", "value": status},
                ],
                "markdown": True
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "View Fray on GitHub",
                "targets": [{"os": "default", "uri": "https://github.com/dalisecurity/fray"}]
            }
        ]
    }


def _build_generic_payload(report: Dict) -> Dict:
    """Build a simple JSON payload for unknown webhook endpoints."""
    summary = report.get("summary", {})
    return {
        "text": (
            f"Fray Scan Complete\n"
            f"Target: {report.get('target', 'unknown')}\n"
            f"Total: {summary.get('total', 0)} | "
            f"Blocked: {summary.get('blocked', 0)} | "
            f"Bypassed: {summary.get('passed', 0)} | "
            f"Block Rate: {summary.get('block_rate', 'N/A')}\n"
            f"Duration: {report.get('duration', 'N/A')}"
        )
    }


def _build_slack_recon_payload(data: Dict) -> Dict:
    """Build Slack Block Kit message for recon diff notifications."""
    target = data.get("target", "unknown")
    risk_level = data.get("risk_level", "?")
    risk_score = data.get("risk_score", 0)
    diff = data.get("diff", {})
    changes = diff.get("changes", [])
    n_high = diff.get("high_severity_changes", 0)
    findings = data.get("findings", [])

    # Emoji based on severity
    if n_high > 0:
        emoji = ":rotating_light:"
    elif changes:
        emoji = ":warning:"
    else:
        emoji = ":white_check_mark:"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Fray Recon Alert — {target}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Risk:* {risk_level} ({risk_score}/100)"},
                {"type": "mrkdwn", "text": f"*Changes:* {len(changes)} ({n_high} critical/high)"},
            ]
        },
    ]

    # List high/critical changes
    critical_changes = [c for c in changes if c.get("severity") in ("critical", "high")]
    if critical_changes:
        change_lines = []
        for c in critical_changes[:5]:
            field = c.get("field", "?")
            old_v = str(c.get("old", "—"))[:40]
            new_v = str(c.get("new", "—"))[:40]
            change_lines.append(f":red_circle: *{field}*: `{old_v}` → `{new_v}`")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(change_lines)}
        })

    # List current findings
    if findings:
        finding_lines = []
        for f in findings[:5]:
            sev = f.get("severity", "?")
            sev_emoji = {
                "critical": ":red_circle:",
                "high": ":large_orange_circle:",
                "medium": ":large_yellow_circle:",
                "low": ":white_circle:",
            }.get(sev, ":black_circle:")
            finding_lines.append(f"{sev_emoji} [{sev.upper()}] {f.get('finding', '?')}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Current Findings:*\n" + "\n".join(finding_lines)}
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn",
             "text": f"_Fray Recon • {data.get('timestamp', '')} • <https://github.com/dalisecurity/fray|dalisec.io>_"}
        ]
    })

    return {"blocks": blocks}


def _build_generic_recon_payload(data: Dict) -> Dict:
    """Build a generic JSON payload for recon notifications."""
    return {
        "text": (
            f"Fray Recon Alert: {data.get('target', '?')} — "
            f"Risk {data.get('risk_level', '?')} ({data.get('risk_score', 0)}/100), "
            f"{data.get('diff', {}).get('total_changes', 0)} change(s), "
            f"{data.get('diff', {}).get('high_severity_changes', 0)} critical/high"
        ),
        "data": data,
    }


def send_recon_notification(webhook_url: str, target: str,
                             recon_result: Dict,
                             diff: Optional[Dict] = None,
                             verbose: bool = False) -> bool:
    """Send recon results (optionally with diff) to a webhook.

    Args:
        webhook_url: Slack/Discord/Teams/generic webhook URL.
        target: Target URL that was scanned.
        recon_result: Full recon result dict.
        diff: Optional diff from diff_recon() (for --compare + --notify).
        verbose: Print debug info.

    Returns:
        True if sent successfully.
    """
    atk = recon_result.get("attack_surface", {})
    data = {
        "target": target,
        "risk_score": atk.get("risk_score", 0),
        "risk_level": atk.get("risk_level", "?"),
        "findings": atk.get("findings", []),
        "diff": diff or {"changes": [], "total_changes": 0, "high_severity_changes": 0},
        "timestamp": recon_result.get("timestamp", ""),
    }

    platform = detect_platform(webhook_url)
    if platform == "slack":
        payload = _build_slack_recon_payload(data)
    else:
        payload = _build_generic_recon_payload(data)

    # Reuse the same HTTP sending logic
    return _send_payload(webhook_url, payload, platform, verbose)


def _send_payload(webhook_url: str, payload: Dict, platform: str, verbose: bool = False) -> bool:
    """Low-level: POST a JSON payload to a webhook URL."""
    parsed = urllib.parse.urlparse(webhook_url)
    host = parsed.hostname
    port = parsed.port
    path = parsed.path
    if parsed.query:
        path = f"{path}?{parsed.query}"

    use_ssl = parsed.scheme == "https"
    if port is None:
        port = 443 if use_ssl else 80

    # SSRF prevention
    if host:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                print(f"  {Colors.RED}Webhook blocked{Colors.END}: destination resolves to private/internal IP ({ip})")
                return False
        except (socket.gaierror, ValueError):
            pass

    body = json.dumps(payload).encode("utf-8")

    if verbose:
        print(f"{Colors.DIM}Webhook platform: {platform}{Colors.END}")
        print(f"{Colors.DIM}Payload: {json.dumps(payload, indent=2)[:500]}{Colors.END}")

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)

        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "User-Agent": "Fray/3.0 (+https://github.com/dalisecurity/fray)",
        })

        resp = conn.getresponse()
        conn.close()

        if resp.status in (200, 201, 204):
            print(f"  {Colors.GREEN}Notification sent{Colors.END} ({platform}) — HTTP {resp.status}")
            return True
        else:
            resp_body = resp.read().decode("utf-8", errors="replace")[:200]
            print(f"  {Colors.RED}Notification failed{Colors.END} ({platform}) — HTTP {resp.status}: {resp_body}")
            return False

    except Exception as e:
        print(f"  {Colors.RED}Notification error{Colors.END}: {e}")
        return False


def send_generic_notification(webhook_url: str, command: str, target: str,
                               summary: Dict, verbose: bool = False) -> bool:
    """Send a notification for any fray command.

    Args:
        webhook_url: Slack/Discord/Teams/generic webhook URL.
        command: Command name (osint, cred, scan, leak, etc.).
        target: Target that was scanned.
        summary: Dict with key findings (varies per command).
        verbose: Print debug info.

    Returns:
        True if sent successfully.
    """
    platform = detect_platform(webhook_url)

    # Build platform-specific payload
    title = f"Fray {command.upper()} Complete"
    fields = [{"name": "Target", "value": target}]
    for k, v in summary.items():
        if k.startswith("_"):
            continue
        label = k.replace("_", " ").title()
        fields.append({"name": label, "value": str(v)})

    # Severity color
    severity = summary.get("_severity", "info")
    colors = {"critical": 0xEF4444, "high": 0xF97316, "medium": 0xEAB308,
              "low": 0x22C55E, "info": 0x3B82F6}
    color = colors.get(severity, 0x3B82F6)
    color_hex = f"{color:06X}"

    emojis = {"critical": ":rotating_light:", "high": ":warning:",
              "medium": ":large_yellow_circle:", "low": ":white_check_mark:",
              "info": ":mag:"}
    emoji = emojis.get(severity, ":mag:")

    if platform == "slack":
        slack_fields = [{"type": "mrkdwn", "text": f"*{f['name']}:*\n{f['value']}"} for f in fields[:8]]
        payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True}},
                {"type": "section", "fields": slack_fields},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": "Powered by <https://github.com/dalisecurity/fray|Fray> — DALI Security"}
                ]}
            ]
        }
    elif platform == "discord":
        discord_fields = [{"name": f["name"], "value": f["value"], "inline": True} for f in fields[:8]]
        payload = {
            "embeds": [{
                "title": title,
                "color": color,
                "fields": discord_fields,
                "footer": {"text": "Fray — DALI Security | github.com/dalisecurity/fray"}
            }]
        }
    elif platform == "teams":
        facts = [{"name": f["name"], "value": f["value"]} for f in fields[:8]]
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_hex,
            "summary": f"Fray {command}: {target}",
            "sections": [{"activityTitle": title, "activitySubtitle": target, "facts": facts, "markdown": True}]
        }
    else:
        lines = [f"{f['name']}: {f['value']}" for f in fields]
        payload = {"text": f"{title}\n" + "\n".join(lines)}

    return _send_payload(webhook_url, payload, platform, verbose)


def send_webhook(webhook_url: str, report: Dict, verbose: bool = False) -> bool:
    """
    Send scan results to a webhook URL.

    Args:
        webhook_url: Full webhook URL (Slack, Discord, Teams, or generic)
        report: Fray scan report dict with 'target', 'summary', 'duration', etc.
        verbose: Print debug info

    Returns:
        True if notification sent successfully, False otherwise.
    """
    platform = detect_platform(webhook_url)

    builders = {
        "slack": _build_slack_payload,
        "discord": _build_discord_payload,
        "teams": _build_teams_payload,
        "generic": _build_generic_payload,
    }
    payload = builders[platform](report)

    if verbose:
        print(f"{Colors.DIM}Webhook platform: {platform}{Colors.END}")
        print(f"{Colors.DIM}Payload: {json.dumps(payload, indent=2)[:500]}{Colors.END}")

    # Parse URL and send via stdlib http.client
    parsed = urllib.parse.urlparse(webhook_url)
    host = parsed.hostname
    port = parsed.port
    path = parsed.path
    if parsed.query:
        path = f"{path}?{parsed.query}"

    use_ssl = parsed.scheme == "https"
    if port is None:
        port = 443 if use_ssl else 80

    # Block webhooks to private/internal IPs (SSRF prevention)
    if host:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                print(f"  {Colors.RED}Webhook blocked{Colors.END}: destination resolves to private/internal IP ({ip})")
                return False
        except (socket.gaierror, ValueError):
            pass  # Let the connection attempt handle DNS failures

    body = json.dumps(payload).encode("utf-8")

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)

        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "User-Agent": "Fray/3.0 (+https://github.com/dalisecurity/fray)",
            }
        )

        resp = conn.getresponse()
        conn.close()

        if resp.status in (200, 201, 204):
            print(f"  {Colors.GREEN}Webhook sent{Colors.END} ({platform}) — HTTP {resp.status}")
            return True
        else:
            resp_body = resp.read().decode("utf-8", errors="replace")[:200]
            print(f"  {Colors.RED}Webhook failed{Colors.END} ({platform}) — HTTP {resp.status}: {resp_body}")
            return False

    except Exception as e:
        print(f"  {Colors.RED}Webhook error{Colors.END}: {e}")
        return False
