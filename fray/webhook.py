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
