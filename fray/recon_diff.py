#!/usr/bin/env python3
"""
Fray Diff — Compare two recon reports and highlight attack surface changes.

Usage:
    fray diff report_old.json report_new.json
    fray diff report_old.json report_new.json --json
"""

import json
from typing import Dict, List, Optional, Tuple


def _set_diff(old: list, new: list) -> Tuple[list, list]:
    """Return (added, removed) between two lists."""
    old_s = set(str(x) for x in old)
    new_s = set(str(x) for x in new)
    return sorted(new_s - old_s), sorted(old_s - new_s)


def diff_reports(old: Dict, new: Dict) -> Dict:
    """Compare two recon result dicts and return structured diff.

    Returns dict with keys:
      - summary: {added, removed, changed} counts
      - sections: list of section diffs
    """
    sections = []

    # ── Risk score ────────────────────────────────────────────────────
    old_atk = old.get("attack_surface", {})
    new_atk = new.get("attack_surface", {})
    old_risk = old_atk.get("risk_score", 0)
    new_risk = new_atk.get("risk_score", 0)
    if old_risk != new_risk:
        delta = new_risk - old_risk
        direction = "increased" if delta > 0 else "decreased"
        sections.append({
            "section": "Risk Score",
            "type": "changed",
            "old": f"{old_risk}/100 ({old_atk.get('risk_level', '?')})",
            "new": f"{new_risk}/100 ({new_atk.get('risk_level', '?')})",
            "detail": f"Risk {direction} by {abs(delta)} points",
            "severity": "high" if delta > 10 else "medium" if delta > 0 else "low",
        })

    # ── WAF / CDN ─────────────────────────────────────────────────────
    old_waf = old_atk.get("waf_vendor", "")
    new_waf = new_atk.get("waf_vendor", "")
    if old_waf != new_waf:
        sections.append({
            "section": "WAF",
            "type": "changed",
            "old": old_waf or "None",
            "new": new_waf or "None",
            "severity": "high" if not new_waf else "medium",
        })

    # ── Subdomains ────────────────────────────────────────────────────
    old_subs = old.get("subdomains", {}).get("subdomains", [])
    new_subs = new.get("subdomains", {}).get("subdomains", [])
    added_subs, removed_subs = _set_diff(old_subs, new_subs)
    if added_subs:
        sections.append({
            "section": "Subdomains",
            "type": "added",
            "count": len(added_subs),
            "items": added_subs[:20],
            "severity": "medium",
        })
    if removed_subs:
        sections.append({
            "section": "Subdomains",
            "type": "removed",
            "count": len(removed_subs),
            "items": removed_subs[:20],
            "severity": "low",
        })

    # ── Findings ──────────────────────────────────────────────────────
    old_findings = old_atk.get("findings", [])
    new_findings = new_atk.get("findings", [])
    old_fkeys = {f"{f.get('type','')}/{f.get('title','')}" for f in old_findings}
    new_fkeys = {f"{f.get('type','')}/{f.get('title','')}" for f in new_findings}
    added_findings = new_fkeys - old_fkeys
    removed_findings = old_fkeys - new_fkeys
    if added_findings:
        sections.append({
            "section": "Findings",
            "type": "added",
            "count": len(added_findings),
            "items": sorted(added_findings)[:15],
            "severity": "high",
        })
    if removed_findings:
        sections.append({
            "section": "Findings",
            "type": "removed",
            "count": len(removed_findings),
            "items": sorted(removed_findings)[:15],
            "severity": "low",
        })

    # ── Attack Vectors ────────────────────────────────────────────────
    old_vecs = old_atk.get("attack_vectors", [])
    new_vecs = new_atk.get("attack_vectors", [])
    old_vtypes = {v.get("type", "") for v in old_vecs}
    new_vtypes = {v.get("type", "") for v in new_vecs}
    added_vecs = new_vtypes - old_vtypes
    removed_vecs = old_vtypes - new_vtypes
    if added_vecs:
        sections.append({
            "section": "Attack Vectors",
            "type": "added",
            "count": len(added_vecs),
            "items": sorted(added_vecs),
            "severity": "high",
        })
    if removed_vecs:
        sections.append({
            "section": "Attack Vectors",
            "type": "removed",
            "count": len(removed_vecs),
            "items": sorted(removed_vecs),
            "severity": "low",
        })

    # ── Security Headers ──────────────────────────────────────────────
    old_hdrs = old.get("headers", {})
    new_hdrs = new.get("headers", {})
    old_score = old_hdrs.get("score", 0)
    new_score = new_hdrs.get("score", 0)
    if old_score != new_score:
        sections.append({
            "section": "Headers Score",
            "type": "changed",
            "old": f"{old_score}/100",
            "new": f"{new_score}/100",
            "severity": "medium" if new_score < old_score else "low",
        })

    old_missing = set(old_hdrs.get("missing", {}).keys()) if isinstance(old_hdrs.get("missing"), dict) else set()
    new_missing = set(new_hdrs.get("missing", {}).keys()) if isinstance(new_hdrs.get("missing"), dict) else set()
    now_present = old_missing - new_missing  # Were missing, now present = improved
    now_missing = new_missing - old_missing  # Were present, now missing = regressed
    if now_present:
        sections.append({
            "section": "Security Headers",
            "type": "improved",
            "count": len(now_present),
            "items": sorted(now_present),
            "severity": "low",
        })
    if now_missing:
        sections.append({
            "section": "Security Headers",
            "type": "regressed",
            "count": len(now_missing),
            "items": sorted(now_missing),
            "severity": "high",
        })

    # ── Technologies ──────────────────────────────────────────────────
    old_techs = set(old.get("fingerprint", {}).get("technologies", {}).keys())
    new_techs = set(new.get("fingerprint", {}).get("technologies", {}).keys())
    added_techs = new_techs - old_techs
    removed_techs = old_techs - new_techs
    if added_techs:
        sections.append({
            "section": "Technologies",
            "type": "added",
            "count": len(added_techs),
            "items": sorted(added_techs),
            "severity": "medium",
        })
    if removed_techs:
        sections.append({
            "section": "Technologies",
            "type": "removed",
            "count": len(removed_techs),
            "items": sorted(removed_techs),
            "severity": "low",
        })

    # ── Admin Panels ──────────────────────────────────────────────────
    old_admin = old.get("admin_panels", {})
    new_admin = new.get("admin_panels", {})
    old_panels = set(str(p) for p in (old_admin.get("panels_found", []) or old_admin.get("found", []) or []))
    new_panels = set(str(p) for p in (new_admin.get("panels_found", []) or new_admin.get("found", []) or []))
    added_panels = new_panels - old_panels
    if added_panels:
        sections.append({
            "section": "Admin Panels",
            "type": "added",
            "count": len(added_panels),
            "items": sorted(added_panels)[:10],
            "severity": "high",
        })

    # ── Summary ───────────────────────────────────────────────────────
    n_added = sum(1 for s in sections if s["type"] in ("added", "regressed"))
    n_removed = sum(1 for s in sections if s["type"] in ("removed", "improved"))
    n_changed = sum(1 for s in sections if s["type"] == "changed")

    return {
        "summary": {
            "added": n_added,
            "removed": n_removed,
            "changed": n_changed,
            "total_changes": len(sections),
        },
        "sections": sections,
        "old_target": old.get("host", "?"),
        "new_target": new.get("host", "?"),
    }


def print_diff(diff: Dict):
    """Pretty-print a diff result to terminal."""
    summary = diff["summary"]
    sections = diff["sections"]

    print(f"\n  ⚔  Fray Diff — Attack Surface Changes")
    print(f"  {'─' * 50}")
    print(f"  Target: {diff.get('new_target', '?')}")
    print(f"  Changes: {summary['total_changes']} "
          f"(+{summary['added']} added, -{summary['removed']} removed, "
          f"~{summary['changed']} changed)\n")

    if not sections:
        print(f"  ✔ No changes detected.")
        return

    _SEV_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[90m"}
    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _TYPE_ICONS = {
        "added": "+", "removed": "-", "changed": "~",
        "improved": "↑", "regressed": "↓",
    }

    for s in sections:
        icon = _TYPE_ICONS.get(s["type"], "•")
        sev_c = _SEV_COLORS.get(s.get("severity", "low"), "")
        section = s["section"]

        if s["type"] == "changed":
            print(f"  {sev_c}{icon}{_RESET} {_BOLD}{section}{_RESET}: "
                  f"{s.get('old', '')} → {s.get('new', '')}"
                  f"{' — ' + s['detail'] if s.get('detail') else ''}")
        else:
            count = s.get("count", 0)
            label = s["type"].upper()
            print(f"  {sev_c}{icon}{_RESET} {_BOLD}{section}{_RESET}: "
                  f"{count} {label}")
            for item in s.get("items", [])[:5]:
                print(f"    {sev_c}{'+ ' if 'add' in s['type'] else '- '}{_RESET}{item}")
            if count > 5:
                print(f"    ... and {count - 5} more")

    print()
