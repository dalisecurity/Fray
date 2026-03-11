"""v11 report CSS and SVG helpers."""
import html as _html
import math as _math
from typing import List

_esc = _html.escape
SEV_COLORS = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#22c55e'}

CSS = """:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--border:#475569;--text:#e2e8f0;--muted:#94a3b8;--accent:#6366f1;--accent2:#818cf8;--red:#ef4444;--orange:#f97316;--yellow:#eab308;--green:#22c55e;--blue:#3b82f6;--purple:#a855f7;--cyan:#06b6d4}*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}.wrap{max-width:1200px;margin:0 auto;padding:32px 24px}.hdr{background:linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#4c1d95 100%);padding:36px 44px;border-radius:16px;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;box-shadow:0 20px 60px rgba(99,102,241,.15);border:1px solid rgba(255,255,255,.08)}.hdr h1{font-size:1.8em;font-weight:700;letter-spacing:-.5px}.hdr .sub{font-size:.9em;opacity:.7;margin-top:4px}.hdr .logo{display:flex;flex-direction:column;line-height:1.15}.hdr .logo-name{font-size:24px;font-weight:800;letter-spacing:2px}.hdr .logo-sub{font-size:11px;letter-spacing:3px;opacity:.7;font-weight:600}.rbadge{background:rgba(255,255,255,.08);padding:16px 28px;border-radius:12px;text-align:center;border:1px solid rgba(255,255,255,.1)}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:24px}.mc{background:var(--surface);padding:20px;border-radius:12px;border:1px solid var(--border)}.mc .l{font-size:.75em;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:600;margin-bottom:4px}.mc .v{font-size:1.3em;font-weight:700}.sec{background:var(--surface);padding:28px 32px;border-radius:14px;margin-bottom:20px;border:1px solid var(--border)}.sec h2{font-size:1.35em;font-weight:700;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid var(--accent);display:flex;align-items:center;gap:10px}.sec h2 .count{font-size:.7em;font-weight:500;color:var(--muted)}table{width:100%;border-collapse:collapse;font-size:.9em}th{background:var(--surface2);color:var(--muted);padding:10px 14px;text-align:left;font-size:.8em;text-transform:uppercase;letter-spacing:.5px;font-weight:600}td{padding:9px 14px;border-bottom:1px solid rgba(71,85,105,.5)}tr:hover td{background:rgba(99,102,241,.04)}.kv-key{font-weight:600;color:var(--accent2);white-space:nowrap;width:180px}.mono{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:.88em}.num{text-align:right;font-variant-numeric:tabular-nums}.muted{color:var(--muted)}.finding{background:var(--surface2);padding:12px 16px;border-radius:8px;margin-bottom:8px;border-left:4px solid;display:flex;align-items:center;gap:10px;font-size:.92em}.sev-badge{padding:2px 10px;border-radius:4px;font-weight:700;font-size:.78em;letter-spacing:.5px;flex-shrink:0}.type-badge{padding:2px 10px;border-radius:4px;font-weight:600;font-size:.82em;white-space:nowrap}.tag{display:inline-block;padding:3px 10px;border-radius:5px;margin:2px;font-size:.82em;font-weight:600}.tag-ok{background:rgba(34,197,94,.15);color:var(--green)}.tag-miss{background:rgba(239,68,68,.15);color:var(--red)}details{margin-bottom:8px}details>summary{cursor:pointer;color:var(--accent2);font-weight:600;font-size:.9em;padding:6px 0;user-select:none}details>summary:hover{color:var(--accent)}.toc-link{display:inline-block;background:var(--surface2);color:var(--text);padding:5px 12px;border-radius:6px;text-decoration:none;font-size:.8em;font-weight:500;border:1px solid var(--border);transition:all .15s}.toc-link:hover{background:var(--accent);color:#fff;border-color:var(--accent)}.foot{text-align:center;padding:28px;color:var(--muted);font-size:.8em;margin-top:20px}.foot a{color:var(--accent2);text-decoration:none}@media print{body{background:#fff;color:#1a202c;-webkit-print-color-adjust:exact;print-color-adjust:exact}.wrap{padding:0;max-width:100%}.sec{border:1px solid #e2e8f0;box-shadow:none;background:#fff;page-break-inside:avoid;margin-bottom:16px}.hdr{background:#1e3a8a!important}th{background:#f1f5f9;color:#334155}td{border-color:#e2e8f0}.mc{background:#f8fafc;border-color:#e2e8f0}.finding{background:#f8fafc}.muted{color:#64748b}details{page-break-inside:avoid}table{page-break-inside:auto}tr{page-break-inside:avoid}h2{page-break-after:avoid}}@media(max-width:768px){.wrap{padding:16px 12px}.hdr{padding:20px 24px}.sec{padding:20px}}"""


def risk_color(score):
    if score >= 60: return '#ef4444'
    if score >= 40: return '#f97316'
    if score >= 20: return '#eab308'
    return '#22c55e'


def risk_grade(score):
    if score >= 80: return 'F'
    if score >= 60: return 'D'
    if score >= 40: return 'D'
    if score >= 20: return 'C'
    if score >= 10: return 'B'
    return 'A'


def gauge_svg(score):
    c = risk_color(score)
    pct = min(score, 100) / 100.0
    a = pct * 180
    r = _math.radians(a)
    ax, ay = 100 - 80*_math.cos(r), 100 - 80*_math.sin(r)
    la = 1 if a > 90 else 0
    nx, ny = 100 - 60*_math.cos(r), 100 - 60*_math.sin(r)
    rl = 'CRITICAL' if score >= 60 else 'HIGH' if score >= 40 else 'MEDIUM' if score >= 20 else 'LOW'
    return (f'<svg viewBox="0 0 200 130" style="width:200px;height:130px;">'
            f'<path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--surface2)" stroke-width="12" stroke-linecap="round"/>'
            f'<path d="M 20 100 A 80 80 0 {la} 1 {ax:.1f} {ay:.1f}" fill="none" stroke="{c}" stroke-width="12" stroke-linecap="round"/>'
            f'<line x1="100" y1="100" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{c}" stroke-width="3" stroke-linecap="round"/>'
            f'<circle cx="100" cy="100" r="5" fill="{c}"/>'
            f'<text x="100" y="82" text-anchor="middle" font-size="24" font-weight="800" fill="{c}">{score}</text>'
            f'<text x="100" y="124" text-anchor="middle" font-size="11" fill="var(--muted)" font-weight="600">{rl} RISK</text></svg>')


def donut_svg(counts: List[int], colors: List[str], total_label: int):
    total = max(sum(counts), 1)
    circ = 2 * _math.pi * 40
    arcs, off = '', 0.0
    for cnt, col in zip(counts, colors):
        if cnt > 0:
            d = (cnt/total)*circ
            arcs += f'<circle cx="60" cy="60" r="40" fill="none" stroke="{col}" stroke-width="14" stroke-dasharray="{d:.1f} {circ:.1f}" stroke-dashoffset="-{off:.1f}" transform="rotate(-90 60 60)"/>'
            off += d
    return (f'<svg viewBox="0 0 120 120" style="width:120px;height:120px;">'
            f'<circle cx="60" cy="60" r="40" fill="none" stroke="var(--surface2)" stroke-width="14"/>{arcs}'
            f'<text x="60" y="56" text-anchor="middle" font-size="22" font-weight="800" fill="var(--text)">{total_label}</text>'
            f'<text x="60" y="72" text-anchor="middle" font-size="9" fill="var(--muted)" font-weight="600">FINDINGS</text></svg>')
