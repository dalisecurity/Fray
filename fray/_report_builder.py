"""v11 Recon Report HTML builder — called by SecurityReportGenerator._build_recon_html_v11()."""
import html as _html
from typing import Dict, Any
from fray._report_css import CSS, SEV_COLORS, risk_color, risk_grade, gauge_svg, donut_svg

_esc = _html.escape


def _targets_chips(items, limit=5):
    """Render a list of target URLs as code chips, with overflow."""
    chips = ''
    for t in items[:limit]:
        url = t if isinstance(t, str) else t.get('target', t.get('url', str(t)))
        chips += f'<code style="background:var(--surface2);padding:2px 8px;border-radius:4px;font-size:0.85em;">{_esc(str(url))}</code> '
    if len(items) > limit:
        chips += f'<span class="muted">+ {len(items) - limit} more</span>'
    return chips


def _method_upgrade_tip(mode: str, target: str) -> str:
    """Return a tip suggesting deeper scan profiles when applicable."""
    if mode in ('deep', 'bounty', 'stealth'):
        return ''
    tips = {
        'default':  ('deep', 'Deep scan includes historical URL crawling, JavaScript analysis, parameter discovery, and extended admin panel enumeration — recommended for thorough assessments.'),
        'standard': ('deep', 'Deep scan includes historical URL crawling, JavaScript analysis, parameter discovery, and extended admin panel enumeration — recommended for thorough assessments.'),
        'quick':    ('standard', 'Standard scan adds admin panel enumeration, rate-limit testing, and WAF gap analysis. For maximum coverage, use <code>--profile bounty</code>.'),
        'fast':     ('standard', 'Standard scan adds admin panel enumeration, rate-limit testing, and WAF gap analysis. For maximum coverage, use <code>--profile bounty</code>.'),
        'api':      ('bounty', 'Bounty profile adds full subdomain probing, admin panel enumeration, and extended attack surface analysis.'),
    }
    rec = tips.get(mode)
    if not rec:
        return ''
    profile, desc = rec
    cmd = f'fray recon {_esc(target)} --profile {profile}'
    return (f'<div style="margin-top:14px;background:var(--surface2);border-radius:10px;padding:14px 18px;'
            f'border-left:3px solid var(--accent);">'
            f'<p style="font-size:0.88em;margin-bottom:6px;"><strong style="color:var(--accent2);">'
            f'Want deeper results?</strong> {desc}</p>'
            f'<code style="background:var(--surface);padding:6px 12px;border-radius:6px;font-size:0.88em;">'
            f'{cmd}</code></div>')


def build(rd: Dict[str, Any]) -> str:
    host = rd.get('host', 'Unknown')
    target = rd.get('target', f'https://{host}')
    ts = rd.get('timestamp', '')
    ts_short = ts[:16].replace('T', ' ') if ts else '—'
    scan_mode = rd.get('mode', 'default')
    _PROFILE_LABELS = {
        'default': 'Standard', 'standard': 'Standard', 'quick': 'Quick',
        'deep': 'Deep', 'stealth': 'Stealth', 'api': 'API-Focused',
        'bounty': 'Bounty (Max Coverage)', 'fast': 'Fast',
    }
    _profile_label = _PROFILE_LABELS.get(scan_mode, scan_mode.title())

    atk = rd.get('attack_surface', {})
    risk_score = atk.get('risk_score', 0)
    risk_level = atk.get('risk_level', '?')
    findings = atk.get('findings', [])
    n_findings = len(findings)
    n_crit = sum(1 for f in findings if f.get('severity') == 'critical')
    n_high = sum(1 for f in findings if f.get('severity') == 'high')
    n_med = sum(1 for f in findings if f.get('severity') == 'medium')
    n_low = sum(1 for f in findings if f.get('severity') == 'low')

    gap = rd.get('gap_analysis', {}) or {}
    _waf_single = gap.get('waf_vendor') or atk.get('waf_vendor') or '—'
    _cdn_single = rd.get('dns', {}).get('cdn_detected') or atk.get('cdn') or '—'
    tls_data = rd.get('tls', {}) or {}
    tls_ver = tls_data.get('tls_version', '—')
    cert_days = tls_data.get('cert_days_remaining', '—')
    cert_issuer = tls_data.get('cert_issuer') or tls_data.get('issuer', '—')

    hdrs = rd.get('headers', {}) or {}
    hdr_score = hdrs.get('score', 0)
    present_hdrs = hdrs.get('present', {})
    if not isinstance(present_hdrs, dict):
        present_hdrs = {h: {} for h in present_hdrs} if isinstance(present_hdrs, list) else {}
    missing_hdrs = hdrs.get('missing', {})
    if not isinstance(missing_hdrs, dict):
        missing_hdrs = {h: {} for h in missing_hdrs} if isinstance(missing_hdrs, list) else {}

    subs_data = rd.get('subdomains', {}) or {}
    sub_list = subs_data.get('subdomains', []) if isinstance(subs_data, dict) else []
    n_subs = len(sub_list) if isinstance(sub_list, list) else 0
    sub_sources = subs_data.get('sources', {}) if isinstance(subs_data, dict) else {}

    attack_vectors = atk.get('attack_vectors', [])
    attack_targets = atk.get('attack_targets', [])
    n_attack_targets = len(attack_targets)

    csp_data = rd.get('csp', {}) or {}
    csp_present = csp_data.get('present', False) if isinstance(csp_data, dict) else False
    csp_score = csp_data.get('score', 0) if isinstance(csp_data, dict) else 0
    csp_bypasses = csp_data.get('bypass_techniques', []) if isinstance(csp_data, dict) else []

    admin_data = rd.get('admin_panels', {}) or {}
    admin_panels = (admin_data.get('panels_found', []) or admin_data.get('found', []) or
                    admin_data.get('panels', [])) if isinstance(admin_data, dict) else []
    n_admin = len(admin_panels)

    cloud_dist = rd.get('cloud_distribution', {}) or {}
    per_sub = cloud_dist.get('per_subdomain', [])
    waf_bypass_subs = cloud_dist.get('waf_bypass_subdomains', [])

    # Build WAF/CDN display labels — prefer multi-vendor summary when applicable
    _waf_dist = cloud_dist.get('waf_distribution', {})
    _cdn_dist = cloud_dist.get('cdn_distribution', {})
    if _waf_dist and len(_waf_dist) > 1:
        waf_vendor = 'Multi-WAF: ' + ', '.join(sorted(_waf_dist.keys()))
    elif _waf_dist and len(_waf_dist) == 1:
        waf_vendor = next(iter(_waf_dist.keys()))
    else:
        waf_vendor = _waf_single
    if _cdn_dist and len(_cdn_dist) > 1:
        cdn_vendor = 'Multi-CDN: ' + ', '.join(sorted(_cdn_dist.keys()))
    elif _cdn_dist and len(_cdn_dist) == 1:
        cdn_vendor = next(iter(_cdn_dist.keys()))
    else:
        cdn_vendor = _cdn_single

    probes = rd.get('subdomain_probes', {}) or {}
    probe_results = probes.get('results', []) if isinstance(probes, dict) else []
    n_probes = probes.get('total', 0) if isinstance(probes, dict) else 0
    n_responsive = probes.get('responsive', 0) if isinstance(probes, dict) else 0

    dns = rd.get('dns', {}) or {}
    fp = rd.get('fingerprint', {}) or {}
    techs = fp.get('technologies', {})
    fl = rd.get('frontend_libs', {}) or {}
    fl_vulns = fl.get('vulnerabilities', []) if isinstance(fl, dict) else []
    n_vuln_libs = fl.get('vulnerable_libs', 0) if isinstance(fl, dict) else 0

    origin_ips_data = rd.get('origin_ips', {}) or {}
    origin_list = origin_ips_data.get('candidates', []) if isinstance(origin_ips_data, dict) else []

    rec_cats = rd.get('recommended_categories', [])
    gap_findings = gap.get('findings', []) if isinstance(gap, dict) else []
    rate_limit = rd.get('rate_limit', {}) or {}
    remediation = atk.get('remediation', [])
    staging_envs = atk.get('staging_envs', [])
    checks = rd.get('security_checks', {}) or {}

    # Emoji map for attack vectors
    _VEC_EMOJI = {
        'WAF Bypass': '\U0001f6e1\ufe0f', 'Unprotected Subdomain': '\U0001f310',
        'Account Takeover': '\U0001f511', 'API Vulnerability': '\U0001f50c',
        'LLM / AI Prompt Injection': '\U0001f916', 'Payment / Financial Abuse': '\U0001f4b3',
        'Staging / Dev Environment': '\U0001f9ea', 'DDoS / L7 Denial of Service': '\u26a1',
        'Web Cache Poisoning': '\U0001f4be', 'DDoS \u2014 Direct Origin': '\u26a1',
    }

    rc = risk_color(risk_score)
    hdr_color = 'var(--red)' if hdr_score < 30 else 'var(--yellow)' if hdr_score < 60 else 'var(--green)'

    # ── Pieces ──
    parts = []
    parts.append(f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
                 f'<meta name="viewport" content="width=device-width,initial-scale=1.0">'
                 f'<title>Recon Report — {_esc(host)} — Fray</title>'
                 f'<style>{CSS}</style></head><body><div class="wrap">')

    # Header
    parts.append(f'''
<div class="hdr">
  <div>
    <div class="logo"><span class="logo-name">DALI</span><span class="logo-sub">SECURITY</span></div>
    <h1 style="margin-top:12px;">Reconnaissance Report</h1>
    <div class="sub">{_esc(host)} — {_esc(ts_short)} — Profile: {_esc(_profile_label)}</div>
  </div>
  <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;">
    <div class="rbadge">{gauge_svg(risk_score)}</div>
  </div>
</div>''')

    # Dashboard
    donut = donut_svg([n_crit, n_high, n_med, n_low],
                      ['#ef4444', '#f97316', '#eab308', '#22c55e'], n_findings)
    legend = ''
    for cnt, col, nm in zip([n_crit, n_high, n_med, n_low],
                            ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                            ['Critical', 'High', 'Medium', 'Low']):
        if cnt > 0:
            legend += f'<div style="display:flex;align-items:center;gap:6px;font-size:0.85em;"><span style="width:10px;height:10px;border-radius:50%;background:{col};display:inline-block;"></span><strong>{nm}:</strong> {cnt}</div>'

    parts.append(f'''
<div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:24px;align-items:stretch;">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px;display:flex;align-items:center;gap:20px;flex:0 0 auto;">
    {donut}
    <div style="display:flex;flex-direction:column;gap:6px;">{legend}</div>
  </div>
  <div style="flex:1;min-width:300px;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;">
    <div class="mc"><div class="l">WAF</div><div class="v" style="font-size:0.85em;">{_esc(str(waf_vendor))[:50]}</div></div>
    <div class="mc"><div class="l">CDN</div><div class="v" style="font-size:0.85em;">{_esc(str(cdn_vendor))[:50]}</div></div>
    <div class="mc"><div class="l">TLS</div><div class="v">{_esc(str(tls_ver))}</div></div>
    <div class="mc"><div class="l">Headers Score</div><div class="v" style="color:{hdr_color};">{hdr_score}/100</div></div>
    <div class="mc"><div class="l">Subdomains</div><div class="v">{n_subs}</div></div>
    <div class="mc"><div class="l">Attack Targets</div><div class="v" style="color:var(--orange);">{n_attack_targets}</div></div>
    <div class="mc"><div class="l">Attack Vectors</div><div class="v" style="color:var(--red);">{len(attack_vectors)}</div></div>
    <div class="mc"><div class="l">Admin Panels</div><div class="v">{n_admin}</div></div>
  </div>
</div>''')

    # TOC
    parts.append('''
<nav style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px 24px;margin-bottom:24px;">
  <div style="font-size:0.75em;font-weight:700;color:var(--muted);letter-spacing:1px;margin-bottom:12px;">REPORT NAVIGATION</div>
  <div style="display:flex;flex-wrap:wrap;gap:20px;">
    <div><div style="font-size:0.72em;font-weight:600;color:var(--accent2);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">Overview</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;"><a href="#exec" class="toc-link">Summary</a><a href="#methodology" class="toc-link">Methodology</a><a href="#findings" class="toc-link">Findings</a><a href="#remediation" class="toc-link">Remediation</a></div></div>
    <div><div style="font-size:0.72em;font-weight:600;color:var(--red);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">Threats</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;"><a href="#vectors" class="toc-link">Attack Vectors</a><a href="#priorities" class="toc-link">Priorities</a><a href="#cves" class="toc-link">CVEs</a><a href="#checks" class="toc-link">Security Checks</a></div></div>
    <div><div style="font-size:0.72em;font-weight:600;color:var(--cyan);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">Infrastructure</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;"><a href="#headers" class="toc-link">Headers</a><a href="#csp" class="toc-link">CSP</a><a href="#tech" class="toc-link">Tech</a><a href="#dns" class="toc-link">DNS</a><a href="#waf-cdn" class="toc-link">WAF/CDN</a><a href="#gap" class="toc-link">Gap Analysis</a><a href="#rl" class="toc-link">Rate Limits</a></div></div>
    <div><div style="font-size:0.72em;font-weight:600;color:var(--orange);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px;">Targets</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;"><a href="#subs" class="toc-link">Subdomains</a><a href="#probes" class="toc-link">Probes</a><a href="#origin" class="toc-link">Origin IPs</a><a href="#admin" class="toc-link">Admin Panels</a><a href="#hvt" class="toc-link">HVT</a><a href="#tests" class="toc-link">Tests</a><a href="#cats" class="toc-link">Categories</a></div></div>
  </div>
</nav>''')

    # Executive Summary
    sp = []
    sp.append(f'Fray performed automated reconnaissance of <strong>{_esc(host)}</strong> '
              f'and assessed the external attack surface at <strong style="color:{rc};">'
              f'{_esc(risk_level)} risk ({risk_score}/100)</strong>, corresponding to a '
              f'security grade of <strong style="color:{rc};">{risk_grade(risk_score)}</strong>. '
              f'A total of <strong>{n_findings}</strong> finding(s) were identified'
              + (f' across <strong>{n_attack_targets}</strong> prioritised attack targets.' if n_attack_targets else '.'))
    if waf_vendor and waf_vendor != '—':
        sp.append(f'The target infrastructure is protected by <strong>{_esc(str(waf_vendor))}</strong> WAF'
                  + (f', served via <strong>{_esc(str(cdn_vendor))}</strong> CDN' if cdn_vendor and cdn_vendor != '—' else '')
                  + f', TLS {_esc(str(tls_ver))}.')
    else:
        sp.append('<span style="color:var(--red);font-weight:700;">No WAF was detected — the application is directly exposed.</span>')

    n_waf_bypass = len(waf_bypass_subs)
    n_unprotected = sum(1 for s in per_sub if not s.get('waf') and not s.get('cdn'))
    n_staging = len(staging_envs) if isinstance(staging_envs, list) else 0
    vb = []
    if n_waf_bypass:
        vb.append(f'<li><strong style="color:var(--red);">{n_waf_bypass} subdomain(s) bypass WAF</strong> — attackers can reach origin servers directly</li>')
    if n_unprotected:
        vb.append(f'<li><strong style="color:var(--orange);">{n_unprotected} subdomain(s) have no CDN/WAF</strong> — exposed without edge protection</li>')
    if n_staging:
        vb.append(f'<li><strong style="color:var(--yellow);">{n_staging} staging/dev environment(s)</strong> — often have weaker security controls</li>')
    if origin_list:
        vb.append(f'<li><strong>{len(origin_list)} origin IP candidate(s)</strong> discovered</li>')
    if n_admin:
        vb.append(f'<li>{n_admin} admin panel(s) discovered</li>')
    for vec in attack_vectors[:6]:
        vn = vec.get('type', '')
        if vn not in ('waf_bypass', 'unprotected', 'staging_dev', ''):
            vs = vec.get('severity', 'medium')
            vc = SEV_COLORS.get(vs, 'var(--muted)')
            vb.append(f'<li><strong style="color:{vc};">{_esc(vn)}</strong> — {_esc(vec.get("description", "")[:80])}</li>')
    vuln_html = f'<div style="margin-bottom:16px;font-size:0.95em;line-height:1.6;"><strong>Key vulnerabilities:</strong><ul style="margin:8px 0 0 20px;line-height:2;">{"".join(vb)}</ul></div>' if vb else ''

    rb = []
    if hdr_score < 50:
        rb.append(f'<li><strong>Security headers weak</strong> ({hdr_score}/100) — {len(missing_hdrs)} essential header(s) missing</li>')
    for r in remediation[:6]:
        t = r.get('action', str(r)) if isinstance(r, dict) else str(r)
        rb.append(f'<li>{_esc(t)}</li>')
    if n_waf_bypass:
        rb.append(f'<li>Route {n_waf_bypass} WAF-bypass subdomain(s) through CDN</li>')
    remed_html = f'<div style="margin-bottom:16px;font-size:0.95em;line-height:1.6;"><strong>Recommended improvements:</strong><ol style="margin:8px 0 0 20px;line-height:2;">{"".join(rb)}</ol></div>' if rb else ''

    if risk_score >= 60: risk_msg = '<span style="color:var(--red);font-weight:700;">The attack surface has critical exposures requiring immediate action.</span>'
    elif risk_score >= 40: risk_msg = '<span style="color:var(--orange);font-weight:700;">The attack surface has notable exposures that should be addressed promptly.</span>'
    elif risk_score >= 20: risk_msg = '<span style="color:var(--yellow);font-weight:700;">The attack surface has moderate exposures.</span>'
    else: risk_msg = '<span style="color:var(--green);font-weight:700;">The attack surface is relatively well-secured.</span>'

    parts.append(f'''
<div class="sec" id="exec">
  <h2>Executive Summary</h2>
  <p style="font-size:1.02em;line-height:1.8;margin-bottom:16px;">{"<br>".join(sp)}</p>
  {vuln_html}{remed_html}
  <p style="font-size:1em;line-height:1.8;margin-top:8px;">{risk_msg}</p>
</div>''')

    # Methodology
    techs_list = ['DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)',
                  'Passive subdomain discovery (Certificate Transparency)',
                  'Active subdomain brute-force (common prefixes)',
                  'HTTP fingerprinting (headers, response body, scripts)',
                  'Technology detection (Wappalyzer 7,500+ signatures)',
                  'TLS/SSL analysis (version, cipher suites, certificate)',
                  'Security header assessment (HSTS, CSP, etc.)',
                  'WAF detection & bypass analysis',
                  'Origin IP discovery', 'Admin panel enumeration',
                  'Per-subdomain WAF/CDN/cache fingerprinting',
                  'Attack surface prioritization (MITRE-mapped)',
                  'Rate limit & DDoS resilience testing',
                  'Frontend library CVE scanning']
    tl = ''.join(f'<li style="font-size:0.9em;">{_esc(t)}</li>' for t in techs_list)
    src_parts = ', '.join(f'{k}: {v}' for k, v in sub_sources.items()) if sub_sources else ''
    parts.append(f'''
<div class="sec" id="methodology">
  <h2>Methodology &amp; Scope</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:16px;">
    <div><table>
      <tr><td class="kv-key">Target</td><td class="mono">{_esc(target)}</td></tr>
      <tr><td class="kv-key">Scan Date</td><td>{_esc(ts_short)}</td></tr>
      <tr><td class="kv-key">Profile</td><td>{_esc(_profile_label)}</td></tr>
    </table></div>
    <div><table>
      <tr><td class="kv-key">Subdomains Found</td><td>{n_subs}</td></tr>
      <tr><td class="kv-key">Probes Sent</td><td>{n_probes}</td></tr>
      <tr><td class="kv-key">Admin Paths Checked</td><td>{n_admin}</td></tr>
    </table></div>
  </div>
  <details><summary>Techniques Applied ({len(techs_list)})</summary><ol style="padding-left:20px;line-height:2.2;">{tl}</ol></details>
  {f'<p class="muted" style="margin-top:8px;font-size:0.85em;">Sources: {_esc(src_parts)}</p>' if src_parts else ''}
  <p class="muted" style="margin-top:12px;font-size:0.85em;">This assessment is non-intrusive reconnaissance only — no exploitation was performed.</p>
{_method_upgrade_tip(scan_mode, target)}
</div>''')

    # Findings
    fi = ''
    for f in findings:
        sev = f.get('severity', 'low')
        col = SEV_COLORS.get(sev, '#64748b')
        fi += f'<div class="finding" style="border-left:4px solid {col};"><span class="sev-badge" style="background:{col}20;color:{col};">{sev.upper()}</span> {_esc(f.get("finding", ""))}</div>'
    parts.append(f'''
<div class="sec" id="findings">
  <h2>Key Findings <span class="count">({n_findings})</span></h2>
  {fi if fi else '<p class="muted">No findings detected.</p>'}
</div>''')

    # Attack Vectors
    if attack_vectors:
        vi = ''
        for vec in attack_vectors:
            vs = vec.get('severity', 'medium')
            vc = SEV_COLORS.get(vs, '#64748b')
            vn_raw = vec.get('type', 'Unknown')
            vn = _esc(vn_raw)
            vct = vec.get('count', 0)
            vp = vec.get('priority', 0)
            vd = _esc(vec.get('description', ''))
            vim = _esc(vec.get('impact', ''))
            vm = vec.get('mitre', '')
            vt = vec.get('targets', [])
            emoji = _VEC_EMOJI.get(vn_raw, '')
            emoji_html = f'<span style="font-size:1.4em;">{emoji}</span>' if emoji else ''
            detail = vec.get('detail', '')
            detail_html = f'<details style="margin-top:8px;"><summary style="font-size:0.82em;">Detail</summary><p class="muted" style="font-size:0.85em;margin-top:6px;">{_esc(detail[:500])}</p></details>' if detail else ''
            vi += f'''<div style="background:var(--surface2);border-radius:12px;padding:20px 24px;margin-bottom:16px;border-left:4px solid {vc};">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
    {emoji_html}
    <div style="flex:1;"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <strong style="font-size:1.1em;">{vn}</strong>
      <span class="sev-badge" style="background:{vc}20;color:{vc};">{vs.upper()}</span>
      <span class="muted" style="font-size:0.82em;">P{vp} · {vct} target(s)</span>
    </div></div>
  </div>
  {f'<p style="margin-bottom:8px;font-size:0.92em;">{vd}</p>' if vd else ''}
  {f'<p style="margin-bottom:8px;font-size:0.92em;"><strong style="color:var(--orange);">Impact:</strong> {vim}</p>' if vim else ''}
  {f'<p style="margin-bottom:8px;font-size:0.82em;"><span class="muted">MITRE:</span> <code style="background:var(--surface);padding:2px 8px;border-radius:4px;">{_esc(vm)}</code></p>' if vm else ''}
  {f'<div style="margin-top:10px;"><span class="muted" style="font-size:0.82em;">Affected:</span><br><div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px;">{_targets_chips(vt)}</div></div>' if vt else ''}
  {detail_html}
</div>'''
        parts.append(f'''
<div class="sec" id="vectors">
  <h2>Attack Vectors <span class="count">({len(attack_vectors)} types across {n_attack_targets} targets)</span></h2>
  {vi}
</div>''')

    # Attack Priorities
    if attack_targets:
        at_rows = ''
        for i, t in enumerate(attack_targets[:50], 1):
            tp = t.get('priority', 0)
            tt = t.get('type', '')
            tgt = t.get('target', '')
            pc = '#ef4444' if tp >= 90 else '#f97316' if tp >= 70 else '#eab308' if tp >= 50 else '#64748b'
            at_rows += f'<tr><td class="num">{i}</td><td style="color:{pc};font-weight:700;">P{tp}</td><td><span class="type-badge" style="background:#64748b20;color:#64748b;">{_esc(tt)}</span></td><td class="mono" style="font-size:0.85em;">{_esc(tgt)}</td></tr>'
        parts.append(f'''
<div class="sec" id="priorities">
  <h2>Attack Priorities <span class="count">({n_attack_targets} targets)</span></h2>
  <table><tr><th>#</th><th>P</th><th>Type</th><th>Target</th></tr>{at_rows}</table>
</div>''')

    # CVEs
    cve_items = ''
    for v in fl_vulns[:20]:
        cve_items += f'<tr><td><span style="color:{SEV_COLORS.get(v.get("severity","info"),"#64748b")};font-weight:700;">{_esc(v.get("id",""))}</span></td><td>{_esc(v.get("library",""))}</td><td>{_esc(v.get("severity",""))}</td><td class="muted" style="font-size:0.85em;">{_esc(v.get("description","")[:100])}</td></tr>'
    parts.append(f'''
<div class="sec" id="cves">
  <h2>CVE / Frontend Vulnerabilities <span class="count">({len(fl_vulns)} CVEs, {n_vuln_libs} vulnerable lib(s))</span></h2>
  {f'<table><tr><th>CVE</th><th>Library</th><th>Severity</th><th>Description</th></tr>{cve_items}</table>' if cve_items else '<p class="muted">No frontend CVEs detected.</p>'}
</div>''')

    # Security Checks
    if checks:
        ck_html = ''
        all_pass = True
        for ck_name, ck_val in checks.items():
            if isinstance(ck_val, dict) and ck_val.get('findings'):
                all_pass = False
                for cf in ck_val['findings']:
                    ck_html += f'<div class="finding" style="border-left:4px solid #f97316;"><span class="sev-badge" style="background:#f9731620;color:#f97316;">WARN</span> {_esc(str(cf))}</div>'
        if all_pass:
            ck_html = '<p style="color:var(--green);">All additional checks passed — no CORS, subdomain takeover, exposed files, or cookie issues detected.</p>'
        parts.append(f'<div class="sec" id="checks"><h2>Additional Security Checks</h2>{ck_html}</div>')

    # CSP Analysis
    csp_html_sec = ''
    if csp_present:
        csp_html_sec = f'<p style="margin-bottom:8px;"><strong>Score:</strong> {csp_score}/100</p>'
        if csp_bypasses:
            for bp in csp_bypasses[:5]:
                csp_html_sec += f'<div class="finding" style="border-left:4px solid #f97316;"><span class="sev-badge" style="background:#f9731620;color:#f97316;">BYPASS</span> {_esc(str(bp))}</div>'
    else:
        csp_html_sec = ('<div class="finding" style="border-left:4px solid #ef4444;">'
            '<span class="sev-badge" style="background:#ef444420;color:#ef4444;">CRITICAL</span> '
            'No Content-Security-Policy header — all inline scripts execute freely</div>')
        csp_html_sec += '''<div style="margin-top:14px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid #ef4444;">
  <p style="font-size:0.9em;font-weight:600;color:var(--red);margin-bottom:8px;">Risks without CSP:</p>
  <ul style="padding-left:18px;font-size:0.85em;line-height:1.9;color:var(--text);">
    <li><strong>Reflected &amp; Stored XSS</strong> — attacker-injected scripts execute in user browsers, stealing sessions and credentials</li>
    <li><strong>Data exfiltration</strong> — malicious inline scripts can send form data, cookies, and tokens to attacker servers</li>
    <li><strong>Clickjacking via iframes</strong> — page can be embedded in attacker-controlled frames without restriction</li>
    <li><strong>Cryptojacking</strong> — injected scripts can run cryptocurrency miners in visitor browsers</li>
    <li><strong>Magecart / skimming</strong> — third-party scripts can be injected to capture payment card data</li>
  </ul>
</div>'''
    parts.append(f'''
<div class="sec" id="csp">
  <h2>CSP Analysis <span class="count">({csp_score}/100)</span></h2>
  {csp_html_sec}
</div>''')

    # Security Headers
    pt = ''.join(f'<span class="tag tag-ok">{_esc(h)}</span>' for h in present_hdrs)
    mt = ''
    for h, info in missing_hdrs.items():
        sev = info.get('severity', 'low') if isinstance(info, dict) else 'low'
        mt += f'<span class="tag tag-miss">{_esc(h)} <small>({_esc(sev)})</small></span> '
    _HDR_RISKS = {
        'HSTS': 'SSL stripping attacks — attacker downgrades HTTPS to HTTP and intercepts traffic',
        'CSP': 'XSS and code injection — no restrictions on inline scripts or loaded resources',
        'X-Frame-Options': 'Clickjacking — page can be embedded in malicious iframes to trick user clicks',
        'X-Content-Type-Options': 'MIME-type sniffing — browsers may execute uploaded files as scripts',
        'X-XSS-Protection': 'Legacy XSS filter disabled — reflected XSS in older browsers',
        'Referrer-Policy': 'URL leakage — sensitive query parameters exposed to third-party sites',
        'Permissions-Policy': 'Unrestricted browser APIs — camera, microphone, geolocation accessible to any script',
        'COOP': 'Cross-origin attacks — Spectre-class side-channel leaks via shared browsing context',
        'CORP': 'Cross-origin resource theft — sensitive resources loadable by attacker pages',
    }
    hdr_risk_html = ''
    if hdr_score < 30 and missing_hdrs:
        risk_items = ''
        for h in list(missing_hdrs.keys())[:6]:
            risk = _HDR_RISKS.get(h, '')
            if risk:
                risk_items += f'<li><strong>{_esc(h)}</strong> — {_esc(risk)}</li>'
        if risk_items:
            hdr_risk_html = f'''<div style="margin-top:14px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid #ef4444;">
  <p style="font-size:0.9em;font-weight:600;color:var(--red);margin-bottom:8px;">Risks from missing headers:</p>
  <ul style="padding-left:18px;font-size:0.85em;line-height:1.9;color:var(--text);">{risk_items}</ul>
</div>'''
    parts.append(f'''
<div class="sec" id="headers">
  <h2>Security Headers <span class="count">({hdr_score}/100)</span></h2>
  <p style="margin-bottom:10px;"><strong>Present:</strong> {pt or '<span class="muted">None</span>'}</p>
  <p><strong>Missing:</strong> {mt or '<span style="color:var(--green);">None — all present</span>'}</p>
  {hdr_risk_html}
</div>''')

    # Technologies
    _CAT_COLORS = {
        'WAF': 'var(--green)', 'CDN': 'var(--blue)', 'Cloud': 'var(--purple)',
        'Web Server': 'var(--cyan)', 'Application Server': 'var(--orange)',
        'Framework': 'var(--yellow)', 'CMS': 'var(--yellow)',
        'Hosting Panel': 'var(--muted)', 'Container': 'var(--cyan)',
        'CI/CD': 'var(--orange)', 'DevOps': 'var(--purple)',
        'Database': 'var(--red)', 'Search Engine': 'var(--blue)',
        'API': 'var(--accent2)', 'Container Orchestration': 'var(--cyan)',
    }
    tr_html = ''
    tech_items = sorted(techs.items(), key=lambda x: -(x[1].get('confidence', 0) if isinstance(x[1], dict) else (x[1] * 100 if isinstance(x[1], (int, float)) and x[1] <= 1 else x[1] if isinstance(x[1], (int, float)) else 0)))
    for name, ver in tech_items:
        if isinstance(ver, dict):
            cat = ver.get('category', '')
            conf = ver.get('confidence', 50)
            cat_col = _CAT_COLORS.get(cat, 'var(--muted)')
            cat_badge = f'<span class="type-badge" style="background:{cat_col}20;color:{cat_col};font-size:0.8em;">{_esc(cat)}</span>' if cat else ''
            tr_html += f'<tr><td><strong>{_esc(name)}</strong> {cat_badge}</td><td><div class="bar-wrap"><div class="bar-fill" style="width:{conf}%"></div></div></td><td class="num">{conf}%</td></tr>'
        elif isinstance(ver, (int, float)):
            pct = max(1, int(ver * 100)) if ver <= 1 else int(ver)
            tr_html += f'<tr><td><strong>{_esc(name)}</strong></td><td><div class="bar-wrap"><div class="bar-fill" style="width:{pct}%"></div></div></td><td class="num">{pct}%</td></tr>'
        else:
            v = ver if isinstance(ver, str) else str(ver) if ver else '—'
            tr_html += f'<tr><td><strong>{_esc(name)}</strong></td><td colspan="2">{_esc(str(v))}</td></tr>'
    parts.append(f'''
<div class="sec" id="tech">
  <h2>Technologies <span class="count">({len(techs)})</span></h2>
  {f'<table><tr><th>Technology</th><th>Confidence</th><th></th></tr>{tr_html}</table>' if tr_html else '<p class="muted">No technologies detected.</p>'}
</div>''')

    # DNS
    a_recs = ', '.join(dns.get('a', [])) or '—'
    aaaa_recs = ', '.join(dns.get('aaaa', [])) or '—'
    cname = ', '.join(dns.get('cname', [])) if isinstance(dns.get('cname'), list) else (dns.get('cname') or '—')
    spf = dns.get('spf', '')
    dmarc = dns.get('dmarc', '')
    parts.append(f'''
<div class="sec" id="dns">
  <h2>DNS Records</h2>
  <table>
    <tr><td class="kv-key">A</td><td class="mono" style="word-break:break-all;">{_esc(a_recs)}</td></tr>
    <tr><td class="kv-key">AAAA</td><td class="mono" style="word-break:break-all;">{_esc(aaaa_recs)}</td></tr>
    <tr><td class="kv-key">CNAME</td><td class="mono" style="word-break:break-all;">{_esc(str(cname))}</td></tr>
    <tr><td class="kv-key">CDN</td><td>{_esc(str(cdn_vendor))}</td></tr>
    <tr><td class="kv-key">SPF</td><td>{'&#x2713; ' + _esc(spf[:60]) if spf else '&#x2717; Missing'}</td></tr>
    <tr><td class="kv-key">DMARC</td><td>{'&#x2713; ' + _esc(dmarc[:60]) if dmarc else '&#x2717; Missing'}</td></tr>
  </table>
</div>''')

    # Per-Subdomain WAF/CDN (the main new section)
    if per_sub:
        waf_dist = cloud_dist.get('waf_distribution', {})
        cdn_dist_d = cloud_dist.get('cdn_distribution', {})
        badges = ''
        for name, info in waf_dist.items():
            badges += f'<span class="tag" style="background:rgba(34,197,94,0.15);color:var(--green);">WAF: {_esc(name)} ({info["pct"]}%)</span> '
        for name, info in cdn_dist_d.items():
            badges += f'<span class="tag" style="background:rgba(59,130,246,0.15);color:var(--blue);">CDN: {_esc(name)} ({info["pct"]}%)</span> '
        if cloud_dist.get('multi_waf'):
            badges += '<span class="tag" style="background:rgba(234,179,8,0.15);color:var(--yellow);">Multi-WAF</span> '
        if cloud_dist.get('multi_cdn'):
            badges += '<span class="tag" style="background:rgba(234,179,8,0.15);color:var(--yellow);">Multi-CDN</span> '

        show_limit = 200
        def _sub_sort_key(s):
            has_waf = 1 if s.get('waf') else 0
            has_cdn = 1 if s.get('cdn') else 0
            return (-has_waf, -has_cdn, s.get('subdomain', ''))
        per_sub_sorted = sorted(per_sub, key=_sub_sort_key)
        sr = ''
        for i, s in enumerate(per_sub_sorted[:show_limit]):
            wv = s.get('waf') or '(no WAF)'
            cv = s.get('cdn') or '(direct)'
            ca = s.get('cache_status') or '-'
            ht = str(s.get('status') or '-')
            sv = _esc((s.get('server') or '-')[:20])
            ws = 'color:var(--green);font-weight:600;' if s.get('waf') else 'color:var(--red);'
            cs = 'color:var(--blue);font-weight:600;' if s.get('cdn') else 'color:var(--muted);'
            sr += f'<tr><td class="mono">{_esc(s["subdomain"])}</td><td style="{ws}">{_esc(wv)}</td><td style="{cs}">{_esc(cv)}</td><td>{_esc(ca)}</td><td>{_esc(ht)}</td><td class="muted">{sv}</td></tr>'

        overflow = f'<p class="muted" style="margin-top:8px;">Showing first {show_limit} of {len(per_sub)} subdomains.</p>' if len(per_sub) > show_limit else ''

        parts.append(f'''
<div class="sec" id="waf-cdn">
  <h2>Per-Subdomain WAF / CDN Analysis <span class="count">({len(per_sub)} subdomains)</span></h2>
  <div style="margin-bottom:14px;">{badges}</div>
  <details open><summary>Show per-subdomain table ({len(per_sub)} subdomains)</summary>
  <table><tr><th>Subdomain</th><th>WAF</th><th>CDN</th><th>Cache</th><th>HTTP</th><th>Server</th></tr>{sr}</table>
  {overflow}</details>
</div>''')

    # WAF Gap Analysis
    if gap_findings:
        gf = ''
        for g in gap_findings:
            gs = g.get('severity', 'medium') if isinstance(g, dict) else 'medium'
            gc = SEV_COLORS.get(gs, '#64748b')
            gn = _esc(g.get('technique', '')) if isinstance(g, dict) else ''
            gd = _esc(g.get('description', str(g))) if isinstance(g, dict) else _esc(str(g))
            gf += f'<div class="finding" style="border-left:4px solid {gc};"><span class="sev-badge" style="background:{gc}20;color:{gc};">{gs.upper()}</span> <strong>{gn}</strong> — {gd}</div>'
        parts.append(f'<div class="sec" id="gap"><h2>WAF Gap Analysis</h2>{gf}</div>')

    # Rate Limits
    rl_type = rate_limit.get('type', 'none') if isinstance(rate_limit, dict) else 'none'
    rl_thresh = rate_limit.get('threshold') if isinstance(rate_limit, dict) else None
    parts.append(f'''
<div class="sec" id="rl">
  <h2>Rate Limits</h2>
  <table>
    <tr><td class="kv-key">Type</td><td>{_esc(str(rl_type))}</td></tr>
    <tr><td class="kv-key">Threshold</td><td>{rl_thresh or 'None'} req/s</td></tr>
  </table>
</div>''')

    # Subdomains
    if sub_list:
        src_line = f'<p class="muted" style="margin-bottom:10px;">Sources: {_esc(", ".join(f"{k}: {v}" for k, v in sub_sources.items()))}</p>' if sub_sources else ''
        waf_bypass_html = ''
        if waf_bypass_subs:
            wb_rows = ''
            for s in waf_bypass_subs[:20]:
                if isinstance(s, dict):
                    sd = _esc(s.get('subdomain', ''))
                    ips = _esc(', '.join(s.get('ips', []))) if s.get('ips') else '<span class="muted">—</span>'
                    reason = _esc(s.get('reason', ''))
                else:
                    sd = _esc(str(s))
                    ips = '<span class="muted">—</span>'
                    reason = ''
                wb_rows += f'<tr><td class="mono">{sd}</td><td class="mono">{ips}</td><td class="muted">{reason}</td></tr>'
            waf_bypass_html = (
                f'<p style="color:var(--red);font-weight:600;margin-bottom:12px;">&#x26a0; WAF Bypass — '
                f'{len(waf_bypass_subs)} subdomain(s) skip {_esc(str(waf_vendor))}</p>'
                f'<details><summary>Show WAF bypass subdomains ({len(waf_bypass_subs)})</summary>'
                f'<table><tr><th>Subdomain</th><th>IPs</th><th>Reason</th></tr>{wb_rows}</table></details>'
            )

        show_sub_limit = 200
        sub_rows = ''.join(f'<tr><td class="mono">{_esc(s)}</td></tr>' for s in sub_list[:show_sub_limit])
        sub_overflow = f' (first {show_sub_limit} of {n_subs})' if n_subs > show_sub_limit else ''

        parts.append(f'''
<div class="sec" id="subs">
  <h2>Subdomains <span class="count">({n_subs} unique)</span></h2>
  {src_line}{waf_bypass_html}
  <details open><summary>Show subdomains{sub_overflow}</summary>
  <table><tr><th>Subdomain</th></tr>{sub_rows}</table></details>
</div>''')

    # Probes
    if probe_results:
        pr = ''
        for p in probe_results[:30]:
            st = p.get('status', 0)
            st_col = 'var(--green)' if 200 <= st < 300 else 'var(--orange)' if 300 <= st < 400 else 'var(--red)' if st >= 400 else 'var(--muted)'
            pr += f'<tr><td class="mono">{_esc(p.get("subdomain",""))}</td><td style="color:{st_col};font-weight:700;">{st}</td><td class="muted">{_esc(p.get("title","")[:50])}</td><td>{_esc(",".join(p.get("surfaces",[])))}</td></tr>'
        parts.append(f'''
<div class="sec" id="probes">
  <h2>Subdomain Probes <span class="count">({n_responsive}/{n_probes} responsive)</span></h2>
  <table><tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Surfaces</th></tr>{pr}</table>
</div>''')

    # Origin IPs
    if origin_list:
        oi = ''
        for o in origin_list[:20]:
            if isinstance(o, dict):
                oi += f'<tr><td class="mono">{_esc(o.get("ip",""))}</td><td>{_esc(o.get("source",""))}</td></tr>'
            else:
                oi += f'<tr><td class="mono">{_esc(str(o))}</td><td></td></tr>'
        origin_rec = f'''<div style="margin-top:16px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid var(--orange);">
  <p style="font-size:0.9em;font-weight:600;color:var(--orange);margin-bottom:8px;">Recommendations:</p>
  <ul style="padding-left:18px;font-size:0.85em;line-height:1.9;color:var(--text);">
    <li><strong>Restrict origin access</strong> — configure firewall rules (iptables, security groups, NSGs) to allow inbound traffic only from your CDN/WAF IP ranges</li>
    <li><strong>Enable origin cloaking</strong> — remove DNS records that directly expose origin IPs (e.g., mail, webmail, ftp subdomains)</li>
    <li><strong>Rotate origin IPs</strong> — if origin IPs are already leaked, migrate to new IPs and ensure they are never published in DNS</li>
    <li><strong>Use authenticated origin pulls</strong> — configure your CDN (Cloudflare, AWS CloudFront) to send a secret header that the origin validates before responding</li>
    <li><strong>Monitor for leaks</strong> — run <code>fray recon {_esc(host)} --deep</code> periodically to detect newly exposed origin IPs</li>
  </ul>
</div>'''
        parts.append(f'''
<div class="sec" id="origin">
  <h2>Origin IP Discovery <span class="count">({len(origin_list)} candidates)</span></h2>
  <table><tr><th>IP</th><th>Source</th></tr>{oi}</table>
  {origin_rec}
</div>''')

    # Admin Panels
    if admin_panels:
        ap = ''
        for a in admin_panels[:30]:
            ap += f'<tr><td class="mono">{_esc(a.get("path",""))}</td><td>{_esc(a.get("protection",""))}</td><td>{a.get("status","")}</td><td class="muted">{_esc(a.get("category",""))}</td></tr>'
        parts.append(f'''
<div class="sec" id="admin">
  <h2>Admin Panels <span class="count">({n_admin} found)</span></h2>
  <table><tr><th>Path</th><th>Protection</th><th>Status</th><th>Category</th></tr>{ap}</table>
</div>''')

    # High Value Targets
    hvt_items = []
    if staging_envs:
        hvt_items.append(('Staging / Dev', staging_envs, '#eab308'))
    auth_subs = [s for s in sub_list if any(k in s.lower() for k in ('auth', 'sso', 'login', 'id', 'account', 'oauth'))]
    if auth_subs:
        hvt_items.append(('Auth / Identity', auth_subs[:10], '#ef4444'))
    api_subs = [s for s in sub_list if any(k in s.lower() for k in ('api', 'graphql', 'grpc', 'gateway'))]
    if api_subs:
        hvt_items.append(('API', api_subs[:10], '#f97316'))
    pay_subs = [s for s in sub_list if any(k in s.lower() for k in ('pay', 'shop', 'store', 'cart', 'order', 'checkout'))]
    if pay_subs:
        hvt_items.append(('Payment / E-Commerce', pay_subs[:10], '#ef4444'))
    ai_subs = [s for s in sub_list if any(k in s.lower() for k in ('ai', 'llm', 'chat', 'bot', 'gpt', 'robot'))]
    if ai_subs:
        hvt_items.append(('AI / LLM', ai_subs[:10], '#a855f7'))
    if hvt_items:
        total_hvt = sum(len(items) for _, items, _ in hvt_items)
        hvt_html = ''
        for label, items, color in hvt_items:
            chips = ''.join(f'<code style="background:var(--surface);padding:5px 12px;border-radius:5px;font-size:0.9em;border:1px solid var(--border);">{_esc(s)}</code>' for s in items[:8])
            overflow = f'<span class="muted"> + {len(items) - 8} more</span>' if len(items) > 8 else ''
            hvt_html += f'''<div style="background:var(--surface2);border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:3px solid {color};"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;"><span class="type-badge" style="background:{color}20;color:{color};font-size:0.92em;">{_esc(label)}</span><span class="muted" style="font-size:0.85em;">{len(items)} environment(s)</span></div><div style="display:flex;flex-wrap:wrap;gap:6px;">{chips}{overflow}</div></div>'''
        parts.append(f'''
<div class="sec" id="hvt">
  <h2>High Value Targets <span class="count">({total_hvt})</span></h2>
  {hvt_html}
</div>''')

    # Suggested Tests — each with Fray-specific commands
    def _test_meta(typ, t0):
        """Return (sev_label, sev_color, description, fray_commands) for a test type."""
        t0e = _esc(t0)
        m = {
            'WAF Bypass': ('critical', '#ef4444',
                'These subdomains resolve to origin IPs outside the WAF — payloads reach the server unfiltered. '
                'Use <strong>fray agent</strong> to run iterative bypass testing directly against origin, or '
                '<strong>fray test</strong> with XSS/SQLi categories.',
                [f'fray agent {t0e} -c xss --rounds 5',
                 f'fray test {t0e} -c sqli --smart',
                 f'fray bypass {t0e} -c modern_bypasses']),
            'Unprotected Subdomain': ('high', '#f97316',
                'No WAF or CDN protection — all payloads reach these subdomains directly. '
                'Use <strong>fray test</strong> to probe for XSS, SSRF, and open redirect vulnerabilities.',
                [f'fray test {t0e} -c xss --smart',
                 f'fray recon {t0e} --deep',
                 f'fray test {t0e} -c ssrf --smart']),
            'Account Takeover': ('critical', '#ef4444',
                'Login and authentication endpoints are exposed. Use <strong>fray test</strong> to check for '
                'injection in auth forms, and <strong>fray recon</strong> with auth credentials to map the '
                'authenticated attack surface.',
                [f'fray test {t0e} -c xss --smart',
                 f'fray recon {t0e} --deep --login-flow "{t0e}/login,user=test,pass=test"',
                 f'fray leak {t0e}']),
            'API Vulnerability': ('high', '#f97316',
                'API endpoints discovered. Use <strong>fray recon --profile api</strong> for API-focused '
                'reconnaissance, then <strong>fray test</strong> with API-specific payloads for BOLA, SSRF, and injection.',
                [f'fray recon {t0e} --profile api',
                 f'fray test {t0e} -c api_security --smart',
                 f'fray test {t0e} -c ssrf --smart']),
            'LLM / AI Prompt Injection': ('high', '#f97316',
                'AI/chatbot endpoints found. Use <strong>fray agent</strong> with prompt injection payloads '
                'to test for jailbreaking, system prompt leakage, and indirect injection.',
                [f'fray agent {t0e} -c xss --rounds 3 --ai',
                 f'fray test {t0e} -c modern_bypasses --smart']),
            'Payment / Financial Abuse': ('critical', '#ef4444',
                'Payment and commerce endpoints detected. Use <strong>fray recon --deep</strong> to map the '
                'full payment flow, then <strong>fray test</strong> for injection in transaction parameters.',
                [f'fray recon {t0e} --deep',
                 f'fray test {t0e} -c xss --smart',
                 f'fray leak {t0e}']),
            'Staging / Dev Environment': ('high', '#f97316',
                'Staging/dev environments are publicly accessible and often have weaker security. '
                'Use <strong>fray recon --profile bounty</strong> for maximum coverage, then '
                '<strong>fray agent</strong> to find bypasses on weaker WAF rules.',
                [f'fray recon {t0e} --profile bounty',
                 f'fray agent {t0e} -c xss --rounds 5',
                 f'fray test {t0e} -c ssti --smart']),
            'DDoS / L7 Denial of Service': ('medium', '#eab308',
                'No rate limiting detected. Use <strong>fray recon</strong> to verify rate limit thresholds '
                'and <strong>fray harden</strong> to generate WAF rules that enforce limits.',
                [f'fray recon {t0e} -v',
                 f'fray harden {t0e}']),
            'Web Cache Poisoning': ('medium', '#eab308',
                'CDN caching + authenticated pages = cache deception risk. Use <strong>fray smuggle</strong> '
                'to test HTTP request smuggling, and <strong>fray test</strong> with cache-specific payloads.',
                [f'fray smuggle {t0e}',
                 f'fray test {t0e} -c csp_bypass --smart']),
            'DDoS \u2014 Direct Origin': ('high', '#f97316',
                'Origin servers reachable without CDN protection. Use <strong>fray recon</strong> to confirm '
                'origin IP exposure, and <strong>fray harden</strong> to generate firewall rules.',
                [f'fray recon {t0e} --deep',
                 f'fray harden {t0e}']),
        }
        return m.get(typ, ('medium', '#64748b', '', []))

    tests_by_type = {}
    for t in attack_targets:
        typ = t.get('type', 'Other')
        tests_by_type.setdefault(typ, []).append(t.get('target', ''))
    if tests_by_type:
        st_html = ''
        for typ, targets in tests_by_type.items():
            first_target = targets[0] if targets else target
            meta = _test_meta(typ, first_target)
            sev_label, sev_color, test_desc = meta[0], meta[1], meta[2]
            fray_cmds = meta[3] if len(meta) > 3 else []
            chips = ''.join(f'<code style="background:var(--surface);padding:5px 12px;border-radius:5px;font-size:0.9em;border:1px solid var(--border);">{_esc(t)}</code>' for t in targets[:10])
            overflow = f'<span class="muted"> + {len(targets) - 10} more</span>' if len(targets) > 10 else ''
            desc_html = f'<p style="font-size:0.85em;margin:6px 0 10px;color:var(--text);">{test_desc}</p>' if test_desc else ''
            cmds_html = ''
            if fray_cmds:
                cmd_items = ''.join(f'<code style="background:var(--surface);padding:4px 10px;border-radius:5px;font-size:0.84em;display:inline-block;margin:2px 4px 2px 0;border:1px solid var(--border);">{c}</code>' for c in fray_cmds)
                cmds_html = f'<div style="margin-top:8px;"><span class="muted" style="font-size:0.8em;">Fray commands:</span><br><div style="margin-top:4px;">{cmd_items}</div></div>'
            st_html += f'''<div style="background:var(--surface2);border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:3px solid {sev_color};"><div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;"><span class="sev-badge" style="background:{sev_color}20;color:{sev_color};">{sev_label.upper()}</span><span style="font-weight:700;font-size:0.95em;">{_esc(typ)}</span><span class="muted" style="font-size:0.85em;">{len(targets)} target(s)</span></div>{desc_html}<div style="display:flex;flex-wrap:wrap;gap:6px;">{chips}{overflow}</div>{cmds_html}</div>'''
        parts.append(f'''
<div class="sec" id="tests">
  <h2>Suggested Tests <span class="count">({len(tests_by_type)} types, {n_attack_targets} targets)</span></h2>
  {st_html}
</div>''')

    # Recommended Categories
    _CAT_DESC = {
        'csp_bypass': 'Bypass Content-Security-Policy restrictions via JSONP, base-tag, and trusted-type abuse',
        'modern_bypasses': 'Latest WAF evasion techniques — encoding tricks, DOM clobbering, prototype pollution payloads',
        'prototype_pollution': 'Pollute JavaScript Object.prototype to hijack application logic and achieve XSS',
        'ssrf': 'Server-Side Request Forgery — access internal services, cloud metadata, and private networks',
        'ssti': 'Server-Side Template Injection — execute arbitrary code via Jinja2, Twig, Freemarker templates',
        'api_security': 'OWASP API Top-10 payloads — BOLA, broken auth, mass assignment, injection',
        'xss': 'Cross-Site Scripting — reflected, stored, and DOM-based injection vectors',
        'sqli': 'SQL Injection — union, blind, time-based, and out-of-band techniques',
        'xxe': 'XML External Entity — file read, SSRF, and denial of service via DTD abuse',
        'lfi': 'Local File Inclusion — path traversal, null-byte injection, wrapper abuse',
    }
    if rec_cats:
        cl = ''
        for c in rec_cats[:10]:
            desc = _CAT_DESC.get(c, '')
            desc_html = f'<span class="muted" style="font-size:0.85em;"> — {_esc(desc)}</span>' if desc else ''
            cmd = f'fray test {_esc(target)} -c {_esc(c)} --smart'
            cl += (f'<li style="margin:8px 0;"><strong>{_esc(c)}</strong>{desc_html}'
                   f'<br><code style="background:var(--surface2);padding:4px 10px;border-radius:5px;font-size:0.85em;margin-top:4px;display:inline-block;">{cmd}</code></li>')
        parts.append(f'''
<div class="sec" id="cats">
  <h2>Recommended Payload Categories</h2>
  <ol style="padding-left:20px;line-height:1.8;">{cl}</ol>
</div>''')

    # Remediation Plan
    if remediation:
        rr = ''
        for i, r in enumerate(remediation[:10], 1):
            if isinstance(r, dict):
                ra = _esc(r.get('action', ''))
                rs = r.get('severity', 'medium')
                rsc = SEV_COLORS.get(rs, '#64748b')
                rw = _esc(r.get('why', ''))
                rh = _esc(r.get('how', ''))
                rt = _esc(r.get('timeline', ''))
                rr += f'<tr><td class="num">{i}</td><td><strong>{ra}</strong></td><td><span class="sev-badge" style="background:{rsc}20;color:{rsc};">{rs.upper()}</span></td><td class="muted" style="font-size:0.85em;">{rw}</td><td style="font-size:0.85em;">{rh}</td><td style="font-size:0.85em;white-space:nowrap;">{rt}</td></tr>'
            else:
                rr += f'<tr><td class="num">{i}</td><td colspan="5">{_esc(str(r))}</td></tr>'
        parts.append(f'''
<div class="sec" id="remediation">
  <h2>Remediation Plan <span class="count">({len(remediation)} action items)</span></h2>
  <p class="muted" style="margin-bottom:14px;">Prioritised remediation actions sorted by severity and business impact.</p>
  <table><tr><th>#</th><th>Action</th><th>Severity</th><th>Why</th><th>How</th><th>Timeline</th></tr>{rr}</table>
</div>''')

    # Footer
    parts.append(f'''
<div class="foot">
  <div style="border-top:1px solid var(--border);padding-top:20px;margin-top:8px;">
    <p><strong><a href="https://github.com/dalisecurity/Fray">Fray</a></strong> — DALI Security Reconnaissance Engine</p>
    <p style="margin-top:4px;">Report generated: {_esc(ts_short)}</p>
    <p style="margin-top:8px;font-size:0.75em;max-width:700px;margin-left:auto;margin-right:auto;">
      <strong>CONFIDENTIAL</strong> — This report contains sensitive security information.
      Share only with authorized personnel.
    </p>
  </div>
</div>
</div></body></html>''')

    return '\n'.join(parts)
