"""v11 Recon Report HTML builder — called by SecurityReportGenerator._build_recon_html_v11()."""
import html as _html
import ipaddress as _ipaddr
import re as _re_mod
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
    rate_limit = rd.get('rate_limits', rd.get('rate_limit', {})) or {}
    remediation = atk.get('remediation', [])
    staging_envs = atk.get('staging_envs', [])
    checks = rd.get('security_checks', {}) or {}

    # VPN endpoints
    vpn_data = rd.get('vpn_endpoints', {}) or {}
    vpn_list = vpn_data.get('vpn_endpoints', []) if isinstance(vpn_data, dict) else []
    vpn_cve_findings = vpn_data.get('cve_findings', []) if isinstance(vpn_data, dict) else []
    n_vpn = len(vpn_list)

    # API security
    api_sec = rd.get('api_security', {}) or {}
    api_specs = api_sec.get('specs', api_sec.get('exposed_specs', [])) if isinstance(api_sec, dict) else []
    api_endpoints = api_sec.get('endpoints', api_sec.get('api_endpoints', [])) if isinstance(api_sec, dict) else []
    api_gw = api_sec.get('api_gateway', api_sec.get('gateway_info', {})) if isinstance(api_sec, dict) else {}
    api_rate = api_sec.get('rate_limiting', api_sec.get('rate_limit_info', {})) if isinstance(api_sec, dict) else {}
    api_auth = api_sec.get('authentication', api_sec.get('auth_info', {})) if isinstance(api_sec, dict) else {}
    n_api_specs = api_sec.get('total_specs', len(api_specs) if isinstance(api_specs, list) else 0)

    # Cloud buckets
    bucket_data = rd.get('cloud_buckets', {}) or {}
    bucket_list = bucket_data.get('buckets', []) if isinstance(bucket_data, dict) else []
    n_buckets = bucket_data.get('total_found', len(bucket_list)) if isinstance(bucket_data, dict) else 0
    n_public_buckets = bucket_data.get('total_public', 0) if isinstance(bucket_data, dict) else 0

    # Per-subdomain security
    sub_sec = rd.get('subdomain_security', {}) or {}

    # Emoji map for attack vectors
    _VEC_EMOJI = {
        'WAF Bypass': '\U0001f6e1\ufe0f', 'Unprotected Subdomain': '\U0001f310',
        'Account Takeover': '\U0001f511', 'API Vulnerability': '\U0001f50c',
        'LLM / AI Prompt Injection': '\U0001f916', 'Payment / Financial Abuse': '\U0001f4b3',
        'Staging / Dev Environment': '\U0001f9ea', 'DDoS / L7 Denial of Service': '\u26a1',
        'Web Cache Poisoning': '\U0001f4be', 'DDoS \u2014 Direct Origin': '\u26a1',
    }

    # VPN vendor display
    vpn_vendors = [v.get('label', '') for v in vpn_list] if vpn_list else []
    if vpn_vendors:
        vpn_display = ', '.join(v.split('(')[0].strip() for v in vpn_vendors[:2])
        if len(vpn_vendors) > 2:
            vpn_display += f' +{len(vpn_vendors) - 2}'
    else:
        vpn_display = ''
    vpn_has_cves = bool(vpn_data.get('verified_cves') or vpn_data.get('potential_cves'))

    # API gateway display
    api_gw_display = ''
    if isinstance(api_gw, dict) and api_gw.get('detected'):
        gw_names = [info.get('vendor', k) for k, info in api_gw.items() if k != 'detected' and isinstance(info, dict)]
        api_gw_display = ', '.join(gw_names[:2]) if gw_names else 'Detected'

    rc = risk_color(risk_score)
    hdr_color = 'var(--red)' if hdr_score < 30 else 'var(--yellow)' if hdr_score < 60 else 'var(--green)'

    # ── Pieces ──
    parts = []
    parts.append(f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
                 f'<meta name="viewport" content="width=device-width,initial-scale=1.0">'
                 f'<title>Attack Surface Intelligence — {_esc(host)} — Fray</title>'
                 f'<style>{CSS}</style></head><body><div class="wrap">')

    # Header
    parts.append(f'''
<div class="hdr">
  <div>
    <div class="logo"><span class="logo-name">DALI</span><span class="logo-sub">SECURITY</span></div>
    <h1 style="margin-top:12px;">Attack Surface Intelligence</h1>
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
    {f'<div class="mc"><div class="l">VPN Vendor</div><div class="v" style="font-size:0.85em;color:{"var(--red)" if vpn_has_cves else "var(--orange)"};"><a href="#vpn" style="color:inherit;text-decoration:none;">{_esc(vpn_display)}</a></div></div>' if vpn_display else ''}
    {f'<div class="mc"><div class="l">API Gateway</div><div class="v" style="font-size:0.85em;color:var(--cyan);"><a href="#apisec" style="color:inherit;text-decoration:none;">{_esc(api_gw_display)}</a></div></div>' if api_gw_display else ''}
    {f'<div class="mc"><div class="l">Public Buckets</div><div class="v" style="color:var(--red);"><a href="#buckets" style="color:inherit;text-decoration:none;">{n_public_buckets}</a></div></div>' if n_public_buckets else ''}
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
      <div style="display:flex;flex-wrap:wrap;gap:5px;"><a href="#headers" class="toc-link">Headers</a><a href="#csp" class="toc-link">CSP</a><a href="#tech" class="toc-link">Tech</a><a href="#dns" class="toc-link">DNS</a><a href="#waf-cdn" class="toc-link">WAF/CDN</a><a href="#gap" class="toc-link">Gap Analysis</a><a href="#rl" class="toc-link">Rate Limits</a><a href="#vpn" class="toc-link">VPN</a><a href="#apisec" class="toc-link">API Security</a><a href="#buckets" class="toc-link">Cloud Buckets</a></div></div>
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
        _TYPE_COLORS = {
            'WAF Bypass': '#ef4444', 'Unprotected Subdomain': '#f97316',
            'Account Takeover': '#ef4444', 'API Vulnerability': '#f97316',
            'SSRF': '#ef4444', 'File Upload': '#f97316',
            'Payment': '#ef4444', 'Cloud Storage': '#a855f7',
            'LLM/AI': '#a855f7', 'DDoS': '#eab308',
            'Cache Poisoning': '#eab308', 'JWT': '#f97316',
            'Rate Limit': '#eab308', 'WebSocket': '#3b82f6',
            'Robots Paths': '#64748b', 'Open Redirect': '#f97316',
            'Critical Endpoint Exposure': '#ef4444', 'Staging / Dev Environment': '#eab308',
            'DDoS / L7 Denial of Service': '#eab308', 'DDoS — Direct Origin': '#eab308',
            'Web Cache Poisoning': '#f97316', 'Payment / Financial Abuse': '#ef4444',
            'LLM / AI Prompt Injection': '#a855f7',
        }
        at_rows = ''
        _at_limit = 20
        for i, t in enumerate(attack_targets[:_at_limit], 1):
            tp = t.get('priority', 0)
            tt = t.get('type', '')
            tgt = t.get('target', '')
            pc = '#ef4444' if tp >= 90 else '#f97316' if tp >= 70 else '#eab308' if tp >= 50 else '#64748b'
            tc = _TYPE_COLORS.get(tt, '#3b82f6')
            at_rows += f'<tr><td class="num">{i}</td><td style="color:{pc};font-weight:700;">{tp}</td><td><span class="type-badge" style="background:{tc}20;color:{tc};">{_esc(tt)}</span></td><td class="mono" style="font-size:0.85em;">{_esc(tgt)}</td></tr>'
        overflow_note = f'<p class="muted" style="margin-top:8px;font-size:0.85em;">Showing top {_at_limit} of {n_attack_targets} targets by priority. See <a href="#vectors" style="color:var(--accent);">Attack Vectors</a> above for full details.</p>' if n_attack_targets > _at_limit else ''
        parts.append(f'''
<div class="sec" id="priorities">
  <h2>Attack Priorities <span class="count">(Top {min(_at_limit, n_attack_targets)} of {n_attack_targets})</span></h2>
  <table><tr><th>#</th><th>Priority</th><th>Type</th><th>Target</th></tr>{at_rows}</table>
  {overflow_note}
</div>''')

    # CVEs — both frontend libs and server-side technologies
    cve_items = ''
    # Sort: critical first, then high, medium, low
    _sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_vulns = sorted(fl_vulns, key=lambda v: _sev_order.get(v.get('severity', 'info'), 5))
    for v in sorted_vulns[:30]:
        sev = v.get('severity', 'info')
        sc = SEV_COLORS.get(sev, '#64748b')
        src = v.get('source', 'frontend')
        src_badge = f'<span class="type-badge" style="background:#64748b20;color:#64748b;font-size:0.75em;">{_esc(src)}</span>' if src == 'server_header' else ''
        cve_items += f'<tr><td><span style="color:{sc};font-weight:700;">{_esc(v.get("id",""))}</span></td><td class="mono">{_esc(v.get("library",""))} {src_badge}</td><td><span style="color:{sc};">{_esc(sev)}</span></td><td class="muted" style="font-size:0.85em;">{_esc(v.get("description", v.get("summary",""))[:120])}</td></tr>'
    # Show detected libs table
    detected_libs = fl.get('libraries', []) if isinstance(fl, dict) else []
    libs_html = ''
    if detected_libs:
        lib_rows = ''
        for l in detected_libs[:20]:
            cves = l.get('cves', [])
            status = f'<span style="color:var(--red);font-weight:600;">{len(cves)} CVE(s)</span>' if cves else '<span style="color:var(--green);">No known CVEs</span>'
            lib_rows += f'<tr><td class="mono">{_esc(l.get("name",""))}</td><td>{_esc(l.get("version",""))}</td><td>{_esc(l.get("source",""))}</td><td>{status}</td></tr>'
        libs_html = f'<details style="margin-top:12px;"><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Detected libraries & technologies ({len(detected_libs)})</summary><table style="margin-top:8px;"><tr><th>Technology</th><th>Version</th><th>Source</th><th>Status</th></tr>{lib_rows}</table></details>'
    elif not cve_items:
        libs_html = f'''<div style="margin-top:8px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid var(--muted);">
  <p style="font-size:0.85em;line-height:1.7;">Scans 35+ frontend libraries (jQuery, Bootstrap, Angular, Vue, React, Lodash, D3, etc.) and server technologies (Apache, Nginx, IIS, Tomcat, PHP, OpenSSL) for known CVEs.
  Run <code>fray recon {_esc(host)} --deep</code> for deeper subdomain-level version detection.</p>
</div>'''
    cve_table = f'<table><tr><th>CVE</th><th>Technology</th><th>Severity</th><th>Description</th></tr>{cve_items}</table>' if cve_items else ''
    parts.append(f'''
<div class="sec" id="cves">
  <h2>Known Vulnerabilities <span class="count">({len(fl_vulns)} CVEs, {n_vuln_libs} vulnerable component(s))</span></h2>
  {cve_table}{libs_html}
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
        'Load Balancer': 'var(--cyan)', 'Proxy': 'var(--cyan)',
        'Storage': 'var(--blue)', 'Cache': 'var(--blue)',
        'JavaScript Framework': 'var(--yellow)', 'JavaScript Library': 'var(--yellow)',
        'CSS Framework': 'var(--yellow)', 'UI Library': 'var(--yellow)',
        'Runtime': 'var(--green)', 'Language': 'var(--green)',
        'Analytics': 'var(--purple)', 'Marketing': 'var(--purple)',
        'Captcha': 'var(--orange)', 'Security': 'var(--green)',
        'E-commerce': 'var(--orange)', 'Payment': 'var(--orange)',
        'CRM': 'var(--blue)', 'Support': 'var(--blue)',
        'ITSM': 'var(--blue)', 'Identity': 'var(--green)',
        'SaaS': 'var(--purple)', 'PaaS': 'var(--purple)',
        'Hosting': 'var(--muted)', 'BaaS': 'var(--purple)',
        'Monitoring': 'var(--orange)', 'SIEM': 'var(--red)',
        'Telco': 'var(--blue)', 'Communication': 'var(--blue)',
        'Editor': 'var(--yellow)', 'Visualization': 'var(--purple)',
        'Media': 'var(--cyan)', 'Maps': 'var(--green)',
        'A/B Testing': 'var(--purple)', 'Feature Flags': 'var(--purple)',
        'Message Queue': 'var(--orange)', 'Directory': 'var(--muted)',
        'Collaboration': 'var(--blue)', 'Wiki': 'var(--blue)',
        'Project Management': 'var(--blue)', 'Code Quality': 'var(--orange)',
        'API Gateway': 'var(--cyan)', 'Icon Library': 'var(--yellow)',
        'AI / LLM': '#a855f7', 'AI / ML': '#a855f7',
        'AI Chatbot': '#a855f7', 'Chatbot': '#a855f7',
        'AI Framework': '#a855f7', 'AI Gateway': '#a855f7',
        'AI Search': '#a855f7', 'AI Support': '#a855f7',
        'Vector DB': '#a855f7',
    }
    # Group technologies by category
    _CAT_ORDER = [
        # Security & Infrastructure
        'WAF', 'CDN', 'CDN/WAF', 'Cloud', 'Cloud/CDN',
        'Web Server', 'Load Balancer', 'Proxy', 'API Gateway', 'Storage', 'Cache',
        'Application Server', 'Framework', 'Runtime', 'Language',
        # Frontend
        'JavaScript Framework', 'JavaScript Library', 'CSS Framework', 'UI Library', 'Icon Library',
        'Visualization', 'Editor', 'Media', 'Maps',
        # CMS & E-commerce
        'CMS', 'E-commerce',
        # SaaS & Business
        'CRM', 'Support', 'ITSM', 'Payment', 'Identity',
        'Marketing', 'Analytics', 'A/B Testing', 'Feature Flags',
        'Captcha', 'Security',
        # Communication & Collaboration
        'Communication', 'Collaboration', 'Wiki', 'Project Management',
        # Data & Search
        'Database', 'Search Engine', 'Message Queue',
        # Platform & Hosting
        'SaaS', 'PaaS', 'BaaS', 'Hosting', 'Telco',
        # DevOps & Monitoring
        'Container', 'Container Orchestration', 'CI/CD', 'DevOps', 'Code Quality',
        'Monitoring', 'SIEM', 'Directory',
        # AI / LLM / Chatbot
        'AI / LLM', 'AI / ML', 'AI Chatbot', 'Chatbot', 'AI Framework',
        'AI Gateway', 'AI Search', 'AI Support', 'Vector DB',
        # API & Infra
        'API', 'TLS', 'Cipher Suite', 'Certificate Authority', 'Infrastructure',
    ]
    cat_groups = {}  # category -> [(name, info), ...]
    for name, ver in techs.items():
        if isinstance(ver, dict):
            cat = ver.get('category', 'Other')
        else:
            cat = 'Other'
        cat_groups.setdefault(cat, []).append(name)
    tech_html = ''
    for cat in _CAT_ORDER + [c for c in cat_groups if c not in _CAT_ORDER]:
        if cat not in cat_groups:
            continue
        names = sorted(cat_groups[cat])
        cat_col = _CAT_COLORS.get(cat, 'var(--muted)')
        # Also check partial matches for combined categories like CDN/WAF
        if cat_col == 'var(--muted)':
            for base_cat in cat.split('/'):
                if base_cat.strip() in _CAT_COLORS:
                    cat_col = _CAT_COLORS[base_cat.strip()]
                    break
        chips = ' '.join(f'<span style="display:inline-block;background:var(--surface);padding:5px 12px;border-radius:6px;font-size:0.88em;border:1px solid var(--border);margin:3px 2px;">{_esc(n)}</span>' for n in names)
        tech_html += f'<div style="margin-bottom:10px;"><span class="type-badge" style="background:{cat_col}20;color:{cat_col};font-size:0.82em;min-width:100px;text-align:center;">{_esc(cat)}</span> {chips}</div>'
    parts.append(f'''
<div class="sec" id="tech">
  <h2>Technologies <span class="count">({len(techs)})</span></h2>
  {tech_html if tech_html else '<p class="muted">No technologies detected.</p>'}
</div>''')

    # DNS — show NS, MX, CNAME chain, email provider, SPF, DMARC
    def _is_ip(s):
        try:
            _ipaddr.ip_address(s)
            return True
        except (ValueError, TypeError):
            return False
    raw_a = dns.get('a', [])
    # Build CNAME chain
    cname_list = dns.get('cname', [])
    if isinstance(cname_list, str):
        cname_list = [cname_list] if cname_list else []
    chain_hosts = [r for r in raw_a if not _is_ip(r)]
    full_chain = []
    if cname_list:
        full_chain.extend(cname_list)
    for h in chain_hosts:
        if h not in full_chain:
            full_chain.append(h)
    a_ips = [r for r in raw_a if _is_ip(r)]
    if a_ips:
        full_chain.append(a_ips[0])
    cname_display = ' &rarr; '.join(f'<span class="mono">{_esc(h)}</span>' for h in full_chain) if full_chain else '—'

    # NS records
    ns_recs = dns.get('ns', [])
    ns_display = ', '.join(ns_recs) if ns_recs else '—'

    # MX records + email provider
    mx_recs = dns.get('mx', [])
    email_providers = dns.get('email_providers', [])
    if mx_recs:
        mx_chips = ' '.join(f'<code style="background:var(--surface);padding:3px 8px;border-radius:4px;font-size:0.85em;border:1px solid var(--border);">{_esc(m)}</code>' for m in mx_recs[:5])
        provider_badge = ''
        if email_providers:
            provider_badge = ' ' + ' '.join(f'<span class="type-badge" style="background:var(--blue)20;color:var(--blue);font-size:0.8em;">{_esc(p)}</span>' for p in email_providers)
        mx_display = f'{mx_chips}{provider_badge}'
    else:
        mx_display = '<span class="muted">No MX records</span>'

    spf = dns.get('spf', '')
    dmarc = dns.get('dmarc', '')

    # DNSSEC
    dnssec = rd.get('dnssec', {}) or {}
    dnssec_enabled = dnssec.get('enabled', False) if isinstance(dnssec, dict) else False
    dnssec_validated = dnssec.get('validated', False) if isinstance(dnssec, dict) else False
    if dnssec_enabled and dnssec_validated:
        dnssec_display = '<span style="color:var(--green);font-weight:600;">&#x2713; Enabled &amp; Validated</span>'
    elif dnssec_enabled:
        dnssec_display = '<span style="color:var(--yellow);font-weight:600;">&#x26a0; Enabled but not validated</span>'
    else:
        dnssec_display = '<span style="color:var(--red);">&#x2717; Not enabled</span>'
    dnssec_detail = ''
    if dnssec.get('has_dnskey'):
        dnssec_detail += ' <span class="muted" style="font-size:0.82em;">DNSKEY</span>'
    if dnssec.get('has_rrsig'):
        dnssec_detail += ' <span class="muted" style="font-size:0.82em;">RRSIG</span>'
    if dnssec.get('nsec_type'):
        dnssec_detail += f' <span class="muted" style="font-size:0.82em;">{_esc(str(dnssec["nsec_type"]))}</span>'

    # OSINT email harvest
    email_harvest = rd.get('email_harvest', {}) or {}
    harvest_emails_list = email_harvest.get('emails', []) if isinstance(email_harvest, dict) else []
    role_addresses = email_harvest.get('role_addresses', []) if isinstance(email_harvest, dict) else []
    email_patterns = email_harvest.get('patterns', []) if isinstance(email_harvest, dict) else []
    email_html = ''
    if harvest_emails_list or role_addresses:
        email_chips = ''
        for e in harvest_emails_list[:10]:
            addr = e.get('email', str(e)) if isinstance(e, dict) else str(e)
            email_chips += f'<code style="background:var(--surface);padding:3px 8px;border-radius:4px;font-size:0.85em;border:1px solid var(--border);">{_esc(addr)}</code> '
        for r in role_addresses[:5]:
            addr = r.get('address', str(r)) if isinstance(r, dict) else str(r)
            status = r.get('status', '') if isinstance(r, dict) else ''
            st_color = 'var(--green)' if status == 'valid' else 'var(--muted)'
            email_chips += f'<code style="background:var(--surface);padding:3px 8px;border-radius:4px;font-size:0.85em;border:1px solid {st_color};">{_esc(addr)}</code> '
        n_emails = len(harvest_emails_list) + len(role_addresses)
        pattern_note = ''
        if email_patterns:
            pat = email_patterns[0].get('pattern', '') if isinstance(email_patterns[0], dict) else str(email_patterns[0])
            if pat:
                pattern_note = f' <span class="muted" style="font-size:0.82em;">Pattern: <code>{_esc(pat)}</code></span>'
        email_html = f'<tr><td class="kv-key">Emails (OSINT)</td><td>{email_chips}{pattern_note}</td></tr>'
    elif not harvest_emails_list:
        email_html = '<tr><td class="kv-key">Emails (OSINT)</td><td class="muted">No emails discovered (set HUNTER_API_KEY for deeper results)</td></tr>'

    spf_cell = '&#x2713; ' + _esc(spf[:100]) if spf else '&#x2717; <span style="color:var(--red);">Missing</span>'
    dmarc_cell = '&#x2713; ' + _esc(dmarc[:100]) if dmarc else '&#x2717; <span style="color:var(--red);">Missing</span>'

    parts.append(f'''
<div class="sec" id="dns">
  <h2>DNS &amp; Email</h2>
  <table>
    <tr><td class="kv-key">NS</td><td class="mono" style="word-break:break-all;">{_esc(ns_display)}</td></tr>
    <tr><td class="kv-key">MX</td><td style="word-break:break-all;">{mx_display}</td></tr>
    <tr><td class="kv-key">CNAME Chain</td><td style="word-break:break-all;">{cname_display}</td></tr>
    <tr><td class="kv-key">DNSSEC</td><td>{dnssec_display}{dnssec_detail}</td></tr>
    <tr><td class="kv-key">SPF</td><td>{spf_cell}</td></tr>
    <tr><td class="kv-key">DMARC</td><td>{dmarc_cell}</td></tr>
    {email_html}
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
        # Only show subdomains with WAF or CDN (unprotected are in Subdomains section)
        protected_subs = [s for s in per_sub if s.get('waf') or s.get('cdn')]
        per_sub_sorted = sorted(protected_subs, key=_sub_sort_key)
        n_unprotected = len(per_sub) - len(protected_subs)
        sr = ''
        for i, s in enumerate(per_sub_sorted[:show_limit]):
            wv = s.get('waf') or '—'
            cv = s.get('cdn') or '—'
            sv = _esc((s.get('server') or '-')[:20])
            ws = 'color:var(--green);font-weight:600;' if s.get('waf') else 'color:var(--red);'
            cs = 'color:var(--blue);font-weight:600;' if s.get('cdn') else 'color:var(--muted);'
            sr += f'<tr><td class="mono">{_esc(s["subdomain"])}</td><td style="{ws}">{_esc(wv)}</td><td style="{cs}">{_esc(cv)}</td><td class="muted">{sv}</td></tr>'

        overflow = f'<p class="muted" style="margin-top:8px;">Showing first {show_limit} of {len(per_sub)} subdomains.</p>' if len(per_sub) > show_limit else ''

        unprotected_note = f'<p class="muted" style="margin-top:8px;font-size:0.85em;">{n_unprotected} subdomain(s) without WAF/CDN protection — see <a href="#subs" style="color:var(--accent);">Subdomains</a> section for details.</p>' if n_unprotected else ''
        parts.append(f'''
<div class="sec" id="waf-cdn">
  <h2>Per-Subdomain WAF / CDN Analysis <span class="count">({len(protected_subs)} protected of {len(per_sub)} probed)</span></h2>
  <div style="margin-bottom:14px;">{badges}</div>
  <details open><summary>Show protected subdomains ({len(protected_subs)})</summary>
  <table><tr><th>Subdomain</th><th>WAF</th><th>CDN</th><th>Server</th></tr>{sr}</table>
  {overflow}{unprotected_note}</details>
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
    rl_type = rate_limit.get('detection_type', rate_limit.get('type', 'none')) if isinstance(rate_limit, dict) else 'none'
    rl_thresh = rate_limit.get('threshold_rps', rate_limit.get('threshold')) if isinstance(rate_limit, dict) else None
    rl_headers = rate_limit.get('rate_limit_headers', {}) if isinstance(rate_limit, dict) else {}
    rl_crit = rd.get('rate_limits_critical', {}) or {}
    rl_crit_paths = rl_crit.get('rate_limited_paths', []) if isinstance(rl_crit, dict) else []
    rl_crit_summary = rl_crit.get('summary', '') if isinstance(rl_crit, dict) else ''

    # Infer rate limiting from WAF/CDN when detection returned 'none'
    waf_dist_data = cloud_dist.get('waf_distribution', {})
    cdn_dist_data = cloud_dist.get('cdn_distribution', {})
    rl_inferred = ''
    if rl_type == 'none' and (waf_dist_data or cdn_dist_data):
        waf_names = ', '.join(waf_dist_data.keys())
        cdn_names = ', '.join(cdn_dist_data.keys())
        providers = [p for p in [waf_names, cdn_names] if p]
        rl_inferred = (f'<div style="margin-top:12px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid var(--orange);">'
            f'<p style="font-size:0.9em;font-weight:600;color:var(--orange);margin-bottom:8px;">Inferred Rate Limiting</p>'
            f'<p style="font-size:0.85em;line-height:1.7;">'
            f'WAF/CDN providers detected: <strong>{", ".join(providers)}</strong>. '
            f'These services typically enforce rate limiting at the edge (e.g., AWS WAF rate-based rules, '
            f'Azure Front Door rate limiting, Akamai Bot Manager). '
            f'Rate limits may not be visible via passive header inspection but are likely active.</p>'
            f'<ul style="padding-left:18px;font-size:0.85em;line-height:1.9;margin-top:8px;">'
            f'<li><strong>AWS WAF</strong> — rate-based rules (100-20,000 req/5min per IP), auto-block on threshold</li>'
            f'<li><strong>Azure Front Door</strong> — rate limiting rules with custom thresholds per route</li>'
            f'<li><strong>Akamai</strong> — Bot Manager + Client Reputation, adaptive rate controls</li>'
            f'<li>Run <code>fray recon {_esc(host)} --deep</code> to actively probe rate limit thresholds</li>'
            f'</ul></div>')

    # Rate limit headers found
    rl_hdr_html = ''
    if rl_headers:
        hdr_rows = ''.join(f'<tr><td class="mono">{_esc(k)}</td><td>{_esc(str(v))}</td></tr>' for k, v in rl_headers.items())
        rl_hdr_html = f'<h3 style="margin-top:14px;font-size:0.95em;">Rate Limit Headers</h3><table><tr><th>Header</th><th>Value</th></tr>{hdr_rows}</table>'

    # Critical path rate limiting
    rl_crit_html = ''
    if rl_crit_paths:
        cp_rows = ''.join(f'<tr><td class="mono">{_esc(p.get("path",""))}</td><td>{p.get("status","")}</td><td class="muted">{_esc(p.get("type",""))}</td></tr>' for p in rl_crit_paths[:10])
        rl_crit_html = f'<h3 style="margin-top:14px;font-size:0.95em;">Critical Path Rate Limiting</h3><table><tr><th>Path</th><th>Status</th><th>Type</th></tr>{cp_rows}</table>'
    elif rl_crit_summary:
        rl_crit_html = f'<p class="muted" style="margin-top:8px;font-size:0.85em;">{_esc(rl_crit_summary)}</p>'

    rl_status_color = 'var(--green)' if rl_type != 'none' else 'var(--red)'
    parts.append(f'''
<div class="sec" id="rl">
  <h2>Rate Limits</h2>
  <table>
    <tr><td class="kv-key">Detection</td><td style="color:{rl_status_color};font-weight:600;">{_esc(str(rl_type))}</td></tr>
    <tr><td class="kv-key">Threshold</td><td>{rl_thresh or '<span class="muted">Not detected via headers</span>'}</td></tr>
  </table>
  {rl_hdr_html}{rl_crit_html}{rl_inferred}
</div>''')

    # ── VPN Endpoints ──
    if vpn_list:
        vpn_rows = ''
        for v in vpn_list:
            prod = _esc(v.get('label', ''))
            paths = ', '.join(v.get('paths', [])[:3])
            sigs = ', '.join(v.get('signals', [])[:2])
            sev_note = v.get('severity_note') or ''
            verified = v.get('verified_cves', [])
            potential = v.get('potential_cves', [])

            # Severity color
            if sev_note.startswith('Critical') or verified:
                sev_col = '#ef4444'
                sev_label = 'CRITICAL'
            elif sev_note.startswith('High'):
                sev_col = '#f97316'
                sev_label = 'HIGH'
            else:
                sev_col = '#eab308'
                sev_label = 'MEDIUM'

            cve_badges = ''
            for cv in verified:
                cve_badges += f'<span class="sev-badge" style="background:#ef444420;color:#ef4444;font-size:0.78em;">{_esc(cv)} &#x2713;</span> '
            for cv in potential:
                cve_badges += f'<span class="sev-badge" style="background:#eab30820;color:#eab308;font-size:0.78em;">{_esc(cv)} ?</span> '

            vpn_rows += f'''<tr>
  <td><strong style="color:{sev_col};">{prod}</strong></td>
  <td><span class="sev-badge" style="background:{sev_col}20;color:{sev_col};">{sev_label}</span></td>
  <td class="mono" style="font-size:0.82em;">{_esc(paths)}</td>
  <td style="font-size:0.82em;">{cve_badges or '<span class="muted">—</span>'}</td>
  <td class="muted" style="font-size:0.82em;">{_esc(sigs[:80])}</td>
</tr>'''

        # CVE detail table
        cve_detail = ''
        if vpn_cve_findings:
            cve_rows = ''
            for c in sorted(vpn_cve_findings, key=lambda x: -(x.get('cvss', 0) or 0)):
                cvss = c.get('cvss', 0)
                cvss_col = '#ef4444' if cvss >= 9 else '#f97316' if cvss >= 7 else '#eab308'
                verified_icon = '&#x2713;' if c.get('verified') else '&#x26a0;'
                ver_col = 'var(--green)' if c.get('verified') else 'var(--yellow)'
                evidence = '; '.join(c.get('evidence', [])[:2])
                cve_rows += f'''<tr>
  <td><strong>{_esc(c.get("cve_id", ""))}</strong></td>
  <td style="color:{cvss_col};font-weight:700;">{cvss}</td>
  <td style="color:{ver_col};">{verified_icon}</td>
  <td style="font-size:0.84em;">{_esc(c.get("description", "")[:100])}</td>
  <td class="muted" style="font-size:0.82em;">{_esc(c.get("affected_versions", "")[:60])}</td>
  <td style="font-size:0.82em;">{_esc(c.get("remediation", "")[:80])}</td>
</tr>'''
            cve_detail = f'''<details style="margin-top:14px;"><summary style="cursor:pointer;font-weight:600;font-size:0.92em;color:var(--accent);">CVE Verification Details ({len(vpn_cve_findings)})</summary>
  <table style="margin-top:8px;"><tr><th>CVE</th><th>CVSS</th><th>Status</th><th>Description</th><th>Affected</th><th>Remediation</th></tr>{cve_rows}</table>
</details>'''

        # Sub-VPN findings
        sub_vpn_rows = ''
        sub_vpn_list = sub_sec.get('vpn_endpoints', []) if isinstance(sub_sec, dict) else []
        if sub_vpn_list:
            for sf, vd in sub_vpn_list[:10]:
                for sv in vd.get('vpn_endpoints', []):
                    sub_vpn_rows += f'<tr><td class="mono">{_esc(sf)}</td><td><strong>{_esc(sv.get("label", ""))}</strong></td><td class="mono" style="font-size:0.82em;">{_esc(", ".join(sv.get("paths", [])[:2]))}</td></tr>'
            if sub_vpn_rows:
                sub_vpn_rows = f'<details style="margin-top:14px;"><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Subdomain VPN Findings ({len(sub_vpn_list)})</summary><table style="margin-top:8px;"><tr><th>Subdomain</th><th>Vendor</th><th>Paths</th></tr>{sub_vpn_rows}</table></details>'

        n_verified = len(vpn_data.get('verified_cves', []))
        n_potential = len(vpn_data.get('potential_cves', []))
        cve_summary = ''
        if n_verified:
            cve_summary += f' <span style="color:var(--red);font-weight:600;">{n_verified} verified CVE(s)</span>'
        if n_potential:
            cve_summary += f' <span style="color:var(--yellow);">{n_potential} potential</span>'

        parts.append(f'''
<div class="sec" id="vpn">
  <h2>VPN / Remote Access Endpoints <span class="count">({n_vpn} vendor(s){cve_summary})</span></h2>
  <div style="margin-bottom:14px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid #ef4444;">
    <p style="font-size:0.9em;line-height:1.6;margin:0;">Enterprise VPN concentrators are high-priority targets — consistently in <strong>CISA KEV</strong> and exploited by ransomware groups for initial network access. Each detected vendor is checked against known CVEs with safe, non-destructive probes.</p>
  </div>
  <table><tr><th>Vendor</th><th>Severity</th><th>Detected Paths</th><th>CVEs</th><th>Detection Signals</th></tr>{vpn_rows}</table>
  {cve_detail}{sub_vpn_rows}
</div>''')

    # ── API Security ──
    _api_has_data = (n_api_specs > 0 or
                     (isinstance(api_gw, dict) and api_gw.get('detected')) or
                     (isinstance(api_rate, dict) and api_rate.get('detected')) or
                     (isinstance(api_auth, dict) and api_auth.get('detected')) or
                     (isinstance(api_endpoints, list) and len(api_endpoints) > 0))
    if _api_has_data:
        # Gateway info
        gw_html = '<span class="muted">Not detected</span>'
        if isinstance(api_gw, dict) and api_gw.get('detected'):
            gw_vendors = []
            for hdr, info in api_gw.items():
                if hdr == 'detected':
                    continue
                if isinstance(info, dict):
                    gw_vendors.append(info.get('vendor', hdr))
            gw_html = ', '.join(f'<strong style="color:var(--cyan);">{_esc(v)}</strong>' for v in gw_vendors) if gw_vendors else '<span style="color:var(--green);">Detected</span>'

        # Rate limiting
        rl_api_html = '<span style="color:var(--red);font-weight:600;">&#x2717; Not Detected</span>'
        if isinstance(api_rate, dict) and api_rate.get('detected'):
            rl_api_html = '<span style="color:var(--green);font-weight:600;">&#x2713; Detected</span>'
            rl_hdrs = {k: v for k, v in api_rate.items() if k != 'detected'}
            if rl_hdrs:
                rl_api_html += ' <span class="muted" style="font-size:0.82em;">(' + ', '.join(f'{k}={v}' for k, v in list(rl_hdrs.items())[:3]) + ')</span>'

        # Authentication
        auth_html = '<span style="color:var(--red);font-weight:600;">&#x2717; Not Detected</span>'
        if isinstance(api_auth, dict) and api_auth.get('detected'):
            auth_html = '<span style="color:var(--green);font-weight:600;">&#x2713; Detected</span>'
            auth_schemes = {k: v for k, v in api_auth.items() if k != 'detected'}
            if auth_schemes:
                auth_html += ' <span class="muted" style="font-size:0.82em;">(' + ', '.join(list(auth_schemes.keys())[:3]) + ')</span>'

        # Exposed specs table
        spec_rows = ''
        if isinstance(api_specs, list) and api_specs:
            for s in api_specs[:10]:
                if isinstance(s, dict):
                    spath = _esc(s.get('path', ''))
                    scat = _esc(s.get('category', ''))
                    sst = s.get('status', 0)
                    ssev = s.get('severity', 'info')
                    sc = SEV_COLORS.get(ssev, '#64748b')
                    spec_rows += f'<tr><td class="mono">{spath}</td><td>{scat}</td><td style="color:{sc};font-weight:600;">{sst}</td><td><span class="sev-badge" style="background:{sc}20;color:{sc};">{ssev.upper()}</span></td></tr>'
            spec_rows = f'<details style="margin-top:14px;"><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Exposed API Specs / Docs ({len(api_specs)})</summary><table style="margin-top:8px;"><tr><th>Path</th><th>Category</th><th>Status</th><th>Severity</th></tr>{spec_rows}</table></details>'

        # Sub-API findings
        sub_api_list = sub_sec.get('api_security', []) if isinstance(sub_sec, dict) else []
        sub_api_html = ''
        if sub_api_list:
            sa_rows = ''
            for sf, ad in sub_api_list[:10]:
                n_sp = ad.get('total_specs', 0)
                gw_det = '&#x2713;' if ad.get('api_gateway', {}).get('detected') else '&#x2717;'
                rl_det = '&#x2713;' if ad.get('rate_limiting', {}).get('detected') else '&#x2717;'
                au_det = '&#x2713;' if ad.get('authentication', {}).get('detected') else '&#x2717;'
                sa_rows += f'<tr><td class="mono">{_esc(sf)}</td><td>{n_sp}</td><td>{gw_det}</td><td>{rl_det}</td><td>{au_det}</td></tr>'
            sub_api_html = f'<details style="margin-top:14px;"><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Subdomain API Findings ({len(sub_api_list)})</summary><table style="margin-top:8px;"><tr><th>Subdomain</th><th>Specs</th><th>Gateway</th><th>Rate Limit</th><th>Auth</th></tr>{sa_rows}</table></details>'

        api_summary = api_sec.get('summary', '') if isinstance(api_sec, dict) else ''
        parts.append(f'''
<div class="sec" id="apisec">
  <h2>API Security <span class="count">({n_api_specs} spec(s) exposed)</span></h2>
  <table>
    <tr><td class="kv-key">API Gateway</td><td>{gw_html}</td></tr>
    <tr><td class="kv-key">Rate Limiting</td><td>{rl_api_html}</td></tr>
    <tr><td class="kv-key">Authentication</td><td>{auth_html}</td></tr>
    <tr><td class="kv-key">Specs Exposed</td><td>{('<span style="color:var(--red);font-weight:600;">' + str(n_api_specs) + ' spec(s)</span>') if n_api_specs else '<span style="color:var(--green);">None exposed</span>'}</td></tr>
  </table>
  {f'<p class="muted" style="margin-top:8px;font-size:0.85em;">{_esc(api_summary)}</p>' if api_summary else ''}
  {spec_rows}{sub_api_html}
</div>''')

    # ── Cloud Buckets ──
    if n_buckets > 0 or n_public_buckets > 0:
        _BUCKET_VENDOR_COLORS = {
            's3': ('#f97316', 'AWS S3'), 'azure': ('#3b82f6', 'Azure Blob'),
            'gcs': ('#22c55e', 'Google Cloud Storage'),
        }
        bkt_rows = ''
        for b in bucket_list[:30]:
            if not isinstance(b, dict):
                continue
            bname = _esc(b.get('name', ''))
            burl = _esc(b.get('url', ''))
            bvendor_key = b.get('provider', b.get('vendor', ''))
            bvendor_col, bvendor_label = _BUCKET_VENDOR_COLORS.get(
                bvendor_key.lower() if isinstance(bvendor_key, str) else '',
                ('#64748b', _esc(str(bvendor_key)) if bvendor_key else 'Unknown'))
            pub_read = b.get('public_read', False)
            pub_list = b.get('public_listing', False)
            found_on = b.get('found_on', '')
            status = b.get('status', '')

            access_badges = ''
            if pub_read:
                access_badges += '<span class="sev-badge" style="background:#ef444420;color:#ef4444;">PUBLIC READ</span> '
            if pub_list:
                access_badges += '<span class="sev-badge" style="background:#ef444420;color:#ef4444;">PUBLIC LIST</span> '
            if not pub_read and not pub_list:
                access_badges = '<span class="muted">Private</span>'

            bkt_rows += f'''<tr>
  <td class="mono" style="font-size:0.85em;">{bname}</td>
  <td><span class="type-badge" style="background:{bvendor_col}20;color:{bvendor_col};">{bvendor_label}</span></td>
  <td>{access_badges}</td>
  <td class="mono" style="font-size:0.82em;">{_esc(found_on) if found_on else _esc(host)}</td>
  <td class="muted" style="font-size:0.82em;">{status}</td>
</tr>'''

        # Sub-bucket findings
        sub_bkt_list = sub_sec.get('cloud_buckets', []) if isinstance(sub_sec, dict) else []
        sub_bkt_html = ''
        if sub_bkt_list:
            sb_rows = ''
            for sf, bd in sub_bkt_list[:10]:
                n_pub = bd.get('total_public', 0)
                n_found = bd.get('total_found', 0)
                sb_rows += f'<tr><td class="mono">{_esc(sf)}</td><td>{n_found}</td><td style="color:{"var(--red)" if n_pub else "var(--green)"};">{n_pub}</td></tr>'
            sub_bkt_html = f'<details style="margin-top:14px;"><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Subdomain Bucket Findings ({len(sub_bkt_list)})</summary><table style="margin-top:8px;"><tr><th>Subdomain</th><th>Total</th><th>Public</th></tr>{sb_rows}</table></details>'

        pub_color = 'var(--red)' if n_public_buckets else 'var(--green)'
        pub_warning = '<div style="margin-bottom:14px;background:var(--surface2);border-radius:10px;padding:14px 18px;border-left:3px solid #ef4444;"><p style="font-size:0.9em;line-height:1.6;margin:0;"><strong style="color:var(--red);">Public buckets detected!</strong> These cloud storage containers are accessible without authentication. Data exfiltration, backup leakage, and sensitive file exposure are immediate risks.</p></div>' if n_public_buckets else ''
        parts.append(f'''
<div class="sec" id="buckets">
  <h2>Cloud Storage Buckets <span class="count">({n_buckets} found, <span style="color:{pub_color};">{n_public_buckets} public</span>)</span></h2>
  {pub_warning}
  <table><tr><th>Bucket</th><th>Vendor</th><th>Access</th><th>Found On</th><th>Status</th></tr>{bkt_rows}</table>
  {sub_bkt_html}
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
  <details><summary>Show subdomains{sub_overflow}</summary>
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

    # High Value Targets (includes Admin Panels)
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
    _HVT_AI_STRICT = {"llm", "gpt", "openai", "chatgpt", "copilot", "genai", "gen-ai", "langchain", "ollama", "agenticai", "agentic"}
    _HVT_AI_SEG = {"ai", "chat", "bot", "robot", "chatbot", "aibot", "assistant"}
    def _hvt_is_ai(s):
        sl = s.lower()
        segs = _re_mod.split(r'[.\-_]', sl)
        for seg in segs:
            if seg in _HVT_AI_SEG:
                return True
            if len(seg) > 3 and seg.endswith("ai"):
                return True
        return any(kw in sl for kw in _HVT_AI_STRICT)
    ai_subs = [s for s in sub_list if _hvt_is_ai(s)]
    if ai_subs:
        hvt_items.append(('AI / LLM', ai_subs[:10], '#a855f7'))
    # Add Admin Panels as HVT category
    if admin_panels:
        admin_paths = [a.get('path', '') for a in admin_panels if isinstance(a, dict)]
        hvt_items.append(('Admin Panels', admin_paths, '#ef4444'))
    if hvt_items:
        total_hvt = sum(len(items) for _, items, _ in hvt_items)
        hvt_html = ''
        for label, items, color in hvt_items:
            if label == 'Admin Panels' and admin_panels:
                ap_rows = ''.join(f'<tr><td class="mono">{_esc(a.get("path",""))}</td><td class="muted">{_esc(a.get("category",""))}</td></tr>' for a in admin_panels[:30])
                ap_overflow = f'<span class="muted"> + {len(admin_panels) - 30} more</span>' if len(admin_panels) > 30 else ''
                hvt_html += f'''<div style="background:var(--surface2);border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:3px solid {color};"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;"><span class="type-badge" style="background:{color}20;color:{color};font-size:0.92em;">{_esc(label)}</span><span class="muted" style="font-size:0.85em;">{n_admin} panel(s) found</span></div><details><summary style="cursor:pointer;font-size:0.85em;color:var(--accent);">Show admin panel paths</summary><table style="margin-top:8px;"><tr><th>Path</th><th>Category</th></tr>{ap_rows}</table>{ap_overflow}</details></div>'''
            else:
                chips = ''.join(f'<code style="background:var(--surface);padding:5px 12px;border-radius:5px;font-size:0.9em;border:1px solid var(--border);">{_esc(s)}</code>' for s in items[:8])
                overflow = f'<span class="muted"> + {len(items) - 8} more</span>' if len(items) > 8 else ''
                hvt_html += f'''<div style="background:var(--surface2);border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:3px solid {color};"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;"><span class="type-badge" style="background:{color}20;color:{color};font-size:0.92em;">{_esc(label)}</span><span class="muted" style="font-size:0.85em;">{len(items)} environment(s)</span></div><div style="display:flex;flex-wrap:wrap;gap:6px;">{chips}{overflow}</div></div>'''

        # Per-category recommendations
        _HVT_RECOMMENDATIONS = {
            'Staging / Dev': ('Staging and development environments often have weaker security controls, debug modes enabled, and default credentials. They frequently expose internal APIs, database connections, and configuration details that mirror production.',
                ['Restrict access via IP allowlist or VPN — staging should never be publicly accessible',
                 'Disable debug mode, verbose error pages, and stack traces',
                 'Use separate credentials from production and rotate regularly',
                 'Remove or password-protect directory listings and development tools',
                 'Ensure staging data does not contain real customer PII']),
            'Auth / Identity': ('Authentication and identity endpoints are primary targets for credential stuffing, account takeover, and session hijacking. A single flaw here can compromise the entire user base.',
                ['Enforce rate limiting on login, registration, and password reset endpoints',
                 'Implement multi-factor authentication (MFA) for all user accounts',
                 'Use secure session management — HttpOnly, Secure, SameSite cookie flags',
                 'Deploy CAPTCHA or bot detection on authentication flows',
                 'Monitor for credential stuffing attacks and implement account lockout policies']),
            'API': ('API endpoints often lack the same security controls as web UIs. Missing authentication, excessive data exposure, and injection vulnerabilities are common attack vectors.',
                ['Enforce authentication and authorization on all API endpoints',
                 'Implement rate limiting and request throttling per API key/user',
                 'Validate and sanitize all input parameters — prevent injection attacks',
                 'Use API gateway with WAF rules to filter malicious requests',
                 'Disable unnecessary HTTP methods (PUT, DELETE, PATCH) where not required',
                 'Implement proper CORS policies — avoid wildcard (*) origins']),
            'Payment / E-Commerce': ('Payment and e-commerce endpoints process sensitive financial data. PCI DSS compliance is mandatory. A breach here has direct financial and regulatory consequences.',
                ['Ensure PCI DSS compliance for all payment processing flows',
                 'Use tokenization — never store raw credit card numbers',
                 'Enforce TLS 1.2+ on all payment endpoints',
                 'Implement Content Security Policy (CSP) to prevent Magecart-style skimming attacks',
                 'Monitor for unauthorized script injections on checkout pages',
                 'Use 3D Secure (3DS) for payment verification']),
            'AI / LLM': ('AI and LLM endpoints are vulnerable to prompt injection, data extraction, and model abuse. These are emerging attack surfaces that often lack mature security controls.',
                ['Implement input validation and prompt sanitization',
                 'Set strict output filtering to prevent data leakage',
                 'Rate limit API calls to prevent model abuse and cost escalation',
                 'Log and monitor all interactions for anomalous patterns',
                 'Ensure the model cannot access internal systems or sensitive data']),
            'Admin Panels': ('Administrative interfaces provide privileged access to application configuration, user management, and data. Exposure of admin panels is a critical finding.',
                ['Restrict admin panel access to internal networks or VPN only',
                 'Enforce strong authentication — MFA required for all admin accounts',
                 'Implement IP allowlisting for admin endpoints',
                 'Remove default admin paths (/admin, /wp-admin, /administrator) or rename them',
                 'Enable audit logging for all administrative actions',
                 'Use separate admin domains (e.g., admin.internal.company.com) not publicly resolvable']),
        }
        rec_html = ''
        active_cats = [label for label, _, _ in hvt_items]
        for cat in active_cats:
            if cat in _HVT_RECOMMENDATIONS:
                desc, recs = _HVT_RECOMMENDATIONS[cat]
                cat_color = next((c for l, _, c in hvt_items if l == cat), '#64748b')
                rec_items = ''.join(f'<li>{_esc(r)}</li>' for r in recs)
                rec_html += f'''<div style="margin-bottom:14px;">
  <div style="font-weight:600;font-size:0.9em;color:{cat_color};margin-bottom:4px;">{_esc(cat)}</div>
  <p style="font-size:0.84em;color:var(--muted);margin-bottom:6px;">{_esc(desc)}</p>
  <ul style="padding-left:18px;font-size:0.84em;line-height:1.8;">{rec_items}</ul>
</div>'''

        parts.append(f'''
<div class="sec" id="hvt">
  <h2>High Value Targets <span class="count">({total_hvt})</span></h2>
  <div style="background:var(--surface2);border-radius:10px;padding:14px 18px;margin-bottom:16px;border-left:3px solid var(--accent);">
    <p style="font-size:0.88em;line-height:1.6;margin:0;">High Value Targets are subdomains, endpoints, and services that represent elevated risk due to their function (authentication, payment, admin), exposure level (staging, dev), or data sensitivity. Compromise of these targets can lead to data breaches, unauthorized access, financial loss, or regulatory violations. Each category below requires specific hardening measures.</p>
  </div>
  {hvt_html}
  <details style="margin-top:16px;"><summary style="cursor:pointer;font-weight:600;font-size:0.92em;color:var(--accent);">Security Recommendations by Category</summary>
  <div style="margin-top:12px;background:var(--surface2);border-radius:10px;padding:18px 22px;">
    {rec_html}
  </div>
  </details>
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
