#!/usr/bin/env python3
"""
Fray - Professional Security Testing Report Generator
Generates comprehensive HTML/PDF reports with Dali Security branding
"""

import json
import datetime
from pathlib import Path
from collections import defaultdict

# Import WAF recommendation engine
try:
    from waf_recommendation_engine import WAFRecommendationEngine
    WAF_RECOMMENDATIONS_AVAILABLE = True
except ImportError:
    WAF_RECOMMENDATIONS_AVAILABLE = False

class SecurityReportGenerator:
    """Generate professional security testing reports"""
    
    def __init__(self):
        self.dali_logo_html = '''
        <div class="dali-logo-container" style="display: flex; align-items: center; gap: 15px;">
            <a href="https://dalisec.io/" target="_blank" style="display: flex; align-items: center; gap: 12px; text-decoration: none;">
                <div style="display: flex; flex-direction: column; line-height: 1.2;">
                    <span style="font-size: 28px; font-weight: bold; color: white; letter-spacing: 2px;">DALI</span>
                    <span style="font-size: 14px; color: rgba(255,255,255,0.9); letter-spacing: 3px;">SECURITY</span>
                </div>
            </a>
        </div>
        '''
    
    def generate_html_report(self, test_results, output_file='security_report.html', waf_detection=None):
        """Generate comprehensive HTML security report"""
        
        # Calculate statistics
        stats = self._calculate_statistics(test_results)
        vulnerabilities = self._identify_vulnerabilities(test_results)
        
        # Generate WAF recommendations if detection data is available
        waf_recommendations = None
        if WAF_RECOMMENDATIONS_AVAILABLE and waf_detection:
            engine = WAFRecommendationEngine()
            vuln_list = [f"{v['category'].upper()} ({v['count']} bypasses)" for v in vulnerabilities]
            waf_recommendations = engine.generate_recommendations(
                waf_detected=waf_detection.get('waf_detected', False),
                waf_vendor=waf_detection.get('waf_vendor'),
                confidence=waf_detection.get('confidence', 0),
                target=waf_detection.get('target', ''),
                vulnerabilities_found=vuln_list
            )
        
        recommendations = self._generate_recommendations(vulnerabilities, stats, waf_recommendations)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report - Dali Security</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: linear-gradient(135deg, #f5f7fa 0%, #e8edf2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 50%, #5b21b6 100%);
            color: white;
            padding: 35px 45px;
            border-radius: 16px;
            margin-bottom: 35px;
            box-shadow: 0 20px 60px rgba(30, 58, 138, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .header-left {{
            display: flex;
            align-items: center;
            gap: 25px;
            flex: 1;
        }}
        
        .logo {{
            flex-shrink: 0;
        }}
        
        .header-title {{
            flex: 1;
        }}
        
        .header h1 {{
            font-size: 2.2em;
            margin: 0;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        
        .header .subtitle {{
            font-size: 1em;
            opacity: 0.85;
            margin-top: 5px;
            font-weight: 300;
        }}
        
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .meta-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            border: 1px solid rgba(0,0,0,0.05);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .meta-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.1);
        }}
        
        .meta-card .label {{
            font-size: 0.85em;
            color: #64748b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}
        
        .meta-card .value {{
            font-size: 1.5em;
            font-weight: 700;
            color: #1e293b;
            letter-spacing: -0.5px;
        }}
        
        .section {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            border: 1px solid rgba(0,0,0,0.05);
        }}
        
        .section h2 {{
            font-size: 1.75em;
            margin-bottom: 25px;
            color: #1e293b;
            border-bottom: 3px solid #3730a3;
            padding-bottom: 12px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        
        .severity-critical {{
            color: #e53e3e;
            font-weight: bold;
        }}
        
        .severity-high {{
            color: #dd6b20;
            font-weight: bold;
        }}
        
        .severity-medium {{
            color: #d69e2e;
            font-weight: bold;
        }}
        
        .severity-low {{
            color: #38a169;
            font-weight: bold;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            padding: 30px;
            border-radius: 12px;
            border-left: 5px solid;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-3px);
        }}
        
        .stat-card.blocked {{
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            border-color: #16a34a;
        }}
        
        .stat-card.bypassed {{
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
            border-color: #dc2626;
        }}
        
        .stat-card.total {{
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            border-color: #2563eb;
        }}
        
        .stat-card .number {{
            font-size: 3em;
            font-weight: 800;
            margin-bottom: 8px;
            letter-spacing: -1px;
        }}
        
        .stat-card .label {{
            font-size: 1em;
            color: #475569;
            font-weight: 500;
        }}
        
        .vulnerability-list {{
            margin: 20px 0;
        }}
        
        .vulnerability-item {{
            background: #f7fafc;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        
        .vulnerability-item.critical {{
            border-color: #e53e3e;
        }}
        
        .vulnerability-item.high {{
            border-color: #dd6b20;
        }}
        
        .vulnerability-item.medium {{
            border-color: #d69e2e;
        }}
        
        .vulnerability-item.low {{
            border-color: #38a169;
        }}
        
        .vulnerability-item h3 {{
            font-size: 1.3em;
            margin-bottom: 10px;
        }}
        
        .vulnerability-item .details {{
            margin: 10px 0;
            color: #4a5568;
        }}
        
        .vulnerability-item .payload {{
            background: #2d3748;
            color: #68d391;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .recommendation-list {{
            margin: 20px 0;
        }}
        
        .recommendation-item {{
            background: #edf2f7;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #4299e1;
        }}
        
        .recommendation-item h3 {{
            font-size: 1.2em;
            margin-bottom: 10px;
            color: #2d3748;
        }}
        
        .recommendation-item .priority {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .priority.high {{
            background: #fed7d7;
            color: #c53030;
        }}
        
        .priority.medium {{
            background: #feebc8;
            color: #c05621;
        }}
        
        .priority.low {{
            background: #c6f6d5;
            color: #276749;
        }}
        
        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background: #f7fafc;
            border-radius: 8px;
        }}
        
        .progress-bar {{
            height: 40px;
            background: #e2e8f0;
            border-radius: 20px;
            overflow: hidden;
            margin: 15px 0;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #1e3a8a 0%, #3730a3 50%, #5b21b6 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            transition: width 0.3s ease;
            font-size: 1.1em;
            letter-spacing: 0.5px;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #718096;
            border-top: 2px solid #e2e8f0;
            margin-top: 50px;
        }}
        
        .footer .powered-by {{
            margin-top: 10px;
            font-size: 0.9em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        th {{
            background: #f7fafc;
            font-weight: bold;
            color: #2d3748;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge.success {{
            background: #c6f6d5;
            color: #276749;
        }}
        
        .badge.danger {{
            background: #fed7d7;
            color: #c53030;
        }}
        
        .badge.warning {{
            background: #feebc8;
            color: #c05621;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .section {{
                box-shadow: none;
                border: 1px solid #e2e8f0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-left">
                <div class="logo">
                    {self.dali_logo_html}
                </div>
                <div class="header-title">
                    <h1>Security Testing Report</h1>
                    <div class="subtitle">Comprehensive Web Application Security Assessment</div>
                </div>
            </div>
        </div>
        
        <!-- Meta Information -->
        <div class="meta-info">
            <div class="meta-card">
                <div class="label">Report Date</div>
                <div class="value">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
            </div>
            <div class="meta-card">
                <div class="label">Target URL</div>
                <div class="value">{self._escape_html(waf_detection.get('target', 'N/A')) if waf_detection else 'N/A'}</div>
            </div>
            <div class="meta-card">
                <div class="label">Test Duration</div>
                <div class="value">N/A</div>
            </div>
            <div class="meta-card">
                <div class="label">Security Score</div>
                <div class="value">{stats['security_score']}/100</div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="number">{stats['total_payloads']}</div>
                    <div class="label">Total Payloads Tested</div>
                </div>
                <div class="stat-card blocked">
                    <div class="number">{stats['blocked_payloads']}</div>
                    <div class="label">Payloads Blocked ✓</div>
                </div>
                <div class="stat-card bypassed">
                    <div class="number">{stats['bypassed_payloads']}</div>
                    <div class="label">Payloads Bypassed ⚠️</div>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>Security Effectiveness</h3>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {stats['block_rate']}%">
                        {stats['block_rate']}% Blocked
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Found -->
        <div class="section">
            <h2>🔍 Vulnerabilities Discovered</h2>
            {self._render_vulnerabilities(vulnerabilities)}
        </div>
        
        <!-- Payload Analysis -->
        <div class="section">
            <h2>📈 Payload Analysis by Category</h2>
            {self._render_payload_analysis(stats)}
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <h2>💡 Security Recommendations</h2>
            {self._render_recommendations(recommendations)}
        </div>
        
        <!-- Leak Search Results -->
        {self._render_leak_section(test_results)}
        
        <!-- Detailed Test Results -->
        <div class="section">
            <h2>📋 Detailed Test Results</h2>
            {self._render_detailed_results(test_results)}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>Generated by Fray</strong></p>
            <p class="powered-by">Powered by Dali Security | Professional Security Testing Platform</p>
            <p style="margin-top: 10px; font-size: 0.85em;">
                This report is confidential and intended for authorized personnel only.
            </p>
        </div>
    </div>
</body>
</html>'''
        
        # Write report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file
    
    def _calculate_statistics(self, test_results):
        """Calculate testing statistics"""
        # Handle both dict and list formats
        if isinstance(test_results, dict):
            results = test_results.get('results', [])
        else:
            results = test_results if isinstance(test_results, list) else []
        
        total = len(results)
        blocked = sum(1 for r in results if r.get('blocked', False))
        bypassed = total - blocked
        block_rate = round((blocked / total * 100) if total > 0 else 0, 1)
        
        # Calculate security score (higher is better)
        security_score = min(100, round(block_rate))
        
        # Category breakdown
        categories = defaultdict(lambda: {'total': 0, 'blocked': 0, 'bypassed': 0})
        for result in results:
            cat = result.get('category', 'unknown')
            categories[cat]['total'] += 1
            if result.get('blocked', False):
                categories[cat]['blocked'] += 1
            else:
                categories[cat]['bypassed'] += 1
        
        return {
            'total_payloads': total,
            'blocked_payloads': blocked,
            'bypassed_payloads': bypassed,
            'block_rate': block_rate,
            'security_score': security_score,
            'categories': dict(categories)
        }
    
    def _identify_vulnerabilities(self, test_results):
        """Identify vulnerabilities from test results"""
        # Handle both dict and list formats
        if isinstance(test_results, dict):
            results = test_results.get('results', [])
        else:
            results = test_results if isinstance(test_results, list) else []
        
        vulnerabilities = []
        results = results
        
        # Group bypassed payloads by category
        bypassed_by_category = defaultdict(list)
        for result in results:
            if not result.get('blocked', False):
                cat = result.get('category', 'unknown')
                bypassed_by_category[cat].append(result)
        
        # Create vulnerability entries
        severity_map = {
            'xss': 'high',
            'sqli': 'critical',
            'command_injection': 'critical',
            'xxe': 'high',
            'ssrf': 'high',
            'ssti': 'high',
            'path_traversal': 'medium',
            'open-redirect': 'medium',
            'crlf_injection': 'medium',
        }
        
        for category, payloads in bypassed_by_category.items():
            if payloads:
                vulnerabilities.append({
                    'category': category,
                    'severity': severity_map.get(category, 'medium'),
                    'count': len(payloads),
                    'payloads': payloads[:5],  # Show first 5 examples
                    'description': self._get_vulnerability_description(category)
                })
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return vulnerabilities
    
    def _get_vulnerability_description(self, category):
        """Get description for vulnerability category"""
        descriptions = {
            'xss': 'Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages.',
            'sqli': 'SQL Injection vulnerabilities allow attackers to manipulate database queries and access sensitive data.',
            'command_injection': 'Command Injection allows attackers to execute arbitrary system commands on the server.',
            'xxe': 'XML External Entity (XXE) vulnerabilities can lead to data disclosure and server-side request forgery.',
            'ssrf': 'Server-Side Request Forgery (SSRF) allows attackers to make requests from the server to internal resources.',
            'ssti': 'Server-Side Template Injection can lead to remote code execution.',
            'path_traversal': 'Path Traversal vulnerabilities allow access to files outside the intended directory.',
            'open-redirect': 'Open Redirect vulnerabilities can be used in phishing attacks.',
            'crlf_injection': 'CRLF Injection can lead to HTTP response splitting and cache poisoning.',
        }
        return descriptions.get(category, 'Security vulnerability detected in this category.')
    
    def _generate_recommendations(self, vulnerabilities, stats, waf_recommendations=None):
        """Generate security recommendations"""
        recommendations = []
        
        # Add WAF-specific recommendations first (highest priority)
        if waf_recommendations:
            if not waf_recommendations.get('waf_detected'):
                # No WAF detected - CRITICAL priority
                recommendations.append({
                    'priority': 'critical',
                    'title': '🚨 CRITICAL: No WAF Protection Detected',
                    'description': 'Your application has no Web Application Firewall protection, leaving it vulnerable to automated attacks and OWASP Top 10 vulnerabilities.',
                    'action': 'Deploy a WAF immediately. Recommended: Cloudflare (5 min setup, $20/month) or AWS WAF (30 min setup, pay-as-you-go).',
                    'waf_info': waf_recommendations
                })
            else:
                # WAF detected - add vendor info
                vendor = waf_recommendations.get('waf_vendor', 'Unknown')
                confidence = waf_recommendations.get('confidence', 0)
                recommendations.append({
                    'priority': 'info',
                    'title': f'✅ {vendor} WAF Detected',
                    'description': f'WAF protection is active with {confidence}% confidence. Continue monitoring and tuning for optimal protection.',
                    'action': f'Review {vendor} configuration and ensure all OWASP Top 10 protections are enabled.',
                    'waf_info': waf_recommendations
                })
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v['severity'] == 'critical']
        if critical_vulns:
            for vuln in critical_vulns:
                recommendations.append({
                    'priority': 'high',
                    'title': f'Fix {vuln["category"].upper()} Vulnerability',
                    'description': f'Immediately address {vuln["count"]} bypassed {vuln["category"]} payloads.',
                    'action': self._get_fix_recommendation(vuln['category'])
                })
        
        # High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v['severity'] == 'high']
        if high_vulns:
            for vuln in high_vulns:
                recommendations.append({
                    'priority': 'high',
                    'title': f'Strengthen {vuln["category"].upper()} Protection',
                    'description': f'{vuln["count"]} {vuln["category"]} payloads bypassed security controls.',
                    'action': self._get_fix_recommendation(vuln['category'])
                })
        
        # General recommendations based on block rate
        if stats['block_rate'] < 80:
            recommendations.append({
                'priority': 'high',
                'title': 'Improve Overall WAF Configuration',
                'description': f'Current block rate is {stats["block_rate"]}%. Target should be >95%.',
                'action': 'Review and update WAF rules, enable stricter security policies, and implement defense-in-depth strategies.'
            })
        
        # Category-specific recommendations
        for category, data in stats['categories'].items():
            if data['bypassed'] > 0:
                bypass_rate = round((data['bypassed'] / data['total'] * 100), 1)
                if bypass_rate > 20:
                    recommendations.append({
                        'priority': 'medium',
                        'title': f'Enhance {category.upper()} Detection',
                        'description': f'{bypass_rate}% of {category} payloads bypassed detection.',
                        'action': self._get_fix_recommendation(category)
                    })
        
        return recommendations
    
    def _get_fix_recommendation(self, category):
        """Get specific fix recommendations for each category"""
        fixes = {
            'xss': 'Implement Content Security Policy (CSP), use output encoding, sanitize user input, and enable XSS protection headers.',
            'sqli': 'Use parameterized queries/prepared statements, implement input validation, apply principle of least privilege to database accounts.',
            'command_injection': 'Avoid system calls with user input, use safe APIs, implement strict input validation and whitelisting.',
            'xxe': 'Disable external entity processing in XML parsers, use less complex data formats like JSON when possible.',
            'ssrf': 'Implement URL whitelisting, validate and sanitize URLs, use network segmentation to restrict outbound requests.',
            'ssti': 'Use logic-less template engines, implement sandboxing, validate and sanitize template inputs.',
            'path_traversal': 'Implement strict path validation, use chroot jails, avoid user input in file operations.',
            'open-redirect': 'Validate redirect URLs against whitelist, avoid using user input directly in redirects.',
            'crlf_injection': 'Sanitize user input in HTTP headers, use framework-provided header setting methods.',
        }
        return fixes.get(category, 'Review security best practices for this vulnerability type and implement appropriate controls.')
    
    def _render_vulnerabilities(self, vulnerabilities):
        """Render vulnerabilities section"""
        if not vulnerabilities:
            return '<p style="color: #38a169; font-size: 1.2em;">✅ No vulnerabilities detected! All payloads were successfully blocked.</p>'
        
        html = f'<p style="margin-bottom: 20px;">Found <strong>{len(vulnerabilities)}</strong> vulnerability categories:</p>'
        html += '<div class="vulnerability-list">'
        
        for vuln in vulnerabilities:
            severity_class = vuln['severity']
            html += f'''
            <div class="vulnerability-item {severity_class}">
                <h3>
                    <span class="severity-{severity_class}">[{vuln["severity"].upper()}]</span>
                    {vuln["category"].upper()} Vulnerability
                </h3>
                <div class="details">
                    <p><strong>Bypassed Payloads:</strong> {vuln["count"]}</p>
                    <p><strong>Description:</strong> {vuln["description"]}</p>
                </div>
                <p><strong>Example Bypassed Payloads:</strong></p>
            '''
            
            for payload in vuln['payloads'][:3]:
                html += f'<div class="payload">{self._escape_html(payload.get("payload", "N/A"))}</div>'
            
            html += '</div>'
        
        html += '</div>'
        return html
    
    def _render_payload_analysis(self, stats):
        """Render payload analysis table"""
        html = '<table>'
        html += '<thead><tr><th>Category</th><th>Total Tested</th><th>Blocked</th><th>Bypassed</th><th>Block Rate</th><th>Status</th></tr></thead>'
        html += '<tbody>'
        
        for category, data in sorted(stats['categories'].items()):
            block_rate = round((data['blocked'] / data['total'] * 100) if data['total'] > 0 else 0, 1)
            
            if block_rate >= 95:
                status = '<span class="badge success">Excellent</span>'
            elif block_rate >= 80:
                status = '<span class="badge warning">Good</span>'
            else:
                status = '<span class="badge danger">Needs Attention</span>'
            
            html += f'''
            <tr>
                <td><strong>{category.upper()}</strong></td>
                <td>{data["total"]}</td>
                <td style="color: #38a169;">{data["blocked"]}</td>
                <td style="color: #e53e3e;">{data["bypassed"]}</td>
                <td><strong>{block_rate}%</strong></td>
                <td>{status}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html
    
    def _render_recommendations(self, recommendations):
        """Render recommendations section"""
        if not recommendations:
            return '<p style="color: #38a169;">✅ No immediate recommendations. Security posture is strong!</p>'
        
        html = '<div class="recommendation-list">'
        
        for rec in recommendations:
            html += f'''
            <div class="recommendation-item">
                <span class="priority {rec["priority"]}">{rec["priority"].upper()} PRIORITY</span>
                <h3>{rec["title"]}</h3>
                <p><strong>Issue:</strong> {rec["description"]}</p>
                <p><strong>Recommended Action:</strong> {rec["action"]}</p>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _render_detailed_results(self, test_results):
        """Render detailed test results table with confidence and timing"""
        # Handle both dict and list formats
        if isinstance(test_results, dict):
            results = test_results.get('results', [])[:50]
        else:
            results = (test_results if isinstance(test_results, list) else [])[:50]

        # Detect if confidence data is available
        has_confidence = any(r.get('bypass_confidence') is not None for r in results)

        html = '<table>'
        header = '<thead><tr><th>#</th><th>Category</th><th>Payload</th><th>Status</th><th>Code</th>'
        if has_confidence:
            header += '<th>Confidence</th><th>Time</th>'
        header += '</tr></thead>'
        html += header
        html += '<tbody>'

        for i, result in enumerate(results, 1):
            status = 'Blocked' if result.get('blocked', False) else 'Bypassed'
            status_class = 'success' if result.get('blocked', False) else 'danger'
            conf = result.get('bypass_confidence')
            elapsed = result.get('elapsed_ms')

            conf_cell = ''
            if has_confidence:
                if conf is not None:
                    if conf >= 80:
                        c_color = '#dc2626'
                    elif conf >= 50:
                        c_color = '#ea580c'
                    elif conf >= 25:
                        c_color = '#d97706'
                    else:
                        c_color = '#64748b'
                    conf_cell = f'<td style="font-weight:700;color:{c_color};">{conf}%</td>'
                else:
                    conf_cell = '<td style="color:#94a3b8;">—</td>'
                time_cell = f'<td>{elapsed:.0f}ms</td>' if elapsed is not None else '<td>—</td>'

            html += f'''
            <tr>
                <td>{i}</td>
                <td>{result.get("category", "N/A")}</td>
                <td style="font-family:monospace;font-size:0.85em;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{self._escape_html(result.get("payload", "N/A")[:120])}</td>
                <td><span class="badge {status_class}">{status}</span></td>
                <td>{result.get("status_code", "N/A")}</td>
                {conf_cell}{time_cell if has_confidence else ""}
            </tr>
            '''

        html += '</tbody></table>'

        # Handle both dict and list formats for total count
        if isinstance(test_results, dict):
            total_results = len(test_results.get('results', []))
        else:
            total_results = len(test_results if isinstance(test_results, list) else [])

        if total_results > 50:
            html += f'<p style="margin-top: 10px; color: #718096;">Showing first 50 of {total_results} results.</p>'

        return html
    
    def _render_leak_section(self, test_results):
        """Render leak search results section if leak data is present."""
        # Extract leak data from test_results dict
        leak_data = None
        if isinstance(test_results, dict):
            leak_data = test_results.get('leak_check') or test_results.get('leak')
        
        if not leak_data:
            return ''
        
        risk_level = leak_data.get('risk_level', 'low')
        risk_colors = {'critical': '#dc2626', 'high': '#ea580c', 'medium': '#ca8a04', 'low': '#16a34a'}
        risk_color = risk_colors.get(risk_level, '#6b7280')
        
        html = f'''
        <div class="section">
            <h2>🔓 Leak Search Results</h2>
            <div style="background: {risk_color}15; border-left: 4px solid {risk_color}; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <strong style="color: {risk_color};">Risk Level: {risk_level.upper()}</strong>
            </div>
        '''
        
        # Risk factors
        factors = leak_data.get('risk_factors', [])
        if factors:
            html += '<ul style="margin: 10px 0;">'
            for f in factors:
                html += f'<li>{f}</li>'
            html += '</ul>'
        
        # GitHub results
        gh_repos = leak_data.get('github_repos', 0)
        confirmed = leak_data.get('confirmed_secrets', 0)
        if gh_repos > 0 or confirmed > 0:
            html += f'''
            <h3 style="margin-top: 15px;">📁 GitHub Code Search</h3>
            <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
                <tr><td style="padding: 5px; border-bottom: 1px solid #e2e8f0;"><strong>Repos with credential keywords</strong></td>
                    <td style="padding: 5px; border-bottom: 1px solid #e2e8f0;">{gh_repos}</td></tr>
                <tr><td style="padding: 5px; border-bottom: 1px solid #e2e8f0;"><strong>Confirmed secrets (regex-verified)</strong></td>
                    <td style="padding: 5px; border-bottom: 1px solid #e2e8f0; color: {"#dc2626" if confirmed > 0 else "#16a34a"};">{confirmed}</td></tr>
            </table>
            '''
            
            # Top repos
            details = leak_data.get('details', {})
            gh_detail = details.get('github', {})
            top_repos = gh_detail.get('top_repos', [])
            if top_repos:
                html += '<p><strong>Top repos:</strong></p><ul>'
                for repo in top_repos[:5]:
                    html += f'<li><code>{repo}</code></li>'
                html += '</ul>'
        
        # HIBP results
        hibp_breaches = leak_data.get('hibp_breaches', 0)
        hibp_pwn = leak_data.get('hibp_pwn_count', 0)
        if hibp_breaches > 0:
            html += f'''
            <h3 style="margin-top: 15px;">🔓 Have I Been Pwned</h3>
            <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
                <tr><td style="padding: 5px; border-bottom: 1px solid #e2e8f0;"><strong>Breaches</strong></td>
                    <td style="padding: 5px; border-bottom: 1px solid #e2e8f0; color: #dc2626;">{hibp_breaches}</td></tr>
                <tr><td style="padding: 5px; border-bottom: 1px solid #e2e8f0;"><strong>Total accounts affected</strong></td>
                    <td style="padding: 5px; border-bottom: 1px solid #e2e8f0;">{hibp_pwn:,}</td></tr>
            </table>
            '''
            
            details = leak_data.get('details', {})
            hibp_detail = details.get('hibp', {})
            breaches = hibp_detail.get('breaches', [])
            if breaches:
                html += '<p><strong>Breach details:</strong></p><ul>'
                for b in breaches[:5]:
                    html += f'<li><strong>{b.get("name", "?")}</strong> ({b.get("date", "?")}) — {b.get("pwn_count", 0):,} accounts</li>'
                html += '</ul>'
        
        if gh_repos == 0 and confirmed == 0 and hibp_breaches == 0:
            html += '<p style="color: #16a34a;">✅ No leaked credentials or breaches found.</p>'
        
        html += '</div>'
        return html

    def generate_markdown_report(self, test_results, output_file='security_report.md', waf_detection=None):
        """Generate a Markdown security report (great for GitHub issues / bug bounty submissions)."""
        stats = self._calculate_statistics(test_results)
        vulnerabilities = self._identify_vulnerabilities(test_results)
        recommendations = self._generate_recommendations(vulnerabilities, stats, None)

        # Handle both dict and list formats
        if isinstance(test_results, dict):
            results = test_results.get('results', [])
            target = test_results.get('target', 'N/A')
            duration = test_results.get('duration', 'N/A')
            timestamp = test_results.get('timestamp', datetime.datetime.now().isoformat())
        else:
            results = test_results if isinstance(test_results, list) else []
            target = 'N/A'
            duration = 'N/A'
            timestamp = datetime.datetime.now().isoformat()

        # Determine WAF info
        waf_name = 'N/A'
        if waf_detection:
            waf_name = waf_detection.get('waf', waf_detection.get('waf_vendor', 'N/A'))

        # Security score badge
        score = stats['security_score']
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 60:
            grade = 'C'
        elif score >= 40:
            grade = 'D'
        else:
            grade = 'F'

        lines = []
        lines.append(f'# Fray Security Report')
        lines.append('')
        lines.append(f'> Generated by [Fray](https://github.com/dalisecurity/Fray) — DALI Security')
        lines.append('')
        lines.append('## Summary')
        lines.append('')
        lines.append(f'| Field | Value |')
        lines.append(f'|-------|-------|')
        lines.append(f'| **Target** | `{target}` |')
        lines.append(f'| **WAF** | {waf_name} |')
        lines.append(f'| **Security Grade** | **{grade}** ({score}/100) |')
        lines.append(f'| **Block Rate** | {stats["block_rate"]}% |')
        lines.append(f'| **Total Payloads** | {stats["total_payloads"]} |')
        lines.append(f'| **Blocked** | {stats["blocked_payloads"]} |')
        lines.append(f'| **Bypassed** | {stats["bypassed_payloads"]} |')
        lines.append(f'| **Duration** | {duration} |')
        lines.append(f'| **Timestamp** | {timestamp} |')
        lines.append('')

        # Category breakdown
        if stats['categories']:
            lines.append('## Category Breakdown')
            lines.append('')
            lines.append('| Category | Total | Blocked | Bypassed | Block Rate |')
            lines.append('|----------|------:|--------:|---------:|-----------:|')
            for cat, data in sorted(stats['categories'].items()):
                cat_rate = round((data['blocked'] / data['total'] * 100), 1) if data['total'] > 0 else 0
                lines.append(f'| {cat} | {data["total"]} | {data["blocked"]} | {data["bypassed"]} | {cat_rate}% |')
            lines.append('')

        # Vulnerabilities
        if vulnerabilities:
            lines.append('## Vulnerabilities Found')
            lines.append('')
            for vuln in vulnerabilities:
                sev = vuln['severity'].upper()
                lines.append(f'### {sev}: {vuln["category"].upper()} ({vuln["count"]} bypasses)')
                lines.append('')
                lines.append(f'{vuln["description"]}')
                lines.append('')
                if vuln.get('payloads'):
                    lines.append('**Sample bypassed payloads:**')
                    lines.append('')
                    lines.append('```')
                    for p in vuln['payloads'][:5]:
                        payload_text = p.get('payload', str(p))
                        lines.append(payload_text)
                    lines.append('```')
                    lines.append('')

        # Recommendations
        if recommendations:
            lines.append('## Recommendations')
            lines.append('')
            for i, rec in enumerate(recommendations, 1):
                priority = rec.get('priority', 'medium').upper()
                lines.append(f'{i}. **[{priority}] {rec["title"]}**')
                lines.append(f'   {rec["description"]}')
                lines.append(f'   - *Action:* {rec["action"]}')
                lines.append('')

        # Detailed results table (first 50)
        if results:
            lines.append('## Detailed Results')
            lines.append('')
            show = results[:50]
            lines.append('| # | Status | Blocked | Category | Payload |')
            lines.append('|--:|-------:|:-------:|----------|---------|')
            for idx, r in enumerate(show, 1):
                status = r.get('status', r.get('status_code', 0))
                blocked = '🛡️' if r.get('blocked', False) else '⚠️'
                cat = r.get('category', 'unknown')
                payload = r.get('payload', '')
                # Escape pipe characters in payload for Markdown table
                payload_escaped = str(payload).replace('|', '\\|')[:60]
                lines.append(f'| {idx} | {status} | {blocked} | {cat} | `{payload_escaped}` |')
            if len(results) > 50:
                lines.append(f'')
                lines.append(f'*Showing first 50 of {len(results)} results.*')
            lines.append('')

        lines.append('---')
        lines.append('*Report generated by [Fray](https://github.com/dalisecurity/Fray) — AI-Powered WAF Security Testing*')

        md_content = '\n'.join(lines)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        return output_file

    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ''
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))


    def _build_per_subdomain_html(self, recon_data: dict) -> str:
        """Build HTML table for per-subdomain WAF/CDN/cache analysis."""
        import html as html_mod
        cloud_dist = recon_data.get("cloud_distribution", {})
        per_sub = cloud_dist.get("per_subdomain", [])
        if not per_sub:
            return ""

        waf_dist = cloud_dist.get("waf_distribution", {})
        cdn_dist = cloud_dist.get("cdn_distribution", {})

        # Distribution summary badges
        badges = ""
        for name, info in waf_dist.items():
            badges += f'<span style="background:#dcfce7;color:#166534;padding:3px 10px;border-radius:6px;margin:2px;font-size:0.85em;font-weight:600;">WAF: {html_mod.escape(name)} ({info["pct"]}%)</span> '
        for name, info in cdn_dist.items():
            badges += f'<span style="background:#dbeafe;color:#1e40af;padding:3px 10px;border-radius:6px;margin:2px;font-size:0.85em;font-weight:600;">CDN: {html_mod.escape(name)} ({info["pct"]}%)</span> '
        if cloud_dist.get("multi_waf"):
            badges += '<span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:6px;margin:2px;font-size:0.85em;font-weight:600;">Multi-WAF</span> '

        # Table rows
        rows = ""
        for s in per_sub:
            waf = s.get("waf") or "(no WAF)"
            cdn_v = s.get("cdn") or "(direct)"
            cache = s.get("cache_status") or "-"
            http_st = str(s.get("status") or "-")
            srv = html_mod.escape((s.get("server") or "-")[:20])

            waf_style = 'color:#166534;font-weight:600;' if s.get("waf") else 'color:#dc2626;'
            cdn_style = 'color:#1e40af;font-weight:600;' if s.get("cdn") else 'color:#94a3b8;'

            rows += f'''<tr>
                <td style="font-family:monospace;font-size:0.9em;">{html_mod.escape(s["subdomain"])}</td>
                <td style="{waf_style}">{html_mod.escape(waf)}</td>
                <td style="{cdn_style}">{html_mod.escape(cdn_v)}</td>
                <td>{html_mod.escape(cache)}</td>
                <td>{html_mod.escape(http_st)}</td>
                <td style="color:#64748b;">{srv}</td>
            </tr>'''

        return f'''
    <div class="section">
        <h2>Per-Subdomain WAF / CDN Analysis ({len(per_sub)} subdomains)</h2>
        <div style="margin-bottom:14px;">{badges}</div>
        <table>
            <tr><th>Subdomain</th><th>WAF</th><th>CDN</th><th>Cache</th><th>HTTP</th><th>Server</th></tr>
            {rows}
        </table>
    </div>'''

    def generate_recon_html_report(self, recon_data, output_file='recon_report.html'):
        """Generate a branded HTML report from fray recon JSON results."""
        import html as html_mod

        host = recon_data.get('host', 'Unknown')
        ts = recon_data.get('timestamp', '')
        atk = recon_data.get('attack_surface', {})
        risk_score = atk.get('risk_score', 0)
        risk_level = atk.get('risk_level', '?')
        findings = atk.get('findings', [])

        # Risk color
        if risk_score >= 60:
            risk_color = '#dc2626'
        elif risk_score >= 40:
            risk_color = '#ea580c'
        elif risk_score >= 20:
            risk_color = '#d97706'
        else:
            risk_color = '#16a34a'

        # Build findings HTML
        findings_html = ''
        for f in findings:
            sev = f.get('severity', 'info')
            sev_cls = sev if sev in ('critical', 'high', 'medium', 'low') else 'low'
            findings_html += f'''
            <div class="vulnerability-item {sev_cls}">
                <span class="severity-{sev_cls}" style="text-transform:uppercase;font-size:0.85em;">{html_mod.escape(sev)}</span>
                <span style="margin-left:12px;">{html_mod.escape(f.get("finding", ""))}</span>
            </div>'''

        # Technologies
        fp = recon_data.get('fingerprint', {})
        techs = fp.get('technologies', {})
        tech_rows = ''
        for name, ver in sorted(techs.items()):
            v = ver if isinstance(ver, str) else str(ver) if ver else '—'
            tech_rows += f'<tr><td>{html_mod.escape(name)}</td><td>{html_mod.escape(v)}</td></tr>'

        # Security headers
        hdrs = recon_data.get('headers', {})
        hdr_score = hdrs.get('score', 0)
        present = hdrs.get('present', [])
        missing = hdrs.get('missing', [])
        present_html = ''.join(f'<span style="background:#dcfce7;color:#166534;padding:3px 8px;border-radius:4px;margin:2px;display:inline-block;font-size:0.85em;">{html_mod.escape(h)}</span>' for h in present)
        missing_html = ''.join(f'<span style="background:#fee2e2;color:#991b1b;padding:3px 8px;border-radius:4px;margin:2px;display:inline-block;font-size:0.85em;">{html_mod.escape(h)}</span>' for h in missing)

        # TLS
        tls = recon_data.get('tls', {})
        tls_ver = tls.get('tls_version', '—')
        cert_days = tls.get('cert_days_remaining', '—')
        cert_issuer = tls.get('issuer', '—')

        # DNS
        dns = recon_data.get('dns', {})
        a_records = ', '.join(dns.get('a', [])) or '—'
        cdn = dns.get('cdn_detected', '—') or '—'

        # Subdomains
        subs = recon_data.get('subdomains', {})
        sub_list = subs.get('subdomains', [])
        n_subs = len(sub_list) if isinstance(sub_list, list) else 0

        # Frontend libs
        fl = recon_data.get('frontend_libs', {})
        n_vuln_libs = fl.get('vulnerable_libs', 0)
        fl_vulns = fl.get('vulnerabilities', [])

        cve_rows = ''
        for v in fl_vulns[:20]:
            cve_rows += f'''<tr>
                <td><span class="severity-{v.get("severity","info")}">{html_mod.escape(v.get("id",""))}</span></td>
                <td>{html_mod.escape(v.get("library",""))}</td>
                <td>{html_mod.escape(v.get("severity",""))}</td>
                <td>{html_mod.escape(v.get("description","")[:100])}</td>
            </tr>'''

        # WAF
        gap = recon_data.get('gap_analysis', {})
        waf_vendor = gap.get('waf_vendor') or atk.get('waf_vendor') or '—'

        # Executive summary — dynamic narrative
        n_crit = sum(1 for f in findings if f.get('severity') == 'critical')
        n_high = sum(1 for f in findings if f.get('severity') == 'high')
        n_med  = sum(1 for f in findings if f.get('severity') == 'medium')
        n_low  = sum(1 for f in findings if f.get('severity') == 'low')

        summary_lines = []
        summary_lines.append(
            f'Fray performed an automated reconnaissance scan of '
            f'<strong>{html_mod.escape(host)}</strong> and identified '
            f'<strong>{len(findings)}</strong> finding(s) across the target\'s '
            f'external attack surface.'
        )
        if waf_vendor and waf_vendor != '—':
            summary_lines.append(f'The target is protected by <strong>{html_mod.escape(str(waf_vendor))}</strong> WAF.')
        else:
            summary_lines.append('<span style="color:#dc2626;font-weight:600;">No WAF was detected — the application is directly exposed to attack.</span>')
        if n_crit:
            summary_lines.append(f'<span style="color:#dc2626;font-weight:600;">{n_crit} critical-severity finding(s) require immediate attention.</span>')
        if n_high:
            summary_lines.append(f'{n_high} high-severity finding(s) should be addressed promptly.')
        if n_vuln_libs:
            summary_lines.append(f'{n_vuln_libs} frontend library(ies) contain known CVEs.')
        summary_paragraph = ' '.join(summary_lines)

        dali_logo_dark = '''
        <a href="https://dalisec.io/" target="_blank" style="display:inline-flex;align-items:center;gap:10px;text-decoration:none;">
            <div style="display:flex;flex-direction:column;line-height:1.15;">
                <span style="font-size:22px;font-weight:800;color:#1e293b;letter-spacing:2px;">DALI</span>
                <span style="font-size:11px;color:#64748b;letter-spacing:3px;font-weight:600;">SECURITY</span>
            </div>
        </a>
        '''

        report_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report — {html_mod.escape(host)} — Fray by DALI Security</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; line-height:1.6; color:#1a202c; background:linear-gradient(135deg,#f5f7fa 0%,#e8edf2 100%); min-height:100vh; }}
        .container {{ max-width:1100px; margin:0 auto; padding:40px 20px; }}
        .header {{ background:linear-gradient(135deg,#1e3a8a 0%,#3730a3 50%,#5b21b6 100%); color:#fff; padding:35px 45px; border-radius:16px; margin-bottom:35px; box-shadow:0 20px 60px rgba(30,58,138,0.25); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:20px; }}
        .header h1 {{ font-size:2em; font-weight:700; letter-spacing:-0.5px; }}
        .header .subtitle {{ font-size:0.95em; opacity:0.85; margin-top:4px; }}
        .risk-badge {{ background:rgba(255,255,255,0.15); padding:18px 30px; border-radius:12px; text-align:center; }}
        .risk-score {{ font-size:2.8em; font-weight:800; color:{risk_color}; text-shadow:0 0 20px rgba(0,0,0,0.1); }}
        .risk-label {{ font-size:0.85em; opacity:0.9; margin-top:4px; text-transform:uppercase; letter-spacing:1px; }}
        .meta-info {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; margin-bottom:30px; }}
        .meta-card {{ background:#fff; padding:22px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.06); border:1px solid rgba(0,0,0,0.05); }}
        .meta-card .label {{ font-size:0.8em; color:#64748b; text-transform:uppercase; letter-spacing:0.5px; font-weight:600; margin-bottom:6px; }}
        .meta-card .value {{ font-size:1.4em; font-weight:700; color:#1e293b; }}
        .section {{ background:#fff; padding:35px; border-radius:16px; margin-bottom:25px; box-shadow:0 4px 20px rgba(0,0,0,0.06); border:1px solid rgba(0,0,0,0.05); }}
        .section h2 {{ font-size:1.5em; margin-bottom:20px; color:#1e293b; border-bottom:3px solid #3730a3; padding-bottom:10px; font-weight:700; }}
        table {{ width:100%; border-collapse:collapse; margin:10px 0; }}
        th {{ background:#f1f5f9; padding:10px 14px; text-align:left; font-size:0.85em; color:#475569; text-transform:uppercase; letter-spacing:0.5px; }}
        td {{ padding:10px 14px; border-bottom:1px solid #e2e8f0; font-size:0.95em; }}
        tr:hover td {{ background:#f8fafc; }}
        .severity-critical {{ color:#dc2626; font-weight:700; }}
        .severity-high {{ color:#ea580c; font-weight:700; }}
        .severity-medium {{ color:#d97706; font-weight:700; }}
        .severity-low {{ color:#16a34a; font-weight:700; }}
        .severity-info {{ color:#64748b; }}
        .vulnerability-item {{ background:#f7fafc; padding:14px 18px; border-radius:8px; margin-bottom:10px; border-left:4px solid; display:flex; align-items:center; }}
        .vulnerability-item.critical {{ border-color:#dc2626; }}
        .vulnerability-item.high {{ border-color:#ea580c; }}
        .vulnerability-item.medium {{ border-color:#d97706; }}
        .vulnerability-item.low {{ border-color:#16a34a; }}
        .footer {{ text-align:center; padding:30px; color:#94a3b8; font-size:0.85em; }}
        .footer a {{ color:#6366f1; text-decoration:none; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            {self.dali_logo_html}
            <h1>Reconnaissance Report</h1>
            <div class="subtitle">{html_mod.escape(host)} — {html_mod.escape(ts[:19] if ts else '—')}</div>
        </div>
        <div class="risk-badge">
            <div class="risk-score">{risk_score}</div>
            <div class="risk-label">{html_mod.escape(risk_level)} Risk</div>
        </div>
    </div>

    <div class="meta-info">
        <div class="meta-card"><div class="label">WAF Vendor</div><div class="value">{html_mod.escape(str(waf_vendor))}</div></div>
        <div class="meta-card"><div class="label">CDN</div><div class="value">{html_mod.escape(str(cdn))}</div></div>
        <div class="meta-card"><div class="label">TLS</div><div class="value">{html_mod.escape(str(tls_ver))}</div></div>
        <div class="meta-card"><div class="label">Cert Expires</div><div class="value">{cert_days} days</div></div>
        <div class="meta-card"><div class="label">Subdomains</div><div class="value">{n_subs}</div></div>
        <div class="meta-card"><div class="label">Header Score</div><div class="value">{hdr_score}/100</div></div>
    </div>

    <div class="section" style="display:flex;flex-direction:column;gap:14px;">
        <div style="display:flex;align-items:center;justify-content:space-between;">
            <h2 style="border-bottom:none;padding-bottom:0;margin-bottom:0;">Executive Summary</h2>
            {dali_logo_dark}
        </div>
        <p style="color:#334155;font-size:1.05em;line-height:1.75;">{summary_paragraph}</p>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:4px;">
            {('<span style="background:#fef2f2;color:#dc2626;padding:4px 12px;border-radius:6px;font-weight:700;font-size:0.9em;">' + str(n_crit) + ' Critical</span>') if n_crit else ''}
            {('<span style="background:#fff7ed;color:#ea580c;padding:4px 12px;border-radius:6px;font-weight:700;font-size:0.9em;">' + str(n_high) + ' High</span>') if n_high else ''}
            {('<span style="background:#fffbeb;color:#d97706;padding:4px 12px;border-radius:6px;font-weight:700;font-size:0.9em;">' + str(n_med) + ' Medium</span>') if n_med else ''}
            {('<span style="background:#f0fdf4;color:#16a34a;padding:4px 12px;border-radius:6px;font-weight:700;font-size:0.9em;">' + str(n_low) + ' Low</span>') if n_low else ''}
        </div>
    </div>

    <div class="section">
        <h2>Findings ({len(findings)})</h2>
        {findings_html if findings_html else '<p style="color:#64748b;">No findings detected.</p>'}
    </div>

    <div class="section">
        <h2>Security Headers</h2>
        <p style="margin-bottom:12px;"><strong>Present:</strong> {present_html or '<span style="color:#94a3b8;">None</span>'}</p>
        <p><strong>Missing:</strong> {missing_html or '<span style="color:#16a34a;">None — all headers present</span>'}</p>
    </div>

    <div class="section">
        <h2>Technologies</h2>
        {"<table><tr><th>Technology</th><th>Version</th></tr>" + tech_rows + "</table>" if tech_rows else '<p style="color:#64748b;">No technologies detected.</p>'}
    </div>

    {"<div class='section'><h2>Frontend CVEs (" + str(len(fl_vulns)) + ")</h2><table><tr><th>CVE</th><th>Library</th><th>Severity</th><th>Description</th></tr>" + cve_rows + "</table></div>" if cve_rows else ""}

    <div class="section">
        <h2>Infrastructure</h2>
        <table>
            <tr><td><strong>A Records</strong></td><td>{html_mod.escape(a_records)}</td></tr>
            <tr><td><strong>CDN</strong></td><td>{html_mod.escape(str(cdn))}</td></tr>
            <tr><td><strong>TLS Version</strong></td><td>{html_mod.escape(str(tls_ver))}</td></tr>
            <tr><td><strong>Certificate Issuer</strong></td><td>{html_mod.escape(str(cert_issuer))}</td></tr>
            <tr><td><strong>Certificate Days Left</strong></td><td>{cert_days}</td></tr>
        </table>
    </div>

    {self._build_per_subdomain_html(recon_data)}

    <div class="footer">
        Generated by <a href="https://dalisec.io">DALI Security</a> — Fray Reconnaissance Engine
    </div>
</div>
</body>
</html>'''

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_html)
        return output_file


def generate_markdown_report(data: dict, output_file: str = "fray_report.md") -> str:
    """Generate a Markdown security report from test or recon results.

    Supports both test results (data['results']) and recon results (data['attack_surface']).
    """
    lines = []
    target = data.get("target", "unknown")
    timestamp = data.get("timestamp", datetime.datetime.now().isoformat())
    duration = data.get("duration", data.get("scan_stats", {}).get("duration", "N/A"))

    lines.append(f"# Fray Security Report")
    lines.append(f"")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Date:** {timestamp}  ")
    lines.append(f"**Duration:** {duration}  ")
    lines.append(f"**Generated by:** [DALI Security](https://dalisec.io) — Fray")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # ── Test results ──
    results = data.get("results", [])
    summary = data.get("summary", {})
    if results:
        total = summary.get("total", len(results))
        blocked = summary.get("blocked", sum(1 for r in results if r.get("blocked")))
        passed = summary.get("passed", total - blocked)
        block_rate = summary.get("block_rate", f"{blocked/total*100:.1f}%" if total else "0%")

        lines.append(f"## Summary")
        lines.append(f"")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Payloads | {total} |")
        lines.append(f"| Blocked | {blocked} |")
        lines.append(f"| Bypassed | {passed} |")
        lines.append(f"| Block Rate | {block_rate} |")
        lines.append(f"")

        # Bypasses table
        bypasses = [r for r in results if not r.get("blocked")]
        if bypasses:
            lines.append(f"## Bypasses ({len(bypasses)})")
            lines.append(f"")
            lines.append(f"| # | Category | Payload | Status | Confidence | FP Score |")
            lines.append(f"|---|----------|---------|--------|------------|----------|")
            for i, r in enumerate(bypasses[:50], 1):
                cat = r.get("category", "?")
                payload = r.get("payload", "")[:60].replace("|", "\\|")
                status = r.get("status", 0)
                conf = r.get("bypass_confidence", 0)
                fp = r.get("fp_score", 0)
                lines.append(f"| {i} | {cat} | `{payload}` | {status} | {conf}% | {fp} |")
            lines.append(f"")

        # Category breakdown
        cats = defaultdict(lambda: {"total": 0, "blocked": 0, "bypassed": 0})
        for r in results:
            cat = r.get("category", "unknown")
            cats[cat]["total"] += 1
            if r.get("blocked"):
                cats[cat]["blocked"] += 1
            else:
                cats[cat]["bypassed"] += 1

        lines.append(f"## Category Breakdown")
        lines.append(f"")
        lines.append(f"| Category | Total | Blocked | Bypassed | Bypass Rate |")
        lines.append(f"|----------|-------|---------|----------|-------------|")
        for cat, s in sorted(cats.items(), key=lambda x: x[1]["bypassed"], reverse=True):
            rate = f"{s['bypassed']/s['total']*100:.0f}%" if s["total"] else "0%"
            lines.append(f"| {cat} | {s['total']} | {s['blocked']} | {s['bypassed']} | {rate} |")
        lines.append(f"")

    # ── Recon / attack surface findings ──
    atk = data.get("attack_surface", {})
    findings = atk.get("findings", [])
    if findings:
        risk_score = atk.get("risk_score", 0)
        risk_level = atk.get("risk_level", "?")
        lines.append(f"## Risk Assessment")
        lines.append(f"")
        lines.append(f"**Risk Score:** {risk_score}/100 ({risk_level})")
        lines.append(f"")
        lines.append(f"## Findings ({len(findings)})")
        lines.append(f"")
        lines.append(f"| Score | Severity | Category | Finding |")
        lines.append(f"|-------|----------|----------|---------|")
        for f in findings:
            sev = f.get("severity", "?")
            score = f.get("risk_score", 0)
            cat = f.get("category", "other")
            finding = f.get("finding", "").replace("|", "\\|")
            lines.append(f"| {score} | {sev.upper()} | {cat} | {finding} |")
        lines.append(f"")

    # Scan stats
    stats = data.get("scan_stats", {})
    if stats:
        lines.append(f"## Scan Statistics")
        lines.append(f"")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        for k, v in stats.items():
            lines.append(f"| {k.replace('_', ' ').title()} | {v} |")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"*Report generated by [Fray](https://github.com/dalisec/fray) — DALI Security*")

    md_content = "\n".join(lines) + "\n"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md_content)
    return output_file


def generate_sample_report():
    """Generate a sample report for demonstration"""
    sample_data = {
        'target': 'https://example.com',
        'duration': '5 minutes 32 seconds',
        'results': [
            {'category': 'xss', 'payload': '<script>alert(1)</script>', 'blocked': True, 'status_code': 403},
            {'category': 'xss', 'payload': '<img src=x onerror=alert(1)>', 'blocked': False, 'status_code': 200},
            {'category': 'sqli', 'payload': "' OR '1'='1", 'blocked': True, 'status_code': 403},
            {'category': 'sqli', 'payload': "' UNION SELECT NULL--", 'blocked': False, 'status_code': 200},
            {'category': 'command_injection', 'payload': '; ls -la', 'blocked': True, 'status_code': 403},
            {'category': 'ssrf', 'payload': 'http://169.254.169.254', 'blocked': False, 'status_code': 200},
        ] * 10  # Multiply for more data
    }
    
    generator = SecurityReportGenerator()
    output_file = generator.generate_html_report(sample_data, 'sample_security_report.html')
    print(f"✅ Sample report generated: {output_file}")
    return output_file


if __name__ == '__main__':
    print("=" * 60)
    print("Fray - Report Generator")
    print("=" * 60)
    print("\nGenerating sample security report...")
    generate_sample_report()
    print("\n✅ Done! Open 'sample_security_report.html' in your browser.")
