#!/usr/bin/env python3
"""
WAF Recommendation Engine
Provides security recommendations based on WAF detection results
"""

from typing import Dict, List, Optional

class WAFRecommendationEngine:
    """Generate security recommendations based on WAF detection"""
    
    # Top WAF vendors with their key features
    WAF_VENDORS = {
        'Cloudflare': {
            'type': 'Cloud WAF',
            'pricing': 'Starts at $20/month',
            'features': ['DDoS protection', 'Bot management', 'Rate limiting', 'Global CDN'],
            'best_for': 'Small to large websites, e-commerce, SaaS',
            'deployment': 'DNS change (5 minutes)',
            'url': 'https://www.cloudflare.com/waf/'
        },
        'AWS WAF': {
            'type': 'Cloud WAF',
            'pricing': 'Pay-as-you-go ($5/month base + rules)',
            'features': ['AWS integration', 'Custom rules', 'Managed rule groups', 'API protection'],
            'best_for': 'AWS-hosted applications, APIs',
            'deployment': 'CloudFormation/Terraform (30 minutes)',
            'url': 'https://aws.amazon.com/waf/'
        },
        'Akamai': {
            'type': 'Enterprise WAF',
            'pricing': 'Enterprise pricing (contact sales)',
            'features': ['Advanced bot management', 'API security', 'DDoS protection', 'Global CDN'],
            'best_for': 'Large enterprises, high-traffic sites',
            'deployment': 'DNS/CNAME change (varies)',
            'url': 'https://www.akamai.com/products/app-and-api-protector'
        },
        'Imperva': {
            'type': 'Enterprise WAF',
            'pricing': 'Enterprise pricing (contact sales)',
            'features': ['Advanced threat intelligence', 'DDoS protection', 'Bot management', 'CDN'],
            'best_for': 'Enterprises, compliance-heavy industries',
            'deployment': 'DNS change or on-premise (varies)',
            'url': 'https://www.imperva.com/products/web-application-firewall-waf/'
        },
        'Microsoft Azure WAF': {
            'type': 'Cloud WAF',
            'pricing': 'Pay-as-you-go (included with Application Gateway)',
            'features': ['Azure integration', 'OWASP rule sets', 'Custom rules', 'Bot protection'],
            'best_for': 'Azure-hosted applications',
            'deployment': 'Azure Portal/ARM templates (30 minutes)',
            'url': 'https://azure.microsoft.com/en-us/products/web-application-firewall'
        },
        'Google Cloud Armor': {
            'type': 'Cloud WAF',
            'pricing': 'Pay-as-you-go ($0.75/policy/month + rules)',
            'features': ['GCP integration', 'DDoS protection', 'Adaptive protection', 'Rate limiting'],
            'best_for': 'GCP-hosted applications',
            'deployment': 'gcloud CLI/Terraform (30 minutes)',
            'url': 'https://cloud.google.com/armor'
        },
        'F5': {
            'type': 'Enterprise WAF',
            'pricing': 'Enterprise pricing (contact sales)',
            'features': ['Advanced WAF', 'Bot defense', 'API security', 'DDoS protection'],
            'best_for': 'Large enterprises, complex applications',
            'deployment': 'On-premise or cloud (varies)',
            'url': 'https://www.f5.com/products/security/advanced-waf'
        },
        'ModSecurity': {
            'type': 'Open Source WAF',
            'pricing': 'Free (open source)',
            'features': ['OWASP Core Rule Set', 'Custom rules', 'Self-hosted'],
            'best_for': 'Budget-conscious, self-managed infrastructure',
            'deployment': 'Server installation (1-2 hours)',
            'url': 'https://github.com/SpiderLabs/ModSecurity'
        }
    }
    
    @staticmethod
    def generate_recommendations(waf_detected: bool, waf_vendor: Optional[str] = None, 
                                 confidence: int = 0, target: str = '', 
                                 vulnerabilities_found: List[str] = None) -> Dict:
        """
        Generate security recommendations based on WAF detection results
        
        Args:
            waf_detected: Whether a WAF was detected
            waf_vendor: Name of detected WAF vendor (if any)
            confidence: Confidence level of WAF detection (0-100)
            target: Target URL/domain
            vulnerabilities_found: List of vulnerabilities found during testing
            
        Returns:
            Dictionary containing recommendations
        """
        recommendations = {
            'waf_status': 'detected' if waf_detected else 'not_detected',
            'waf_vendor': waf_vendor,
            'confidence': confidence,
            'target': target,
            'timestamp': None,
            'security_posture': '',
            'recommendations': [],
            'immediate_actions': [],
            'vendor_info': None,
            'alternative_vendors': []
        }
        
        if not waf_detected:
            # No WAF detected - Critical security gap
            recommendations['security_posture'] = 'CRITICAL - No WAF Protection Detected'
            recommendations['recommendations'] = WAFRecommendationEngine._get_no_waf_recommendations(
                target, vulnerabilities_found
            )
            recommendations['immediate_actions'] = [
                '🚨 Deploy a Web Application Firewall immediately',
                '🔍 Conduct comprehensive security assessment',
                '🛡️ Implement input validation and output encoding',
                '📊 Enable security monitoring and logging',
                '⚡ Consider cloud WAF for quick deployment (5-30 minutes)'
            ]
            recommendations['alternative_vendors'] = WAFRecommendationEngine._get_recommended_vendors(target)
            
        else:
            # WAF detected
            if confidence >= 70:
                recommendations['security_posture'] = f'GOOD - {waf_vendor} WAF Detected (High Confidence)'
            elif confidence >= 40:
                recommendations['security_posture'] = f'MODERATE - Possible {waf_vendor} WAF (Medium Confidence)'
            else:
                recommendations['security_posture'] = f'UNCERTAIN - Weak {waf_vendor} Detection (Low Confidence)'
            
            recommendations['recommendations'] = WAFRecommendationEngine._get_waf_present_recommendations(
                waf_vendor, confidence, vulnerabilities_found
            )
            recommendations['immediate_actions'] = WAFRecommendationEngine._get_waf_actions(
                waf_vendor, confidence
            )
            
            if waf_vendor in WAFRecommendationEngine.WAF_VENDORS:
                recommendations['vendor_info'] = WAFRecommendationEngine.WAF_VENDORS[waf_vendor]
        
        return recommendations
    
    @staticmethod
    def _get_no_waf_recommendations(target: str, vulnerabilities: List[str] = None) -> List[str]:
        """Generate recommendations when no WAF is detected"""
        recs = [
            '⚠️ CRITICAL: No Web Application Firewall detected on target',
            '',
            '📋 Immediate Security Risks:',
            '   • Vulnerable to OWASP Top 10 attacks (XSS, SQLi, etc.)',
            '   • No protection against automated attacks and bots',
            '   • No rate limiting or DDoS protection',
            '   • Exposed to zero-day vulnerabilities',
            '   • No virtual patching capability',
            '',
            '🛡️ Recommended Actions:',
            '',
            '1. Deploy a WAF Immediately (Priority: CRITICAL)',
            '   Choose based on your infrastructure:',
            '',
            '   Cloud-Based WAF (Fastest - 5-30 min deployment):',
            '   • Cloudflare WAF - Best for: Quick deployment, any size',
            '     - Pricing: $20/month, includes CDN + DDoS protection',
            '     - Setup: DNS change only (5 minutes)',
            '     - URL: https://www.cloudflare.com/waf/',
            '',
            '   • AWS WAF - Best for: AWS-hosted applications',
            '     - Pricing: $5/month + $1/rule + $0.60/million requests',
            '     - Setup: CloudFormation/Terraform (30 minutes)',
            '     - URL: https://aws.amazon.com/waf/',
            '',
            '   • Azure WAF - Best for: Azure-hosted applications',
            '     - Pricing: Included with Application Gateway',
            '     - Setup: Azure Portal (30 minutes)',
            '     - URL: https://azure.microsoft.com/products/web-application-firewall',
            '',
            '   • Google Cloud Armor - Best for: GCP-hosted applications',
            '     - Pricing: $0.75/policy/month + per-rule pricing',
            '     - Setup: gcloud CLI (30 minutes)',
            '     - URL: https://cloud.google.com/armor',
            '',
            '   Open Source (Budget-friendly):',
            '   • ModSecurity with OWASP Core Rule Set',
            '     - Pricing: Free (self-hosted)',
            '     - Setup: Server installation (1-2 hours)',
            '     - URL: https://github.com/SpiderLabs/ModSecurity',
            '',
            '2. Enable Security Headers',
            '   • Content-Security-Policy',
            '   • X-Frame-Options: DENY',
            '   • X-Content-Type-Options: nosniff',
            '   • Strict-Transport-Security',
            '',
            '3. Implement Input Validation',
            '   • Validate all user inputs',
            '   • Use parameterized queries',
            '   • Encode outputs properly',
            '',
            '4. Enable Logging and Monitoring',
            '   • Application logs',
            '   • Security event monitoring',
            '   • Intrusion detection system (IDS)',
            '',
            '5. Regular Security Testing',
            '   • Penetration testing',
            '   • Vulnerability scanning',
            '   • Code security reviews'
        ]
        
        if vulnerabilities:
            recs.extend([
                '',
                '⚠️ Vulnerabilities Found During Testing:',
                *[f'   • {vuln}' for vuln in vulnerabilities],
                '',
                '🚨 These vulnerabilities could be exploited immediately!',
                '   A WAF would provide virtual patching while you fix the code.'
            ])
        
        return recs
    
    @staticmethod
    def _get_waf_present_recommendations(vendor: str, confidence: int, 
                                         vulnerabilities: List[str] = None) -> List[str]:
        """Generate recommendations when WAF is detected"""
        recs = [
            f'✅ {vendor} WAF Detected (Confidence: {confidence}%)',
            '',
            '📊 Current Security Posture:',
            f'   • WAF Vendor: {vendor}',
            f'   • Detection Confidence: {confidence}%',
            '   • Basic protection layer in place',
            ''
        ]
        
        if confidence < 70:
            recs.extend([
                '⚠️ Low Confidence Detection - Verification Needed:',
                '   • Confirm WAF is properly configured',
                '   • Check if WAF is in monitoring mode vs blocking mode',
                '   • Verify WAF rules are up to date',
                ''
            ])

        # ── Vendor-specific intel from waf_intel.json ──
        try:
            from fray import load_waf_intel
            intel = load_waf_intel()
            vendors_db = intel.get("vendors", {})
            technique_matrix = intel.get("technique_matrix", {})

            # Resolve vendor key
            vendor_key = None
            vendor_lower = vendor.lower()
            for key in vendors_db:
                if key.replace("_", " ") in vendor_lower or vendor_lower in key.replace("_", " "):
                    vendor_key = key
                    break
            if not vendor_key:
                for key, data in vendors_db.items():
                    if vendor_lower in data.get("display_name", "").lower():
                        vendor_key = key
                        break

            if vendor_key and vendor_key in vendors_db:
                vdata = vendors_db[vendor_key]
                mode = vdata.get("detection_mode", "unknown")
                recs.append(f'🔍 WAF Intelligence ({vdata.get("display_name", vendor)}):')
                recs.append(f'   • Detection mode: {mode}')
                recs.append('')

                # Known bypass techniques the WAF is vulnerable to
                effective = vdata.get("bypass_techniques", {}).get("effective", [])
                if effective:
                    recs.append('⚠️ Known Bypass Techniques (address these):')
                    for t in effective:
                        conf = t.get("confidence", "?")
                        recs.append(f'   • [{conf}] {t["technique"]}: {t["description"]}')
                    recs.append('')

                # Detection gaps
                gaps = vdata.get("detection_gaps", {})
                sig_misses = gaps.get("signature", {}).get("misses", [])
                anom_misses = gaps.get("anomaly", {}).get("misses", [])
                if sig_misses or anom_misses:
                    recs.append('🕳️ Detection Gaps (consider custom rules):')
                    if sig_misses:
                        recs.append(f'   • Signature gaps: {", ".join(sig_misses)}')
                    if anom_misses:
                        recs.append(f'   • Anomaly gaps: {", ".join(anom_misses)}')
                    recs.append('')

                # Cross-vendor technique matrix
                eff_techs = []
                blk_techs = []
                for tech_name, tech_data in technique_matrix.items():
                    if not isinstance(tech_data, dict):
                        continue
                    if vendor_key in tech_data.get("effective_against", []):
                        eff_techs.append(tech_name)
                    elif vendor_key in tech_data.get("blocked_by", []):
                        blk_techs.append(tech_name)
                if eff_techs:
                    recs.append('🎯 Techniques Effective Against This WAF:')
                    for t in eff_techs:
                        recs.append(f'   • {t}')
                    recs.append('   → Add custom rules to mitigate these techniques')
                    recs.append('')
                if blk_techs:
                    recs.append('✅ Techniques Already Blocked:')
                    for t in blk_techs:
                        recs.append(f'   • {t}')
                    recs.append('')

                # Vendor-specific hardening
                rec_cats = vdata.get("recommended_categories", [])
                if rec_cats:
                    recs.append(f'� Test These Categories: {", ".join(rec_cats)}')
                    recs.append(f'   → fray test <url> -c {rec_cats[0]} --smart')
                    recs.append('')

                delay = vdata.get("recommended_delay")
                if delay:
                    recs.append(f'⏱️ Safe testing delay: {delay}s between requests')
                    recs.append('')
        except Exception:
            pass  # Fallback to generic if intel unavailable

        recs.extend([
            '🔧 General Recommendations:',
            '',
            '1. Verify WAF Configuration',
            '   • Ensure WAF is in blocking mode (not just monitoring)',
            '   • Review and update rule sets regularly',
            '   • Enable all OWASP Top 10 protections',
            '   • Configure custom rules for your application',
            '',
            '2. Enable Advanced Features',
            '   • Bot management and mitigation',
            '   • Rate limiting and DDoS protection',
            '   • API security rules',
            '   • Geo-blocking if applicable',
            '',
            '3. Monitoring and Logging',
            '   • Enable detailed WAF logs',
            '   • Set up alerts for blocked requests',
            '   • Review false positives regularly',
            '   • Integrate with SIEM if available',
            '',
            '4. Layered Security',
            '   • WAF is not enough - implement defense in depth',
            '   • Use security headers',
            '   • Implement input validation in code',
            '   • Keep software updated'
        ])
        
        if vulnerabilities:
            recs.extend([
                '',
                '⚠️ Vulnerabilities Found Despite WAF:',
                *[f'   • {vuln}' for vuln in vulnerabilities],
                '',
                '🔧 Action Required:',
                '   • These bypasses indicate WAF configuration gaps',
                '   • Update WAF rules to block these specific payloads',
                '   • Fix vulnerabilities in application code',
                '   • Consider additional security layers'
            ])
        
        return recs
    
    @staticmethod
    def _get_waf_actions(vendor: str, confidence: int) -> List[str]:
        """Get immediate actions based on WAF detection"""
        actions = []
        
        if confidence >= 70:
            actions = [
                f'✅ {vendor} WAF is properly protecting your application',
                '📊 Review WAF logs for blocked attacks',
                '🔧 Fine-tune rules to reduce false positives',
                '📈 Monitor WAF performance and effectiveness',
                '🔄 Keep WAF rules updated with latest threat intelligence'
            ]
        elif confidence >= 40:
            actions = [
                f'⚠️ Verify {vendor} WAF configuration',
                '🔍 Check if WAF is in blocking mode',
                '📋 Review WAF rule sets',
                '🧪 Test WAF effectiveness with known payloads',
                '📞 Contact WAF vendor support if needed'
            ]
        else:
            actions = [
                f'⚠️ Low confidence {vendor} detection - verification needed',
                '🔍 Manually verify WAF presence and configuration',
                '📋 Check WAF dashboard/logs',
                '🧪 Test with additional payloads',
                '📞 Contact security team for confirmation'
            ]
        
        return actions
    
    @staticmethod
    def _get_recommended_vendors(target: str) -> List[Dict]:
        """Get recommended WAF vendors based on target"""
        # Simplified recommendation - in production, this could analyze target infrastructure
        return [
            {
                'name': 'Cloudflare',
                'reason': 'Quick deployment (5 min), affordable, includes CDN',
                'pricing': '$20/month',
                'deployment_time': '5 minutes',
                'url': 'https://www.cloudflare.com/waf/'
            },
            {
                'name': 'AWS WAF',
                'reason': 'Best for AWS-hosted applications, pay-as-you-go',
                'pricing': '$5/month base + usage',
                'deployment_time': '30 minutes',
                'url': 'https://aws.amazon.com/waf/'
            },
            {
                'name': 'ModSecurity',
                'reason': 'Free and open source, self-hosted',
                'pricing': 'Free',
                'deployment_time': '1-2 hours',
                'url': 'https://github.com/SpiderLabs/ModSecurity'
            }
        ]
    
    @staticmethod
    def format_recommendations_text(recommendations: Dict) -> str:
        """Format recommendations as readable text"""
        output = []
        output.append('=' * 80)
        output.append('WAF DETECTION AND SECURITY RECOMMENDATIONS')
        output.append('=' * 80)
        output.append('')
        output.append(f'Target: {recommendations["target"]}')
        output.append(f'Security Posture: {recommendations["security_posture"]}')
        output.append('')
        
        if recommendations['waf_vendor']:
            output.append(f'Detected WAF: {recommendations["waf_vendor"]}')
            output.append(f'Confidence: {recommendations["confidence"]}%')
            output.append('')
        
        output.append('IMMEDIATE ACTIONS:')
        output.append('-' * 80)
        for action in recommendations['immediate_actions']:
            output.append(action)
        output.append('')
        
        output.append('DETAILED RECOMMENDATIONS:')
        output.append('-' * 80)
        for rec in recommendations['recommendations']:
            output.append(rec)
        output.append('')
        
        if recommendations.get('vendor_info'):
            info = recommendations['vendor_info']
            output.append('WAF VENDOR INFORMATION:')
            output.append('-' * 80)
            output.append(f'Type: {info["type"]}')
            output.append(f'Pricing: {info["pricing"]}')
            output.append(f'Best For: {info["best_for"]}')
            output.append(f'Deployment: {info["deployment"]}')
            output.append(f'Features: {", ".join(info["features"])}')
            output.append(f'URL: {info["url"]}')
            output.append('')
        
        if recommendations.get('alternative_vendors'):
            output.append('RECOMMENDED WAF VENDORS:')
            output.append('-' * 80)
            for vendor in recommendations['alternative_vendors']:
                output.append(f'\n{vendor["name"]}:')
                output.append(f'  Reason: {vendor["reason"]}')
                output.append(f'  Pricing: {vendor["pricing"]}')
                output.append(f'  Deployment: {vendor["deployment_time"]}')
                output.append(f'  URL: {vendor["url"]}')
            output.append('')
        
        output.append('=' * 80)
        
        return '\n'.join(output)


if __name__ == '__main__':
    # Example usage
    engine = WAFRecommendationEngine()
    
    # Test 1: No WAF detected
    print("Test 1: No WAF Detected")
    print("=" * 80)
    recs = engine.generate_recommendations(
        waf_detected=False,
        target='https://example.com',
        vulnerabilities_found=['SQL Injection in /login', 'XSS in /search']
    )
    print(engine.format_recommendations_text(recs))
    print('\n\n')
    
    # Test 2: Cloudflare detected
    print("Test 2: Cloudflare WAF Detected")
    print("=" * 80)
    recs = engine.generate_recommendations(
        waf_detected=True,
        waf_vendor='Cloudflare',
        confidence=95,
        target='https://example.com'
    )
    print(engine.format_recommendations_text(recs))
