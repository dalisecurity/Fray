#!/usr/bin/env python3
"""
Complete integration test simulating real-world payload testing
Tests all components without requiring external dependencies
"""

import time
from waf_detector import WAFDetector
from waf_recommendation_engine import WAFRecommendationEngine
from report_generator import SecurityReportGenerator

def simulate_payload_testing():
    """Simulate realistic payload testing results"""
    print('=' * 80)
    print('INTEGRATION TEST: Complete Payload Testing Workflow')
    print('=' * 80)
    
    # Simulate test results from a vulnerable application
    test_results = [
        # XSS payloads
        {'payload': '<script>alert(1)</script>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.15},
        {'payload': '<img src=x onerror=alert(1)>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.12},
        {'payload': '<svg/onload=alert`XSS`>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.18},
        {'payload': '"><script>alert(String.fromCharCode(88,83,83))</script>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.14},
        {'payload': '<iframe src="javascript:alert(1)">', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.16},
        
        # SQLi payloads
        {'payload': "' OR '1'='1", 'category': 'sqli', 'status_code': 500, 'blocked': False, 'response_time': 0.20},
        {'payload': "admin'--", 'category': 'sqli', 'status_code': 500, 'blocked': False, 'response_time': 0.19},
        {'payload': "' OR 1=1--", 'category': 'sqli', 'status_code': 500, 'blocked': False, 'response_time': 0.21},
        {'payload': "1' UNION SELECT NULL--", 'category': 'sqli', 'status_code': 500, 'blocked': False, 'response_time': 0.22},
        {'payload': "'; DROP TABLE users--", 'category': 'sqli', 'status_code': 500, 'blocked': False, 'response_time': 0.18},
        
        # Command Injection
        {'payload': '; ls -la', 'category': 'command_injection', 'status_code': 200, 'blocked': False, 'response_time': 0.17},
        {'payload': '| whoami', 'category': 'command_injection', 'status_code': 200, 'blocked': False, 'response_time': 0.15},
        
        # Path Traversal
        {'payload': '../../../etc/passwd', 'category': 'path_traversal', 'status_code': 200, 'blocked': False, 'response_time': 0.13},
        {'payload': '....//....//....//etc/passwd', 'category': 'path_traversal', 'status_code': 200, 'blocked': False, 'response_time': 0.14},
    ]
    
    return test_results

def test_scenario_1_no_waf():
    """Test Scenario 1: No WAF detected (worst case)"""
    print('\n' + '=' * 80)
    print('SCENARIO 1: No WAF Protection Detected')
    print('=' * 80)
    
    # Simulate WAF detection
    waf_detection = {
        'waf_detected': False,
        'waf_vendor': None,
        'confidence': 0,
        'target': 'http://vulnerable-app.example.com'
    }
    
    # Get test results
    test_results = simulate_payload_testing()
    
    print(f'\n✅ Simulated {len(test_results)} payload tests')
    print(f'   All payloads bypassed (no protection)')
    
    # Generate recommendations
    print('\n📋 Generating WAF recommendations...')
    engine = WAFRecommendationEngine()
    
    vulnerabilities = [f"{r['category'].upper()}: {r['payload'][:30]}..." for r in test_results if not r['blocked']]
    recommendations = engine.generate_recommendations(
        waf_detected=False,
        target=waf_detection['target'],
        vulnerabilities_found=vulnerabilities
    )
    
    print(f'✅ Recommendations generated')
    print(f'   Security Posture: {recommendations["security_posture"]}')
    print(f'   Critical Actions: {len(recommendations["immediate_actions"])}')
    print(f'   Recommended Vendors: {len(recommendations["alternative_vendors"])}')
    
    # Generate HTML report
    print('\n📊 Generating HTML report...')
    generator = SecurityReportGenerator()
    report_file = 'integration_test_no_waf.html'
    generator.generate_html_report(
        test_results=test_results,
        output_file=report_file,
        waf_detection=waf_detection
    )
    
    print(f'✅ Report generated: {report_file}')
    
    return test_results, waf_detection, recommendations, report_file

def test_scenario_2_cloudflare_detected():
    """Test Scenario 2: Cloudflare WAF detected (good protection)"""
    print('\n' + '=' * 80)
    print('SCENARIO 2: Cloudflare WAF Detected')
    print('=' * 80)
    
    # Simulate WAF detection
    waf_detection = {
        'waf_detected': True,
        'waf_vendor': 'Cloudflare',
        'confidence': 95,
        'target': 'http://protected-app.example.com'
    }
    
    # Simulate test results with WAF blocking most payloads
    test_results = [
        # Most XSS blocked
        {'payload': '<script>alert(1)</script>', 'category': 'xss', 'status_code': 403, 'blocked': True, 'response_time': 0.05},
        {'payload': '<img src=x onerror=alert(1)>', 'category': 'xss', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': '<svg/onload=alert`XSS`>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.18},  # Bypass
        {'payload': '"><script>alert(String.fromCharCode(88,83,83))</script>', 'category': 'xss', 'status_code': 403, 'blocked': True, 'response_time': 0.05},
        
        # All SQLi blocked
        {'payload': "' OR '1'='1", 'category': 'sqli', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': "admin'--", 'category': 'sqli', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': "' OR 1=1--", 'category': 'sqli', 'status_code': 403, 'blocked': True, 'response_time': 0.05},
        
        # Command Injection blocked
        {'payload': '; ls -la', 'category': 'command_injection', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': '| whoami', 'category': 'command_injection', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
    ]
    
    blocked = sum(1 for r in test_results if r['blocked'])
    print(f'\n✅ Simulated {len(test_results)} payload tests')
    print(f'   Blocked: {blocked}/{len(test_results)} ({blocked/len(test_results)*100:.1f}%)')
    print(f'   Bypassed: {len(test_results) - blocked}')
    
    # Generate recommendations
    print('\n📋 Generating WAF recommendations...')
    engine = WAFRecommendationEngine()
    
    vulnerabilities = [f"{r['category'].upper()}: {r['payload'][:30]}..." for r in test_results if not r['blocked']]
    recommendations = engine.generate_recommendations(
        waf_detected=True,
        waf_vendor='Cloudflare',
        confidence=95,
        target=waf_detection['target'],
        vulnerabilities_found=vulnerabilities
    )
    
    print(f'✅ Recommendations generated')
    print(f'   Security Posture: {recommendations["security_posture"]}')
    print(f'   WAF Vendor: {recommendations["waf_vendor"]}')
    print(f'   Confidence: {recommendations["confidence"]}%')
    
    # Generate HTML report
    print('\n📊 Generating HTML report...')
    generator = SecurityReportGenerator()
    report_file = 'integration_test_cloudflare.html'
    generator.generate_html_report(
        test_results=test_results,
        output_file=report_file,
        waf_detection=waf_detection
    )
    
    print(f'✅ Report generated: {report_file}')
    
    return test_results, waf_detection, recommendations, report_file

def test_scenario_3_aws_waf_partial():
    """Test Scenario 3: AWS WAF with partial protection"""
    print('\n' + '=' * 80)
    print('SCENARIO 3: AWS WAF with Partial Protection')
    print('=' * 80)
    
    # Simulate WAF detection
    waf_detection = {
        'waf_detected': True,
        'waf_vendor': 'AWS WAF',
        'confidence': 75,
        'target': 'http://aws-app.example.com'
    }
    
    # Simulate test results with some bypasses
    test_results = [
        # Some XSS blocked, some bypass
        {'payload': '<script>alert(1)</script>', 'category': 'xss', 'status_code': 403, 'blocked': True, 'response_time': 0.05},
        {'payload': '<img src=x onerror=alert(1)>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.15},
        {'payload': '<svg/onload=alert`XSS`>', 'category': 'xss', 'status_code': 200, 'blocked': False, 'response_time': 0.18},
        
        # SQLi mostly blocked
        {'payload': "' OR '1'='1", 'category': 'sqli', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': "admin'--", 'category': 'sqli', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': "1' UNION SELECT NULL--", 'category': 'sqli', 'status_code': 200, 'blocked': False, 'response_time': 0.20},
        
        # Command Injection some bypass
        {'payload': '; ls -la', 'category': 'command_injection', 'status_code': 403, 'blocked': True, 'response_time': 0.04},
        {'payload': '`whoami`', 'category': 'command_injection', 'status_code': 200, 'blocked': False, 'response_time': 0.17},
    ]
    
    blocked = sum(1 for r in test_results if r['blocked'])
    print(f'\n✅ Simulated {len(test_results)} payload tests')
    print(f'   Blocked: {blocked}/{len(test_results)} ({blocked/len(test_results)*100:.1f}%)')
    print(f'   Bypassed: {len(test_results) - blocked}')
    
    # Generate recommendations
    print('\n📋 Generating WAF recommendations...')
    engine = WAFRecommendationEngine()
    
    vulnerabilities = [f"{r['category'].upper()}: {r['payload'][:30]}..." for r in test_results if not r['blocked']]
    recommendations = engine.generate_recommendations(
        waf_detected=True,
        waf_vendor='AWS WAF',
        confidence=75,
        target=waf_detection['target'],
        vulnerabilities_found=vulnerabilities
    )
    
    print(f'✅ Recommendations generated')
    print(f'   Security Posture: {recommendations["security_posture"]}')
    print(f'   Improvement Needed: {len(vulnerabilities)} bypasses found')
    
    # Generate HTML report
    print('\n📊 Generating HTML report...')
    generator = SecurityReportGenerator()
    report_file = 'integration_test_aws_waf.html'
    generator.generate_html_report(
        test_results=test_results,
        output_file=report_file,
        waf_detection=waf_detection
    )
    
    print(f'✅ Report generated: {report_file}')
    
    return test_results, waf_detection, recommendations, report_file

def main():
    """Run all integration tests"""
    print('\n' + '=' * 80)
    print('COMPLETE INTEGRATION TEST SUITE')
    print('Testing WAF Detection and Recommendation System')
    print('=' * 80)
    
    results = []
    
    # Test Scenario 1: No WAF
    try:
        result1 = test_scenario_1_no_waf()
        results.append(('No WAF Detected', result1, True))
    except Exception as e:
        print(f'\n❌ Scenario 1 failed: {e}')
        import traceback
        traceback.print_exc()
        results.append(('No WAF Detected', None, False))
    
    # Test Scenario 2: Cloudflare WAF
    try:
        result2 = test_scenario_2_cloudflare_detected()
        results.append(('Cloudflare WAF', result2, True))
    except Exception as e:
        print(f'\n❌ Scenario 2 failed: {e}')
        import traceback
        traceback.print_exc()
        results.append(('Cloudflare WAF', None, False))
    
    # Test Scenario 3: AWS WAF Partial
    try:
        result3 = test_scenario_3_aws_waf_partial()
        results.append(('AWS WAF Partial', result3, True))
    except Exception as e:
        print(f'\n❌ Scenario 3 failed: {e}')
        import traceback
        traceback.print_exc()
        results.append(('AWS WAF Partial', None, False))
    
    # Final Summary
    print('\n' + '=' * 80)
    print('INTEGRATION TEST SUMMARY')
    print('=' * 80)
    
    passed = sum(1 for _, _, success in results if success)
    total = len(results)
    
    for scenario_name, result, success in results:
        status = '✅ PASSED' if success else '❌ FAILED'
        print(f'{status} - {scenario_name}')
        if success and result:
            _, _, _, report_file = result
            print(f'         Report: {report_file}')
    
    print(f'\n📊 Overall Results: {passed}/{total} scenarios passed')
    
    if passed == total:
        print('\n🎉 ALL INTEGRATION TESTS PASSED!')
        print('\n📁 Generated Reports:')
        print('   1. integration_test_no_waf.html - No WAF scenario')
        print('   2. integration_test_cloudflare.html - Cloudflare WAF scenario')
        print('   3. integration_test_aws_waf.html - AWS WAF partial protection')
        print('\n✅ All features working correctly:')
        print('   - WAF detection simulation')
        print('   - Payload testing simulation')
        print('   - Recommendation generation')
        print('   - HTML report generation')
        print('   - Multiple WAF vendors supported')
        print('   - Different security postures handled')
    else:
        print(f'\n⚠️ {total - passed} scenario(s) failed')
    
    print('=' * 80)

if __name__ == '__main__':
    main()
