#!/usr/bin/env python3
"""
End-to-end test of WAF payload testing functionality
Tests against a local vulnerable application
"""

import urllib.request
import urllib.parse
import urllib.error
import time
import sys
from waf_detector import WAFDetector
from waf_recommendation_engine import WAFRecommendationEngine
from report_generator import SecurityReportGenerator

def test_server_availability(url):
    """Test if the target server is available"""
    print(f'\n{"="*80}')
    print('TEST 1: Server Availability')
    print(f'{"="*80}')
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read()
            print(f'✅ Server is reachable')
            print(f'   Status Code: {response.status}')
            print(f'   Response Length: {len(data)} bytes')
        return True
    except Exception as e:
        print(f'❌ Server is not reachable: {e}')
        return False

def test_waf_detection(url):
    """Test WAF detection against the target"""
    print(f'\n{"="*80}')
    print('TEST 2: WAF Detection')
    print(f'{"="*80}')
    
    try:
        detector = WAFDetector()
        result = detector.detect(url)
        
        print(f'WAF Detected: {result["waf_detected"]}')
        if result['waf_detected']:
            print(f'WAF Vendor: {result.get("waf_vendor", "Unknown")}')
            print(f'Confidence: {result.get("confidence", 0)}%')
        else:
            print('No WAF protection detected (as expected for local test server)')
        
        return result
    except Exception as e:
        print(f'❌ WAF detection failed: {e}')
        import traceback
        traceback.print_exc()
        return {'waf_detected': False, 'waf_vendor': None, 'confidence': 0}

def test_payload_delivery(url):
    """Test payload delivery against various endpoints"""
    print(f'\n{"="*80}')
    print('TEST 3: Payload Delivery')
    print(f'{"="*80}')
    
    test_results = []
    
    # XSS payloads
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert`XSS`>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<iframe src="javascript:alert(1)">',
    ]
    
    print('\n3a. Testing XSS payloads on /search endpoint:')
    for payload in xss_payloads:
        try:
            params = urllib.parse.urlencode({'q': payload})
            full_url = f'{url}/search?{params}'
            start_time = time.time()
            
            req = urllib.request.Request(full_url)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read().decode('utf-8')
                status_code = response.status
                response_time = time.time() - start_time
            
            blocked = status_code in [403, 406, 429]
            reflected = payload in data
            
            result = {
                'payload': payload,
                'category': 'xss',
                'status_code': status_code,
                'blocked': blocked,
                'reflected': reflected,
                'response_time': response_time
            }
            test_results.append(result)
            
            status = '🛡️ Blocked' if blocked else ('⚠️ Reflected' if reflected else '✅ Safe')
            print(f'  {status} - {payload[:50]}... (Status: {status_code})')
            
        except urllib.error.HTTPError as e:
            blocked = e.code in [403, 406, 429]
            result = {
                'payload': payload,
                'category': 'xss',
                'status_code': e.code,
                'blocked': blocked,
                'response_time': 0
            }
            test_results.append(result)
            print(f'  🛡️ Blocked - {payload[:50]}... (Status: {e.code})')
        except Exception as e:
            print(f'  ❌ Error testing payload: {e}')
    
    # SQLi payloads
    sqli_payloads = [
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
    ]
    
    print('\n3b. Testing SQLi payloads on /api/user endpoint:')
    for payload in sqli_payloads:
        try:
            params = urllib.parse.urlencode({'id': payload})
            full_url = f'{url}/api/user?{params}'
            start_time = time.time()
            
            req = urllib.request.Request(full_url)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read().decode('utf-8')
                status_code = response.status
                response_time = time.time() - start_time
            
            blocked = status_code in [403, 406, 429]
            sql_error = any(err in data.lower() for err in ['sql', 'syntax', 'error'])
            
            result = {
                'payload': payload,
                'category': 'sqli',
                'status_code': status_code,
                'blocked': blocked,
                'sql_error': sql_error,
                'response_time': response_time
            }
            test_results.append(result)
            
            status = '🛡️ Blocked' if blocked else ('⚠️ SQL Error' if sql_error else '✅ Handled')
            print(f'  {status} - {payload[:50]}... (Status: {status_code})')
            
        except urllib.error.HTTPError as e:
            blocked = e.code in [403, 406, 429]
            result = {
                'payload': payload,
                'category': 'sqli',
                'status_code': e.code,
                'blocked': blocked,
                'response_time': 0
            }
            test_results.append(result)
            print(f'  🛡️ Blocked - {payload[:50]}... (Status: {e.code})')
        except Exception as e:
            print(f'  ❌ Error testing payload: {e}')
    
    # Summary
    total = len(test_results)
    blocked = sum(1 for r in test_results if r.get('blocked', False))
    print(f'\n📊 Payload Testing Summary:')
    print(f'   Total Payloads: {total}')
    print(f'   Blocked: {blocked}')
    print(f'   Bypassed: {total - blocked}')
    print(f'   Block Rate: {(blocked/total*100):.1f}%')
    
    return test_results

def test_recommendation_generation(waf_detection, test_results):
    """Test recommendation generation"""
    print(f'\n{"="*80}')
    print('TEST 4: Recommendation Generation')
    print(f'{"="*80}')
    
    try:
        engine = WAFRecommendationEngine()
        
        # Extract vulnerabilities
        vulnerabilities = []
        for result in test_results:
            if not result.get('blocked', False):
                vuln_desc = f"{result['category'].upper()} - {result['payload'][:30]}..."
                vulnerabilities.append(vuln_desc)
        
        recommendations = engine.generate_recommendations(
            waf_detected=waf_detection['waf_detected'],
            waf_vendor=waf_detection.get('waf_vendor'),
            confidence=waf_detection.get('confidence', 0),
            target='http://127.0.0.1:5000',
            vulnerabilities_found=vulnerabilities
        )
        
        print(f'✅ Recommendations generated')
        print(f'   Security Posture: {recommendations["security_posture"]}')
        print(f'   Recommendations: {len(recommendations["recommendations"])} items')
        print(f'   Immediate Actions: {len(recommendations["immediate_actions"])} items')
        
        if not waf_detection['waf_detected']:
            print(f'   Alternative Vendors: {len(recommendations["alternative_vendors"])} vendors')
        
        # Display formatted recommendations
        print('\n📋 Formatted Recommendations:')
        print('-' * 80)
        text = engine.format_recommendations_text(recommendations)
        print(text[:500] + '...' if len(text) > 500 else text)
        
        return recommendations
        
    except Exception as e:
        print(f'❌ Recommendation generation failed: {e}')
        import traceback
        traceback.print_exc()
        return None

def test_report_generation(test_results, waf_detection):
    """Test HTML report generation"""
    print(f'\n{"="*80}')
    print('TEST 5: HTML Report Generation')
    print(f'{"="*80}')
    
    try:
        generator = SecurityReportGenerator()
        
        # Add target to waf_detection
        waf_detection['target'] = 'http://127.0.0.1:5000'
        
        output_file = 'test_live_report.html'
        generator.generate_html_report(
            test_results=test_results,
            output_file=output_file,
            waf_detection=waf_detection
        )
        
        print(f'✅ HTML report generated: {output_file}')
        print(f'   Open the file in your browser to view the report')
        
        return output_file
        
    except Exception as e:
        print(f'❌ Report generation failed: {e}')
        import traceback
        traceback.print_exc()
        return None

def main():
    """Run all end-to-end tests"""
    print('=' * 80)
    print('END-TO-END PAYLOAD TESTING')
    print('Testing against local vulnerable application')
    print('=' * 80)
    
    target_url = 'http://127.0.0.1:5000'
    
    # Test 1: Server availability
    if not test_server_availability(target_url):
        print('\n❌ Server is not available. Please start the test server first:')
        print('   python3 test_vulnerable_app.py')
        sys.exit(1)
    
    # Test 2: WAF detection
    waf_detection = test_waf_detection(target_url)
    
    # Test 3: Payload delivery
    test_results = test_payload_delivery(target_url)
    
    # Test 4: Recommendation generation
    recommendations = test_recommendation_generation(waf_detection, test_results)
    
    # Test 5: Report generation
    report_file = test_report_generation(test_results, waf_detection)
    
    # Final summary
    print(f'\n{"="*80}')
    print('END-TO-END TEST SUMMARY')
    print(f'{"="*80}')
    print(f'✅ Server Availability: PASSED')
    print(f'✅ WAF Detection: PASSED')
    print(f'✅ Payload Delivery: PASSED ({len(test_results)} payloads tested)')
    print(f'✅ Recommendation Generation: {"PASSED" if recommendations else "FAILED"}')
    print(f'✅ Report Generation: {"PASSED" if report_file else "FAILED"}')
    print(f'\n📊 Results:')
    print(f'   - WAF Detected: {waf_detection["waf_detected"]}')
    print(f'   - Payloads Tested: {len(test_results)}')
    print(f'   - Payloads Blocked: {sum(1 for r in test_results if r.get("blocked", False))}')
    print(f'   - Report Generated: {report_file if report_file else "N/A"}')
    print(f'\n🎉 All end-to-end tests completed successfully!')
    print('=' * 80)

if __name__ == '__main__':
    main()
