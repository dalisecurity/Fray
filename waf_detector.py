#!/usr/bin/env python3
"""
WAF Detector - Identify Web Application Firewall vendors
Detects major WAF vendors including Cloudflare, Akamai, AWS, Imperva, and more
"""

import socket
import ssl
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class Colors:
    """Terminal colors for better output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class WAFDetector:
    """Detect WAF vendor based on response headers, cookies, and behavior"""
    
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
                'cookies': ['__cfduid', '__cflb'],
                'response_codes': [403, 503],
                'response_text': ['cloudflare', 'attention required', 'ray id'],
                'server': ['cloudflare']
            },
            'Akamai': {
                'headers': ['akamai-origin-hop', 'akamai-grn', 'x-akamai-session-id', 'akamai-x-cache', 'x-akamai-transformed', 'akamai-cache-status'],
                'cookies': ['ak_bmsc', 'bm_sv', 'bm_sz', 'akacd_'],
                'response_codes': [403],
                'response_text': ['akamai', 'reference #', 'akamai technologies'],
                'server': ['akamaighost', 'akamaighost', 'akamai']
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-trace-id', 'x-amz-apigw-id', 'x-amz-id', 'x-amz-request-id'],
                'cookies': ['awsalb', 'awsalbcors', 'awsalbapp', 'awsalbtg'],
                'response_codes': [403],
                'response_text': ['aws', 'forbidden', 'access denied'],
                'server': ['awselb', 'awselb/2.0', 'amazon']
            },
            'Imperva (Incapsula)': {
                'headers': ['x-cdn', 'x-iinfo', 'x-true-client-ip'],
                'cookies': ['incap_ses', 'visid_incap', 'nlbi', 'incap'],
                'response_codes': [403],
                'response_text': ['incapsula', 'imperva', 'incident id', 'incap'],
                'server': ['imperva', 'incapsula']
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info', 'x-cnection'],
                'cookies': ['bigipserver', 'f5_cspm', 'ts', 'bigip'],
                'response_codes': [403],
                'response_text': ['the requested url was rejected', 'f5'],
                'server': ['big-ip', 'bigip']
            },
            'Fastly': {
                'headers': ['fastly-io-info', 'x-fastly-request-id', 'fastly-restarts', 'x-served-by', 'x-cache', 'x-timer'],
                'cookies': ['fastly_'],
                'response_codes': [403],
                'response_text': ['fastly', 'varnish'],
                'server': ['fastly', 'varnish']
            },
            'Barracuda': {
                'headers': ['x-barracuda-url', 'x-barracuda-virus'],
                'cookies': ['barra_counter_session', 'barracuda'],
                'response_codes': [403],
                'response_text': ['barracuda', 'you have been blocked'],
                'server': ['barracuda']
            },
            'Citrix NetScaler': {
                'headers': ['ns-cache', 'citrix-transactionid', 'x-citrix-via'],
                'cookies': ['nsvs', 'citrix_ns_id', 'nsc_'],
                'response_codes': [403],
                'response_text': ['netscaler', 'citrix'],
                'server': ['netscaler']
            },
            'Radware': {
                'headers': ['x-protected-by'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['radware', 'appwall'],
                'server': []
            },
            'Microsoft Azure WAF': {
                'headers': ['x-azure-ref', 'x-msedge-ref', 'x-azure-requestid', 'x-ms-', 'x-azure-', 'x-msedge-', 'azure-'],
                'cookies': ['arr_affinity', 'arraffinity', 'arraffinitysamessite', 'ai_session', 'ai_user'],
                'response_codes': [403],
                'response_text': ['azure', 'microsoft', 'access denied', 'azure front door'],
                'server': ['microsoft-iis', 'azure', 'kestrel', 'microsoft-httpapi']
            },
            'Google Cloud Armor': {
                'headers': ['x-goog-', 'x-cloud-trace-context', 'x-gfe-'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['google', 'cloud armor', 'gcp'],
                'server': ['gws', 'gfe']
            },
            'Qualys WAF': {
                'headers': ['x-qualys'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['qualys'],
                'server': []
            },
            'Penta Security (WAPPLES)': {
                'headers': ['x-wapples'],
                'cookies': ['wapples'],
                'response_codes': [403],
                'response_text': ['wapples', 'penta security'],
                'server': []
            },
            'Signal Sciences (Fastly)': {
                'headers': ['x-sigsci-requestid', 'x-sigsci-tags', 'x-sigsci-agentresponse'],
                'cookies': [],
                'response_codes': [406, 403],
                'response_text': ['signal sciences', 'sigsci', 'request blocked'],
                'server': []
            },
            'StackPath': {
                'headers': ['x-sp-url', 'x-stackpath-shield'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['stackpath'],
                'server': ['stackpath']
            },
            'Sophos': {
                'headers': ['x-sophos'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['sophos', 'utm'],
                'server': []
            },
            'Palo Alto (Prisma Cloud)': {
                'headers': ['x-pan-', 'x-prisma'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['palo alto', 'prisma'],
                'server': []
            },
            'Check Point': {
                'headers': ['x-checkpoint'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['check point', 'checkpoint'],
                'server': []
            },
            'Trustwave (ModSecurity)': {
                'headers': ['x-mod-security', 'x-trustwave'],
                'cookies': [],
                'response_codes': [403, 406],
                'response_text': ['mod_security', 'modsecurity', 'trustwave'],
                'server': ['mod_security']
            },
            'Scutum': {
                'headers': ['x-scutum'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['scutum'],
                'server': []
            },
            'Rohde & Schwarz': {
                'headers': ['x-rs-'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['rohde', 'schwarz'],
                'server': []
            }
        }
    
    def detect_waf(self, target: str, timeout: int = 8) -> Dict:
        """Detect WAF vendor for a target"""
        
        # Parse target URL
        if not target.startswith('http'):
            target = f'https://{target}'
        
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'waf_detected': False,
            'waf_vendor': None,
            'confidence': 0,
            'signatures_found': [],
            'headers': {},
            'cookies': [],
            'server': None,
            'status_code': None,
            'response_snippet': None
        }
        
        try:
            # Create connection
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=timeout)
                conn = ctx.wrap_socket(sock, server_hostname=host)
            else:
                conn = socket.create_connection((host, port), timeout=timeout)
            
            # Send request with suspicious payload to trigger WAF
            test_payload = "' OR '1'='1' --"
            enc = urllib.parse.quote(test_payload, safe='')
            req = f"GET {path}?test={enc} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            
            conn.sendall(req.encode('utf-8', errors='replace'))
            
            # Read response
            resp = b""
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    resp += data
                    if len(resp) > 100000:
                        break
                except:
                    break
            
            conn.close()
            
            # Parse response
            resp_str = resp.decode('utf-8', errors='replace')
            
            # Extract status code
            status_match = re.search(r'HTTP/[\d.]+ (\d+)', resp_str)
            if status_match:
                results['status_code'] = int(status_match.group(1))
            
            # Extract headers
            header_section = resp_str.split('\r\n\r\n')[0] if '\r\n\r\n' in resp_str else resp_str
            for line in header_section.split('\r\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    results['headers'][key.strip().lower()] = value.strip()
            
            # Extract server header
            results['server'] = results['headers'].get('server', None)
            
            # Extract cookies
            for key, value in results['headers'].items():
                if key == 'set-cookie':
                    cookie_name = value.split('=')[0].strip()
                    results['cookies'].append(cookie_name)
            
            # Get response body snippet
            if '\r\n\r\n' in resp_str:
                body = resp_str.split('\r\n\r\n', 1)[1][:500]
                results['response_snippet'] = body
            
            # Detect WAF
            detection_results = self._analyze_signatures(results)
            results.update(detection_results)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _analyze_signatures(self, results: Dict) -> Dict:
        """Analyze response for WAF signatures"""
        
        detected_wafs = []
        
        for waf_name, signatures in self.waf_signatures.items():
            confidence = 0
            found_signatures = []
            signature_count = 0
            
            # Check headers (higher weight for unique headers)
            for header in signatures['headers']:
                for resp_header in results['headers'].keys():
                    if header.lower() in resp_header.lower():
                        # Give more weight to vendor-specific headers
                        if header.startswith(('cf-', 'x-amz', 'x-azure', 'akamai', 'x-iinfo')):
                            confidence += 35  # Unique vendor headers
                        else:
                            confidence += 25  # Generic headers
                        found_signatures.append(f"Header: {resp_header}")
                        signature_count += 1
            
            # Check cookies (high confidence for vendor-specific cookies)
            for cookie in signatures['cookies']:
                for resp_cookie in results['cookies']:
                    if cookie.lower() in resp_cookie.lower():
                        # Vendor-specific cookies are strong indicators
                        if cookie.startswith(('__cfd', 'incap', 'ak_', 'awsalb', 'bigip')):
                            confidence += 30  # Unique vendor cookies
                        else:
                            confidence += 20  # Generic cookies
                        found_signatures.append(f"Cookie: {resp_cookie}")
                        signature_count += 1
            
            # Check server header (very strong indicator)
            if results['server']:
                for server_sig in signatures['server']:
                    if server_sig.lower() in results['server'].lower():
                        # Server header is a strong indicator
                        confidence += 35
                        found_signatures.append(f"Server: {results['server']}")
                        signature_count += 1
            
            # Check response text (moderate confidence)
            if results['response_snippet']:
                for text_sig in signatures['response_text']:
                    if text_sig.lower() in results['response_snippet'].lower():
                        # Vendor-specific error messages
                        if text_sig in ['cloudflare', 'incapsula', 'imperva', 'akamai']:
                            confidence += 20  # Unique vendor text
                        else:
                            confidence += 10  # Generic error text
                        found_signatures.append(f"Response text: {text_sig}")
                        signature_count += 1
            
            # Check status code (low weight, many WAFs use same codes)
            if results['status_code'] in signatures['response_codes']:
                confidence += 5  # Reduced from 10
            
            # Bonus for multiple signature types (indicates stronger match)
            if signature_count >= 3:
                confidence += 15
            elif signature_count >= 2:
                confidence += 10
            
            if confidence > 0:
                detected_wafs.append({
                    'vendor': waf_name,
                    'confidence': min(confidence, 100),
                    'signatures': found_signatures,
                    'signature_count': signature_count
                })
        
        # Sort by confidence, then by signature count
        detected_wafs.sort(key=lambda x: (x['confidence'], x['signature_count']), reverse=True)
        
        if detected_wafs:
            top_match = detected_wafs[0]
            return {
                'waf_detected': True,
                'waf_vendor': top_match['vendor'],
                'confidence': top_match['confidence'],
                'signatures_found': top_match['signatures'],
                'all_detections': detected_wafs
            }
        else:
            return {
                'waf_detected': False,
                'waf_vendor': 'Unknown or No WAF',
                'confidence': 0,
                'signatures_found': [],
                'all_detections': []
            }
    
    def print_results(self, results: Dict):
        """Print detection results in a formatted way"""
        
        print(f"\n{Colors.HEADER}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}WAF Detection Results{Colors.END}")
        print(f"{Colors.HEADER}{'='*70}{Colors.END}")
        
        print(f"\n{Colors.BLUE}Target:{Colors.END} {results['target']}")
        print(f"{Colors.BLUE}Status Code:{Colors.END} {results.get('status_code', 'N/A')}")
        
        if results.get('server'):
            print(f"{Colors.BLUE}Server:{Colors.END} {results['server']}")
        
        print(f"\n{Colors.HEADER}WAF Detection:{Colors.END}")
        
        if results['waf_detected']:
            color = Colors.GREEN if results['confidence'] >= 70 else Colors.YELLOW
            print(f"{color}✓ WAF Detected: {results['waf_vendor']}{Colors.END}")
            print(f"{Colors.BLUE}Confidence:{Colors.END} {results['confidence']}%")
            
            if results['signatures_found']:
                print(f"\n{Colors.BLUE}Signatures Found:{Colors.END}")
                for sig in results['signatures_found']:
                    print(f"  • {sig}")
            
            # Show other possible matches
            if len(results.get('all_detections', [])) > 1:
                print(f"\n{Colors.BLUE}Other Possible Matches:{Colors.END}")
                for detection in results['all_detections'][1:4]:  # Show top 3 alternatives
                    print(f"  • {detection['vendor']} ({detection['confidence']}%)")
        else:
            print(f"{Colors.YELLOW}✗ No WAF Detected{Colors.END}")
            print(f"  The target may not be using a WAF, or it's using a custom/unknown WAF")
        
        print(f"\n{Colors.HEADER}{'='*70}{Colors.END}\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='WAF Detector - Identify Web Application Firewall vendors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported WAF Vendors:
  • Cloudflare
  • Akamai
  • AWS WAF
  • Imperva (Incapsula)
  • F5 BIG-IP
  • Fastly
  • Barracuda Networks
  • Citrix NetScaler
  • Radware
  • Microsoft Azure WAF
  • Google Cloud Armor
  • Qualys WAF
  • Penta Security (WAPPLES)
  • Signal Sciences (Fastly)
  • StackPath
  • Sophos
  • Palo Alto Networks (Prisma Cloud)
  • Check Point
  • Trustwave (ModSecurity)
  • Scutum
  • Rohde & Schwarz

Examples:
  # Detect WAF for a domain
  python3 waf_detector.py -t https://example.com
  
  # Detect WAF for multiple targets
  python3 waf_detector.py -t https://example.com -t https://api.example.com
  
  # Detect WAF from targets file
  python3 waf_detector.py --targets-file targets.txt
        """
    )
    
    parser.add_argument('-t', '--target', action='append', help='Target URL to check (can be used multiple times)')
    parser.add_argument('--targets-file', help='File containing list of target URLs (one per line)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (seconds)')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    
    args = parser.parse_args()
    
    # Get list of targets
    targets = []
    if args.targets_file:
        try:
            with open(args.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            print(f"{Colors.RED}Error loading targets file: {e}{Colors.END}")
            return
    elif args.target:
        targets = args.target
    else:
        parser.print_help()
        return
    
    # Detect WAF for each target
    detector = WAFDetector()
    all_results = []
    
    for target in targets:
        print(f"\n{Colors.BLUE}Checking: {target}{Colors.END}")
        results = detector.detect_waf(target, timeout=args.timeout)
        detector.print_results(results)
        all_results.append(results)
    
    # Save results if output file specified
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"{Colors.GREEN}✓ Results saved to: {args.output}{Colors.END}\n")


if __name__ == '__main__':
    main()
