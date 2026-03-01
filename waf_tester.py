#!/usr/bin/env python3
"""
WAF Tester - Easy-to-use CLI tool for WAF testing
Simple command-line interface for testing WAFs with comprehensive payload database
"""

import argparse
import json
import socket
import ssl
import re
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import sys

# Import WAF detector if available
try:
    from waf_detector import WAFDetector
    WAF_DETECTOR_AVAILABLE = True
except ImportError:
    WAF_DETECTOR_AVAILABLE = False

class Colors:
    """Terminal colors for better output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class WAFTester:
    """Main WAF testing class"""
    
    def __init__(self, target: str, timeout: int = 8, delay: float = 0.5):
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.results = []
        self.start_time = None
        
        # Parse target URL
        if not target.startswith('http'):
            target = f'https://{target}'
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.use_ssl = parsed.scheme == 'https'
        self.path = parsed.path or '/'
        self.query = parsed.query
    
    def test_payload(self, payload: str, method: str = 'GET', param: str = 'input') -> Dict:
        """Test a single payload"""
        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.host)
                conn = ssock
            else:
                conn = socket.create_connection((self.host, self.port), timeout=self.timeout)
            
            if method == 'GET':
                enc = urllib.parse.quote(payload, safe='')
                query_string = f"{self.query}&{param}={enc}" if self.query else f"{param}={enc}"
                req = f"GET {self.path}?{query_string} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n"
            else:
                enc = urllib.parse.quote(payload, safe='')
                body = f"{param}={enc}"
                req = f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
            
            conn.sendall(req.encode('utf-8', errors='replace'))
            
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
            
            resp_str = resp.decode('utf-8', errors='replace')
            status_match = re.search(r'HTTP/[\d.]+ (\d+)', resp_str)
            status = int(status_match.group(1)) if status_match else 0
            
            error_code = None
            if 'error code:' in resp_str.lower():
                error_match = re.search(r'error code:\s*(\d+)', resp_str, re.IGNORECASE)
                if error_match:
                    error_code = error_match.group(1)
            
            blocked = status in (403, 406, 503)
            
            return {
                'payload': payload,
                'status': status,
                'error_code': error_code,
                'blocked': blocked,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'status': 0,
                'error': str(e),
                'blocked': True,
                'timestamp': datetime.now().isoformat()
            }
    
    def load_payloads(self, filepath: str) -> List[Dict]:
        """Load payloads from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if 'payloads' in data:
            return data['payloads']
        return data if isinstance(data, list) else []
    
    def test_payloads(self, payloads: List[Dict], method: str = 'GET', param: str = 'input', 
                     max_payloads: Optional[int] = None) -> List[Dict]:
        """Test multiple payloads"""
        results = []
        total = min(len(payloads), max_payloads) if max_payloads else len(payloads)
        
        self.start_time = datetime.now()
        print(f"\n{Colors.HEADER}Testing {total} payloads against {self.target}{Colors.END}\n")
        
        for idx, payload_data in enumerate(payloads[:total], 1):
            payload = payload_data.get('payload', payload_data) if isinstance(payload_data, dict) else payload_data
            desc = payload_data.get('description', '') if isinstance(payload_data, dict) else ''
            category = payload_data.get('category', 'unknown') if isinstance(payload_data, dict) else 'unknown'
            
            result = self.test_payload(payload, method, param)
            result['category'] = category
            result['description'] = desc
            results.append(result)
            
            # Print result
            status_color = Colors.RED if result['blocked'] else Colors.GREEN
            status_text = "BLOCKED" if result['blocked'] else "PASSED"
            
            print(f"[{idx}/{total}] {status_color}{status_text:8}{Colors.END} | "
                  f"Status: {result['status']} | "
                  f"{desc[:40] if desc else payload[:40]}")
            
            time.sleep(self.delay)
        
        return results
    
    def generate_report(self, results: List[Dict], output: str = 'report.json', html: bool = False):
        """Generate test report"""
        total = len(results)
        blocked = sum(1 for r in results if r.get('blocked'))
        passed = total - blocked
        
        # Calculate duration
        duration = "N/A"
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            duration = f"{minutes} minutes {seconds} seconds" if minutes > 0 else f"{seconds} seconds"
        
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'summary': {
                'total': total,
                'blocked': blocked,
                'passed': passed,
                'block_rate': f"{(blocked/total*100):.2f}%" if total > 0 else "0%"
            },
            'results': results
        }
        
        # Save JSON report
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report if requested
        if html:
            try:
                from report_generator import SecurityReportGenerator
                generator = SecurityReportGenerator()
                html_output = output.replace('.json', '.html')
                generator.generate_html_report(report, html_output)
                print(f"\n{Colors.GREEN}✅ HTML Report: {html_output}{Colors.END}")
            except Exception as e:
                print(f"\n{Colors.YELLOW}⚠️  HTML report generation failed: {e}{Colors.END}")
        
        # Print summary
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Test Summary{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"Target:      {self.target}")
        print(f"Duration:    {duration}")
        print(f"Total:       {total}")
        print(f"Blocked:     {Colors.RED}{blocked}{Colors.END}")
        print(f"Passed:      {Colors.GREEN}{passed}{Colors.END}")
        print(f"Block Rate:  {report['summary']['block_rate']}")
        print(f"\nReport saved to: {output}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")

def interactive_mode():
    """Interactive mode for easy testing"""
    print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}WAF Tester - Interactive Mode{Colors.END}")
    print(f"{Colors.HEADER}{'='*60}{Colors.END}\n")
    
    # Get target
    target = input(f"{Colors.BLUE}Enter target URL (e.g., https://example.com): {Colors.END}").strip()
    if not target:
        print(f"{Colors.RED}Error: Target URL required{Colors.END}")
        return
    
    # Get payload category
    print(f"\n{Colors.BLUE}Available payload categories:{Colors.END}")
    print("1. XSS - Basic")
    print("2. XSS - SVG-based")
    print("3. XSS - Encoded")
    print("4. XSS - All")
    print("5. SQL Injection")
    print("6. SSRF")
    print("7. Custom payload file")
    
    choice = input(f"\n{Colors.BLUE}Select category (1-7): {Colors.END}").strip()
    
    payload_map = {
        '1': 'payloads/xss/basic.json',
        '2': 'payloads/xss/svg_based.json',
        '3': 'payloads/xss/encoded.json',
        '4': 'payloads/xss/',
        '5': 'payloads/sqli/general.json',
        '6': 'payloads/ssrf/general.json',
    }
    
    if choice == '7':
        payload_file = input(f"{Colors.BLUE}Enter payload file path: {Colors.END}").strip()
    elif choice in payload_map:
        payload_file = payload_map[choice]
    else:
        print(f"{Colors.RED}Invalid choice{Colors.END}")
        return
    
    # Get method
    method = input(f"\n{Colors.BLUE}HTTP method (GET/POST) [GET]: {Colors.END}").strip().upper() or 'GET'
    
    # Get max payloads
    max_input = input(f"{Colors.BLUE}Max payloads to test (blank for all): {Colors.END}").strip()
    max_payloads = int(max_input) if max_input else None
    
    # Run test
    tester = WAFTester(target)
    
    if Path(payload_file).is_dir():
        # Load all files in directory
        all_payloads = []
        for file in Path(payload_file).glob('*.json'):
            all_payloads.extend(tester.load_payloads(str(file)))
        payloads = all_payloads
    else:
        payloads = tester.load_payloads(payload_file)
    
    results = tester.test_payloads(payloads, method=method, max_payloads=max_payloads)
    tester.generate_report(results)

def main():
    parser = argparse.ArgumentParser(
        description='WAF Tester - Test Web Application Firewalls with comprehensive payload database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python waf_tester.py -i
  
  # Test single domain
  python waf_tester.py -t https://example.com -p payloads/xss/basic.json
  
  # Test specific endpoint/path
  python waf_tester.py -t https://example.com/api/search -p payloads/sqli/general.json
  
  # Test with POST method
  python waf_tester.py -t https://example.com/login -p payloads/sqli/general.json -m POST
  
  # Test multiple domains from file
  python waf_tester.py --targets-file targets.txt -p payloads/xss/ --html-report
  
  # Test with custom parameters
  python waf_tester.py -t https://api.example.com/v1/users -p payloads/ --param query --max 50
  
  # Generate HTML report
  python waf_tester.py -t https://example.com -p payloads/xss/basic.json --html-report
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL to test (supports full URLs with paths/endpoints)')
    parser.add_argument('--targets-file', help='File containing list of target URLs (one per line)')
    parser.add_argument('-p', '--payloads', help='Path to payload JSON file or directory')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--param', default='input', help='Parameter name (default: input)')
    parser.add_argument('--max', type=int, help='Maximum number of payloads to test')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (seconds)')
    parser.add_argument('-o', '--output', default='report.json', help='Output report file')
    parser.add_argument('--html-report', action='store_true', help='Generate HTML report with Dali Security branding')
    parser.add_argument('--detect-waf', action='store_true', help='Detect WAF vendor before testing')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
        return
    
    # Get list of targets
    targets = []
    if args.targets_file:
        # Load targets from file
        try:
            with open(args.targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            print(f"\n{Colors.BLUE}Loaded {len(targets)} targets from {args.targets_file}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Error loading targets file: {e}{Colors.END}\n")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        print(f"\n{Colors.YELLOW}Tip: Use -i for interactive mode{Colors.END}\n")
        sys.exit(1)
    
    if not args.payloads:
        parser.print_help()
        print(f"\n{Colors.RED}Error: --payloads is required{Colors.END}\n")
        sys.exit(1)
    
    # Test each target
    all_results = []
    for idx, target in enumerate(targets, 1):
        print(f"\n{Colors.HEADER}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}Testing Target {idx}/{len(targets)}: {target}{Colors.END}")
        print(f"{Colors.HEADER}{'='*60}{Colors.END}")
        
        # Detect WAF if requested
        waf_info = None
        if args.detect_waf and WAF_DETECTOR_AVAILABLE:
            print(f"\n{Colors.BLUE}🔍 Detecting WAF...{Colors.END}")
            detector = WAFDetector()
            waf_info = detector.detect_waf(target, timeout=args.timeout)
            
            if waf_info['waf_detected']:
                print(f"{Colors.GREEN}✓ WAF Detected: {waf_info['waf_vendor']} ({waf_info['confidence']}% confidence){Colors.END}")
            else:
                print(f"{Colors.YELLOW}✗ No WAF detected or unknown WAF{Colors.END}")
        elif args.detect_waf and not WAF_DETECTOR_AVAILABLE:
            print(f"{Colors.YELLOW}⚠️  WAF detection not available (waf_detector.py not found){Colors.END}")
        
        # Run test
        tester = WAFTester(target, timeout=args.timeout, delay=args.delay)
        
        # Load payloads
        payload_path = Path(args.payloads)
        if payload_path.is_dir():
            all_payloads = []
            for file in payload_path.glob('*.json'):
                all_payloads.extend(tester.load_payloads(str(file)))
            payloads = all_payloads
        else:
            payloads = tester.load_payloads(args.payloads)
        
        # Test payloads
        results = tester.test_payloads(payloads, method=args.method, param=args.param, max_payloads=args.max)
        
        # Generate report for this target
        if len(targets) > 1:
            # Multiple targets - create separate reports
            output_name = args.output.replace('.json', f'_{idx}.json')
            tester.generate_report(results, output=output_name, html=args.html_report)
            all_results.append({'target': target, 'results': results})
        else:
            # Single target - use specified output name
            tester.generate_report(results, output=args.output, html=args.html_report)
    
    # Generate combined report for multiple targets
    if len(targets) > 1:
        combined_output = args.output.replace('.json', '_combined.json')
        combined_report = {
            'targets': targets,
            'timestamp': datetime.now().isoformat(),
            'total_targets': len(targets),
            'results_by_target': all_results
        }
        with open(combined_output, 'w', encoding='utf-8') as f:
            json.dump(combined_report, f, indent=2, ensure_ascii=False)
        print(f"\n{Colors.GREEN}✅ Combined report saved to: {combined_output}{Colors.END}")

if __name__ == '__main__':
    main()
