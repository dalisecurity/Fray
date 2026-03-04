#!/usr/bin/env python3
"""
WAF Tester - Easy-to-use CLI tool for WAF testing
Simple command-line interface for testing WAFs with comprehensive payload database
"""

import argparse
import ipaddress
import json
import random
import socket
import ssl
import re
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import sys


# Realistic User-Agent pool for stealth mode
_STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
]

# Accept-Language variants for stealth
_STEALTH_ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.8",
    "en,*;q=0.5",
]


def _is_private_host(hostname: str) -> bool:
    """Check if a hostname resolves to a private/internal IP address."""
    if not hostname:
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (socket.gaierror, ValueError):
        return False

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
    
    def __init__(self, target: str, timeout: int = 8, delay: float = 0.5,
                 custom_headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True, verbose: bool = False,
                 max_redirects: int = 5, jitter: float = 0.0,
                 stealth: bool = False, rate_limit: float = 0.0):
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.jitter = jitter
        self.stealth = stealth
        self.rate_limit = rate_limit
        self.results = []
        self.start_time = None
        self.custom_headers = custom_headers or {}
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.max_redirects = max_redirects
        self._last_request_time = 0.0

        # Stealth mode defaults: if --stealth is on, apply sane defaults
        if self.stealth:
            if self.delay < 1.0:
                self.delay = 1.5
            if self.jitter == 0.0:
                self.jitter = 1.0
            if self.rate_limit == 0.0:
                self.rate_limit = 2.0  # max 2 req/s
        
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
    
    def _stealth_delay(self):
        """Apply delay + jitter + rate limit between requests."""
        # Rate limit: enforce minimum interval between requests
        if self.rate_limit > 0:
            min_interval = 1.0 / self.rate_limit
            elapsed = time.time() - self._last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

        # Base delay + random jitter
        wait = self.delay
        if self.jitter > 0:
            wait += random.uniform(0, self.jitter)
        if wait > 0:
            time.sleep(wait)

        self._last_request_time = time.time()

    def _get_stealth_headers(self) -> str:
        """Return randomized User-Agent and Accept-Language for stealth mode."""
        if not self.stealth:
            return ""
        ua = random.choice(_STEALTH_USER_AGENTS)
        lang = random.choice(_STEALTH_ACCEPT_LANGS)
        lines = f"User-Agent: {ua}\r\nAccept-Language: {lang}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        return lines

    def _build_extra_headers(self) -> str:
        """Build extra header lines from custom_headers dict."""
        lines = ""
        for k, v in self.custom_headers.items():
            # Sanitize CRLF to prevent header injection
            k = k.replace('\r', '').replace('\n', '')
            v = v.replace('\r', '').replace('\n', '')
            lines += f"{k}: {v}\r\n"
        return lines

    def _resolve_and_check(self, host: str) -> str:
        """Resolve hostname once and return the IP. Raises ValueError for private IPs."""
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(f"Resolved to private/internal IP: {ip_str}")
        return ip_str

    def _raw_request(self, host: str, port: int, use_ssl: bool,
                     request: str) -> tuple:
        """Send a raw HTTP request and return (status, response_str, headers_dict)."""
        # DNS rebinding protection: resolve once, pin IP, verify it's not private
        try:
            resolved_ip = self._resolve_and_check(host)
        except (socket.gaierror, ValueError) as e:
            if isinstance(e, ValueError):
                raise  # Propagate private-IP block
            resolved_ip = host  # Fallback for raw IPs or unresolvable hosts

        if use_ssl:
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((resolved_ip, port), timeout=self.timeout)
            conn = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = socket.create_connection((resolved_ip, port), timeout=self.timeout)

        if self.verbose:
            print(f"\n{Colors.HEADER}>>> RAW REQUEST >>>{Colors.END}")
            print(request[:500])
            print(f"{Colors.HEADER}>>> END REQUEST >>>{Colors.END}")

        conn.sendall(request.encode('utf-8', errors='replace'))

        resp = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                resp += data
                if len(resp) > 100000:
                    break
            except (socket.error, socket.timeout, OSError):
                break
        conn.close()

        resp_str = resp.decode('utf-8', errors='replace')
        status_match = re.search(r'HTTP/[\d.]+ (\d+)', resp_str)
        status = int(status_match.group(1)) if status_match else 0

        # Parse Location header for redirects
        headers = {}
        header_section = resp_str.split('\r\n\r\n', 1)[0] if '\r\n\r\n' in resp_str else resp_str
        for line in header_section.split('\r\n')[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        if self.verbose:
            print(f"\n{Colors.HEADER}<<< RAW RESPONSE (status={status}, {len(resp_str)} bytes) <<<{Colors.END}")
            print(resp_str[:800])
            print(f"{Colors.HEADER}<<< END RESPONSE <<<{Colors.END}")

        return status, resp_str, headers

    def test_payload(self, payload: str, method: str = 'GET', param: str = 'input') -> Dict:
        """Test a single payload, following redirects up to max_redirects hops."""
        max_redirects = self.max_redirects
        current_host = self.host
        current_port = self.port
        current_ssl = self.use_ssl
        current_path = self.path
        current_query = self.query
        extra_hdrs = self._build_extra_headers()

        for hop in range(max_redirects + 1):
            try:
                enc = urllib.parse.quote(payload, safe='')

                stealth_hdrs = self._get_stealth_headers()

                if method == 'GET' or hop > 0:
                    query_string = f"{current_query}&{param}={enc}" if current_query else f"{param}={enc}"
                    req = (f"GET {current_path}?{query_string} HTTP/1.1\r\n"
                           f"Host: {current_host}\r\n"
                           f"{stealth_hdrs}"
                           f"{extra_hdrs}"
                           f"Connection: close\r\n\r\n")
                else:
                    body = f"{param}={enc}"
                    req = (f"POST {current_path} HTTP/1.1\r\n"
                           f"Host: {current_host}\r\n"
                           f"Content-Type: application/x-www-form-urlencoded\r\n"
                           f"Content-Length: {len(body)}\r\n"
                           f"{stealth_hdrs}"
                           f"{extra_hdrs}"
                           f"Connection: close\r\n\r\n{body}")

                status, resp_str, headers = self._raw_request(
                    current_host, current_port, current_ssl, req)

                # Follow redirects
                if status in (301, 302, 303, 307, 308) and 'location' in headers:
                    location = headers['location']
                    if location.startswith('/'):
                        current_path = location.split('?')[0]
                        current_query = location.split('?')[1] if '?' in location else ''
                    elif location.startswith('http'):
                        parsed = urllib.parse.urlparse(location)
                        redirect_host = parsed.hostname or current_host
                        # Block redirects to private/internal IPs (SSRF prevention)
                        if _is_private_host(redirect_host):
                            return {
                                'payload': payload,
                                'status': status,
                                'error': f'Redirect to private/internal host blocked: {redirect_host}',
                                'blocked': True,
                                'redirects': hop,
                                'timestamp': datetime.now().isoformat()
                            }
                        current_host = redirect_host
                        current_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                        current_ssl = parsed.scheme == 'https'
                        current_path = parsed.path or '/'
                        current_query = parsed.query or ''
                    continue  # Follow the redirect

                # Handle 429 rate-limiting with Retry-After
                if status == 429 and hop == 0:
                    retry_after = headers.get('retry-after', '')
                    try:
                        wait = min(int(retry_after), 30) if retry_after.isdigit() else 5
                    except (ValueError, AttributeError):
                        wait = 5
                    if self.verbose:
                        print(f"{Colors.YELLOW}429 rate-limited, retrying after {wait}s{Colors.END}")
                    time.sleep(wait)
                    continue  # Retry this hop

                # Final response — determine if blocked
                error_code = None
                if 'error code:' in resp_str.lower():
                    error_match = re.search(r'error code:\s*(\d+)', resp_str, re.IGNORECASE)
                    if error_match:
                        error_code = error_match.group(1)

                blocked = status in (403, 406, 429, 503)

                # Extract response body for reflection analysis
                resp_body = ''
                if '\r\n\r\n' in resp_str:
                    resp_body = resp_str.split('\r\n\r\n', 1)[1]

                # Check if payload is reflected in response
                reflected = False
                reflection_context = ''
                if not blocked and resp_body:
                    # Check for raw payload reflection
                    if payload in resp_body:
                        reflected = True
                        idx = resp_body.index(payload)
                        start = max(0, idx - 40)
                        end = min(len(resp_body), idx + len(payload) + 40)
                        reflection_context = resp_body[start:end]
                    # Check for URL-decoded reflection
                    elif urllib.parse.unquote(payload) in resp_body:
                        reflected = True
                        decoded = urllib.parse.unquote(payload)
                        idx = resp_body.index(decoded)
                        start = max(0, idx - 40)
                        end = min(len(resp_body), idx + len(decoded) + 40)
                        reflection_context = resp_body[start:end]

                # Collect security headers
                sec_headers = {}
                for hdr_name in ('content-security-policy', 'x-xss-protection',
                                 'x-content-type-options', 'x-frame-options',
                                 'strict-transport-security', 'content-type',
                                 'server'):
                    if hdr_name in headers:
                        sec_headers[hdr_name] = headers[hdr_name]

                return {
                    'payload': payload,
                    'status': status,
                    'error_code': error_code,
                    'blocked': blocked,
                    'redirects': hop,
                    'final_url': f"{'https' if current_ssl else 'http'}://{current_host}{current_path}",
                    'reflected': reflected,
                    'reflection_context': reflection_context[:200],
                    'response_length': len(resp_body),
                    'security_headers': sec_headers,
                    'timestamp': datetime.now().isoformat()
                }

            except Exception as e:
                return {
                    'payload': payload,
                    'status': 0,
                    'error': str(e),
                    'blocked': True,
                    'redirects': hop,
                    'timestamp': datetime.now().isoformat()
                }

        # Ran out of redirect hops
        return {
            'payload': payload,
            'status': 0,
            'error': f'Too many redirects ({max_redirects})',
            'blocked': True,
            'redirects': max_redirects,
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
            
            self._stealth_delay()
        
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
