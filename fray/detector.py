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
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id', 'cf-cache-status', 'cf-request-id'],
                'cookies': ['__cfduid', '__cflb', 'cf_clearance'],
                'response_codes': [403, 503, 520, 521, 522, 523, 524, 525, 526, 527],
                'response_text': ['cloudflare', 'attention required', 'ray id', 'checking your browser', 'just a moment', 'cf-error-details', 'cf-wrapper'],
                'server': ['cloudflare'],
                'error_patterns': [r'Ray ID: [a-f0-9]+', r'Cloudflare Ray ID'],
                'challenge_patterns': ['cf-challenge', 'cf-captcha-container']
            },
            'Akamai': {
                'headers': ['akamai-origin-hop', 'akamai-grn', 'x-akamai-session-id', 'akamai-x-cache', 'x-akamai-transformed', 'akamai-cache-status'],
                'cookies': ['ak_bmsc', 'bm_sv', 'bm_sz', 'akacd_', 'bm_mi'],
                'response_codes': [403, 503],
                'response_text': ['akamai', 'reference #', 'akamai technologies'],
                'server': ['akamaighost', 'akamai'],
                'error_patterns': [r'Reference #[\d\.]+', r'Akamai Error'],
                'bot_manager': True
            },
            'AWS WAF': {
                'headers': ['x-amzn-waf-action', 'x-amzn-waf-', 'x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-trace-id', 'x-amz-apigw-id'],
                'cookies': ['awsalb', 'awsalbcors', 'awsalbapp', 'awsalbtg', 'awsalbtgcors'],
                'response_codes': [403, 429],
                'response_text': ['aws waf', 'request blocked by aws', 'x-amzn-waf', 'security policy', 'blocked by waf', 'aws', 'forbidden', 'access denied'],
                'server': ['awselb', 'awselb/2.0', 'amazon', 'cloudfront'],
                'error_patterns': [r'Request ID: [a-zA-Z0-9\-]+', r'x-amzn-waf-', r'security policy', r'blocked by waf'],
                'waf_specific_headers': ['x-amzn-waf-action', 'x-amzn-waf-'],
                'header_prefix': 'x-amzn-waf-',
                'header_combinations': [
                    ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],
                    ['x-amzn-requestid', 'x-amz-cf-id']
                ],
                'response_body_patterns': ['request blocked by security policy', 'security violation', 'blocked by waf']
            },
            'Imperva (Incapsula)': {
                'headers': ['x-cdn', 'x-iinfo', 'x-true-client-ip'],
                'cookies': ['incap_ses', 'visid_incap', 'nlbi', 'incap'],
                'response_codes': [403],
                'response_text': ['incapsula', 'imperva', 'incident id', 'incap', 'support id'],
                'server': ['imperva', 'incapsula'],
                'error_patterns': [r'Incident ID: [a-zA-Z0-9]+', r'Support ID: [0-9]+'],
                'challenge_patterns': ['Verifying you are human']
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info', 'x-cnection'],
                'cookies': ['bigipserver', 'f5_cspm', 'ts', 'bigip'],
                'response_codes': [403],
                'response_text': ['the requested url was rejected', 'f5', 'please consult with your administrator'],
                'server': ['big-ip', 'bigip'],
                'error_patterns': [r'Support ID: [0-9]+', r'The requested URL was rejected']
            },
            'Fastly (Signal Sciences WAF)': {
                'headers': ['fastly-io-info', 'x-fastly-request-id', 'fastly-restarts', 'x-served-by', 'x-cache', 'x-timer', 'x-sigsci-requestid', 'x-sigsci-tags'],
                'cookies': ['fastly_'],
                'response_codes': [403, 406],
                'response_text': ['fastly', 'varnish', 'signal sciences', 'sigsci'],
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
                'headers': ['x-azure-fdid', 'x-azure-ref', 'x-fd-healthprobe', 'x-azure-requestchain', 'x-azure-socketip', 'x-azure-clientip', 'x-azure-ja4-fingerprint', 'x-msedge-ref', 'x-azure-requestid'],
                'cookies': ['arr_affinity', 'arraffinity', 'arraffinitysamesite', 'ai_session', 'ai_user', 'x-azure-ref-originshield'],
                'response_codes': [403],
                'response_text': ['azure web application firewall', 'azure front door', 'x-azure-fdid', 'azure waf', 'request blocked by azure', 'access denied by waf', 'azure', 'microsoft'],
                'server': ['microsoft-iis', 'azure', 'kestrel', 'microsoft-httpapi'],
                'error_patterns': [r'X-Azure-Ref: [a-zA-Z0-9]+', r'X-Azure-FDID: [a-f0-9\-]+', r'blocked by azure', r'azure waf'],
                'front_door_headers': ['x-azure-fdid', 'x-fd-healthprobe', 'x-azure-requestchain'],
                'header_combinations': [
                    ['x-azure-fdid', 'x-azure-ref'],
                    ['x-azure-ref', 'x-fd-healthprobe']
                ],
                'response_body_patterns': ['azure web application firewall', 'request blocked by azure', 'access denied by waf'],
                'cache_patterns': ['TCP_DENIED', 'TCP_MISS']
            },
            'Google Cloud Armor': {
                'headers': ['x-goog-', 'x-cloud-trace-context', 'x-gfe-'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['google', 'cloud armor', 'gcp', 'your client does not have permission', 'google cloud platform'],
                'server': ['gws', 'gfe', 'Google Frontend'],
                'error_patterns': [r'cloud armor', r'does not have permission'],
                'gcp_headers': ['x-cloud-trace-context', 'x-goog-', 'x-gfe-'],
                'response_body_patterns': ['cloud armor', 'google cloud platform', 'your client does not have permission'],
                'recaptcha_indicators': ['recaptcha', 'g-recaptcha', 'google.com/recaptcha']
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
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'cookies': ['sucuri_cloudproxy_uuid'],
                'response_codes': [403],
                'response_text': ['sucuri', 'cloudproxy', 'access denied - sucuri website firewall'],
                'server': ['sucuri/cloudproxy'],
                'error_patterns': [r'Sucuri WebSite Firewall', r'CloudProxy']
            },
            'Fortinet FortiWeb': {
                'headers': ['x-fortiweb'],
                'cookies': ['fortiwafsid', 'cookiesession1'],
                'response_codes': [403, 406],
                'response_text': ['fortiweb', 'fortigate', 'fortinet', '.fwb'],
                'server': ['fortiweb'],
                'error_patterns': [r'FortiWeb', r'The page cannot be displayed']
            },
            'Wallarm': {
                'headers': ['x-wallarm-waf-check'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['wallarm', 'ngx_wallarm'],
                'server': ['nginx-wallarm'],
                'error_patterns': [r'wallarm', r'ngx_wallarm']
            },
            'Reblaze': {
                'headers': ['x-reblaze-protection'],
                'cookies': ['rbzid', 'rbzsessionid'],
                'response_codes': [403],
                'response_text': ['reblaze', 'access denied'],
                'server': ['reblaze'],
                'error_patterns': [r'Reblaze', r'rbzid']
            },
            'Vercel': {
                'headers': ['x-vercel-id', 'x-vercel-cache'],
                'cookies': [],
                'response_codes': [403],
                'response_text': ['vercel', 'vercel firewall'],
                'server': ['vercel'],
                'error_patterns': [r'Vercel', r'x-vercel-id']
            }
        }
    
    def detect_waf(self, target: str, timeout: int = 8, verify_ssl: bool = True,
                   impersonate: str = None) -> Dict:
        """Detect WAF vendor for a target.

        Args:
            impersonate: Browser to impersonate TLS fingerprint (e.g. "chrome").
                         When set, uses curl_cffi instead of raw sockets.
        """
        
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

        # ── Impersonated detection path (curl_cffi) ──
        if impersonate:
            try:
                from fray.impersonate import ImpersonatedSession, AVAILABLE
                if AVAILABLE:
                    return self._detect_waf_impersonated(
                        target, host, port, use_ssl, path, timeout,
                        verify_ssl, impersonate, results)
            except ImportError:
                pass
        
        try:
            # Create connection
            if use_ssl:
                ctx = ssl.create_default_context()
                if not verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=timeout)
                conn = ctx.wrap_socket(sock, server_hostname=host)

                # ── TLS cert org fingerprinting ──
                # Extract certificate issuer/subject org to identify CDN/WAF providers
                try:
                    cert = conn.getpeercert()
                    if cert:
                        _cert_subject = dict(x[0] for x in cert.get('subject', ()) if x)
                        _cert_issuer = dict(x[0] for x in cert.get('issuer', ()) if x)
                        _cert_org = _cert_subject.get('organizationName', '')
                        _cert_issuer_org = _cert_issuer.get('organizationName', '')
                        _cert_san = [v for t, v in cert.get('subjectAltName', ()) if t == 'DNS']
                        results['tls_cert'] = {
                            'subject_org': _cert_org,
                            'issuer_org': _cert_issuer_org,
                            'san_count': len(_cert_san),
                        }
                        # Known CDN/WAF cert org names → boost detection confidence
                        _TLS_CERT_HINTS = {
                            'cloudflare': 'cloudflare',
                            'amazon': 'aws_waf',
                            'akamai': 'akamai',
                            'imperva': 'imperva',
                            'incapsula': 'imperva',
                            'fastly': 'fastly',
                            'stackpath': 'stackpath',
                            'sucuri': 'sucuri',
                            'google trust': 'google_cloud_armor',
                        }
                        _combined_org = f"{_cert_org} {_cert_issuer_org}".lower()
                        for _hint_key, _hint_vendor in _TLS_CERT_HINTS.items():
                            if _hint_key in _combined_org:
                                results['tls_cert']['waf_hint'] = _hint_vendor
                                break
                except Exception:
                    pass
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
                except (socket.error, socket.timeout, OSError):
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

            # ── Vendor-specific canary probes ──
            # If passive detection found candidates with moderate confidence,
            # send vendor-specific payloads to confirm via block response fingerprint.
            _CANARY_PROBES = {
                'cloudflare': {
                    'payload': '?fray_canary=<script>cf_canary</script>',
                    'confirm': [r'cloudflare', r'cf-error', r'attention required', r'ray id'],
                },
                'aws_waf': {
                    'payload': "?fray_canary=' OR 1=1--",
                    'confirm': [r'x-amzn-requestid', r'aws-waf', r'request blocked'],
                },
                'akamai': {
                    'payload': '?fray_canary=../../etc/passwd',
                    'confirm': [r'reference\s*#[\d.]+', r'akamai'],
                },
                'imperva': {
                    'payload': '?fray_canary=|id',
                    'confirm': [r'incapsula', r'incident\s*id', r'imperva'],
                },
                'f5_bigip': {
                    'payload': '?fray_canary=<script>alert(1)</script>',
                    'confirm': [r'the requested url was rejected', r'support id'],
                },
            }
            _all_dets = results.get('all_detections', [])
            _canary_results = []
            # Only run canaries for vendors detected with confidence 20-80 (uncertain)
            _candidates = [d for d in _all_dets if 20 <= d.get('confidence', 0) <= 80]
            for _cand in _candidates[:3]:
                _v = _cand['vendor'].lower().replace(' ', '_')
                for _ck, _cv in _CANARY_PROBES.items():
                    if _ck in _v or _v in _ck:
                        try:
                            _csock = socket.create_connection((host, port), timeout=timeout)
                            if use_ssl:
                                _cctx = ssl.create_default_context()
                                if not verify_ssl:
                                    _cctx.check_hostname = False
                                    _cctx.verify_mode = ssl.CERT_NONE
                                _cconn = _cctx.wrap_socket(_csock, server_hostname=host)
                            else:
                                _cconn = _csock
                            _cpayload = urllib.parse.quote(_cv['payload'], safe='?=&/')
                            _creq = f"GET {path}{_cpayload} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                            _cconn.sendall(_creq.encode('utf-8', errors='replace'))
                            _cresp = b""
                            while True:
                                try:
                                    _cd = _cconn.recv(4096)
                                    if not _cd:
                                        break
                                    _cresp += _cd
                                    if b"\r\n\r\n" in _cresp and len(_cresp) > 512:
                                        break
                                    if len(_cresp) > 16000:
                                        break
                                except (socket.error, socket.timeout, OSError):
                                    break
                            _cconn.close()
                            _cresp_str = _cresp.decode('utf-8', errors='replace').lower()
                            _confirmed = any(re.search(p, _cresp_str, re.I) for p in _cv['confirm'])
                            if _confirmed:
                                _cand['confidence'] = min(_cand['confidence'] + 25, 100)
                                _cand['signatures'].append(f"Canary probe confirmed: {_ck}")
                                _cand['signature_count'] += 1
                                _canary_results.append({'vendor': _ck, 'confirmed': True})
                            else:
                                _canary_results.append({'vendor': _ck, 'confirmed': False})
                        except Exception:
                            pass
                        break
            if _canary_results:
                results['canary_probes'] = _canary_results
                # Re-sort and update top match after canary boosts
                _all_dets.sort(key=lambda x: (x['confidence'], x['signature_count']), reverse=True)
                if _all_dets:
                    _top = _all_dets[0]
                    results['waf_vendor'] = _top['vendor']
                    results['confidence'] = _top['confidence']
                    results['signatures_found'] = _top['signatures']

        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _detect_waf_impersonated(self, target, host, port, use_ssl, path,
                                  timeout, verify_ssl, browser, results):
        """WAF detection using curl_cffi browser impersonation.

        Uses real browser TLS fingerprint so WAFs that gate on JA3/JA4
        won't block us at the TLS layer.
        """
        from fray.impersonate import ImpersonatedSession

        with ImpersonatedSession(browser=browser, verify=verify_ssl, timeout=timeout) as sess:
            # Send suspicious payload to trigger WAF (same as raw path)
            test_payload = "' OR '1'='1' --"
            enc = urllib.parse.quote(test_payload, safe='')
            scheme = 'https' if use_ssl else 'http'
            port_s = '' if (use_ssl and port == 443) or (not use_ssl and port == 80) else f':{port}'
            url = f"{scheme}://{host}{port_s}{path}?test={enc}"

            try:
                r = sess.get(url)
                results['status_code'] = r.status_code
                results['response_snippet'] = r.text[:500] if r.text else None
                results['impersonated'] = sess.browser

                # Parse headers
                for k, v in r.headers.items():
                    results['headers'][k.lower()] = v
                results['server'] = results['headers'].get('server', None)

                # Extract cookies from set-cookie headers
                sc = r.headers.get('set-cookie', '')
                if sc:
                    for part in sc.split(','):
                        cookie_name = part.strip().split('=')[0].strip()
                        if cookie_name:
                            results['cookies'].append(cookie_name)

                # TLS cert info (curl_cffi doesn't expose cert, skip)
                # Run signature analysis
                detection_results = self._analyze_signatures(results)
                results.update(detection_results)

                # Canary probes via impersonated session
                _all_dets = results.get('all_detections', [])
                _CANARY_PROBES = {
                    'cloudflare': ('?fray_canary=<script>cf_canary</script>',
                                   [r'cloudflare', r'cf-error', r'attention required', r'ray id']),
                    'aws_waf': ("?fray_canary=' OR 1=1--",
                                [r'x-amzn-requestid', r'aws-waf', r'request blocked']),
                    'akamai': ('?fray_canary=../../etc/passwd',
                               [r'reference\s*#[\d.]+', r'akamai']),
                    'imperva': ('?fray_canary=|id',
                                [r'incapsula', r'incident\s*id', r'imperva']),
                    'f5_bigip': ('?fray_canary=<script>alert(1)</script>',
                                 [r'the requested url was rejected', r'support id']),
                }
                _candidates = [d for d in _all_dets if 20 <= d.get('confidence', 0) <= 80]
                _canary_results = []
                for _cand in _candidates[:3]:
                    _v = _cand['vendor'].lower().replace(' ', '_')
                    for _ck, (_cp, _cc) in _CANARY_PROBES.items():
                        if _ck in _v or _v in _ck:
                            try:
                                _curl = f"{scheme}://{host}{port_s}{path}{_cp}"
                                _cr = sess.get(_curl)
                                _ctext = _cr.text.lower() if _cr.text else ""
                                _confirmed = any(re.search(p, _ctext, re.I) for p in _cc)
                                if _confirmed:
                                    _cand['confidence'] = min(_cand['confidence'] + 25, 100)
                                    _cand['signatures'].append(f"Canary probe confirmed: {_ck}")
                                    _cand['signature_count'] += 1
                                    _canary_results.append({'vendor': _ck, 'confirmed': True})
                                else:
                                    _canary_results.append({'vendor': _ck, 'confirmed': False})
                            except Exception:
                                pass
                            break
                if _canary_results:
                    results['canary_probes'] = _canary_results
                    _all_dets.sort(key=lambda x: (x['confidence'], x['signature_count']), reverse=True)
                    if _all_dets:
                        _top = _all_dets[0]
                        results['waf_vendor'] = _top['vendor']
                        results['confidence'] = _top['confidence']
                        results['signatures_found'] = _top['signatures']

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
            
            # Special handling for AWS WAF prefix matching (x-amzn-waf-*)
            if 'header_prefix' in signatures:
                prefix = signatures['header_prefix']
                for resp_header in results['headers'].keys():
                    if resp_header.lower().startswith(prefix.lower()):
                        confidence += 50  # Very strong indicator of AWS WAF
                        found_signatures.append(f"WAF-specific header: {resp_header}")
                        signature_count += 1
            
            # Special handling for Azure Front Door headers
            if 'front_door_headers' in signatures:
                fd_header_count = sum(1 for h in signatures['front_door_headers'] 
                                     if any(h.lower() in rh.lower() for rh in results['headers'].keys()))
                if fd_header_count >= 2:
                    confidence += 40  # Multiple Front Door headers = strong indicator
                    found_signatures.append(f"Azure Front Door: {fd_header_count} headers")
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
            
            # Check error patterns (regex-based, high confidence)
            if results['response_snippet'] and 'error_patterns' in signatures:
                for pattern in signatures['error_patterns']:
                    if re.search(pattern, results['response_snippet'], re.IGNORECASE):
                        confidence += 25  # Error pattern match is strong indicator
                        found_signatures.append(f"Error pattern: {pattern}")
                        signature_count += 1
            
            # Check challenge patterns (CAPTCHA/challenge pages)
            if results['response_snippet'] and 'challenge_patterns' in signatures:
                for pattern in signatures['challenge_patterns']:
                    if pattern.lower() in results['response_snippet'].lower():
                        confidence += 20  # Challenge page is good indicator
                        found_signatures.append(f"Challenge: {pattern}")
                        signature_count += 1
            
            # Check WAF-specific headers (very high confidence)
            if 'waf_specific_headers' in signatures:
                for waf_header in signatures['waf_specific_headers']:
                    if waf_header.lower() in [h.lower() for h in results['headers'].keys()]:
                        confidence += 40  # WAF-specific header is very strong
                        found_signatures.append(f"WAF-specific header: {waf_header}")
                        signature_count += 1
            
            # Check response body patterns (advanced cloud WAF detection)
            if results['response_snippet'] and 'response_body_patterns' in signatures:
                for body_pattern in signatures['response_body_patterns']:
                    if body_pattern.lower() in results['response_snippet'].lower():
                        confidence += 15  # Response body pattern is strong indicator
                        found_signatures.append(f"Body pattern: {body_pattern}")
                        signature_count += 1
            
            # Check header combinations (multi-factor cloud WAF detection)
            if 'header_combinations' in signatures:
                for combo in signatures['header_combinations']:
                    matches = sum(1 for h in combo if h.lower() in [x.lower() for x in results['headers'].keys()])
                    if matches == len(combo):
                        # All headers in combination present
                        confidence += 20
                        found_signatures.append(f"Header combo: {len(combo)} headers")
                        signature_count += 1
                    elif matches >= len(combo) * 0.7:
                        # Most headers present (70%+)
                        confidence += 10
                        found_signatures.append(f"Partial combo: {matches}/{len(combo)}")
                        signature_count += 1
            
            # Check GCP-specific headers (Google Cloud Armor)
            if 'gcp_headers' in signatures:
                gcp_header_count = sum(1 for h in signatures['gcp_headers'] 
                                      if any(h.lower() in rh.lower() for rh in results['headers'].keys()))
                if gcp_header_count >= 2:
                    confidence += 30  # Multiple GCP headers = strong indicator
                    found_signatures.append(f"GCP headers: {gcp_header_count}")
                    signature_count += 1
            
            # Check cache patterns (Azure Front Door)
            if 'cache_patterns' in signatures and 'x-cache' in results['headers']:
                cache_value = results['headers']['x-cache']
                for cache_pattern in signatures['cache_patterns']:
                    if cache_pattern in cache_value:
                        confidence += 10
                        found_signatures.append(f"Cache pattern: {cache_pattern}")
                        signature_count += 1
            
            # Check status code (low weight, many WAFs use same codes)
            if results['status_code'] in signatures['response_codes']:
                # Give more weight to unique status codes
                if results['status_code'] in [520, 521, 522, 523, 524, 525, 526, 527]:
                    confidence += 15  # Cloudflare-specific codes
                elif results['status_code'] == 406:
                    confidence += 10  # Signal Sciences specific
                elif results['status_code'] == 429:
                    confidence += 10  # Rate limiting (WAF-specific)
                else:
                    confidence += 5  # Common codes
            
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
        
        # Boost confidence from TLS cert org hint
        _tls_hint = results.get('tls_cert', {}).get('waf_hint', '')
        if _tls_hint:
            for dw in detected_wafs:
                if _tls_hint.lower() in dw['vendor'].lower() or dw['vendor'].lower() in _tls_hint.lower():
                    dw['confidence'] = min(dw['confidence'] + 15, 100)
                    dw['signatures'].append(f"TLS cert org: {results['tls_cert'].get('issuer_org', '')}")
                    dw['signature_count'] += 1
                    break
            else:
                # TLS hint vendor not yet in detected list — add as low-confidence detection
                detected_wafs.append({
                    'vendor': _tls_hint,
                    'confidence': 15,
                    'signatures': [f"TLS cert org: {results['tls_cert'].get('issuer_org', '')}"],
                    'signature_count': 1,
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
        
        target = results['target']
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

            # Next steps
            waf = results['waf_vendor']
            waf_slug = waf.lower().replace(" ", "_").split("(")[0].strip("_")
            print(f"\n{Colors.BOLD}Next Steps:{Colors.END}")
            print(f"  Test WAF bypass:   fray bypass {target} -c xss --waf {waf_slug} -m 30")
            print(f"  Run full test:     fray test {target} -c xss -m 50")
            print(f"  Run recon:         fray recon {target}")
        else:
            print(f"{Colors.YELLOW}✗ No WAF Detected{Colors.END}")
            print(f"  The target may not be using a WAF, or it's using a custom/unknown WAF")
            print(f"\n{Colors.BOLD}Next Steps:{Colors.END}")
            print(f"  Test anyway:       fray test {target} -c xss -m 20")
            print(f"  Run recon:         fray recon {target}")
            print(f"  Scan for inputs:   fray scan {target} -c xss")
        
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
  • Fastly (Signal Sciences WAF)
  • Barracuda Networks
  • Citrix NetScaler
  • Radware
  • Microsoft Azure WAF
  • Google Cloud Armor
  • Qualys WAF
  • Penta Security (WAPPLES)
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
