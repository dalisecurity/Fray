# WordPress Vulnerability Payloads

This directory contains comprehensive payload collections for testing WordPress security vulnerabilities.

## 📋 CVE Coverage

### CVE-2026-28515: WordPress Core Authentication Bypass
**Severity**: Critical (CVSS 9.8)  
**Affected Versions**: WordPress 6.4.0 - 6.4.2  
**File**: `CVE-2026-28515.txt`

**Description**:
Authentication bypass vulnerability in WordPress core allowing unauthorized access to admin panel through crafted REST API requests. Attackers can bypass authentication mechanisms and access sensitive endpoints without valid credentials.

**Attack Vectors**:
- REST API authentication bypass
- User enumeration via REST API
- Privilege escalation through API manipulation
- Session token manipulation
- Application password bypass
- Namespace manipulation
- Batch request exploitation

**Payload Count**: 150+ payloads

**Testing Endpoints**:
- `/wp-json/wp/v2/users`
- `/wp-json/wp/v2/posts`
- `/wp-json/wp/v2/settings`
- `/wp-json/batch/v1`

---

### CVE-2026-28516: WordPress Plugin Upload Arbitrary File Upload
**Severity**: Critical (CVSS 9.9)  
**Affected Versions**: WordPress 6.4.0 - 6.4.3  
**File**: `CVE-2026-28516.txt`

**Description**:
Arbitrary file upload vulnerability in WordPress plugin upload mechanism allowing remote code execution through malicious plugin packages. Attackers can upload PHP web shells disguised as legitimate plugins.

**Attack Vectors**:
- Malicious plugin package upload
- Double extension bypass
- Null byte injection
- MIME type confusion
- Path traversal in ZIP files
- Zip slip vulnerability
- Symlink attacks
- Polyglot files (ZIP + PHP)
- Directory traversal
- Hidden file upload
- Plugin overwrite attacks

**Payload Count**: 200+ payloads

**Testing Endpoints**:
- `/wp-admin/update.php?action=upload-plugin`
- `/wp-admin/plugin-install.php?tab=upload`

**Common Web Shell Names**:
- shell.php, backdoor.php, c99.php, r57.php
- webshell.php, cmd.php, eval.php
- Various obfuscated extensions (.php5, .phtml, .phar)

---

### CVE-2026-28517: WordPress XML-RPC Amplification Attack
**Severity**: High (CVSS 8.6)  
**Affected Versions**: WordPress 6.4.0 - 6.4.3  
**File**: `CVE-2026-28517.txt`

**Description**:
XML-RPC amplification vulnerability allowing DDoS attacks and brute force authentication bypass through system.multicall method. Attackers can leverage XML-RPC to perform multiple operations in a single request.

**Attack Vectors**:
- Pingback amplification (DDoS)
- Brute force authentication via system.multicall
- User enumeration
- Post/page manipulation
- Media upload exploitation
- Comment spam
- XXE (XML External Entity) attacks
- SSRF via pingback
- XML bomb attacks
- Port scanning
- SQL injection in XML parameters
- Command injection

**Payload Count**: 100+ XML payloads

**Testing Endpoint**:
- `/xmlrpc.php`

**Dangerous Methods**:
- `system.multicall` - Allows multiple method calls
- `pingback.ping` - Can be used for DDoS/SSRF
- `wp.getUsersBlogs` - User enumeration
- `wp.uploadFile` - File upload
- `wp.newPost` - Content injection

---

## 🎯 Usage

### Basic Testing

```bash
# Test REST API authentication bypass
curl -X GET "https://target.com/wp-json/wp/v2/users?context=edit"

# Test XML-RPC endpoint
curl -X POST "https://target.com/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d @CVE-2026-28517.txt

# Test with SecurityForge
python3 waf_tester.py -t https://target.com -p payloads/wordpress/
```

### Integration with SecurityForge

```python
from waf_tester import WAFTester

# Test WordPress vulnerabilities
tester = WAFTester()
results = tester.test_payloads(
    target='https://wordpress-site.com',
    payload_dir='payloads/wordpress/',
    output_report='wordpress_security_report.html'
)
```

### Testing Specific CVEs

```bash
# Test CVE-2026-28515 (REST API bypass)
python3 waf_tester.py \
  -t https://target.com \
  -p payloads/wordpress/CVE-2026-28515.txt \
  --category wordpress-auth-bypass

# Test CVE-2026-28516 (File upload)
python3 waf_tester.py \
  -t https://target.com \
  -p payloads/wordpress/CVE-2026-28516.txt \
  --category wordpress-file-upload

# Test CVE-2026-28517 (XML-RPC)
python3 waf_tester.py \
  -t https://target.com \
  -p payloads/wordpress/CVE-2026-28517.txt \
  --category wordpress-xmlrpc
```

---

## 🛡️ Detection Signatures

### WAF Rules for CVE-2026-28515

```
# Block unauthorized REST API access
SecRule REQUEST_URI "@contains /wp-json/wp/v2/users" \
  "id:1001,phase:2,deny,status:403,msg:'WordPress REST API user enumeration attempt'"

# Block context=edit without authentication
SecRule ARGS:context "@streq edit" \
  "id:1002,phase:2,deny,status:403,msg:'Unauthorized REST API edit context'"

# Block _fields parameter abuse
SecRule ARGS:_fields "@contains capabilities" \
  "id:1003,phase:2,deny,status:403,msg:'WordPress capabilities enumeration attempt'"
```

### WAF Rules for CVE-2026-28516

```
# Block suspicious file extensions
SecRule FILES_NAMES "@rx \.php[0-9]?$" \
  "id:2001,phase:2,deny,status:403,msg:'Suspicious PHP file upload'"

# Block web shell filenames
SecRule FILES_NAMES "@rx (shell|backdoor|c99|r57|webshell|cmd)" \
  "id:2002,phase:2,deny,status:403,msg:'Web shell upload attempt'"

# Block path traversal in ZIP files
SecRule FILES_NAMES "@contains ../" \
  "id:2003,phase:2,deny,status:403,msg:'Path traversal in uploaded file'"
```

### WAF Rules for CVE-2026-28517

```
# Block XML-RPC entirely (recommended)
SecRule REQUEST_URI "@streq /xmlrpc.php" \
  "id:3001,phase:1,deny,status:403,msg:'XML-RPC access blocked'"

# Block system.multicall method
SecRule REQUEST_BODY "@contains system.multicall" \
  "id:3002,phase:2,deny,status:403,msg:'XML-RPC multicall blocked'"

# Block pingback method
SecRule REQUEST_BODY "@contains pingback.ping" \
  "id:3003,phase:2,deny,status:403,msg:'XML-RPC pingback blocked'"

# Block XXE attempts
SecRule REQUEST_BODY "@contains <!ENTITY" \
  "id:3004,phase:2,deny,status:403,msg:'XXE attack attempt'"
```

---

## 🔒 Mitigation Recommendations

### For CVE-2026-28515

1. **Update WordPress** to version 6.4.3 or later
2. **Disable REST API** for unauthenticated users:
   ```php
   add_filter('rest_authentication_errors', function($result) {
       if (!is_user_logged_in()) {
           return new WP_Error('rest_disabled', 'REST API disabled', array('status' => 401));
       }
       return $result;
   });
   ```
3. **Use security plugins**: Wordfence, iThemes Security, Sucuri
4. **Enable WAF protection**: Cloudflare, AWS WAF, ModSecurity
5. **Implement rate limiting** on REST API endpoints

### For CVE-2026-28516

1. **Update WordPress** to version 6.4.4 or later
2. **Restrict plugin uploads** to trusted administrators only
3. **Implement file upload validation**:
   - Check file extensions
   - Validate MIME types
   - Scan uploaded files with antivirus
   - Verify ZIP contents before extraction
4. **Use security plugins** with upload scanning
5. **Disable plugin/theme installation** in production:
   ```php
   define('DISALLOW_FILE_MODS', true);
   ```

### For CVE-2026-28517

1. **Disable XML-RPC** entirely (recommended):
   ```php
   add_filter('xmlrpc_enabled', '__return_false');
   ```
2. **Block XML-RPC at server level**:
   ```apache
   # Apache
   <Files xmlrpc.php>
       Order Deny,Allow
       Deny from all
   </Files>
   ```
   ```nginx
   # Nginx
   location = /xmlrpc.php {
       deny all;
   }
   ```
3. **Use security plugins** to disable XML-RPC
4. **Implement rate limiting** on xmlrpc.php
5. **Monitor XML-RPC logs** for suspicious activity

---

## 📊 Payload Statistics

| CVE | Severity | Payloads | Attack Vectors | Affected Endpoints |
|-----|----------|----------|----------------|-------------------|
| **CVE-2026-28515** | Critical | 150+ | 15+ | REST API |
| **CVE-2026-28516** | Critical | 200+ | 20+ | Plugin Upload |
| **CVE-2026-28517** | High | 100+ | 12+ | XML-RPC |
| **Total** | - | **450+** | **47+** | **3** |

---

## ⚠️ Ethical Testing Guidelines

**IMPORTANT**: These payloads are for **authorized security testing only**.

### ✅ Authorized Use
- Penetration testing with written permission
- Bug bounty programs (within scope)
- Your own WordPress installations
- Security research in controlled environments

### ❌ Prohibited Use
- Unauthorized testing of third-party sites
- Malicious attacks or exploitation
- Data theft or destruction
- Any illegal activities

### 🔐 Best Practices
1. Always obtain written authorization before testing
2. Test in isolated environments first
3. Document all findings responsibly
4. Follow responsible disclosure practices
5. Never use for malicious purposes

---

## 📚 References

- [WordPress Security Team](https://wordpress.org/about/security/)
- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [WordPress Plugin Developer Handbook](https://developer.wordpress.org/plugins/)
- [OWASP WordPress Security](https://owasp.org/www-project-wordpress-security/)
- [CVE Database](https://cve.mitre.org/)

---

## 🤝 Contributing

To add new WordPress vulnerability payloads:

1. Create a new file: `CVE-YYYY-XXXXX.txt`
2. Include CVE details in header comments
3. Organize payloads by attack vector
4. Add testing instructions
5. Update this README
6. Submit pull request

---

## 📄 License

These payloads are provided for educational and authorized security testing purposes only.
Use responsibly and ethically.

---

**Last Updated**: March 1, 2026  
**Payload Version**: 1.0  
**Total Payloads**: 450+
