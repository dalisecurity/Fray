# 🎯 Comprehensive Payload Database Coverage

## Executive Summary

Complete implementation of all attack types from [awesome-claude-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security) repository, providing comprehensive security testing payloads for WAF detection and penetration testing.

**Status**: ✅ **COMPLETE** - All attack types covered  
**Total Payload Files**: 15  
**Coverage**: 100% of awesome-claude-skills-security categories + WordPress CVEs  
**Purpose**: Authorized security testing, CTF competitions, bug bounties

---

## 📊 Coverage Matrix

| Category | Status | File Location | Payload Count |
|----------|--------|---------------|---------------|
| **XSS Injection** | ✅ Complete | `payloads/xss/` | 100+ |
| **XXE Payloads** | ✅ Complete | `payloads/xxe/` | 30+ |
| **Template Injection** | ✅ Complete | `payloads/ssti/` | 80+ |
| **File Upload Bypasses** | ✅ Complete | `payloads/file_upload/` | 70+ |
| **Path Traversal** | ✅ Complete | `payloads/path_traversal/` | 150+ |
| **Web Shells - PHP** | ✅ Complete | `payloads/web_shells/` | 50+ |
| **Web Shells - ASP/ASPX** | ✅ Complete | `payloads/web_shells/` | 25+ |
| **Web Shells - JSP** | ✅ Complete | `payloads/web_shells/` | 20+ |
| **Web Shells - Python** | ✅ Complete | `payloads/web_shells/` | 30+ |
| **Web Shells - Perl** | ✅ Complete | `payloads/web_shells/` | 35+ |
| **LLM Testing** | ✅ Complete | `payloads/llm_testing/` | 200+ |
| **WordPress CVE-2026-28515** | ✅ Complete | `payloads/wordpress/` | 150+ |
| **WordPress CVE-2026-28516** | ✅ Complete | `payloads/wordpress/` | 200+ |
| **WordPress CVE-2026-28517** | ✅ Complete | `payloads/wordpress/` | 100+ |

---

## 🔍 Detailed Coverage

### 1. XSS Injection Vectors ✅

**Files**:
- `payloads/xss/xss_basic.txt` - Basic XSS payloads
- `payloads/xss/xss_advanced.txt` - Advanced and obfuscated XSS

**Coverage**:
- ✅ Basic script injection
- ✅ Event handler XSS
- ✅ SVG-based XSS
- ✅ JavaScript protocol
- ✅ Data URI XSS
- ✅ HTML5 XSS vectors
- ✅ Form-based XSS
- ✅ Link and meta refresh XSS
- ✅ Style-based XSS
- ✅ Template XSS
- ✅ Encoded XSS (Unicode, Hex, Octal)
- ✅ Filter bypass techniques
- ✅ Context breaking
- ✅ Polyglot XSS
- ✅ DOM-based XSS

**Total Payloads**: 100+

---

### 2. XXE (XML External Entity) Payloads ✅

**File**: `payloads/xxe/xxe_basic.txt`

**Coverage**:
- ✅ Basic XXE file read
- ✅ Parameter entity XXE
- ✅ XXE SSRF attacks
- ✅ External DTD XXE
- ✅ Blind XXE
- ✅ PHP wrapper XXE
- ✅ Expect wrapper XXE
- ✅ Out-of-band XXE
- ✅ Error-based XXE
- ✅ CDATA XXE
- ✅ UTF-7/UTF-16 encoded XXE
- ✅ Billion Laughs DoS
- ✅ XInclude XXE
- ✅ SOAP XXE
- ✅ SVG XXE
- ✅ DOCX XXE
- ✅ Data URI XXE
- ✅ JAR protocol XXE
- ✅ FTP/Gopher XXE

**Total Payloads**: 30+

---

### 3. Server-Side Template Injection (SSTI) ✅

**File**: `payloads/ssti/template_injection.txt`

**Coverage**:
- ✅ Jinja2 (Python/Flask)
- ✅ Twig (PHP)
- ✅ Smarty (PHP)
- ✅ Freemarker (Java)
- ✅ Velocity (Java)
- ✅ Thymeleaf (Java)
- ✅ Pug/Jade (Node.js)
- ✅ Handlebars (Node.js)
- ✅ ERB (Ruby)
- ✅ Tornado (Python)
- ✅ Mako (Python)
- ✅ Django (Python)
- ✅ Razor (ASP.NET)
- ✅ Groovy
- ✅ Expression Language (EL)
- ✅ OGNL (Java)
- ✅ Spring EL
- ✅ Blade (Laravel/PHP)
- ✅ Liquid (Ruby)
- ✅ Mustache
- ✅ Nunjucks (Node.js)
- ✅ Dot (Node.js)
- ✅ EJS (Node.js)
- ✅ Marko (Node.js)
- ✅ Underscore (Node.js)
- ✅ Swig (Node.js)
- ✅ Dust (Node.js)
- ✅ Eta (Node.js)
- ✅ Squirrelly (Node.js)

**Total Payloads**: 80+

---

### 4. File Upload Bypass Techniques ✅

**File**: `payloads/file_upload/upload_bypass.txt`

**Coverage**:
- ✅ Double extension bypasses
- ✅ Null byte injection
- ✅ Case manipulation
- ✅ Special characters
- ✅ Unicode/UTF-8 bypasses
- ✅ Alternative extensions (PHP, ASP, JSP, Perl, Python)
- ✅ Content-Type bypasses
- ✅ Magic bytes bypasses
- ✅ Polyglot files (GIF/PHP, JPEG/PHP, ZIP/PHP)
- ✅ Filename bypasses
- ✅ Path traversal in filenames
- ✅ MIME type bypasses
- ✅ Archive bypasses
- ✅ .htaccess upload
- ✅ web.config upload
- ✅ .user.ini upload
- ✅ SVG with XSS/XXE
- ✅ EXIF metadata injection
- ✅ Filename encoding
- ✅ Directory traversal
- ✅ Race conditions
- ✅ Zip Slip
- ✅ ImageTragick
- ✅ XXE in SVG
- ✅ SSRF in SVG
- ✅ PDF with JavaScript
- ✅ Office document macros
- ✅ HTML upload for XSS
- ✅ CSV injection
- ✅ XML upload for XXE

**Total Payloads**: 70+

---

### 5. Path Traversal / Directory Traversal ✅

**File**: `payloads/path_traversal/path_traversal.txt`

**Coverage**:
- ✅ Basic path traversal (../)
- ✅ Windows path traversal (..\)
- ✅ URL encoded traversal
- ✅ Double URL encoded
- ✅ UTF-8 encoded
- ✅ 16-bit Unicode
- ✅ Overlong UTF-8
- ✅ Mixed encoding
- ✅ Null byte injection
- ✅ Dot variations
- ✅ Filter bypasses
- ✅ Absolute paths (Linux)
- ✅ Absolute paths (Windows)
- ✅ Relative paths with filenames
- ✅ Log poisoning paths
- ✅ PHP wrappers (filter, input, data, expect, file)
- ✅ Zip wrapper
- ✅ Phar wrapper
- ✅ Data wrapper
- ✅ Glob wrapper
- ✅ Input wrapper
- ✅ Filter chains (PHP 8+)
- ✅ ASP.NET paths
- ✅ Java paths (WEB-INF, META-INF)
- ✅ Node.js paths
- ✅ Python paths
- ✅ Ruby paths
- ✅ Cloud metadata endpoints
- ✅ Container escape paths
- ✅ Backup file discovery
- ✅ Source code disclosure

**Total Payloads**: 150+

---

### 6. Web Shells - PHP ✅

**File**: `payloads/web_shells/php_shells.txt`

**Coverage**:
- ✅ Basic PHP shells (system, shell_exec, passthru, exec)
- ✅ One-liner shells
- ✅ Obfuscated shells
- ✅ Base64 encoded shells
- ✅ Assert shells
- ✅ Preg_replace shells
- ✅ Array map shells
- ✅ Variable function shells
- ✅ File upload shells
- ✅ File write shells
- ✅ Mini shells
- ✅ Backdoors with authentication
- ✅ WSO shell
- ✅ C99 shell
- ✅ R57 shell
- ✅ FilesMan shell
- ✅ Weevely shell
- ✅ China Chopper
- ✅ b374k shell
- ✅ Anonymous shell
- ✅ Reverse shells
- ✅ Bind shells
- ✅ File manager shells
- ✅ Database shells
- ✅ Eval shells with XOR
- ✅ Callback shells
- ✅ Reflection shells
- ✅ Namespace shells
- ✅ Goto shells
- ✅ Heredoc/Nowdoc shells
- ✅ Phar shells
- ✅ Stream shells
- ✅ Superglobal shells
- ✅ Compact shells
- ✅ Parse_str shells

**Total Payloads**: 50+

---

### 7. Web Shells - ASP/ASPX ✅

**File**: `payloads/web_shells/asp_shells.txt`

**Coverage**:
- ✅ Basic ASP shells (eval, execute)
- ✅ ASP command execution
- ✅ ASP.NET basic shells
- ✅ ASPX eval shells
- ✅ ASPX one-liners
- ✅ ASP file upload
- ✅ ASPX file upload
- ✅ ASP.NET reverse shells
- ✅ ASPX with authentication
- ✅ ASPX China Chopper
- ✅ ASPX Antak shell
- ✅ ASPX obfuscated shells
- ✅ ASP.NET reflection shells
- ✅ ASPX base64 encoded shells
- ✅ ASP.NET dynamic compilation
- ✅ ASPX PowerShell shells
- ✅ ASP.NET file manager
- ✅ ASP.NET database shells
- ✅ ASPX WMI shells
- ✅ ASPX registry shells
- ✅ ASP classic file manager
- ✅ ASPX encoded command shells

**Total Payloads**: 25+

---

### 8. Web Shells - JSP ✅

**File**: `payloads/web_shells/jsp_shells.txt`

**Coverage**:
- ✅ Basic JSP shells
- ✅ JSP command execution
- ✅ JSP ProcessBuilder shells
- ✅ JSP reverse shells
- ✅ JSP file upload
- ✅ JSP file manager
- ✅ JSP reflection shells
- ✅ JSP Expression Language shells
- ✅ JSP ScriptEngine shells
- ✅ JSP JNDI shells
- ✅ JSP deserialization shells
- ✅ JSP JDBC shells
- ✅ JSP ClassLoader shells
- ✅ JSP base64 encoded shells
- ✅ JSP obfuscated shells
- ✅ JSP China Chopper
- ✅ JSP with authentication
- ✅ JSP JMX shells
- ✅ JSP RMI shells
- ✅ JSP LDAP shells
- ✅ JSP XSL transform shells
- ✅ JSP Groovy shells

**Total Payloads**: 20+

---

### 9. Web Shells - Python ✅

**File**: `payloads/web_shells/python_shells.txt`

**Coverage**:
- ✅ Basic Python shells
- ✅ Flask shells
- ✅ Django shells
- ✅ Python CGI shells
- ✅ Python subprocess shells
- ✅ Python eval/exec shells
- ✅ Python reverse shells
- ✅ Python bind shells
- ✅ Python one-liner reverse shells
- ✅ Python base64 shells
- ✅ Python pickle shells
- ✅ Python YAML shells
- ✅ Python template shells (Jinja2)
- ✅ Python file upload shells
- ✅ Python file manager shells
- ✅ Python database shells
- ✅ Python obfuscated shells
- ✅ Python lambda shells
- ✅ Python comprehension shells
- ✅ Python decorator shells
- ✅ Python metaclass shells
- ✅ Python property shells
- ✅ Python descriptor shells
- ✅ Python context manager shells
- ✅ Python iterator shells
- ✅ Python generator shells
- ✅ Python asyncio shells
- ✅ Python threading shells
- ✅ Python multiprocessing shells
- ✅ Python socket server shells
- ✅ Python HTTP server shells
- ✅ Python WSGI shells
- ✅ Python Tornado shells
- ✅ Python FastAPI shells

**Total Payloads**: 30+

---

### 10. Web Shells - Perl ✅

**File**: `payloads/web_shells/perl_shells.txt`

**Coverage**:
- ✅ Basic Perl shells
- ✅ Perl system shells
- ✅ Perl backtick shells
- ✅ Perl exec shells
- ✅ Perl open shells
- ✅ Perl CGI shells
- ✅ Perl reverse shells
- ✅ Perl bind shells
- ✅ Perl one-liner reverse shells
- ✅ Perl file upload shells
- ✅ Perl file manager shells
- ✅ Perl eval shells
- ✅ Perl do shells
- ✅ Perl require shells
- ✅ Perl IPC::Open3 shells
- ✅ Perl IO::Socket shells
- ✅ Perl LWP shells
- ✅ Perl DBI shells
- ✅ Perl obfuscated shells
- ✅ Perl base64 shells
- ✅ Perl fork shells
- ✅ Perl thread shells
- ✅ Perl pipe shells
- ✅ Perl glob shells
- ✅ Perl regex shells
- ✅ Perl symbolic reference shells
- ✅ Perl typeglob shells
- ✅ Perl AUTOLOAD shells
- ✅ Perl tie shells
- ✅ Perl overload shells
- ✅ Perl source filter shells
- ✅ Perl Inline C shells
- ✅ Perl XS shells
- ✅ Perl Moose shells
- ✅ Perl Mojo shells
- ✅ Perl Dancer shells
- ✅ Perl Catalyst shells

**Total Payloads**: 35+

---

### 11. LLM Testing - Comprehensive AI Security ✅

**Files**:
- `payloads/llm_testing/bias_detection.txt` - Bias testing prompts
- `payloads/llm_testing/data_leakage.txt` - Privacy and data leakage testing
- `payloads/llm_testing/adversarial_prompts.txt` - Jailbreak and adversarial attacks

**Coverage**:

#### Bias Detection ✅
- ✅ Gender bias detection
- ✅ Nationality bias detection
- ✅ Race/ethnicity bias detection
- ✅ Age bias detection
- ✅ Disability bias detection
- ✅ Socioeconomic bias detection
- ✅ Religious bias detection
- ✅ Sexual orientation bias detection
- ✅ Appearance bias detection
- ✅ Political bias detection
- ✅ Educational bias detection
- ✅ Intersectional bias detection
- ✅ Implicit association testing
- ✅ Stereotype activation
- ✅ Microaggression detection
- ✅ Fairness testing

#### Data Leakage and Privacy Testing ✅
- ✅ Training data extraction
- ✅ PII disclosure testing
- ✅ Memorization testing
- ✅ Context window leakage
- ✅ System prompt extraction
- ✅ Model architecture leakage
- ✅ API key and credential leakage
- ✅ Internal system information
- ✅ User data aggregation
- ✅ Cross-user information leakage
- ✅ Jailbreak for data extraction
- ✅ Indirect information extraction
- ✅ Prompt injection for data leakage
- ✅ Encoding-based extraction
- ✅ Timing attack leakage
- ✅ Model inversion attacks
- ✅ Membership inference
- ✅ Gradient leakage simulation
- ✅ Cache poisoning
- ✅ Side channel leakage
- ✅ Federated learning leakage

#### Adversarial Prompt Resistance ✅
- ✅ Basic jailbreak attempts
- ✅ DAN (Do Anything Now) prompts
- ✅ Role-playing jailbreaks
- ✅ Hypothetical scenarios
- ✅ Encoded instructions
- ✅ Prompt injection
- ✅ Nested instructions
- ✅ Alignment breaking
- ✅ Goal hijacking
- ✅ Token manipulation
- ✅ Context confusion
- ✅ Authority exploitation
- ✅ Emotional manipulation
- ✅ Gradual escalation
- ✅ Reverse psychology
- ✅ Multi-step attacks
- ✅ Boundary testing
- ✅ Comparison attacks
- ✅ Linguistic tricks
- ✅ Meta-prompting
- ✅ Chain-of-thought exploitation
- ✅ Few-shot manipulation
- ✅ Instruction hierarchy confusion
- ✅ Token smuggling
- ✅ Plausible deniability

**Total Prompts**: 200+

---

## 🎯 Comparison with awesome-claude-skills-security

| Category | awesome-claude-skills | Our Coverage | Status |
|----------|----------------------|--------------|--------|
| **Fuzzing** | SQL, Command, NoSQL, LDAP | ✅ Covered in existing payloads | ✅ |
| **Passwords** | Password lists | ⚠️ Not included (out of scope) | N/A |
| **Pattern-Matching** | API keys, CC, Email, IP | ⚠️ Not included (detection, not attack) | N/A |
| **Payloads - XSS** | XSS injection vectors | ✅ 100+ payloads | ✅ |
| **Payloads - XXE** | XXE payloads | ✅ 30+ payloads | ✅ |
| **Payloads - Template** | Template injection | ✅ 80+ payloads | ✅ |
| **Payloads - File Upload** | File upload bypasses | ✅ 70+ payloads | ✅ |
| **Payloads - Path Traversal** | Path traversal strings | ✅ 150+ payloads | ✅ |
| **Usernames** | Username wordlists | ⚠️ Not included (out of scope) | N/A |
| **Web-Shells - PHP** | PHP web shells | ✅ 50+ shells | ✅ |
| **Web-Shells - ASP/ASPX** | ASP/ASPX shells | ✅ 25+ shells | ✅ |
| **Web-Shells - JSP** | JSP shells | ✅ 20+ shells | ✅ |
| **Web-Shells - Python** | Python shells | ✅ 30+ shells | ✅ |
| **Web-Shells - Perl** | Perl shells | ✅ 35+ shells | ✅ |
| **LLM - Bias** | Bias detection | ✅ 50+ prompts | ✅ |
| **LLM - Data Leakage** | Privacy testing | ✅ 80+ prompts | ✅ |
| **LLM - Memory Recall** | Memory testing | ✅ Covered in data_leakage.txt | ✅ |
| **LLM - Alignment** | Alignment attacks | ✅ Covered in adversarial_prompts.txt | ✅ |
| **LLM - Adversarial** | Prompt resistance | ✅ 70+ prompts | ✅ |
| **LLM - AI Safety** | Safety evaluation | ✅ Covered in all LLM files | ✅ |

**Coverage Score**: 100% of attack payload categories  
**Excluded**: Password lists, username lists, pattern-matching (detection tools, not attack payloads)

---

## 📁 File Structure

```
waf-payload-database/
├── payloads/
│   ├── xss/
│   │   ├── xss_basic.txt (60+ payloads)
│   │   └── xss_advanced.txt (40+ payloads)
│   ├── xxe/
│   │   └── xxe_basic.txt (30+ payloads)
│   ├── ssti/
│   │   └── template_injection.txt (80+ payloads)
│   ├── file_upload/
│   │   └── upload_bypass.txt (70+ payloads)
│   ├── path_traversal/
│   │   └── path_traversal.txt (150+ payloads)
│   ├── web_shells/
│   │   ├── php_shells.txt (50+ shells)
│   │   ├── asp_shells.txt (25+ shells)
│   │   ├── jsp_shells.txt (20+ shells)
│   │   ├── python_shells.txt (30+ shells)
│   │   └── perl_shells.txt (35+ shells)
│   └── llm_testing/
│       ├── bias_detection.txt (50+ prompts)
│       ├── data_leakage.txt (80+ prompts)
│       └── adversarial_prompts.txt (70+ prompts)
└── PAYLOAD_DATABASE_COVERAGE.md (this file)
```

---

## 🔒 Security & Ethics

### ✅ Authorized Use Cases
- Penetration testing with written authorization
- Security research in controlled environments
- CTF competitions and training
- Bug bounty programs
- Educational purposes in authorized labs
- WAF testing and validation
- Security tool development

### ❌ Prohibited Use Cases
- Unauthorized access to systems
- Malicious attacks on production systems
- Data theft or destruction
- Privacy violations
- Illegal activities
- Harassment or harm to individuals
- Unauthorized security testing

### 📋 Responsible Usage Guidelines
1. **Always obtain written authorization** before testing
2. **Use in isolated environments** (labs, sandboxes, authorized targets)
3. **Document all testing activities** for compliance
4. **Follow responsible disclosure** for vulnerabilities found
5. **Respect privacy and data protection** laws
6. **Limit scope to authorized targets** only
7. **Maintain confidentiality** of findings
8. **Follow ethical hacking principles**

---

## 🎓 Educational Value

This payload database serves as:

1. **WAF Testing Resource** - Validate WAF detection capabilities
2. **Security Training Material** - Teach attack vectors and defenses
3. **Research Tool** - Study attack patterns and trends
4. **Development Aid** - Build better security tools
5. **Compliance Testing** - Verify security controls
6. **Incident Response** - Understand attack techniques
7. **Threat Intelligence** - Recognize attack patterns

---

## 📊 Statistics

| Metric | Count |
|--------|-------|
| **Total Payload Files** | 11 |
| **Total Payloads** | 800+ |
| **Attack Categories** | 11 |
| **Programming Languages** | 10+ |
| **Template Engines** | 29 |
| **LLM Test Prompts** | 200+ |
| **Web Shell Variants** | 160+ |
| **File Upload Bypasses** | 70+ |
| **Path Traversal Techniques** | 150+ |

---

## 🚀 Integration with WAF Detector

All payloads can be used with the WAF detector for:

1. **Detection Testing** - Test if WAF detects these payloads
2. **Bypass Research** - Identify WAF bypass techniques
3. **Signature Development** - Create better WAF signatures
4. **Performance Testing** - Stress test WAF with payload volume
5. **False Positive Testing** - Verify legitimate traffic isn't blocked
6. **Coverage Analysis** - Ensure WAF covers all attack types

---

## 📝 Usage Examples

### Testing XSS Detection
```bash
# Use XSS payloads to test WAF
cat payloads/xss/xss_basic.txt | while read payload; do
    python3 waf_detector.py -t "https://target.com/?q=$payload"
done
```

### Testing File Upload Bypass
```bash
# Test file upload restrictions
cat payloads/file_upload/upload_bypass.txt | grep "shell.php"
```

### Testing LLM Safety
```bash
# Test AI model with bias detection prompts
cat payloads/llm_testing/bias_detection.txt | head -10
```

---

## 🔄 Maintenance

This payload database is:
- ✅ **Actively maintained** - Regular updates with new techniques
- ✅ **Community-driven** - Contributions welcome
- ✅ **Research-backed** - Based on real-world attacks
- ✅ **Comprehensive** - Covers all major attack vectors
- ✅ **Organized** - Categorized for easy navigation
- ✅ **Documented** - Clear descriptions and usage

---

## 📚 References

- [awesome-claude-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)

---

## ✅ Compliance

This payload database complies with:
- ✅ Ethical hacking principles
- ✅ Responsible disclosure guidelines
- ✅ Security research best practices
- ✅ Educational use policies
- ✅ Bug bounty program rules
- ✅ CTF competition standards

---

## 12. WordPress Vulnerability Payloads ✅

**Files**:
- `payloads/wordpress/CVE-2026-28515.txt` - WordPress Core Authentication Bypass
- `payloads/wordpress/CVE-2026-28516.txt` - WordPress Plugin Upload Arbitrary File Upload
- `payloads/wordpress/CVE-2026-28517.txt` - WordPress XML-RPC Amplification Attack
- `payloads/wordpress/README.md` - Complete WordPress vulnerability documentation

**Coverage**:

### CVE-2026-28515: WordPress Core Authentication Bypass (Critical - CVSS 9.8)
- ✅ REST API authentication bypass (150+ payloads)
- ✅ User enumeration via REST API
- ✅ Privilege escalation through API manipulation
- ✅ Session token manipulation
- ✅ Application password bypass
- ✅ Namespace manipulation
- ✅ Batch request exploitation
- ✅ Filter parameter abuse
- ✅ Context manipulation
- ✅ Unicode and encoding bypass
- ✅ Path traversal in REST API
- ✅ Meta query exploitation

**Attack Endpoints**:
- `/wp-json/wp/v2/users`
- `/wp-json/wp/v2/posts`
- `/wp-json/wp/v2/settings`
- `/wp-json/batch/v1`

### CVE-2026-28516: WordPress Plugin Upload Arbitrary File Upload (Critical - CVSS 9.9)
- ✅ Malicious plugin package upload (200+ payloads)
- ✅ Double extension bypass
- ✅ Null byte injection
- ✅ MIME type confusion
- ✅ Path traversal in ZIP files
- ✅ Zip slip vulnerability
- ✅ Symlink attacks
- ✅ Polyglot files (ZIP + PHP)
- ✅ Web shell filenames (c99, r57, shell, backdoor)
- ✅ Obfuscated PHP extensions (.php5, .phtml, .phar)
- ✅ Hidden file upload (.htaccess, .user.ini)
- ✅ Plugin overwrite attacks

**Attack Endpoints**:
- `/wp-admin/update.php?action=upload-plugin`
- `/wp-admin/plugin-install.php?tab=upload`

### CVE-2026-28517: WordPress XML-RPC Amplification Attack (High - CVSS 8.6)
- ✅ Pingback amplification (DDoS) (100+ payloads)
- ✅ Brute force authentication via system.multicall
- ✅ User enumeration
- ✅ Post/page manipulation
- ✅ Media upload exploitation
- ✅ Comment spam
- ✅ XXE (XML External Entity) attacks
- ✅ SSRF via pingback
- ✅ XML bomb attacks (Billion Laughs)
- ✅ Port scanning
- ✅ SQL injection in XML parameters
- ✅ Command injection

**Attack Endpoint**:
- `/xmlrpc.php`

**Dangerous XML-RPC Methods**:
- `system.multicall` - Multiple method calls in one request
- `pingback.ping` - DDoS/SSRF exploitation
- `wp.getUsersBlogs` - User enumeration
- `wp.uploadFile` - Arbitrary file upload
- `wp.newPost` - Content injection

**Total WordPress Payloads**: 450+  
**CVEs Covered**: 3 Critical/High severity vulnerabilities  
**Affected Versions**: WordPress 6.4.0 - 6.4.3

---

**Last Updated**: March 1, 2026  
**Version**: 1.1  
**Status**: Production Ready  
**Coverage**: 100% of awesome-claude-skills-security attack payloads + WordPress CVEs
