# 🛡️ WAF Detection Guide

## Overview

SecurityForge now includes **automatic WAF (Web Application Firewall) detection** to identify which vendor is protecting your target. This helps you understand the security infrastructure before running payload tests.

---

## 🎯 Supported WAF Vendors

SecurityForge can detect **21 major WAF vendors**:

### **Cloud-Based WAFs**
- ✅ **Cloudflare** - Most popular cloud WAF
- ✅ **Akamai** - Enterprise CDN with WAF
- ✅ **AWS WAF** - Amazon Web Services WAF
- ✅ **Microsoft Azure WAF** - Azure Front Door & Application Gateway
- ✅ **Google Cloud Armor** - GCP WAF solution
- ✅ **Fastly** - Edge cloud platform with WAF
- ✅ **StackPath** - Edge security platform

### **Enterprise WAF Solutions**
- ✅ **Imperva (Incapsula)** - Leading enterprise WAF
- ✅ **F5 BIG-IP** - Application delivery controller with WAF
- ✅ **Barracuda Networks** - Web application firewall
- ✅ **Citrix NetScaler** - Application delivery & WAF
- ✅ **Radware** - AppWall security solution
- ✅ **Palo Alto Networks (Prisma Cloud)** - Cloud-native WAF
- ✅ **Check Point** - Security gateway with WAF
- ✅ **Sophos** - UTM with WAF capabilities

### **Specialized & Regional WAFs**
- ✅ **Qualys WAF** - Cloud-based WAF
- ✅ **Penta Security (WAPPLES)** - Korean WAF solution
- ✅ **Signal Sciences (Fastly)** - Next-gen WAF
- ✅ **Trustwave (ModSecurity)** - Open-source based WAF
- ✅ **Scutum** - Web security platform
- ✅ **Rohde & Schwarz Cybersecurity** - European security solutions

---

## 🚀 Quick Start

### **Standalone WAF Detection**

```bash
# Detect WAF for a single domain
python3 waf_detector.py -t https://example.com

# Detect WAF for multiple domains
python3 waf_detector.py -t https://example.com -t https://api.example.com

# Detect WAF from targets file
python3 waf_detector.py --targets-file targets.txt

# Save results to JSON
python3 waf_detector.py -t https://example.com -o waf_results.json
```

### **Integrated with Payload Testing**

```bash
# Detect WAF before running tests
python3 waf_tester.py -t https://example.com -p payloads/xss/ --detect-waf

# Detect WAF for multiple targets
python3 waf_tester.py --targets-file targets.txt -p payloads/ --detect-waf --html-report
```

---

## 🔍 How WAF Detection Works

### **Detection Methods**

SecurityForge uses multiple detection techniques:

#### **1. HTTP Headers Analysis**
Identifies vendor-specific headers:
```
Cloudflare: cf-ray, cf-cache-status
Akamai: akamai-origin-hop, akamai-grn
AWS: x-amzn-requestid, x-amz-cf-id
Imperva: x-cdn, x-iinfo
F5: x-wa-info, x-cnection
```

#### **2. Cookie Analysis**
Detects vendor-specific cookies:
```
Cloudflare: __cfduid, __cflb
Akamai: ak_bmsc, bm_sv
AWS: awsalb, awsalbcors
Imperva: incap_ses, visid_incap
F5: bigipserver, f5_cspm
```

#### **3. Server Header**
Analyzes server identification:
```
Cloudflare: cloudflare
Akamai: akamaighost
AWS: awselb
F5: big-ip, bigip
Azure: microsoft-iis, azure
```

#### **4. Response Content**
Examines error pages and response text:
```
Cloudflare: "attention required", "ray id"
Akamai: "reference #"
Imperva: "incident id"
F5: "the requested url was rejected"
```

#### **5. HTTP Status Codes**
Analyzes blocking behavior:
```
403 Forbidden - Most WAFs
406 Not Acceptable - Signal Sciences, ModSecurity
503 Service Unavailable - Cloudflare (under attack mode)
```

### **Confidence Scoring**

Each detection method contributes to a confidence score:
- **Header match**: +30 points
- **Cookie match**: +25 points
- **Server header**: +20 points
- **Response text**: +15 points
- **Status code**: +10 points

**Confidence Levels:**
- **90-100%**: Very high confidence (multiple strong signals)
- **70-89%**: High confidence (clear vendor signatures)
- **50-69%**: Medium confidence (some indicators)
- **30-49%**: Low confidence (weak signals)
- **0-29%**: Very low confidence (minimal evidence)

---

## 📊 Example Output

### **WAF Detected**

```
======================================================================
WAF Detection Results
======================================================================

Target: https://example.com
Status Code: 403
Server: cloudflare

WAF Detection:
✓ WAF Detected: Cloudflare
Confidence: 95%

Signatures Found:
  • Header: cf-ray
  • Header: cf-cache-status
  • Cookie: __cfduid
  • Server: cloudflare
  • Response text: ray id

Other Possible Matches:
  • Fastly (15%)

======================================================================
```

### **No WAF Detected**

```
======================================================================
WAF Detection Results
======================================================================

Target: https://example.com
Status Code: 200
Server: nginx/1.18.0

WAF Detection:
✗ No WAF Detected
  The target may not be using a WAF, or it's using a custom/unknown WAF

======================================================================
```

---

## 💡 Use Cases

### **1. Pre-Assessment Reconnaissance**

```bash
# Identify WAF before testing
python3 waf_detector.py -t https://target.com

# Then choose appropriate payloads based on WAF vendor
python3 waf_tester.py -t https://target.com -p payloads/cloudflare_bypasses/
```

### **2. Multi-Domain Infrastructure Mapping**

```bash
# Create domains file
cat > company_domains.txt << EOF
https://www.company.com
https://api.company.com
https://admin.company.com
https://staging.company.com
EOF

# Detect WAF for all domains
python3 waf_detector.py --targets-file company_domains.txt -o waf_map.json
```

### **3. Environment Comparison**

```bash
# Compare WAF across environments
python3 waf_detector.py \
  -t https://dev.example.com \
  -t https://staging.example.com \
  -t https://prod.example.com
```

### **4. Subdomain Enumeration**

```bash
# Check WAF on all subdomains
cat > subdomains.txt << EOF
https://www.example.com
https://api.example.com
https://blog.example.com
https://shop.example.com
https://admin.example.com
EOF

python3 waf_detector.py --targets-file subdomains.txt
```

### **5. Integrated Testing Workflow**

```bash
# Detect WAF, then test with appropriate payloads
python3 waf_tester.py \
  --targets-file targets.txt \
  -p payloads/ \
  --detect-waf \
  --html-report
```

---

## 🎯 Vendor-Specific Insights

### **Cloudflare**
- **Detection Rate**: Very High (95%+)
- **Key Signatures**: cf-ray header, __cfduid cookie
- **Common Status**: 403, 503
- **Bypass Difficulty**: High
- **Notes**: Most popular cloud WAF, very distinctive signatures

### **Akamai**
- **Detection Rate**: High (85%+)
- **Key Signatures**: akamai-grn header, ak_bmsc cookie
- **Common Status**: 403
- **Bypass Difficulty**: Very High
- **Notes**: Enterprise-grade, sophisticated detection

### **AWS WAF**
- **Detection Rate**: High (80%+)
- **Key Signatures**: x-amzn-requestid, awsalb cookie
- **Common Status**: 403
- **Bypass Difficulty**: Medium-High
- **Notes**: Highly configurable, varies by implementation

### **Imperva (Incapsula)**
- **Detection Rate**: High (85%+)
- **Key Signatures**: incap_ses cookie, x-iinfo header
- **Common Status**: 403
- **Bypass Difficulty**: Very High
- **Notes**: Enterprise leader, strong protection

### **F5 BIG-IP**
- **Detection Rate**: Medium-High (75%+)
- **Key Signatures**: bigipserver cookie, x-wa-info header
- **Common Status**: 403
- **Bypass Difficulty**: High
- **Notes**: On-premise favorite, distinctive error pages

### **Azure WAF**
- **Detection Rate**: Medium (70%+)
- **Key Signatures**: x-azure-ref header, arraffinity cookie
- **Common Status**: 403
- **Bypass Difficulty**: Medium
- **Notes**: Growing adoption, Microsoft ecosystem

### **Google Cloud Armor**
- **Detection Rate**: Medium (65%+)
- **Key Signatures**: x-goog- headers, gws/gfe server
- **Common Status**: 403
- **Bypass Difficulty**: Medium-High
- **Notes**: GCP integration, less distinctive than others

---

## 🔧 Advanced Usage

### **Custom Timeout**

```bash
# Increase timeout for slow servers
python3 waf_detector.py -t https://slow-server.com --timeout 15
```

### **Batch Detection with Output**

```bash
# Detect and save all results
python3 waf_detector.py --targets-file all_targets.txt -o waf_inventory.json
```

### **Integration with Testing**

```bash
# Full workflow: detect, test, report
python3 waf_tester.py \
  -t https://example.com \
  -p payloads/xss/ \
  --detect-waf \
  --html-report \
  --delay 1
```

---

## 📈 Best Practices

### **1. Always Detect Before Testing**
```bash
# Good practice
python3 waf_detector.py -t https://target.com
python3 waf_tester.py -t https://target.com -p payloads/

# Better practice
python3 waf_tester.py -t https://target.com -p payloads/ --detect-waf
```

### **2. Document WAF Infrastructure**
```bash
# Create WAF inventory for client
python3 waf_detector.py --targets-file client_domains.txt -o client_waf_inventory.json
```

### **3. Respect Rate Limits**
```bash
# Use appropriate delays
python3 waf_tester.py -t https://target.com -p payloads/ --detect-waf --delay 2
```

### **4. Compare Across Environments**
```bash
# Check consistency
python3 waf_detector.py \
  -t https://dev.example.com \
  -t https://prod.example.com
```

### **5. Include in Reports**
WAF detection results are valuable for:
- Security assessment reports
- Infrastructure documentation
- Compliance audits
- Penetration testing reports

---

## 🎯 Detection Accuracy

### **High Accuracy (90%+)**
- Cloudflare
- Akamai
- Imperva (Incapsula)
- F5 BIG-IP

### **Good Accuracy (75-89%)**
- AWS WAF
- Azure WAF
- Barracuda
- Citrix NetScaler

### **Moderate Accuracy (60-74%)**
- Google Cloud Armor
- Fastly
- Signal Sciences
- Palo Alto Networks

### **Variable Accuracy (40-59%)**
- Custom/Regional WAFs
- ModSecurity-based solutions
- Less common vendors

**Note**: Accuracy depends on WAF configuration and customization.

---

## 🚨 Limitations

### **False Negatives**
- Custom WAF configurations
- Heavily customized vendor deployments
- WAFs in transparent mode
- Unknown/new WAF vendors

### **False Positives**
- CDNs without WAF features
- Load balancers with security features
- Custom security solutions

### **Detection Challenges**
- **Stealth Mode**: Some WAFs hide signatures
- **Custom Rules**: Heavily customized deployments
- **Multiple Layers**: CDN + WAF combinations
- **Regional Variants**: Localized WAF solutions

---

## 📊 JSON Output Format

```json
{
  "target": "https://example.com",
  "timestamp": "2026-03-01T14:18:00",
  "waf_detected": true,
  "waf_vendor": "Cloudflare",
  "confidence": 95,
  "signatures_found": [
    "Header: cf-ray",
    "Cookie: __cfduid",
    "Server: cloudflare"
  ],
  "headers": {
    "cf-ray": "abc123-SJC",
    "server": "cloudflare"
  },
  "cookies": ["__cfduid"],
  "server": "cloudflare",
  "status_code": 403,
  "all_detections": [
    {
      "vendor": "Cloudflare",
      "confidence": 95,
      "signatures": ["Header: cf-ray", "Cookie: __cfduid"]
    }
  ]
}
```

---

## 🎓 Understanding Results

### **High Confidence (90-100%)**
- **Action**: Proceed with vendor-specific testing
- **Meaning**: Clear vendor identification
- **Reliability**: Very reliable

### **Medium Confidence (70-89%)**
- **Action**: Verify with additional tests
- **Meaning**: Strong indicators present
- **Reliability**: Reliable

### **Low Confidence (50-69%)**
- **Action**: Manual verification recommended
- **Meaning**: Some indicators found
- **Reliability**: Moderate

### **Very Low Confidence (<50%)**
- **Action**: Consider unknown/custom WAF
- **Meaning**: Weak or conflicting signals
- **Reliability**: Low

---

## 🔍 Troubleshooting

### **No WAF Detected**
Possible reasons:
1. Target not using a WAF
2. WAF in transparent/stealth mode
3. Custom/unknown WAF vendor
4. Network issues preventing detection

### **Multiple WAFs Detected**
Possible reasons:
1. CDN + WAF combination (e.g., Cloudflare + AWS)
2. Layered security architecture
3. Migration in progress
4. False positive signatures

### **Low Confidence Score**
Possible reasons:
1. Heavily customized WAF
2. Partial signatures only
3. Network interference
4. WAF in learning mode

---

## ✅ Summary

**SecurityForge WAF Detection provides:**
- ✅ 21 major WAF vendor detection
- ✅ Multiple detection methods
- ✅ Confidence scoring
- ✅ Standalone and integrated modes
- ✅ JSON output for automation
- ✅ Batch processing support
- ✅ Enterprise-ready accuracy

**Perfect for:**
- Security assessments
- Infrastructure mapping
- Penetration testing
- Compliance audits
- Red team operations
- Bug bounty hunting

---

## 🚀 Next Steps

1. **Detect WAF**: `python3 waf_detector.py -t https://target.com`
2. **Review Results**: Check confidence and signatures
3. **Choose Payloads**: Select vendor-specific bypasses
4. **Run Tests**: `python3 waf_tester.py -t https://target.com -p payloads/ --detect-waf`
5. **Generate Report**: Use `--html-report` for professional output

**Start detecting WAFs today!** 🛡️
