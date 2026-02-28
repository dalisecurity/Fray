# Contributing to WAF Payload Database

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## 🎯 Ways to Contribute

1. **Add New Payloads**: Submit new attack vectors and bypass techniques
2. **Improve Classification**: Help organize and categorize existing payloads
3. **Enhance Tools**: Improve testing and analysis tools
4. **Documentation**: Add or improve documentation
5. **Bug Reports**: Report issues or inaccuracies
6. **Feature Requests**: Suggest new features or improvements

## 📋 Contribution Guidelines

### Adding Payloads

When submitting new payloads, please follow this format:

```json
{
  "id": "xss-001",
  "category": "xss",
  "subcategory": "basic",
  "payload": "<script>alert(1)</script>",
  "description": "Basic script tag XSS",
  "technique": "direct_injection",
  "encoding": "none",
  "tags": ["script", "alert", "basic"],
  "source": "Original/URL/Reference",
  "tested_against": ["cloudflare", "aws_waf"],
  "success_rate": 0.0,
  "severity": "high",
  "notes": "Additional context or observations"
}
```

### Payload Requirements

- **Unique**: Ensure the payload isn't already in the database
- **Documented**: Include description and technique explanation
- **Tested**: Indicate which WAFs it was tested against
- **Ethical**: Only include payloads from authorized testing
- **Sourced**: Credit original researchers when applicable

### File Organization

Place payloads in the appropriate directory:

```
payloads/
├── xss/
│   ├── basic.json          # Simple, straightforward XSS
│   ├── encoded.json        # Encoded variations
│   ├── obfuscated.json     # Obfuscation techniques
│   └── advanced.json       # Complex/novel techniques
├── sqli/
├── command-injection/
└── ...
```

## 🔧 Development Setup

1. **Fork the repository**
2. **Clone your fork**:
   ```bash
   git clone https://github.com/dalisecurity/waf-payload-database.git
   cd waf-payload-database
   ```
3. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## ✅ Pull Request Process

1. **Update Documentation**: Ensure README and docs reflect your changes
2. **Test Your Changes**: Run validation scripts
3. **Follow Style Guide**: Maintain consistent formatting
4. **Write Clear Commits**: Use descriptive commit messages
5. **Submit PR**: Provide detailed description of changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] New payloads
- [ ] Bug fix
- [ ] Documentation
- [ ] Tool improvement
- [ ] Other (specify)

## Payloads Added
- Category: XSS
- Count: 50
- Technique: Obfuscation

## Testing
- [ ] Validated JSON format
- [ ] Tested payloads (if applicable)
- [ ] Updated documentation
- [ ] Ran validation scripts

## Additional Notes
Any additional context or information
```

## 🧪 Testing Guidelines

Before submitting:

1. **Validate JSON**:
   ```bash
   python scripts/validate_json.py payloads/xss/your_file.json
   ```

2. **Run Tests**:
   ```bash
   pytest tests/
   ```

3. **Check Formatting**:
   ```bash
   python scripts/format_check.py
   ```

## 📝 Commit Message Guidelines

Use clear, descriptive commit messages:

```
feat: Add 50 new SVG-based XSS payloads
fix: Correct classification of polyglot payloads
docs: Update methodology documentation
refactor: Improve payload classifier performance
test: Add unit tests for analyzer tool
```

Prefixes:
- `feat`: New feature or payloads
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

## 🔒 Security and Ethics

### Ethical Guidelines

1. **Authorization Required**: Only test systems you own or have permission to test
2. **Responsible Disclosure**: Follow proper disclosure practices
3. **No Malicious Use**: Do not use for unauthorized access or harm
4. **Respect Scope**: Honor bug bounty program rules
5. **Legal Compliance**: Follow all applicable laws

### Reporting Security Issues

If you discover a security issue in this repository:

1. **Do NOT** open a public issue
2. Email: security@example.com (replace with actual contact)
3. Include detailed description and reproduction steps
4. Allow time for response before public disclosure

## 📊 Code Style

### Python Code

- Follow PEP 8
- Use type hints
- Write docstrings for functions
- Keep functions focused and small

Example:
```python
def classify_payload(payload: str, category: str) -> dict:
    """
    Classify a payload by technique and encoding.
    
    Args:
        payload: The payload string to classify
        category: The attack category (xss, sqli, etc.)
    
    Returns:
        Dictionary containing classification details
    """
    # Implementation
    pass
```

### JSON Format

- Use 2-space indentation
- Sort keys alphabetically
- Include all required fields
- Validate against schema

## 🎓 Learning Resources

New to security testing? Check these resources:

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bug Bounty Bootcamp](https://nostarch.com/bug-bounty-bootcamp)

## 🏆 Recognition

Contributors will be recognized in:
- README.md acknowledgments
- CONTRIBUTORS.md file
- Release notes

## 📞 Getting Help

- **Questions**: Open a GitHub Discussion
- **Issues**: Create a GitHub Issue
- **Chat**: Join our Discord/Slack (if applicable)

## 📜 Code of Conduct

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Publishing others' private information
- Unethical use of payloads

## 🔄 Review Process

1. **Automated Checks**: CI/CD runs validation
2. **Maintainer Review**: Core team reviews changes
3. **Community Feedback**: Others may comment
4. **Approval**: Requires 1-2 approvals
5. **Merge**: Merged into main branch

## 📅 Release Cycle

- **Minor releases**: Monthly (new payloads, small features)
- **Major releases**: Quarterly (significant changes)
- **Hotfixes**: As needed (critical bugs)

## 🙏 Thank You

Your contributions help make the web more secure. Thank you for being part of this community!

---

Questions? Open an issue or discussion on GitHub.
