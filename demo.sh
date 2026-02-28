#!/bin/bash
# Demo script showing WAF Tester usage

echo "=================================="
echo "WAF Tester Demo"
echo "=================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo ""

# Demo 1: Interactive mode
echo "📝 Demo 1: Interactive Mode"
echo "Run: python3 waf_tester.py -i"
echo "This will guide you through testing step-by-step"
echo ""

# Demo 2: Quick XSS test
echo "📝 Demo 2: Quick XSS Test (10 payloads)"
echo "Run: python3 waf_tester.py -t https://example.com -p payloads/xss/basic.json --max 10"
echo ""

# Demo 3: Comprehensive test
echo "📝 Demo 3: Comprehensive XSS Test"
echo "Run: python3 waf_tester.py -t https://example.com -p payloads/xss/"
echo ""

# Demo 4: Docker
echo "📝 Demo 4: Docker (if installed)"
if command -v docker &> /dev/null; then
    echo "✅ Docker found"
    echo "Build: docker build -t waf-tester ."
    echo "Run: docker run -it --rm waf-tester"
else
    echo "⚠️  Docker not installed (optional)"
fi
echo ""

echo "=================================="
echo "Ready to start testing!"
echo "=================================="
echo ""
echo "Quick start: python3 waf_tester.py -i"
echo "Documentation: cat QUICKSTART.md"
echo ""
