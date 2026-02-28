# Docker Usage Guide

Run WAF Tester in a containerized environment for easy portability and sharing.

## 🐳 Quick Start with Docker

### Build the Image

```bash
cd waf-payload-database
docker build -t waf-tester .
```

### Run Interactive Mode

```bash
docker run -it --rm waf-tester
```

### Run with Command Line

```bash
docker run --rm waf-tester -t https://example.com -p payloads/xss/basic.json
```

### Save Reports

```bash
# Create reports directory
mkdir reports

# Run with volume mount
docker run --rm -v $(pwd)/reports:/app/reports waf-tester \
  -t https://example.com \
  -p payloads/xss/basic.json \
  -o /app/reports/report.json
```

## 🚀 Docker Compose

### Start Interactive Mode

```bash
docker-compose run --rm waf-tester
```

### Run Specific Test

Edit `docker-compose.yml` to uncomment and modify the command line:

```yaml
command: ["-t", "https://your-target.com", "-p", "payloads/xss/basic.json"]
```

Then run:

```bash
docker-compose up
```

## 📦 Pre-built Image (Coming Soon)

Pull from Docker Hub:

```bash
docker pull dalisecurity/waf-tester:latest
docker run -it --rm dalisecurity/waf-tester
```

## 🔧 Advanced Usage

### Custom Payload Files

```bash
docker run --rm \
  -v $(pwd)/custom-payloads:/app/custom \
  waf-tester \
  -t https://example.com \
  -p /app/custom/my-payloads.json
```

### Network Configuration

```bash
# Use host network
docker run --rm --network host waf-tester -t https://example.com -p payloads/xss/basic.json

# Use specific network
docker run --rm --network my-network waf-tester -t https://example.com -p payloads/xss/basic.json
```

### Environment Variables

```bash
docker run --rm \
  -e TARGET=https://example.com \
  -e PAYLOADS=payloads/xss/basic.json \
  waf-tester
```

## 🎯 Use Cases

### 1. Share with Team

Build once, share the image:

```bash
# Build
docker build -t waf-tester .

# Save to file
docker save waf-tester > waf-tester.tar

# Share waf-tester.tar with colleagues

# They load it
docker load < waf-tester.tar

# They run it
docker run -it --rm waf-tester
```

### 2. CI/CD Integration

```yaml
# .github/workflows/waf-test.yml
name: WAF Testing

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build Docker image
        run: docker build -t waf-tester .
      - name: Run WAF tests
        run: |
          docker run --rm waf-tester \
            -t ${{ secrets.TEST_TARGET }} \
            -p payloads/xss/basic.json \
            -o report.json
```

### 3. Automated Testing

```bash
#!/bin/bash
# test-all.sh

targets=(
  "https://site1.example.com"
  "https://site2.example.com"
  "https://site3.example.com"
)

for target in "${targets[@]}"; do
  echo "Testing $target..."
  docker run --rm \
    -v $(pwd)/reports:/app/reports \
    waf-tester \
    -t "$target" \
    -p payloads/xss/ \
    -o "/app/reports/$(echo $target | sed 's/https:\/\///g' | sed 's/\//_/g').json"
done
```

## 🛠️ Troubleshooting

### Permission Issues

```bash
# Run as current user
docker run --rm --user $(id -u):$(id -g) waf-tester
```

### Network Issues

```bash
# Use host network
docker run --rm --network host waf-tester -t https://example.com -p payloads/xss/basic.json
```

### Volume Mount Issues

```bash
# Use absolute path
docker run --rm -v /absolute/path/to/reports:/app/reports waf-tester
```

## 📊 Image Details

- **Base Image**: python:3.11-slim
- **Size**: ~150MB
- **Python Version**: 3.11
- **Dependencies**: None (uses standard library)

## 🔒 Security Considerations

- Container runs as root by default (can be changed with --user)
- No sensitive data stored in image
- Network access required for testing
- Reports saved to mounted volumes

---

**Happy containerized testing! 🐳**
