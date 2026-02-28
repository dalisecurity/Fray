# AI-Powered PR Review Setup Guide

This repository uses **CodeRabbit** and **Snyk** for automated AI-powered pull request reviews.

## 🤖 What's Included

### 1. CodeRabbit (AI Code Review)
- **Purpose**: Intelligent code review with security focus
- **Features**: 
  - Line-by-line code analysis
  - JSON payload validation
  - CVE format checking
  - Documentation review
  - Security best practices
- **Cost**: FREE for open-source projects

### 2. Snyk (Security Scanning)
- **Purpose**: Vulnerability detection and dependency scanning
- **Features**:
  - Dependency vulnerability scanning
  - Code security analysis
  - License compliance
  - Automated fix suggestions
- **Cost**: FREE for open-source projects

---

## 🚀 Setup Instructions

### Step 1: Enable CodeRabbit

1. **Install CodeRabbit App**:
   - Go to: https://github.com/apps/coderabbitai
   - Click "Install"
   - Select "dalisecurity/waf-payload-arsenal"
   - Grant required permissions

2. **Configuration**:
   - Already configured in `.github/coderabbit.yml`
   - No additional setup needed!

3. **Test**:
   - Create a test PR
   - CodeRabbit will automatically review within 1-2 minutes
   - Look for comments from @coderabbitai

### Step 2: Enable Snyk

1. **Create Snyk Account**:
   - Go to: https://snyk.io/
   - Sign up with GitHub account
   - It's FREE for open-source

2. **Connect Repository**:
   - In Snyk dashboard, click "Add project"
   - Select "GitHub"
   - Choose "dalisecurity/waf-payload-arsenal"
   - Click "Add selected repositories"

3. **Get Snyk Token**:
   - Go to: https://app.snyk.io/account
   - Copy your API token

4. **Add Token to GitHub**:
   - Go to: https://github.com/dalisecurity/waf-payload-arsenal/settings/secrets/actions
   - Click "New repository secret"
   - Name: `SNYK_TOKEN`
   - Value: [paste your Snyk API token]
   - Click "Add secret"

5. **Test**:
   - Push a commit or create a PR
   - Snyk will scan automatically
   - Check the "Security" tab for results

---

## 📋 What Gets Reviewed

### CodeRabbit Reviews:

**For JSON Payloads** (`payloads/**/*.json`):
- ✅ JSON syntax validity
- ✅ Required fields present
- ✅ CVE format validation (CVE-YYYY-NNNNN)
- ✅ CVSS score accuracy
- ✅ Payload safety
- ✅ Proper categorization
- ✅ Source attribution

**For Python Code** (`**/*.py`):
- ✅ Security vulnerabilities
- ✅ Input validation
- ✅ Error handling
- ✅ Code injection risks
- ✅ Path traversal prevention
- ✅ Python best practices

**For Documentation** (`**/*.md`):
- ✅ Documentation clarity
- ✅ Legal disclaimers
- ✅ Ethical use guidelines
- ✅ Technical accuracy
- ✅ Markdown formatting

### Snyk Scans:

- ✅ Dependency vulnerabilities
- ✅ Code security issues
- ✅ License compliance
- ✅ Known CVEs in dependencies
- ✅ Outdated packages

---

## 🎯 How It Works

### When You Create a PR:

1. **CodeRabbit** (1-2 minutes):
   - Reviews all changed files
   - Posts line-by-line comments
   - Provides high-level summary
   - Suggests improvements

2. **Snyk** (2-3 minutes):
   - Scans for vulnerabilities
   - Checks dependencies
   - Posts security findings
   - Suggests fixes

3. **GitHub Actions** (1 minute):
   - Validates JSON files
   - Counts payloads
   - Checks documentation

### Example PR Review Flow:

```
1. You create PR
   ↓
2. CodeRabbit reviews code (auto-comment)
   ↓
3. Snyk scans security (auto-comment)
   ↓
4. GitHub Actions validate (status check)
   ↓
5. You address feedback
   ↓
6. Maintainer approves & merges
```

---

## 💬 Interacting with CodeRabbit

### Commands:

- `@coderabbitai summary` - Generate PR summary
- `@coderabbitai review` - Re-review the PR
- `@coderabbitai resolve` - Mark conversation as resolved
- `@coderabbitai help` - Show available commands

### Example:

```markdown
@coderabbitai Can you explain why this payload might be unsafe?
```

CodeRabbit will respond with detailed analysis!

---

## 🔧 Customization

### Modify CodeRabbit Behavior:

Edit `.github/coderabbit.yml`:

```yaml
reviews:
  auto_review:
    enabled: true  # Change to false to disable auto-review
  
  path_instructions:
    - path: "payloads/**/*.json"
      instructions: |
        Your custom review instructions here
```

### Modify Snyk Behavior:

Edit `.github/workflows/snyk-security.yml`:

```yaml
with:
  args: --severity-threshold=high  # Change to medium or low
```

---

## 📊 Monitoring

### CodeRabbit:
- View reviews in PR comments
- Check review status in PR checks
- See statistics in CodeRabbit dashboard

### Snyk:
- View results in "Security" tab
- Check Snyk dashboard: https://app.snyk.io/
- Review findings in PR comments

---

## 🐛 Troubleshooting

### CodeRabbit Not Reviewing:

1. Check if CodeRabbit app is installed
2. Verify repository permissions
3. Check `.github/coderabbit.yml` syntax
4. Try `@coderabbitai review` command

### Snyk Not Running:

1. Verify `SNYK_TOKEN` secret is set
2. Check Snyk workflow syntax
3. Ensure repository is connected in Snyk dashboard
4. Check GitHub Actions logs

### Both Not Working:

1. Check GitHub Actions are enabled
2. Verify branch protection rules
3. Check repository permissions
4. Review workflow logs

---

## 📚 Additional Resources

- **CodeRabbit Docs**: https://docs.coderabbit.ai/
- **Snyk Docs**: https://docs.snyk.io/
- **GitHub Actions**: https://docs.github.com/actions

---

## ✅ Quick Checklist

After setup, verify:

- [ ] CodeRabbit app installed
- [ ] Snyk token added to secrets
- [ ] Test PR created
- [ ] CodeRabbit reviewed test PR
- [ ] Snyk scanned test PR
- [ ] GitHub Actions passed
- [ ] Security tab shows Snyk results

---

**Setup Time**: ~5 minutes  
**Maintenance**: Zero (fully automated)  
**Cost**: FREE for open-source

**Questions?** Open an issue or check the documentation links above.
