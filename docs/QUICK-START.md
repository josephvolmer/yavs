# YAVS Quick Start Guide

**Yet Another Vulnerability Scanner** - AI-Enhanced Security Scanning with Policy-as-Code

---

## Installation

```bash
pip install yavs

# Install optional scanners for full coverage
pip install bandit semgrep safety
npm install -g eslint
# For IaC scanning
brew install terrascan  # or download from GitHub
# For Azure templates
# Download template-analyzer from Microsoft
```

---

## Basic Usage

### 1. Simple Scan (Auto-Detect)

```bash
# Automatically detect languages and run appropriate scanners
yavs scan .
```

### 2. Scan with All Features

```bash
# Comprehensive scan with all 8 new features
yavs scan . \
  --auto \
  --all \
  --blame \
  --baseline .yavs-baseline.yaml \
  --policy src/yavs/policy/builtins/security.yaml \
  --policy-mode enforce \
  --fail-on HIGH \
  --fail-fast \
  --csv findings.csv \
  --output-dir results
```

### 3. Export Results

```bash
# Export to CSV
yavs scan . --csv findings.csv

# Export to TSV
yavs scan . --tsv findings.tsv

# Multiple formats
yavs scan . --csv findings.csv --output-dir results
# Creates: results/yavs-results.sarif, results/scan-results.json, results/report.html
```

---

## Feature Highlights

### 🎯 Auto-Detect Mode

Automatically detects your project languages and runs appropriate scanners:

```bash
yavs scan . --auto --all
```

**Detects**:
- Python, JavaScript, Java, Go, Ruby, PHP, C/C++, C#, Rust
- Terraform, ARM/Bicep, Kubernetes
- npm, pip, Maven, Bundler, Composer dependencies
- Secrets in code

### 📊 CSV/TSV Export

Export findings with 24 comprehensive columns:

```bash
yavs scan . --csv findings.csv --tsv findings.tsv
```

**Includes**:
- Basic fields: severity, tool, category, title, file, line
- Vulnerability details: CVE, CVSS, CWE, fix version
- Git blame: author, email, commit, date
- Policy: suppressed, tags, rule
- Baseline: suppression status and reason

### 🔍 Git Blame Tracking

Identify who introduced each vulnerability:

```bash
yavs scan . --blame --csv findings.csv
```

**Output includes**:
- Git author name
- Git author email
- Commit hash
- Commit date

### 📋 Policy-as-Code

Define security policies in YAML:

```bash
yavs scan . \
  --policy policies/security.yaml \
  --policy-mode enforce
```

**Example policy** (`policies/security.yaml`):

```yaml
version: "1.0"
name: "Security Policy"
rules:
  # Suppress low severity
  - id: "SEC-001"
    conditions:
      - field: "severity"
        operator: "in"
        value: ["LOW", "INFO"]
    action: "suppress"
    reason: "Low severity auto-suppressed"

  # Fail on critical
  - id: "SEC-002"
    conditions:
      - field: "severity"
        operator: "equals"
        value: "CRITICAL"
    action: "fail"

  # Tag SQL injection
  - id: "SEC-003"
    conditions:
      - field: "title"
        operator: "regex"
        value: "(?i)sql.*injection"
    action: "tag"
    tags: ["sql", "high-priority"]
```

**Policy Modes**:
- `enforce`: Fail build on policy violations
- `audit`: Report violations but don't fail build
- `off`: Disable policy evaluation

### 🚫 Baseline Management

Suppress known issues with expiring baselines:

```bash
# Create baseline
yavs scan . --save-baseline .yavs-baseline.yaml

# Use baseline with expiration
yavs scan . --baseline .yavs-baseline.yaml
```

**Baseline with expiration** (`.yavs-baseline.yaml`):

```yaml
version: "1.0"
created: "2025-01-01"
expires: "2025-06-01"  # Auto-expire after 6 months
suppressions:
  - fingerprint: "abc123..."
    reason: "False positive - reviewed by security team"
```

### ⚡ Fast-Fail Mode

Exit immediately when critical issues are found (saves CI/CD time):

```bash
yavs scan . --fail-on HIGH --fail-fast
```

**Behavior**:
- Exits as soon as threshold is exceeded
- Saves remaining scan time
- Still exports partial results

### 🏗️ Infrastructure-as-Code Scanning

Automatically detects and scans IaC files:

```bash
# Terrascan for Terraform
yavs scan . --auto  # Detects .tf files

# TemplateAnalyzer for Azure ARM/Bicep
yavs scan . --auto  # Detects .bicep and ARM JSON files
```

---

## Common Workflows

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install YAVS
        run: pip install yavs

      - name: Run Security Scan
        run: |
          yavs scan . \
            --auto \
            --all \
            --policy .github/policies/security.yaml \
            --policy-mode enforce \
            --fail-on HIGH \
            --fail-fast \
            --csv findings.csv \
            --output-dir scan-results

      - name: Upload Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-scan
          path: scan-results/
```

### Local Development

```bash
# Quick scan before commit
yavs scan . --auto --fail-on HIGH

# Detailed scan with all outputs
yavs scan . \
  --auto \
  --all \
  --blame \
  --csv findings.csv \
  --output-dir results

# Review HTML report
open results/report.html
```

### Security Review

```bash
# Full scan with policy enforcement
yavs scan . \
  --auto \
  --all \
  --blame \
  --baseline .yavs-baseline.yaml \
  --policy policies/security.yaml \
  --policy policies/compliance.yaml \
  --policy-mode audit \
  --csv findings.csv \
  --output-dir security-review

# Export for spreadsheet analysis
yavs scan . --csv findings.csv
```

---

## Output Formats

### SARIF

Standard format for GitHub Code Scanning:

```bash
yavs scan . --output-dir results
# Creates: results/yavs-results.sarif
```

Upload to GitHub:
```bash
gh api repos/:owner/:repo/code-scanning/sarifs \
  -F sarif=@results/yavs-results.sarif \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main
```

### CSV (24 columns)

Full finding details in spreadsheet format:

```bash
yavs scan . --csv findings.csv
```

Columns: severity, tool, category, title, description, file, line, rule_id, vulnerability_id, package, version, fix_version, cvss_score, cwe, references, git_author, git_email, git_commit, git_date, policy_suppressed, policy_tags, policy_rule, suppressed, suppression_reason

### JSON

Complete structured data:

```bash
yavs scan . --output-dir results
# Creates: results/scan-results.json
```

### HTML

Visual report with charts and tables:

```bash
yavs scan . --output-dir results
# Creates: results/report.html
open results/report.html
```

---

## Policy Examples

### Suppress Test Code

```yaml
rules:
  - id: "TEST-001"
    name: "Suppress test findings"
    conditions:
      - field: "file"
        operator: "regex"
        value: "/(tests?|__tests__|spec)/"
    action: "suppress"
    reason: "Test code excluded"
```

### Escalate Payment Code

```yaml
rules:
  - id: "PAYMENT-001"
    name: "Escalate payment findings"
    conditions:
      - field: "file"
        operator: "contains"
        value: "/payment/"
    severity_override: "CRITICAL"
    action: "tag"
    tags: ["payment", "critical-path"]
```

### Tag by Author Team

```yaml
rules:
  - id: "TEAM-001"
    name: "Tag backend team findings"
    conditions:
      - field: "git_blame.email"
        operator: "regex"
        value: "@backend\\.company\\.com$"
    action: "tag"
    tags: ["backend-team"]
```

### Fail on Injection

```yaml
rules:
  - id: "INJECTION-001"
    name: "Fail on injection vulnerabilities"
    conditions:
      - field: "category"
        operator: "in"
        value: ["sql-injection", "command-injection", "xss"]
    action: "fail"
```

---

## CLI Reference

### Scan Options

```
--auto                  Auto-detect project type and scanners
--all                   Run all available scanners
--sast                  Run SAST scanners (Bandit, Semgrep, ESLint)
--sca                   Run SCA scanners (Safety, npm audit)
--iac                   Run IaC scanners (Terrascan, TemplateAnalyzer)
--secrets               Run secret scanners
```

### Policy Options

```
--policy PATH           Policy file or directory (repeatable)
--policy-mode MODE      Policy mode: enforce, audit, off
```

### Git Options

```
--blame                 Enrich findings with git blame data
```

### Baseline Options

```
--baseline PATH         Baseline file to suppress known findings
--save-baseline PATH    Save current findings as baseline
```

### Failure Options

```
--fail-on SEVERITY      Fail if findings at or above severity (CRITICAL, HIGH, MEDIUM, LOW)
--fail-fast             Exit immediately when failure threshold is met
--continue-on-error     Continue scan even if individual scanners fail
```

### Export Options

```
--output-dir DIR        Output directory for all reports
--csv PATH              Export findings to CSV file
--tsv PATH              Export findings to TSV file
```

### AI Options

```
--ai                    Enable AI-powered analysis
--no-ai                 Disable AI analysis
```

---

## Examples Directory

See `examples/` for:
- `comprehensive-scan.sh`: Full-featured scan script
- `policies/security.yaml`: Example security policy
- `policies/compliance.yaml`: Example compliance policy
- `policies/team-exceptions.yaml`: Team-specific rules

---

## Documentation

- **Policy Guide**: `docs/POLICY.md` (650+ lines)
- **Schemas**: `docs/schemas/`
- **Verification Report**: `POLICY-VERIFICATION-REPORT.md`
- **Feature Parity Report**: `FEATURE-PARITY-COMPLETE.md`
- **CLI Help**: `yavs --help`, `yavs scan --help`

---

## Support

- **Issues**: https://github.com/your-org/yavs/issues
- **Docs**: `docs/`
- **Examples**: `examples/`

---

**YAVS - Production-ready security scanning with AI and Policy-as-Code** ✅
