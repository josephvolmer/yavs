# YAVS Examples

This directory contains example configurations, scripts, and CI/CD pipelines demonstrating YAVS features.

---

## 📁 Directory Structure

```
examples/
├── comprehensive-scan.sh    # All-in-one demo script (8 features)
├── configs/                 # Configuration file examples
├── docker/                  # Docker-related examples
├── policies/                # Policy-as-Code examples
└── ci-cd/                   # CI/CD pipeline examples
```

---

## 🚀 Quick Start

### Run Comprehensive Demo

The `comprehensive-scan.sh` script demonstrates all 8 new features:

```bash
chmod +x examples/comprehensive-scan.sh
./examples/comprehensive-scan.sh
```

**Features Demonstrated**:
1. ✅ Baseline Expiration - Time-limited suppression
2. ✅ CSV/TSV Export - 24-column comprehensive output
3. ✅ Auto-Detect Mode - Multi-language detection
4. ✅ Fast-Fail Mode - Early exit on critical findings
5. ✅ Git Blame Tracking - Author attribution
6. ✅ Terrascan Scanner - Terraform/IaC scanning
7. ✅ TemplateAnalyzer - Azure ARM/Bicep scanning
8. ✅ Policy-as-Code - Declarative security policies

---

## 📋 Policy Examples (`policies/`)

### Built-in Policies

```bash
# Security baseline
yavs scan . --policy src/yavs/policy/builtins/security.yaml --policy-mode enforce

# PCI-DSS compliance
yavs scan . --policy src/yavs/policy/builtins/compliance.yaml --policy-mode audit
```

### Custom Policies

See `policies/team-exceptions.yaml` for real-world examples:
- Suppress findings in legacy code
- Escalate severity for critical paths
- Tag findings by team ownership (using git blame)
- Suppress test utilities

**Usage**:
```bash
yavs scan . --policy examples/policies/team-exceptions.yaml --policy-mode enforce
```

**Learn More**: See [docs/POLICY.md](../docs/POLICY.md) for complete policy guide

---

## ⚙️ Configuration Examples (`configs/`)

### Full Configuration

`configs/yavs-config-full.yaml` - Complete example with all options:
- All scanner configurations
- AI provider settings
- Output format options
- Baseline management
- Policy integration

**Usage**:
```bash
cp examples/configs/yavs-config-full.yaml .yavs.yaml
yavs scan --config .yavs.yaml
```

### Native Scanner Configs

Examples for native scanner configuration files:
- `.semgrep.yml` - Semgrep rules
- `trivy.yaml` - Trivy configuration
- `.checkov.yaml` - Checkov settings

**Learn More**: See [docs/NATIVE_CONFIGS.md](../docs/NATIVE_CONFIGS.md)

---

## 🐳 Docker Examples (`docker/`)

### Scan Multiple Images

`docker/images.txt` - List of Docker images to scan:

```bash
yavs scan --images-file examples/docker/images.txt --sbom
```

---

## 🔄 CI/CD Examples (`ci-cd/`)

All CI/CD examples now showcase the **8 new features**:

### GitHub Actions

`ci-cd/github-actions.yml` - Full-featured workflow:

```yaml
- name: Run comprehensive scan
  run: |
    yavs scan . \
      --auto \
      --all \
      --blame \
      --baseline .yavs-baseline.yaml \
      --policy examples/policies/security-policy.yaml \
      --policy-mode enforce \
      --fail-on HIGH \
      --csv findings.csv \
      --tsv findings.tsv \
      --output-dir results
```

**Features Showcased**:
- ✅ Auto-detect mode
- ✅ Git blame tracking
- ✅ Baseline with expiration
- ✅ Policy enforcement
- ✅ CSV/TSV export
- ✅ IaC scanners (auto-detected)

### GitLab CI

`ci-cd/gitlab-ci.yml` - Complete pipeline with all features

### Jenkins

`ci-cd/jenkinsfile` - Declarative pipeline example

### Azure Pipelines

`ci-cd/azure-pipelines.yml` - Azure DevOps integration

**All examples include**:
- Full scanner installation
- Comprehensive scanning with new features
- Artifact uploads
- Code Scanning integration
- Policy enforcement

---

## 💡 Usage Patterns

### Basic Scan with Auto-Detect

```bash
yavs scan . --auto --all
```

### Policy-Enforced Scan

```bash
yavs scan . \
  --auto \
  --policy src/yavs/policy/builtins/security.yaml \
  --policy-mode enforce \
  --fail-on HIGH
```

### Full-Featured CI/CD Scan

```bash
yavs scan . \
  --auto \
  --all \
  --blame \
  --baseline .yavs-baseline.yaml \
  --policy policies/security.yaml \
  --policy-mode enforce \
  --csv findings.csv \
  --output-dir results
```

### Audit Mode (Non-Blocking)

```bash
yavs scan . \
  --auto \
  --policy policies/compliance.yaml \
  --policy-mode audit \
  --csv audit-findings.csv
```

---

## 📖 Documentation

For detailed documentation on each feature:

- **Quick Start**: [docs/QUICK-START.md](../docs/QUICK-START.md)
- **Policy Guide**: [docs/POLICY.md](../docs/POLICY.md)
- **Production CLI**: [docs/PRODUCTION_CLI.md](../docs/PRODUCTION_CLI.md)
- **AI Providers**: [docs/AI_PROVIDER_GUIDE.md](../docs/AI_PROVIDER_GUIDE.md)
- **Output Schemas**: [docs/OUTPUT_SCHEMAS.md](../docs/OUTPUT_SCHEMAS.md)

---

## 🎯 Feature Matrix

| Example | Auto-Detect | Git Blame | Baseline | Policy | CSV/TSV | IaC Scanners |
|---------|------------|-----------|----------|--------|---------|--------------|
| comprehensive-scan.sh | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ci-cd/github-actions.yml | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ci-cd/gitlab-ci.yml | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ci-cd/jenkinsfile | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ci-cd/azure-pipelines.yml | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

*All examples demonstrate YAVS production best practices and the latest features*
