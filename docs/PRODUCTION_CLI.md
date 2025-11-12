# Production-Ready CLI Enhancements

## Overview
This document outlines production-ready enhancements for YAVS CLI to support both CI/CD pipelines and interactive use.

## Implementation Status
✅ **Fully Implemented** - Exit Code Control, Severity Filtering, Quiet Mode, Scan Timeout, Continue on Error, Baseline/Allowlist, Diff Command
⏳ **Pending** - Webhook Integration

## Critical Features for CI/CD Pipelines

### 1. Exit Code Control (`--fail-on`) ✅ IMPLEMENTED
**Priority: CRITICAL**

Control when the scan should return non-zero exit code (fail the pipeline).

```bash
# Fail on CRITICAL severity findings
yavs scan --all --fail-on CRITICAL

# Fail on HIGH or above
yavs scan --all --fail-on HIGH

# Fail on MEDIUM or above
yavs scan --all --fail-on MEDIUM

# Never fail (always exit 0)
yavs scan --all --fail-on NONE
```

**Exit Codes:**
- `0` - Success (no findings above threshold)
- `1` - Findings found above threshold
- `2` - Scan error (scanner failed, config invalid, etc.)

### 2. Severity Filtering (`--severity`) ✅ IMPLEMENTED
**Priority: HIGH**

Filter which severity levels to report/include in results.

```bash
# Only report CRITICAL findings
yavs scan --all --severity CRITICAL

# Report CRITICAL and HIGH
yavs scan --all --severity CRITICAL,HIGH

# Report everything except INFO
yavs scan --all --severity CRITICAL,HIGH,MEDIUM,LOW
```

### 3. Quiet Mode (`--quiet`) ✅ IMPLEMENTED
**Priority: HIGH**

Minimal output for CI/CD logs - only show summary and errors.

```bash
yavs scan --all --quiet
```

**Quiet Mode Output:**
```
Found 42 findings (8 CRITICAL, 15 HIGH, 19 MEDIUM)
Results: ./yavs-results.json
```

### 4. Scan Timeout (`--timeout`) ✅ IMPLEMENTED
**Priority: MEDIUM**

Overall scan timeout (in seconds).

```bash
# Timeout after 10 minutes
yavs scan --all --timeout 600
```

**Note:** Uses signal-based timeout on Unix/Linux/Mac. Windows support pending (see KNOWN_ISSUES.md).

### 5. Continue on Error (`--continue-on-error`) ✅ IMPLEMENTED
**Priority: MEDIUM**

Don't fail entire scan if one scanner fails.

```bash
yavs scan --all --continue-on-error
```

**Behavior:**
- Failed scanners logged as warnings
- Partial results still generated
- Exit code based on findings from successful scanners

### 6. Baseline/Allowlist (`--baseline`) ✅ IMPLEMENTED
**Priority: MEDIUM**

Suppress known/accepted vulnerabilities using baseline files.

```bash
# Use baseline file to suppress known issues
yavs scan --all --baseline .yavs-baseline.yaml

# Baseline management commands
yavs ignore add CVE-2023-1234 -r "False positive"
yavs ignore remove CVE-2023-1234
yavs ignore list
yavs ignore export results.json -o baseline.yaml
```

**Baseline File Format (YAML):**
```yaml
version: 1.0
description: YAVS suppression baseline
suppressions:
  - id: CVE-2023-1234
    reason: False positive
    date: 2024-01-15
```

### 7. Dependency Diff (`yavs diff`) ✅ IMPLEMENTED
**Priority: LOW**

Compare two scan results to see what changed.

```bash
# Compare current scan to previous
yavs diff baseline.json current.json

# Show all findings (new, fixed, existing)
yavs diff baseline.json current.json --show-all

# Save comparison report
yavs diff baseline.json current.json -o comparison.json
```

**Output:**
- New findings (appeared in current scan)
- Fixed findings (were in baseline, now gone)
- Existing findings (in both scans)

---

## Real-World CI/CD Examples

### GitHub Actions / GitLab CI / Jenkins
```yaml
# Fail pipeline on HIGH or CRITICAL findings
- name: Security Scan
  run: |
    yavs scan --all \
      --quiet \
      --fail-on HIGH \
      --continue-on-error \
      --baseline .yavs-baseline.yaml \
      --output-dir ./security-results
```

### Strict Security Gate (Block on CRITICAL only)
```bash
yavs scan --all \
  --severity CRITICAL,HIGH \
  --fail-on CRITICAL \
  --quiet \
  --timeout 600 \
  --baseline .yavs-baseline.yaml \
  --output-dir ./artifacts
```

### Development/Testing (Non-blocking, full visibility)
```bash
yavs scan --all \
  --fail-on NONE \
  --continue-on-error \
  --output-dir ./dev-scan
```

### Baseline Tracking Workflow
```bash
# First run - create baseline
yavs scan --all -o baseline.json
git add baseline.json
git commit -m "Add security baseline"

# Future runs - compare against baseline
yavs scan --all -o current.json
yavs diff baseline.json current.json

# Show only new findings
yavs diff baseline.json current.json | grep "New findings"
```

---

## Tool Version Management

### 8. Scanner Version Control (`yavs tools`) ✅ IMPLEMENTED
**Priority: HIGH**

YAVS provides comprehensive tool version management for reproducible builds and safe upgrades in CI/CD pipelines.

**Tested Versions (Nov 2025):**
- Trivy: 0.67.2
- Semgrep: 1.142.1
- Bandit: 1.8.6
- Checkov: 3.2.492

#### Install Specific Versions

```bash
# Install all tools (tested versions)
yavs tools install

# Install specific tool
yavs tools install --tool trivy
yavs tools install --tool semgrep

# Install exact version
yavs tools install --tool trivy --version 0.67.2
yavs tools install --tool semgrep --version 1.142.1
```

#### Check and Validate Versions

```bash
# List installed tool versions
yavs tools status

# Validate version compatibility
yavs tools check
```

**Output Example:**
```
Tool Version Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
trivy      0.67.2    ✓ Tested version
semgrep    1.142.1   ✓ Tested version
bandit     1.8.6     ✓ Tested version
checkov    3.2.492   ✓ Tested version
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
All tools are compatible with YAVS
```

#### Upgrade Tools

```bash
# Upgrade all tools (tested versions)
yavs tools upgrade

# Upgrade specific tool
yavs tools upgrade --tool trivy
yavs tools upgrade --tool semgrep

# Upgrade to absolute latest (may be untested)
yavs tools upgrade --latest
yavs tools upgrade --tool trivy --latest

# Skip confirmation
yavs tools upgrade -y
```

#### Pin Versions (Reproducible Builds)

```bash
# Create lock file (.yavs-tools.lock in YAML format)
yavs tools pin

# Create pip requirements file
yavs tools pin --format requirements

# Custom output path
yavs tools pin -o my-tools.lock
yavs tools pin --format requirements -o requirements-scanners.txt
```

**Lock File Example (`.yavs-tools.lock`):**
```yaml
version: "1.0"
generated_at: "2025-11-12T10:30:00Z"
tools:
  trivy:
    version: "0.67.2"
    tested: true
    path: "/Users/user/.yavs/bin/trivy"
  semgrep:
    version: "1.142.1"
    tested: true
  bandit:
    version: "1.8.6"
    tested: true
  checkov:
    version: "3.2.492"
    tested: true
```

#### CI/CD Best Practices

**1. Lock versions for reproducibility:**
```yaml
# GitHub Actions example
- name: Install YAVS with locked versions
  run: |
    pip install yavs
    yavs tools install
    yavs tools pin  # Generate lock file
    git add .yavs-tools.lock
    git commit -m "Lock scanner versions"
```

**2. Validate versions before scanning:**
```yaml
- name: Validate scanner versions
  run: |
    yavs tools status
    yavs tools check
```

**3. Use tested versions in production:**
```yaml
- name: Install tested versions
  run: |
    yavs tools install  # Installs tested versions by default
```

**4. Upgrade with caution:**
```bash
# Test upgrades in development first
yavs tools upgrade --tool semgrep
yavs tools check

# Only use --latest after validation
yavs tools upgrade --latest  # Use cautiously
```

#### Version Control Mechanisms

YAVS supports multiple version control approaches:

1. **Lock Files** (Recommended for CI/CD)
   - `.yavs-tools.lock` - YAML format with full metadata
   - `requirements-scanners.txt` - pip format for Python tools

2. **Configuration Files**
   ```yaml
   # .yavs-config.yaml
   tool_versions:
     trivy: "0.67.2"
     semgrep: "1.142.1"
     bandit: "1.8.6"
     checkov: "3.2.492"
   ```

3. **Environment Variables**
   ```bash
   export TRIVY_VERSION=0.67.2
   export SEMGREP_VERSION=1.142.1
   export BANDIT_VERSION=1.8.6
   export CHECKOV_VERSION=3.2.492
   ```

4. **Direct Installation**
   ```bash
   yavs tools install --tool trivy --version 0.67.2
   ```

#### Automatic Version Validation

YAVS automatically validates scanner versions during scans:

```
⚠ Warning: semgrep version 1.150.0 is outside tested range (1.142.1-1.142.999)
  Scan will continue but results may vary. Consider running 'yavs tools upgrade'
```

**Non-Blocking Behavior:**
- Version warnings are logged but don't fail scans
- Results are still generated with potentially incompatible versions
- Use `yavs tools check` to validate before scanning

---

## Additional Features

### 9. Continuous Monitoring Integration ⏳ PENDING
**Priority: MEDIUM**

Webhook/API integration for CI/CD.

```bash
# Post results to webhook (planned)
yavs scan --all --webhook https://your-endpoint.com/security

# Export to monitoring tools (planned)
yavs scan --all --export prometheus
```

---

## Implementation Status Table

| Feature | Status | Priority | Notes |
|---------|--------|----------|-------|
| Exit Code Control | ✅ Complete | CRITICAL | `--fail-on` flag |
| Severity Filtering | ✅ Complete | HIGH | `--severity` flag |
| Quiet Mode | ✅ Complete | HIGH | `--quiet` flag |
| Scan Timeout | ✅ Complete | MEDIUM | Unix/Linux/Mac only |
| Continue on Error | ✅ Complete | MEDIUM | `--continue-on-error` flag |
| Core Scanning | ✅ Complete | CRITICAL | All scanners integrated |
| Output Formats | ✅ Complete | CRITICAL | JSON, SARIF, HTML, SBOM |
| AI Integration | ✅ Complete | HIGH | Multi-provider support |
| SBOM Generation | ✅ Complete | HIGH | CycloneDX format |
| Ignore Patterns | ✅ Complete | MEDIUM | Regex and glob support |
| Statistics | ✅ Complete | MEDIUM | Multiple grouping options |
| **Baseline/Allowlist** | ✅ Complete | MEDIUM | `--baseline` + `yavs ignore` commands |
| **Dependency Diff** | ✅ Complete | LOW | `yavs diff` command |
| **Tool Version Management** | ✅ Complete | HIGH | `yavs tools` commands with version control |
| Webhook Integration | ⏳ Pending | MEDIUM | Planned for future release |

---

## Notes

This document tracks the production CLI features and their implementation status. As of v1.0.0:
- **Baseline management** is fully implemented with `--baseline` flag and `yavs ignore` commands
- **Diff functionality** is fully implemented with `yavs diff` command
- **Tool version management** is fully implemented with `yavs tools` commands for install/upgrade/pin/check
- **Webhook integration** remains the only pending feature

For complete usage documentation, see the main README.md or run `yavs man`.
