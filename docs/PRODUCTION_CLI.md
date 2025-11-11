# Production-Ready CLI Enhancements

## Overview
This document outlines production-ready enhancements for YAVS CLI to support both CI/CD pipelines and interactive use.

## Implementation Status
✅ **Implemented** - Exit Code Control, Severity Filtering, Quiet Mode, Scan Timeout, Continue on Error
⏳ **Pending** - Baseline/Allowlist, Additional Commands

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

**Note:** Uses signal-based timeout on Unix/Linux/Mac. Not supported on Windows.

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
      --output-dir ./security-results
```

### Strict Security Gate (Block on CRITICAL only)
```bash
yavs scan --all \
  --severity CRITICAL,HIGH \
  --fail-on CRITICAL \
  --quiet \
  --timeout 600 \
  --output-dir ./artifacts
```

### Development/Testing (Non-blocking, full visibility)
```bash
yavs scan --all \
  --fail-on NONE \
  --continue-on-error \
  --output-dir ./dev-scan
```

### Combined with Severity Filtering
```bash
# Only review CRITICAL findings but don't fail the build
yavs scan --all \
  --severity CRITICAL \
  --fail-on NONE \
  --quiet

# Review CRITICAL and HIGH, fail on CRITICAL only
yavs scan --all \
  --severity CRITICAL,HIGH \
  --fail-on CRITICAL \
  --continue-on-error
```

## Additional Features (Pending Implementation)

### 6. Baseline/Allowlist (`--baseline`) ⏳ PENDING
**Priority: MEDIUM**

Suppress known/accepted vulnerabilities.

```bash
# Use baseline file to suppress known issues
yavs scan --all --baseline .yavs-baseline.json

# Generate baseline from current scan
yavs scan --all --generate-baseline