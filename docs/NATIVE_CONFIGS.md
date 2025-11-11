# Native Tool Configuration Support

YAVS supports using native configuration files for each scanner tool. Native configs **extend and override** YAVS baseline settings, giving you the best of both worlds: YAVS simplicity + full tool power.

## Overview

YAVS provides simple, unified configuration for common use cases. However, power users may need access to the full capabilities of each underlying tool. Rather than exposing hundreds of environment variables (like [Microsoft Security DevOps](https://github.com/microsoft/security-devops-azdevops/wiki)), YAVS allows you to provide each tool's native configuration file.

### Smart Configuration Merging

YAVS uses a **layered configuration approach**:

1. **YAVS Baseline** - Sensible defaults for quick scanning
2. **Native Config** - Tool-specific customization (extends baseline)
3. **CLI Flags** - Override everything for one-off changes

This means you get:
- ✅ **YAVS defaults** for settings you don't customize
- ✅ **Native config** for tool-specific features
- ✅ **No conflicts** - clear precedence rules (CLI > Native > YAVS)

## Benefits

- ✅ **Best of Both Worlds** - YAVS simplicity + full tool customization
- ✅ **Incremental Customization** - Only override what you need
- ✅ **Tool-Native Syntax** - Use official documentation and examples
- ✅ **Gradual Migration** - Keep existing tool configs when adopting YAVS
- ✅ **Clear Precedence** - Well-defined override rules
- ✅ **Simple for Beginners** - YAVS baseline works out of the box

## Configuration

In your `config.yaml`, specify the path to each tool's native config file:

```yaml
scanners:
  trivy:
    enabled: true
    timeout: 300
    flags: ""
    native_config: "config/trivy.yaml"  # Path to Trivy's native config

  semgrep:
    enabled: true
    timeout: 300
    flags: ""
    native_config: "config/.semgrep.yml"  # Path to Semgrep's native config

  bandit:
    enabled: true
    timeout: 300
    flags: ""
    native_config: "config/.bandit"  # Path to Bandit's native config

  checkov:
    enabled: true
    timeout: 300
    flags: ""
    native_config: "config/.checkov.yaml"  # Path to Checkov's native config

  binskim:
    enabled: true
    timeout: 300
    flags: ""
    native_config: "config/.gdnconfig"  # Path to BinSkim's native config
```

## How It Works

### Configuration Layering

YAVS builds commands using a **layered approach**:

```bash
# Layer 1: YAVS Baseline (always included)
trivy fs --security-checks vuln,secret,license --format json

# Layer 2: Native Config (extends baseline)
trivy fs --security-checks vuln,secret,license --config config/trivy.yaml --format json

# Layer 3: CLI Flags (highest priority)
trivy fs --security-checks vuln,secret,license --config config/trivy.yaml --severity HIGH --format json
```

**Result**: Each tool uses its native precedence rules (typically: CLI flags > config file > defaults)

### Practical Example

**YAVS config.yaml:**
```yaml
scanners:
  trivy:
    flags: ""  # No extra flags
    native_config: "config/trivy.yaml"
```

**config/trivy.yaml:**
```yaml
severity:
  - CRITICAL
  - HIGH
skip-dirs:
  - vendor
  - node_modules
```

**Generated command:**
```bash
trivy fs --security-checks vuln,secret,license --config config/trivy.yaml --format json .
```

**What you get:**
- ✅ YAVS default: `--security-checks vuln,secret,license`
- ✅ YAVS default: `--format json` (required for parsing)
- ✅ Native config: `severity: CRITICAL,HIGH`
- ✅ Native config: `skip-dirs: vendor,node_modules`
- ✅ Best of both: YAVS defaults + your customization

## Tool-Specific Examples

### Trivy (`trivy.yaml`)

```yaml
# Trivy Native Configuration
# See: https://aquasecurity.github.io/trivy/latest/docs/configuration/

# Severity levels to report
severity:
  - CRITICAL
  - HIGH
  - MEDIUM

# Security checks to perform
security:
  - vuln
  - secret
  - config
  - license

# Vulnerability database
db:
  skip-update: false

# Secret scanning
secret:
  config: config/trivy-secret.yaml

# Vulnerability settings
vulnerability:
  type:
    - os
    - library

# Ignore unfixed vulnerabilities
ignore-unfixed: false

# Skip files/directories
skip-dirs:
  - node_modules
  - vendor
```

### Semgrep (`.semgrep.yml`)

```yaml
# Semgrep Native Configuration Example
# See: https://semgrep.dev/docs/writing-rules/rule-syntax/

# Option 1: Use Semgrep Registry rulesets
# Reference pre-built rulesets from Semgrep Registry
rules:
  - id: p/security-audit
    # Comprehensive security checks across multiple languages

  - id: p/owasp-top-10
    # OWASP Top 10 security vulnerabilities

  - id: p/cwe-top-25
    # CWE Top 25 Most Dangerous Software Weaknesses

# Option 2: Define custom rules inline
# Uncomment to add custom Semgrep rules
# rules:
#   - id: hardcoded-secret
#     patterns:
#       - pattern: password = "..."
#       - pattern-not: password = ""
#     message: Hardcoded password detected
#     languages: [python, javascript, java]
#     severity: ERROR
```

### Bandit (`.bandit`)

```yaml
# Bandit Native Configuration
# See: https://bandit.readthedocs.io/en/latest/config.html

# Tests to skip
skips:
  - B404  # Consider possible security implications
  - B603  # subprocess without shell equals true

# Tests to run
tests:
  - B201  # flask_debug_true
  - B501  # request_with_no_cert_validation

# Exclude paths
exclude_dirs:
  - /test
  - /tests
  - /venv

# Severity thresholds
severity: medium
confidence: high
```

### Checkov (`.checkov.yaml`)

```yaml
# Checkov Native Configuration
# See: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html

# Framework to check
framework:
  - terraform
  - kubernetes
  - dockerfile

# Checks to skip
skip-check:
  - CKV_AWS_1   # Example: Skip specific check
  - CKV_K8S_*   # Skip all K8s checks

# Severity threshold
check:
  - HIGH
  - CRITICAL

# External checks directory
external-checks-dir:
  - custom-checks/

# Compact mode
compact: true

# Soft fail (don't fail pipeline)
soft-fail: false
```

### BinSkim (`.gdnconfig`)

```json
{
  "fileVersion": "1.0.0",
  "tools": [
    {
      "fileVersion": "1.0.0",
      "tool": {
        "name": "binskim",
        "version": "1.9.5"
      },
      "arguments": {
        "config": "default",
        "recurse": true,
        "verbose": false,
        "rich-return-code": true,
        "level": [
          "error",
          "warning",
          "note"
        ],
        "kind": [
          "pass",
          "fail",
          "review",
          "open",
          "notApplicable"
        ]
      },
      "outputExtension": "sarif",
      "successfulExitCodes": [
        0
      ],
      "errorExitCodes": {
        "1": "An error occurred during analysis"
      }
    }
  ]
}
```

## Configuration Precedence

YAVS uses a **layered approach** that respects each tool's native precedence rules:

### Precedence Hierarchy (Highest to Lowest)

1. **CLI Flags** (YAVS `flags:` in config.yaml) - **Highest Priority**
   - Overrides everything
   - Perfect for one-off changes or force-overriding

2. **Native Config File** (tool's native `.yaml`/`.ini` file)
   - Extends/overrides YAVS baseline
   - Tool-specific customization

3. **YAVS Baseline** (built-in defaults)
   - Sensible defaults
   - Always present unless overridden

### Example: All Layers Together

```yaml
# config.yaml
scanners:
  trivy:
    flags: "--timeout 10m"                 # Layer 3: Highest priority
    native_config: "config/trivy.yaml"     # Layer 2: Extends baseline
    # YAVS baseline (Layer 1): --security-checks vuln,secret,license --format json
```

```yaml
# config/trivy.yaml
severity:
  - CRITICAL
  - HIGH
timeout: 5m  # This will be OVERRIDDEN by flags: "--timeout 10m"
```

**Generated command:**
```bash
trivy fs --security-checks vuln,secret,license --config config/trivy.yaml --timeout 10m --format json .
```

**What happens:**
- ✅ YAVS baseline: `--security-checks vuln,secret,license` (not overridden)
- ✅ Native config: `severity: CRITICAL,HIGH` (extends baseline)
- ✅ Native config: `timeout: 5m` (set in config)
- ✅ **CLI flags win**: `--timeout 10m` overrides native config's `timeout: 5m`

### Smart Merging, Not Replacement

Unlike "all-or-nothing" approaches, YAVS **merges intelligently**:

| Scenario | YAVS Baseline | Native Config | CLI Flags | Result |
|----------|---------------|---------------|-----------|--------|
| No customization | `--security-checks vuln` | (none) | (none) | Uses YAVS default |
| Native config only | `--security-checks vuln` | `severity: HIGH` | (none) | YAVS default + native severity |
| Conflicting settings | `--security-checks vuln` | `severity: HIGH` | `--severity CRITICAL` | CLI flag wins |
| Non-conflicting | `--format json` | `skip-dirs: vendor` | `--timeout 10m` | All three apply |

## When to Use Native Config

**Use YAVS Config When:**
- ✅ You need simple, quick scanning
- ✅ You're new to security scanning
- ✅ You want YAVS to manage complexity

**Use Native Config When:**
- ✅ You need advanced tool features not exposed by YAVS
- ✅ You're migrating existing tool configurations to YAVS
- ✅ You need tool-specific customization (custom rules, plugins, etc.)
- ✅ You want full control over scanner behavior

## Testing Native Configs

To verify your native config is working:

1. Enable debug logging in `config.yaml`:
   ```yaml
   logging:
     level: "DEBUG"
   ```

2. Run a scan and check for the log message:
   ```
   Using Trivy native config: config/trivy.yaml
   ```

3. Verify the command being executed:
   ```bash
   trivy fs --config config/trivy.yaml --format json .
   ```

## Example Project Structure

```
my-project/
├── config/
│   ├── trivy.yaml           # Trivy native config
│   ├── .semgrep.yml         # Semgrep native config
│   ├── .bandit              # Bandit native config
│   ├── .checkov.yaml        # Checkov native config
│   └── .gdnconfig           # BinSkim native config
├── config.yaml              # YAVS configuration
├── src/
│   └── ...
└── README.md
```

## Migration Guide

### From Existing Tool Config to YAVS

If you already have tool configs:

```bash
# Before: Using tool directly
trivy fs --config .trivy.yaml --format json .

# After: Using YAVS with native config
yavs scan --sbom  # Uses config/trivy.yaml from config.yaml
```

Your YAVS `config.yaml`:

```yaml
scanners:
  trivy:
    enabled: true
    native_config: ".trivy.yaml"  # Use your existing config
```

## References

- [Trivy Configuration](https://aquasecurity.github.io/trivy/latest/docs/configuration/)
- [Semgrep Configuration](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [Bandit Configuration](https://bandit.readthedocs.io/en/latest/config.html)
- [Checkov Configuration](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [BinSkim Configuration](https://github.com/microsoft/binskim)
