# Policy-as-Code Guide

## Overview

YAVS Policy-as-Code provides enterprise-grade automated security governance. Define rules that automatically suppress, fail, warn, or tag findings based on flexible conditions.

**Benefits:**
- 📋 **Automated Governance**: Enforce security standards without manual review
- 🎯 **Consistent Standards**: Apply same rules across all teams/projects
- 📊 **Compliance Integration**: Map to PCI-DSS, HIPAA, SOC2, etc.
- 🔄 **Version-Controlled**: Store policies in Git alongside code
- 🏷️ **Smart Tagging**: Automatically categorize findings for tracking

---

## Quick Start

### 1. Create a Policy File

**`my-policy.yaml`:**
```yaml
version: "1.0"
name: "My Security Policy"
description: "Custom security governance rules"

rules:
  - id: "CUSTOM-001"
    name: "Suppress low severity in tests"
    enabled: true
    conditions:
      - field: "severity"
        operator: "in"
        value: ["LOW", "INFO"]
      - field: "file"
        operator: "contains"
        value: "/tests/"
        case_sensitive: false
    action: "suppress"
    reason: "Low findings in tests auto-suppressed"
```

### 2. Apply Policy During Scan

```bash
# Enforce mode (fail build on violations)
yavs scan --all --policy ./my-policy.yaml

# Audit mode (report but don't fail)
yavs scan --all --policy ./my-policy.yaml --policy-mode audit

# Multiple policies
yavs scan --all --policy ./security.yaml --policy ./compliance.yaml

# Policy directory
yavs scan --all --policy ./policies/
```

---

## Policy File Structure

```yaml
version: "1.0"              # Required: Policy schema version
name: "Policy Name"         # Required: Human-readable name
description: "..."          # Optional: Detailed description

settings:                   # Optional: Global settings
  compliance_framework: "PCI-DSS"
  version: "3.2.1"

rules:                      # Required: List of rules
  - id: "RULE-001"          # Required: Unique identifier
    name: "Rule Name"       # Required: Human-readable name
    description: "..."      # Optional: Rule description
    enabled: true           # Optional: Enable/disable (default: true)

    conditions:             # Required: Matching conditions (AND logic)
      - field: "severity"
        operator: "equals"
        value: "CRITICAL"

    action: "fail"          # Required: suppress|fail|warn|tag

    action_config:          # Optional: Action-specific config
      fail_build: true

    severity_override: "HIGH"  # Optional: Override finding severity
    tags: ["tag1", "tag2"]     # Optional: Tags to apply
    owner: "team@company.com"  # Optional: Responsible party
    reason: "Justification"    # Optional: Why this rule exists
```

---

## Conditions

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match (case-aware) | `severity` equals `"CRITICAL"` |
| `contains` | Substring match | `file` contains `"/test/"` |
| `regex` | Regular expression | `title` regex `"(?i)sql.*injection"` |
| `in` | Value in list | `severity` in `["LOW", "INFO"]` |
| `gt` | Greater than (numbers) | `cvss_score` > `7.0` |
| `lt` | Less than (numbers) | `cvss_score` < `4.0` |

### Common Fields

**Core Fields:**
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `tool`: Scanner name (`trivy`, `semgrep`, `bandit`, etc.)
- `category`: `dependency`, `sast`, `compliance`, `secret`, etc.
- `title`: Finding title/name
- `description`: Detailed description
- `file`: File path
- `line`: Line number
- `rule_id`: Rule/CVE/CWE ID

**Git Blame Fields** (when `--blame` flag used):
- `git_blame.author`: Commit author name
- `git_blame.email`: Commit author email
- `git_blame.commit`: Commit hash
- `git_blame.date`: Commit date (ISO format)

**Package Fields** (for dependency findings):
- `package`: Package name
- `version`: Current version
- `fixed_version`: Fixed version available

### Nested Fields

Access nested fields with dot notation:

```yaml
conditions:
  - field: "git_blame.author"
    operator: "equals"
    value: "John Doe"
```

### Case Sensitivity

By default, string comparisons are case-sensitive. Disable for flexible matching:

```yaml
conditions:
  - field: "file"
    operator: "contains"
    value: "/TEST/"
    case_sensitive: false  # Matches "/test/", "/Test/", "/TEST/"
```

### Multiple Conditions (AND Logic)

All conditions must match for the rule to apply:

```yaml
conditions:
  - field: "severity"
    operator: "equals"
    value: "HIGH"
  - field: "tool"
    operator: "equals"
    value: "semgrep"
  # Finding must be HIGH severity AND from semgrep
```

---

## Actions

### 1. Suppress

Automatically suppress findings (won't appear in reports):

```yaml
action: "suppress"
reason: "False positive - reviewed by security team"
```

**Use Cases:**
- Known false positives
- Accepted risks
- Test code exclusions
- Vendor code exclusions

### 2. Fail

Fail the build/scan when rule matches:

```yaml
action: "fail"
action_config:
  fail_build: true
```

**Use Cases:**
- Critical vulnerabilities
- Compliance violations
- Security baseline enforcement

### 3. Warn

Add warning flag without failing:

```yaml
action: "warn"
```

**Use Cases:**
- Findings requiring review
- Deprecation warnings
- Best practice violations

### 4. Tag

Add tags for categorization and tracking:

```yaml
action: "tag"
tags: ["sql-injection", "owasp-top-10", "requires-review"]
```

**Use Cases:**
- Categorizing by attack type
- Compliance mapping
- Team assignment
- Prioritization

---

## Built-in Policies

YAVS includes pre-built policies in `src/yavs/policy/builtins/`:

### Security Baseline (`security.yaml`)

```bash
yavs scan --all --policy security
```

**Rules:**
- `SEC-001`: Auto-suppress LOW/INFO severity
- `SEC-002`: Fail on CRITICAL vulnerabilities
- `SEC-003`: Suppress test directory findings
- `SEC-004`: Tag SQL injection findings
- `SEC-005`: Suppress vendor directories

### PCI-DSS Compliance (`compliance.yaml`)

```bash
yavs scan --all --policy compliance
```

**Rules:**
- `PCI-6.5.1`: Injection flaws (fail)
- `PCI-6.5.3`: Cryptographic storage (fail)
- `PCI-6.5.4`: Insecure communications (warn)
- `PCI-6.5.8`: Access control (fail)
- `PCI-6.5.10`: Authentication (fail)

---

## Advanced Examples

### Suppress by Git Author

```yaml
- id: "TEAM-001"
  name: "Suppress findings by contractor"
  conditions:
    - field: "git_blame.author"
      operator: "equals"
      value: "contractor@external.com"
  action: "suppress"
  reason: "Contractor code under review"
```

### Severity Escalation

```yaml
- id: "ESCALATE-001"
  name: "Escalate auth issues to CRITICAL"
  conditions:
    - field: "title"
      operator: "regex"
      value: "(?i)(authentication|authorization)"
  severity_override: "CRITICAL"
  action: "fail"
```

### Complex Regex Pattern

```yaml
- id: "SEC-SQL-001"
  name: "Detect all SQL injection variants"
  conditions:
    - field: "description"
      operator: "regex"
      value: "(?i)(sql|nosql|ldap|xpath|command).*injection"
  action: "tag"
  tags: ["injection", "owasp-a03"]
```

### Compliance Mapping

```yaml
- id: "SOC2-CC6.1"
  name: "Logical access controls"
  description: "SOC2 Common Criteria 6.1"
  conditions:
    - field: "rule_id"
      operator: "regex"
      value: "(CWE-284|CWE-285|CWE-862)"
  action: "fail"
  tags: ["soc2", "access-control"]
  owner: "compliance@company.com"
```

---

## Policy Modes

### Enforce Mode (Default)

Fail build on policy violations:

```bash
yavs scan --all --policy ./policy.yaml --policy-mode enforce
```

**Behavior:**
- Evaluates all policies
- Fails with exit code 1 if violations found
- Shows violation details

### Audit Mode

Report policy results without failing:

```bash
yavs scan --all --policy ./policy.yaml --policy-mode audit
```

**Behavior:**
- Evaluates all policies
- Reports violations as warnings
- Never fails build
- Useful for testing new policies

### Off Mode

Disable policy evaluation:

```bash
yavs scan --all --policy-mode off
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run YAVS with Policy
        run: |
          yavs scan --all \
            --policy .yavs/policies/ \
            --policy-mode enforce \
            --output-dir security-results

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-scan
          path: security-results/
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - yavs scan --all --policy policies/ --policy-mode enforce
  artifacts:
    when: always
    paths:
      - results/
```

---

## Best Practices

### 1. Version Control Policies

Store policies in Git alongside code:

```
.yavs/
  policies/
    security.yaml
    compliance.yaml
    team-overrides.yaml
```

### 2. Start with Audit Mode

Test policies before enforcing:

```bash
# Test new policy
yavs scan --all --policy new-policy.yaml --policy-mode audit

# Review results, then enforce
yavs scan --all --policy new-policy.yaml --policy-mode enforce
```

### 3. Layer Policies

Use multiple policies for separation of concerns:

```bash
yavs scan --all \
  --policy policies/security.yaml \
  --policy policies/compliance.yaml \
  --policy policies/team-exceptions.yaml
```

### 4. Document Rules

Always include `name`, `description`, and `reason`:

```yaml
- id: "CUSTOM-001"
  name: "Clear, descriptive name"
  description: "Detailed explanation of what this rule does"
  reason: "Why this rule exists and what problem it solves"
  # ...
```

### 5. Use Meaningful IDs

Follow a consistent naming scheme:

- `SEC-###`: Security rules
- `PCI-#.#.#`: PCI-DSS requirements
- `TEAM-###`: Team-specific rules
- `PROJ-###`: Project-specific rules

### 6. Regular Reviews

Schedule periodic policy reviews:

```bash
# Generate report of suppressed findings
yavs scan --all --policy policies/ --csv suppressions.csv

# Review suppressions in spreadsheet
open suppressions.csv
```

---

## Troubleshooting

### Policy Not Matching

**Problem**: Rule doesn't match expected findings

**Solution**:
1. Verify field names match exactly (check JSON output)
2. Check operator usage (e.g., `in` requires array)
3. Test regex patterns separately
4. Enable debug logging: `YAVS_LOG_LEVEL=DEBUG yavs scan ...`

### Performance

**Problem**: Scan is slow with many policies

**Solution**:
- Consolidate similar rules
- Use simpler operators (`equals` faster than `regex`)
- Disable unused rules (`enabled: false`)

### Validation Errors

**Problem**: Policy file fails to load

**Solution**:
- Validate YAML syntax: `yamllint policy.yaml`
- Check against schema: `docs/schemas/schema-policy.json`
- Ensure required fields present: `version`, `name`, `rules`

---

## Schema Reference

Full JSON schema available at: `docs/schemas/schema-policy.json`

Validate your policy:

```bash
# Using jsonschema (Python)
pip install jsonschema pyyaml
python -c "
import yaml, json, jsonschema
with open('policy.yaml') as f:
    policy = yaml.safe_load(f)
with open('docs/schemas/schema-policy.json') as f:
    schema = json.load(f)
jsonschema.validate(policy, schema)
print('✓ Policy is valid')
"
```

---

## Examples Library

See `examples/policies/` for complete examples:
- `security-baseline.yaml`: Enterprise security standards
- `compliance-pci.yaml`: PCI-DSS 3.2.1 requirements
- `team-exceptions.yaml`: Team-specific overrides
- `severity-escalation.yaml`: Risk-based escalation
- `false-positive-suppression.yaml`: Known FP management

---

## Getting Help

- Documentation: https://docs.yavs.dev/policy-as-code
- Schema: `docs/schemas/schema-policy.json`
- Examples: `examples/policies/`
- Issues: https://github.com/YAVS-OSS/yavs/issues

---

**Next Steps:**
- Create your first policy
- Test in audit mode
- Integrate into CI/CD
- Build compliance policies
