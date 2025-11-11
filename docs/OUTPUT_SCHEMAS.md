# YAVS Output Schemas

YAVS provides multiple JSON output formats, all with complete metadata and optional AI-enhanced fields. This document describes all schemas and when to use each.

## Output Formats

### Summary Format (AI Analysis)

**File:** [`schema-summary.json`](./schema-summary.json)

AI-generated executive summary and triage analysis from the `yavs summarize` command.

**Use when:**
- You need high-level overview of findings
- Prioritizing remediation work
- Creating executive reports
- Clustering similar findings

**Generate with:**
```bash
# Save to separate file (default: yavs-ai-summary.json in current directory)
yavs summarize yavs-results.json

# Enrich scan results file with summary data
yavs summarize yavs-results.json --enrich

# Custom output directory
yavs summarize yavs-results.json -o artifacts/summaries
```

**Example Structure:**
```json
{
  "build_cycle": "2025-11-09T05:30:00Z",
  "findings_count": 97,
  "executive_summary": "## Executive Summary\n\n...",
  "ai_provider": "anthropic",
  "ai_model": "claude-sonnet-4-5-20250929",
  "triage": {
    "clusters": [...],
    "cluster_count": 3,
    "total_findings": 97,
    "ai_analysis": "## Triage Analysis\n\n..."
  }
}
```

## Scan Output Formats

### Structured Format (Default)

**File:** [`schema-structured.json`](./schema-structured.json)

Organizes findings by category (compliance, SAST) and scanner tool for easier consumption and analysis.

**Use when:**
- You want organized, categorized results
- Building dashboards or reports
- Need statistical summaries
- Consuming results in applications

**Enable with:**
```bash
# Default from config (output.structured: true)
yavs scan --all

# Or explicitly
yavs scan --all --structured
```

**Example Structure:**
```json
{
  "build_cycle": "2025-11-09T03:42:28Z",
  "project": "my-app",
  "commit_hash": "abc123...",
  "branch": "main",
  "sbom": { ... },
  "compliance": [
    {
      "tool": "Trivy",
      "violations": [...]
    }
  ],
  "sast": [
    {
      "tool": "Semgrep",
      "issues": [...]
    }
  ],
  "summary": {
    "total_findings": 97,
    "by_severity": {...},
    "by_category": {...}
  }
}
```

### Flat Format

**File:** [`schema-flat.json`](./schema-flat.json)

All findings in a single array with metadata wrapper for simple iteration and filtering.

**Use when:**
- You need simple array iteration
- Filtering/searching across all findings
- Custom grouping/sorting logic
- Maximum flexibility

**Enable with:**
```bash
yavs scan --all --flat
```

**Example Structure:**
```json
{
  "build_cycle": "2025-11-09T03:42:28Z",
  "project": "my-app",
  "commit_hash": "abc123...",
  "branch": "main",
  "sbom": { ... },
  "data": [
    {
      "tool": "trivy",
      "category": "dependency",
      "severity": "CRITICAL",
      "file": "pom.xml",
      "message": "Log4j RCE vulnerability",
      "rule_id": "CVE-2021-44228",
      ...
    },
    {
      "tool": "semgrep",
      "category": "sast",
      ...
    }
  ]
}
```

## Common Fields (Both Formats)

### Root Level (Required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `build_cycle` | string | ✅ Yes | ISO 8601 timestamp (UTC) of scan execution |
| `project` | string | ✅ Yes | Project name (from directory or git repo) |
| `commit_hash` | string\|null | ✅ Yes | Git commit SHA (null if not a git repo) |
| `branch` | string\|null | ✅ Yes | Git branch name (null if not a git repo) |
| `sbom` | object\|null | ❌ No | SBOM metadata (present if `--sbom` used) |

### SBOM Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | string | ✅ Yes | SBOM format ("CYCLONEDX" or "SPDX") |
| `location` | string | ✅ Yes | Absolute path to SBOM file |
| `size_bytes` | integer | ✅ Yes | SBOM file size in bytes |
| `tool` | string | ✅ Yes | Tool used to generate SBOM (e.g., "trivy") |

## AI-Enhanced Fields

When AI features are enabled (`--ai` or without `--no-ai`), findings may include:

### AI Fix Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ai_fix` | string | ❌ No | AI-generated remediation guidance (Markdown) |
| `ai_provider` | string | ❌ No | AI provider ("anthropic" or "openai") |
| `ai_model` | string | ❌ No | AI model name (e.g., "claude-sonnet-4-5-20250929") |

**Example AI Fix:**
```json
{
  "ai_fix": "Update log4j-core to version 2.17.1 or later:\n\n```xml\n<dependency>\n  <groupId>org.apache.logging.log4j</groupId>\n  <artifactId>log4j-core</artifactId>\n  <version>2.17.1</version>\n</dependency>\n```\n\nSteps:\n1. Update pom.xml\n2. Run `mvn clean install`\n3. Restart application",
  "ai_provider": "anthropic",
  "ai_model": "claude-sonnet-4-5-20250929"
}
```

## Finding Categories

YAVS organizes findings into these categories:

| Category | Description | Scanners |
|----------|-------------|----------|
| `dependency` | Vulnerable dependencies (CVEs) | Trivy |
| `secret` | Exposed secrets (API keys, passwords) | Trivy |
| `license` | License compliance issues | Trivy |
| `config` | Configuration issues | Trivy, Checkov |
| `compliance` | IaC policy violations | Checkov |
| `sast` | Static analysis code issues | Semgrep, Bandit |

## Severity Levels

All findings use normalized severity levels:

- `CRITICAL` - Immediate action required
- `HIGH` - High priority, plan remediation
- `MEDIUM` - Should be addressed
- `LOW` - Low priority
- `INFO` - Informational only
- `UNKNOWN` - Severity not determined

## Schema Validation

### Using Python

```python
import json
import jsonschema

# Load schema
with open('docs/schema-structured.json') as f:
    schema = json.load(f)

# Load YAVS results
with open('artifacts/yavs-results.json') as f:
    results = json.load(f)

# Validate
jsonschema.validate(instance=results, schema=schema)
print("✓ Valid YAVS output")
```

### Using Node.js

```javascript
const Ajv = require('ajv');
const fs = require('fs');

const ajv = new Ajv();

// Load schema
const schema = JSON.parse(fs.readFileSync('docs/schema-structured.json'));

// Load YAVS results
const results = JSON.parse(fs.readFileSync('artifacts/yavs-results.json'));

// Validate
const validate = ajv.compile(schema);
const valid = validate(results);

if (valid) {
  console.log('✓ Valid YAVS output');
} else {
  console.error('✗ Invalid:', validate.errors);
}
```

## Field Reference by Format

### Structured Format Fields

**Top-level:**
- `build_cycle`, `project`, `commit_hash`, `branch` (metadata)
- `sbom` (optional SBOM metadata)
- `compliance[]` (array of compliance tools)
- `sast[]` (array of SAST tools)
- `summary` (statistics)

**Compliance Tool:**
- `tool` (scanner name)
- `violations[]` (array of violation objects)

**Violation:**
- `severity`, `rule_id`, `description`, `file`, `line`
- `package`, `version`, `fixed_version` (for CVEs)
- `ai_fix`, `ai_provider`, `ai_model` (optional AI fields)

**SAST Tool:**
- `tool` (scanner name)
- `issues[]` (array of issue objects)

**SAST Issue:**
- `severity`, `rule_id`, `description`, `file`, `line`
- `ai_fix`, `ai_provider`, `ai_model` (optional AI fields)

**Summary:**
- `total_findings` (integer count)
- `by_severity` (object with severity counts)
- `by_category` (object with category counts)

### Flat Format Fields

**Top-level:**
- `build_cycle`, `project`, `commit_hash`, `branch` (metadata)
- `sbom` (optional SBOM metadata)
- `data[]` (array of all findings)

**Finding (in data array):**
- `tool`, `category`, `severity`, `file`, `line`, `message`, `rule_id`
- `description` (detailed description)
- `package`, `version`, `fixed_version` (for dependency findings)
- `source`, `source_type` (scan source information)
- `ai_fix`, `ai_provider`, `ai_model`, `ai_summary` (optional AI fields)

## Per-Tool Output Files

When enabled with `--per-tool-files`, YAVS generates individual JSON files per scanner:

```bash
yavs scan --all --per-tool-files -o artifacts
```

**Outputs:**
```
artifacts/
├── yavs-results.json  # Unified output (structured or flat)
├── trivy.json         # Trivy findings only
├── semgrep.json       # Semgrep findings only
├── checkov.json       # Checkov findings only
├── bandit.json        # Bandit findings only (if Python scanned)
└── sbom.json          # SBOM (if --sbom used)
```

Each per-tool file contains an array of findings in flat format (no metadata wrapper).

## Enriched Scan Results

When using `yavs summarize --enrich`, the AI summary data is added directly to your scan results file instead of creating a separate file.

**Standard scan results:**
```json
{
  "build_cycle": "2025-11-09T03:42:28Z",
  "project": "my-app",
  "compliance": [...],
  "sast": [...],
  "summary": {...}
}
```

**Enriched scan results (with --enrich):**
```json
{
  "build_cycle": "2025-11-09T03:42:28Z",
  "project": "my-app",
  "compliance": [...],
  "sast": [...],
  "summary": {...},
  "ai_summary": {
    "build_cycle": "2025-11-09T05:30:00Z",
    "findings_count": 97,
    "executive_summary": "## Executive Summary\n\n...",
    "ai_provider": "anthropic",
    "ai_model": "claude-sonnet-4-5-20250929",
    "triage": {
      "clusters": [...],
      "cluster_count": 3,
      "total_findings": 97,
      "ai_analysis": "## Triage Analysis\n\n..."
    }
  }
}
```

**How to enrich:**
```bash
# From command line
yavs summarize yavs-results.json --enrich

# Or set in config.yaml
ai:
  summary:
    enrich_scan_results: true
```

**Important:** When using `--enrich`, the `-o/--output-dir` flag is ignored and a warning is shown. The scan results file is always modified in place.

## Migration Guide

### From Flat to Structured

If you were using the old flat array format (before metadata wrapper):

**Old format (pre-v1.0.0):**
```json
[
  { "tool": "trivy", ... },
  { "tool": "semgrep", ... }
]
```

**New flat format (v1.0.0+):**
```json
{
  "build_cycle": "...",
  "project": "...",
  "data": [
    { "tool": "trivy", ... },
    { "tool": "semgrep", ... }
  ]
}
```

**Migration:**
```python
# Old code
findings = json.load(f)

# New code
results = json.load(f)
findings = results['data']  # Access findings array
metadata = {
    'build_cycle': results['build_cycle'],
    'project': results['project'],
    'commit_hash': results['commit_hash'],
    'branch': results['branch']
}
```

## Configuration

Control output format in `config.yaml`:

```yaml
output:
  directory: "."
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"

  # Output format (default: structured)
  structured: true

  # Per-tool files (default: false)
  per_tool_files: false

ai:
  # AI summary/triage output
  summary:
    output_file: "yavs-ai-summary.json"  # Filename for separate summary file
    enrich_scan_results: false            # Add summary to scan results instead
```

Override in CLI:
```bash
# Scan output formats
yavs scan --all --flat
yavs scan --all --per-tool-files
yavs scan --all --flat --per-tool-files

# Summary output options
yavs summarize yavs-results.json                        # Separate file (default dir)
yavs summarize yavs-results.json --enrich               # Enrich scan results
yavs summarize yavs-results.json -o artifacts/summaries # Custom directory
```

## Examples

Complete example files are available in the `docs/` directory:

- **[example-structured-with-ai.json](./example-structured-with-ai.json)**: Structured format with AI fixes
- **[example-structured-enriched.json](./example-structured-enriched.json)**: Structured format enriched with AI summary (shows `ai_summary` field)
- **[example-summary.json](./example-summary.json)**: Standalone AI summary output

See the `examples/` section in each schema file for additional examples.

## Schema Versioning

These schemas follow semantic versioning aligned with YAVS releases:

- **Current version:** v1.0.0
- **Schema ID:** `https://yavs.dev/schema/{format}-output.json`
- **Last updated:** 2025-11-09

## Additional Resources

- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [JSON Schema Documentation](https://json-schema.org/)
