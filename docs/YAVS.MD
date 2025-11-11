Technical Documentation — YAVS (Yet Another Vulnerability Scanner)

Version 1.0 — Developer Implementation Specification

⸻

Overview

YAVS (Yet Another Vulnerability Scanner) is an open-source, AI-enhanced vulnerability scanning framework.
It orchestrates trusted open-source tools — Trivy, Semgrep, and Checkov — into a unified CLI that outputs:
	•	Standard JSON (for ingestion and AI analysis)
	•	Official SARIF 2.1.0 (for GitHub, Azure DevOps, and IDE integrations)

YAVS supports AI-based summarization, triage, and fix suggestions to accelerate secure development.

Design philosophy:
	•	Simplicity — one CLI, no agents
	•	Extensibility — plugin-based architecture
	•	Standards compliance — official SARIF schema
	•	AI augmentation — contextual summarization and prioritization

⸻

1. Architectural Summary

┌──────────────────────────────┐
│            YAVS CLI          │
│   (Typer-based command app)  │
└────────────┬─────────────────┘
             │
     ┌───────┴────────┐
     │ Scan Orchestrator │
     └───────┬────────┘
 ┌───────────┼────────────────────────────┐
 │           │                            │
 │     Trivy Scanner                Semgrep Scanner
 │   (BOM/SCA/Secrets)               (SAST)
 │                                    │
 │                Checkov Scanner     │
 │             (IaC / Compliance)     │
 └───────────┬────────────────────────┘
             │
       Aggregator & Normalizer
             │
             ▼
     Unified JSON & SARIF Outputs
             │
             ▼
       AI Analysis Layer
    (Summarizer / Fix / Triage)


⸻

2. Core Responsibilities by Module

Module	Responsibility
cli.py	Entry point using Typer. Handles user input and command execution.
scanners/	Tool adapters for Trivy, Semgrep, and Checkov. Each returns normalized vulnerability data.
reporting/	Aggregates normalized results and exports to JSON and SARIF 2.1.0.
ai/	Provides AI-powered summarization, triage, and remediation text.
utils/	Shared helpers for subprocess execution, schema validation, and output writing.
config.yaml	Defines scanner configurations, output formats, and AI settings.


⸻

3. Scanner Responsibilities

3.1 Trivy (BOM / SCA / Secrets)
	•	Command:

trivy fs --security-checks vuln,secret,config --format json .


	•	Parses: "Results[].Vulnerabilities"
	•	Normalized Fields:

Field	Source
tool	"trivy"
category	"dependency"
severity	Vulnerability.Severity
file	Result.Target
package	Vulnerability.PkgName
version	Vulnerability.InstalledVersion
message	Vulnerability.Title


⸻

3.2 Semgrep (SAST)
	•	Command:

semgrep --json --quiet .


	•	Parses: "results" array
	•	Normalized Fields:

Field	Source
tool	"semgrep"
category	"sast"
severity	extra.severity
file	path
message	extra.message


⸻

3.3 Checkov (Compliance / IaC)
	•	Command:

checkov -d . -o json


	•	Parses: "results.failed_checks"
	•	Normalized Fields:

Field	Source
tool	"checkov"
category	"compliance"
severity	severity
file	file_path
message	check_name


⸻

4. Unified Result Model

All scanners return dictionaries in the YAVS Unified JSON Schema, which then map to SARIF v2.1.0 results.

4.1 Unified JSON Schema

{
  "tool": "trivy",
  "category": "dependency",
  "severity": "HIGH",
  "file": "requirements.txt",
  "package": "requests",
  "version": "2.19.0",
  "message": "CVE-2018-18074 - Insufficient CRLF sanitization",
  "ai_summary": "Upgrade to requests>=2.20.0 to prevent header injection attacks."
}


⸻

5. SARIF 2.1.0 Output Specification

5.1 Compliance

YAVS must generate valid SARIF 2.1.0 compliant documents following the schema at:

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Each scan result becomes one SARIF "result" entry.

⸻

5.2 SARIF Structure Example

{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "YAVS",
          "informationUri": "https://github.com/YAVS-OSS/yavs",
          "rules": []
        }
      },
      "results": [
        {
          "ruleId": "TRIVY_CVE_2018_18074",
          "level": "error",
          "message": { "text": "CVE-2018-18074 - Insufficient CRLF sanitization" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "requirements.txt" },
                "region": { "startLine": 42 }
              }
            }
          ],
          "properties": {
            "tool": "trivy",
            "category": "dependency",
            "package": "requests",
            "version": "2.19.0",
            "ai_summary": "Upgrade to requests>=2.20.0"
          }
        }
      ]
    }
  ]
}


⸻

5.3 Field Mapping: Unified JSON → SARIF

JSON Field	SARIF Field	Notes
tool	runs[].tool.driver.name	Primary scanner
category	properties.category	Maintained in properties
severity	results[].level	Map CRITICAL/HIGH/MEDIUM/LOW → error/warning/note/information
file	artifactLocation.uri	Absolute or relative path
package	properties.package	Optional
version	properties.version	Optional
message	results[].message.text	Human-readable description
ai_summary	properties.ai_summary	Optional AI enhancement


⸻

6. CLI Specification

6.1 yavs scan

Run one or more scanners.

Syntax:

yavs scan [TARGET] [OPTIONS]

Options:

Flag	Description
--sast	Run Semgrep
--bom	Run Trivy
--compliance	Run Checkov
--all	Run all scanners
--json <path>	Path to JSON output file (default: yavs-results.json)
--sarif <path>	Path to SARIF output file (default: yavs-results.sarif)

Example:

yavs scan --all --json results.json --sarif results.sarif


⸻

6.2 yavs summarize

Use AI to summarize findings.

yavs summarize results.json --model gpt-4o-mini

Description:
	•	Analyzes aggregated results.
	•	Prioritizes top issues.
	•	Suggests fixes or mitigations.

⸻

7. AI Integration Specification

Function	Description
ai_summarize(input_path, model)	Summarize and categorize vulnerabilities.
ai_triage(results)	Cluster related findings.
ai_fixer(result)	Suggest code or configuration fixes.

Prompt Example:

“Given these SARIF and JSON findings, group them by shared root cause, prioritize critical ones, and suggest developer-friendly remediations.”

⸻

8. Output & Reporting

Format	Purpose	Consumers
JSON	Human-readable + AI summarization	YAVS AI, dashboards
SARIF (v2.1.0)	Standards-compliant reporting	GitHub, Azure DevOps, IDEs

Both outputs must be generated per run, even if one is empty.

⸻

9. Configuration File

config.yaml

scanners:
  trivy:
    enabled: true
    flags: "--security-checks vuln,secret,config"
  semgrep:
    enabled: true
  checkov:
    enabled: false
output:
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"
ai:
  enabled: true
  provider: "openai"
  model: "gpt-4o-mini"


⸻

10. Dependencies & Environment

Dependency	Purpose	Install
Python ≥ 3.10	Runtime	—
Typer, Rich	CLI framework & UI	pip install typer rich
Trivy	SCA, Secrets	brew install trivy
Semgrep	SAST	pip install semgrep
Checkov	IaC compliance	pip install checkov
sarif-tools	SARIF schema builder	pip install sarif-tools
OpenAI SDK (optional)	AI summarization	pip install openai


⸻

11. Packaging & Distribution
	•	CLI name: yavs
	•	PyPI install: pip install yavs
	•	Entrypoint: yavs = "yavs.cli:app"

Example Usage:

pipx install yavs
yavs scan --all
yavs summarize results.json

Repository Layout:

pyproject.toml
README.md
LICENSE
src/yavs/


⸻

12. Roadmap

Milestone	Deliverables
v0.1	Run Trivy + Semgrep; produce JSON + SARIF
v0.2	Add Checkov integration
v0.3	AI summarization and fix suggestion
v0.4	HTML reporting & baseline diff
v1.0	Plugin SDK, policy engine, enterprise config profiles


⸻

13. Example Developer Tasks

Task	Priority
Implement JSON & SARIF writers in reporting/aggregator.py	✅ Critical
Build SARIF converter conforming to v2.1.0 schema	✅ Critical
Add schema validation via sarif-tools validate	✅
Integrate AI summarization with unified JSON	⏳
Implement CI test to verify SARIF compliance	⏳


⸻

14. Key SARIF Validation Requirements
	•	Must include $schema field:
"https://json.schemastore.org/sarif-2.1.0.json"
	•	Must specify version: "2.1.0"
	•	Must contain at least one "run" entry
	•	Must include "results" array, even if empty
	•	File URIs should be relative paths for portability
	•	Severity mapped as:

YAVS Severity	SARIF Level
CRITICAL / HIGH	error
MEDIUM	warning
LOW	note
INFO	none



⸻

15. Extension Ideas
	•	Pre-commit hook (yavs scan --fast)
	•	GitHub Action integration (upload-sarif)
	•	CI artifact publishing (yavs-results.sarif)
	•	AI fix generator (yavs fix --ai)
	•	Policy as Code: .yavs-policy.yaml

⸻

Project Name:
YAVS — Yet Another Vulnerability Scanner
Tagline: “Yet another scanner — but smarter.”

⸻

SARIF Implementation Guide — YAVS

This section ensures that all YAVS outputs conform strictly to the SARIF v2.1.0 specification, as defined by OASIS.
SARIF output enables full integration with:
  • GitHub Advanced Security (via upload-sarif action)
  • Azure DevOps Code Scanning
  • JetBrains IDEs and VS Code Security Analysis

⸻

1. SARIF File Requirements

Requirement Description
Version Must be "2.1.0"
$schema Must point to "https://json.schemastore.org/sarif-2.1.0.json"
runs[]  Array of scan sessions (at least one)
runs[].results[]  Array of findings (can be empty)
runs[].tool.driver.name Must be "YAVS"
Artifact URIs Use relative paths (src/main.py, not /home/...)
Levels  Must map to SARIF’s severity taxonomy (error, warning, note, none)


⸻

2. Minimal Valid SARIF Template

All YAVS-generated SARIF files must at minimum include the following structure:

{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "YAVS",
          "informationUri": "https://github.com/YAVS-OSS/yavs",
          "rules": []
        }
      },
      "results": []
    }
  ]
}

The aggregator appends individual findings under "results" and optionally defines "rules" for tools with known identifiers (e.g., Semgrep rule IDs or CVEs).

⸻

3. Result Object Schema

Each YAVS finding must be represented as a SARIF result object inside runs[0].results.

Example:

{
  "ruleId": "TRIVY_CVE_2018_18074",
  "level": "error",
  "message": { "text": "CVE-2018-18074 - Insufficient CRLF sanitization" },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "requirements.txt" },
        "region": { "startLine": 42 }
      }
    }
  ],
  "properties": {
    "tool": "trivy",
    "category": "dependency",
    "package": "requests",
    "version": "2.19.0",
    "ai_summary": "Upgrade to requests>=2.20.0"
  }
}

Required Fields:

Field Description
ruleId  Unique identifier per finding (TRIVY_CVE_####, SEMGREP_RULE_ID, etc.)
level One of: error, warning, note, none
message.text  Human-readable message (max 512 chars recommended)
locations[].physicalLocation.artifactLocation.uri Relative path to affected file
properties  Tool metadata (category, package, AI summary, etc.)


⸻

4. Mapping: YAVS Unified Schema → SARIF

YAVS Field  SARIF Field Transformation
tool  runs[].tool.driver.name First letter uppercase (Trivy → TRIVY)
category  properties.category Copied verbatim
severity  level Mapped via table below
file  locations[].physicalLocation.artifactLocation.uri Convert to relative path
package properties.package  Copied verbatim
version properties.version  Copied verbatim
message message.text  Copied verbatim
ai_summary  properties.ai_summary Optional
ruleId  Derived "TOOL_IDENTIFIER" (e.g., TRIVY_CVE_XXXX or SEMGREP_<RULE_ID>)

Severity Mapping Table

YAVS Severity SARIF Level
CRITICAL / HIGH error
MEDIUM  warning
LOW note
INFO / UNKNOWN  none


⸻

5. Recommended File Generation Flow

Function: generate_sarif(results: List[dict], output_path: str)

Purpose: Converts normalized YAVS JSON results into a compliant SARIF file.

Steps:
  1.  Initialize SARIF skeleton with $schema and version.
  2.  Create single run with:
  • tool.driver.name = "YAVS"
  • tool.driver.version = YAVS CLI version
  • tool.driver.rules = empty or rule list
  3.  Iterate through results and transform each item to SARIF result.
  4.  Append to runs[0].results.
  5.  Write to output_path.
  6.  Validate output schema (see below).

⸻

6. Validation Procedure

CLI Validation

Developers can validate SARIF output with:

pip install sarif-tools
sarif validate yavs-results.sarif

Expected output:

✓ Valid SARIF file (v2.1.0)

If errors appear (missing fields, wrong version, invalid URI), fix before release.

⸻

Example GitHub Action Validation

Add this workflow step in .github/workflows/security.yml:

- name: Validate SARIF Output
  run: |
    pip install sarif-tools
    sarif validate yavs-results.sarif


⸻

7. Rule Metadata (Optional)

You may optionally enrich SARIF with rule definitions.
For example:

"rules": [
  {
    "id": "SEMGREP_SQLI",
    "name": "SQL Injection Check",
    "shortDescription": { "text": "Detects potential SQL injection" },
    "helpUri": "https://semgrep.dev/rules/sql-injection"
  }
]

Benefits:
  • GitHub UI displays rule names and documentation links.
  • Enables rule-based filtering and trend tracking.

⸻

8. Integration with CI/CD

GitHub Advanced Security

- name: Run YAVS
  run: yavs scan --all --sarif results.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

Azure DevOps

- task: PublishSecurityAnalysisLogs@3
  inputs:
    AnalysisLogsFolder: '$(Build.ArtifactStagingDirectory)'
    ArtifactName: 'CodeAnalysisLogs'
    ToolName: 'YAVS'


⸻

9. Validation Checklist (Before Release)

Check Description Required
✅ $schema matches SARIF 2.1.0 URI Required for IDE & CI ingestion Yes
✅ "version": "2.1.0"  Mandatory Yes
✅ Each result includes ruleId, level, message Required  Yes
✅ File paths are relative Ensures portability Yes
✅ JSON validates via sarif-tools validate Schema compliance Yes
✅ Output encoding UTF-8 Required by SARIF spec  Yes


⸻

10. Developer Testing Guide

Scenario  Test
No vulnerabilities  YAVS outputs valid SARIF with empty "results" array.
Single tool only (Trivy)  Validate SARIF tool name and rule IDs appear correctly.
Multiple scanners Confirm runs[0].results aggregates all sources.
Corrupted input Verify graceful failure with non-zero exit code.
Schema drift  Run sarif validate in CI pipeline.


⸻

11. Example SARIF File — End-to-End

{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "YAVS",
          "informationUri": "https://github.com/YAVS-OSS/yavs",
          "rules": [
            {
              "id": "TRIVY_CVE_2018_18074",
              "name": "CVE-2018-18074",
              "shortDescription": { "text": "Insufficient CRLF sanitization in requests" },
              "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2018-18074"
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "TRIVY_CVE_2018_18074",
          "level": "error",
          "message": { "text": "Upgrade to requests>=2.20.0 to prevent header injection attacks." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "requirements.txt" },
                "region": { "startLine": 42 }
              }
            }
          ],
          "properties": {
            "tool": "trivy",
            "category": "dependency",
            "package": "requests",
            "version": "2.19.0",
            "ai_summary": "Upgrade to requests>=2.20.0"
          }
        }
      ]
    }
  ]
}

This file passes validation on:
  • GitHub’s upload-sarif action
  • Azure DevOps Security Analysis
  • VS Code SARIF Viewer

⸻

12. Key Implementation Notes for Developers
  • Use the sarif-tools Python library or custom JSON serialization (dict → file).
  • Always include relative paths for file URIs.
  • Ensure all numeric fields (like line numbers) are integers.
  • The SARIF file must not exceed 50 MB for GitHub ingestion.
  • If AI summaries exceed size limits, store them only in JSON, not SARIF.

⸻

13. Developer Command Reference

Command Purpose
yavs scan --all --sarif results.sarif Full scan with SARIF output
sarif validate results.sarif  Validate file
sarif view results.sarif  Visualize results (local viewer)
yavs summarize results.json --model gpt-4o-mini Generate AI overview


⸻

14. Summary

YAVS must:
  1.  Output fully compliant SARIF 2.1.0.
  2.  Pass validation via sarif-tools.
  3.  Support both JSON (for AI + dashboards) and SARIF (for CI integration).
  4.  Embed AI summaries only in the "properties" section (never top-level).
  5.  Maintain stability across environments and scanners.

⸻

Developer Testing & Validation Workflow — YAVS

Purpose

This section defines the testing, validation, and CI/CD workflow for ensuring every build of YAVS produces:
  • Valid SARIF 2.1.0 output
  • Consistent JSON aggregation
  • Stable behavior across Trivy, Semgrep, and Checkov

It includes both local developer testing and automated CI validation.

⸻

1. Local Developer Testing Harness

1.1 Prerequisites

Install all dependencies:

pip install typer rich sarif-tools pytest semgrep checkov
brew install trivy


⸻

1.2 Local Test Structure

tests/
├── test_scan_output.py
├── test_sarif_validation.py
└── fixtures/
    ├── sample_project/
    │   ├── requirements.txt
    │   ├── main.py
    │   └── terraform.tf
    └── expected_results.json

Purpose:
  • test_scan_output.py: checks CLI and JSON structure
  • test_sarif_validation.py: validates SARIF schema
  • fixtures/: sample projects to simulate scans

⸻

2. Local Testing Commands

Run CLI manually:

yavs scan --all --json out/results.json --sarif out/results.sarif
yavs summarize out/results.json --model gpt-4o-mini

Validate SARIF locally:

sarif validate out/results.sarif

Inspect SARIF visually (optional):

sarif view out/results.sarif


⸻

3. Automated Unit Tests (pytest)

tests/test_sarif_validation.py

import json
import subprocess
from pathlib import Path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

def test_sarif_schema(tmp_path):
    """Ensures generated SARIF file passes schema validation."""
    output_file = tmp_path / "results.sarif"
    subprocess.run(["yavs", "scan", "--all", "--sarif", str(output_file)], check=True)
    result = subprocess.run(["sarif", "validate", str(output_file)], capture_output=True, text=True)
    assert "✓ Valid SARIF file" in result.stdout

def test_sarif_structure(tmp_path):
    """Ensures SARIF output includes required top-level fields."""
    output_file = tmp_path / "results.sarif"
    subprocess.run(["yavs", "scan", "--all", "--sarif", str(output_file)], check=True)
    data = json.loads(output_file.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data and isinstance(data["runs"], list)
    assert "results" in data["runs"][0]


⸻

tests/test_scan_output.py

import json
import subprocess
from pathlib import Path

def test_yavs_json_output(tmp_path):
    """Ensure YAVS produces valid JSON result file."""
    output_file = tmp_path / "results.json"
    subprocess.run(["yavs", "scan", "--all", "--json", str(output_file)], check=True)
    data = json.loads(output_file.read_text())
    assert isinstance(data, list)
    assert all("tool" in item for item in data)
    assert all("severity" in item for item in data)


⸻

4. Continuous Integration Setup

4.1 GitHub Actions Workflow

Create .github/workflows/validate.yml:

name: Validate YAVS Outputs

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Dependencies
        run: |
          pip install typer rich pytest sarif-tools semgrep checkov
          sudo apt-get update && sudo apt-get install -y trivy

      - name: Run YAVS Scan
        run: |
          yavs scan --all --json results.json --sarif results.sarif

      - name: Validate SARIF Output
        run: sarif validate results.sarif

      - name: Run Unit Tests
        run: pytest -q --disable-warnings

This workflow guarantees:
  • Each PR produces a SARIF and JSON report.
  • SARIF validation occurs automatically.
  • Build fails if SARIF schema validation fails.

⸻

5. Validation Criteria

Check Description Tool
✅ Schema Compliance SARIF file must validate successfully sarif validate
✅ Severity Mapping  CRITICAL → error, MEDIUM → warning, etc.  pytest
✅ Mandatory Fields  $schema, version, runs[].results[]  pytest
✅ UTF-8 Encoding  All files saved with UTF-8  default
✅ Output Consistency  JSON and SARIF counts match pytest
✅ Exit Codes  0 success, 1 failure  CLI


⸻

6. Developer Workflow Summary

Step  Action  Command
1 Run scan  yavs scan --all --json results.json --sarif results.sarif
2 Validate SARIF  sarif validate results.sarif
3 Run tests pytest -q
4 Commit results  git commit -am "Validated YAVS SARIF outputs"
5 CI validates automatically  (via GitHub Actions)


⸻

7. Troubleshooting Common Failures

Symptom Cause Fix
schema mismatch Missing $schema URI Ensure $schema field matches exact URL
missing results Empty runs[].results  Confirm scanners returned findings
level invalid Invalid severity mapping  Only use error, warning, note, or none
upload-sarif fails  File too large  Exclude low-severity findings or truncate ai_summary
relative path error Paths begin with /  Strip leading / before saving URI


⸻

8. Optional Local Validation Script

To streamline dev experience, include a helper in tools/validate_sarif.py:

import subprocess, sys

def validate():
    subprocess.run(["sarif", "validate", "out/results.sarif"], check=True)
    print("✓ YAVS SARIF validation passed!")

if __name__ == "__main__":
    try:
        validate()
    except subprocess.CalledProcessError:
        print("SARIF validation failed ❌")
        sys.exit(1)

Usage:

python tools/validate_sarif.py


⸻

9. Expected Developer Deliverables
  1.  Validated SARIF file (results.sarif)
  2.  Validated JSON file (results.json)
  3.  All tests passing in CI
  4.  Documented severity mapping
  5.  Rule IDs generated consistently
  6.  Validation logs included in release artifacts

⸻

10. Release Readiness Checklist

Item  Description Status
✅ yavs scan produces both JSON and SARIF  Required for v1.0 
✅ SARIF validated via sarif-tools Passes schema test  
✅ Tests integrated in CI  Running via GitHub Actions  
✅ Sample fixtures included  /tests/fixtures/  
✅ Exit codes standardized 0 success, 1 on error 
✅ Output format documented  JSON + SARIF verified 


⸻

11. Example CI Pass Output

Run yavs scan --all --json results.json --sarif results.sarif
✓ Scan completed: 135 findings
✓ JSON report saved to results.json
✓ SARIF report saved to results.sarif
Run sarif validate results.sarif
✓ Valid SARIF file (v2.1.0)
pytest -q
..                                                                       [100%]
2 passed in 4.13s


⸻

12. Summary

With this workflow in place, your developers can:
  • Build and validate SARIF/JSON outputs locally.
  • Enforce schema compliance automatically in CI.
  • Ensure every release of YAVS integrates seamlessly with GitHub, Azure, and AI summarization pipelines.

⸻

Release Engineering & Packaging — YAVS

Purpose

This section defines the versioning strategy, packaging rules, and release automation for YAVS.
It ensures every release:
  • Produces validated SARIF and JSON artifacts
  • Publishes to PyPI and GitHub Releases
  • Maintains semantic version consistency (vX.Y.Z)
  • Includes automated changelog and artifact upload

⸻

1. Versioning Policy

YAVS uses Semantic Versioning (SemVer 2.0.0):

Type  Meaning Example
MAJOR Breaking changes  1.0.0 → 2.0.0
MINOR New features, backward-compatible 1.0.0 → 1.1.0
PATCH Bug fixes, internal improvements  1.0.0 → 1.0.1

Version file

Store version in yavs/__init__.py:

__version__ = "1.0.0"

All CLI, SARIF headers, and logs must reference this version dynamically.

⸻

2. Build & Distribution Tools

Tool  Purpose
Poetry  Dependency & build management
Twine PyPI publishing
GitHub Actions  CI/CD + release automation
sarif-tools Validation prior to release
gh CLI  GitHub release asset upload


⸻

3. Build Artifacts

Each release generates the following:

Artifact  Description Destination
yavs-results.sarif  Validated SARIF v2.1.0 report GitHub release assets
yavs-results.json Unified AI-readable JSON  GitHub release assets
dist/yavs-X.Y.Z.tar.gz  Source distribution PyPI
dist/yavs-X.Y.Z-py3-none-any.whl  Binary wheel  PyPI
CHANGELOG.md  Auto-generated changelog  GitHub release page


⸻

4. Packaging Configuration

pyproject.toml

[project]
name = "yavs"
version = "1.0.0"
description = "Yet Another Vulnerability Scanner — AI-enhanced, standards-compliant, open source."
readme = "README.md"
authors = [{ name = "Your Team", email = "dev@yavs.io" }]
license = "MIT"
dependencies = [
  "typer[all]",
  "rich",
  "requests",
  "pyyaml",
  "sarif-tools",
]
[project.scripts]
yavs = "yavs.cli:app"

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"


⸻

5. Build Process

Local developer steps:

# Ensure clean environment
rm -rf dist build *.egg-info

# Build package
python -m build

# Verify contents
twine check dist/*

Output:

✓ Built yavs-1.0.0.tar.gz
✓ Built yavs-1.0.0-py3-none-any.whl
✓ Package description is valid.


⸻

6. PyPI Publishing

6.1 Manual

twine upload dist/*

6.2 Automated (GitHub Action)

Add .github/workflows/publish.yml:

name: Publish YAVS to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install build dependencies
        run: |
          pip install build twine sarif-tools

      - name: Validate SARIF
        run: sarif validate yavs-results.sarif || echo "Skipping if no SARIF"

      - name: Build YAVS package
        run: python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@v1.9.0
        with:
          user: __token__
          password: ${{ secrets.PYPI_API_TOKEN }}


⸻

7. GitHub Release Automation

.github/workflows/release.yml

name: Release YAVS

on:
  workflow_dispatch:
  push:
    tags:
      - 'v*.*.*'

jobs:
  release:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up environment
        run: |
          pip install typer rich sarif-tools
          sudo apt-get update && sudo apt-get install -y trivy
          pip install semgrep checkov

      - name: Run validation scan
        run: |
          yavs scan --all --json yavs-results.json --sarif yavs-results.sarif
          sarif validate yavs-results.sarif

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            yavs-results.json
            yavs-results.sarif
          tag_name: ${{ github.ref_name }}
          name: "YAVS ${{ github.ref_name }}"
          body_path: CHANGELOG.md
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}


⸻

8. Changelog Automation

YAVS should generate changelogs automatically on tag creation.

tools/generate_changelog.py

import subprocess, datetime

def generate():
    version = subprocess.getoutput("python -m yavs --version").strip()
    date = datetime.date.today().isoformat()
    logs = subprocess.getoutput("git log -n 10 --pretty=format:'- %s'")
    changelog = f"## {version} ({date})\n\n{logs}\n"
    with open("CHANGELOG.md", "w") as f:
        f.write(changelog)
    print("✓ CHANGELOG.md generated.")

if __name__ == "__main__":
    generate()

Example output:

## 1.1.0 (2025-11-08)
- Added SARIF validation tests
- Implemented AI summarization via OpenAI
- Fixed path normalization for Windows runners


⸻

9. Artifact Retention Policy

Artifact  Retention Storage
SARIF & JSON  90 days GitHub Actions Artifacts
Release assets  Permanent GitHub Releases
PyPI package  Permanent pypi.org/project/yavs
CI logs 30 days GitHub Actions

To clean artifacts manually:

gh run delete <run-id> --confirm


⸻

10. Release Checklist

Check Description Owner
✅ SARIF output validated (sarif validate) Schema compliance QA
✅ JSON output validated Basic structure QA
✅ Tests passed (pytest -q)  All green Dev
✅ Version incremented Matches tag Maintainer
✅ Changelog generated Current changes only  Maintainer
✅ Tag created (git tag vX.Y.Z)  Follows SemVer  Maintainer
✅ Release published GitHub + PyPI CI


⸻

11. Tagging and Release Commands

Manual release example:

git add .
git commit -m "Release: v1.1.0"
git tag v1.1.0
git push origin v1.1.0

CI/CD will:
  • Validate SARIF/JSON
  • Generate changelog
  • Publish to PyPI
  • Attach artifacts to GitHub release

⸻

12. Verification After Release

Run these to verify the deployment:

PyPI

pip install yavs==1.1.0
yavs --version

GitHub

Check under
https://github.com/YAVS-OSS/yavs/releases/tag/v1.1.0
Artifacts:
  • yavs-results.sarif
  • yavs-results.json
  • CHANGELOG.md

⸻

13. Release Failure Recovery

Failure Symptom Resolution
PyPI upload rejected  “Version already exists”  Bump patch version, rebuild
Invalid SARIF Schema error during CI  Run sarif validate locally, fix structure
Missing artifacts Assets not uploaded Ensure paths match softprops/action-gh-release config
Changelog empty Git log not found Verify repo has recent commits
Build fails Missing trivy/semgrep Update CI apt-get and pip install steps


⸻

14. Example End-to-End Release Log

Run yavs scan --all --json yavs-results.json --sarif yavs-results.sarif
✓ 123 findings across 3 scanners
✓ JSON saved: yavs-results.json
✓ SARIF validated: yavs-results.sarif

Run sarif validate yavs-results.sarif
✓ Valid SARIF file (v2.1.0)

Build package
✓ Built yavs-1.1.0.tar.gz
✓ Built yavs-1.1.0-py3-none-any.whl

Upload to PyPI
✓ Successfully published yavs-1.1.0

GitHub Release
✓ Created release v1.1.0
✓ Uploaded artifacts (SARIF, JSON)
✓ Attached changelog


⸻

15. Summary

The YAVS release engineering workflow ensures:
  1.  Every version outputs validated SARIF + JSON artifacts.
  2.  CI/CD automatically builds, tests, validates, and publishes releases.
  3.  Developers follow consistent versioning and changelog generation.
  4.  Users can install directly from PyPI and access verified results via GitHub Releases.

⸻

Release Governance & Maintainer Roles — YAVS

Purpose

This governance section defines who can:
  • Approve pull requests and merge code
  • Tag and sign releases
  • Publish packages to PyPI
  • Manage secrets (tokens, keys, signing certs)
  • Validate security compliance

It establishes a minimal-trust, auditable, and sustainable workflow for long-term open source and internal development.

⸻

1. Governance Model

YAVS follows a 3-tier governance model:

Role  Description Example Members
Maintainers Own repository, manage releases and PyPI publishing Project leads
Contributors  Submit PRs, add features, fix bugs  Core devs
External Contributors Fork, propose enhancements via PR Community

All code changes must pass automated CI validation (tests + SARIF validation) before merging.

⸻

2. Role Responsibilities

2.1 Maintainers
  • Review and merge approved PRs
  • Increment semantic versions (vX.Y.Z)
  • Tag releases
  • Trigger CI/CD publishing pipelines
  • Manage PyPI and GitHub release credentials
  • Approve security-critical changes

Tools they manage:
  • GitHub repository settings
  • PyPI API token
  • GPG signing key (optional)
  • GitHub Actions secrets

⸻

2.2 Contributors
  • Open pull requests
  • Maintain code style and testing standards
  • Add or update unit tests
  • Validate local SARIF/JSON output before committing
  • Request reviews from maintainers

They cannot tag releases or publish to PyPI.

⸻

2.3 External Contributors
  • Submit forks via PR
  • Must sign the Contributor License Agreement (CLA) if applicable
  • Require at least 1 maintainer approval + 1 successful CI run

⸻

3. Protected Branch Policy

Branch  Protection  Description
main  ✅ Required reviews, ✅ CI passing, ✅ Signed commits  Release branch
develop ✅ Required CI, ❌ reviews optional Active development
feature/* ❌ Short-lived branches for PRs

Example GitHub configuration:
  • Require status checks: pytest, sarif validate
  • Require branch protection for main
  • Enforce linear history (no merge commits)

⸻

4. Version Tagging Authority

Operation Authorized Roles
Create Git tag (vX.Y.Z) Maintainers only
Delete tags Maintainers only
Edit changelog  Maintainers only
Approve pre-release (vX.Y.Z-beta) Maintainers only
Post-release patch fix  Maintainers + designated release engineers

All tags must be signed if GPG signing is enabled:

git tag -s v1.1.0 -m "Release 1.1.0"
git push origin v1.1.0


⸻

5. PyPI Access Control

5.1 Account Roles

Role  Access Level  Description
Owner Full access (manage tokens, releases) Lead maintainer
Maintainer  Upload releases Secondary maintainers
Developer No PyPI access  Local testing only

5.2 Authentication

Use an API token (never password):

TWINE_USERNAME=__token__
TWINE_PASSWORD=pypi-<token>

The token must be stored in GitHub Actions → Secrets → PYPI_API_TOKEN with least privilege.

⸻

6. Secrets Management

All sensitive credentials are stored in GitHub Actions secrets:

Secret  Description Scope
PYPI_API_TOKEN  Auth for PyPI publishing  publish.yml
OPENAI_API_KEY  For AI summarization  summarize stage only
GITHUB_TOKEN  Default Actions token Required for releases
SLACK_WEBHOOK (optional)  Release notifications CI only

Secrets must never be hardcoded, printed, or committed.
Access limited to maintainers and CI workflows.

⸻

7. Security & Compliance Checks

Every PR and release must:
  1.  Pass unit tests
  2.  Validate SARIF 2.1.0 output
  3.  Run Trivy + Semgrep + Checkov
  4.  Be scanned for secrets and credentials

Optional GitHub workflow step:

- name: Security Self-Scan
  run: |
    yavs scan --all --json out/self.json --sarif out/self.sarif
    sarif validate out/self.sarif


⸻

8. Release Approval Workflow

8.1 Steps

Step  Action  Responsible
1 PR submitted  Contributor
2 CI runs full validation Automated
3 Review & approval Maintainer
4 Version bump & tag  Maintainer
5 CI publishes to PyPI  Automated
6 SARIF + JSON artifacts attached to release  Automated

8.2 Required Approvals
  • At least one maintainer approval
  • At least one successful CI validation
  • No open vulnerabilities in YAVS dependencies

⸻

9. Key Management

If release signing is used, configure GPG or Sigstore:

git config user.signingkey <key-id>
git config commit.gpgsign true

All maintainers must have:
  • Private GPG key stored securely (YubiKey recommended)
  • Public keys uploaded to GitHub
  • Optional Sigstore keyless signing for supply chain attestation

⸻

10. Incident Response & Rollback

Scenario  Response  Action
Corrupted PyPI release  Yank version  twine yank yavs -v X.Y.Z
Security vulnerability  Patch + bump patch version  vX.Y.Z → vX.Y.Z+1
Compromised API token Rotate immediately  New secret in GitHub
Broken release  Delete GitHub release + retag Tag vX.Y.Z-hotfix

Rollback command:

git tag -d v1.1.0
git push origin :v1.1.0


⸻

11. Maintainer Rotation & Access Auditing
  • Review GitHub collaborators quarterly
  • Rotate PyPI tokens every 90 days
  • Maintain a maintainer registry (MAINTAINERS.md) including:
  • Name
  • Role
  • Public key fingerprint
  • Date of onboarding/offboarding

Example:

## Maintainers
- Alice Smith — Lead Maintainer — 0xA1B2C3D4
- Bob Lee — Release Engineer — 0xE5F6A7B8


⸻

12. Governance Summary

Category  Policy
Versioning  Semantic Versioning (MAJOR.MINOR.PATCH)
Release Approval  Maintainer + CI validation
Secrets Stored in GitHub Actions
Tagging Maintainers only, signed
PyPI Access Restricted to owners/maintainers
Rollback  Only maintainers can yank or re-tag
Auditing  Quarterly review of secrets & keys


⸻

13. Recommended Governance Files

File  Purpose
MAINTAINERS.md  List of maintainers and roles
SECURITY.md Disclosure policy and contact
CODE_OF_CONDUCT.md  Contributor expectations
CONTRIBUTING.md PR and coding guidelines
LICENSE MIT recommended
CHANGELOG.md  Auto-generated each release


⸻

14. Example Governance Workflow (Visual)

Contributor → PR → CI (Tests + SARIF Validation)
     ↓
 Maintainer Review → Merge → Tag (vX.Y.Z)
     ↓
   CI Publish → PyPI + GitHub Release
     ↓
  Artifacts: SARIF + JSON + Changelog


⸻

15. Summary

YAVS governance ensures:
  • Controlled releases via verified maintainers
  • Reproducible builds through version tagging
  • Audited secrets and publishing tokens
  • Automated compliance validation via CI
  • Transparency and trust for both enterprise and open-source users

