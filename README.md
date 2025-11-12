<div align="center">
  <img src="docs/images/bug.png" alt="YAVS Logo" width="200"/>
</div>

---

# YAVS

### Yet Another Vulnerability Scanner

**AI-Enhanced Security Scanning with SARIF 2.1.0 Output**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Anthropic Claude](https://img.shields.io/badge/AI-Claude%20Sonnet%204.5-blueviolet.svg)](https://www.anthropic.com/)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Workflows](#-github-actions-workflows) • [Contributing](#-contributing)


## 🎯 What is YAVS?

YAVS is a **next-generation vulnerability scanner** that unifies industry-leading security tools (Trivy, Semgrep, Checkov) and enhances them with **Claude AI** for intelligent analysis. Get comprehensive security coverage with AI-powered insights, all in standards-compliant SARIF 2.1.0 format.

### Why YAVS?

<table>
  <tr>
    <td>🔍 <b>Unified Scanning</b></td>
    <td>One tool, three scanners — no more juggling multiple security tools</td>
  </tr>
  <tr>
    <td>🤖 <b>AI-Powered</b></td>
    <td>Claude AI provides smart summaries, triage, and fix suggestions</td>
  </tr>
  <tr>
    <td>📊 <b>Standards Compliant</b></td>
    <td>SARIF 2.1.0 output integrates with GitHub, Azure DevOps, and IDEs</td>
  </tr>
  <tr>
    <td>⚡ <b>Production Ready</b></td>
    <td>Built-in GitHub Actions workflows for instant CI/CD integration</td>
  </tr>
  <tr>
    <td>🎯 <b>Developer Friendly</b></td>
    <td>Simple CLI, rich output, and actionable insights</td>
  </tr>
  <tr>
    <td>🔧 <b>Flexible</b></td>
    <td>YAML configuration, custom policies, and extensible architecture</td>
  </tr>
</table>

---

## ✨ Features

### 🔍 Comprehensive Security Coverage

- **🛡️ SCA/SBOM (Software Composition Analysis)** — Detect vulnerable dependencies via Trivy
- **🔒 SAST (Static Application Security Testing)** — Find code vulnerabilities via Semgrep, Bandit, BinSkim
- **⚙️ IaC Compliance** — Validate infrastructure as code via Checkov
- **🔐 Secret Detection** — Catch exposed credentials and API keys via Trivy
- **🐳 Container Scanning** — Scan Docker images for CVEs and misconfigurations
- **📦 Multi-Language** — Python, JavaScript/Node.js, Java, Go, Terraform, Kubernetes, and more
- **🗂️ Multi-Directory** — Scan multiple directories in a single run
- **🎯 Ignore Patterns** — Filter findings with regex patterns to reduce noise
- **📊 Statistics** — Instant scan statistics and metrics via `yavs stats`
- **🔕 Baseline Management** — Suppress false positives with `yavs ignore` commands
- **⏰ Baseline Expiration** — Time-bound suppressions for tech debt management with `--expires`
- **🚀 Auto-Detection** — Intelligent project type detection with `--auto` flag
- **📄 CSV/TSV Export** — Spreadsheet-friendly formats with `--csv` and `--tsv` flags

### 🤖 AI-Enhanced Analysis

Powered by **Anthropic's Claude Sonnet 4.5**:

- 📝 **Executive Summaries** — Get plain-English explanations of security findings
- 🎯 **Smart Triage** — AI clusters related issues and identifies root causes
- 🔧 **Fix Suggestions** — Receive specific remediation code and upgrade paths
- 📊 **Risk Assessment** — Understand overall security posture at a glance
- 🧠 **Pattern Recognition** — Detect systemic issues and recurring vulnerabilities

### 📊 Standards-Compliant Output

- **SARIF 2.1.0** — Full compliance with Static Analysis Results Interchange Format
- **GitHub Integration** — Upload to GitHub Security tab automatically
- **IDE Support** — Works with VS Code, JetBrains, and other SARIF viewers
- **CI/CD Ready** — Azure DevOps, Jenkins, CircleCI compatible
- **JSON Export** — Clean, normalized format for custom tooling

### 🛠️ Production-Ready Tooling

- **Configuration Management** — YAML config with `yavs config` commands
- **Tool Management** — Install/upgrade scanners with `yavs tools` commands
- **Statistics & Metrics** — Quick insights with `yavs stats` command
- **Baseline Suppression** — Manage false positives with `yavs ignore` commands
- **Diff Comparison** — Track security changes over time with `yavs diff`
- **Policy Enforcement** — CI/CD gates with `--fail-on` severity thresholds

---

## 🚀 Quick Start

### Installation

**Option 1: Automated Setup (Recommended)**

```bash
# Install YAVS (includes Semgrep, Checkov, Bandit)
pip install yavs

# Run setup wizard - installs Trivy automatically
yavs tools install

# Or use package manager for Trivy
yavs tools install --use-brew
```

**Option 2: Manual Installation**

```bash
# Install YAVS
pip install yavs

# Install Trivy manually
brew install trivy              # macOS

# Optional: Install BinSkim (for Windows binary analysis)
dotnet tool install --global Microsoft.CodeAnalysis.BinSkim
```

<details>
<summary>📦 Linux Installation</summary>

**Automated (Recommended):**

```bash
# Install YAVS (includes Semgrep, Checkov, Bandit)
pip install yavs

# Run setup wizard - installs Trivy automatically
yavs tools install
```

**Manual:**

```bash
# Install YAVS
pip install yavs

# Install Trivy (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Or use setup command with package manager
yavs tools install --use-brew  # Uses apt on Linux
```
</details>

### Basic Usage

```bash
# Scan current directory with all scanners
yavs scan --all

# Scan specific project
yavs scan /path/to/project --all

# Custom output paths
yavs scan --all --json results.json --sarif results.sarif

# Generate AI-powered summary
export ANTHROPIC_API_KEY="your-api-key"
yavs summarize results.json
```

### Advanced Usage

```bash
# Auto-detect project type and scan appropriately
yavs scan --auto

# Export to CSV for spreadsheet analysis
yavs scan --all --csv findings.csv

# Export to TSV (Tab-Separated Values)
yavs scan --all --tsv findings.tsv

# Scan multiple directories
yavs scan /path/dir1 /path/dir2 /path/dir3 --all

# Scan Docker images
yavs scan --images nginx:latest python:3.11 --sbom

# Scan images from file
yavs scan --images-file images.txt --sbom

# Scan both filesystem AND Docker images
yavs scan --all --images nginx:latest

# Ignore specific paths (regex patterns)
yavs scan --all --ignore "test/" --ignore ".*_test\\.py$"

# Use structured output format (organized by category)
yavs scan --all --structured -o ./results

# Suppress finding with expiration date (tech debt tracking)
yavs ignore add CVE-2023-1234 --reason "Fix planned for Q2" --expires 2025-06-30 --owner john

# List suppressions with details
yavs ignore list --details
```

### Example Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   YAVS v0.3.0                            ┃
┃   Yet Another Vulnerability Scanner      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Scanning: /Users/dev/my-project

✓ Trivy: 12 finding(s)
✓ Semgrep: 8 finding(s)
✓ Checkov: 5 finding(s)

┌──────────────────────────────────────────┐
│ Scan Results Summary                     │
├──────────────────────────────────────────┤
│ Total Findings           25              │
│                                          │
│   CRITICAL              3                │
│   HIGH                  7                │
│   MEDIUM                10               │
│   LOW                   5                │
│                                          │
│   Dependencies          12               │
│   SAST                  8                │
│   Compliance            5                │
└──────────────────────────────────────────┘

Writing outputs...
✓ JSON: yavs-results.json
✓ SARIF: yavs-results.sarif
✓ SARIF validation: Valid SARIF file (v2.1.0)

Scan completed!
Found 25 total finding(s)
```

---

## 📖 Documentation

### Command Reference

#### `yavs tools install` - Install Scanner Dependencies

```bash
# Automated setup - installs Trivy automatically
yavs tools install

# Use package manager (brew on macOS, apt on Linux)
yavs tools install --use-brew

# Force reinstall even if already installed
yavs tools install --force

# Skip Trivy installation
yavs tools install --no-trivy
```

The setup command:
- ✅ Automatically downloads and installs Trivy
- ✅ Verifies all scanner installations (Trivy, Semgrep, Checkov, Bandit, BinSkim)
- ✅ Shows installation instructions for missing scanners
- ✅ Works on macOS, Linux, and Windows

#### Tool Version Management

YAVS ships with tested scanner versions and provides flexible version control for reproducible builds and safe upgrades.

**Tested Versions (Nov 2025):**
- Trivy: 0.67.2
- Semgrep: 1.142.1
- Bandit: 1.8.6
- Checkov: 3.2.492

```bash
# Check installed tool versions and compatibility
yavs tools status              # List all installed tools
yavs tools check               # Validate version compatibility

# Install specific tool or version
yavs tools install --tool trivy                     # Install/reinstall specific tool
yavs tools install --tool trivy --version 0.67.2    # Install exact version
yavs tools install --tool semgrep --version 1.142.1 # Install specific Semgrep version

# Upgrade to tested versions (safe)
yavs tools upgrade              # Upgrade all tools (tested versions)
yavs tools upgrade --tool trivy # Upgrade specific tool

# Upgrade to absolute latest (may be untested)
yavs tools upgrade --latest              # Upgrade all to latest
yavs tools upgrade --tool semgrep --latest  # Upgrade specific tool to latest

# Lock versions for reproducibility
yavs tools pin                              # Create .yavs-tools.lock (YAML)
yavs tools pin --format requirements        # Create requirements-scanners.txt
yavs tools pin -o my-tools.lock             # Custom output path
```

**Version Control Mechanisms:**

1. **Lock Files**: Pin exact versions for reproducible builds
   - `.yavs-tools.lock` (YAML format, includes all tools + Trivy)
   - `requirements-scanners.txt` (pip format, Python tools only)

2. **Configuration**: Set preferred versions in `.yavs-config.yaml`
   ```yaml
   tool_versions:
     trivy: "0.67.2"
     semgrep: "1.142.1"
   ```

3. **Environment Variables**: Override at runtime
   ```bash
   export TRIVY_VERSION=0.67.2
   export SEMGREP_VERSION=1.142.1
   ```

**Best Practices:**

- 🎯 **Use tested versions**: Default `yavs tools install` installs tested versions
- 🔒 **Lock versions in CI/CD**: Commit `.yavs-tools.lock` for reproducibility
- ⚠️ **Test before upgrading**: Use `--latest` flag cautiously in production
- ✅ **Validate compatibility**: Run `yavs tools check` after upgrades
- 📌 **Pin for consistency**: Lock versions across team with `yavs tools pin`

#### `yavs scan` - Run Security Scan

```bash
# Basic scanning
yavs scan --all                                  # Scan current directory
yavs scan /path/to/code --all                    # Scan specific directory

# Multi-directory scanning
yavs scan /path/dir1 /path/dir2 /path/dir3 --all # Scan multiple directories
yavs scan src lib tests --all                    # Scan multiple subdirectories

# Docker image scanning
yavs scan --images nginx:latest --sbom           # Scan single image
yavs scan --images nginx:latest python:3.11 --sbom  # Scan multiple images
yavs scan --images-file images.txt --sbom        # Scan images from file

# Combined scanning (filesystem + images)
yavs scan --all --images nginx:latest            # Scan directory AND image
yavs scan src --all --images myapp:latest        # Scan specific dir + image

# Filtering with ignore patterns
yavs scan --all --ignore "test/" --ignore "node_modules/"  # Ignore paths
yavs scan --all --ignore ".*\\.min\\.js$"        # Ignore minified files

# Run specific scanner types
yavs scan --sast              # SAST only (Semgrep, Bandit, BinSkim)
yavs scan --sbom              # Dependencies + SBOM (Trivy)
yavs scan --compliance        # IaC compliance (Checkov)
yavs scan --sast --sbom       # Combine multiple

# Output options
yavs scan --all --structured  # Structured output (organized by category)
yavs scan --all -o ./results  # Custom output directory
yavs scan --all \
  --json custom-results.json \
  --sarif custom-results.sarif \
  --sbom-output custom-sbom.json \
  --config my-config.yaml \
  --no-ai                     # Disable AI features
```

#### `yavs summarize` - AI Analysis

```bash
# Generate AI-powered summary (separate file: yavs-ai-summary.json)
yavs summarize results.json

# Enrich scan results file with AI summary
yavs summarize results.json --enrich

# Save to custom output directory
yavs summarize results.json -o artifacts/summaries

# Use specific Claude model
yavs summarize results.json --model claude-sonnet-4-5-20250929

# Skip triage analysis
yavs summarize results.json --no-triage
```

#### `yavs report` - HTML Report Generation

```bash
# Generate beautiful HTML security report
yavs report yavs-results.json

# Custom output path
yavs report yavs-results.json -o security-report.html

# Include separate AI summary file
yavs report yavs-results.json --summary yavs-ai-summary.json

# Works with all formats (structured, flat, enriched)
yavs report enriched-results.json -o report.html
```

#### `yavs version` - Show Version

```bash
yavs version
```

### Multi-Directory and Image Scanning

YAVS supports scanning multiple filesystem directories and Docker images in a single run:

#### Multiple Directories

```bash
# Scan multiple directories (CLI)
yavs scan /path/dir1 /path/dir2 /path/dir3 --all

# Or configure in config.yaml
# scan:
#   directories:
#     - "src"
#     - "lib"
#     - "tests"
```

**Behavior:**
- Each directory is scanned independently
- Results are aggregated into a single output
- All findings are tagged with `source: "filesystem:/path/to/dir"`
- **SBOM is generated from the first directory only** (with a note displayed)

#### Docker Image Scanning

```bash
# Scan single image
yavs scan --images nginx:latest --sbom

# Scan multiple images
yavs scan --images nginx:latest python:3.11 ubuntu:22.04 --sbom

# Scan from file (one image per line)
yavs scan --images-file images.txt --sbom

# Combine filesystem + images
yavs scan /path/to/code --all --images nginx:latest
```

**Image List File (`images.txt`):**
```txt
# Docker images to scan (one per line)
nginx:latest
python:3.11-slim
ubuntu:22.04

# Comments start with #
# myregistry.azurecr.io/myapp:v1.2.3
```

**Behavior:**
- Images are scanned for CVEs, secrets, and licenses
- All findings tagged with `source: "image:nginx:latest"`
- Works with local and remote registries

### Filtering Results with Ignore Patterns

Use regex patterns to exclude findings from specific paths:

```bash
# Ignore via CLI
yavs scan --all --ignore "test/" --ignore ".*_test\\.py$"

# Or configure in config.yaml
# scan:
#   ignore_paths:
#     - "node_modules/"
#     - "vendor/"
#     - "test/"
#     - ".*\\.min\\.js$"
```

**Important Notes:**
- Patterns are **regex** (not glob patterns)
- Patterns **only filter vulnerability findings**, not SBOM
- SBOM always includes ALL dependencies (even from ignored paths)
- CLI `--ignore` patterns are **added to** config patterns (not replaced)

**Why separate SBOM from ignore?**
- **SBOM** = Complete software inventory (you want ALL dependencies)
- **Ignore** = Reduce noise in reports (you may not care about test file vulnerabilities)

**Examples:**
```bash
# Ignore all test files
yavs scan --all --ignore "test" --ignore ".*_spec\\.js$"

# Ignore minified files
yavs scan --all --ignore ".*\\.min\\.(js|css)$"

# Ignore build artifacts
yavs scan --all --ignore "dist/|build/|target/"
```

### Native Tool Configuration (Advanced)

Power users can provide native configuration files for each scanner tool. Native configs **extend** YAVS baseline settings, giving you the best of both worlds: YAVS simplicity + full tool power.

```yaml
scanners:
  trivy:
    flags: "--timeout 10m"              # Highest priority (overrides everything)
    native_config: "config/trivy.yaml"  # Extends YAVS baseline with tool-specific settings
    # YAVS provides baseline: --security-checks vuln,secret,license --format json
```

**Configuration Precedence**: `flags` > `native_config` > YAVS baseline

📚 **[Native Config Documentation](docs/NATIVE_CONFIGS.md)** | 📁 **[Example Configs](config/examples/)**

**Benefits:**
- ✅ **Layered approach** - YAVS defaults + native customization + CLI override
- ✅ **Incremental** - Only customize what you need
- ✅ **No conflicts** - Clear precedence rules (CLI > native > YAVS)
- ✅ **Full power** - Access 100% of tool features (custom rules, plugins, etc.)
- ✅ **Easy migration** - Keep existing tool configs when adopting YAVS

### Configuration

Create a `config.yaml` file to customize behavior:

```yaml
# Scan configuration
scan:
  # Default directories to scan
  directories:
    - "."

  # Ignore patterns (filter findings, NOT SBOM)
  ignore_paths:
    - "node_modules/"
    - "vendor/"
    - "test/"
    - ".*\\.min\\.js$"

# Scanner configuration
scanners:
  trivy:
    enabled: true
    flags: "--security-checks vuln,secret,config"
    timeout: 300

  semgrep:
    enabled: true
    flags: "--config=auto"
    timeout: 300

  checkov:
    enabled: true
    timeout: 300

# Output configuration
output:
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"

# AI configuration
ai:
  enabled: true
  provider: "anthropic"
  model: "claude-sonnet-4-5-20250929"
  api_key_env: "ANTHROPIC_API_KEY"

  features:
    summarize: true       # Generate executive summary
    triage: true          # Cluster and prioritize findings
    fix_suggestions: true # Provide remediation code

  summary:
    output_file: "yavs-ai-summary.json"  # Default summary output filename
    enrich_scan_results: false            # Add summary to scan results file

# Severity mapping to SARIF levels
severity_mapping:
  CRITICAL: "error"
  HIGH: "error"
  MEDIUM: "warning"
  LOW: "note"
  INFO: "none"

# Logging
logging:
  level: "INFO"
  format: "rich"
```

---

## 🔄 GitHub Actions Workflows

YAVS includes **7 production-ready GitHub Actions workflows** for various CI/CD scenarios:

<table>
  <tr>
    <th>Workflow</th>
    <th>Purpose</th>
    <th>Trigger</th>
    <th>Speed</th>
  </tr>
  <tr>
    <td><b>security-scan.yml</b></td>
    <td>PR/Push scanning with AI summaries</td>
    <td>Every PR/push</td>
    <td>⚡⚡ 3min</td>
  </tr>
  <tr>
    <td><b>scheduled-scan.yml</b></td>
    <td>Daily vulnerability monitoring</td>
    <td>Scheduled (2 AM UTC)</td>
    <td>⚡⚡ 3min</td>
  </tr>
  <tr>
    <td><b>release-scan.yml</b></td>
    <td>Pre-release security gate</td>
    <td>Version tags</td>
    <td>⚡ 5min</td>
  </tr>
  <tr>
    <td><b>dependency-scan.yml</b></td>
    <td>Fast dependency checks</td>
    <td>Dependency changes</td>
    <td>⚡⚡⚡ 1min</td>
  </tr>
  <tr>
    <td><b>comprehensive-scan.yml</b></td>
    <td>Full weekly analysis</td>
    <td>Weekly/on-demand</td>
    <td>⚡ 10min</td>
  </tr>
  <tr>
    <td><b>multi-environment-scan.yml</b></td>
    <td>Environment-specific policies</td>
    <td>Per environment</td>
    <td>⚡⚡ 4min</td>
  </tr>
  <tr>
    <td><b>yavs-self-scan.yml</b></td>
    <td>Dogfooding YAVS</td>
    <td>Every commit</td>
    <td>⚡⚡ 2min</td>
  </tr>
</table>

### Quick Setup

```bash
# Copy workflows to your repository
mkdir -p .github/workflows
cp .github/workflows/security-scan.yml YOUR_REPO/.github/workflows/
cp .github/workflows/scheduled-scan.yml YOUR_REPO/.github/workflows/

# Add secrets (optional, for AI features)
# Settings → Secrets → New repository secret
# Name: ANTHROPIC_API_KEY
# Value: your-api-key
```

📚 **[Full Workflow Documentation](docs/development/WORKFLOWS_OVERVIEW.md)**

---

## 🏗️ Architecture

```
┌──────────────────────────────┐
│         YAVS CLI             │
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
    (Claude-powered Analysis)
             │
     ┌───────┴────────┐
     │                │
 Summarizer      Triage Engine
     │                │
     └───────┬────────┘
             │
        Fix Generator
```

### Project Structure

```
yavs/
├── src/yavs/
│   ├── cli.py                 # Main CLI application
│   ├── scanners/              # Scanner implementations
│   │   ├── base.py            # Abstract base class
│   │   ├── trivy.py           # Trivy integration
│   │   ├── semgrep.py         # Semgrep integration
│   │   └── checkov.py         # Checkov integration
│   ├── reporting/             # Output generation
│   │   ├── aggregator.py      # Result normalization
│   │   └── sarif_converter.py # SARIF 2.1.0 converter
│   ├── ai/                    # AI-powered features
│   │   ├── summarizer.py      # Executive summaries
│   │   ├── fixer.py           # Fix suggestions
│   │   └── triage.py          # Intelligent clustering
│   └── utils/                 # Utilities
│       ├── subprocess_runner.py
│       ├── path_utils.py
│       ├── schema_validator.py
│       └── logging.py
├── tests/                     # Test suite
├── .github/workflows/         # CI/CD workflows
├── config.yaml                # Default configuration
└── pyproject.toml             # Package metadata
```

---

## 🎓 Use Cases

### For Development Teams

- **Pull Request Scanning** — Catch vulnerabilities before merge
- **Dependency Updates** — Know which packages to upgrade
- **Security Debt** — Track and prioritize security issues
- **Compliance** — Ensure IaC follows security best practices

### For Security Teams

- **Daily Monitoring** — Catch newly disclosed CVEs
- **Release Gates** — Block unsafe releases automatically
- **Trend Analysis** — Track security posture over time
- **Incident Response** — Quickly identify affected systems

### For DevOps/Platform Teams

- **CI/CD Integration** — Automated security in pipelines
- **Policy Enforcement** — Different rules for different environments
- **Multi-Project Scanning** — Consistent security across repos
- **Compliance Reporting** — SARIF for audit trails

---

## 📊 Output Formats

### JSON Output

Clean, normalized format for programmatic access:

```json
[
  {
    "tool": "trivy",
    "category": "dependency",
    "severity": "HIGH",
    "file": "requirements.txt",
    "package": "requests",
    "version": "2.19.0",
    "fixed_version": "2.20.0",
    "message": "CVE-2018-18074 - Insufficient CRLF sanitization",
    "rule_id": "CVE-2018-18074",
    "ai_summary": "Upgrade to requests>=2.20.0 to prevent header injection attacks."
  }
]
```

### SARIF 2.1.0 Output

Standards-compliant format for tool integration:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "YAVS",
          "version": "0.3.0",
          "informationUri": "https://github.com/YAVS-OSS/yavs",
          "rules": [...]
        }
      },
      "results": [...]
    }
  ]
}
```

**Upload to GitHub Security:**

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: yavs-results.sarif
```

---

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/YAVS-OSS/yavs
cd yavs

# Install in development mode (includes Semgrep, Checkov, Bandit)
pip install -e ".[dev]"

# Install Trivy
brew install trivy

# Optional: Install BinSkim (for Windows binary analysis)
# dotnet tool install --global Microsoft.CodeAnalysis.BinSkim

# Run tests
pytest

# Run with coverage
pytest --cov=yavs --cov-report=html
```

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_sarif_validation.py

# With verbose output
pytest -v

# Integration tests only
pytest -m integration

# Multi-language integration tests
make test-multi-language

# Comprehensive combination tests (41 test scenarios)
make test-combinations
```

**Comprehensive Testing:** The `test-combinations` command runs 41 different test scenarios covering:
- All scanner combinations (SBOM, SAST, Compliance)
- All output formats (JSON flat, structured, SARIF, SBOM)
- Multi-language support (Python, Node.js, Java, Go, Kubernetes)
- Multi-directory scanning
- Ignore pattern filtering
- Edge cases and special scenarios

Results are saved to `artifacts/` with detailed reports. See [docs/development/COMBINATION_TESTS.md](docs/development/COMBINATION_TESTS.md) for full documentation.

### Code Style

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking (if mypy installed)
mypy src/
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Add** tests for new functionality
5. **Run** tests (`pytest`)
6. **Commit** your changes (`git commit -m 'Add amazing feature'`)
7. **Push** to your branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

### Contribution Ideas

- 🔌 Add new scanner integrations
- 📝 Improve documentation
- 🐛 Fix bugs
- ✨ Add new AI analysis features
- 🎨 Enhance output formatting
- 🧪 Add more test coverage
- 🌍 Translations
- 📊 New output formats

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📦 Releasing & Publishing

YAVS uses automated PyPI publishing via GitHub Actions. Every version bump automatically publishes to PyPI.

### For Maintainers

**Quick Release:**
```bash
# Bump version and auto-publish
./scripts/bump-version.sh 1.0.1
# Follow prompts to commit and push
```

**What Happens:**
1. ✅ Version detected in `src/yavs/__init__.py`
2. ✅ Tests run on Python 3.10, 3.11, 3.12
3. ✅ Package built and validated
4. ✅ Published to TestPyPI (staging)
5. ✅ Published to PyPI (production)
6. ✅ GitHub release created with tag
7. ✅ CHANGELOG.md section auto-extracted

**Setup Required** (one-time):
- Configure PyPI trusted publishing (see [docs/development/PYPI_PUBLISHING_SETUP.md](docs/development/PYPI_PUBLISHING_SETUP.md))
- Create GitHub environments: `pypi` and `testpypi`
- No API tokens needed (uses OIDC)

**Manual Release:**
1. Go to Actions → "Publish to PyPI"
2. Click "Run workflow"
3. Select branch and confirm

See [docs/development/PYPI_PUBLISHING_SETUP.md](docs/development/PYPI_PUBLISHING_SETUP.md) for complete setup guide.

---

## 📋 Roadmap

### v1.0 ✅ (Current - Stable Release)
- ✅ 5 integrated scanners (Trivy, Semgrep, Bandit, Checkov, BinSkim)
- ✅ JSON + SARIF 2.1.0 output with validation
- ✅ Claude AI analysis with parallel processing
- ✅ 7 production-ready GitHub Actions workflows
- ✅ 10 comprehensive CLI commands
- ✅ Baseline/suppression management
- ✅ Statistics and metrics
- ✅ Configuration management
- ✅ Automated PyPI publishing

### v1.1 🚧 (In Progress)
- Policy as Code (YAML-based security policies)
- SBOM vulnerability enrichment (OSV.dev, EPSS scores)
- Pre-commit hook integration
- Enhanced HTML reporting with trends

### v2.0 🎯 (Planned)
- Interactive triage mode (TUI)
- Plugin SDK for custom scanners
- Multi-repo dashboard
- Historical trend analysis
- Jira/GitHub issue integration
- Webhook/Slack notifications
- Enterprise configuration profiles

---

## 🙏 Acknowledgments

YAVS is built on the shoulders of giants:

- **[Trivy](https://github.com/aquasecurity/trivy)** by Aqua Security — Comprehensive vulnerability scanner
- **[Semgrep](https://github.com/semgrep/semgrep)** by Semgrep Inc. — Lightweight static analysis
- **[Checkov](https://github.com/bridgecrewio/checkov)** by Bridgecrew — IaC security scanner
- **[Anthropic Claude](https://www.anthropic.com/)** — AI-powered analysis and insights
- **[OASIS SARIF](https://www.oasis-open.org/committees/sarif/)** — Standard format specification

Special thanks to all contributors and the open source security community!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 💬 Community & Support

- **Issues:** [GitHub Issues](https://github.com/YAVS-OSS/yavs/issues)
- **Discussions:** [GitHub Discussions](https://github.com/YAVS-OSS/yavs/discussions)
- **Documentation:** [Wiki](https://github.com/YAVS-OSS/yavs/wiki)

---

## ⭐ Star History

If you find YAVS useful, please consider giving it a star! It helps others discover the project.

---

## 📸 Screenshots

<details>
<summary>Click to see more screenshots</summary>

### CLI Output
![CLI Scan Output](docs/yavs.png)

### GitHub Security Integration
Upload SARIF files directly to GitHub's Security tab for centralized vulnerability tracking.

### AI-Powered Summary
Get plain-English explanations and actionable remediation steps powered by Claude.

</details>

---

<div align="center">

  **Built with ❤️ by the YAVS community**

  [⬆ Back to Top](#yavs)

</div>