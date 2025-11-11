# Changelog

All notable changes to YAVS (Yet Another Vulnerability Scanner) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-10

### 🎉 First Stable Release

YAVS v1.0.0 is production-ready! This release includes comprehensive security scanning, AI-powered analysis, and production-grade tooling.

### Added

#### New Commands
- **`yavs stats`** - Display scan statistics and metrics
  - Overview mode with severity breakdown
  - Group by severity, scanner, or category
  - JSON output for scripting
  - One-line summary mode

- **`yavs ignore`** - Baseline and suppression management
  - `yavs ignore add` - Suppress false positives
  - `yavs ignore remove` - Un-suppress findings
  - `yavs ignore list` - View all suppressions
  - `yavs ignore clear` - Clear all suppressions
  - `yavs ignore export` - Create baseline from scan results

- **`yavs config`** - Configuration file management
  - `yavs config init` - Create config file (minimal or full)
  - `yavs config validate` - Validate config syntax
  - `yavs config show` - Display current configuration
  - `yavs config path` - Show config search paths
  - `yavs config edit` - Open config in editor

- **`yavs tools`** - Scanner tool management
  - `yavs tools install` - Install scanner dependencies
  - `yavs tools status` - Check installed versions
  - `yavs tools upgrade` - Update all scanners
  - `yavs tools pin` - Generate requirements file

#### Scan Features
- `--baseline` flag to filter findings against suppression baseline
- `--fail-on` to set CI/CD exit code based on severity threshold
- `--severity` to filter findings by severity levels
- `--quiet` mode for minimal output
- `--timeout` for overall scan timeout
- `--continue-on-error` to keep scanning if a tool fails
- Multi-directory scanning support
- Docker image scanning via `--images` and `--images-file`

#### AI Features
- Claude Sonnet 4.5 integration
- AI-powered fix suggestions with parallel processing
- Executive summaries
- Intelligent triage and clustering
- Auto-detection of Anthropic/OpenAI providers

#### Output Formats
- SARIF 2.1.0 compliant output
- Structured JSON format (organized by category)
- Flat JSON format (array of findings)
- Per-tool output files option
- SBOM generation (CycloneDX format)
- HTML security reports

### Security Scanners
- **Trivy** - Dependencies, secrets, licenses, IaC, container scanning
- **Semgrep** - SAST for multiple languages
- **Bandit** - Python-specific SAST
- **Checkov** - IaC compliance scanning
- **BinSkim** - Binary analysis (Windows)

### Documentation
- Comprehensive man pages (`yavs man`)
- Section-based documentation (quickstart, commands, config, examples, ci, ai, scanners)
- CLI help for all commands
- 7 production-ready GitHub Actions workflows
- Makefile with 37 automation commands
- Testing guide with 41 combination test scenarios

### Developer Experience
- Rich terminal UI with colors and tables
- Beautiful ASCII art banner
- Progress indicators for long operations
- Clear error messages with suggestions
- Auto-installation of Trivy scanner
- YAML-based configuration with sensible defaults

### Testing
- 6 multi-language test fixtures
- 41 combination test scenarios
- Unit tests with pytest
- Integration tests
- SARIF validation tests
- Coverage reporting

## [0.3.0] - 2025-11-08

### Added
- Initial implementation of multi-scanner orchestration
- Basic CLI commands (scan, summarize, report)
- SARIF output support
- AI integration framework
- GitHub Actions workflows

## [0.2.0] - 2025-11-07

### Added
- Trivy integration
- Semgrep integration
- Basic aggregation

## [0.1.0] - 2025-11-06

### Added
- Initial project structure
- Basic scanning framework

---

## Release Notes

### v1.0.0 Highlights

**Production-Ready Features:**
- 10 CLI commands covering all security scanning needs
- Complete suppression/baseline management for false positives
- Statistics and metrics for quick insights
- Full CI/CD integration with policy enforcement
- Comprehensive documentation (100+ pages)

**AI Intelligence:**
- Claude-powered analysis with 50 RPM parallel processing
- Context-aware fix suggestions
- Executive summaries for non-technical stakeholders
- Smart triage and clustering

**Standards Compliance:**
- SARIF 2.1.0 validated output
- CycloneDX SBOM generation
- GitHub Security tab integration
- IDE support (VS Code, JetBrains)

**Developer Friendly:**
- Zero-config scanning with sensible defaults
- Beautiful Rich-based terminal UI
- Auto-installation of dependencies
- Clear error messages

### Migration from 0.3.0

No breaking changes. New features are additive:

```bash
# New in v1.0.0 - these commands didn't exist before
yavs stats results.json
yavs ignore add CVE-2023-1234
yavs config init
yavs tools status

# Enhanced in v1.0.0 - new flags
yavs scan --all --baseline .yavs-baseline.yaml
yavs scan --all --fail-on HIGH
```

### Support

- **Documentation**: `yavs man` or https://github.com/YAVS-OSS/yavs
- **Issues**: https://github.com/YAVS-OSS/yavs/issues
- **Discussions**: https://github.com/YAVS-OSS/yavs/discussions

---

[1.0.0]: https://github.com/YAVS-OSS/yavs/releases/tag/v1.0.0
[0.3.0]: https://github.com/YAVS-OSS/yavs/releases/tag/v0.3.0
[0.2.0]: https://github.com/YAVS-OSS/yavs/releases/tag/v0.2.0
[0.1.0]: https://github.com/YAVS-OSS/yavs/releases/tag/v0.1.0
