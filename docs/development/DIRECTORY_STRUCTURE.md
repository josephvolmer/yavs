# YAVS Directory Structure

## Root Level
```
yavs/
├── .env                    # Environment variables (gitignored, use .env.example)
├── .env.example            # Template for environment variables
├── .github/                # GitHub Actions workflows
├── .gitignore              # Git ignore rules
├── CONTRIBUTING.md         # Contribution guidelines
├── LICENSE                 # MIT License
├── MANIFEST.in             # Files to include in pip package
├── Makefile                # Development automation
├── README.md               # Main project documentation
├── RELEASE_CHECKLIST.md    # Pre-release verification checklist
├── pyproject.toml          # Package configuration (PEP 518)
├── docs/                   # Documentation
├── examples/               # Example configurations
├── scripts/                # Helper scripts
│   ├── bump-version.sh     # Version bumping and release
│   └── run-yavs.sh         # Development helper (optional)
├── src/                    # Source code
└── tests/                  # Test suite
```

## Documentation (docs/)
```
docs/
├── README.md                      # Documentation index
├── QUICKSTART.md                  # Quick start guide for developers
├── AI_PROVIDER_GUIDE.md          # AI features guide
├── NATIVE_CONFIGS.md             # Native scanner configs
├── OUTPUT_SCHEMAS.md             # Output format documentation
├── PRODUCTION_CLI.md             # Production usage guide
├── SUMMARIZE_BEHAVIOR.md         # AI summarization docs
├── MAKEFILE_COMMANDS.md          # Quick Makefile reference
├── KNOWN_ISSUES.md               # Known issues and limitations
├── development/                   # Development & maintainer docs
│   ├── DIRECTORY_STRUCTURE.md    # This file - repository structure
│   ├── TESTING.md                # Testing guide
│   ├── MAKEFILE_GUIDE.md         # Complete Makefile tutorial
│   ├── WORKFLOWS_OVERVIEW.md     # CI/CD workflows overview
│   ├── PYPI_PUBLISHING_SETUP.md  # PyPI publishing setup
│   ├── MULTI_PROVIDER_SUMMARY.md # AI provider implementation
│   ├── MULTI_PROVIDER_TEST_RESULTS.md # AI provider test results
│   └── RELEASE_CHECKLIST.md      # Release verification checklist
├── examples/                      # Example outputs
│   ├── example-structured-enriched.json
│   ├── example-structured-with-ai.json
│   └── example-summary.json
├── schemas/                       # JSON schemas
│   ├── schema-flat.json
│   ├── schema-structured.json
│   └── schema-summary.json
└── images/                        # Images and assets
    ├── yavs.png
    ├── yavs-transparent.png
    └── bug.png
```

## Examples (examples/)
```
examples/
├── README.md                      # Examples guide
├── ci-cd/                         # CI/CD pipeline examples
│   ├── github-actions.yml        # GitHub Actions workflow
│   ├── gitlab-ci.yml             # GitLab CI pipeline
│   └── jenkinsfile               # Jenkins pipeline
├── configs/                       # Configuration examples
│   ├── yavs-config-full.yaml     # Complete YAVS config
│   ├── yavs-config-native.yaml   # Using native configs
│   └── trivy.yaml                # Trivy native config
└── docker/                        # Docker examples
    └── images.txt                # List of images to scan
```

## Source Code (src/)
```
src/
└── yavs/
    ├── __init__.py
    ├── cli.py                     # Main CLI entry point
    ├── ai/                        # AI integration
    │   ├── __init__.py
    │   ├── provider.py           # AI provider abstraction
    │   ├── fixer.py              # AI fix suggestions
    │   ├── summarizer.py         # AI summarization
    │   └── triage.py             # AI triage
    ├── scanners/                  # Scanner implementations
    │   ├── __init__.py
    │   ├── base.py               # Base scanner class
    │   ├── trivy.py              # Trivy scanner
    │   ├── semgrep.py            # Semgrep scanner
    │   ├── bandit.py             # Bandit scanner
    │   ├── checkov.py            # Checkov scanner
    │   ├── binskim.py            # BinSkim scanner
    │   └── sbom.py               # SBOM generation
    ├── reporting/                 # Output generation
    │   ├── __init__.py
    │   ├── aggregator.py         # Findings aggregation
    │   ├── sarif_converter.py    # SARIF conversion
    │   ├── html_report.py        # HTML report generation
    │   └── structured_output.py  # Structured JSON output
    ├── templates/                 # HTML templates
    │   └── report.jinja          # HTML report template
    └── utils/                     # Utilities
        ├── __init__.py
        ├── baseline.py           # Baseline management
        ├── logging.py            # Logging configuration
        ├── metadata.py           # Metadata extraction
        ├── path_utils.py         # Path utilities
        ├── preflight.py          # Pre-scan checks
        ├── rule_links.py         # Rule documentation links
        ├── scanner_installer.py  # Scanner installation
        ├── schema_validator.py   # Schema validation
        ├── subprocess_runner.py  # Command execution
        └── timeout.py            # Timeout handling
```

## Tests (tests/)
```
tests/
├── __init__.py
├── TEST_GUIDE.md                  # Testing guide
├── COMBINATION_TESTS.md           # Combination test docs
├── test_all_combinations.sh       # Test script
├── fixtures/                      # Test fixtures
│   ├── README.md
│   ├── sample_project/           # Python test project
│   ├── nodejs_project/           # Node.js test project
│   ├── java_project/             # Java test project
│   ├── go_project/               # Go test project
│   ├── kubernetes/               # K8s manifests
│   └── docker_images/            # Docker test files
├── test_aggregator.py            # Aggregator tests
├── test_baseline.py              # Baseline tests
├── test_cli.py                   # CLI tests
├── test_config.py                # Configuration tests
├── test_html_report.py           # HTML report tests
├── test_integration.py           # Integration tests
├── test_multi_language.py        # Multi-language tests
├── test_sarif_validation.py      # SARIF validation tests
├── test_scanners.py              # Scanner tests
├── test_structured_output.py     # Structured output tests
├── test_summarize.py             # Summarization tests
└── test_utils.py                 # Utility tests
```

## Gitignored Items

The following are automatically ignored by git (see .gitignore):
- **Build artifacts**: `build/`, `dist/`, `*.egg-info/`, `*.whl`, `*.tar.gz`
- **Python cache**: `__pycache__/`, `*.pyc`, `*.pyo`
- **Test artifacts**: `.pytest_cache/`, `.coverage`, `htmlcov/`
- **Virtual environments**: `venv/`, `env/`, `.venv`
- **IDE files**: `.vscode/`, `.idea/`, `.claude/`, `*.swp`
- **OS files**: `.DS_Store`, `Thumbs.db`
- **YAVS outputs**: `artifacts/`, `yavs-results.*`, `sbom.json`
- **Environment**: `.env`, `.env.local`
- **Temporary files**: `*.tmp`, `*.bak`, `.~*`

## What Gets Packaged

When building for pip (`python -m build`), the following are included:
- All source code in `src/yavs/`
- Templates in `src/yavs/templates/`
- Documentation in `docs/` (all `.md` and `.json` files)
- Images in `docs/images/` (all `.png` files)
- Examples in `examples/` (all `.yaml`, `.yml`, `.txt`, `.md` files)
- Root files: `LICENSE`, `README.md`, `CONTRIBUTING.md`

## Directory Organization Principles

1. **Source Separation**: All source code is in `src/yavs/` for proper packaging
2. **Documentation Organization**: User docs in `docs/`, dev docs in `docs/development/`
3. **Example Isolation**: All examples are in `examples/` with clear subdirectories
4. **Test Isolation**: All tests in `tests/` with fixtures organized separately
5. **Clean Root**: Minimal files at root level, mostly configuration and documentation
