# YAVS Testing Guide

This document provides a comprehensive guide to testing YAVS, including all available test commands, output locations, and cleanup procedures.

## Quick Start

```bash
# Run all tests (unit tests + combination tests)
make test-all

# Run just unit tests
make test

# Run comprehensive combination tests (41 scenarios)
make test-combinations

# Clean everything
make clean-all
```

## Test Output Locations

**All test outputs are saved to the `artifacts/` directory.**

This ensures:
- ✅ Consistent output location across all test commands
- ✅ Easy cleanup with `make clean-artifacts`
- ✅ No scattered test files in fixture directories
- ✅ Clear separation between source code and test outputs

## Available Test Commands

### Unit Tests (pytest)

```bash
# Run all pytest tests
make test

# Run with coverage report
make test-coverage

# Run integration tests only
make test-integration

# Run multi-language tests
make test-multi-language
```

**Outputs:**
- `.coverage` - Coverage data
- `htmlcov/` - HTML coverage report

### Combination Tests

```bash
# Run comprehensive combination tests (41 scenarios)
make test-combinations

# Or directly
./tests/test_all_combinations.sh
```

**Outputs:** `artifacts/` with 41+ test result directories

**Test Coverage:**
- All scanner combinations (SBOM, SAST, Compliance)
- All output formats (JSON flat, structured, SARIF, SBOM)
- Multi-language support (Python, Node.js, Java, Go, Kubernetes)
- Multi-directory scanning
- Ignore pattern filtering
- Edge cases

**Documentation:** See `tests/COMBINATION_TESTS.md` for detailed test matrix.

### All Tests

```bash
# Run everything (pytest + combination tests)
make test-all
```

## Scanning Commands

All scanning commands output to `artifacts/` subdirectories:

```bash
# Quick scan (Python fixture)
make scan
# Output: artifacts/quick-scan/

# Scan with AI features
make scan-ai
# Output: artifacts/ai-scan/

# Structured output format
make scan-structured
# Output: artifacts/structured-scan/

# Docker image scanning
make scan-images
# Output: artifacts/image-scan/

# Scan all fixtures
make scan-all-fixtures
# Output: artifacts/fixtures/{python,nodejs,java,go,kubernetes}/

# Multi-directory scanning
make scan-multi-dir
# Output: artifacts/multi-dir/
```

## Artifacts Directory Structure

After running tests, the `artifacts/` directory contains:

```
artifacts/
├── test-summary.txt              # Overall test summary
├── findings-summary.txt          # Findings count per test
│
├── quick-scan/                   # From: make scan
│   ├── yavs-results.json
│   ├── yavs-results.sarif
│   └── sbom.json
│
├── ai-scan/                      # From: make scan-ai
│   └── ...
│
├── structured-scan/              # From: make scan-structured
│   └── ...
│
├── fixtures/                     # From: make scan-all-fixtures
│   ├── python/
│   ├── nodejs/
│   ├── java/
│   ├── go/
│   └── kubernetes/
│
├── multi-dir/                    # From: make scan-multi-dir
│   └── ...
│
├── sample_project/               # From: make test-combinations
│   ├── all-scanners/
│   ├── sast-only/
│   ├── sbom-scan/
│   ├── structured/
│   └── ... (19 test scenarios)
│
├── nodejs_project/
│   └── ... (4 test scenarios)
│
├── java_project/
│   └── ... (5 test scenarios)
│
├── go_project/
│   └── ... (3 test scenarios)
│
├── kubernetes/
│   └── ... (3 test scenarios)
│
└── multi_dir/
    └── ... (7 test scenarios)
```

## Cleanup Commands

```bash
# Clean build artifacts only (dist/, __pycache__, etc.)
make clean

# Clean test artifacts only (artifacts/ directory)
make clean-artifacts

# Clean scattered test results (old yavs-results.* in fixtures)
make clean-test-results

# Clean everything (build + artifacts + scattered results)
make clean-all
```

### What Each Clean Command Does

| Command | Removes |
|---------|---------|
| `clean` | `build/`, `dist/`, `*.egg-info`, `__pycache__/`, `.pytest_cache`, `.coverage`, `htmlcov/` |
| `clean-artifacts` | `artifacts/` directory |
| `clean-test-results` | `tests/fixtures/**/yavs-results.*`, `tests/fixtures/**/sbom.json`, `tests/multi-dir-results/` |
| `clean-all` | All of the above |

## Test Fixture Projects

YAVS includes 6 test fixture projects covering multiple languages:

| Fixture | Language | Purpose | Key Vulnerabilities |
|---------|----------|---------|---------------------|
| `sample_project/` | Python | Main test project | Django CVEs, SQL injection, secrets |
| `nodejs_project/` | JavaScript/Node.js | npm ecosystem | Vulnerable Express, lodash, XSS |
| `java_project/` | Java/Maven | JVM ecosystem | Jackson CVEs, Spring CVEs, Log4j |
| `go_project/` | Go | Go modules | JWT vulnerabilities, YAML issues |
| `kubernetes/` | YAML/K8s | IaC compliance | Privileged containers, secrets |
| `docker_images/` | Dockerfile | Container scanning | Buildable vulnerable images |

## Running Specific Test Scenarios

### Test a Specific Scanner

```bash
# SBOM only (Trivy dependencies)
yavs scan tests/fixtures/sample_project --sbom --no-ai -o artifacts/test-sbom

# SAST only (Semgrep + Bandit)
yavs scan tests/fixtures/sample_project --sast --no-ai -o artifacts/test-sast

# Compliance only (Checkov)
yavs scan tests/fixtures/sample_project --compliance --no-ai -o artifacts/test-compliance

# All scanners
yavs scan tests/fixtures/sample_project --all --no-ai -o artifacts/test-all
```

### Test a Specific Language

```bash
# Java project
yavs scan tests/fixtures/java_project --all --no-ai -o artifacts/test-java

# Go project
yavs scan tests/fixtures/go_project --all --no-ai -o artifacts/test-go

# Node.js project
yavs scan tests/fixtures/nodejs_project --all --no-ai -o artifacts/test-nodejs

# Kubernetes manifests
yavs scan tests/fixtures/kubernetes --compliance --no-ai -o artifacts/test-k8s
```

### Test Multi-Directory Scanning

```bash
# Two directories
yavs scan tests/fixtures/sample_project tests/fixtures/java_project \
  --all --no-ai -o artifacts/test-multi

# Three directories with structured output
yavs scan tests/fixtures/sample_project tests/fixtures/java_project tests/fixtures/go_project \
  --all --structured --no-ai -o artifacts/test-multi-structured
```

### Test Ignore Patterns

```bash
# Ignore test directories
yavs scan tests/fixtures/sample_project \
  --all --no-ai --ignore 'test/' -o artifacts/test-ignore

# Multiple ignore patterns
yavs scan tests/fixtures/sample_project \
  --all --no-ai --ignore 'test/' --ignore '__pycache__/' --ignore '.*\.pyc$' \
  -o artifacts/test-multi-ignore
```

### Test Output Formats

```bash
# Structured JSON output
yavs scan tests/fixtures/sample_project \
  --all --structured --no-ai -o artifacts/test-structured

# Flat JSON (default)
yavs scan tests/fixtures/sample_project \
  --all --no-ai -o artifacts/test-flat

# With SBOM generation
yavs scan tests/fixtures/sample_project \
  --all --no-ai -o artifacts/test-with-sbom
```

## Continuous Integration

### GitHub Actions

```yaml
name: Test YAVS

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install YAVS
        run: |
          pip install -e .

      - name: Setup scanners
        run: make setup

      - name: Run all tests
        run: make test-all

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results
          path: artifacts/
```

## Interpreting Test Results

### Combination Test Summary

After running `make test-combinations`, check:

1. **Terminal Output:**
   - Total tests run
   - Pass/fail counts
   - Failed tests with error messages

2. **`artifacts/test-summary.txt`:**
   - Test categories
   - Pass/fail breakdown
   - Scanner and format coverage

3. **`artifacts/findings-summary.txt`:**
   - Findings count per test
   - Comparison across scenarios

### Individual Test Results

Each test directory contains:

```
test-name/
├── yavs-results.json    # Main findings (flat or structured)
├── yavs-results.sarif   # SARIF 2.1.0 format
└── sbom.json            # CycloneDX SBOM (when --sbom used)
```

**Example Finding (JSON):**
```json
{
  "tool": "trivy",
  "category": "dependency",
  "severity": "HIGH",
  "file": "requirements.txt",
  "package": "django",
  "version": "1.11.0",
  "fixed_version": "1.11.23",
  "rule_id": "CVE-2019-14234",
  "message": "Django: SQL injection possibility...",
  "source": "filesystem:/path/to/project",
  "source_type": "filesystem"
}
```

## Expected Test Results

### Sample Project (Python)

```
SBOM only:        ~31 findings (dependencies)
SAST only:        ~13 findings (code issues)
Compliance only:  ~53 findings (Checkov)
All scanners:     ~97 findings (aggregated)
```

### Java Project

```
SBOM only:        ~91 findings (CVEs in Jackson, Spring, Log4j)
SAST only:        ~5 findings (code patterns)
All scanners:     ~96 findings
```

### Go Project

```
SBOM only:        ~4 findings (JWT, YAML CVEs)
SAST only:        ~12 findings (code patterns)
All scanners:     ~16 findings
```

### Kubernetes

```
Compliance only:  ~14 findings (security misconfigurations)
All scanners:     ~17 findings
```

## Troubleshooting

### Tests Failing

**Issue:** All tests fail with "No such option: --trivy"
**Solution:** YAVS uses `--sbom`, `--sast`, `--compliance`, not individual scanner flags.

**Issue:** "Trivy not found"
**Solution:** Run `make setup` to install scanners.

**Issue:** "No findings for Node.js project"
**Reason:** Dependencies not installed. Run `npm install` in `tests/fixtures/nodejs_project/`.

**Issue:** "Checkov failed: 'list' object has no attribute 'get'"
**Reason:** Known Checkov bug with certain YAML structures. Trivy config scanning works as fallback.

### Cleanup Issues

**Issue:** `make clean-all` doesn't remove all files
**Solution:** Check for files in ignored directories (`.venv/`, `.git/`, etc.)

**Issue:** Artifacts directory too large
**Solution:** Run `make clean-artifacts` to remove test outputs. They can be regenerated.

## Best Practices

1. **Always clean before running full tests:**
   ```bash
   make clean-all && make test-all
   ```

2. **Run specific tests during development:**
   ```bash
   # Instead of full test suite, test specific functionality
   make scan
   # Or
   pytest tests/test_sarif_validation.py -v
   ```

3. **Review artifacts after failures:**
   ```bash
   # Check what was generated
   tree artifacts/
   # Read specific results
   cat artifacts/quick-scan/yavs-results.json | jq
   ```

4. **Use structured output for analysis:**
   ```bash
   make scan-structured
   cat artifacts/structured-scan/yavs-results.json | jq '.compliance.violations | length'
   ```

5. **Commit with clean workspace:**
   ```bash
   make clean-all
   git status  # Should not show artifacts/
   ```

## Performance

**Expected test execution times:**

| Command | Time | Tests | Notes |
|---------|------|-------|-------|
| `make test` | ~30s | Unit tests | pytest suite |
| `make test-combinations` | ~15-20min | 41 scenarios | Full coverage |
| `make test-all` | ~20min | All tests | Unit + combination |
| `make scan` | ~30s | 1 fixture | Quick validation |
| `make scan-all-fixtures` | ~3min | 5 fixtures | All languages |

## Summary

- ✅ **All outputs go to `artifacts/`** - consistent and organized
- ✅ **Easy cleanup** - `make clean-all` removes everything
- ✅ **41 test combinations** - comprehensive coverage
- ✅ **6 language fixtures** - Python, Node.js, Java, Go, K8s, Docker
- ✅ **Multiple test levels** - unit tests, integration, combination
- ✅ **Clear documentation** - this guide + `tests/COMBINATION_TESTS.md`

For more details on specific test scenarios, see `tests/COMBINATION_TESTS.md`.
