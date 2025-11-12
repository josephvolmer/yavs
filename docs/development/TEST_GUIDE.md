# YAVS Test Suite Guide

## Overview

YAVS has a comprehensive test suite covering multiple languages, scanners, and workflows. This guide explains the test structure and how to run tests.

## Test Statistics

- **Total Test Files**: 6
- **Lines of Test Code**: ~1,600+
- **Test Fixtures**: 6 projects (Python, Node.js, Java, Go, Kubernetes, Docker)
- **Languages Covered**: Python, JavaScript, Java, Go, YAML
- **Scanners Tested**: Trivy, Semgrep, Bandit, BinSkim, Checkov

## Test Structure

```
tests/
├── __init__.py
├── fixtures/                        # Test projects with vulnerabilities
│   ├── README.md                    # Fixtures documentation
│   ├── sample_project/              # Python (original)
│   │   ├── main.py                  # Vulnerable Python code
│   │   ├── requirements.txt         # Vulnerable dependencies
│   │   └── terraform.tf             # IaC config
│   ├── nodejs_project/              # Node.js/JavaScript
│   │   ├── package.json             # Vulnerable npm packages
│   │   └── server.js                # Vulnerable Express app
│   ├── java_project/                # Java/Maven
│   │   ├── pom.xml                  # Vulnerable Maven deps
│   │   └── src/main/java/...        # Vulnerable Java code
│   ├── go_project/                  # Go
│   │   ├── go.mod                   # Vulnerable Go modules
│   │   └── main.go                  # Vulnerable Go code
│   ├── kubernetes/                  # Kubernetes/IaC
│   │   └── deployment.yaml          # Insecure K8s manifest
│   └── docker_images/               # Docker images
│       ├── Dockerfile.vulnerable-app
│       ├── Dockerfile.python-app
│       ├── requirements.txt
│       ├── app.py
│       └── build-test-images.sh     # Helper script
├── test_aggregator.py               # Aggregation tests (137 lines)
├── test_integration.py              # Integration tests (186 lines)
├── test_multi_language.py           # Multi-language tests (NEW, 370+ lines)
├── test_sarif_validation.py         # SARIF validation (163 lines)
├── test_scanners.py                 # Scanner tests (253 lines)
└── test_structured_output.py        # Structured output (224 lines)
```

## Running Tests

### Quick Test Commands

```bash
# Run all tests
make test

# Run with coverage report
make test-coverage

# Run integration tests only
make test-integration

# Run multi-language tests
make test-multi-language

# Build Docker test images
make build-test-images

# Build and scan Docker test images
make scan-test-images
```

### Detailed pytest Commands

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_multi_language.py -v

# Run integration tests only
pytest tests/ -v -m integration

# Run with coverage
pytest tests/ --cov=yavs --cov-report=html --cov-report=term

# Run specific test class
pytest tests/test_multi_language.py::TestMultiLanguageScanning -v

# Run specific test
pytest tests/test_multi_language.py::TestMultiLanguageScanning::test_python_project_scanning -v
```

## Test Coverage Areas

### 1. Scanner Integration (`test_scanners.py`)

Tests for individual scanner implementations:

- ✅ Trivy scanner (dependency, secret, license scanning)
- ✅ Semgrep scanner (SAST)
- ✅ Bandit scanner (Python SAST)
- ✅ BinSkim scanner (binary analysis)
- ✅ Checkov scanner (IaC compliance)
- ✅ Severity mapping across scanners

### 2. Aggregation & Normalization (`test_aggregator.py`)

Tests for result aggregation:

- ✅ Adding findings from multiple scanners
- ✅ Deduplication of identical findings
- ✅ Sorting by severity
- ✅ Statistics generation
- ✅ JSON read/write operations

### 3. SARIF Output (`test_sarif_validation.py`)

Tests for SARIF 2.1.0 compliance:

- ✅ SARIF structure validation
- ✅ Schema compliance
- ✅ Tool metadata
- ✅ Result mapping
- ✅ Severity level conversion
- ✅ File path handling

### 4. Structured Output (`test_structured_output.py`)

Tests for structured output format:

- ✅ Category consolidation (compliance, sast, sbom)
- ✅ Tool grouping
- ✅ SBOM metadata inclusion
- ✅ Summary statistics
- ✅ Violation formatting

### 5. Integration Workflows (`test_integration.py`)

End-to-end workflow tests:

- ✅ Complete scan workflow
- ✅ JSON to SARIF conversion
- ✅ Aggregation workflow
- ✅ File write operations

### 6. Multi-Language Support (`test_multi_language.py`) **NEW**

Tests for multiple programming languages:

- ✅ Python project scanning (Bandit, Trivy, Semgrep)
- ✅ Node.js project structure and dependencies
- ✅ Java project structure (Maven, pom.xml)
- ✅ Go project structure (go.mod)
- ✅ Kubernetes manifest scanning
- ✅ Docker image scanning and tagging
- ✅ Ignore patterns filtering
- ✅ Multi-directory aggregation
- ✅ Source tagging (filesystem vs image)
- ✅ Severity mapping consistency
- ✅ Structured output with multi-language findings

## Test Fixtures

### Python Project (`sample_project/`)

**Vulnerabilities Included:**
- SQL Injection
- Command Injection
- Hardcoded credentials
- Insecure random
- Path traversal
- Eval injection
- Vulnerable dependencies (requests, flask, django, pyyaml)

**Tests**: Bandit, Trivy, Semgrep, Checkov

### Node.js Project (`nodejs_project/`) **NEW**

**Vulnerabilities Included:**
- SQL Injection
- Command Injection
- Path Traversal
- XSS
- Eval injection
- Hardcoded secrets
- Vulnerable dependencies (express, lodash, moment, jquery)

**Tests**: Trivy, Semgrep

### Java Project (`java_project/`) **NEW**

**Vulnerabilities Included:**
- SQL Injection
- Command Injection
- Path Traversal
- XSS
- Insecure deserialization
- Weak cryptography
- Vulnerable dependencies (Spring, Jackson, Log4j)

**Tests**: Trivy, Semgrep

### Go Project (`go_project/`) **NEW**

**Vulnerabilities Included:**
- SQL Injection
- Command Injection
- Path Traversal
- XSS
- Weak cryptography
- Insecure HTTP client
- Vulnerable dependencies (jwt-go)

**Tests**: Trivy, Semgrep

### Kubernetes Manifests (`kubernetes/`) **NEW**

**Issues Included:**
- Hardcoded secrets
- Running as root
- Privileged containers
- No resource limits
- Using 'latest' tag
- Exposed services

**Tests**: Checkov, Trivy

### Docker Images (`docker_images/`) **NEW**

**Issues Included:**
- Outdated base images
- Hardcoded secrets in ENV
- Running as root
- Vulnerable dependencies
- No health checks
- Unnecessary exposed ports

**Tests**: Trivy (image mode), Checkov

**Buildable Image**: `Dockerfile.python-app` can be built and scanned:
```bash
cd tests/fixtures/docker_images
docker build -t yavs-test-python:vulnerable -f Dockerfile.python-app .
yavs scan --images yavs-test-python:vulnerable --sbom
```

## Docker Image Testing

### Building Test Images

```bash
# Build all test images
make build-test-images

# Or manually
cd tests/fixtures/docker_images
./build-test-images.sh
```

### Scanning Test Images

```bash
# Build and scan test images
make scan-test-images

# Or manually scan
yavs scan --images yavs-test-python:vulnerable --sbom

# Scan multiple images
yavs scan --images yavs-test-python:vulnerable nginx:latest --sbom

# With structured output
yavs scan --images yavs-test-python:vulnerable --sbom --structured -o results/
```

## CI/CD Integration

The test suite is designed to run in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Tests
  run: |
    pip install -e ".[dev]"
    pytest tests/ --cov=yavs --cov-report=xml

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Test Dependencies

Required for running tests:

```bash
# Core testing
pytest>=7.0.0
pytest-cov>=4.0.0

# Scanners (optional for some tests)
trivy       # Dependency/container scanning
semgrep     # SAST
bandit      # Python SAST
checkov     # IaC scanning

# Docker (optional for image tests)
docker      # For building test images
```

## Writing New Tests

### Adding Test Fixtures

1. Create directory under `tests/fixtures/`
2. Add vulnerable code with clear comments
3. Include various vulnerability types
4. Document in `fixtures/README.md`
5. Add tests to `test_multi_language.py`

### Test Naming Conventions

- Test files: `test_*.py`
- Test classes: `Test*`
- Test methods: `test_*`
- Fixtures: Use lowercase with underscores

### Example Test Structure

```python
import pytest
from pathlib import Path

class TestNewScanner:
    """Test new scanner integration."""

    @pytest.fixture
    def sample_project(self):
        """Path to test fixture."""
        return Path(__file__).parent / "fixtures" / "sample_project"

    def test_scanner_finds_vulnerabilities(self, sample_project):
        """Test that scanner detects expected vulnerabilities."""
        # Arrange
        scanner = NewScanner(sample_project)

        # Act
        findings = scanner.run()

        # Assert
        assert len(findings) > 0
        assert any(f["severity"] == "HIGH" for f in findings)
```

## Troubleshooting

### Tests Skipping

Some tests may skip if dependencies aren't installed:

```
SKIPPED [1] tests/test_multi_language.py:42: Bandit not available
```

**Solution**: Install the missing scanner:
```bash
pip install bandit
# or
brew install trivy
```

### Docker Tests Failing

If Docker image tests fail:

1. Ensure Docker is installed and running
2. Build images first: `make build-test-images`
3. Check Docker daemon is accessible

### Coverage Issues

If coverage is low:

1. Install all optional dependencies
2. Build Docker test images
3. Run: `make test-coverage`

## Best Practices

1. **Run tests before committing**
   ```bash
   make test
   ```

2. **Check coverage**
   ```bash
   make test-coverage
   ```

3. **Test specific changes**
   ```bash
   pytest tests/test_your_change.py -v
   ```

4. **Use fixtures for test data**
   - Don't create inline vulnerable code
   - Use existing fixtures when possible

5. **Mark slow tests**
   ```python
   @pytest.mark.slow
   def test_expensive_operation():
       pass
   ```

## Summary

The YAVS test suite provides:

- ✅ **1,600+ lines** of test code
- ✅ **6 test fixture projects** covering 4 languages
- ✅ **5 scanner integrations** tested
- ✅ **Docker image testing** capabilities
- ✅ **Multi-language workflows** validated
- ✅ **SARIF 2.1.0 compliance** verified
- ✅ **Structured output** tested
- ✅ **Ignore patterns** validated
- ✅ **Source tagging** verified

All tests are designed to run quickly in CI/CD environments while providing comprehensive coverage of YAVS functionality.
