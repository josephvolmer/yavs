# YAVS Test Suite

Comprehensive test suite for YAVS (Yet Another Vulnerability Scanner).

---

## Directory Structure

```
tests/
├── unit/                          # Unit tests (fast, isolated)
│   ├── core/                      # Core functionality tests
│   │   └── test_aggregator.py     # Finding aggregation logic
│   ├── policy/                    # Policy-as-Code tests
│   │   └── test_policy_engine.py  # Policy engine (26 tests)
│   ├── reporting/                 # Report generation tests
│   │   ├── test_html_report.py    # HTML report generation
│   │   ├── test_sarif_validation.py # SARIF format validation
│   │   └── test_structured_output.py # JSON/structured output
│   ├── scanners/                  # Scanner tests
│   │   └── test_scanners.py       # Scanner implementations
│   └── utils/                     # Utility tests
│       ├── test_baseline.py       # Baseline management
│       ├── test_config.py         # Configuration handling
│       └── test_utils.py          # General utilities
│
├── integration/                   # Integration tests (slower, end-to-end)
│   ├── test_cli.py                # CLI command integration
│   ├── test_multi_language.py     # Multi-language detection
│   ├── test_policy_integration.py # Policy-as-Code integration (9 tests)
│   ├── test_summarize.py          # AI summarization integration
│   └── workflows/                 # End-to-end workflows
│       └── test_integration.py    # Complete scan workflows
│
├── fixtures/                      # Test fixtures and data
│   ├── docker_images/             # Docker test images
│   ├── go_project/                # Go test project
│   ├── java_project/              # Java test project
│   ├── kubernetes/                # Kubernetes manifests
│   ├── nodejs_project/            # Node.js test project
│   └── sample_project/            # Multi-language sample
│
└── test_all_combinations.sh       # Test all feature combinations
```

---

## Test Categories

### Unit Tests (tests/unit/)

**Purpose**: Fast, isolated tests of individual components

**Characteristics**:
- No external dependencies (scanners, APIs)
- Mock external calls
- Fast execution (< 1 second per test)
- Focus on logic and edge cases

**Coverage**:
- ✅ Core: Aggregator, finding management
- ✅ Policy: Policy engine (26 tests, 89% coverage)
- ✅ Reporting: HTML, SARIF, JSON generation
- ✅ Scanners: Scanner implementations
- ✅ Utils: Baseline, config, utilities

**Run unit tests**:
```bash
pytest tests/unit/ -v
```

---

### Integration Tests (tests/integration/)

**Purpose**: Test component interactions and end-to-end workflows

**Characteristics**:
- May use real scanners (if installed)
- Test CLI commands
- Test full pipelines
- Slower execution (seconds to minutes)

**Coverage**:
- ✅ CLI: All command-line flags and commands
- ✅ Multi-language: Auto-detection, multiple scanners
- ✅ Policy: Policy evaluation in scan pipeline (9 tests)
- ✅ Summarize: AI-powered summarization
- ✅ Workflows: Complete scan workflows

**Run integration tests**:
```bash
pytest tests/integration/ -v
```

---

## Running Tests

### All Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=src/yavs --cov-report=html

# With verbose output
pytest -v
```

### Unit Tests Only (Fast)

```bash
pytest tests/unit/ -v
```

### Integration Tests Only

```bash
pytest tests/integration/ -v
```

### Specific Test Categories

```bash
# Policy tests only
pytest tests/unit/policy/ tests/integration/test_policy_integration.py -v

# Reporting tests
pytest tests/unit/reporting/ -v

# CLI tests
pytest tests/integration/test_cli.py -v
```

### With Markers

```bash
# Integration tests only (using markers)
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

---

## Test Fixtures

### Sample Projects (tests/fixtures/)

**Purpose**: Realistic test projects for integration testing

**Available fixtures**:
- `sample_project/`: Multi-language project (Python, Terraform)
- `nodejs_project/`: Node.js with npm dependencies
- `java_project/`: Java with Maven
- `go_project/`: Go with modules
- `kubernetes/`: Kubernetes manifests
- `docker_images/`: Docker test containers

**Usage in tests**:
```python
@pytest.fixture
def sample_project():
    return Path(__file__).parent.parent / "fixtures" / "sample_project"

def test_scan(sample_project):
    result = scan_directory(sample_project)
    assert len(result) > 0
```

---

## Test Coverage

### Current Coverage (as of 2025-11-12)

| Component | Unit Tests | Integration Tests | Coverage |
|-----------|-----------|-------------------|----------|
| Policy Engine | 26 | 9 | 89% |
| Aggregator | ✅ | ✅ | High |
| Baseline | ✅ | ✅ | High |
| CLI | ✅ | ✅ | High |
| Scanners | ✅ | ✅ | High |
| Reporting | ✅ | ✅ | High |
| Utils | ✅ | ✅ | High |

**Total Tests**: 60+ tests across all components

---

## Writing New Tests

### Unit Test Template

```python
"""Unit tests for [component]."""

import pytest
from yavs.[module] import [Component]


class Test[Component]:
    """Test [component] functionality."""

    def test_basic_functionality(self):
        """Test basic [component] behavior."""
        component = Component()
        result = component.do_something()
        assert result == expected

    def test_edge_case(self):
        """Test edge case handling."""
        component = Component()
        with pytest.raises(ValueError):
            component.do_something(invalid_input)
```

### Integration Test Template

```python
"""Integration tests for [feature]."""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from yavs.cli import app


@pytest.fixture
def runner():
    return CliRunner()


@pytest.mark.integration
def test_end_to_end_workflow(runner, tmp_path):
    """Test complete workflow."""
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
```

---

## Test Conventions

### Naming

- **Unit tests**: `test_[component].py` or `test_[module]_[feature].py`
- **Integration tests**: `test_[feature]_integration.py` or `test_[workflow].py`
- **Test functions**: `test_[what_is_being_tested]`
- **Test classes**: `Test[Component]` or `Test[Feature]`

### Organization

- Group related tests in classes
- Use descriptive docstrings
- Keep tests focused (one assertion per test when possible)
- Use fixtures for common setup

### Markers

Use pytest markers for test categorization:

```python
@pytest.mark.integration  # Integration test
@pytest.mark.slow         # Slow test (> 5 seconds)
@pytest.mark.requires_scanner  # Requires external scanner
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Unit Tests
  run: pytest tests/unit/ -v

- name: Run Integration Tests
  run: pytest tests/integration/ -v

- name: Generate Coverage
  run: pytest --cov=src/yavs --cov-report=xml
```

### Test All Combinations

```bash
# Run test matrix (all scanner combinations)
./tests/test_all_combinations.sh
```

---

## Debugging Tests

### Run single test

```bash
pytest tests/unit/policy/test_policy_engine.py::TestPolicyConditions::test_equals_operator_case_sensitive -v
```

### Run with print statements

```bash
pytest tests/unit/policy/ -v -s
```

### Run with debugger

```bash
pytest tests/unit/policy/ --pdb
```

### Show test durations

```bash
pytest tests/ --durations=10
```

---

## Test Dependencies

### Required

```bash
pip install pytest pytest-cov
```

### Optional (for integration tests)

```bash
# Scanners
pip install bandit semgrep safety trivy checkov

# Docker (for container tests)
docker pull python:3.9-slim
```

---

## Common Issues

### Import Errors

If you get import errors, ensure PYTHONPATH includes src:

```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
pytest
```

Or use pytest's built-in path handling:

```bash
pytest --import-mode=importlib
```

### Scanner Not Found

Integration tests may skip if scanners aren't installed:

```python
@pytest.mark.skipif(not shutil.which("bandit"), reason="Bandit not installed")
def test_bandit_scan():
    ...
```

### Slow Tests

Use markers to skip slow tests during development:

```bash
pytest -m "not slow"
```

---

## Test Metrics

### Performance Targets

- Unit tests: < 1 second each
- Integration tests: < 30 seconds each
- Full suite: < 5 minutes

### Coverage Targets

- Overall: > 80%
- Critical components (policy, CLI): > 85%
- New features: 100% coverage required

---

## Contributing Tests

When adding new features:

1. ✅ Write unit tests first (TDD)
2. ✅ Achieve > 85% coverage for new code
3. ✅ Add integration tests for user-facing features
4. ✅ Update this README if adding new test categories
5. ✅ Ensure all tests pass before submitting PR

---

## Related Documentation

- **Policy Tests**: See `docs/POLICY-VERIFICATION-REPORT.md`
- **CLI Usage**: See `docs/QUICK-START.md`
- **Development**: See `CONTRIBUTING.md`

---

*Last Updated: 2025-11-12*
*Total Tests: 60+*
*Test Organization: Complete ✅*
