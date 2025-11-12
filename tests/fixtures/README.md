# YAVS Test Fixtures

This directory contains intentionally vulnerable test projects for validating YAVS scanning capabilities.

## ⚠️ WARNING

**These are INTENTIONALLY VULNERABLE applications for testing purposes only.**

- Do NOT deploy these to production
- Do NOT use as templates for real applications
- Only use in isolated test environments

## Available Fixtures

- **sample_project/** - Python project with vulnerable dependencies and code
- **nodejs_project/** - Node.js/JavaScript project with Express vulnerabilities
- **java_project/** - Java/Maven project with multiple vulnerability types
- **go_project/** - Go project with SQL injection and weak crypto
- **kubernetes/** - Kubernetes manifests with IaC misconfigurations
- **docker_images/** - Docker files with security issues

## Quick Start

```bash
# Run all tests
pytest tests/

# Run integration tests
pytest tests/test_integration.py -v

# Run multi-language tests
pytest tests/test_multi_language.py -v
```

## Documentation

For detailed information about test fixtures, vulnerabilities, and coverage:
- **[docs/development/TEST_GUIDE.md](../../docs/development/TEST_GUIDE.md)** - Complete testing guide
- **[docs/development/COMBINATION_TESTS.md](../../docs/development/COMBINATION_TESTS.md)** - Test matrix and scenarios

## Security Note

These fixtures are excluded from production scans via `.trivyignore`, `.semgrepignore`, and `.banditignore` in the repository root.
