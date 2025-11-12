# YAVS Test Fixtures

This directory contains intentionally vulnerable test projects for validating YAVS scanning capabilities.

## ⚠️ WARNING

**These are INTENTIONALLY VULNERABLE applications for testing purposes only.**

- Do NOT deploy these to production
- Do NOT use as templates for real applications
- Only use in isolated test environments

## Test Projects

### 1. Python Project (`sample_project/`)

**Language**: Python
**Vulnerabilities**:
- SQL Injection (main.py)
- Command Injection (main.py)
- Hardcoded credentials (main.py)
- Insecure random (main.py)
- Path traversal (main.py)
- Eval injection (main.py)
- Vulnerable dependencies (requirements.txt)
  - requests==2.19.0 (CVE-2018-18074)
  - flask==0.12.2 (Multiple CVEs)
  - django==1.11.0 (CVE-2018-14574)
  - pyyaml==3.12 (CVE-2017-18342)

**Scanners Tested**: Trivy, Semgrep, Bandit, Checkov

### 2. Node.js Project (`nodejs_project/`)

**Language**: JavaScript/Node.js
**Vulnerabilities**:
- SQL Injection (server.js)
- Command Injection (server.js)
- Path Traversal (server.js)
- Eval injection (server.js)
- XSS (server.js)
- Hardcoded credentials (server.js)
- Weak cryptography (server.js)
- Vulnerable dependencies (package.json)
  - express==4.16.0 (CVEs)
  - lodash==4.17.4 (Prototype pollution)
  - moment==2.19.3 (CVEs)

**Scanners Tested**: Trivy, Semgrep

### 3. Java Project (`java_project/`)

**Language**: Java
**Vulnerabilities**:
- SQL Injection (VulnerableApp.java)
- Command Injection (VulnerableApp.java)
- Path Traversal (VulnerableApp.java)
- XSS (VulnerableApp.java)
- Insecure deserialization (VulnerableApp.java)
- Weak cryptography (VulnerableApp.java)
- Hardcoded credentials (VulnerableApp.java)
- Vulnerable dependencies (pom.xml)
  - spring-core==4.3.0
  - jackson-databind==2.9.0
  - log4j==1.2.17

**Scanners Tested**: Trivy, Semgrep

### 4. Go Project (`go_project/`)

**Language**: Go
**Vulnerabilities**:
- SQL Injection (main.go)
- Command Injection (main.go)
- Path Traversal (main.go)
- XSS (main.go)
- Hardcoded credentials (main.go)
- Weak cryptography (main.go)
- Insecure HTTP client (main.go)
- Vulnerable dependencies (go.mod)
  - dgrijalva/jwt-go==3.2.0

**Scanners Tested**: Trivy, Semgrep

### 5. Kubernetes Manifests (`kubernetes/`)

**Type**: IaC (Infrastructure as Code)
**Issues**:
- Hardcoded secrets in manifest
- Running as root (runAsUser: 0)
- Privileged containers
- No resource limits
- Using 'latest' image tag
- LoadBalancer exposing services

**Scanners Tested**: Checkov, Trivy

### 6. Docker Images (`docker_images/`)

**Type**: Container Images
**Files**:
- `Dockerfile.vulnerable-app` - Multiple security issues for detection
- `Dockerfile.python-app` - Buildable image with vulnerabilities
- `requirements.txt` - Vulnerable Python dependencies
- `app.py` - Simple Flask app with secrets

**Issues**:
- Outdated base images
- Hardcoded secrets in ENV
- Running as root
- Vulnerable dependencies
- No health checks
- Exposed unnecessary ports

**Scanners Tested**: Trivy (image mode), Checkov

## Building Docker Test Images

To build the test Docker images:

```bash
# Build Python test image
cd tests/fixtures/docker_images
docker build -t yavs-test-python:vulnerable -f Dockerfile.python-app .

# Scan the built image
cd ../../..
yavs scan --images yavs-test-python:vulnerable --sbom
```

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run integration tests only
```bash
pytest tests/test_integration.py -v
```

### Run multi-language tests
```bash
pytest tests/test_multi_language.py -v
```

### Run with coverage
```bash
pytest tests/ --cov=yavs --cov-report=html
```

## Test Coverage

The test suite validates:

1. **Scanner Integration**
   - Trivy (dependencies, secrets, licenses, images)
   - Semgrep (SAST)
   - Bandit (Python SAST)
   - BinSkim (Binary analysis)
   - Checkov (IaC compliance)

2. **Multi-Language Support**
   - Python
   - JavaScript/Node.js
   - Java
   - Go

3. **Output Formats**
   - JSON (flat and structured)
   - SARIF 2.1.0
   - SBOM (CycloneDX)

4. **Features**
   - Severity mapping
   - Ignore patterns
   - Multi-directory scanning
   - Docker image scanning
   - Source tagging (filesystem vs image)
   - Deduplication
   - Aggregation

## Adding New Test Fixtures

When adding new test fixtures:

1. Create a new directory under `tests/fixtures/`
2. Add vulnerable code/config with clear comments
3. Include a variety of vulnerability types
4. Add to `test_multi_language.py`
5. Update this README

### Example Structure

```
tests/fixtures/
├── your_project/
│   ├── README.md           # Document vulnerabilities
│   ├── dependency_file     # Package manager file with vulns
│   └── source_code         # Code with SAST issues
```

## Security Considerations

These fixtures are designed to:
- Trigger multiple scanner types
- Cover various vulnerability categories
- Test edge cases and deduplication
- Validate severity mapping
- Test multi-language workflows

**Remember**: These are educational tools. Never use vulnerable code patterns in production!

## Scan Exclusions

To prevent these intentionally vulnerable test fixtures from triggering security alerts in production scans, they are excluded via ignore files in the repository root:

### `.trivyignore`
Excludes test fixtures from Trivy dependency scanning to prevent alerts on:
- Django 1.11.0 (CVE-2018-14574: SQL injection)
- PyYAML 3.12 (CVE-2017-18342: arbitrary code execution)
- jackson-databind 2.9.0 (29 deserialization RCE vulnerabilities)
- log4j 1.2.17 (deserialization vulnerabilities)

### `.semgrepignore`
Excludes test fixtures from Semgrep SAST scanning to prevent alerts on intentional code vulnerabilities like SQL injection, command injection, XSS, etc.

### `.banditignore`
Excludes test fixtures from Bandit Python security analysis to prevent alerts on intentional insecure code patterns.

### Purpose
These exclusions ensure that:
1. Production security scans focus only on `src/` code
2. CI/CD pipelines pass with clean security posture
3. Test fixtures remain functional for YAVS testing
4. Security teams can distinguish between intentional test code and real vulnerabilities

### Verifying Production Code Security
To scan only production code (excluding test fixtures):
```bash
# The ignore files automatically exclude tests/fixtures/
yavs scan . --all --output-dir scan-output

# Or explicitly scan only src/ directory
yavs scan src/ --all --output-dir scan-output
```
