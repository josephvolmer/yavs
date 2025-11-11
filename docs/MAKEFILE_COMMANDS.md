# YAVS Makefile Commands Reference

Quick reference for all `make` commands available in YAVS.

## 📦 Installation & Setup

```bash
make install        # Install YAVS in development mode
make install-dev    # Install with dev dependencies (pytest, black, ruff)
make setup          # Install scanner dependencies (Trivy)
```

## 🔧 Tool Management

### Verify Tools
```bash
make verify-tools   # Check installed scanner versions
```
Shows versions of Trivy, Semgrep, Bandit, Checkov, BinSkim

### Update Tools
```bash
make update-tools   # Update all scanners to latest versions
```
Updates: Semgrep, Bandit, Checkov (Trivy via system package manager)

### Pin Tool Versions
```bash
make pin-tools      # Create requirements-scanners.txt with current versions
```
Creates `requirements-scanners.txt` with pinned versions for reproducible environments

**Example output:**
```
# Scanner tool versions - Generated on Sat Nov 9 22:15:00 PST 2024
# Install with: pip install -r requirements-scanners.txt

semgrep==1.45.0
bandit==1.7.5
checkov==3.0.42

# Note: Trivy should be installed via system package manager
```

## 🔐 Environment Check

```bash
make check-env      # Verify API keys are configured
```

## 🔍 Scanning

### Basic Scans
```bash
make scan           # Quick scan (no AI)
make scan-ai        # Scan with AI features
make scan-images    # Scan Docker images
```

### Output Formats
```bash
make scan-structured  # Structured JSON output (default)
make scan-flat        # Flat JSON output
```

### Comprehensive Scans
```bash
make scan-all-fixtures  # Scan all test fixtures
make scan-multi-dir     # Test multi-directory scanning
```

## 📊 Reporting

```bash
make summarize       # Generate AI summary (separate file)
make summarize-enrich # Add AI summary to scan results
make report          # Generate HTML security report
```

## 🧪 Testing

### Run Tests
```bash
make test            # Run pytest test suite
make test-coverage   # Run with coverage report
make test-integration # Integration tests only
make test-combinations # 41 combination scenarios
make test-all        # All tests (pytest + combinations)
```

### Docker Tests
```bash
make build-test-images # Build Docker test images
make scan-test-images  # Build and scan test images
```

## 🧹 Cleanup

```bash
make clean           # Clean build artifacts & temp files
make clean-artifacts # Remove scan results
make clean-test-results # Clean scattered test results
make clean-all       # Clean EVERYTHING
```

**What `make clean` removes:**
- Build artifacts: `build/`, `dist/`, `*.egg-info`
- Test artifacts: `.pytest_cache/`, `.coverage`, `htmlcov/`
- Python cache: `__pycache__/`, `*.pyc`, `*.pyo`
- IDE files: `.claude/`, `*.swp`, `*.swo`, `*~`
- OS files: `.DS_Store`

## 💻 Development

### Code Quality
```bash
make lint            # Run ruff linter
make format          # Auto-format with black
make format-check    # Check formatting (no changes)
```

### Build & Release
```bash
make build           # Build wheel and source distribution
make build-check     # Build and verify package contents
make upload-test     # Upload to Test PyPI
make upload          # Upload to production PyPI (requires confirmation)
```

## 🚀 Common Workflows

### Initial Setup
```bash
make install-dev     # Install with dev dependencies
make setup           # Install scanners
make verify-tools    # Verify everything is installed
```

### Development Workflow
```bash
make clean           # Clean old artifacts
make format          # Format code
make lint            # Check code quality
make test            # Run tests
make build-check     # Verify package builds
```

### Pre-Commit Workflow
```bash
make clean-all       # Clean everything
make test            # Run tests
make format-check    # Verify formatting
```

### Release Workflow
```bash
make clean-all       # Start clean
make test-all        # Run all tests
make pin-tools       # Pin scanner versions
make build           # Build package
make upload-test     # Test on Test PyPI
make upload          # Release to PyPI
```

### Pin Current Environment
```bash
make verify-tools    # Check versions
make pin-tools       # Create requirements-scanners.txt
```
Commit `requirements-scanners.txt` for reproducible CI/CD environments.

## 📝 Help

```bash
make help            # Show all available commands
make                 # Same as 'make help' (default)
```

## 💡 Tips

1. **Always run `make verify-tools` after `make setup`** to confirm scanners are installed
2. **Use `make pin-tools` in CI/CD** to lock scanner versions for consistent results
3. **Run `make clean-all` before commits** to ensure no artifacts are committed
4. **Use `make format` before `make lint`** to auto-fix formatting issues
5. **Test with `make upload-test`** before production release
6. **Run `make test-all`** before creating pull requests

## 🔄 Update Workflow

When scanner tools release new versions:

```bash
make verify-tools    # Check current versions
make update-tools    # Update to latest
make verify-tools    # Verify updates
make pin-tools       # Pin new versions
make test-all        # Ensure everything works
```

## 📚 Related Documentation

- [MAKE_CLEAN_GUIDE.md](MAKE_CLEAN_GUIDE.md) - Detailed cleanup guide
- [MAKEFILE_GUIDE.md](docs/MAKEFILE_GUIDE.md) - Original Makefile documentation
- [DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md) - Repository organization
