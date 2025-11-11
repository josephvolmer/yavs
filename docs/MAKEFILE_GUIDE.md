# YAVS Makefile & Automation Guide

Complete guide to using the YAVS Makefile for easy development and testing.

---

## 🚀 Two Ways to Run YAVS

### 1. Makefile (Recommended for Development)

```bash
make quickstart         # Install + setup + scan
make scan-ai            # Scan with AI
make summarize          # AI summary
make help               # See all commands
```

### 2. Direct CLI (For End Users)

```bash
yavs scan --all
yavs summarize yavs-results.json
yavs stats yavs-results.json
```

### Optional: Development Helper Script

A convenience wrapper is available in `scripts/run-yavs.sh`:
```bash
./scripts/run-yavs.sh setup     # First time setup
./scripts/run-yavs.sh scan      # Quick scan
./scripts/run-yavs.sh demo      # Full demo
```

**Note:** This script just calls Makefile targets. Using `make` directly is recommended.

---

## 📋 Makefile Targets Reference

### Setup & Installation

| Target | Description | First Time? |
|--------|-------------|-------------|
| `make install` | Install YAVS in dev mode | ✅ Yes |
| `make setup` | Install Trivy scanner | ✅ Yes |
| `make dev-install` | Install with dev tools | If developing |
| `make quickstart` | All of the above + scan | ✅ **Start here!** |

**Example:**
```bash
# First time setup
make quickstart
```

---

### Environment Management

| Target | Description | Output |
|--------|-------------|--------|
| `make check-env` | Check API keys | Shows which keys are set |
| `make load-env` | Load .env file | Exports variables |

**Example:**
```bash
# Check if API keys are configured
make check-env

# Output:
# ✓ .env file found
# ✓ ANTHROPIC_API_KEY is set
# ✓ OPENAI_API_KEY is set
```

---

### Scanning

| Target | Description | AI Features | Time |
|--------|-------------|-------------|------|
| `make scan` | Basic scan | ❌ No | ~10s |
| `make scan-ai` | Full scan with AI | ✅ Yes | ~30s |
| `make scan-demo` | Same as scan-ai | ✅ Yes | ~30s |
| `make summarize` | Generate AI summary | ✅ Yes | ~15s |

**Examples:**

```bash
# Quick scan without AI
make scan

# Full scan with AI features
make scan-ai

# Generate AI summary from previous scan
make summarize

# Full demo (scan + summarize)
make demo
```

**Scan outputs:**
- `tests/fixtures/sample_project/yavs-results.json`
- `tests/fixtures/sample_project/yavs-results.sarif`

---

### Testing

| Target | Description | Coverage |
|--------|-------------|----------|
| `make test` | Full test suite | ✅ Yes |
| `make test-fast` | Quick tests | ❌ No |
| `make test-providers` | Test AI providers | N/A |

**Examples:**

```bash
# Run full test suite with coverage
make test

# Quick tests (no coverage)
make test-fast

# Test AI provider system
make test-providers
```

---

### Code Quality

| Target | Description | Modifies Files? |
|--------|-------------|-----------------|
| `make format` | Format code (Black) | ✅ Yes |
| `make format-check` | Check formatting | ❌ No |
| `make lint` | Lint code (Ruff) | ❌ No |

**Examples:**

```bash
# Format all code
make format

# Check if code is formatted (CI)
make format-check

# Lint code
make lint
```

---

### Cleanup

| Target | Description | What Gets Deleted |
|--------|-------------|-------------------|
| `make clean` | Clean build artifacts | `*.pyc`, `__pycache__`, `dist/` |
| `make clean-results` | Clean scan results | `yavs-results.*` |
| `make clean-all` | Clean everything | All of the above |

**Examples:**

```bash
# Clean build artifacts
make clean

# Clean old scan results
make clean-results

# Nuclear option - clean everything
make clean-all
```

---

### Documentation & Utilities

| Target | Description |
|--------|-------------|
| `make docs` | List documentation files |
| `make view-results` | View latest scan summary |
| `make version` | Show YAVS version |
| `make help` | Show all targets |

**Examples:**

```bash
# View scan results summary
make view-results

# Output:
# CRITICAL: 8
# HIGH: 25
# MEDIUM: 58
# LOW: 6

# Show version
make version

# Show all available targets
make help
```

---

### Development

| Target | Description | Use Case |
|--------|-------------|----------|
| `make watch` | Auto-run tests on change | Active development |
| `make repl` | Python REPL with YAVS | Quick testing |
| `make shell` | IPython shell | Interactive exploration |
| `make build` | Build packages | Release preparation |

**Examples:**

```bash
# Watch for changes and re-run tests
make watch

# Start Python REPL with YAVS loaded
make repl
```

---

## 🎯 Common Workflows

### First Time Setup

```bash
# Clone repo
git clone https://github.com/YAVS-OSS/yavs.git
cd yavs

# One command setup
make quickstart

# Output:
# ✓ YAVS installed
# ✓ Trivy installed
# ✓ Scan complete
# ✓ Results saved
```

---

### Daily Development

```bash
# Pull latest changes
git pull

# Install any new dependencies
make install

# Run tests
make test

# Format code
make format

# Scan test fixtures
make scan
```

---

### Testing AI Features

```bash
# Check environment
make check-env

# If API keys not set:
cat > .env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
EOF

# Test with Anthropic (default)
make scan-ai

# Test with OpenAI (explicit)
export $(grep -v '^#' .env | xargs)
yavs scan --all --provider openai

# Generate summary
make summarize
```

---

### Release Process

```bash
# Clean everything
make clean-all

# Run full test suite
make test

# Format and lint
make format
make lint

# Build packages
make build

# Output in dist/
ls dist/
# yavs-1.0.0-py3-none-any.whl
# yavs-1.0.0.tar.gz
```

---

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: make install

      - name: Run tests
        run: make test

      - name: Check formatting
        run: make format-check

      - name: Lint
        run: make lint

      - name: Run scan
        run: make scan
```

---

## 🔧 Customizing the Makefile

### Adding Your Own Targets

Edit `Makefile` and add:

```makefile
##@ Custom

my-scan: install setup ## Scan my project
	@echo "Scanning my project..."
	@cd ~/my-project && yavs scan --all

my-workflow: my-scan summarize ## Custom workflow
	@echo "Custom workflow complete!"
```

Then run:
```bash
make my-scan
make my-workflow
```

---

### Environment Variables

The Makefile respects these environment variables:

```bash
# Set custom Python
PYTHON=python3.11 make install

# Set custom pip
PIP=pip3 make install

# Verbose output
VERBOSE=1 make scan
```

---

## 💡 Tips & Tricks

### 1. Tab Completion

```bash
# Enable bash completion
complete -W "$(make -qp | awk -F':' '/^[a-zA-Z0-9][^$#\/\t=]*:([^=]|$)/ {split($1,A,/ /);for(i in A)print A[i]}')" make
```

### 2. Parallel Execution

```bash
# Run tests in parallel
make -j4 test

# Multiple targets
make clean install test
```

### 3. Dry Run

```bash
# See what would be executed
make -n scan

# Output: Shows commands without running them
```

### 4. Keep Going on Error

```bash
# Continue even if one target fails
make -k test lint format
```

### 5. Silent Mode

```bash
# Suppress command output
make -s scan
```

---

## 🐛 Troubleshooting

### "make: command not found"

**macOS:**
```bash
xcode-select --install
```

**Linux:**
```bash
sudo apt-get install build-essential  # Ubuntu/Debian
sudo dnf install make                  # Fedora/RHEL
```

### "No rule to make target"

```bash
# Make sure you're in the project root
cd /path/to/yavs

# Check Makefile exists
ls -la Makefile

# Try help
make help
```

### Targets Not Working

```bash
# Clean and retry
make clean-all
make quickstart
```

### Permission Issues

```bash
# Make scripts executable
chmod +x scripts/run-yavs.sh
chmod +x scripts/bump-version.sh
chmod +x tests/fixtures/sample_project/test_multi_provider.sh
```

---

## 📚 Additional Resources

### Helper Scripts

Development scripts are in the `scripts/` directory:

```bash
./scripts/run-yavs.sh setup     # Development setup
./scripts/bump-version.sh 1.0.1 # Release new version
```

See `scripts/README.md` for full documentation.

### Documentation Files

- `QUICKSTART.md` - Step-by-step getting started
- `AI_PROVIDER_GUIDE.md` - AI provider setup
- `MULTI_PROVIDER_SUMMARY.md` - Implementation details
- `README.md` - Main documentation

### Online Help

```bash
make help              # Makefile targets
yavs --help           # CLI help
yavs scan --help      # Scan command help
```

---

## 🎓 Learning Path

**Beginner:**
1. `make quickstart` - See it work
2. `make check-env` - Understand environment
3. `make scan` - Basic scanning
4. `make view-results` - See what was found

**Intermediate:**
5. `make scan-ai` - Add AI features
6. `make summarize` - AI analysis
7. `make test` - Run tests
8. `make format` - Code quality

**Advanced:**
9. Customize Makefile for your workflows
10. Integrate into CI/CD
11. Build custom targets
12. Contribute back!

---

## ✅ Quick Reference Card

```
╔═══════════════════════════════════════════════════╗
║           YAVS Makefile Quick Reference           ║
╠═══════════════════════════════════════════════════╣
║ First Time:    make quickstart                    ║
║ Quick Scan:    make scan                          ║
║ Full Scan:     make scan-ai                       ║
║ AI Summary:    make summarize                     ║
║ Full Demo:     make demo                          ║
║ Clean:         make clean-all                     ║
║ Check Env:     make check-env                     ║
║ Run Tests:     make test                          ║
║ All Commands:  make help                          ║
╚═══════════════════════════════════════════════════╝
```

---

**Happy scanning!** 🔒
