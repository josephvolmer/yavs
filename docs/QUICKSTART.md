# YAVS Quick Start Guide

> **Note**: This guide is for **YAVS contributors and developers**. If you installed YAVS via `pip install yavs`, see the main [README.md](../README.md) for end-user documentation.

Get YAVS development environment running in under 5 minutes!

---

## 1. Development Setup

```bash
# Clone the repository
git clone https://github.com/josephvolmer/yavs.git
cd yavs

# Install YAVS in development mode and all scanner dependencies
make setup

# Check everything is ready
make check-env
```

---

## 2. Set Up API Keys (Optional - for AI features)

Create a `.env` file:

```bash
cat > .env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-your-key
OPENAI_API_KEY=sk-your-key
EOF

# Verify
make check-env
```

---

## 3. Run Your First Scan

**Basic scan (no AI):**
```bash
make scan
```

**With AI features:**
```bash
make scan-ai
```

**Generate AI summary:**
```bash
make summarize
```

---

## 4. Available Commands

```bash
make help        # Show all commands
make setup       # Install dependencies
make check-env   # Check API keys
make scan        # Basic scan
make scan-ai     # Scan with AI
make summarize   # AI summary
make test        # Run tests
make clean       # Clean build files
make clean-all   # Clean everything
```

---

## 5. Manual Usage

```bash
# Scan your own project
cd /path/to/your/project
yavs scan --all

# With specific scanners
yavs scan --sast --sbom --compliance

# AI summary
yavs summarize yavs-results.json --provider openai

# Check version
yavs version
```

---

## 6. Troubleshooting

**"Trivy not found"**
```bash
make setup
```

**"No API keys"**
```bash
# Create .env file
echo "ANTHROPIC_API_KEY=your-key" > .env
make check-env
```

**"Command not found: make"**
- macOS: `xcode-select --install`
- Ubuntu: `sudo apt-get install build-essential`

Or just use the CLI directly:
```bash
pip install -e .
yavs tools install
yavs scan --all
```

---

## 7. Example Workflow

```bash
# 1. Setup (first time only)
make setup

# 2. Add API keys
cat > .env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
EOF

# 3. Run scan with AI
make scan-ai

# 4. Get AI summary
make summarize
```

---

## 8. Tool Version Management

YAVS ships with tested scanner versions and supports flexible version control:

```bash
# Check installed versions and compatibility
yavs tools status
yavs tools check

# Upgrade to tested versions (safe)
yavs tools upgrade

# Upgrade specific tool
yavs tools upgrade --tool trivy

# Install specific version
yavs tools install --tool semgrep --version 1.95.0

# Upgrade to absolute latest (may be untested)
yavs tools upgrade --latest

# Lock versions for reproducibility
yavs tools pin                    # Creates .yavs-tools.lock
yavs tools pin --format requirements  # Creates requirements-scanners.txt
```

**Tested Versions (Nov 2025):**
- Trivy: 0.67.2
- Semgrep: 1.142.1
- Bandit: 1.8.6
- Checkov: 3.2.492

---

## Next Steps

- Scan your own projects: `cd ~/my-project && yavs scan --all`
- Try different AI providers: `yavs summarize results.json --provider openai`
- Integrate with CI/CD: See `.github/workflows/` for examples
- Read full docs: `README.md`, `AI_PROVIDER_GUIDE.md`
- Manage tool versions: `yavs tools --help`

---

**That's it! You're ready to scan.** 🚀
