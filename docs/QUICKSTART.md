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
yavs scan --sast --bom --compliance

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

## Next Steps

- Scan your own projects: `cd ~/my-project && yavs scan --all`
- Try different AI providers: `yavs summarize results.json --provider openai`
- Integrate with CI/CD: See `.github/workflows/` for examples
- Read full docs: `README.md`, `AI_PROVIDER_GUIDE.md`

---

**That's it! You're ready to scan.** 🚀
