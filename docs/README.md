# YAVS Documentation

Complete documentation for YAVS (Yet Another Vulnerability Scanner).

---

## 📖 Quick Start

**New to YAVS?** Start here:
- **[QUICK-START.md](QUICK-START.md)** - Get started in 5 minutes

---

## 📚 User Guides

### Core Features

- **[QUICK-START.md](QUICK-START.md)** - Installation, basic usage, common workflows
- **[POLICY.md](POLICY.md)** - Policy-as-Code comprehensive guide (650+ lines)
- **[PRODUCTION_CLI.md](PRODUCTION_CLI.md)** - Production CLI usage and best practices

### Configuration

- **[NATIVE_CONFIGS.md](NATIVE_CONFIGS.md)** - Scanner configuration files (.bandit, .semgrepignore, etc.)
- **[AI_PROVIDER_GUIDE.md](AI_PROVIDER_GUIDE.md)** - AI provider configuration (Anthropic, OpenAI, Azure)

### Output Formats

- **[OUTPUT_SCHEMAS.md](OUTPUT_SCHEMAS.md)** - JSON output schemas and formats
- **[schemas/](schemas/)** - JSON Schema files for validation

---

## 🎯 Documentation by Use Case

### First-Time User

1. Read [QUICK-START.md](QUICK-START.md) - "Installation" and "Basic Usage"
2. Run `yavs scan . --auto`
3. Review generated reports

### Implementing Policy-as-Code

1. Read [POLICY.md](POLICY.md) - Complete guide
2. Review [../examples/policies/](../examples/policies/) - Example policies
3. Start with built-in policies: `src/yavs/policy/builtins/security.yaml`

### CI/CD Integration

1. Read [QUICK-START.md](QUICK-START.md) - "CI/CD Pipeline" section
2. Copy [../examples/comprehensive-scan.sh](../examples/comprehensive-scan.sh)
3. Configure policies for your project

### AI-Powered Analysis

1. Read [AI_PROVIDER_GUIDE.md](AI_PROVIDER_GUIDE.md) - Provider setup
2. Configure API keys
3. Run with `--ai` flag

### Production Deployment

1. Read [PRODUCTION_CLI.md](PRODUCTION_CLI.md) - Production best practices
2. Configure native scanner configs: [NATIVE_CONFIGS.md](NATIVE_CONFIGS.md)
3. Set up baseline management and policies

---

## 📋 File Reference

### User Guides
- `QUICK-START.md` - Quick start guide with examples
- `POLICY.md` - Policy-as-Code comprehensive guide
- `PRODUCTION_CLI.md` - Production CLI features
- `AI_PROVIDER_GUIDE.md` - AI provider configuration
- `NATIVE_CONFIGS.md` - Scanner configuration files
- `OUTPUT_SCHEMAS.md` - Output format documentation

### Schemas
- `schemas/schema-policy.json` - Policy file validation schema
- `schemas/schema-structured.json` - Structured output schema
- `schemas/schema-flat.json` - Flat output schema
- `schemas/schema-summary.json` - AI summary schema

---

## 🔗 Related Documentation

- **Main README**: [../README.md](../README.md) - Project overview
- **Examples**: [../examples/](../examples/) - Sample scripts and policies
- **Tests**: [../tests/README.md](../tests/README.md) - Test suite documentation
- **Contributing**: [../CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines

---

## 💡 Tips

### Quick Reference Commands

```bash
# Basic scan
yavs scan .

# Auto-detect with all scanners
yavs scan . --auto --all

# With policy enforcement
yavs scan . --policy policies/security.yaml --policy-mode enforce

# Export to CSV
yavs scan . --csv findings.csv

# AI-powered analysis
yavs scan . --ai --auto
```

### Getting Help

```bash
# General help
yavs --help

# Command-specific help
yavs scan --help
yavs summarize --help
yavs diff --help
```

---

## 📊 Documentation Coverage

| Feature | Documentation | Examples | Schema |
|---------|--------------|----------|--------|
| Quick Start | ✅ QUICK-START.md | ✅ Examples | - |
| Policy-as-Code | ✅ POLICY.md | ✅ Examples + Built-in | ✅ schema-policy.json |
| AI Integration | ✅ AI_PROVIDER_GUIDE.md | ✅ CLI flags | ✅ schema-summary.json |
| Output Formats | ✅ OUTPUT_SCHEMAS.md | ✅ Examples | ✅ All schemas |
| Scanner Config | ✅ NATIVE_CONFIGS.md | ✅ Examples | - |
| Production | ✅ PRODUCTION_CLI.md | ✅ comprehensive-scan.sh | - |

---

*Last Updated: 2025-11-12*
*Documentation: Customer-Facing Only*
