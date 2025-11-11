# YAVS Scripts Directory

Helper scripts for YAVS development and maintenance.

---

## Scripts for Maintainers

### bump-version.sh

**Purpose:** Automate version bumping and release preparation

**Usage:**
```bash
./scripts/bump-version.sh 1.0.1
./scripts/bump-version.sh 1.1.0 "Add new feature"
```

**What it does:**
1. Updates version in `src/yavs/__init__.py`
2. Updates `CHANGELOG.md` with new version section
3. Shows git diff preview
4. Prompts to commit and push changes
5. Triggers automated PyPI publishing via GitHub Actions

**When to use:**
- Releasing a new version to PyPI
- Creating a new GitHub release
- Following semantic versioning (MAJOR.MINOR.PATCH)

**Features:**
- Semver validation
- Color-coded output
- Safety prompts before pushing
- Cross-platform (macOS and Linux)

---

## Scripts for Contributors/Developers

### run-yavs.sh

**Purpose:** Quick development wrapper for Makefile commands

**Usage:**
```bash
./scripts/run-yavs.sh setup      # First time setup
./scripts/run-yavs.sh scan       # Quick scan on test fixtures
./scripts/run-yavs.sh scan-ai    # Scan with AI features
./scripts/run-yavs.sh demo       # Full demo
./scripts/run-yavs.sh check      # Check environment
./scripts/run-yavs.sh clean      # Clean artifacts
./scripts/run-yavs.sh help       # Show help
```

**What it does:**
- Provides colored output with banners
- Wraps common Makefile targets
- Runs scans on test fixtures (for development)

**Note:** This script is for DEVELOPMENT only. End users should use the `yavs` CLI command directly after installation.

**Alternative:** Use `make` directly (recommended)
```bash
make quickstart    # Instead of ./scripts/run-yavs.sh setup
make scan          # Instead of ./scripts/run-yavs.sh scan
make help          # See all targets
```

---

## Test Scripts

Test-related scripts are located in `tests/` directory:

- `tests/test_all_combinations.sh` - Run combination tests
- `tests/fixtures/docker_images/build-test-images.sh` - Build test Docker images
- `tests/fixtures/sample_project/test_multi_provider.sh` - Test AI provider switching

---

## For End Users

**IMPORTANT:** If you installed YAVS via `pip install yavs`, you don't need these scripts!

Use the `yavs` CLI command directly:

```bash
# For end users
yavs scan --all
yavs summarize results.json
yavs stats results.json

# See all commands
yavs --help
```

---

## Script Guidelines

When adding new scripts:

1. **Location:**
   - Maintainer scripts → `scripts/`
   - Test scripts → `tests/`
   - CI/CD scripts → `.github/workflows/`

2. **Naming:**
   - Use kebab-case: `bump-version.sh`, not `BumpVersion.sh`
   - Descriptive names: `bump-version.sh`, not `bv.sh`

3. **Shebang:**
   - Always start with `#!/bin/bash`
   - Use `set -e` for error handling

4. **Documentation:**
   - Add script description in header comments
   - Update this README when adding new scripts
   - Include usage examples

5. **Permissions:**
   - Make executable: `chmod +x script-name.sh`
   - Committed as executable via git

---

## Quick Reference

| Script | Purpose | Audience |
|--------|---------|----------|
| `bump-version.sh` | Release new version | Maintainers |
| `run-yavs.sh` | Development wrapper | Contributors (optional) |

**Recommendation:** Use `make` for development tasks and `yavs` CLI for end-user operations.
