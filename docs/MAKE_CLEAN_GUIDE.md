# Make Clean Guide

## Updated `make clean` Target

The `make clean` command now performs comprehensive cleanup matching the manual cleanup process.

### What `make clean` Removes:

```bash
make clean
```

**Build Artifacts:**
- `build/` - Python build directory
- `dist/` - Distribution packages (wheels, tarballs)
- `*.egg-info` - Package metadata (root)
- `src/*.egg-info` - Package metadata (src)

**Test Artifacts:**
- `.pytest_cache/` - Pytest cache directory
- `.coverage` - Coverage data file
- `htmlcov/` - HTML coverage reports

**Python Cache:**
- `__pycache__/` - All Python bytecode cache directories
- `*.pyc` - Compiled Python files
- `*.pyo` - Optimized Python files

**IDE & Editor Files:**
- `.claude/` - Claude Code settings
- `*.swp` - Vim swap files
- `*.swo` - Vim swap files
- `*~` - Editor backup files

**OS Files:**
- `.DS_Store` - macOS metadata files

### Additional Cleanup Commands:

**Clean Scan Artifacts:**
```bash
make clean-artifacts
```
Removes: `artifacts/` directory with all scan results

**Clean Test Results:**
```bash
make clean-test-results
```
Removes: Scattered test results in fixture directories

**Clean Everything:**
```bash
make clean-all
```
Runs all cleanup targets: `clean` + `clean-artifacts` + `clean-test-results`

### Usage Examples:

**Development Cleanup:**
```bash
make clean          # Remove build artifacts but keep scan results
```

**Complete Reset:**
```bash
make clean-all      # Remove everything (recommended before git commit)
```

**Just Artifacts:**
```bash
make clean-artifacts  # Keep build files but remove scan results
```

### Verification:

After running `make clean`, these should be gone:
- [ ] No `.DS_Store` files
- [ ] No `.coverage` file
- [ ] No `.pytest_cache/` directory
- [ ] No `build/` directory
- [ ] No `dist/` directory
- [ ] No `.claude/` directory
- [ ] No `__pycache__/` directories
- [ ] No `*.pyc` files

All these items are also in `.gitignore` so they won't be committed even if they exist.

### Rebuild After Cleaning:

```bash
# Rebuild package
python -m build

# Reinstall development version
pip install -e .

# Run tests
pytest tests/
```
