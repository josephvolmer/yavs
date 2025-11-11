# Known Issues

## Windows Timeout Support (v1.0.0)

**Status**: Partial Implementation
**Priority**: Low
**Affects**: Windows users using `--timeout` flag

### Description
The `--timeout` feature currently uses a hybrid approach:
- Unix/Linux/Mac: Uses `signal.SIGALRM` (fully supported)
- Windows: Cross-platform `timeout.py` utility created but integration pending

### Workaround
Windows users can:
1. Omit the `--timeout` flag (scans run without timeout)
2. Use CI/CD platform's native timeout (GitHub Actions `timeout-minutes`, etc.)

### Fix Plan
Complete integration of `src/yavs/utils/timeout.py` context manager into scan command. This requires:
- Proper indentation of scanning logic within timeout context
- Exception handling for `TimeoutError`
- Testing on Windows platform

### Files
- `src/yavs/utils/timeout.py` - Cross-platform timeout utility (✅ Created)
- `src/yavs/cli.py` - Integration pending (⏳ In Progress)

---

## Checkov Parsing Edge Cases

**Status**: Mitigated
**Priority**: Low

### Description
Checkov sometimes returns non-standard JSON structures that could cause parsing errors.

### Fix
Added defensive programming in `src/yavs/scanners/checkov.py`:
- Type checking for finding objects
- Safe access to nested fields
- Default values for missing data

### Status
✅ Fixed in v1.0.0
