# YAVS Summarize Command Behavior

This document clarifies the behavior of the `yavs summarize` command, especially regarding flag interactions.

## Command Overview

```bash
yavs summarize <results_file> [OPTIONS]
```

## Output Modes

### 1. Separate File Mode (Default)

Creates a separate AI summary file alongside your scan results.

```bash
yavs summarize yavs-results.json
```

**Output:**
- `yavs-ai-summary.json` (in current directory)

**With custom directory:**
```bash
yavs summarize yavs-results.json -o artifacts/summaries
```

**Output:**
- `artifacts/summaries/yavs-ai-summary.json`

### 2. Enriched Mode

Adds AI summary directly to the scan results file.

```bash
yavs summarize yavs-results.json --enrich
```

**Output:**
- `yavs-results.json` (modified in place with `ai_summary` field added)

## Flag Interactions

### `--enrich` + `-o/--output-dir`

**Behavior:** `--enrich` takes precedence and `-o` is **ignored**.

```bash
yavs summarize /path/to/results.json --enrich -o /different/path
```

**What happens:**
1. ⚠️  Warning shown: `--output-dir is ignored when using --enrich`
2. Original file is modified in place: `/path/to/results.json`
3. The `-o /different/path` flag has no effect

**Rationale:**
- `--enrich` means "modify the scan results file in place"
- `-o` means "save separate file to this directory"
- These are mutually exclusive intentions

**Recommendation:** Don't use both flags together. If you want enriched output in a different location, copy the results file first:

```bash
cp results.json artifacts/enriched-results.json
yavs summarize artifacts/enriched-results.json --enrich
```

## Examples

### Scenario 1: Keep separate summary

```bash
# Scan produces: artifacts/scan/yavs-results.json
yavs scan . --all -o artifacts/scan

# Summarize to same directory
yavs summarize artifacts/scan/yavs-results.json -o artifacts/scan

# Result:
# - artifacts/scan/yavs-results.json (unchanged)
# - artifacts/scan/yavs-ai-summary.json (new)
```

### Scenario 2: Enrich scan results

```bash
# Scan produces: artifacts/scan/yavs-results.json
yavs scan . --all -o artifacts/scan

# Enrich in place
yavs summarize artifacts/scan/yavs-results.json --enrich

# Result:
# - artifacts/scan/yavs-results.json (now contains ai_summary field)
```

### Scenario 3: Summaries in different directory

```bash
# Scan in one location
yavs scan . --all -o artifacts/scans

# Summaries in another location
yavs summarize artifacts/scans/yavs-results.json -o artifacts/summaries

# Result:
# - artifacts/scans/yavs-results.json (unchanged)
# - artifacts/summaries/yavs-ai-summary.json (new)
```

### Scenario 4: Config-based enrichment

```yaml
# config.yaml
ai:
  summary:
    enrich_scan_results: true
```

```bash
yavs summarize results.json
# Always enriches, even without --enrich flag
```

## Decision Tree

```
yavs summarize results.json [FLAGS]
│
├─ --enrich flag?
│  ├─ YES → Modify results.json in place
│  │         (ignore -o if present, show warning)
│  │
│  └─ NO → Save separate summary file
│           ├─ -o specified? → Use that directory
│           ├─ config.output.directory set? → Use that
│           └─ Neither? → Use current directory
│
└─ Filename: Always "yavs-ai-summary.json" (from config)
```

## Configuration

```yaml
# config.yaml
output:
  directory: "."  # Default for scan output

ai:
  summary:
    output_file: "yavs-ai-summary.json"  # Summary filename
    enrich_scan_results: false            # Enable enrichment by default
```

## Common Pitfalls

### ❌ Wrong: Both flags together

```bash
yavs summarize results.json --enrich -o /some/dir
# Warning shown, -o ignored
```

### ✅ Right: Choose one approach

```bash
# Option A: Separate file
yavs summarize results.json -o /some/dir

# Option B: Enrich in place
yavs summarize results.json --enrich
```

## Migration from Old Behavior

**Old (v0.2.x):**
```bash
yavs summarize results.json -o summary.json  # Specified file path
```

**New (v1.0.0+):**
```bash
yavs summarize results.json -o .  # Specify directory
# Creates: ./yavs-ai-summary.json
```

To get a custom filename, edit `config.yaml`:
```yaml
ai:
  summary:
    output_file: "custom-summary.json"
```
