#!/bin/bash
##
## YAVS Comprehensive Scan Example
## Demonstrates all 8 new features in a single command
##

set -e  # Exit on error

echo "======================================"
echo "  YAVS Comprehensive Security Scan"
echo "  Demonstrating All 8 New Features"
echo "======================================"
echo ""

# Configuration
TARGET_DIR="${1:-.}"  # Scan current directory by default
OUTPUT_DIR="comprehensive-scan-results"
BASELINE_FILE=".yavs-baseline.yaml"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "🔍 Scanning: $TARGET_DIR"
echo "📁 Output: $OUTPUT_DIR"
echo ""

# Feature demonstration
echo "✨ Features Enabled:"
echo "  1️⃣  Baseline Expiration    (--baseline)"
echo "  2️⃣  CSV/TSV Export        (--csv, --tsv)"
echo "  3️⃣  Auto-Detect Mode      (--auto)"
echo "  4️⃣  Fast-Fail Mode        (--fail-fast)"
echo "  5️⃣  Git Blame Tracking    (--blame)"
echo "  6️⃣  Terrascan Scanner     (auto-detected)"
echo "  7️⃣  TemplateAnalyzer      (auto-detected)"
echo "  8️⃣  Policy-as-Code        (--policy)"
echo ""

# Run comprehensive scan
echo "🚀 Starting scan..."
echo ""

yavs scan "$TARGET_DIR" \
  --auto \
  --all \
  --blame \
  --baseline "$BASELINE_FILE" \
  --policy src/yavs/policy/builtins/security.yaml \
  --policy examples/policies/team-exceptions.yaml \
  --policy-mode enforce \
  --fail-on HIGH \
  --fail-fast \
  --csv "$OUTPUT_DIR/findings.csv" \
  --tsv "$OUTPUT_DIR/findings.tsv" \
  --output-dir "$OUTPUT_DIR" \
  --continue-on-error

EXIT_CODE=$?

echo ""
echo "======================================"
echo "  Scan Complete!"
echo "======================================"
echo ""

# Display results
if [ -f "$OUTPUT_DIR/findings.csv" ]; then
  FINDING_COUNT=$(tail -n +2 "$OUTPUT_DIR/findings.csv" | wc -l | tr -d ' ')
  echo "📊 Results Summary:"
  echo "  - Total Findings: $FINDING_COUNT"
  echo "  - CSV Export: $OUTPUT_DIR/findings.csv"
  echo "  - TSV Export: $OUTPUT_DIR/findings.tsv"
  echo "  - SARIF Report: $OUTPUT_DIR/yavs-results.sarif"
  echo "  - JSON Report: $OUTPUT_DIR/scan-results.json"
  echo ""
fi

# Feature-specific outputs
echo "🎯 Feature Highlights:"
echo ""

# Check for git blame data
if command -v jq &> /dev/null && [ -f "$OUTPUT_DIR/scan-results.json" ]; then
  BLAME_COUNT=$(jq '[.data[]? | select(.git_blame != null)] | length' "$OUTPUT_DIR/scan-results.json" 2>/dev/null || echo "0")
  echo "  Git Blame: $BLAME_COUNT findings attributed"
fi

# Check for policy suppressions
if [ -f "$OUTPUT_DIR/scan-results.json" ]; then
  POLICY_SUPPRESSED=$(jq '[.data[]? | select(.suppressed_by_policy == true)] | length' "$OUTPUT_DIR/scan-results.json" 2>/dev/null || echo "0")
  echo "  Policy Suppressions: $POLICY_SUPPRESSED findings suppressed"
fi

echo ""

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ Scan passed - no critical issues found"
elif [ $EXIT_CODE -eq 1 ]; then
  echo "⚠️  Scan found issues above threshold (fail-fast triggered)"
else
  echo "❌ Scan encountered errors"
fi

echo ""
echo "📖 View detailed results:"
echo "   open $OUTPUT_DIR/report.html"
echo ""

exit $EXIT_CODE
