#!/bin/bash
#
# Comprehensive YAVS Testing Script
# Tests all combinations of scanners, features, and output formats
#

set -e

ARTIFACTS_DIR="artifacts"
FIXTURES_DIR="tests/fixtures"

echo "========================================"
echo "YAVS Comprehensive Combination Testing"
echo "========================================"
echo ""

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local command="$2"
    local output_dir="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BLUE}[Test $TOTAL_TESTS]${NC} $test_name"
    echo "Command: $command"

    # Run command and capture exit code (allow non-zero since findings cause exit 1)
    set +e
    eval "$command" > /tmp/yavs_test_$TOTAL_TESTS.log 2>&1
    EXIT_CODE=$?
    set -e

    # Check if output files were created (main success criterion)
    if [ -f "$output_dir/yavs-results.json" ]; then
        echo -e "${GREEN}✓ PASSED${NC} (exit code: $EXIT_CODE)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC} (exit code: $EXIT_CODE)"
        echo "  Last 5 lines of output:"
        tail -5 /tmp/yavs_test_$TOTAL_TESTS.log | sed 's/^/  /'
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

# Clean artifacts directory
echo "Cleaning artifacts directory..."
rm -rf "$ARTIFACTS_DIR"
mkdir -p "$ARTIFACTS_DIR"/{sample_project,nodejs_project,java_project,go_project,kubernetes,multi_dir,docker_images}
echo ""

echo "========================================"
echo "Section 1: Individual Scanner Tests"
echo "========================================"
echo ""

# Test 1.1: SBOM (Trivy dependency/secret/license scanning)
run_test "Python: SBOM scanner (Trivy vuln/secret/license)" \
    "yavs scan $FIXTURES_DIR/sample_project --sbom --no-ai -o $ARTIFACTS_DIR/sample_project/sbom-scan" \
    "$ARTIFACTS_DIR/sample_project/sbom-scan"

# Test 1.2: SAST only (Semgrep + Bandit)
run_test "Python: SAST scanners (Semgrep + Bandit)" \
    "yavs scan $FIXTURES_DIR/sample_project --sast --no-ai -o $ARTIFACTS_DIR/sample_project/sast-only" \
    "$ARTIFACTS_DIR/sample_project/sast-only"

# Test 1.3: Compliance only (Checkov)
run_test "Python: Compliance scanner (Checkov)" \
    "yavs scan $FIXTURES_DIR/sample_project --compliance --no-ai -o $ARTIFACTS_DIR/sample_project/compliance-only" \
    "$ARTIFACTS_DIR/sample_project/compliance-only"

# Test 1.4: All scanners
run_test "Python: All scanners" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai -o $ARTIFACTS_DIR/sample_project/all-scanners" \
    "$ARTIFACTS_DIR/sample_project/all-scanners"

echo "========================================"
echo "Section 2: Output Format Tests"
echo "========================================"
echo ""

# Test 2.1: Structured JSON output
run_test "Python: Structured JSON output" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai --structured -o $ARTIFACTS_DIR/sample_project/structured" \
    "$ARTIFACTS_DIR/sample_project/structured"

# Test 2.2: Flat JSON output (default)
run_test "Python: Flat JSON output (default)" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai -o $ARTIFACTS_DIR/sample_project/flat" \
    "$ARTIFACTS_DIR/sample_project/flat"

# Test 2.3: SBOM generation
run_test "Python: With SBOM generation" \
    "yavs scan $FIXTURES_DIR/sample_project --sbom --no-ai -o $ARTIFACTS_DIR/sample_project/with-sbom" \
    "$ARTIFACTS_DIR/sample_project/with-sbom"

# Test 2.4: All scanners with structured output and SBOM
run_test "Python: All scanners + structured + SBOM" \
    "yavs scan $FIXTURES_DIR/sample_project --all --structured --no-ai -o $ARTIFACTS_DIR/sample_project/all-structured-sbom" \
    "$ARTIFACTS_DIR/sample_project/all-structured-sbom"

echo "========================================"
echo "Section 3: Scanner Combination Tests"
echo "========================================"
echo ""

# Test 3.1: SBOM + SAST
run_test "Python: SBOM + SAST" \
    "yavs scan $FIXTURES_DIR/sample_project --sbom --sast --no-ai -o $ARTIFACTS_DIR/sample_project/sbom-sast" \
    "$ARTIFACTS_DIR/sample_project/sbom-sast"

# Test 3.2: SBOM + Compliance
run_test "Python: SBOM + Compliance" \
    "yavs scan $FIXTURES_DIR/sample_project --sbom --compliance --no-ai -o $ARTIFACTS_DIR/sample_project/sbom-compliance" \
    "$ARTIFACTS_DIR/sample_project/sbom-compliance"

# Test 3.3: SAST + Compliance
run_test "Python: SAST + Compliance" \
    "yavs scan $FIXTURES_DIR/sample_project --sast --compliance --no-ai -o $ARTIFACTS_DIR/sample_project/sast-compliance" \
    "$ARTIFACTS_DIR/sample_project/sast-compliance"

# Test 3.4: All scanners (SBOM + SAST + Compliance)
run_test "Python: All scanners (complete coverage)" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai -o $ARTIFACTS_DIR/sample_project/all-complete" \
    "$ARTIFACTS_DIR/sample_project/all-complete"

echo "========================================"
echo "Section 4: Multi-Language Tests"
echo "========================================"
echo ""

# Test 4.1: Node.js project
run_test "Node.js: Full scan" \
    "yavs scan $FIXTURES_DIR/nodejs_project --all --no-ai -o $ARTIFACTS_DIR/nodejs_project/full-scan" \
    "$ARTIFACTS_DIR/nodejs_project/full-scan"

# Test 4.2: Java project
run_test "Java: Full scan" \
    "yavs scan $FIXTURES_DIR/java_project --all --no-ai -o $ARTIFACTS_DIR/java_project/full-scan" \
    "$ARTIFACTS_DIR/java_project/full-scan"

# Test 4.3: Java with SBOM only
run_test "Java: SBOM scan (dependency CVEs)" \
    "yavs scan $FIXTURES_DIR/java_project --sbom --no-ai -o $ARTIFACTS_DIR/java_project/sbom-only" \
    "$ARTIFACTS_DIR/java_project/sbom-only"

# Test 4.4: Go project
run_test "Go: Full scan" \
    "yavs scan $FIXTURES_DIR/go_project --all --no-ai -o $ARTIFACTS_DIR/go_project/full-scan" \
    "$ARTIFACTS_DIR/go_project/full-scan"

# Test 4.5: Go with SAST
run_test "Go: SAST scan" \
    "yavs scan $FIXTURES_DIR/go_project --sast --no-ai -o $ARTIFACTS_DIR/go_project/sast-scan" \
    "$ARTIFACTS_DIR/go_project/sast-scan"

# Test 4.6: Kubernetes compliance
run_test "Kubernetes: Compliance scan" \
    "yavs scan $FIXTURES_DIR/kubernetes --compliance --no-ai -o $ARTIFACTS_DIR/kubernetes/compliance" \
    "$ARTIFACTS_DIR/kubernetes/compliance"

# Test 4.7: Kubernetes all scanners
run_test "Kubernetes: All scanners" \
    "yavs scan $FIXTURES_DIR/kubernetes --all --no-ai -o $ARTIFACTS_DIR/kubernetes/all-scanners" \
    "$ARTIFACTS_DIR/kubernetes/all-scanners"

echo "========================================"
echo "Section 5: Multi-Directory Tests"
echo "========================================"
echo ""

# Test 5.1: Two directories (Python + Node.js)
run_test "Multi-dir: Python + Node.js" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/nodejs_project --all --no-ai -o $ARTIFACTS_DIR/multi_dir/python-nodejs" \
    "$ARTIFACTS_DIR/multi_dir/python-nodejs"

# Test 5.2: Three directories (Python + Java + Go)
run_test "Multi-dir: Python + Java + Go" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/java_project $FIXTURES_DIR/go_project --all --no-ai -o $ARTIFACTS_DIR/multi_dir/python-java-go" \
    "$ARTIFACTS_DIR/multi_dir/python-java-go"

# Test 5.3: Multi-dir with SBOM
run_test "Multi-dir: Java + Go with SBOM" \
    "yavs scan $FIXTURES_DIR/java_project $FIXTURES_DIR/go_project --sbom --no-ai -o $ARTIFACTS_DIR/multi_dir/java-go-sbom" \
    "$ARTIFACTS_DIR/multi_dir/java-go-sbom"

# Test 5.4: All fixtures
run_test "Multi-dir: All fixtures" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/nodejs_project $FIXTURES_DIR/java_project $FIXTURES_DIR/go_project --all --no-ai -o $ARTIFACTS_DIR/multi_dir/all-fixtures" \
    "$ARTIFACTS_DIR/multi_dir/all-fixtures"

# Test 5.5: Multi-dir with structured output
run_test "Multi-dir: Python + Java structured output" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/java_project --all --structured --no-ai -o $ARTIFACTS_DIR/multi_dir/python-java-structured" \
    "$ARTIFACTS_DIR/multi_dir/python-java-structured"

echo "========================================"
echo "Section 6: Ignore Pattern Tests"
echo "========================================"
echo ""

# Test 6.1: Ignore test directory
run_test "Python: Ignore test/ directory" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai --ignore 'test/' -o $ARTIFACTS_DIR/sample_project/ignore-test" \
    "$ARTIFACTS_DIR/sample_project/ignore-test"

# Test 6.2: Multiple ignore patterns
run_test "Python: Multiple ignore patterns" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai --ignore 'test/' --ignore '__pycache__/' --ignore '.*\.pyc$' -o $ARTIFACTS_DIR/sample_project/multi-ignore" \
    "$ARTIFACTS_DIR/sample_project/multi-ignore"

# Test 6.3: Ignore vulnerable files specifically
run_test "Python: Ignore vulnerable.* files" \
    "yavs scan $FIXTURES_DIR/sample_project --all --no-ai --ignore '.*vulnerable.*' -o $ARTIFACTS_DIR/sample_project/ignore-vulnerable" \
    "$ARTIFACTS_DIR/sample_project/ignore-vulnerable"

# Test 6.4: Multi-dir with ignore patterns
run_test "Multi-dir: With ignore patterns" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/nodejs_project --all --no-ai --ignore 'test/' --ignore 'node_modules/' -o $ARTIFACTS_DIR/multi_dir/with-ignores" \
    "$ARTIFACTS_DIR/multi_dir/with-ignores"

echo "========================================"
echo "Section 7: Output Combinations"
echo "========================================"
echo ""

# Test 7.1: Structured + SBOM
run_test "Python: Structured output + SBOM" \
    "yavs scan $FIXTURES_DIR/sample_project --all --structured --no-ai -o $ARTIFACTS_DIR/sample_project/structured-sbom" \
    "$ARTIFACTS_DIR/sample_project/structured-sbom"

# Test 7.2: Java structured with all scanners
run_test "Java: Structured all scanners" \
    "yavs scan $FIXTURES_DIR/java_project --all --structured --no-ai -o $ARTIFACTS_DIR/java_project/structured-all" \
    "$ARTIFACTS_DIR/java_project/structured-all"

# Test 7.3: SBOM-only for Node.js
run_test "Node.js: SBOM only" \
    "yavs scan $FIXTURES_DIR/nodejs_project --sbom --no-ai -o $ARTIFACTS_DIR/nodejs_project/sbom-only" \
    "$ARTIFACTS_DIR/nodejs_project/sbom-only"

# Test 7.4: SAST-only for Node.js (JavaScript analysis)
run_test "Node.js: SAST only (JavaScript)" \
    "yavs scan $FIXTURES_DIR/nodejs_project --sast --no-ai -o $ARTIFACTS_DIR/nodejs_project/sast-only" \
    "$ARTIFACTS_DIR/nodejs_project/sast-only"

echo "========================================"
echo "Section 8: Language-Specific Scanner Tests"
echo "========================================"
echo ""

# Test 8.1: Java dependency scanning
run_test "Java: Dependency scanning (Maven)" \
    "yavs scan $FIXTURES_DIR/java_project --sbom --no-ai -o $ARTIFACTS_DIR/java_project/maven-deps" \
    "$ARTIFACTS_DIR/java_project/maven-deps"

# Test 8.2: Java SAST
run_test "Java: SAST scanning" \
    "yavs scan $FIXTURES_DIR/java_project --sast --no-ai -o $ARTIFACTS_DIR/java_project/java-sast" \
    "$ARTIFACTS_DIR/java_project/java-sast"

# Test 8.3: Go dependency scanning
run_test "Go: Dependency scanning (go.mod)" \
    "yavs scan $FIXTURES_DIR/go_project --sbom --no-ai -o $ARTIFACTS_DIR/go_project/go-deps" \
    "$ARTIFACTS_DIR/go_project/go-deps"

# Test 8.4: Python SAST
run_test "Python: SAST (Semgrep + Bandit)" \
    "yavs scan $FIXTURES_DIR/sample_project --sast --no-ai -o $ARTIFACTS_DIR/sample_project/python-sast" \
    "$ARTIFACTS_DIR/sample_project/python-sast"

# Test 8.5: Kubernetes IaC compliance
run_test "Kubernetes: IaC compliance only" \
    "yavs scan $FIXTURES_DIR/kubernetes --compliance --no-ai -o $ARTIFACTS_DIR/kubernetes/iac-compliance" \
    "$ARTIFACTS_DIR/kubernetes/iac-compliance"

echo "========================================"
echo "Section 9: Edge Cases and Special Scenarios"
echo "========================================"
echo ""

# Test 9.1: Scan with only compliance (no SBOM, no SAST)
run_test "Python: Compliance only" \
    "yavs scan $FIXTURES_DIR/sample_project --compliance --no-ai -o $ARTIFACTS_DIR/sample_project/compliance-only-test" \
    "$ARTIFACTS_DIR/sample_project/compliance-only-test"

# Test 9.2: Empty Node.js project (no dependencies installed)
run_test "Node.js: Scan without node_modules" \
    "yavs scan $FIXTURES_DIR/nodejs_project --all --no-ai -o $ARTIFACTS_DIR/nodejs_project/no-deps" \
    "$ARTIFACTS_DIR/nodejs_project/no-deps"

# Test 9.3: All scanners + structured + ignore patterns
run_test "Python: Complete scan with ignores and structured" \
    "yavs scan $FIXTURES_DIR/sample_project --all --structured --no-ai --ignore 'test/' -o $ARTIFACTS_DIR/sample_project/complete-complex" \
    "$ARTIFACTS_DIR/sample_project/complete-complex"

# Test 9.4: Multi-language SBOM comparison
run_test "Multi-language: SBOM comparison (Python vs Java vs Go)" \
    "yavs scan $FIXTURES_DIR/sample_project $FIXTURES_DIR/java_project $FIXTURES_DIR/go_project --sbom --no-ai -o $ARTIFACTS_DIR/multi_dir/sbom-comparison" \
    "$ARTIFACTS_DIR/multi_dir/sbom-comparison"

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo ""
echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    EXIT_STATUS=0
else
    echo -e "${YELLOW}Note: Some failures may be expected (e.g., scanners not available, empty fixtures)${NC}"
    EXIT_STATUS=1
fi

echo ""
echo "Artifacts saved to: $ARTIFACTS_DIR/"
echo ""
echo "Generating summary report..."

# Generate a summary report
SUMMARY_FILE="$ARTIFACTS_DIR/test-summary.txt"
cat > "$SUMMARY_FILE" << EOF
YAVS Comprehensive Test Summary
================================
Generated: $(date)

Total Tests Run: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS

Test Categories:
1. Individual Scanner Tests (4 tests)
   - SBOM (Trivy: vuln/secret/license)
   - SAST (Semgrep + Bandit)
   - Compliance (Checkov)
   - All scanners

2. Output Format Tests (4 tests)
   - Structured JSON
   - Flat JSON (default)
   - SBOM generation
   - All formats combined

3. Scanner Combination Tests (4 tests)
   - SBOM + SAST
   - SBOM + Compliance
   - SAST + Compliance
   - All scanners

4. Multi-Language Tests (7 tests)
   - Node.js, Java, Go, Kubernetes
   - Different scanner combinations per language

5. Multi-Directory Tests (5 tests)
   - 2, 3, and 4 directory combinations
   - With SBOM and structured output

6. Ignore Pattern Tests (4 tests)
   - Single and multiple patterns
   - Multi-directory with ignores

7. Output Combinations (4 tests)
   - Various format and scanner combinations

8. Language-Specific Scanner Tests (5 tests)
   - Optimal scanners for each language

9. Edge Cases and Special Scenarios (4 tests)
   - Complex combinations
   - Empty projects
   - Multi-language comparisons

All test artifacts saved to: $ARTIFACTS_DIR/

Directory Structure:
- sample_project/: Python project tests
- nodejs_project/: Node.js project tests
- java_project/: Java project tests
- go_project/: Go project tests
- kubernetes/: Kubernetes manifest tests
- multi_dir/: Multi-directory scanning tests

Each test directory contains:
- yavs-results.json: JSON output (flat or structured)
- yavs-results.sarif: SARIF 2.1.0 format output
- sbom.json: CycloneDX SBOM (when applicable)

Scanner Coverage:
- Trivy: Dependency CVEs, secrets, licenses
- Semgrep: SAST (all languages)
- Bandit: Python security
- Checkov: IaC compliance

Output Format Coverage:
- JSON (flat array format)
- JSON (structured by category)
- SARIF 2.1.0
- SBOM (CycloneDX)

Feature Coverage:
- Multi-directory scanning
- Source tagging
- Ignore patterns (regex)
- Multi-language support
- Combined scanner orchestration
EOF

echo "✓ Summary report saved to: $SUMMARY_FILE"
echo ""

# Generate detailed findings report
FINDINGS_FILE="$ARTIFACTS_DIR/findings-summary.txt"
echo "Generating findings summary..."
echo "YAVS Findings Summary" > "$FINDINGS_FILE"
echo "=====================" >> "$FINDINGS_FILE"
echo "" >> "$FINDINGS_FILE"

for project_dir in sample_project nodejs_project java_project go_project kubernetes multi_dir; do
    if [ -d "$ARTIFACTS_DIR/$project_dir" ]; then
        echo "Project: $project_dir" >> "$FINDINGS_FILE"
        echo "-------------------" >> "$FINDINGS_FILE"

        for test_dir in "$ARTIFACTS_DIR/$project_dir"/*; do
            if [ -d "$test_dir" ] && [ -f "$test_dir/yavs-results.json" ]; then
                test_name=$(basename "$test_dir")
                finding_count=$(jq '. | length' "$test_dir/yavs-results.json" 2>/dev/null || echo "N/A")
                echo "  $test_name: $finding_count findings" >> "$FINDINGS_FILE"
            fi
        done
        echo "" >> "$FINDINGS_FILE"
    fi
done

echo "✓ Findings report saved to: $FINDINGS_FILE"
echo ""
echo "Done!"

# Clean up temp logs
rm -f /tmp/yavs_test_*.log

exit $EXIT_STATUS
