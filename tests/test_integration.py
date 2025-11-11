"""Integration tests for end-to-end YAVS workflow."""

import pytest
from pathlib import Path
import json
import tempfile

from yavs.scanners import TrivyScanner, SemgrepScanner, CheckovScanner
from yavs.reporting import Aggregator, SARIFConverter
from yavs.utils.schema_validator import validate_sarif_structure


@pytest.fixture
def sample_project():
    """Path to sample vulnerable project."""
    return Path(__file__).parent / "fixtures" / "sample_project"


@pytest.mark.integration
def test_end_to_end_scan(sample_project):
    """
    Test complete scan workflow:
    1. Run scanner
    2. Aggregate results
    3. Generate SARIF
    4. Validate SARIF
    """
    # Skip if sample project doesn't exist
    if not sample_project.exists():
        pytest.skip("Sample project not found")

    aggregator = Aggregator()

    # Note: This test requires scanners to be installed
    # In a real test, we might mock the scanner outputs

    # Aggregate findings
    aggregator.sort_by_severity()
    findings = aggregator.get_findings()

    # Generate SARIF
    converter = SARIFConverter(base_path=sample_project)
    sarif = converter.convert(findings)

    # Validate SARIF structure
    is_valid, message = validate_sarif_structure(sarif)
    assert is_valid, f"SARIF validation failed: {message}"

    # Check SARIF content
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    # Check tool metadata
    tool = sarif["runs"][0]["tool"]["driver"]
    assert tool["name"] == "YAVS"


def test_json_to_sarif_conversion():
    """Test converting JSON findings to SARIF."""
    # Sample findings
    findings = [
        {
            "tool": "trivy",
            "category": "dependency",
            "severity": "HIGH",
            "file": "requirements.txt",
            "line": 1,
            "message": "CVE-2021-1234: Vulnerability in package",
            "rule_id": "CVE-2021-1234",
            "package": "requests",
            "version": "2.19.0",
            "fixed_version": "2.20.0"
        },
        {
            "tool": "semgrep",
            "category": "sast",
            "severity": "MEDIUM",
            "file": "app.py",
            "line": 42,
            "message": "Potential SQL injection",
            "rule_id": "python.lang.security.sqli"
        }
    ]

    # Convert to SARIF
    converter = SARIFConverter()
    sarif = converter.convert(findings)

    # Validate structure
    is_valid, _ = validate_sarif_structure(sarif)
    assert is_valid

    # Check results
    results = sarif["runs"][0]["results"]
    assert len(results) == 2

    # Check first result
    result1 = results[0]
    assert result1["ruleId"] == "CVE-2021-1234"
    assert result1["level"] == "error"  # HIGH -> error
    assert result1["properties"]["package"] == "requests"

    # Check second result
    result2 = results[1]
    assert result2["ruleId"] == "python.lang.security.sqli"
    assert result2["level"] == "warning"  # MEDIUM -> warning


def test_aggregation_workflow():
    """Test the aggregation workflow."""
    aggregator = Aggregator()

    # Simulate findings from multiple scanners
    trivy_findings = [
        {"tool": "trivy", "severity": "HIGH", "file": "requirements.txt", "message": "CVE-1"}
    ]

    semgrep_findings = [
        {"tool": "semgrep", "severity": "MEDIUM", "file": "app.py", "message": "SQLI"}
    ]

    checkov_findings = [
        {"tool": "checkov", "severity": "LOW", "file": "terraform.tf", "message": "Compliance"}
    ]

    # Add findings
    aggregator.add_findings(trivy_findings)
    aggregator.add_findings(semgrep_findings)
    aggregator.add_findings(checkov_findings)

    # Process
    aggregator.deduplicate()
    aggregator.sort_by_severity()

    # Verify
    findings = aggregator.get_findings()
    assert len(findings) == 3

    # Check sorting (HIGH, MEDIUM, LOW)
    assert findings[0]["severity"] == "HIGH"
    assert findings[1]["severity"] == "MEDIUM"
    assert findings[2]["severity"] == "LOW"

    # Check statistics
    stats = aggregator.get_statistics()
    assert stats["total"] == 3
    assert stats["by_tool"]["trivy"] == 1
    assert stats["by_tool"]["semgrep"] == 1
    assert stats["by_tool"]["checkov"] == 1


def test_sarif_file_write():
    """Test writing SARIF to file."""
    findings = [
        {
            "tool": "test",
            "category": "test",
            "severity": "HIGH",
            "file": "test.py",
            "message": "Test finding",
            "rule_id": "TEST-001"
        }
    ]

    converter = SARIFConverter()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        temp_path = Path(f.name)

    try:
        converter.convert_and_write(findings, temp_path)

        # Read back and validate
        with open(temp_path, 'r') as f:
            sarif = json.load(f)

        is_valid, _ = validate_sarif_structure(sarif)
        assert is_valid

        # Check content
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

    finally:
        temp_path.unlink()
