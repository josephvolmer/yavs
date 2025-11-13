"""Tests for the aggregator module."""

import pytest
from pathlib import Path
import tempfile
import json

from yavs.reporting.aggregator import Aggregator


def test_aggregator_add_findings():
    """Test adding findings to aggregator."""
    agg = Aggregator()

    findings1 = [
        {"tool": "trivy", "severity": "HIGH", "message": "CVE-2021-1234"}
    ]
    findings2 = [
        {"tool": "semgrep", "severity": "MEDIUM", "message": "SQL Injection"}
    ]

    agg.add_findings(findings1)
    agg.add_findings(findings2)

    assert len(agg.get_findings()) == 2


def test_aggregator_deduplication():
    """Test finding deduplication."""
    agg = Aggregator()

    # Add duplicate findings
    findings = [
        {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "message": "Test finding"
        },
        {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "message": "Test finding"
        },
        {
            "file": "test.py",
            "line": 20,  # Different line
            "rule_id": "TEST-001",
            "message": "Test finding"
        }
    ]

    agg.add_findings(findings)
    agg.deduplicate()

    # Should have 2 unique findings (different lines)
    assert len(agg.get_findings()) == 2


def test_aggregator_sort_by_severity():
    """Test sorting by severity."""
    agg = Aggregator()

    findings = [
        {"severity": "LOW", "message": "Low"},
        {"severity": "CRITICAL", "message": "Critical"},
        {"severity": "MEDIUM", "message": "Medium"},
        {"severity": "HIGH", "message": "High"},
    ]

    agg.add_findings(findings)
    agg.sort_by_severity()

    sorted_findings = agg.get_findings()
    severities = [f["severity"] for f in sorted_findings]

    assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_aggregator_statistics():
    """Test statistics generation."""
    agg = Aggregator()

    findings = [
        {"tool": "trivy", "category": "dependency", "severity": "HIGH"},
        {"tool": "trivy", "category": "dependency", "severity": "MEDIUM"},
        {"tool": "semgrep", "category": "sast", "severity": "HIGH"},
    ]

    agg.add_findings(findings)
    stats = agg.get_statistics()

    assert stats["total"] == 3
    assert stats["by_severity"]["HIGH"] == 2
    assert stats["by_severity"]["MEDIUM"] == 1
    assert stats["by_tool"]["trivy"] == 2
    assert stats["by_tool"]["semgrep"] == 1


def test_aggregator_json_io():
    """Test JSON reading and writing."""
    agg = Aggregator()

    findings = [
        {"tool": "test", "severity": "HIGH", "message": "Test"}
    ]

    agg.add_findings(findings)

    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)

    try:
        agg.write_json(temp_path)

        # Read back
        agg2 = Aggregator()
        agg2.read_json(temp_path)

        assert len(agg2.get_findings()) == 1
        assert agg2.get_findings()[0]["message"] == "Test"
    finally:
        temp_path.unlink()


def test_aggregator_clear():
    """Test clearing findings."""
    agg = Aggregator()
    agg.add_findings([{"test": "data"}])

    assert len(agg.get_findings()) == 1

    agg.clear()

    assert len(agg.get_findings()) == 0


def test_aggregator_register_scanner():
    """Test scanner registration."""
    agg = Aggregator()

    agg.register_scanner("trivy", "dependency", findings_count=5, status="success")
    assert "trivy" in agg.executed_scanners
    # Initial registration doesn't use findings_count parameter initially, just sets to 0
    assert agg.executed_scanners["trivy"]["findings_count"] == 0

    # Register again - should update count
    agg.register_scanner("trivy", "dependency", findings_count=3, status="success")
    assert agg.executed_scanners["trivy"]["findings_count"] == 3


def test_aggregator_register_scanner_with_error():
    """Test scanner registration with error."""
    agg = Aggregator()

    agg.register_scanner("semgrep", "sast", findings_count=0, status="failed", error="Tool not found")
    assert agg.executed_scanners["semgrep"]["status"] == "failed"
    assert "error" in agg.executed_scanners["semgrep"]


def test_aggregator_read_json_flat_array():
    """Test reading flat array JSON format."""
    agg = Aggregator()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)
        json.dump([
            {"tool": "trivy", "severity": "HIGH"},
            {"tool": "semgrep", "severity": "MEDIUM"}
        ], f)

    try:
        agg.read_json(temp_path)
        assert len(agg.get_findings()) == 2
    finally:
        temp_path.unlink()


def test_aggregator_read_json_structured_format():
    """Test reading structured JSON format (with compliance/sast keys)."""
    agg = Aggregator()

    structured_data = {
        "compliance": [
            {
                "tool": "checkov",
                "violations": [
                    {"description": "Security group allows all traffic", "severity": "HIGH"},
                    {"description": "S3 bucket not encrypted", "severity": "MEDIUM"}
                ]
            }
        ],
        "sast": [
            {
                "tool": "semgrep",
                "issues": [
                    {"description": "SQL injection", "severity": "HIGH"}
                ]
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)
        json.dump(structured_data, f)

    try:
        agg.read_json(temp_path)
        findings = agg.get_findings()
        assert len(findings) == 3
        # Check that tool names were added
        assert all('tool' in f for f in findings)
        # Check that message field was created from description
        assert all('message' in f for f in findings)
        # Check categories were added
        categories = [f['category'] for f in findings]
        assert 'compliance' in categories
        assert 'sast' in categories
    finally:
        temp_path.unlink()


def test_aggregator_read_json_with_data_wrapper():
    """Test reading JSON with data wrapper."""
    agg = Aggregator()

    data = {
        "data": [
            {"tool": "trivy", "severity": "HIGH"}
        ],
        "metadata": {"scan_time": "2025-01-01"}
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)
        json.dump(data, f)

    try:
        agg.read_json(temp_path)
        assert len(agg.get_findings()) == 1
    finally:
        temp_path.unlink()


def test_aggregator_read_json_unknown_format():
    """Test reading JSON with unknown format."""
    agg = Aggregator()

    data = {"unknown_key": "value"}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)
        json.dump(data, f)

    try:
        agg.read_json(temp_path)
        # Should handle gracefully
        assert len(agg.get_findings()) == 0
    finally:
        temp_path.unlink()


def test_aggregator_read_json_invalid_format():
    """Test reading JSON with invalid format (not list or dict)."""
    agg = Aggregator()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = Path(f.name)
        json.dump("invalid", f)

    try:
        agg.read_json(temp_path)
        # Should handle gracefully
        assert len(agg.get_findings()) == 0
    finally:
        temp_path.unlink()


def test_aggregator_update_scanner_status():
    """Test updating scanner status to failed."""
    agg = Aggregator()

    agg.register_scanner("bandit", "sast", findings_count=5, status="success")
    assert agg.executed_scanners["bandit"]["status"] == "success"

    # Register again with failed status
    agg.register_scanner("bandit", "sast", findings_count=0, status="failed")
    assert agg.executed_scanners["bandit"]["status"] == "failed"
