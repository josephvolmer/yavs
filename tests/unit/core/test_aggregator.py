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
