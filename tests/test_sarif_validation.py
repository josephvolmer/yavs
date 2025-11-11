"""Tests for SARIF validation and output compliance."""

import json
import pytest
from pathlib import Path

from yavs.reporting.sarif_converter import SARIFConverter
from yavs.utils.schema_validator import validate_sarif, validate_sarif_structure


def test_sarif_structure():
    """Test basic SARIF structure generation."""
    converter = SARIFConverter()

    findings = [
        {
            "tool": "test",
            "category": "test",
            "severity": "HIGH",
            "file": "test.py",
            "line": 10,
            "message": "Test finding",
            "rule_id": "TEST-001"
        }
    ]

    sarif = converter.convert(findings)

    # Check required fields
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) > 0


def test_sarif_tool_metadata():
    """Test SARIF tool metadata."""
    converter = SARIFConverter()
    sarif = converter.convert([])

    tool = sarif["runs"][0]["tool"]["driver"]
    assert tool["name"] == "YAVS"
    assert "version" in tool
    assert "informationUri" in tool


def test_sarif_severity_mapping():
    """Test severity mapping to SARIF levels."""
    converter = SARIFConverter()

    test_cases = [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "none"),
    ]

    for yavs_severity, expected_level in test_cases:
        findings = [{
            "tool": "test",
            "category": "test",
            "severity": yavs_severity,
            "file": "test.py",
            "message": "Test",
            "rule_id": f"TEST-{yavs_severity}"
        }]

        sarif = converter.convert(findings)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == expected_level


def test_sarif_empty_results():
    """Test SARIF generation with no findings."""
    converter = SARIFConverter()
    sarif = converter.convert([])

    assert sarif["runs"][0]["results"] == []


def test_sarif_structure_validation():
    """Test SARIF structure validation."""
    # Valid SARIF
    valid_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "YAVS"
                    }
                },
                "results": []
            }
        ]
    }

    is_valid, message = validate_sarif_structure(valid_sarif)
    assert is_valid

    # Missing version
    invalid_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": []
    }

    is_valid, message = validate_sarif_structure(invalid_sarif)
    assert not is_valid


def test_sarif_with_ai_summary():
    """Test SARIF with AI summaries."""
    converter = SARIFConverter()

    findings = [{
        "tool": "test",
        "category": "test",
        "severity": "HIGH",
        "file": "test.py",
        "message": "Test",
        "rule_id": "TEST-001",
        "ai_summary": "This is an AI-generated fix suggestion."
    }]

    sarif = converter.convert(findings, include_ai_summary=True)
    result = sarif["runs"][0]["results"][0]

    assert "ai_summary" in result["properties"]
    assert result["properties"]["ai_summary"] == "This is an AI-generated fix suggestion."


def test_sarif_rules_generation():
    """Test SARIF rules generation."""
    converter = SARIFConverter()

    findings = [
        {
            "tool": "test",
            "category": "test",
            "severity": "HIGH",
            "file": "test.py",
            "message": "SQL Injection",
            "rule_id": "SQLI-001",
            "description": "Potential SQL injection vulnerability"
        },
        {
            "tool": "test",
            "category": "test",
            "severity": "MEDIUM",
            "file": "test.py",
            "message": "SQL Injection",  # Same rule
            "rule_id": "SQLI-001",
        }
    ]

    sarif = converter.convert(findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    # Should deduplicate rules
    assert len(rules) == 1
    assert rules[0]["id"] == "SQLI-001"
