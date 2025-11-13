"""Tests for schema validator."""

import pytest
import json
import tempfile
from pathlib import Path

from yavs.utils.schema_validator import (
    validate_sarif_structure,
    validate_finding_schema
)


class TestValidateSARIFStructure:
    """Test SARIF structure validation."""

    def test_valid_minimal_sarif(self):
        """Test validation of minimal valid SARIF."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestTool"
                        }
                    },
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is True

    def test_valid_sarif_with_results(self):
        """Test validation of SARIF with results."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "YAVS"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "TEST-001",
                            "message": {
                                "text": "Test finding"
                            },
                            "level": "error"
                        }
                    ]
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is True

    def test_missing_version(self):
        """Test SARIF missing version fails."""
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "version" in message.lower()

    def test_missing_schema(self):
        """Test SARIF missing $schema fails."""
        sarif = {
            "version": "2.1.0",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "schema" in message.lower()

    def test_missing_runs(self):
        """Test SARIF missing runs fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json"
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "runs" in message.lower()

    def test_wrong_version(self):
        """Test SARIF with wrong version fails."""
        sarif = {
            "version": "1.0.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "version" in message.lower()

    def test_runs_not_list(self):
        """Test SARIF with runs not a list fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": {}
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "runs" in message.lower()

    def test_empty_runs(self):
        """Test SARIF with empty runs array fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "run" in message.lower()

    def test_run_missing_tool(self):
        """Test SARIF run missing tool fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "tool" in message.lower()

    def test_tool_missing_driver(self):
        """Test SARIF tool missing driver fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {},
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "driver" in message.lower()

    def test_driver_missing_name(self):
        """Test SARIF driver missing name fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {}
                    },
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "name" in message.lower()

    def test_not_dict(self):
        """Test non-dict input fails."""
        is_valid, message = validate_sarif_structure([])
        assert is_valid is False
        assert "dictionary" in message.lower()

    def test_none_input(self):
        """Test None input fails."""
        is_valid, message = validate_sarif_structure(None)
        assert is_valid is False


class TestValidateFindingSchema:
    """Test finding schema validation."""

    def test_valid_minimal_finding(self):
        """Test validation of minimal valid finding."""
        finding = {
            "tool": "trivy",
            "severity": "HIGH",
            "message": "CVE-2021-1234"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is True

    def test_valid_complete_finding(self):
        """Test validation of complete finding."""
        finding = {
            "tool": "semgrep",
            "category": "sast",
            "severity": "HIGH",
            "file": "src/app.py",
            "line": 42,
            "message": "SQL injection vulnerability",
            "rule_id": "python.lang.security.sqli",
            "description": "Detected SQL injection",
            "remediation": "Use parameterized queries"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is True

    def test_missing_tool(self):
        """Test finding missing tool fails."""
        finding = {
            "severity": "HIGH",
            "message": "Test"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is False
        assert "tool" in message.lower()

    def test_missing_severity(self):
        """Test finding missing severity fails."""
        finding = {
            "tool": "trivy",
            "message": "Test"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is False
        assert "severity" in message.lower()

    def test_missing_message(self):
        """Test finding missing message fails."""
        finding = {
            "tool": "trivy",
            "severity": "HIGH"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is False
        assert "message" in message.lower()

    def test_invalid_severity(self):
        """Test finding with invalid severity fails."""
        finding = {
            "tool": "trivy",
            "severity": "INVALID",
            "message": "Test"
        }
        is_valid, message = validate_finding_schema(finding)
        assert is_valid is False
        assert "severity" in message.lower()

    def test_valid_severity_levels(self):
        """Test all valid severity levels."""
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severities:
            finding = {
                "tool": "test",
                "severity": sev,
                "message": "Test"
            }
            is_valid, message = validate_finding_schema(finding)
            assert is_valid is True, f"Severity {sev} should be valid"

    def test_not_dict(self):
        """Test non-dict input fails."""
        is_valid, message = validate_finding_schema([])
        assert is_valid is False
        assert "dictionary" in message.lower()

    def test_none_input(self):
        """Test None input fails."""
        is_valid, message = validate_finding_schema(None)
        assert is_valid is False

    def test_empty_dict(self):
        """Test empty dict fails."""
        is_valid, message = validate_finding_schema({})
        assert is_valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
