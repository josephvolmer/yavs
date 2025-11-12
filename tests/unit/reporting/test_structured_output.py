"""Tests for structured output formatter."""

import pytest
from pathlib import Path
import tempfile
import json

from yavs.reporting.structured_output import StructuredOutputFormatter


class TestStructuredOutputFormatter:
    """Test structured output formatting."""

    def test_format_basic_structure(self):
        """Test basic structure of formatted output."""
        formatter = StructuredOutputFormatter()

        findings = [
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "HIGH",
                "file": "requirements.txt",
                "message": "CVE-2021-1234",
                "rule_id": "CVE-2021-1234",
                "package": "requests",
                "version": "2.19.0",
                "fixed_version": "2.20.0"
            }
        ]

        metadata = {
            "project": "test-project",
            "build_cycle": "2025-01-01T00:00:00Z",
            "commit_hash": "abc123",
            "branch": "main"
        }

        output = formatter.format(findings, metadata)

        # Check top-level structure
        assert "project" in output
        assert "build_cycle" in output
        assert "commit_hash" in output
        assert "branch" in output
        assert "compliance" in output
        assert "summary" in output

        # Check metadata
        assert output["project"] == "test-project"
        assert output["commit_hash"] == "abc123"

    def test_format_compliance_category(self):
        """Test compliance category consolidation."""
        formatter = StructuredOutputFormatter()

        findings = [
            {"tool": "trivy", "category": "dependency", "severity": "HIGH", "message": "CVE"},
            {"tool": "trivy", "category": "secret", "severity": "HIGH", "message": "API Key"},
            {"tool": "trivy", "category": "license", "severity": "MEDIUM", "message": "GPL"},
            {"tool": "trivy", "category": "config", "severity": "MEDIUM", "message": "Misconfiguration"},
            {"tool": "checkov", "category": "compliance", "severity": "LOW", "message": "Policy"}
        ]

        metadata = {"project": "test"}
        output = formatter.format(findings, metadata)

        # All should be in compliance category
        assert "compliance" in output
        assert isinstance(output["compliance"], list)

        # Check tool grouping
        trivy_findings = [t for t in output["compliance"] if t["tool"] == "Trivy"]
        checkov_findings = [t for t in output["compliance"] if t["tool"] == "Checkov"]

        assert len(trivy_findings) == 1
        assert len(checkov_findings) == 1

        # Trivy should have 4 violations (dependency, secret, license, config)
        assert len(trivy_findings[0]["violations"]) == 4

    def test_format_sast_category(self):
        """Test SAST category formatting."""
        formatter = StructuredOutputFormatter()

        findings = [
            {
                "tool": "semgrep",
                "category": "sast",
                "severity": "HIGH",
                "file": "app.py",
                "line": 42,
                "message": "SQL injection",
                "rule_id": "python.lang.security.sqli"
            },
            {
                "tool": "bandit",
                "category": "sast",
                "severity": "MEDIUM",
                "file": "app.py",
                "line": 10,
                "message": "Hardcoded password",
                "rule_id": "B105"
            }
        ]

        metadata = {"project": "test"}
        output = formatter.format(findings, metadata)

        # Check SAST category
        assert "sast" in output
        assert isinstance(output["sast"], list)
        assert len(output["sast"]) == 2  # Semgrep and Bandit

        # Check tool grouping
        semgrep_findings = [t for t in output["sast"] if t["tool"] == "Semgrep"]
        bandit_findings = [t for t in output["sast"] if t["tool"] == "Bandit"]

        assert len(semgrep_findings) == 1
        assert len(bandit_findings) == 1
        assert len(semgrep_findings[0]["issues"]) == 1
        assert len(bandit_findings[0]["issues"]) == 1

    def test_format_with_sbom(self):
        """Test formatting with SBOM info."""
        formatter = StructuredOutputFormatter()

        findings = []
        metadata = {"project": "test"}
        sbom_info = {
            "format": "CycloneDX",
            "location": "sbom.json",
            "tool": "trivy",
            "size_bytes": 1024
        }

        output = formatter.format(findings, metadata, sbom_info)

        assert "sbom" in output
        assert output["sbom"]["format"] == "CycloneDX"
        assert output["sbom"]["location"] == "sbom.json"

    def test_format_summary_statistics(self):
        """Test summary statistics generation."""
        formatter = StructuredOutputFormatter()

        findings = [
            {"tool": "trivy", "category": "dependency", "severity": "CRITICAL", "message": "CVE1"},
            {"tool": "trivy", "category": "dependency", "severity": "HIGH", "message": "CVE2"},
            {"tool": "semgrep", "category": "sast", "severity": "MEDIUM", "message": "SAST1"},
            {"tool": "checkov", "category": "compliance", "severity": "LOW", "message": "CHECK1"}
        ]

        metadata = {"project": "test"}
        output = formatter.format(findings, metadata)

        # Check summary
        assert "summary" in output
        assert output["summary"]["total_findings"] == 4
        assert "by_severity" in output["summary"]
        assert "by_category" in output["summary"]

        # Check severity counts
        assert output["summary"]["by_severity"]["CRITICAL"] == 1
        assert output["summary"]["by_severity"]["HIGH"] == 1
        assert output["summary"]["by_severity"]["MEDIUM"] == 1
        assert output["summary"]["by_severity"]["LOW"] == 1

        # Check category counts
        assert output["summary"]["by_category"]["dependency"] == 2
        assert output["summary"]["by_category"]["sast"] == 1
        assert output["summary"]["by_category"]["compliance"] == 1

    def test_write_json_to_file(self):
        """Test writing structured output to JSON file."""
        formatter = StructuredOutputFormatter()

        findings = [{"tool": "test", "category": "sast", "severity": "HIGH", "message": "Test"}]
        metadata = {"project": "test"}
        output = formatter.format(findings, metadata)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)

        try:
            formatter.write_json(output, temp_path)

            # Read back and verify
            with open(temp_path, 'r') as f:
                loaded = json.load(f)

            assert loaded["project"] == "test"
            assert "summary" in loaded
        finally:
            temp_path.unlink()

    def test_format_violation_with_package_info(self):
        """Test violation formatting with package info."""
        formatter = StructuredOutputFormatter()

        findings = [
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "HIGH",
                "file": "requirements.txt",
                "message": "CVE-2021-1234",
                "rule_id": "CVE-2021-1234",
                "package": "requests",
                "version": "2.19.0",
                "fixed_version": "2.20.0"
            }
        ]

        metadata = {"project": "test"}
        output = formatter.format(findings, metadata)

        violation = output["compliance"][0]["violations"][0]

        # Check package-specific fields
        assert violation["package"] == "requests"
        assert violation["version"] == "2.19.0"
        assert violation["fixed_version"] == "2.20.0"
        assert violation["vulnerability_id"] == "CVE-2021-1234"
