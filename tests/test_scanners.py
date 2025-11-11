"""Tests for scanner implementations."""

import pytest
from pathlib import Path
from yavs.scanners import BanditScanner, BinSkimScanner
from yavs.scanners.base import BaseScanner


@pytest.fixture
def sample_project():
    """Path to sample project."""
    return Path(__file__).parent / "fixtures" / "sample_project"


class TestSeverityMapping:
    """Test severity mapping functionality."""

    def test_severity_mapping_set_and_normalize(self):
        """Test setting severity mapping and normalization."""
        # Set custom severity mapping
        mapping = {
            "ERROR": "CRITICAL",
            "WARNING": "HIGH",
            "INFO": "LOW",
            "UNKNOWN": "INFO"
        }
        BaseScanner.set_severity_mapping(mapping)

        # Create a mock scanner to test normalization
        class MockScanner(BaseScanner):
            @property
            def tool_name(self):
                return "test"

            @property
            def category(self):
                return "test"

            def get_command(self):
                return "echo test"

            def parse_output(self, output):
                return []

        scanner = MockScanner(Path("."))

        # Test normalization
        assert scanner.normalize_severity("ERROR") == "CRITICAL"
        assert scanner.normalize_severity("WARNING") == "HIGH"
        assert scanner.normalize_severity("INFO") == "LOW"
        assert scanner.normalize_severity("UNKNOWN") == "INFO"

    def test_severity_mapping_case_insensitive(self):
        """Test severity mapping works with different cases."""
        mapping = {
            "error": "HIGH",
            "warning": "MEDIUM",
        }
        BaseScanner.set_severity_mapping(mapping)

        class MockScanner(BaseScanner):
            @property
            def tool_name(self):
                return "test"

            @property
            def category(self):
                return "test"

            def get_command(self):
                return "echo test"

            def parse_output(self, output):
                return []

        scanner = MockScanner(Path("."))

        # Should work with different cases
        assert scanner.normalize_severity("error") == "HIGH"
        assert scanner.normalize_severity("ERROR") == "HIGH"
        assert scanner.normalize_severity("Error") == "HIGH"

    def test_severity_mapping_default_fallback(self):
        """Test default severity when no mapping exists."""
        # Clear mapping
        BaseScanner.set_severity_mapping(None)

        class MockScanner(BaseScanner):
            @property
            def tool_name(self):
                return "test"

            @property
            def category(self):
                return "test"

            def get_command(self):
                return "echo test"

            def parse_output(self, output):
                return []

        scanner = MockScanner(Path("."))

        # Standard severities should pass through
        assert scanner.normalize_severity("CRITICAL") == "CRITICAL"
        assert scanner.normalize_severity("HIGH") == "HIGH"
        assert scanner.normalize_severity("MEDIUM") == "MEDIUM"
        assert scanner.normalize_severity("LOW") == "LOW"
        assert scanner.normalize_severity("INFO") == "INFO"

        # Unknown severities should default to LOW
        assert scanner.normalize_severity("BOGUS") == "LOW"


class TestBanditScanner:
    """Test Bandit scanner."""

    def test_bandit_tool_name(self):
        """Test Bandit tool name."""
        scanner = BanditScanner(Path("."))
        assert scanner.tool_name == "bandit"

    def test_bandit_category(self):
        """Test Bandit category."""
        scanner = BanditScanner(Path("."))
        assert scanner.category == "sast"

    def test_bandit_command_generation(self):
        """Test Bandit command generation."""
        scanner = BanditScanner(Path("."))
        cmd = scanner.get_command()
        assert "bandit" in cmd
        assert "-r" in cmd  # recursive
        assert "-f json" in cmd  # JSON format
        assert "-q" in cmd  # quiet

    def test_bandit_command_with_flags(self):
        """Test Bandit command with extra flags."""
        scanner = BanditScanner(Path("."), extra_flags="--severity-level high")
        cmd = scanner.get_command()
        assert "--severity-level high" in cmd

    def test_bandit_parse_output(self):
        """Test parsing Bandit JSON output."""
        scanner = BanditScanner(Path("."))

        sample_output = """{
            "results": [
                {
                    "code": "password = 'hardcoded'",
                    "col_offset": 0,
                    "end_col_offset": 25,
                    "filename": "./app.py",
                    "issue_confidence": "HIGH",
                    "issue_cwe": {
                        "id": 259,
                        "link": "https://cwe.mitre.org/data/definitions/259.html"
                    },
                    "issue_severity": "MEDIUM",
                    "issue_text": "Possible hardcoded password",
                    "line_number": 10,
                    "line_range": [10, 10],
                    "more_info": "https://bandit.readthedocs.io/",
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string"
                }
            ],
            "metrics": {}
        }"""

        findings = scanner.parse_output(sample_output)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["tool"] == "bandit"
        assert finding["category"] == "sast"
        assert finding["severity"] == "MEDIUM"
        assert finding["file"] == "app.py"  # Leading ./ removed
        assert finding["line"] == 10
        assert finding["rule_id"] == "B105"
        assert "metadata" in finding
        assert finding["metadata"]["cwe"] == 259


class TestBinSkimScanner:
    """Test BinSkim scanner."""

    def test_binskim_tool_name(self):
        """Test BinSkim tool name."""
        scanner = BinSkimScanner(Path("."))
        assert scanner.tool_name == "binskim"

    def test_binskim_category(self):
        """Test BinSkim category."""
        scanner = BinSkimScanner(Path("."))
        assert scanner.category == "sast"

    def test_binskim_command_generation(self):
        """Test BinSkim command generation."""
        scanner = BinSkimScanner(Path("."))
        cmd = scanner.get_command()
        assert "binskim" in cmd
        assert "analyze" in cmd
        assert "--output binskim-results.sarif" in cmd
        assert "--sarif-output-version 2.1.0" in cmd
        assert "--recurse" in cmd

    def test_binskim_parse_sarif(self):
        """Test parsing BinSkim SARIF output."""
        scanner = BinSkimScanner(Path("."))

        sample_sarif = """{
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BinSkim",
                            "version": "1.0.0"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "BA2002",
                            "level": "error",
                            "message": {
                                "text": "Binary not compiled with stack protection"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "file:///app/binary.exe"
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }"""

        findings = scanner._parse_sarif_data(scanner._parse_json_output(sample_sarif))

        assert len(findings) == 1
        finding = findings[0]
        assert finding["tool"] == "binskim"
        assert finding["category"] == "sast"
        # BinSkim uses severity mapping for SARIF levels
        assert finding["rule_id"] == "BA2002"
        assert finding["message"] == "Binary not compiled with stack protection"
        assert finding["line"] is None  # Binary analysis doesn't have line numbers
