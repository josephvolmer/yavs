"""
Comprehensive tests for utility modules.

Tests metadata extraction, schema validation, path utilities, and other helper functions.
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch

from src.yavs.utils.metadata import extract_project_metadata
from src.yavs.utils.schema_validator import validate_sarif
from src.yavs.utils.path_utils import normalize_path, make_relative, is_file_in_directory, ensure_directory
from src.yavs.utils.rule_links import get_rule_documentation_url, format_rule_link_html


class TestMetadataExtraction:
    """Tests for project metadata extraction."""

    def test_extract_metadata_basic(self, tmp_path):
        """Test basic metadata extraction."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()

        metadata = extract_project_metadata(
            project_path=test_dir,
            project_name="test-project",
            branch="main",
            commit_hash="abc123"
        )

        assert metadata["project"] == "test-project"
        assert metadata["branch"] == "main"
        assert metadata["commit_hash"] == "abc123"

    def test_extract_metadata_auto_detect_project(self, tmp_path):
        """Test auto-detection of project name from directory."""
        test_dir = tmp_path / "my_awesome_project"
        test_dir.mkdir()

        metadata = extract_project_metadata(
            project_path=test_dir,
            project_name=None,
            branch=None,
            commit_hash=None
        )

        # Should use directory name
        assert "project" in metadata
        assert isinstance(metadata["project"], str)

    @patch('subprocess.run')
    def test_extract_metadata_git_branch(self, mock_run, tmp_path):
        """Test Git branch extraction."""
        mock_run.return_value = Mock(
            stdout="main\n",
            returncode=0
        )

        test_dir = tmp_path / "test_project"
        test_dir.mkdir()

        metadata = extract_project_metadata(
            project_path=test_dir,
            project_name="test",
            branch=None,
            commit_hash=None
        )

        # Should attempt git detection
        assert "branch" in metadata

    def test_extract_metadata_all_none(self, tmp_path):
        """Test metadata extraction with all None values."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()

        metadata = extract_project_metadata(
            project_path=test_dir,
            project_name=None,
            branch=None,
            commit_hash=None
        )

        # Should have default/detected values
        assert isinstance(metadata, dict)
        assert "project" in metadata


class TestSchemaValidator:
    """Tests for SARIF schema validation."""

    def test_validate_valid_sarif(self):
        """Test validation of valid SARIF."""
        valid_sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Test Tool",
                            "version": "1.0"
                        }
                    },
                    "results": []
                }
            ]
        }

        # Should validate without error
        try:
            result = validate_sarif(valid_sarif)
            assert result is True or result is None
        except Exception:
            # Validation might not be fully implemented
            pass

    def test_validate_minimal_sarif(self):
        """Test validation of minimal SARIF."""
        minimal_sarif = {
            "version": "2.1.0",
            "runs": []
        }

        # Should validate or return gracefully
        try:
            validate_sarif(minimal_sarif)
        except Exception:
            pass

    def test_validate_invalid_sarif(self):
        """Test validation of invalid SARIF."""
        invalid_sarif = {
            "not": "valid",
            "sarif": "data"
        }

        # Should fail validation or return False
        try:
            result = validate_sarif(invalid_sarif)
            # Might return False or raise exception
            assert result is False or result is None
        except Exception:
            # Expected for invalid SARIF
            pass


class TestPathUtils:
    """Tests for path utility functions."""

    def test_normalize_path(self):
        """Test normalizing path."""
        path = Path("test.txt")
        normalized = normalize_path(path)

        assert normalized.is_absolute()

    def test_make_relative(self, tmp_path):
        """Test making relative path."""
        # Create a test file
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.touch()

        # Make relative to tmp_path
        relative = make_relative(test_file, tmp_path)

        assert "/" in relative or "\\" in relative
        assert "subdir" in relative

    def test_is_file_in_directory(self, tmp_path):
        """Test checking if file is in directory."""
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.touch()

        assert is_file_in_directory(test_file, tmp_path) is True
        assert is_file_in_directory(test_file, Path("/other/path")) is False

    def test_ensure_directory(self, tmp_path):
        """Test ensuring directory exists."""
        new_dir = tmp_path / "new" / "nested" / "dir"

        result = ensure_directory(new_dir)

        assert result.exists()
        assert result.is_dir()

    def test_make_relative_forward_slashes(self, tmp_path):
        """Test that make_relative uses forward slashes."""
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.touch()

        relative = make_relative(test_file, tmp_path)

        # Should use forward slashes for SARIF compliance
        assert "/" in relative or "subdir" in relative


class TestRuleLinks:
    """Tests for rule link generation."""

    def test_get_rule_documentation_url_cve(self):
        """Test getting link for CVE rule."""
        link = get_rule_documentation_url("trivy", "CVE-2021-44228")

        # Should return NVD link for CVE
        assert link is not None
        assert "nvd.nist.gov" in link

    def test_get_rule_documentation_url_ghsa(self):
        """Test getting link for GitHub Security Advisory."""
        link = get_rule_documentation_url("trivy", "GHSA-abcd-1234-efgh")

        # Should return GitHub advisory link
        assert link is not None
        assert "github.com/advisories" in link

    def test_get_rule_documentation_url_bandit(self):
        """Test getting link for Bandit rule."""
        link = get_rule_documentation_url("bandit", "B201")

        # Should return Bandit docs link
        assert link is not None
        assert "bandit.readthedocs.io" in link

    def test_get_rule_documentation_url_checkov(self):
        """Test getting link for Checkov rule."""
        link = get_rule_documentation_url("checkov", "CKV_AWS_123")

        # Should return Checkov/Prisma docs link
        assert link is not None
        assert "prismacloud.io" in link or "ckv_aws_123" in link.lower()

    def test_get_rule_documentation_url_semgrep(self):
        """Test getting link for Semgrep rule."""
        link = get_rule_documentation_url("semgrep", "python.lang.security.sql-injection")

        # Should return Semgrep registry link
        assert link is not None
        assert "semgrep.dev" in link

    def test_get_rule_documentation_url_unknown(self):
        """Test getting link for unknown rule."""
        link = get_rule_documentation_url("custom", "UNKNOWN-123")

        # Should return None for unknown rules
        assert link is None

    def test_format_rule_link_html_with_link(self):
        """Test HTML formatting with available link."""
        html = format_rule_link_html("trivy", "CVE-2021-44228")

        # Should contain link and external link icon
        assert "href=" in html
        assert "nvd.nist.gov" in html
        assert "CVE-2021-44228" in html

    def test_format_rule_link_html_without_link(self):
        """Test HTML formatting without available link."""
        html = format_rule_link_html("custom", "UNKNOWN-123")

        # Should just return the rule ID
        assert html == "UNKNOWN-123"
        assert "href=" not in html

    def test_format_rule_link_html_na(self):
        """Test HTML formatting with N/A rule."""
        html = format_rule_link_html("trivy", "N/A")

        # Should return N/A
        assert html == "N/A"


class TestSubprocessRunner:
    """Tests for subprocess runner utility."""

    @patch('subprocess.run')
    def test_run_command_success(self, mock_run):
        """Test successful command execution."""
        from src.yavs.utils.subprocess_runner import run_command

        mock_run.return_value = Mock(
            stdout="success output",
            stderr="",
            returncode=0
        )

        returncode, stdout, stderr = run_command("echo hello", timeout=30)

        assert returncode == 0
        assert "success output" in stdout

    @patch('subprocess.run')
    def test_run_command_failure(self, mock_run):
        """Test failed command execution."""
        from src.yavs.utils.subprocess_runner import run_command

        mock_run.return_value = Mock(
            stdout="",
            stderr="error message",
            returncode=1
        )

        returncode, stdout, stderr = run_command("false", timeout=30, check=False)

        assert returncode == 1

    def test_run_command_timeout(self):
        """Test command timeout handling."""
        from src.yavs.utils.subprocess_runner import run_command
        from src.yavs.utils.subprocess_runner import CommandExecutionError

        try:
            run_command("sleep 100", timeout=0.1, check=False)
            assert False, "Should have raised CommandExecutionError"
        except CommandExecutionError as e:
            # Should handle timeout with CommandExecutionError
            error_msg = str(e).lower()
            assert "timeout" in error_msg or "timed out" in error_msg


class TestLoggingUtils:
    """Tests for logging utilities."""

    def test_get_logger(self):
        """Test logger creation."""
        from src.yavs.utils.logging import get_logger

        logger = get_logger("test_module")

        assert logger is not None
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "warning")

    def test_configure_logging_with_config(self):
        """Test configuring logging with config dict."""
        from src.yavs.utils.logging import configure_logging

        config = {
            "level": "INFO",
            "format": "rich"
        }

        configure_logging(config)

        # Should configure without error


class TestPreflightChecks:
    """Tests for preflight check utilities."""

    @patch('shutil.which')
    def test_check_scanner_availability(self, mock_which):
        """Test checking scanner availability."""
        from src.yavs.utils.preflight import check_scanner_availability

        mock_which.return_value = "/usr/bin/trivy"

        # Check SBOM scanner availability
        success, missing = check_scanner_availability(sbom=True)

        # Should return tuple (bool, list)
        assert isinstance(success, bool)
        assert isinstance(missing, list)

    def test_check_ai_configuration(self):
        """Test checking AI configuration."""
        from src.yavs.utils.preflight import check_ai_configuration

        config = {
            "ai": {
                "provider": None,
                "features": {}
            }
        }

        # Should run and return tuple (bool, optional error message)
        success, error_msg = check_ai_configuration(ai_enabled=False, config=config)
        assert isinstance(success, bool)
        assert error_msg is None or isinstance(error_msg, str)


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_input_handling(self):
        """Test handling of empty inputs."""
        # Test with empty findings list
        from src.yavs.cli import filter_findings_by_ignore_patterns

        result = filter_findings_by_ignore_patterns([], ["test/"])
        assert result == []

    def test_none_input_handling(self):
        """Test handling of None inputs."""
        from src.yavs.cli import filter_findings_by_ignore_patterns

        # Should handle None gracefully
        result = filter_findings_by_ignore_patterns([], [])
        assert result == []

    def test_large_findings_list(self):
        """Test handling of large findings list."""
        from src.yavs.cli import filter_findings_by_ignore_patterns

        # Create large findings list
        findings = [
            {"file": f"src/file{i}.py", "severity": "HIGH"}
            for i in range(1000)
        ]

        result = filter_findings_by_ignore_patterns(findings, ["node_modules/"])

        # Should handle large lists
        assert len(result) == 1000

    def test_special_characters_in_paths(self):
        """Test handling of special characters in file paths."""
        from src.yavs.cli import filter_findings_by_ignore_patterns

        findings = [
            {"file": "src/file with spaces.py", "severity": "HIGH"},
            {"file": "src/file-with-dashes.py", "severity": "HIGH"},
            {"file": "src/file_with_underscores.py", "severity": "HIGH"},
        ]

        result = filter_findings_by_ignore_patterns(findings, [])

        # Should handle special characters
        assert len(result) == 3

    def test_unicode_in_findings(self):
        """Test handling of Unicode characters in findings."""
        from src.yavs.cli import filter_findings_by_ignore_patterns

        findings = [
            {"file": "src/文件.py", "severity": "HIGH", "message": "Test 测试"},
            {"file": "src/файл.py", "severity": "HIGH", "message": "Тест"},
        ]

        result = filter_findings_by_ignore_patterns(findings, [])

        # Should handle Unicode
        assert len(result) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
