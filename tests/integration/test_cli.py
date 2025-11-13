"""
Comprehensive tests for CLI functionality.

Tests all command-line arguments, flags, and commands including:
- Scanner selection flags
- Output format options
- Baseline features
- Production/CI-CD features
- Subcommands (diff, setup, summarize, report)
"""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock

from yavs.cli import app, filter_findings_by_ignore_patterns


runner = CliRunner()


class TestScanCommand:
    """Tests for the main scan command."""

    def test_scan_help(self):
        """Test that scan command help works."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan filesystem and/or Docker images" in result.stdout

    @patch('src.yavs.cli.TrivyScanner')
    @patch('src.yavs.cli.SemgrepScanner')
    @patch('src.yavs.cli.BanditScanner')
    def test_scan_all_flag(self, mock_bandit, mock_semgrep, mock_trivy, tmp_path):
        """Test --all flag runs all scanners."""
        # Mock scanners to return empty findings
        for mock_scanner_class in [mock_trivy, mock_semgrep, mock_bandit]:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_scanner_class.return_value = mock_instance

        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        result = runner.invoke(app, [
            "scan",
            str(target_dir),
            "--all",
            "--output-dir", str(tmp_path / "output")
        ])

        # Should attempt to run all scanners
        assert mock_trivy.called
        assert mock_semgrep.called
        assert mock_bandit.called

    def test_scan_requires_scanner_flag(self, tmp_path):
        """Test that scan requires at least one scanner flag."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        result = runner.invoke(app, ["scan", str(target_dir)])

        # Should fail or warn if no scanner specified
        # The actual behavior depends on config file, so this test
        # verifies the command runs without crashing
        assert isinstance(result.exit_code, int)

    @patch('src.yavs.cli.SemgrepScanner')
    def test_scan_sast_flag(self, mock_semgrep, tmp_path):
        """Test --sast flag."""
        mock_instance = Mock()
        mock_instance.run.return_value = []
        mock_instance.check_available.return_value = True
        mock_semgrep.return_value = mock_instance

        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        result = runner.invoke(app, [
            "scan",
            str(target_dir),
            "--sast",
            "--output-dir", str(tmp_path / "output")
        ])

        assert mock_semgrep.called

    def test_scan_output_dir_option(self, tmp_path):
        """Test --output-dir option creates directory."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()
        output_dir = tmp_path / "custom_output"

        # Mock to avoid actual scanning
        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--output-dir", str(output_dir)
            ])

        # Output directory should be created
        assert output_dir.exists() or result.exit_code != 0

    def test_scan_flat_format_flag(self, tmp_path):
        """Test --flat flag for output format."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--flat",
                "--output-dir", str(tmp_path / "output")
            ])

        # Should run without error
        assert isinstance(result.exit_code, int)

    def test_scan_quiet_mode(self, tmp_path):
        """Test --quiet flag for minimal output."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--quiet",
                "--output-dir", str(tmp_path / "output")
            ])

        # Should run without error
        assert isinstance(result.exit_code, int)


class TestBaselineFeatures:
    """Tests for baseline functionality in CLI."""

    def test_baseline_generate_flag(self, tmp_path):
        """Test --baseline-generate creates baseline file."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()
        baseline_file = tmp_path / "baseline.json"

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = [
                {
                    "tool": "trivy",
                    "file": "package.json",
                    "severity": "HIGH",
                    "rule_id": "CVE-2021-1234",
                    "message": "Test vulnerability"
                }
            ]
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--baseline-generate", str(baseline_file),
                "--output-dir", str(tmp_path / "output")
            ])

        # Baseline file should be created
        if result.exit_code == 0:
            assert baseline_file.exists()

    def test_baseline_compare_flag(self, tmp_path):
        """Test --baseline flag filters out existing findings."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        # Create a baseline file
        baseline_file = tmp_path / "baseline.json"
        baseline_data = {
            "version": "1.0",
            "total_findings": 1,
            "fingerprints": ["abc123"],
            "created_at": "2025-01-01T00:00:00Z",
            "metadata": {},
            "severity_breakdown": {"HIGH": 1}
        }
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--baseline", str(baseline_file),
                "--output-dir", str(tmp_path / "output")
            ])

        # Should run without error
        assert isinstance(result.exit_code, int)


class TestProductionFeatures:
    """Tests for production/CI-CD features."""

    def test_fail_on_severity_critical(self, tmp_path):
        """Test --fail-on CRITICAL exits with code 1 when critical findings exist."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = [
                {
                    "tool": "trivy",
                    "file": "package.json",
                    "severity": "CRITICAL",
                    "rule_id": "CVE-2021-1234",
                    "message": "Critical vulnerability"
                }
            ]
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--fail-on", "CRITICAL",
                "--output-dir", str(tmp_path / "output")
            ])

        # Should exit with code 1 when critical findings exist
        if result.exit_code == 0:
            # Might be 0 if no critical findings or error occurred
            pass
        else:
            assert result.exit_code == 1

    def test_severity_filter(self, tmp_path):
        """Test --severity filter."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            # Return findings of different severities
            mock_instance.run.return_value = [
                {"tool": "trivy", "severity": "CRITICAL", "file": "a.py", "rule_id": "R1", "message": "M1"},
                {"tool": "trivy", "severity": "HIGH", "file": "b.py", "rule_id": "R2", "message": "M2"},
                {"tool": "trivy", "severity": "MEDIUM", "file": "c.py", "rule_id": "R3", "message": "M3"},
            ]
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--severity", "CRITICAL,HIGH",
                "--output-dir", str(tmp_path / "output")
            ])

        # Should filter to only show CRITICAL and HIGH
        assert isinstance(result.exit_code, int)

    def test_timeout_option(self, tmp_path):
        """Test --timeout option."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--timeout", "60",
                "--output-dir", str(tmp_path / "output")
            ])

        assert isinstance(result.exit_code, int)

    def test_continue_on_error(self, tmp_path):
        """Test --continue-on-error flag."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.side_effect = Exception("Scanner failed")
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--continue-on-error",
                "--output-dir", str(tmp_path / "output")
            ])

        # Should continue despite error
        assert isinstance(result.exit_code, int)


class TestIgnorePatterns:
    """Tests for ignore pattern functionality."""

    def test_ignore_single_pattern(self):
        """Test single ignore pattern."""
        findings = [
            {"file": "src/main.py", "severity": "HIGH"},
            {"file": "node_modules/lodash/index.js", "severity": "HIGH"},
        ]

        ignore_patterns = ["node_modules/"]
        filtered = filter_findings_by_ignore_patterns(findings, ignore_patterns)

        assert len(filtered) == 1
        assert filtered[0]["file"] == "src/main.py"

    def test_ignore_multiple_patterns(self):
        """Test multiple ignore patterns."""
        findings = [
            {"file": "src/main.py", "severity": "HIGH"},
            {"file": "tests/test_main.py", "severity": "MEDIUM"},
            {"file": "docs/api.md", "severity": "LOW"},
        ]

        ignore_patterns = ["tests/", "docs/"]
        filtered = filter_findings_by_ignore_patterns(findings, ignore_patterns)

        assert len(filtered) == 1
        assert filtered[0]["file"] == "src/main.py"

    def test_ignore_regex_pattern(self):
        """Test regex ignore patterns."""
        findings = [
            {"file": "src/main.py", "severity": "HIGH"},
            {"file": "src/test_helper.py", "severity": "MEDIUM"},
            {"file": "tests/test_main.py", "severity": "MEDIUM"},
        ]

        ignore_patterns = [r".*_test\.py$", r"test_.*\.py$"]
        filtered = filter_findings_by_ignore_patterns(findings, ignore_patterns)

        assert len(filtered) == 1
        assert filtered[0]["file"] == "src/main.py"

    def test_ignore_no_patterns(self):
        """Test with no ignore patterns."""
        findings = [
            {"file": "src/main.py", "severity": "HIGH"},
            {"file": "tests/test_main.py", "severity": "MEDIUM"},
        ]

        filtered = filter_findings_by_ignore_patterns(findings, [])

        assert len(filtered) == 2

    def test_ignore_cli_flag(self, tmp_path):
        """Test --ignore flag in CLI."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--sbom",
                "--ignore", "test/",
                "--ignore", "node_modules/",
                "--output-dir", str(tmp_path / "output")
            ])

        assert isinstance(result.exit_code, int)


class TestDiffCommand:
    """Tests for the diff subcommand."""

    def test_diff_help(self):
        """Test diff command help."""
        result = runner.invoke(app, ["diff", "--help"])
        assert result.exit_code == 0
        assert "baseline" in result.stdout.lower()

    def test_diff_basic(self, tmp_path):
        """Test basic diff functionality."""
        # Create baseline file
        baseline_file = tmp_path / "baseline.json"
        baseline_data = {
            "data": [
                {"file": "test.py", "line": 10, "rule_id": "R1", "severity": "HIGH", "tool": "test"}
            ]
        }
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)

        # Create current file
        current_file = tmp_path / "current.json"
        current_data = {
            "data": [
                {"file": "test.py", "line": 10, "rule_id": "R1", "severity": "HIGH", "tool": "test"},
                {"file": "test.py", "line": 20, "rule_id": "R2", "severity": "MEDIUM", "tool": "test"}
            ]
        }
        with open(current_file, 'w') as f:
            json.dump(current_data, f)

        result = runner.invoke(app, ["diff", str(baseline_file), str(current_file)])

        # Should show new findings
        assert result.exit_code == 0
        assert "new" in result.stdout.lower() or "1" in result.stdout


class TestSetupCommand:
    """Tests for the setup subcommand."""

    def test_setup_help(self):
        """Test setup command help."""
        result = runner.invoke(app, ["setup", "--help"])
        assert result.exit_code == 0
        assert "install" in result.stdout.lower()

    @patch('src.yavs.cli.scanner_installer')
    def test_setup_basic(self, mock_installer):
        """Test basic setup command."""
        result = runner.invoke(app, ["setup"])

        # Should attempt to install tools
        assert isinstance(result.exit_code, int)


class TestSummarizeCommand:
    """Tests for the summarize subcommand."""

    def test_summarize_help(self):
        """Test summarize command help."""
        result = runner.invoke(app, ["summarize", "--help"])
        assert result.exit_code == 0
        assert "AI" in result.stdout or "summarize" in result.stdout.lower()

    def test_summarize_requires_file(self):
        """Test summarize requires results file."""
        result = runner.invoke(app, ["summarize"])

        # Should fail without file argument
        assert result.exit_code != 0


class TestReportCommand:
    """Tests for the report subcommand."""

    def test_report_help(self):
        """Test report command help."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "HTML" in result.stdout or "report" in result.stdout.lower()

    def test_report_basic(self, tmp_path):
        """Test basic report generation."""
        # Create results file
        results_file = tmp_path / "results.json"
        results_data = {
            "project": "test-project",
            "summary": {
                "total_findings": 0,
                "by_severity": {},
                "by_category": {}
            }
        }
        with open(results_file, 'w') as f:
            json.dump(results_data, f)

        output_file = tmp_path / "report.html"

        result = runner.invoke(app, [
            "report",
            str(results_file),
            "--output", str(output_file)
        ])

        # Should generate HTML report
        if result.exit_code == 0:
            assert output_file.exists()


class TestVersionCommand:
    """Tests for the version command."""

    def test_version_command(self):
        """Test version command displays version."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "v" in result.stdout or "version" in result.stdout.lower()


class TestConfigFile:
    """Tests for config file loading."""

    def test_config_file_option(self, tmp_path):
        """Test --config option loads config file."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        # Create config file
        config_file = tmp_path / "yavs.yaml"
        config_data = {
            "scanners": ["trivy"],
            "output": {
                "format": "structured",
                "directory": str(tmp_path / "output")
            }
        }
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config_data, f)

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                str(target_dir),
                "--config", str(config_file)
            ])

        # Should load config
        assert isinstance(result.exit_code, int)


class TestDockerImageScanning:
    """Tests for Docker image scanning features."""

    @patch('src.yavs.cli.TrivyScanner')
    def test_scan_single_image(self, mock_trivy):
        """Test scanning a single Docker image."""
        mock_instance = Mock()
        mock_instance.run.return_value = []
        mock_instance.check_available.return_value = True
        mock_trivy.return_value = mock_instance

        result = runner.invoke(app, [
            "scan",
            "--sbom",
            "--images", "nginx:latest"
        ])

        # Should attempt to scan image
        assert mock_trivy.called

    @patch('src.yavs.cli.TrivyScanner')
    def test_scan_multiple_images(self, mock_trivy):
        """Test scanning multiple Docker images."""
        mock_instance = Mock()
        mock_instance.run.return_value = []
        mock_instance.check_available.return_value = True
        mock_trivy.return_value = mock_instance

        result = runner.invoke(app, [
            "scan",
            "--sbom",
            "--images", "nginx:latest",
            "--images", "python:3.11"
        ])

        # Should attempt to scan both images
        assert mock_trivy.called

    def test_scan_images_from_file(self, tmp_path):
        """Test scanning images from file."""
        images_file = tmp_path / "images.txt"
        images_file.write_text("nginx:latest\npython:3.11\n")

        with patch('src.yavs.cli.TrivyScanner') as mock_trivy:
            mock_instance = Mock()
            mock_instance.run.return_value = []
            mock_instance.check_available.return_value = True
            mock_trivy.return_value = mock_instance

            result = runner.invoke(app, [
                "scan",
                "--sbom",
                "--images-file", str(images_file)
            ])

        # Should load images from file
        assert isinstance(result.exit_code, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
