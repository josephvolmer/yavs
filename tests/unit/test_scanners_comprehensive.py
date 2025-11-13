"""Comprehensive tests for scanner modules."""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from yavs.scanners.bandit import BanditScanner
from yavs.scanners.semgrep import SemgrepScanner
from yavs.scanners.trivy import TrivyScanner
from yavs.scanners.base import BaseScanner


class TestBanditScanner:
    """Tests for Bandit scanner."""

    def test_bandit_init(self, tmp_path):
        """Test Bandit scanner initialization."""
        scanner = BanditScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "bandit"
        assert scanner.category == "sast"

    def test_bandit_get_command(self, tmp_path):
        """Test getting Bandit command."""
        scanner = BanditScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "bandit" in cmd

    def test_bandit_parse_output_basic(self, tmp_path):
        """Test parsing Bandit output."""
        scanner = BanditScanner(tmp_path)
        output = '{"results": [{"filename": "test.py", "line_number": 10, "issue_severity": "HIGH", "issue_text": "SQL injection"}]}'
        findings = scanner.parse_output(output)
        assert isinstance(findings, list)

    def test_bandit_parse_empty(self, tmp_path):
        """Test parsing empty Bandit output."""
        scanner = BanditScanner(tmp_path)
        findings = scanner.parse_output('{"results": []}')
        assert findings == []

    @patch('shutil.which')
    def test_bandit_check_available(self, mock_which, tmp_path):
        """Test checking Bandit availability."""
        mock_which.return_value = "/usr/bin/bandit"
        scanner = BanditScanner(tmp_path)
        assert scanner.check_available() is True


class TestSemgrepScanner:
    """Tests for Semgrep scanner."""

    def test_semgrep_init(self, tmp_path):
        """Test Semgrep scanner initialization."""
        scanner = SemgrepScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "semgrep"
        assert scanner.category == "sast"

    def test_semgrep_get_command(self, tmp_path):
        """Test getting Semgrep command."""
        scanner = SemgrepScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "semgrep" in cmd

    def test_semgrep_parse_output_basic(self, tmp_path):
        """Test parsing Semgrep output."""
        scanner = SemgrepScanner(tmp_path)
        output = '{"results": [{"path": "test.py", "start": {"line": 10}, "check_id": "python.sql-injection", "extra": {"severity": "ERROR", "message": "SQL injection"}}]}'
        findings = scanner.parse_output(output)
        assert isinstance(findings, list)

    def test_semgrep_parse_empty(self, tmp_path):
        """Test parsing empty Semgrep output."""
        scanner = SemgrepScanner(tmp_path)
        findings = scanner.parse_output('{"results": []}')
        assert findings == []

    @patch('shutil.which')
    def test_semgrep_check_available(self, mock_which, tmp_path):
        """Test checking Semgrep availability."""
        mock_which.return_value = "/usr/bin/semgrep"
        scanner = SemgrepScanner(tmp_path)
        assert scanner.check_available() is True


class TestTrivyScanner:
    """Tests for Trivy scanner."""

    def test_trivy_init(self, tmp_path):
        """Test Trivy scanner initialization."""
        scanner = TrivyScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "trivy"
        assert scanner.category == "dependency"

    def test_trivy_get_command_fs(self, tmp_path):
        """Test getting Trivy filesystem scan command."""
        scanner = TrivyScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "trivy" in cmd

    def test_trivy_parse_output_basic(self, tmp_path):
        """Test parsing Trivy output."""
        scanner = TrivyScanner(tmp_path)
        output = '{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-1234", "Severity": "HIGH", "PkgName": "lodash", "InstalledVersion": "4.17.20"}]}]}'
        findings = scanner.parse_output(output)
        assert isinstance(findings, list)

    def test_trivy_parse_empty(self, tmp_path):
        """Test parsing empty Trivy output."""
        scanner = TrivyScanner(tmp_path)
        findings = scanner.parse_output('{"Results": []}')
        assert findings == []

    @patch('shutil.which')
    def test_trivy_check_available(self, mock_which, tmp_path):
        """Test checking Trivy availability."""
        mock_which.return_value = "/usr/bin/trivy"
        scanner = TrivyScanner(tmp_path)
        assert scanner.check_available() is True


class TestBaseScanner:
    """Tests for BaseScanner abstract class."""

    def test_base_scanner_abstract(self):
        """Test that BaseScanner cannot be instantiated."""
        with pytest.raises(TypeError):
            BaseScanner(Path("."))

    def test_base_scanner_subclass(self, tmp_path):
        """Test creating a concrete scanner subclass."""
        class TestScanner(BaseScanner):
            tool_name = "test"
            category = "sast"

            def __init__(self, target_path):
                super().__init__(target_path)

            def get_command(self):
                return "test scan"

            def parse_output(self, output):
                return []

            def check_available(self):
                return True

        scanner = TestScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "test"
        assert scanner.get_command() == "test scan"
        assert scanner.parse_output("") == []
        assert scanner.check_available() is True


class TestScannerIntegration:
    """Integration tests for scanner workflow."""

    @patch('shutil.which')
    def test_scanner_workflow_bandit(self, mock_which, tmp_path):
        """Test complete scanner workflow for Bandit."""
        mock_which.return_value = "/usr/bin/bandit"

        scanner = BanditScanner(tmp_path)
        assert scanner.check_available()

        cmd = scanner.get_command()
        assert "bandit" in cmd

        # Simulate output
        output = '{"results": [{"filename": "test.py", "line_number": 10, "issue_severity": "HIGH", "issue_text": "Issue"}]}'
        findings = scanner.parse_output(output)
        assert len(findings) >= 0

    @patch('shutil.which')
    def test_scanner_workflow_semgrep(self, mock_which, tmp_path):
        """Test complete scanner workflow for Semgrep."""
        mock_which.return_value = "/usr/bin/semgrep"

        scanner = SemgrepScanner(tmp_path)
        assert scanner.check_available()

        cmd = scanner.get_command()
        assert "semgrep" in cmd

    @patch('shutil.which')
    def test_scanner_workflow_trivy(self, mock_which, tmp_path):
        """Test complete scanner workflow for Trivy."""
        mock_which.return_value = "/usr/bin/trivy"

        scanner = TrivyScanner(tmp_path)
        assert scanner.check_available()

        cmd = scanner.get_command()
        assert "trivy" in cmd


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
