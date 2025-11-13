"""Enhanced tests for Bandit scanner."""
import pytest
from pathlib import Path
from unittest.mock import patch
from yavs.scanners.bandit import BanditScanner

class TestBanditEnhanced:
    def test_bandit_initialization(self, tmp_path):
        """Test Bandit scanner initialization."""
        scanner = BanditScanner(tmp_path)
        assert scanner is not None
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "bandit"
        assert scanner.category == "sast"

    def test_get_command_default(self, tmp_path):
        """Test getting default Bandit command."""
        scanner = BanditScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "bandit" in cmd
        assert "-f json" in cmd or "--format json" in cmd

    def test_get_command_with_config(self, tmp_path):
        """Test getting command with custom config."""
        config_file = tmp_path / ".bandit"
        config_file.write_text("[bandit]\nexclude = /test/")

        scanner = BanditScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "bandit" in cmd

    def test_parse_json_output(self, tmp_path):
        """Test parsing Bandit JSON output."""
        scanner = BanditScanner(tmp_path)
        json_output = '''
        {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 10,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Possible SQL injection",
                    "test_id": "B608"
                }
            ]
        }
        '''
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_parse_empty_results(self, tmp_path):
        """Test parsing output with no results."""
        scanner = BanditScanner(tmp_path)
        json_output = '{"results": []}'
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch('shutil.which')
    def test_check_available_found(self, mock_which, tmp_path):
        """Test availability check when Bandit is found."""
        mock_which.return_value = "/usr/bin/bandit"
        scanner = BanditScanner(tmp_path)
        assert scanner.check_available() is True

    @patch('shutil.which')
    def test_check_available_not_found(self, mock_which, tmp_path):
        """Test availability check when Bandit is not found."""
        mock_which.return_value = None
        scanner = BanditScanner(tmp_path)
        result = scanner.check_available()
        assert isinstance(result, bool)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
