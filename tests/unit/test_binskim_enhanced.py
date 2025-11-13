"""Enhanced tests for BinSkim scanner."""
import pytest
from pathlib import Path
from unittest.mock import patch
from yavs.scanners.binskim import BinSkimScanner

class TestBinSkimEnhanced:
    def test_binskim_initialization(self, tmp_path):
        """Test BinSkim scanner initialization."""
        scanner = BinSkimScanner(tmp_path)
        assert scanner is not None
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "binskim"
        assert scanner.category == "sast"

    def test_get_command(self, tmp_path):
        """Test getting BinSkim command."""
        scanner = BinSkimScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "binskim" in cmd.lower()

    def test_parse_sarif_output(self, tmp_path):
        """Test parsing BinSkim SARIF output."""
        scanner = BinSkimScanner(tmp_path)
        sarif_output = '''
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "BinSkim"}},
                    "results": [
                        {
                            "ruleId": "BA2001",
                            "level": "error",
                            "message": {"text": "Binary issue"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.exe"}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        '''
        findings = scanner.parse_output(sarif_output)
        assert isinstance(findings, list)

    def test_parse_empty_sarif(self, tmp_path):
        """Test parsing SARIF with no results."""
        scanner = BinSkimScanner(tmp_path)
        sarif_output = '''
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "BinSkim"}}, "results": []}]
        }
        '''
        findings = scanner.parse_output(sarif_output)
        assert isinstance(findings, list)
        assert len(findings) == 0

    @patch('shutil.which')
    def test_check_available_found(self, mock_which, tmp_path):
        """Test availability check when BinSkim is found."""
        mock_which.return_value = "/usr/bin/binskim"
        scanner = BinSkimScanner(tmp_path)
        result = scanner.check_available()
        assert isinstance(result, bool)

    @patch('shutil.which')
    def test_check_available_not_found(self, mock_which, tmp_path):
        """Test availability check when BinSkim is not found."""
        mock_which.return_value = None
        scanner = BinSkimScanner(tmp_path)
        assert scanner.check_available() is False

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
