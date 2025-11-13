"""Tests for Semgrep scanner."""
import pytest
from pathlib import Path
from yavs.scanners.semgrep import SemgrepScanner

class TestSemgrepScanner:
    def test_scanner_initialization(self, tmp_path):
        """Test scanner initialization."""
        scanner = SemgrepScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "semgrep"
        
    def test_get_command(self, tmp_path):
        """Test command generation."""
        scanner = SemgrepScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "semgrep" in cmd.lower()
        
    def test_check_available(self, tmp_path):
        """Test availability check."""
        scanner = SemgrepScanner(tmp_path)
        result = scanner.check_available()
        assert isinstance(result, bool)
