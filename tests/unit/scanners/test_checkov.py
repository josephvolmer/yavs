"""Tests for Checkov scanner."""
import pytest
from pathlib import Path
from yavs.scanners.checkov import CheckovScanner

class TestCheckovScanner:
    def test_scanner_initialization(self, tmp_path):
        """Test scanner initialization."""
        scanner = CheckovScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "checkov"
        
    def test_get_command(self, tmp_path):
        """Test command generation."""
        scanner = CheckovScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "checkov" in cmd.lower()
        
    def test_check_available(self, tmp_path):
        """Test availability check."""
        scanner = CheckovScanner(tmp_path)
        result = scanner.check_available()
        assert isinstance(result, bool)
