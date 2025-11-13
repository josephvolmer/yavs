"""Tests for Trivy scanner."""
import pytest
from pathlib import Path
from yavs.scanners.trivy import TrivyScanner

class TestTrivyScanner:
    def test_scanner_initialization(self, tmp_path):
        """Test scanner initialization."""
        scanner = TrivyScanner(tmp_path)
        assert scanner.target_path == tmp_path
        assert scanner.tool_name == "trivy"
        
    def test_get_command(self, tmp_path):
        """Test command generation."""
        scanner = TrivyScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "trivy" in cmd.lower()
        
    def test_check_available(self, tmp_path):
        """Test availability check."""
        scanner = TrivyScanner(tmp_path)
        result = scanner.check_available()
        assert isinstance(result, bool)
