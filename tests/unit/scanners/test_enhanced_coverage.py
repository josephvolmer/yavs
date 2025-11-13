"""Enhanced scanner tests for coverage."""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from yavs.scanners.trivy import TrivyScanner
from yavs.scanners.semgrep import SemgrepScanner
from yavs.scanners.checkov import CheckovScanner
from yavs.scanners.terrascan import TerrascanScanner
from yavs.scanners.template_analyzer import TemplateAnalyzerScanner

class TestTrivyEnhanced:
    def test_parse_json_output(self, tmp_path):
        """Test parsing Trivy JSON output."""
        scanner = TrivyScanner(tmp_path)
        json_output = '{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-1234", "Severity": "HIGH", "PkgName": "test", "InstalledVersion": "1.0.0"}]}]}'
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)

    def test_get_command_with_formats(self, tmp_path):
        """Test command generation with different formats."""
        scanner = TrivyScanner(tmp_path)
        cmd = scanner.get_command()
        assert isinstance(cmd, str)
        assert "trivy" in cmd

class TestSemgrepEnhanced:
    def test_parse_json_output(self, tmp_path):
        """Test parsing Semgrep JSON output."""
        scanner = SemgrepScanner(tmp_path)
        json_output = '{"results": [{"check_id": "test-rule", "extra": {"severity": "ERROR", "message": "test"}, "path": "test.py", "start": {"line": 1}}]}'
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)

class TestCheckovEnhanced:
    def test_parse_json_output(self, tmp_path):
        """Test parsing Checkov JSON output."""
        scanner = CheckovScanner(tmp_path)
        json_output = '{"results": {"failed_checks": [{"check_id": "CKV_1", "check_name": "Test", "file_path": "test.tf", "file_line_range": [1, 2]}]}}'
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)

class TestTerrascanEnhanced:
    def test_parse_json_output(self, tmp_path):
        """Test parsing Terrascan JSON output."""
        scanner = TerrascanScanner(tmp_path)
        json_output = '{"results": {"violations": [{"rule_name": "test", "severity": "HIGH", "resource_name": "test", "file": "test.tf", "line": 1}]}}'
        findings = scanner.parse_output(json_output)
        assert isinstance(findings, list)

class TestTemplateAnalyzerEnhanced:
    def test_initialization(self, tmp_path):
        """Test template analyzer initialization."""
        scanner = TemplateAnalyzerScanner(tmp_path)
        assert scanner is not None
        assert scanner.target_path == tmp_path

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
