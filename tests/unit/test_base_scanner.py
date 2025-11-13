"""Tests for base scanner class."""
import pytest
from pathlib import Path
from yavs.scanners.base import BaseScanner

class TestBaseScanner:
    def test_base_scanner_abstract(self):
        """Test BaseScanner is abstract."""
        # Cannot instantiate directly
        with pytest.raises(TypeError):
            BaseScanner(Path("."))
            
    def test_normalize_severity(self, tmp_path):
        """Test severity normalization."""
        class TestScanner(BaseScanner):
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
        
        scanner = TestScanner(tmp_path)
        assert scanner.normalize_severity("HIGH") == "HIGH"
        assert scanner.normalize_severity("MEDIUM") == "MEDIUM"
        assert scanner.normalize_severity("LOW") == "LOW"
        
    def test_scanner_has_required_methods(self, tmp_path):
        """Test scanner has required methods."""
        class TestScanner(BaseScanner):
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
        
        scanner = TestScanner(tmp_path)
        assert hasattr(scanner, 'tool_name')
        assert hasattr(scanner, 'category')
        assert hasattr(scanner, 'get_command')
        assert hasattr(scanner, 'parse_output')
        assert hasattr(scanner, 'run')
        assert hasattr(scanner, 'check_available')

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
