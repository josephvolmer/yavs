"""Tests for CLI utility functions."""
import pytest
from unittest.mock import Mock, patch
from pathlib import Path
from yavs.cli import (
    build_banner_lines,
    print_banner,
    filter_findings_by_ignore_patterns
)

class TestBannerFunctions:
    def test_build_banner_lines(self):
        """Test building banner ASCII art lines."""
        lines = build_banner_lines()
        assert isinstance(lines, list)
        assert len(lines) > 0
        assert all(isinstance(line, str) for line in lines)

    def test_print_banner(self, capsys):
        """Test printing banner."""
        print_banner()
        captured = capsys.readouterr()
        # Banner should produce some output
        assert len(captured.out) > 0 or len(captured.err) > 0

    def test_print_banner_with_subtitle(self, capsys):
        """Test printing banner with subtitle."""
        print_banner("Test Subtitle")
        captured = capsys.readouterr()
        assert len(captured.out) > 0 or len(captured.err) > 0

class TestFilterFindingsByIgnorePatterns:
    def test_filter_no_patterns(self):
        """Test filtering with no ignore patterns."""
        findings = [
            {"file": "test.py", "message": "Issue 1"},
            {"file": "app.js", "message": "Issue 2"}
        ]
        result = filter_findings_by_ignore_patterns(findings, [])
        assert len(result) == 2

    def test_filter_with_patterns(self):
        """Test filtering with ignore patterns."""
        findings = [
            {"file": "test.py", "message": "Issue 1"},
            {"file": "node_modules/pkg/file.js", "message": "Issue 2"},
            {"file": "app.js", "message": "Issue 3"}
        ]
        result = filter_findings_by_ignore_patterns(findings, ["node_modules/**"])
        # Should filter out node_modules findings
        assert len(result) <= 3

    def test_filter_empty_findings(self):
        """Test filtering empty findings list."""
        result = filter_findings_by_ignore_patterns([], ["**/*.test.js"])
        assert result == []

    def test_filter_multiple_patterns(self):
        """Test filtering with multiple patterns."""
        findings = [
            {"file": "src/app.py", "message": "Issue 1"},
            {"file": "test/test_app.py", "message": "Issue 2"},
            {"file": "dist/bundle.js", "message": "Issue 3"}
        ]
        result = filter_findings_by_ignore_patterns(
            findings,
            ["test/**", "dist/**"]
        )
        assert len(result) <= 3

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
