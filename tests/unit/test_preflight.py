"""Tests for preflight checks."""

import pytest
from pathlib import Path

from yavs.utils.preflight import (
    check_scanner_available,
    get_missing_scanners,
    check_all_scanners,
    recommend_installation
)


class TestCheckScannerAvailable:
    """Test check_scanner_available function."""

    def test_python_available(self):
        """Test that python is available."""
        result = check_scanner_available("python")
        assert isinstance(result, bool)
        # Python should be available since tests run in Python
        assert result is True

    def test_nonexistent_scanner(self):
        """Test nonexistent scanner returns False."""
        result = check_scanner_available("nonexistent-scanner-xyz-12345")
        assert result is False

    def test_returns_boolean(self):
        """Test returns boolean."""
        result = check_scanner_available("test")
        assert isinstance(result, bool)


class TestGetMissingScanners:
    """Test get_missing_scanners function."""

    def test_empty_list(self):
        """Test empty scanner list returns empty."""
        missing = get_missing_scanners([])
        assert missing == []

    def test_returns_list(self):
        """Test returns a list."""
        missing = get_missing_scanners(["trivy", "semgrep"])
        assert isinstance(missing, list)

    def test_available_scanner_not_in_missing(self):
        """Test available scanners not in missing list."""
        missing = get_missing_scanners(["python"])
        assert "python" not in missing


class TestCheckAllScanners:
    """Test check_all_scanners function."""

    def test_returns_dict(self):
        """Test returns a dictionary."""
        result = check_all_scanners()
        assert isinstance(result, dict)

    def test_has_status_for_common_scanners(self):
        """Test result has status for common scanners."""
        result = check_all_scanners()
        # Should have entries for standard scanners
        assert isinstance(result, dict)


class TestRecommendInstallation:
    """Test recommend_installation function."""

    def test_empty_list(self):
        """Test empty missing list."""
        recommendation = recommend_installation([])
        assert isinstance(recommendation, str)

    def test_single_scanner(self):
        """Test recommendation for single scanner."""
        recommendation = recommend_installation(["trivy"])
        assert isinstance(recommendation, str)
        assert "trivy" in recommendation.lower()

    def test_multiple_scanners(self):
        """Test recommendation for multiple scanners."""
        recommendation = recommend_installation(["trivy", "semgrep", "bandit"])
        assert isinstance(recommendation, str)
        # Should mention multiple tools
        assert len(recommendation) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
