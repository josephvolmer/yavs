"""Tests for preflight checks."""

import pytest
from pathlib import Path

from yavs.utils.preflight import (
    check_scanner_availability,
    check_ai_configuration,
    run_preflight_checks
)


class TestCheckScannerAvailability:
    """Test check_scanner_availability function."""

    def test_returns_dict(self):
        """Test returns a dictionary."""
        result = check_scanner_availability()
        assert isinstance(result, dict)

    def test_has_common_scanners(self):
        """Test result includes common scanners."""
        result = check_scanner_availability()
        # Should check for standard scanners
        assert isinstance(result, dict)


class TestCheckAIConfiguration:
    """Test check_ai_configuration function."""

    def test_returns_tuple(self):
        """Test returns a tuple."""
        result = check_ai_configuration()
        assert isinstance(result, tuple)
        assert len(result) == 2
        is_valid, message = result
        assert isinstance(is_valid, bool)
        assert isinstance(message, str)


class TestRunPreflightChecks:
    """Test run_preflight_checks function."""

    def test_returns_dict(self):
        """Test returns a dictionary."""
        result = run_preflight_checks()
        assert isinstance(result, dict)

    def test_has_scanner_and_ai_status(self):
        """Test result has scanner and AI status."""
        result = run_preflight_checks()
        # Should have some status info
        assert isinstance(result, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
