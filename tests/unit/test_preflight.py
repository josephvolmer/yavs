"""Tests for preflight checks."""
import pytest
from unittest.mock import patch
from yavs.utils.preflight import (
    check_scanner_availability,
    check_ai_configuration,
    run_preflight_checks
)

class TestCheckScannerAvailability:
    def test_no_scanners_needed(self):
        """Test when no scanners are needed."""
        available, missing = check_scanner_availability()
        assert isinstance(available, bool)
        assert isinstance(missing, list)

    def test_disabled_scanners_not_checked(self):
        """Test that disabled scanners are not checked."""
        config = {
            "scanners": {
                "trivy": {"enabled": False},
                "semgrep": {"enabled": False},
                "bandit": {"enabled": False},
                "checkov": {"enabled": False}
            }
        }
        available, missing = check_scanner_availability(
            sbom=True, sast=True, compliance=True, config=config
        )
        # Disabled scanners shouldn't be in missing list
        assert "trivy" not in missing
        assert "semgrep" not in missing
        assert "bandit" not in missing
        assert "checkov" not in missing

class TestCheckAIConfiguration:
    def test_no_ai_needed(self):
        """Test when AI is not needed."""
        result, msg = check_ai_configuration(ai_enabled=False, config={})
        assert isinstance(result, bool)
        assert result is True

    def test_ai_disabled_in_config(self):
        """Test AI disabled in config."""
        config = {"ai": {"enabled": False}}
        result, msg = check_ai_configuration(ai_enabled=True, config=config)
        assert isinstance(result, bool)
        assert result is True

class TestRunPreflightChecks:
    def test_with_config(self):
        """Test with configuration and AI disabled."""
        config = {"scanners": {}, "ai": {"enabled": False}}
        result = run_preflight_checks(ai_enabled=False, config=config)
        assert isinstance(result, bool)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
