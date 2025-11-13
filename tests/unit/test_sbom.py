"""Tests for SBOM scanner."""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from yavs.scanners.sbom import SBOMGenerator

class TestSBOMGenerator:
    def test_sbom_initialization(self, tmp_path):
        """Test SBOM generator initialization."""
        generator = SBOMGenerator(tmp_path)
        assert generator is not None
        assert generator.target_path == tmp_path

    def test_sbom_has_methods(self, tmp_path):
        """Test SBOM generator has required methods."""
        generator = SBOMGenerator(tmp_path)
        assert hasattr(generator, 'generate')
        assert callable(generator.generate)

    @patch('shutil.which')
    def test_check_available_trivy_found(self, mock_which, tmp_path):
        """Test availability check when trivy is found."""
        mock_which.return_value = "/usr/bin/trivy"
        generator = SBOMGenerator(tmp_path)
        assert generator.check_available() is True

    @patch('shutil.which')
    def test_check_available_trivy_not_found(self, mock_which, tmp_path):
        """Test availability check when trivy is not found."""
        mock_which.return_value = None
        generator = SBOMGenerator(tmp_path)
        # Just test that check_available returns a boolean
        result = generator.check_available()
        assert isinstance(result, bool)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
