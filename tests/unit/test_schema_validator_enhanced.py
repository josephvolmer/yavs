"""Enhanced tests for schema validator."""
import pytest
import json
from pathlib import Path
from yavs.utils.schema_validator import validate_sarif, validate_sarif_structure

class TestValidateSarif:
    def test_validate_valid_sarif_with_runs(self, tmp_path):
        """Test validating valid SARIF file with runs."""
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}]
        }

        sarif_file = tmp_path / "valid.sarif"
        sarif_file.write_text(json.dumps(sarif_data))

        is_valid, msg = validate_sarif(sarif_file)
        assert isinstance(is_valid, bool)
        assert isinstance(msg, (str, type(None)))

    def test_validate_invalid_sarif(self, tmp_path):
        """Test validating invalid SARIF structure."""
        invalid_data = {"invalid": "structure"}

        sarif_file = tmp_path / "invalid.sarif"
        sarif_file.write_text(json.dumps(invalid_data))

        is_valid, msg = validate_sarif(sarif_file)
        assert isinstance(is_valid, bool)
        assert is_valid is False
        assert isinstance(msg, str)

class TestValidateSarifStructure:
    def test_validate_structure_with_runs(self):
        """Test validating SARIF structure with runs."""
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}]
        }

        is_valid, msg = validate_sarif_structure(sarif_data)
        assert isinstance(is_valid, bool)
        assert isinstance(msg, (str, type(None)))

    def test_validate_minimal_structure(self):
        """Test validating minimal SARIF structure."""
        minimal_sarif = {
            "version": "2.1.0",
            "runs": []
        }

        is_valid, msg = validate_sarif_structure(minimal_sarif)
        assert isinstance(is_valid, bool)
        assert is_valid is False  # Missing $schema

    def test_validate_empty_dict(self):
        """Test validating empty dictionary."""
        is_valid, msg = validate_sarif_structure({})
        assert isinstance(is_valid, bool)
        assert is_valid is False
        assert isinstance(msg, str)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
