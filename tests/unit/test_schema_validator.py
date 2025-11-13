"""Tests for schema validator."""

import pytest
import json
import tempfile
from pathlib import Path

from yavs.utils.schema_validator import (
    validate_sarif_structure,
    validate_sarif
)


class TestValidateSARIFStructure:
    """Test SARIF structure validation."""

    def test_valid_minimal_sarif(self):
        """Test validation of minimal valid SARIF."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestTool"
                        }
                    },
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is True

    def test_valid_sarif_with_results(self):
        """Test validation of SARIF with results."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "YAVS"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "TEST-001",
                            "message": {
                                "text": "Test finding"
                            },
                            "level": "error"
                        }
                    ]
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is True

    def test_missing_version(self):
        """Test SARIF missing version fails."""
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "version" in message.lower()

    def test_missing_schema(self):
        """Test SARIF missing $schema fails."""
        sarif = {
            "version": "2.1.0",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "schema" in message.lower()

    def test_missing_runs(self):
        """Test SARIF missing runs fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json"
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "runs" in message.lower()

    def test_wrong_version(self):
        """Test SARIF with wrong version fails."""
        sarif = {
            "version": "1.0.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "version" in message.lower()

    def test_runs_not_list(self):
        """Test SARIF with runs not a list fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": {}
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "runs" in message.lower()

    def test_empty_runs(self):
        """Test SARIF with empty runs array fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": []
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "run" in message.lower()

    def test_run_missing_tool(self):
        """Test SARIF run missing tool fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "tool" in message.lower()

    def test_tool_missing_driver(self):
        """Test SARIF tool missing driver fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {},
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "driver" in message.lower()

    def test_driver_missing_name(self):
        """Test SARIF driver missing name fails."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {}
                    },
                    "results": []
                }
            ]
        }
        is_valid, message = validate_sarif_structure(sarif)
        assert is_valid is False
        assert "name" in message.lower()

    def test_not_dict(self):
        """Test non-dict input fails."""
        is_valid, message = validate_sarif_structure([])
        assert is_valid is False
        assert "dictionary" in message.lower()

    def test_none_input(self):
        """Test None input fails."""
        is_valid, message = validate_sarif_structure(None)
        assert is_valid is False


class TestValidateSARIFFile:
    """Test validate_sarif function."""

    def test_nonexistent_file(self, tmp_path):
        """Test nonexistent file fails."""
        fake_path = tmp_path / "nonexistent.sarif"
        is_valid, message = validate_sarif(fake_path)
        assert is_valid is False
        assert "not found" in message.lower()

    def test_invalid_json(self, tmp_path):
        """Test invalid JSON fails."""
        sarif_file = tmp_path / "invalid.sarif"
        sarif_file.write_text("{invalid json")
        is_valid, message = validate_sarif(sarif_file)
        assert is_valid is False

    def test_valid_sarif_file(self, tmp_path):
        """Test valid SARIF file."""
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "YAVS"
                        }
                    },
                    "results": []
                }
            ]
        }
        sarif_file = tmp_path / "valid.sarif"
        sarif_file.write_text(json.dumps(sarif_data))
        is_valid, message = validate_sarif(sarif_file)
        assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
