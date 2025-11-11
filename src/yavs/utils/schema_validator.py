"""SARIF schema validation utilities."""

import json
from pathlib import Path
from typing import Tuple


def validate_sarif(sarif_path: Path) -> Tuple[bool, str]:
    """
    Validate a SARIF file against the official schema.

    Uses sarif-tools CLI for validation.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        Tuple of (is_valid, message)
    """
    if not sarif_path.exists():
        return False, f"SARIF file not found: {sarif_path}"

    try:
        # First check if it's valid JSON
        with open(sarif_path, 'r') as f:
            data = json.load(f)

        # Basic structural checks
        if not isinstance(data, dict):
            return False, "SARIF file must be a JSON object"

        if data.get("version") != "2.1.0":
            return False, f"SARIF version must be 2.1.0, got: {data.get('version')}"

        if "$schema" not in data:
            return False, "SARIF file missing $schema field"

        if "runs" not in data or not isinstance(data["runs"], list):
            return False, "SARIF file must contain 'runs' array"

        # Perform structural validation
        is_valid, message = validate_sarif_structure(data)

        if not is_valid:
            return False, message

        return True, "Valid SARIF 2.1.0 file"

    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def validate_sarif_structure(data: dict) -> Tuple[bool, str]:
    """
    Validate SARIF structure without using external tools.

    Args:
        data: Parsed SARIF JSON data

    Returns:
        Tuple of (is_valid, message)
    """
    required_fields = {
        "version": str,
        "$schema": str,
        "runs": list
    }

    for field, expected_type in required_fields.items():
        if field not in data:
            return False, f"Missing required field: {field}"
        if not isinstance(data[field], expected_type):
            return False, f"Field {field} must be of type {expected_type.__name__}"

    if data["version"] != "2.1.0":
        return False, f"Unsupported SARIF version: {data['version']}"

    if not data["runs"]:
        return False, "SARIF must contain at least one run"

    # Validate each run
    for idx, run in enumerate(data["runs"]):
        if not isinstance(run, dict):
            return False, f"Run {idx} must be an object"

        if "tool" not in run:
            return False, f"Run {idx} missing 'tool' field"

        if "results" not in run:
            return False, f"Run {idx} missing 'results' field"

        if not isinstance(run["results"], list):
            return False, f"Run {idx} 'results' must be an array"

    return True, "SARIF structure is valid"
