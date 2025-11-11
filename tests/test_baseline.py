"""
Comprehensive tests for baseline functionality.

Tests baseline generation, comparison, filtering, and diff commands.
"""

import json
import pytest
from pathlib import Path
from src.yavs.utils.baseline import (
    Baseline,
    FindingFingerprint,
    diff_scans,
    _extract_findings
)


class TestFindingFingerprint:
    """Test finding fingerprint generation."""

    def test_fingerprint_generation(self):
        """Test that fingerprints are generated consistently."""
        finding = {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "severity": "HIGH",
            "tool": "testTool"
        }

        fp1 = FindingFingerprint.generate(finding)
        fp2 = FindingFingerprint.generate(finding)

        assert fp1 == fp2
        assert len(fp1) == 64  # SHA256 hex digest length

    def test_fingerprint_uniqueness(self):
        """Test that different findings have different fingerprints."""
        finding1 = {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "severity": "HIGH",
            "tool": "testTool"
        }

        finding2 = {
            "file": "test.py",
            "line": 11,  # Different line
            "rule_id": "TEST-001",
            "severity": "HIGH",
            "tool": "testTool"
        }

        fp1 = FindingFingerprint.generate(finding1)
        fp2 = FindingFingerprint.generate(finding2)

        assert fp1 != fp2

    def test_fingerprint_with_message(self):
        """Test fingerprint generation with message included."""
        finding = {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "severity": "HIGH",
            "tool": "testTool",
            "message": "Test message"
        }

        fp_without_msg = FindingFingerprint.generate(finding, include_message=False)
        fp_with_msg = FindingFingerprint.generate(finding, include_message=True)

        assert fp_without_msg != fp_with_msg


class TestBaselineGeneration:
    """Test baseline generation."""

    def test_baseline_generation(self, tmp_path):
        """Test generating a baseline from findings."""
        findings = [
            {
                "file": "test1.py",
                "line": 10,
                "rule_id": "TEST-001",
                "severity": "HIGH",
                "tool": "testTool"
            },
            {
                "file": "test2.py",
                "line": 20,
                "rule_id": "TEST-002",
                "severity": "MEDIUM",
                "tool": "testTool"
            }
        ]

        baseline = Baseline()
        output_path = tmp_path / "baseline.json"

        result = baseline.generate(findings, output_path=output_path)

        # Check baseline structure
        assert result["version"] == "1.0"
        assert result["total_findings"] == 2
        assert len(result["fingerprints"]) == 2
        assert "created_at" in result

        # Check file was created
        assert output_path.exists()

        # Check file contents
        with open(output_path) as f:
            saved_baseline = json.load(f)
            assert saved_baseline["total_findings"] == 2

    def test_baseline_generation_with_metadata(self, tmp_path):
        """Test baseline generation with custom metadata."""
        findings = [{"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}]

        metadata = {
            "project": "test-project",
            "branch": "main",
            "commit_hash": "abc123"
        }

        baseline = Baseline()
        result = baseline.generate(findings, metadata=metadata)

        assert result["metadata"]["project"] == "test-project"
        assert result["metadata"]["branch"] == "main"
        assert result["metadata"]["commit_hash"] == "abc123"

    def test_baseline_severity_breakdown(self, tmp_path):
        """Test that severity breakdown is calculated correctly."""
        findings = [
            {"file": "a.py", "line": 1, "rule_id": "R1", "severity": "CRITICAL", "tool": "t"},
            {"file": "b.py", "line": 2, "rule_id": "R2", "severity": "CRITICAL", "tool": "t"},
            {"file": "c.py", "line": 3, "rule_id": "R3", "severity": "HIGH", "tool": "t"},
            {"file": "d.py", "line": 4, "rule_id": "R4", "severity": "MEDIUM", "tool": "t"},
        ]

        baseline = Baseline()
        result = baseline.generate(findings)

        assert result["severity_breakdown"]["CRITICAL"] == 2
        assert result["severity_breakdown"]["HIGH"] == 1
        assert result["severity_breakdown"]["MEDIUM"] == 1


class TestBaselineComparison:
    """Test baseline comparison functionality."""

    def test_baseline_comparison_no_changes(self):
        """Test comparing identical findings."""
        findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
        ]

        baseline = Baseline()
        baseline.generate(findings)

        comparison = baseline.compare(findings)

        assert comparison["new_count"] == 0
        assert comparison["fixed_count"] == 0
        assert comparison["existing_count"] == 1

    def test_baseline_comparison_new_findings(self):
        """Test detecting new findings."""
        baseline_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
        ]

        current_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"},
            {"file": "test.py", "line": 20, "rule_id": "TEST-002", "severity": "MEDIUM", "tool": "test"}
        ]

        baseline = Baseline()
        baseline.generate(baseline_findings)

        comparison = baseline.compare(current_findings)

        assert comparison["new_count"] == 1
        assert comparison["fixed_count"] == 0
        assert comparison["existing_count"] == 1

    def test_baseline_comparison_fixed_findings(self):
        """Test detecting fixed findings."""
        baseline_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"},
            {"file": "test.py", "line": 20, "rule_id": "TEST-002", "severity": "MEDIUM", "tool": "test"}
        ]

        current_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
        ]

        baseline = Baseline()
        baseline.generate(baseline_findings)

        comparison = baseline.compare(current_findings)

        assert comparison["new_count"] == 0
        assert comparison["fixed_count"] == 1
        assert comparison["existing_count"] == 1

    def test_filter_new_only(self):
        """Test filtering findings to show only new ones."""
        baseline_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
        ]

        current_findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"},
            {"file": "test.py", "line": 20, "rule_id": "TEST-002", "severity": "MEDIUM", "tool": "test"}
        ]

        baseline = Baseline()
        baseline.generate(baseline_findings)

        new_findings = baseline.filter_new_only(current_findings)

        assert len(new_findings) == 1
        assert new_findings[0]["line"] == 20


class TestExtractFindings:
    """Test finding extraction from different formats."""

    def test_extract_structured_format(self):
        """Test extracting findings from structured format."""
        data = {
            "findings": {
                "sast": [{"file": "a.py", "line": 1}],
                "dependency": [{"file": "b.py", "line": 2}]
            }
        }

        findings = _extract_findings(data)

        assert len(findings) == 2

    def test_extract_flat_format(self):
        """Test extracting findings from flat format."""
        data = {
            "data": [
                {"file": "a.py", "line": 1},
                {"file": "b.py", "line": 2}
            ]
        }

        findings = _extract_findings(data)

        assert len(findings) == 2

    def test_extract_top_level_categories(self):
        """Test extracting findings from top-level category keys."""
        data = {
            "sast": [{"file": "a.py", "line": 1}],
            "compliance": [{"file": "b.py", "line": 2}],
            "dependency": [{"file": "c.py", "line": 3}]
        }

        findings = _extract_findings(data)

        assert len(findings) == 3

    def test_extract_direct_array(self):
        """Test extracting findings from direct array."""
        data = [
            {"file": "a.py", "line": 1},
            {"file": "b.py", "line": 2}
        ]

        findings = _extract_findings(data)

        assert len(findings) == 2

    def test_extract_unknown_format(self):
        """Test handling unknown format."""
        data = {"unknown": "format"}

        findings = _extract_findings(data)

        assert len(findings) == 0


class TestBaselineSuppress:
    """Test baseline suppression functionality."""

    def test_suppress_findings(self):
        """Test suppressing findings."""
        baseline = Baseline()
        baseline.generate([])

        findings_to_suppress = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
        ]

        baseline.suppress_findings(findings_to_suppress)

        assert len(baseline.fingerprints) == 1
        assert "suppressed_findings" in baseline.baseline_data


class TestDiffScans:
    """Test scan diff functionality."""

    def test_diff_scans_basic(self, tmp_path):
        """Test basic scan diffing."""
        # Create baseline scan file
        baseline_data = {
            "data": [
                {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"}
            ]
        }

        baseline_file = tmp_path / "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        # Create current scan file
        current_data = {
            "data": [
                {"file": "test.py", "line": 10, "rule_id": "TEST-001", "severity": "HIGH", "tool": "test"},
                {"file": "test.py", "line": 20, "rule_id": "TEST-002", "severity": "MEDIUM", "tool": "test"}
            ]
        }

        current_file = tmp_path / "current.json"
        with open(current_file, "w") as f:
            json.dump(current_data, f)

        # Diff the scans
        new, fixed, existing = diff_scans(baseline_file, current_file)

        assert len(new) == 1
        assert new[0]["line"] == 20
