"""Enhanced tests for baseline utilities."""
import pytest
import json
import tempfile
from pathlib import Path
from yavs.utils.baseline import Baseline, FindingFingerprint

class TestFindingFingerprint:
    def test_fingerprint_generation(self):
        """Test fingerprint generation for finding."""
        finding = {
            "file": "test.py",
            "line": 10,
            "rule_id": "TEST-001",
            "tool": "test",
            "severity": "HIGH",
            "message": "test finding"
        }
        fingerprint = FindingFingerprint.generate(finding)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) > 0

    def test_fingerprint_consistency(self):
        """Test same finding produces same fingerprint."""
        finding = {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        fp1 = FindingFingerprint.generate(finding)
        fp2 = FindingFingerprint.generate(finding)
        assert fp1 == fp2

    def test_fingerprint_difference(self):
        """Test different findings produce different fingerprints."""
        finding1 = {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        finding2 = {"file": "test.py", "line": 20, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        fp1 = FindingFingerprint.generate(finding1)
        fp2 = FindingFingerprint.generate(finding2)
        assert fp1 != fp2

    def test_fingerprint_with_message(self):
        """Test fingerprint generation with message included."""
        finding = {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH", "message": "test"}
        fp1 = FindingFingerprint.generate(finding, include_message=True)
        fp2 = FindingFingerprint.generate(finding, include_message=False)
        assert fp1 != fp2

class TestBaselineClass:
    def test_baseline_initialization(self):
        """Test Baseline class initialization."""
        baseline = Baseline()
        assert baseline is not None
        assert hasattr(baseline, 'fingerprints')

    def test_baseline_generate(self):
        """Test generating baseline from findings."""
        baseline = Baseline()
        findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        ]
        result = baseline.generate(findings)
        assert isinstance(result, dict)
        assert "fingerprints" in result
        assert len(result["fingerprints"]) == 1

    def test_baseline_compare(self):
        """Test comparing findings against baseline."""
        baseline = Baseline()
        findings = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        ]
        baseline.generate(findings)

        # New finding
        new_findings = [
            {"file": "test.py", "line": 20, "rule_id": "TEST-002", "tool": "test", "severity": "HIGH"}
        ]
        result = baseline.compare(new_findings)
        assert isinstance(result, dict)
        assert result["new_count"] == 1
        assert result["fixed_count"] == 1

    def test_baseline_filter_new_only(self):
        """Test filtering to only new findings."""
        baseline = Baseline()
        existing = [
            {"file": "test.py", "line": 10, "rule_id": "TEST-001", "tool": "test", "severity": "HIGH"}
        ]
        baseline.generate(existing)

        current = existing + [
            {"file": "test.py", "line": 20, "rule_id": "TEST-002", "tool": "test", "severity": "HIGH"}
        ]
        new_only = baseline.filter_new_only(current)
        assert len(new_only) == 1
        assert new_only[0]["line"] == 20

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
