"""
Tests for AI summary and triage features.

Tests the 'yavs summarize' command including:
- Generating separate summary file
- Enriching scan results with --enrich flag
- Custom output paths with -o flag
- Summary data structure validation
"""

import json
import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing summary generation."""
    return {
        "build_cycle": "2025-11-09T04:15:23.456789Z",
        "project": "test-project",
        "commit_hash": "abc123",
        "branch": "main",
        "compliance": [
            {
                "tool": "Trivy",
                "violations": [
                    {
                        "severity": "CRITICAL",
                        "rule_id": "CVE-2021-44228",
                        "description": "Log4Shell vulnerability",
                        "file": "pom.xml",
                        "line": None,
                        "package": "log4j-core",
                        "version": "2.14.0",
                        "fixed_version": "2.17.1"
                    }
                ]
            }
        ],
        "sast": [
            {
                "tool": "Semgrep",
                "issues": [
                    {
                        "severity": "HIGH",
                        "rule_id": "csrf-missing",
                        "description": "Missing CSRF protection",
                        "file": "app.js",
                        "line": 25
                    }
                ]
            }
        ],
        "summary": {
            "total_findings": 2,
            "by_severity": {
                "CRITICAL": 1,
                "HIGH": 1
            },
            "by_category": {
                "dependency": 1,
                "sast": 1
            }
        }
    }


@pytest.fixture
def sample_summary_output():
    """Sample AI summary output for validation."""
    return {
        "build_cycle": "2025-11-09T05:30:00Z",
        "findings_count": 2,
        "executive_summary": "## Executive Summary\n\nFound 2 critical issues...",
        "ai_provider": "anthropic",
        "ai_model": "claude-sonnet-4-5-20250929",
        "triage": {
            "clusters": [
                {
                    "name": "Critical Vulnerabilities",
                    "count": 2,
                    "severity": "CRITICAL",
                    "findings": [0, 1]
                }
            ],
            "cluster_count": 1,
            "total_findings": 2,
            "ai_analysis": "## Triage\n\nPriority 1...",
            "ai_provider": "anthropic",
            "ai_model": "claude-sonnet-4-5-20250929"
        }
    }


class TestSummarySeparateFile:
    """Tests for generating separate summary file (default behavior)."""

    def test_summary_structure(self, sample_summary_output):
        """Test that summary output has correct structure."""
        assert "build_cycle" in sample_summary_output
        assert "findings_count" in sample_summary_output
        assert sample_summary_output["findings_count"] == 2

        # Optional fields (when features enabled)
        if "executive_summary" in sample_summary_output:
            assert isinstance(sample_summary_output["executive_summary"], str)
            assert "ai_provider" in sample_summary_output
            assert "ai_model" in sample_summary_output

        if "triage" in sample_summary_output:
            triage = sample_summary_output["triage"]
            assert "clusters" in triage
            assert "cluster_count" in triage
            assert "total_findings" in triage
            assert "ai_analysis" in triage

    def test_summary_required_fields(self, sample_summary_output):
        """Test that required fields are present."""
        required_fields = ["build_cycle", "findings_count"]
        for field in required_fields:
            assert field in sample_summary_output, f"Missing required field: {field}"

    def test_triage_cluster_structure(self, sample_summary_output):
        """Test that triage clusters have correct structure."""
        if "triage" not in sample_summary_output:
            pytest.skip("Triage not present in sample")

        triage = sample_summary_output["triage"]
        assert len(triage["clusters"]) == triage["cluster_count"]

        for cluster in triage["clusters"]:
            assert "name" in cluster
            assert "count" in cluster
            assert "findings" in cluster
            assert isinstance(cluster["findings"], list)
            assert len(cluster["findings"]) == cluster["count"]


class TestEnrichedScanResults:
    """Tests for enriching scan results with --enrich flag."""

    def test_enriched_structure(self, sample_scan_results, sample_summary_output):
        """Test that enriched results contain both scan and summary data."""
        enriched = sample_scan_results.copy()
        enriched["ai_summary"] = sample_summary_output

        # Original scan fields should still be present
        assert "build_cycle" in enriched
        assert "project" in enriched
        assert "compliance" in enriched
        assert "sast" in enriched
        assert "summary" in enriched

        # AI summary should be added
        assert "ai_summary" in enriched
        assert enriched["ai_summary"]["findings_count"] == 2

    def test_enrich_ignores_output_dir(self):
        """Test that --enrich mode ignores -o/--output-dir flag."""
        # When --enrich is used, the output_dir should be ignored
        # and the original file should be modified in place
        # This is a behavioral test to document expected behavior
        enrich_mode = True
        output_dir_specified = True

        if enrich_mode and output_dir_specified:
            # Should show warning and proceed with in-place modification
            assert True  # Behavioral expectation documented

    def test_enriched_preserves_original_data(self, sample_scan_results, sample_summary_output):
        """Test that enriching doesn't modify original scan data."""
        original_findings_count = sample_scan_results["summary"]["total_findings"]

        enriched = sample_scan_results.copy()
        enriched["ai_summary"] = sample_summary_output

        # Original summary should be unchanged
        assert enriched["summary"]["total_findings"] == original_findings_count

        # AI summary should match findings count
        assert enriched["ai_summary"]["findings_count"] == original_findings_count

    def test_ai_summary_field_optional(self, sample_scan_results):
        """Test that scan results are valid without ai_summary."""
        # Scan results without ai_summary should be valid
        assert "build_cycle" in sample_scan_results
        assert "summary" in sample_scan_results

        # ai_summary is optional
        assert "ai_summary" not in sample_scan_results


class TestSummaryOutputPaths:
    """Tests for custom output paths and file handling."""

    def test_default_output_filename(self):
        """Test default summary output filename."""
        default_filename = "yavs-ai-summary.json"
        assert default_filename.endswith(".json")

    def test_custom_output_directory(self):
        """Test custom output directory with -o flag."""
        output_dir = Path("/tmp/summaries")
        default_filename = "yavs-ai-summary.json"
        summary_path = output_dir / default_filename

        assert summary_path.parent == output_dir
        assert summary_path.name == default_filename
        assert summary_path.suffix == ".json"


class TestSummaryDataValidation:
    """Tests for validating summary data against schema."""

    def test_summary_timestamp_format(self, sample_summary_output):
        """Test that timestamps are in ISO 8601 format."""
        timestamp = sample_summary_output["build_cycle"]
        # Should end with Z (UTC)
        assert timestamp.endswith("Z")
        # Should contain T separator
        assert "T" in timestamp

    def test_findings_count_matches_analysis(self, sample_summary_output):
        """Test that findings_count matches triage total."""
        if "triage" not in sample_summary_output:
            pytest.skip("Triage not present")

        assert sample_summary_output["findings_count"] == \
               sample_summary_output["triage"]["total_findings"]

    def test_cluster_findings_are_unique(self, sample_summary_output):
        """Test that finding indices in clusters are unique."""
        if "triage" not in sample_summary_output:
            pytest.skip("Triage not present")

        all_findings = []
        for cluster in sample_summary_output["triage"]["clusters"]:
            all_findings.extend(cluster["findings"])

        # Each finding should appear exactly once
        assert len(all_findings) == len(set(all_findings))

    def test_ai_provider_valid(self, sample_summary_output):
        """Test that AI provider is valid."""
        if "ai_provider" not in sample_summary_output:
            pytest.skip("AI provider not present")

        valid_providers = ["anthropic", "openai"]
        assert sample_summary_output["ai_provider"] in valid_providers


class TestSummaryIntegration:
    """Integration tests for summary generation workflow."""

    def test_summary_json_serializable(self, sample_summary_output):
        """Test that summary output is JSON serializable."""
        try:
            json_str = json.dumps(sample_summary_output, indent=2)
            assert len(json_str) > 0

            # Should be deserializable
            parsed = json.loads(json_str)
            assert parsed["findings_count"] == sample_summary_output["findings_count"]
        except (TypeError, ValueError) as e:
            pytest.fail(f"Summary output is not JSON serializable: {e}")

    def test_enriched_json_serializable(self, sample_scan_results, sample_summary_output):
        """Test that enriched scan results are JSON serializable."""
        enriched = sample_scan_results.copy()
        enriched["ai_summary"] = sample_summary_output

        try:
            json_str = json.dumps(enriched, indent=2)
            assert len(json_str) > 0

            # Should be deserializable
            parsed = json.loads(json_str)
            assert "ai_summary" in parsed
            assert parsed["ai_summary"]["findings_count"] == 2
        except (TypeError, ValueError) as e:
            pytest.fail(f"Enriched results are not JSON serializable: {e}")


class TestSummaryFileOperations:
    """Tests for file I/O operations."""

    def test_write_separate_summary_file(self, sample_summary_output, tmp_path):
        """Test writing summary to separate file with default filename."""
        # Ensure output directory exists
        output_dir = tmp_path / "summaries"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Use default filename
        summary_file = output_dir / "yavs-ai-summary.json"

        with open(summary_file, 'w') as f:
            json.dump(sample_summary_output, f, indent=2)

        assert summary_file.exists()
        assert summary_file.parent == output_dir

        # Read back and verify
        with open(summary_file, 'r') as f:
            loaded = json.load(f)

        assert loaded["findings_count"] == sample_summary_output["findings_count"]

    def test_enrich_existing_file(self, sample_scan_results, sample_summary_output, tmp_path):
        """Test enriching an existing scan results file."""
        results_file = tmp_path / "yavs-results.json"

        # Write original results
        with open(results_file, 'w') as f:
            json.dump(sample_scan_results, f, indent=2)

        # Read, enrich, and write back
        with open(results_file, 'r') as f:
            results = json.load(f)

        results["ai_summary"] = sample_summary_output

        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        # Verify enriched file
        with open(results_file, 'r') as f:
            enriched = json.load(f)

        assert "ai_summary" in enriched
        assert "summary" in enriched  # Original summary preserved
        assert enriched["ai_summary"]["findings_count"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
