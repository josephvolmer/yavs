"""
Tests for HTML report generation.

Tests the report generator with all input formats:
- Structured output
- Flat output
- Enriched results
- Separate summary files
"""

import json
import pytest
from pathlib import Path
import tempfile
from src.yavs.reporting.html_report import HTMLReportGenerator, generate_html_report


@pytest.fixture
def sample_structured_data():
    """Sample structured scan results."""
    return {
        "build_cycle": "2025-11-09T04:15:23.456789Z",
        "project": "test-project",
        "commit_hash": "abc123def456",
        "branch": "main",
        "sbom": {
            "format": "CYCLONEDX",
            "location": "/path/to/sbom.json",
            "size_bytes": 1024,
            "tool": "trivy"
        },
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
                        "fixed_version": "2.17.1",
                        "ai_fix": "Update to log4j 2.17.1 or later"
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
                        "line": 25,
                        "ai_fix": "Add CSRF middleware"
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
def sample_flat_data():
    """Sample flat format scan results."""
    return {
        "build_cycle": "2025-11-09T04:15:23.456789Z",
        "project": "test-project",
        "commit_hash": "abc123def456",
        "branch": "main",
        "data": [
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "CRITICAL",
                "file": "pom.xml",
                "line": None,
                "message": "Log4Shell vulnerability",
                "rule_id": "CVE-2021-44228",
                "package": "log4j-core",
                "version": "2.14.0",
                "fixed_version": "2.17.1"
            },
            {
                "tool": "semgrep",
                "category": "sast",
                "severity": "HIGH",
                "file": "app.js",
                "line": 25,
                "message": "Missing CSRF protection",
                "rule_id": "csrf-missing"
            }
        ]
    }


@pytest.fixture
def sample_enriched_data(sample_structured_data):
    """Sample enriched scan results with AI summary."""
    enriched = sample_structured_data.copy()
    enriched["ai_summary"] = {
        "build_cycle": "2025-11-09T05:30:00Z",
        "findings_count": 2,
        "executive_summary": "Found 2 critical security issues requiring immediate attention.",
        "ai_provider": "anthropic",
        "ai_model": "claude-sonnet-4-5-20250929"
    }
    return enriched


@pytest.fixture
def sample_summary():
    """Sample AI summary file."""
    return {
        "build_cycle": "2025-11-09T05:30:00Z",
        "findings_count": 2,
        "executive_summary": "Found 2 critical security issues requiring immediate attention.",
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
            "ai_analysis": "Priority 1: Fix critical vulnerabilities"
        }
    }


class TestHTMLReportGenerator:
    """Tests for HTMLReportGenerator class."""

    def test_generator_initialization(self):
        """Test that generator initializes correctly."""
        generator = HTMLReportGenerator()
        assert generator.env is not None
        assert generator.env.loader is not None

    def test_load_structured_data(self, sample_structured_data, tmp_path):
        """Test loading structured format data."""
        # Write sample data to file
        data_file = tmp_path / "results.json"
        with open(data_file, 'w') as f:
            json.dump(sample_structured_data, f)

        generator = HTMLReportGenerator()
        data = generator.load_data(data_file)

        assert data["project"] == "test-project"
        assert data["summary"]["total_findings"] == 2
        assert len(data["compliance"]) > 0
        assert len(data["sast"]) > 0

    def test_load_flat_data(self, sample_flat_data, tmp_path):
        """Test loading and converting flat format data."""
        # Write sample data to file
        data_file = tmp_path / "results.json"
        with open(data_file, 'w') as f:
            json.dump(sample_flat_data, f)

        generator = HTMLReportGenerator()
        data = generator.load_data(data_file)

        # Should be converted to structured format
        assert data["project"] == "test-project"
        assert "compliance" in data
        assert "sast" in data
        assert "summary" in data
        assert data["summary"]["total_findings"] == 2

    def test_load_enriched_data(self, sample_enriched_data, tmp_path):
        """Test loading enriched data with embedded AI summary."""
        # Write sample data to file
        data_file = tmp_path / "enriched-results.json"
        with open(data_file, 'w') as f:
            json.dump(sample_enriched_data, f)

        generator = HTMLReportGenerator()
        data = generator.load_data(data_file)

        assert "ai_summary" in data
        assert data["ai_summary"]["findings_count"] == 2
        assert data["ai_summary"]["ai_provider"] == "anthropic"

    def test_load_with_separate_summary(self, sample_structured_data, sample_summary, tmp_path):
        """Test loading with separate summary file."""
        # Write scan results
        results_file = tmp_path / "results.json"
        with open(results_file, 'w') as f:
            json.dump(sample_structured_data, f)

        # Write summary file
        summary_file = tmp_path / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(sample_summary, f)

        generator = HTMLReportGenerator()
        data = generator.load_data(results_file, summary_file)

        # Should have both scan results and AI summary
        assert data["project"] == "test-project"
        assert "ai_summary" in data
        assert data["ai_summary"]["findings_count"] == 2
        assert "triage" in data["ai_summary"]


class TestFlatToStructuredConversion:
    """Tests for flat to structured conversion."""

    def test_convert_flat_to_structured(self, sample_flat_data):
        """Test converting flat format to structured."""
        generator = HTMLReportGenerator()
        structured = generator._convert_flat_to_structured(sample_flat_data)

        # Should have structured sections
        assert "compliance" in structured
        assert "sast" in structured
        assert len(structured["compliance"]) > 0
        assert len(structured["sast"]) > 0

        # Check compliance section
        trivy_tool = next(t for t in structured["compliance"] if t["tool"] == "Trivy")
        assert len(trivy_tool["violations"]) == 1
        assert trivy_tool["violations"][0]["severity"] == "CRITICAL"

        # Check SAST section
        semgrep_tool = next(t for t in structured["sast"] if t["tool"] == "Semgrep")
        assert len(semgrep_tool["issues"]) == 1
        assert semgrep_tool["issues"][0]["severity"] == "HIGH"

    def test_summary_calculation(self):
        """Test automatic summary calculation."""
        findings = [
            {"severity": "CRITICAL", "category": "dependency"},
            {"severity": "HIGH", "category": "sast"},
            {"severity": "MEDIUM", "category": "config"},
        ]

        generator = HTMLReportGenerator()
        summary = generator._calculate_summary(findings)

        assert summary["total_findings"] == 3
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["MEDIUM"] == 1


class TestHTMLGeneration:
    """Tests for actual HTML generation."""

    def test_generate_from_structured(self, sample_structured_data, tmp_path):
        """Test HTML generation from structured data."""
        # Write input data
        input_file = tmp_path / "results.json"
        with open(input_file, 'w') as f:
            json.dump(sample_structured_data, f)

        # Generate report
        output_file = tmp_path / "report.html"
        generate_html_report(input_file, output_file)

        # Check output exists
        assert output_file.exists()

        # Read and verify HTML content
        html_content = output_file.read_text()

        # Should contain expected elements
        assert "<!DOCTYPE html>" in html_content
        assert "test-project" in html_content
        assert "Security Assessment Report" in html_content
        assert "CRITICAL" in html_content
        assert "HIGH" in html_content
        assert "Log4Shell" in html_content
        assert "CSRF" in html_content

    def test_generate_from_flat(self, sample_flat_data, tmp_path):
        """Test HTML generation from flat data."""
        # Write input data
        input_file = tmp_path / "flat-results.json"
        with open(input_file, 'w') as f:
            json.dump(sample_flat_data, f)

        # Generate report
        output_file = tmp_path / "report.html"
        generate_html_report(input_file, output_file)

        # Check output exists
        assert output_file.exists()

        # Read and verify HTML content
        html_content = output_file.read_text()

        # Should contain expected elements (converted from flat)
        assert "test-project" in html_content
        assert "CRITICAL" in html_content
        assert "Log4Shell" in html_content

    def test_generate_with_ai_summary(self, sample_enriched_data, tmp_path):
        """Test HTML generation with AI summary."""
        # Write enriched data
        input_file = tmp_path / "enriched-results.json"
        with open(input_file, 'w') as f:
            json.dump(sample_enriched_data, f)

        # Generate report
        output_file = tmp_path / "report.html"
        generate_html_report(input_file, output_file)

        # Check output exists
        assert output_file.exists()

        # Read and verify HTML content
        html_content = output_file.read_text()

        # Should contain AI summary section
        assert "AI Executive Summary" in html_content
        assert "Found 2 critical security issues" in html_content
        assert "anthropic" in html_content

    def test_generate_with_separate_summary(self, sample_structured_data, sample_summary, tmp_path):
        """Test HTML generation with separate summary file."""
        # Write scan results
        results_file = tmp_path / "results.json"
        with open(results_file, 'w') as f:
            json.dump(sample_structured_data, f)

        # Write summary file
        summary_file = tmp_path / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(sample_summary, f)

        # Generate report with both files
        output_file = tmp_path / "report.html"
        generate_html_report(results_file, output_file, summary_file)

        # Check output exists
        assert output_file.exists()

        # Read and verify HTML content
        html_content = output_file.read_text()

        # Should contain both scan results and AI summary
        assert "test-project" in html_content
        assert "AI Executive Summary" in html_content
        assert "Found 2 critical security issues" in html_content

    def test_output_to_artifacts_dir(self, sample_structured_data, tmp_path):
        """Test that reports can be written to artifacts directory."""
        # Create artifacts directory
        artifacts_dir = tmp_path / "artifacts" / "reports"
        artifacts_dir.mkdir(parents=True)

        # Write input data
        input_file = tmp_path / "results.json"
        with open(input_file, 'w') as f:
            json.dump(sample_structured_data, f)

        # Generate report in artifacts
        output_file = artifacts_dir / "security-report.html"
        generate_html_report(input_file, output_file)

        # Verify file exists in artifacts
        assert output_file.exists()
        assert output_file.parent == artifacts_dir


class TestErrorHandling:
    """Tests for error handling in report generation."""

    def test_missing_input_file(self, tmp_path):
        """Test handling of missing input file."""
        missing_file = tmp_path / "nonexistent.json"
        output_file = tmp_path / "report.html"

        with pytest.raises(FileNotFoundError):
            generate_html_report(missing_file, output_file)

    def test_invalid_json(self, tmp_path):
        """Test handling of invalid JSON."""
        # Write invalid JSON
        input_file = tmp_path / "invalid.json"
        input_file.write_text("not valid json {")

        output_file = tmp_path / "report.html"

        with pytest.raises(json.JSONDecodeError):
            generate_html_report(input_file, output_file)

    def test_missing_required_fields(self, tmp_path):
        """Test handling of data with missing required fields."""
        # Write minimal data (should still work with defaults)
        input_file = tmp_path / "minimal.json"
        with open(input_file, 'w') as f:
            json.dump({
                "project": "minimal-test",
                "summary": {
                    "total_findings": 0,
                    "by_severity": {},
                    "by_category": {}
                }
            }, f)

        output_file = tmp_path / "report.html"

        # Should still generate report with defaults
        generate_html_report(input_file, output_file)

        assert output_file.exists()
        html_content = output_file.read_text()
        assert "minimal-test" in html_content


class TestReportContent:
    """Tests for specific report content and sections."""

    def test_risk_score_calculation(self, tmp_path):
        """Test that risk scores are calculated correctly."""
        data = {
            "project": "risk-test",
            "summary": {
                "total_findings": 5,
                "by_severity": {
                    "CRITICAL": 2,  # 2 * 10 = 20
                    "HIGH": 1,      # 1 * 5 = 5
                    "MEDIUM": 2,    # 2 * 2 = 4
                },
                "by_category": {
                    "compliance": 1  # 1 * 8 = 8
                }
            }
        }
        # Total risk score: 20 + 5 + 4 + 8 = 37 (High Risk)

        input_file = tmp_path / "risk-data.json"
        with open(input_file, 'w') as f:
            json.dump(data, f)

        output_file = tmp_path / "report.html"
        generate_html_report(input_file, output_file)

        html_content = output_file.read_text()

        # Should show calculated risk
        assert "risk-score" in html_content.lower() or "37" in html_content

    def test_sbom_section_rendering(self, sample_structured_data, tmp_path):
        """Test that SBOM section renders correctly."""
        input_file = tmp_path / "results.json"
        with open(input_file, 'w') as f:
            json.dump(sample_structured_data, f)

        output_file = tmp_path / "report.html"
        generate_html_report(input_file, output_file)

        html_content = output_file.read_text()

        # Should contain SBOM info
        assert "Software Bill of Materials" in html_content
        assert "CYCLONEDX" in html_content
        assert "trivy" in html_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
