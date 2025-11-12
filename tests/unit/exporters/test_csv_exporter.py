"""Unit tests for CSV exporter."""

import csv
import io
from pathlib import Path

import pytest

from yavs.exporters.csv_exporter import export_to_csv, get_csv_columns


class TestCSVExporter:
    """Test CSV export functionality."""

    def test_get_csv_columns(self):
        """Test that CSV columns are comprehensive."""
        columns = get_csv_columns()

        # Should have 24 columns
        assert len(columns) == 24

        # Core fields
        assert "severity" in columns
        assert "tool" in columns
        assert "category" in columns
        assert "title" in columns
        assert "description" in columns
        assert "file" in columns
        assert "line" in columns

        # Git blame fields
        assert "git_author" in columns
        assert "git_email" in columns
        assert "git_commit" in columns
        assert "git_date" in columns

        # Policy fields
        assert "policy_suppressed" in columns
        assert "policy_tags" in columns
        assert "policy_rule" in columns

        # Baseline fields
        assert "suppressed" in columns
        assert "suppression_reason" in columns

    def test_export_empty_findings(self, tmp_path):
        """Test exporting empty findings list."""
        output_file = tmp_path / "empty.csv"

        export_to_csv([], output_file, include_bom=False)

        assert output_file.exists()

        # Should have header row
        with open(output_file) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames == get_csv_columns()
            rows = list(reader)
            assert len(rows) == 0

    def test_export_basic_finding(self, tmp_path):
        """Test exporting a basic finding."""
        output_file = tmp_path / "basic.csv"

        findings = [
            {
                "severity": "HIGH",
                "tool": "bandit",
                "category": "sast",
                "title": "SQL Injection",
                "description": "Potential SQL injection",
                "file": "app.py",
                "line": 42
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        assert output_file.exists()

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["severity"] == "HIGH"
            assert rows[0]["tool"] == "bandit"
            assert rows[0]["category"] == "sast"
            assert rows[0]["title"] == "SQL Injection"
            assert rows[0]["file"] == "app.py"
            assert rows[0]["line"] == "42"

    def test_export_with_git_blame(self, tmp_path):
        """Test exporting finding with git blame."""
        output_file = tmp_path / "git_blame.csv"

        findings = [
            {
                "severity": "MEDIUM",
                "tool": "semgrep",
                "category": "sast",
                "title": "Hardcoded Secret",
                "file": "config.py",
                "line": 10,
                "git_blame": {
                    "author": "John Doe",
                    "email": "john@example.com",
                    "commit": "abc123",
                    "date": "2025-01-15"
                }
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["git_author"] == "John Doe"
            assert rows[0]["git_email"] == "john@example.com"
            assert rows[0]["git_commit"] == "abc123"
            assert rows[0]["git_date"] == "2025-01-15"

    def test_export_with_policy_data(self, tmp_path):
        """Test exporting finding with policy data."""
        output_file = tmp_path / "policy.csv"

        findings = [
            {
                "severity": "LOW",
                "tool": "bandit",
                "category": "sast",
                "title": "Weak Crypto",
                "file": "crypto.py",
                "line": 5,
                "suppressed_by_policy": True,
                "suppression_reason": "Legacy code exemption",
                "policy_tags": ["legacy", "crypto"],
                "policy_rule": "SEC-001"
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["policy_suppressed"] == "Yes"
            assert rows[0]["policy_rule"] == "SEC-001"
            assert "legacy" in rows[0]["policy_tags"]
            assert "crypto" in rows[0]["policy_tags"]

    def test_export_with_baseline_suppression(self, tmp_path):
        """Test exporting finding suppressed by baseline."""
        output_file = tmp_path / "baseline.csv"

        findings = [
            {
                "severity": "HIGH",
                "tool": "trivy",
                "category": "dependency",
                "title": "CVE-2024-1234",
                "file": "package.json",
                "suppressed": True,
                "suppression_reason": "Accepted risk - expires 2025-12-31"
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["suppressed"] == "Yes"
            assert "expires 2025-12-31" in rows[0]["suppression_reason"]

    def test_export_multiple_findings(self, tmp_path):
        """Test exporting multiple findings."""
        output_file = tmp_path / "multiple.csv"

        findings = [
            {
                "severity": "CRITICAL",
                "tool": "trivy",
                "category": "dependency",
                "title": "CVE-2024-9999",
                "package": "requests",
                "version": "2.0.0",
                "fix_version": "2.28.0"
            },
            {
                "severity": "LOW",
                "tool": "bandit",
                "category": "sast",
                "title": "Assert Used",
                "file": "test.py",
                "line": 100
            },
            {
                "severity": "HIGH",
                "tool": "checkov",
                "category": "iac",
                "title": "S3 Bucket Public",
                "file": "main.tf",
                "line": 25
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 3
            assert rows[0]["severity"] == "CRITICAL"
            assert rows[1]["severity"] == "LOW"
            assert rows[2]["severity"] == "HIGH"

    def test_export_handles_missing_fields(self, tmp_path):
        """Test that export handles missing optional fields gracefully."""
        output_file = tmp_path / "minimal.csv"

        findings = [
            {
                "severity": "MEDIUM",
                "tool": "custom",
                "title": "Issue"
                # Missing many optional fields
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["severity"] == "MEDIUM"
            assert rows[0]["tool"] == "custom"
            # Optional fields should be empty strings
            assert rows[0]["file"] == ""
            assert rows[0]["git_author"] == ""

    def test_export_with_complex_values(self, tmp_path):
        """Test exporting findings with complex field values."""
        output_file = tmp_path / "complex.csv"

        findings = [
            {
                "severity": "HIGH",
                "tool": "semgrep",
                "title": "Issue with \"quotes\" and, commas",
                "description": "Multi-line\ndescription\nwith special chars",
                "policy_tags": ["tag1", "tag2", "tag3"],
                "references": ["https://example.com", "CVE-2024-1234"]
            }
        ]

        export_to_csv(findings, output_file, include_bom=False)

        # Should handle quotes, commas, newlines properly
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert "quotes" in rows[0]["title"]
            assert "commas" in rows[0]["title"]
            assert "Multi-line" in rows[0]["description"]

    def test_tsv_export(self, tmp_path):
        """Test TSV export (tab-separated)."""
        from yavs.exporters.csv_exporter import export_to_tsv

        output_file = tmp_path / "output.tsv"

        findings = [
            {
                "severity": "HIGH",
                "tool": "bandit",
                "title": "SQL Injection",
                "file": "app.py"
            }
        ]

        # TSV uses tabs as delimiter
        export_to_tsv(findings, output_file, include_bom=False)

        assert output_file.exists()

        with open(output_file) as f:
            content = f.read()
            # Should have tabs, not commas
            assert '\t' in content

            # Parse as TSV
            f.seek(0)
            reader = csv.DictReader(f, delimiter='\t')
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["severity"] == "HIGH"
