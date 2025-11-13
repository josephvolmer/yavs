"""Tests for exporter modules (CSV, etc)."""
import pytest
from pathlib import Path
from yavs.exporters.csv_exporter import (
    get_csv_columns,
    normalize_finding_for_csv,
    export_to_csv
)


class TestCSVExporter:
    """Tests for CSV exporter."""

    def test_get_csv_columns(self):
        """Test getting CSV column list."""
        columns = get_csv_columns()
        assert isinstance(columns, list)
        assert len(columns) > 0
        assert 'severity' in columns
        assert 'tool' in columns
        assert 'file' in columns

    def test_normalize_finding_for_csv_basic(self):
        """Test normalizing a basic finding for CSV."""
        finding = {
            'severity': 'HIGH',
            'tool': 'bandit',
            'category': 'sast',
            'file': 'test.py',
            'line': 42,
            'rule_id': 'B608'
        }

        normalized = normalize_finding_for_csv(finding)
        assert isinstance(normalized, dict)
        assert normalized['severity'] == 'HIGH'
        assert normalized['tool'] == 'bandit'

    def test_normalize_finding_for_csv_git_blame(self):
        """Test normalizing finding with git blame info."""
        finding = {
            'severity': 'HIGH',
            'tool': 'bandit',
            'file': 'test.py',
            'git_blame': {
                'author': 'John Doe',
                'email': 'john@example.com',
                'commit': 'abc123',
                'date': '2024-01-01'
            }
        }

        normalized = normalize_finding_for_csv(finding)
        assert normalized['git_author'] == 'John Doe'
        assert normalized['git_email'] == 'john@example.com'
        assert normalized['git_commit'] == 'abc123'

    def test_normalize_finding_for_csv_policy_fields(self):
        """Test normalizing finding with policy fields."""
        finding = {
            'severity': 'HIGH',
            'tool': 'bandit',
            'suppressed_by_policy': True,
            'policy_tags': ['production', 'critical'],
            'policy_rule': 'suppress-high'
        }

        normalized = normalize_finding_for_csv(finding)
        assert normalized['policy_suppressed'] == 'Yes'
        assert 'production' in str(normalized['policy_tags'])

    def test_normalize_finding_for_csv_suppressed(self):
        """Test normalizing suppressed finding."""
        finding = {
            'severity': 'HIGH',
            'tool': 'bandit',
            'suppressed': True,
            'suppression_reason': 'False positive'
        }

        normalized = normalize_finding_for_csv(finding)
        assert normalized['suppressed'] == 'Yes'
        assert normalized['suppression_reason'] == 'False positive'

    def test_normalize_finding_for_csv_empty(self):
        """Test normalizing empty finding."""
        finding = {}
        normalized = normalize_finding_for_csv(finding)
        assert isinstance(normalized, dict)

    def test_export_to_csv_basic(self, tmp_path):
        """Test exporting findings to CSV file."""
        output_file = tmp_path / "results.csv"
        findings = [
            {'severity': 'HIGH', 'tool': 'bandit', 'file': 'test.py', 'line': 10},
            {'severity': 'MEDIUM', 'tool': 'semgrep', 'file': 'app.py', 'line': 20},
        ]

        export_to_csv(findings, output_file)
        assert output_file.exists()

        # Check file has content
        content = output_file.read_text()
        assert 'severity' in content
        assert 'HIGH' in content

    def test_export_to_csv_empty_findings(self, tmp_path):
        """Test exporting empty findings list."""
        output_file = tmp_path / "empty.csv"
        findings = []

        export_to_csv(findings, output_file)
        assert output_file.exists()

        # Should have header row
        content = output_file.read_text()
        assert 'severity' in content

    def test_export_to_csv_with_bom(self, tmp_path):
        """Test exporting with BOM."""
        output_file = tmp_path / "results.csv"
        findings = [
            {'severity': 'HIGH', 'tool': 'bandit', 'file': 'test.py'}
        ]

        export_to_csv(findings, output_file, include_bom=True)
        assert output_file.exists()

        content = output_file.read_text()
        assert 'HIGH' in content

    def test_export_to_csv_with_lists(self, tmp_path):
        """Test exporting finding with list fields."""
        output_file = tmp_path / "results.csv"
        findings = [
            {
                'severity': 'HIGH',
                'tool': 'trivy',
                'references': ['https://cve.mitre.org/CVE-1', 'https://nvd.nist.gov/vuln/1'],
                'policy_tags': ['prod', 'critical']
            }
        ]

        export_to_csv(findings, output_file)
        assert output_file.exists()

    def test_export_to_csv_complex_finding(self, tmp_path):
        """Test exporting complex finding with all fields."""
        output_file = tmp_path / "complex.csv"
        findings = [
            {
                'severity': 'CRITICAL',
                'tool': 'trivy',
                'category': 'dependency',
                'title': 'Vulnerable package',
                'description': 'Critical vulnerability in lodash',
                'file': 'package.json',
                'line': 15,
                'rule_id': 'CVE-2021-1234',
                'vulnerability_id': 'CVE-2021-1234',
                'package': 'lodash',
                'version': '4.17.20',
                'fix_version': '4.17.21',
                'cvss_score': 9.8,
                'cwe': 'CWE-79',
                'references': ['https://nvd.nist.gov'],
                'git_blame': {
                    'author': 'Jane Smith',
                    'email': 'jane@example.com',
                    'commit': 'def456',
                    'date': '2024-02-01'
                },
                'suppressed_by_policy': True,
                'policy_tags': ['production'],
                'policy_rule': 'suppress-deps',
                'suppressed': False,
                'suppression_reason': ''
            }
        ]

        export_to_csv(findings, output_file)
        assert output_file.exists()

        content = output_file.read_text()
        assert 'CRITICAL' in content
        assert 'lodash' in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
