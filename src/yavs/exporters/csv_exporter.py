"""
CSV/TSV Export Module

Exports YAVS findings to CSV or TSV format for spreadsheet analysis.
"""

import csv
from pathlib import Path
from typing import List, Dict, Any, Optional


def get_csv_columns() -> List[str]:
    """Define standard CSV column order."""
    return [
        'severity',
        'tool',
        'category',
        'title',
        'description',
        'file',
        'line',
        'rule_id',
        'vulnerability_id',
        'package',
        'version',
        'fix_version',
        'cvss_score',
        'cwe',
        'references',
        # Git blame fields
        'git_author',
        'git_email',
        'git_commit',
        'git_date',
        # Policy fields
        'policy_suppressed',
        'policy_tags',
        'policy_rule',
        # Baseline fields
        'suppressed',
        'suppression_reason'
    ]


def normalize_finding_for_csv(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalize a finding for CSV export.

    Converts all values to strings and handles nested structures.
    """
    normalized = {}

    # Handle standard fields
    for col in get_csv_columns():
        value = ''

        # Extract git blame fields from nested structure
        if col.startswith('git_'):
            git_blame = finding.get('git_blame', {})
            field_name = col.replace('git_', '')
            value = git_blame.get(field_name, '')

        # Extract policy fields
        elif col == 'policy_suppressed':
            value = 'Yes' if finding.get('suppressed_by_policy') else ''
        elif col == 'policy_tags':
            value = finding.get('policy_tags', [])
        elif col == 'policy_rule':
            value = finding.get('policy_rule', '') or finding.get('policy_violation', '')

        # Extract baseline suppression
        elif col == 'suppressed':
            value = 'Yes' if finding.get('suppressed') else ''
        elif col == 'suppression_reason':
            value = finding.get('suppression_reason', '')

        # Standard fields
        else:
            value = finding.get(col, '')

        # Convert lists to comma-separated strings
        if isinstance(value, list):
            value = '; '.join(str(v) for v in value)

        # Convert booleans
        elif isinstance(value, bool):
            value = 'Yes' if value else 'No'

        # Convert None to empty string
        elif value is None:
            value = ''

        # Convert everything else to string
        else:
            value = str(value)

        # Clean up newlines and excessive whitespace for CSV
        value = value.replace('\n', ' ').replace('\r', ' ')
        value = ' '.join(value.split())  # Normalize whitespace

        normalized[col] = value

    return normalized


def export_to_csv(
    findings: List[Dict[str, Any]],
    output_path: Path,
    include_bom: bool = True
) -> None:
    """
    Export findings to CSV format.

    Args:
        findings: List of findings to export
        output_path: Path where CSV file will be written
        include_bom: Include UTF-8 BOM for Excel compatibility (default: True)

    Raises:
        IOError: If file cannot be written
    """
    # Choose encoding with or without BOM
    encoding = 'utf-8-sig' if include_bom else 'utf-8'

    with open(output_path, 'w', newline='', encoding=encoding) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=get_csv_columns(),
            delimiter=',',
            quoting=csv.QUOTE_MINIMAL
        )

        writer.writeheader()

        for finding in findings:
            normalized = normalize_finding_for_csv(finding)
            writer.writerow(normalized)


def export_to_tsv(
    findings: List[Dict[str, Any]],
    output_path: Path,
    include_bom: bool = True
) -> None:
    """
    Export findings to TSV (Tab-Separated Values) format.

    Args:
        findings: List of findings to export
        output_path: Path where TSV file will be written
        include_bom: Include UTF-8 BOM for Excel compatibility (default: True)

    Raises:
        IOError: If file cannot be written
    """
    # Choose encoding with or without BOM
    encoding = 'utf-8-sig' if include_bom else 'utf-8'

    with open(output_path, 'w', newline='', encoding=encoding) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=get_csv_columns(),
            delimiter='\t',
            quoting=csv.QUOTE_MINIMAL
        )

        writer.writeheader()

        for finding in findings:
            normalized = normalize_finding_for_csv(finding)
            writer.writerow(normalized)


def export_with_format(
    findings: List[Dict[str, Any]],
    output_path: Path,
    format: str = 'csv',
    include_bom: bool = True
) -> None:
    """
    Export findings in specified format.

    Args:
        findings: List of findings to export
        output_path: Path where file will be written
        format: Export format ('csv' or 'tsv')
        include_bom: Include UTF-8 BOM for Excel compatibility (default: True)

    Raises:
        ValueError: If format is not supported
        IOError: If file cannot be written
    """
    if format.lower() == 'csv':
        export_to_csv(findings, output_path, include_bom)
    elif format.lower() == 'tsv':
        export_to_tsv(findings, output_path, include_bom)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'csv' or 'tsv'.")
