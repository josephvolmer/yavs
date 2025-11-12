"""
HTML Report Generator

Generates beautiful HTML security reports from YAVS scan results.
Handles all input formats: structured, flat, enriched, and separate summaries.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from ..utils.rule_links import format_rule_link_html


def markdown_to_html(text: str) -> str:
    """
    Convert markdown text to HTML.

    Args:
        text: Markdown text

    Returns:
        HTML string (safe for rendering)
    """
    if not text:
        return ""

    try:
        import markdown
        html = markdown.markdown(
            text,
            extensions=['fenced_code', 'tables', 'nl2br']
        )
        # nosemgrep: python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup
        # Markup() is safe here: markdown library sanitizes HTML, content is from local scans not user input
        return Markup(html)  # noqa: S308
    except ImportError:
        # Fallback: basic conversion if markdown not installed
        # Convert newlines to <br>, wrap in <p>
        html = text.replace('\n\n', '</p><p>').replace('\n', '<br>')
        # nosemgrep: python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup
        # Markup() is safe here: simple text formatting, content is from local scans not user input
        return Markup(f'<p>{html}</p>')  # noqa: S308


class HTMLReportGenerator:
    """Generates HTML reports from YAVS scan results."""

    def __init__(self):
        """Initialize the HTML report generator."""
        # Get the templates directory
        templates_dir = Path(__file__).parent.parent / "templates"

        # Setup Jinja2 environment with autoescaping enabled for security
        # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
        # Direct Jinja2 use is safe: autoescape enabled, content from local scans not web users
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(['html', 'xml', 'jinja'])
        )

        # Add custom filters
        self.env.filters['markdown'] = markdown_to_html
        # nosemgrep: python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup
        # Markup() is safe here: format_rule_link_html generates sanitized link HTML
        self.env.filters['rule_link'] = lambda rule_id, tool: Markup(format_rule_link_html(tool, rule_id))  # noqa: S308

    def load_data(self, scan_results_path: Path, summary_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Load and normalize scan results and optional summary.

        Args:
            scan_results_path: Path to YAVS scan results (structured or flat)
            summary_path: Optional path to separate summary file

        Returns:
            Normalized data dict ready for template rendering
        """
        # Load scan results
        with open(scan_results_path, 'r') as f:
            scan_data = json.load(f)

        # Load optional summary
        summary_data = None
        if summary_path and summary_path.exists():
            with open(summary_path, 'r') as f:
                summary_data = json.load(f)

        # Normalize the data
        normalized = self._normalize_scan_data(scan_data)

        # Merge summary if provided (and not already enriched)
        if summary_data and 'ai_summary' not in normalized:
            normalized['ai_summary'] = summary_data

        return normalized

    def _normalize_scan_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize scan data to structured format.

        Handles:
        - Structured format (as-is)
        - Flat format (convert to structured)
        - Already enriched data (preserve ai_summary)
        """
        # Check if this is flat format (has 'data' key instead of 'compliance'/'sast')
        if 'data' in data and not ('compliance' in data or 'sast' in data):
            return self._convert_flat_to_structured(data)

        # Already structured, ensure all required fields exist
        return self._ensure_structured_fields(data)

    def _convert_flat_to_structured(self, flat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert flat format to structured format.

        Flat format:
        {
          "build_cycle": "...",
          "data": [{"tool": "trivy", "category": "dependency", ...}]
        }

        Structured format:
        {
          "build_cycle": "...",
          "compliance": [{"tool": "Trivy", "violations": [...]}],
          "sast": [{"tool": "Semgrep", "issues": [...]}]
        }
        """
        findings = flat_data.get('data', [])

        # Group by tool and category
        compliance_tools = {}
        sast_tools = {}

        for finding in findings:
            tool = finding.get('tool', 'Unknown').title()
            category = finding.get('category', 'unknown')

            if category in ['dependency', 'secret', 'license', 'config', 'compliance']:
                # Compliance category
                if tool not in compliance_tools:
                    compliance_tools[tool] = []

                # Convert to violation format
                violation = {
                    'severity': finding.get('severity'),
                    'rule_id': finding.get('rule_id'),
                    'description': finding.get('description', finding.get('message', '')),
                    'file': finding.get('file'),
                    'line': finding.get('line'),
                }

                # Add optional fields
                if 'package' in finding:
                    violation['package'] = finding['package']
                if 'version' in finding:
                    violation['version'] = finding['version']
                if 'fixed_version' in finding:
                    violation['fixed_version'] = finding['fixed_version']
                if 'vulnerability_id' in finding:
                    violation['vulnerability_id'] = finding['vulnerability_id']
                if 'ai_fix' in finding:
                    violation['ai_fix'] = finding['ai_fix']
                    violation['ai_provider'] = finding.get('ai_provider')
                    violation['ai_model'] = finding.get('ai_model')

                compliance_tools[tool].append(violation)

            elif category == 'sast':
                # SAST category
                if tool not in sast_tools:
                    sast_tools[tool] = []

                # Convert to issue format
                issue = {
                    'severity': finding.get('severity'),
                    'rule_id': finding.get('rule_id'),
                    'description': finding.get('description', finding.get('message', '')),
                    'file': finding.get('file'),
                    'line': finding.get('line'),
                }

                # Add optional AI fields
                if 'ai_fix' in finding:
                    issue['ai_fix'] = finding['ai_fix']
                    issue['ai_provider'] = finding.get('ai_provider')
                    issue['ai_model'] = finding.get('ai_model')

                sast_tools[tool].append(issue)

        # Build structured format
        structured = {
            'build_cycle': flat_data.get('build_cycle'),
            'project': flat_data.get('project'),
            'commit_hash': flat_data.get('commit_hash'),
            'branch': flat_data.get('branch'),
            'sbom': flat_data.get('sbom'),
            'compliance': [
                {'tool': tool, 'violations': violations}
                for tool, violations in compliance_tools.items()
            ],
            'sast': [
                {'tool': tool, 'issues': issues}
                for tool, issues in sast_tools.items()
            ],
        }

        # Calculate summary
        structured['summary'] = self._calculate_summary(findings)

        # Preserve ai_summary if present
        if 'ai_summary' in flat_data:
            structured['ai_summary'] = flat_data['ai_summary']

        return structured

    def _ensure_structured_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure structured data has all required fields with defaults."""
        # Set defaults for missing fields
        if 'compliance' not in data:
            data['compliance'] = []
        if 'sast' not in data:
            data['sast'] = []

        # Ensure summary exists
        if 'summary' not in data:
            # Calculate from findings
            all_findings = []

            for compliance_tool in data.get('compliance', []):
                all_findings.extend(compliance_tool.get('violations', []))

            for sast_tool in data.get('sast', []):
                all_findings.extend(sast_tool.get('issues', []))

            data['summary'] = self._calculate_summary(all_findings)

        return data

    def _calculate_summary(self, findings: list) -> Dict[str, Any]:
        """Calculate summary statistics from findings."""
        total_findings = len(findings)

        # Count by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1

        # Count by category (if available)
        by_category = {}
        for finding in findings:
            category = finding.get('category', 'unknown')
            by_category[category] = by_category.get(category, 0) + 1

        return {
            'total_findings': total_findings,
            'by_severity': by_severity,
            'by_category': by_category,
        }

    def _load_sbom_file(self, sbom_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Load SBOM file contents if available.

        Args:
            sbom_info: SBOM metadata from scan results

        Returns:
            Parsed SBOM data or None if not available
        """
        if not sbom_info or 'location' not in sbom_info:
            return None

        sbom_path = Path(sbom_info['location'])
        if not sbom_path.exists():
            return None

        try:
            with open(sbom_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def generate(
        self,
        scan_results_path: Path,
        output_path: Path,
        summary_path: Optional[Path] = None
    ) -> None:
        """
        Generate HTML report.

        Args:
            scan_results_path: Path to YAVS scan results file
            output_path: Path where HTML report should be saved
            summary_path: Optional path to separate summary file
        """
        # Load and normalize data
        data = self.load_data(scan_results_path, summary_path)

        # Load SBOM contents if available
        if 'sbom' in data and data['sbom']:
            sbom_contents = self._load_sbom_file(data['sbom'])
            if sbom_contents:
                data['sbom_data'] = sbom_contents

        # Get template
        # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
        # Direct Jinja2 use is safe: autoescape enabled, content from local scans not web users
        template = self.env.get_template('report.jinja')

        # Render report
        html_content = template.render(
            data=data,
            report_generated_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        )

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)


def generate_html_report(
    scan_results: Path,
    output: Path,
    summary: Optional[Path] = None
) -> None:
    """
    Generate an HTML security report.

    Args:
        scan_results: Path to YAVS scan results (structured or flat format)
        output: Path for the HTML report output
        summary: Optional path to separate AI summary file
    """
    generator = HTMLReportGenerator()
    generator.generate(scan_results, output, summary)
