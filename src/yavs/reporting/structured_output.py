"""Structured output formatter for YAVS results."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from collections import defaultdict

from ..utils.logging import LoggerMixin


class StructuredOutputFormatter(LoggerMixin):
    """
    Format YAVS results in a structured format organized by category.

    Output structure:
    {
        "build_cycle": "2025-01-15T12:34:56Z",
        "project": "my-project",
        "commit_hash": "abc123",
        "branch": "main",
        "sbom": {
            "format": "CycloneDX",
            "location": "artifacts/sbom.json",
            "tool": "trivy"
        },
        "compliance": [
            {
                "tool": "Trivy",
                "violations": [
                    // CVEs, secrets, licenses, config issues
                ]
            },
            {
                "tool": "Checkov",
                "violations": [
                    // IaC policy violations
                ]
            }
        ],
        "sast": [
            {
                "tool": "Semgrep",
                "issues": [...]
            }
        ],
        "summary": {
            "total_findings": 100,
            "by_severity": {...}
        }
    }
    """

    def __init__(self):
        """Initialize formatter."""
        pass

    def format(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        sbom_info: Optional[Dict[str, Any]] = None,
        ai_summary: Optional[str] = None,
        executed_scanners: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Format findings into structured output.

        Args:
            findings: List of all findings
            metadata: Project metadata (build_cycle, project, commit_hash, etc)
            sbom_info: SBOM metadata if generated
            ai_summary: AI-generated executive summary text
            executed_scanners: List of scanners that were executed

        Returns:
            Structured output dictionary
        """
        # Initialize output structure
        output = {
            "build_cycle": metadata.get("build_cycle"),
            "project": metadata.get("project"),
            "commit_hash": metadata.get("commit_hash"),
            "branch": metadata.get("branch"),
        }

        # Add scanner execution metadata
        if executed_scanners:
            output["scanners_executed"] = executed_scanners

        # Add SBOM info if available
        if sbom_info:
            output["sbom"] = sbom_info

        # Organize findings by category and tool
        by_category = self._group_by_category(findings)

        # Compliance: Consolidate all security/policy violations
        # Includes: dependencies, secrets, licenses, config, compliance
        compliance_categories = ["dependency", "secret", "license", "config", "compliance"]
        compliance_findings = []
        for cat in compliance_categories:
            if cat in by_category:
                compliance_findings.extend(by_category[cat])

        # Build compliance tools list (including tools with 0 findings)
        compliance_tools = {}
        if compliance_findings:
            by_tool = self._group_by_tool(compliance_findings)
            for tool_name, tool_findings in by_tool.items():
                # Normalize to title case for consistency
                normalized_name = tool_name.title()
                compliance_tools[normalized_name] = [self._format_violation(f) for f in tool_findings]

        # Add executed scanners with 0 findings in compliance categories
        # Store scanner metadata (status, error) separately
        scanner_metadata = {}
        if executed_scanners:
            for scanner in executed_scanners:
                # Normalize scanner name for metadata lookup
                normalized_scanner_name = scanner["tool"].title()
                scanner_metadata[normalized_scanner_name] = {
                    "status": scanner.get("status", "success"),
                    "error": scanner.get("error")
                }
                if scanner["category"] in compliance_categories:
                    tool_name = scanner["tool"]
                    # Normalize to title case for consistency
                    normalized_name = tool_name.title()
                    if normalized_name not in compliance_tools:
                        compliance_tools[normalized_name] = []

        if compliance_tools:
            output["compliance"] = []
            for tool_name, violations in compliance_tools.items():
                tool_entry = {"tool": tool_name.title(), "violations": violations}
                # Add status and error if scanner failed
                if tool_name in scanner_metadata:
                    if scanner_metadata[tool_name]["status"] != "success":
                        tool_entry["status"] = scanner_metadata[tool_name]["status"]
                        if scanner_metadata[tool_name]["error"]:
                            tool_entry["error"] = scanner_metadata[tool_name]["error"]
                output["compliance"].append(tool_entry)

        # SAST issues
        sast_tools = {}
        if "sast" in by_category:
            sast_findings = by_category["sast"]
            by_tool = self._group_by_tool(sast_findings)
            for tool_name, tool_findings in by_tool.items():
                # Normalize to title case for consistency
                normalized_name = tool_name.title()
                sast_tools[normalized_name] = [
                    {
                        "severity": f.get("severity"),
                        "rule_id": f.get("rule_id"),
                        "description": f.get("message"),
                        "file": f.get("file"),
                        "line": f.get("line"),
                        "ai_fix": f.get("ai_fix"),
                        "ai_provider": f.get("ai_provider"),
                    }
                    for f in tool_findings
                ]

        # Add executed SAST scanners with 0 findings
        if executed_scanners:
            for scanner in executed_scanners:
                if scanner["category"] == "sast":
                    tool_name = scanner["tool"]
                    # Normalize to title case for consistency
                    normalized_name = tool_name.title()
                    if normalized_name not in sast_tools:
                        sast_tools[normalized_name] = []

        if sast_tools:
            output["sast"] = []
            for tool_name, issues in sast_tools.items():
                tool_entry = {"tool": tool_name.title(), "issues": issues}
                # Add status and error if scanner failed
                if tool_name in scanner_metadata:
                    if scanner_metadata[tool_name]["status"] != "success":
                        tool_entry["status"] = scanner_metadata[tool_name]["status"]
                        if scanner_metadata[tool_name]["error"]:
                            tool_entry["error"] = scanner_metadata[tool_name]["error"]
                output["sast"].append(tool_entry)

        # Summary statistics
        output["summary"] = self._generate_summary(findings)

        # Add AI summary if available
        if ai_summary:
            output["ai_summary"] = {
                "executive_summary": ai_summary
            }

        return output

    def _group_by_category(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by category."""
        by_category = defaultdict(list)
        for finding in findings:
            category = finding.get("category", "unknown")
            by_category[category].append(finding)
        return dict(by_category)

    def _group_by_tool(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by tool."""
        by_tool = defaultdict(list)
        for finding in findings:
            tool = finding.get("tool", "unknown")
            by_tool[tool].append(finding)
        return dict(by_tool)

    def _format_violation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format a compliance violation with all relevant fields.

        Handles different types: CVEs, secrets, licenses, config issues, IaC policies.
        """
        violation = {
            "severity": finding.get("severity"),
            "rule_id": finding.get("rule_id"),
            "description": finding.get("message"),
            "file": finding.get("file"),
            "line": finding.get("line"),
        }

        # Add type-specific fields if present
        if finding.get("package"):
            violation["package"] = finding.get("package")
            violation["version"] = finding.get("version")
            violation["fixed_version"] = finding.get("fixed_version")
            violation["vulnerability_id"] = finding.get("rule_id")

        # Add AI fix if available
        if finding.get("ai_fix"):
            violation["ai_fix"] = finding.get("ai_fix")
            violation["ai_provider"] = finding.get("ai_provider")

        return violation

    def _get_primary_tool(self, findings: List[Dict[str, Any]]) -> str:
        """Get the primary tool name from findings."""
        if not findings:
            return "Unknown"
        # Get the most common tool
        tools = [f.get("tool", "unknown") for f in findings]
        return max(set(tools), key=tools.count).title()

    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics."""
        by_severity = defaultdict(int)
        by_category = defaultdict(int)

        for finding in findings:
            by_severity[finding.get("severity", "UNKNOWN")] += 1
            by_category[finding.get("category", "unknown")] += 1

        return {
            "total_findings": len(findings),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
        }

    def write_json(self, output: Dict[str, Any], file_path: Path):
        """
        Write structured output to JSON file.

        Args:
            output: Structured output dictionary
            file_path: Output file path
        """
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'w') as f:
            json.dump(output, f, indent=2)

        self.logger.info(f"Wrote structured output to {file_path}")
