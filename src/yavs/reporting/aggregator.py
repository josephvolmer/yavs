"""Aggregator for combining results from multiple scanners."""

import json
from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict

from ..utils.logging import LoggerMixin


class Aggregator(LoggerMixin):
    """
    Aggregates and normalizes results from multiple scanners.

    Handles:
    - Deduplication of findings
    - Sorting by severity
    - JSON output generation
    """

    def __init__(self):
        """Initialize aggregator."""
        self.findings: List[Dict[str, Any]] = []
        self.executed_scanners: Dict[str, Dict[str, Any]] = {}

    def register_scanner(self, tool_name: str, category: str, findings_count: int = 0, status: str = "success", error: str = None):
        """
        Register that a scanner was executed or attempted.

        Args:
            tool_name: Name of the scanner tool
            category: Category of findings (sast, compliance, dependency, secret)
            findings_count: Number of findings from this scanner
            status: Execution status ("success", "failed", "skipped")
            error: Error message if status is "failed"
        """
        if tool_name not in self.executed_scanners:
            self.executed_scanners[tool_name] = {
                "tool": tool_name,
                "category": category,
                "findings_count": 0,
                "status": status
            }
            if error:
                self.executed_scanners[tool_name]["error"] = error
        else:
            # Update existing entry
            self.executed_scanners[tool_name]["findings_count"] += findings_count
            if status != "success":
                self.executed_scanners[tool_name]["status"] = status
                if error:
                    self.executed_scanners[tool_name]["error"] = error

    def add_findings(self, findings: List[Dict[str, Any]], tool_name: str = None, category: str = None):
        """
        Add findings from a scanner.

        Args:
            findings: List of normalized findings
            tool_name: Name of the scanner tool (optional, for backward compatibility)
            category: Category of findings (optional, for backward compatibility)
        """
        self.findings.extend(findings)
        self.logger.debug(f"Added {len(findings)} findings to aggregator")

    def deduplicate(self):
        """
        Remove duplicate findings based on key attributes.

        Deduplication key: (file, line, rule_id, message)
        """
        seen = set()
        deduplicated = []

        for finding in self.findings:
            # Create deduplication key
            key = (
                finding.get("file", ""),
                finding.get("line", ""),
                finding.get("rule_id", ""),
                finding.get("message", "")
            )

            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)

        removed = len(self.findings) - len(deduplicated)
        if removed > 0:
            self.logger.info(f"Removed {removed} duplicate finding(s)")

        self.findings = deduplicated

    def sort_by_severity(self):
        """Sort findings by severity (highest first)."""
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
            "UNKNOWN": 5
        }

        self.findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "UNKNOWN"), 5)
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get summary statistics about the findings.

        Returns:
            Dictionary with statistics
        """
        stats = {
            "total": len(self.findings),
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "by_tool": defaultdict(int),
        }

        for finding in self.findings:
            stats["by_severity"][finding.get("severity", "UNKNOWN")] += 1
            stats["by_category"][finding.get("category", "unknown")] += 1
            stats["by_tool"][finding.get("tool", "unknown")] += 1

        # Convert defaultdicts to regular dicts
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_category"] = dict(stats["by_category"])
        stats["by_tool"] = dict(stats["by_tool"])

        return stats

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings.

        Returns:
            List of findings
        """
        return self.findings

    def get_executed_scanners(self) -> List[Dict[str, Any]]:
        """
        Get list of executed scanners with their finding counts.

        Returns:
            List of scanner metadata dicts
        """
        return list(self.executed_scanners.values())

    def write_json(self, output_path: Path):
        """
        Write findings to JSON file.

        Args:
            output_path: Path to output JSON file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(self.findings, f, indent=2)

        self.logger.info(f"Wrote {len(self.findings)} findings to {output_path}")

    def read_json(self, input_path: Path):
        """
        Read findings from a JSON file.

        Supports both formats:
        - Flat array: [{finding1}, {finding2}, ...]
        - Structured: {"compliance": [...], "sast": [...], ...}

        Args:
            input_path: Path to input JSON file
        """
        input_path = Path(input_path)

        with open(input_path, 'r') as f:
            data = json.load(f)

        # Detect format
        if isinstance(data, list):
            # Flat array format
            self.findings = data
        elif isinstance(data, dict):
            # Check if it's structured format (has compliance/sast keys)
            if 'compliance' in data or 'sast' in data:
                # Structured format - extract findings from both sections
                findings = []

                # Extract from compliance section
                for tool_result in data.get('compliance', []):
                    for violation in tool_result.get('violations', []):
                        # Add tool name if not present
                        if 'tool' not in violation:
                            violation['tool'] = tool_result.get('tool', 'Unknown')
                        # Add category if not present
                        if 'category' not in violation:
                            violation['category'] = 'compliance'
                        # Map description to message if needed
                        if 'message' not in violation and 'description' in violation:
                            violation['message'] = violation['description']
                        findings.append(violation)

                # Extract from SAST section
                for tool_result in data.get('sast', []):
                    for issue in tool_result.get('issues', []):
                        # Add tool name if not present
                        if 'tool' not in issue:
                            issue['tool'] = tool_result.get('tool', 'Unknown')
                        # Add category if not present
                        if 'category' not in issue:
                            issue['category'] = 'sast'
                        # Map description to message if needed
                        if 'message' not in issue and 'description' in issue:
                            issue['message'] = issue['description']
                        findings.append(issue)

                self.findings = findings
            elif 'data' in data:
                # Flat format with metadata wrapper
                self.findings = data['data']
            else:
                # Unknown format - try to use as-is
                self.logger.warning(f"Unknown JSON format in {input_path}, attempting to use as flat array")
                self.findings = data if isinstance(data, list) else []
        else:
            self.logger.error(f"Invalid JSON format in {input_path}")
            self.findings = []

        self.logger.info(f"Loaded {len(self.findings)} findings from {input_path}")

    def clear(self):
        """Clear all findings."""
        self.findings = []
