"""SARIF 2.1.0 converter for standardized security reporting."""

import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..utils.path_utils import make_relative
from ..utils.logging import LoggerMixin
from .. import __version__


class SARIFConverter(LoggerMixin):
    """
    Converts normalized YAVS findings to SARIF 2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) is a standard
    for security tool outputs, supported by GitHub, Azure DevOps, and IDEs.
    """

    # Severity mapping from YAVS to SARIF levels
    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
        "UNKNOWN": "none"
    }

    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize SARIF converter.

        Args:
            base_path: Base directory for relative path calculation
        """
        self.base_path = base_path or Path.cwd()

    def convert(
        self,
        findings: List[Dict[str, Any]],
        include_ai_summary: bool = True
    ) -> Dict[str, Any]:
        """
        Convert normalized findings to SARIF format.

        Args:
            findings: List of normalized YAVS findings
            include_ai_summary: Whether to include AI summaries in properties

        Returns:
            SARIF 2.1.0 compliant dictionary
        """
        self.logger.info(f"Converting {len(findings)} findings to SARIF format")

        # Build SARIF structure
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "YAVS",
                            "version": __version__,
                            "informationUri": "https://github.com/YAVS-OSS/yavs",
                            "rules": self._build_rules(findings)
                        }
                    },
                    "results": self._convert_findings(findings, include_ai_summary),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                        }
                    ]
                }
            ]
        }

        return sarif

    def _build_rules(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract unique rules from findings.

        Args:
            findings: List of findings

        Returns:
            List of SARIF rule definitions
        """
        rules_map = {}

        for finding in findings:
            rule_id = finding.get("rule_id")
            if not rule_id or rule_id in rules_map:
                continue

            # Build rule definition
            rule = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": finding.get("message", "Security finding")
                }
            }

            # Add full description if available
            if finding.get("description"):
                rule["fullDescription"] = {
                    "text": finding["description"]
                }

            # Add help URI if available (for CVEs, etc.)
            if "CVE-" in rule_id:
                rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{rule_id}"

            rules_map[rule_id] = rule

        return list(rules_map.values())

    def _convert_findings(
        self,
        findings: List[Dict[str, Any]],
        include_ai_summary: bool
    ) -> List[Dict[str, Any]]:
        """
        Convert findings to SARIF results.

        Args:
            findings: List of normalized findings
            include_ai_summary: Include AI summaries in properties

        Returns:
            List of SARIF result objects
        """
        results = []

        for finding in findings:
            result = self._convert_single_finding(finding, include_ai_summary)
            results.append(result)

        return results

    def _convert_single_finding(
        self,
        finding: Dict[str, Any],
        include_ai_summary: bool
    ) -> Dict[str, Any]:
        """
        Convert a single finding to SARIF result format.

        Args:
            finding: Normalized finding
            include_ai_summary: Include AI summary in properties

        Returns:
            SARIF result object
        """
        # Map severity
        severity = finding.get("severity", "UNKNOWN")
        sarif_level = self.SEVERITY_MAP.get(severity, "none")

        # Build result object
        result = {
            "ruleId": finding.get("rule_id") or f"{finding.get('tool', 'UNKNOWN')}_{severity}",
            "level": sarif_level,
            "message": {
                "text": finding.get("message", "Security finding detected")
            }
        }

        # Add location if file is present
        if finding.get("file"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": make_relative(finding["file"], self.base_path)
                        },
                        "region": self._build_region(finding)
                    }
                }
            ]

        # Add properties for additional metadata
        properties = {
            "tool": finding.get("tool"),
            "category": finding.get("category"),
        }

        # Add optional fields
        if finding.get("package"):
            properties["package"] = finding["package"]
        if finding.get("version"):
            properties["version"] = finding["version"]
        if finding.get("fixed_version"):
            properties["fixed_version"] = finding["fixed_version"]
        if include_ai_summary and finding.get("ai_summary"):
            properties["ai_summary"] = finding["ai_summary"]
        if finding.get("metadata"):
            properties["metadata"] = finding["metadata"]

        # Add git blame information
        if finding.get("git_blame"):
            properties["git_blame"] = finding["git_blame"]

        # Add policy information
        if finding.get("suppressed_by_policy"):
            properties["policy_suppressed"] = True
            properties["policy_reason"] = finding.get("suppression_reason", "")
        if finding.get("policy_tags"):
            properties["policy_tags"] = finding["policy_tags"]
        if finding.get("policy_rule"):
            properties["policy_rule"] = finding["policy_rule"]
        if finding.get("policy_violation"):
            properties["policy_violation"] = True

        # Add baseline suppression
        if finding.get("suppressed"):
            properties["suppressed"] = True
            if finding.get("suppression_reason"):
                properties["suppression_reason"] = finding["suppression_reason"]

        result["properties"] = properties

        return result

    def _build_region(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build SARIF region object for code location.

        Args:
            finding: Normalized finding

        Returns:
            SARIF region object
        """
        region = {}

        if finding.get("line"):
            region["startLine"] = finding["line"]

        # If no line number, don't include region
        if not region:
            return {"startLine": 1}  # Default to line 1

        return region

    def write_sarif(self, sarif_data: Dict[str, Any], output_path: Path):
        """
        Write SARIF data to file.

        Args:
            sarif_data: SARIF dictionary
            output_path: Output file path
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Wrote SARIF output to {output_path}")

    def convert_and_write(
        self,
        findings: List[Dict[str, Any]],
        output_path: Path,
        include_ai_summary: bool = True
    ):
        """
        Convert findings and write to SARIF file.

        Args:
            findings: List of normalized findings
            output_path: Output file path
            include_ai_summary: Include AI summaries
        """
        sarif_data = self.convert(findings, include_ai_summary)
        self.write_sarif(sarif_data, output_path)
