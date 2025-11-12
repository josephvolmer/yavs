"""Terrascan scanner for Infrastructure as Code security."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class TerrascanScanner(BaseScanner):
    """
    Terrascan scanner integration for IaC security analysis.

    Scans:
    - Terraform (.tf files)
    - Kubernetes manifests (YAML/JSON)
    - Helm charts
    - Dockerfiles
    - CloudFormation templates
    - Azure ARM templates
    """

    @property
    def tool_name(self) -> str:
        return "terrascan"

    @property
    def category(self) -> str:
        return "compliance"

    def get_command(self) -> str:
        """
        Build Terrascan command.

        Configuration precedence:
        1. CLI flags (YAVS extra_flags) - highest priority
        2. Config file (native_config)
        3. Terrascan defaults
        """
        # Build base command with JSON output
        base_cmd = f"terrascan scan -d {self.target_path} -o json"

        # Auto-detect IaC type (let Terrascan figure it out)
        # If specific type needed, can be added via extra_flags: --iac-type terraform

        # Add native config if provided
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using Terrascan native config: {self.native_config}")
            base_cmd += f" -c {self.native_config}"

        # Add extra flags last (highest priority)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Terrascan JSON output into normalized format.

        Terrascan output structure:
        {
            "results": {
                "violations": [
                    {
                        "rule_name": "ruleExample",
                        "description": "Description of the rule violation",
                        "rule_id": "AWS.S3Bucket.DS.High.1043",
                        "severity": "HIGH",
                        "category": "S3",
                        "resource_name": "bucket_name",
                        "resource_type": "aws_s3_bucket",
                        "file": "main.tf",
                        "line": 10,
                        "iac_type": "terraform"
                    }
                ],
                "scan_summary": {...}
            }
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        if not isinstance(data, dict):
            self.logger.warning(f"Unexpected Terrascan output type: {type(data)}")
            return []

        # Extract violations from results
        results = data.get("results", {})
        violations = results.get("violations", [])

        for violation in violations:
            # Normalize severity
            severity = self._normalize_severity(violation.get("severity", "MEDIUM"))

            # Build normalized finding
            finding = {
                "tool": self.tool_name,
                "category": self.category,
                "severity": severity,
                "title": violation.get("rule_name", "Unknown Rule"),
                "description": violation.get("description", ""),
                "file": violation.get("file", ""),
                "line": violation.get("line", 0),
                "rule_id": violation.get("rule_id", ""),
                "resource_name": violation.get("resource_name", ""),
                "resource_type": violation.get("resource_type", ""),
                "iac_type": violation.get("iac_type", ""),
                "rule_category": violation.get("category", ""),
            }

            findings.append(finding)

        return findings

    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize Terrascan severity to YAVS standard.

        Terrascan severities: HIGH, MEDIUM, LOW
        YAVS severities: CRITICAL, HIGH, MEDIUM, LOW, INFO
        """
        severity_map = {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }

        severity_upper = severity.upper()
        return severity_map.get(severity_upper, "MEDIUM")
