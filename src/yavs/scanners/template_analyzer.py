"""TemplateAnalyzer scanner for Azure ARM and Bicep templates."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class TemplateAnalyzerScanner(BaseScanner):
    """
    Microsoft TemplateAnalyzer integration for Azure IaC security.

    Scans:
    - Azure ARM templates (JSON)
    - Bicep files (.bicep)
    - Azure Resource Manager best practices
    """

    @property
    def tool_name(self) -> str:
        return "template-analyzer"

    @property
    def category(self) -> str:
        return "iac"

    def get_command(self) -> str:
        """
        Build TemplateAnalyzer command.

        Configuration precedence:
        1. CLI flags (YAVS extra_flags) - highest priority
        2. Config file (native_config)
        3. TemplateAnalyzer defaults
        """
        # Build base command with JSON output
        base_cmd = f"dotnet template-analyzer analyze-template {self.target_path} --output-format json"

        # Add native config if provided
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using TemplateAnalyzer native config: {self.native_config}")
            base_cmd += f" --config-file {self.native_config}"

        # Add extra flags last (highest priority)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse TemplateAnalyzer JSON output into normalized format.

        TemplateAnalyzer output structure:
        {
            "results": [
                {
                    "filePath": "template.json",
                    "violations": [
                        {
                            "severity": "HIGH",
                            "ruleId": "TA-000001",
                            "ruleName": "Storage HTTPS Only",
                            "message": "Storage account should use HTTPS",
                            "lineNumber": 42,
                            "resourcePath": "resources[0]",
                            "recommendation": "Set supportsHttpsTrafficOnly: true",
                            "helpUri": "https://aka.ms/arm-template-best-practices"
                        }
                    ]
                }
            ]
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        if not isinstance(data, dict):
            self.logger.warning(f"Unexpected TemplateAnalyzer output type: {type(data)}")
            return []

        # Extract results array
        results = data.get("results", [])

        for result in results:
            file_path = result.get("filePath", "")
            violations = result.get("violations", [])

            for violation in violations:
                # Normalize severity
                severity = self._normalize_severity(violation.get("severity", "MEDIUM"))

                # Build normalized finding
                finding = {
                    "tool": self.tool_name,
                    "category": self.category,
                    "severity": severity,
                    "title": violation.get("ruleName", violation.get("ruleId", "Unknown Rule")),
                    "description": violation.get("message", ""),
                    "file": file_path,
                    "line": violation.get("lineNumber", 0),
                    "rule_id": violation.get("ruleId", ""),
                    "rule_name": violation.get("ruleName", ""),
                    "remediation": violation.get("recommendation", ""),
                    "resource": violation.get("resourcePath", ""),
                    "help_uri": violation.get("helpUri", ""),
                }

                findings.append(finding)

        return findings

    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize TemplateAnalyzer severity to YAVS standard.

        TemplateAnalyzer severities: HIGH, MEDIUM, LOW, INFORMATIONAL
        YAVS severities: CRITICAL, HIGH, MEDIUM, LOW, INFO
        """
        severity_map = {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFORMATIONAL": "INFO",
        }

        severity_upper = severity.upper()
        return severity_map.get(severity_upper, "MEDIUM")
