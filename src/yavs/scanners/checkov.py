"""Checkov scanner for Infrastructure as Code compliance."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class CheckovScanner(BaseScanner):
    """
    Checkov scanner integration for IaC compliance, secrets, and SCA.

    Scans:
    - Terraform (IaC policies)
    - CloudFormation (IaC policies)
    - Kubernetes manifests (IaC policies)
    - Dockerfiles (IaC policies)
    - Helm charts (IaC policies)
    - Secrets (hardcoded credentials in IaC)
    - SCA for packages (Terraform modules, Helm charts)
    - SCA for container images (CVEs in Docker images)
    """

    @property
    def tool_name(self) -> str:
        return "checkov"

    @property
    def category(self) -> str:
        # Default category, but individual findings may be categorized differently
        return "compliance"

    def get_command(self) -> str:
        """
        Build Checkov command with all scanning frameworks.

        Configuration precedence (Checkov's native behavior):
        1. CLI flags (highest priority) - YAVS extra_flags
        2. Config file - native_config (.checkov.yaml)
        3. Built-in defaults (lowest priority)

        This means:
        - YAVS provides baseline settings via CLI flags
        - Native config extends/overrides those settings
        - Extra flags can override everything
        """
        # Build base command with YAVS defaults
        # Enable all frameworks: IaC, secrets, SCA
        frameworks = "terraform,cloudformation,kubernetes,dockerfile,secrets,sca_package,sca_image"
        base_cmd = f"checkov -d . --framework {frameworks} -o json --quiet"

        # Add native config if provided (extends YAVS settings)
        # Checkov will merge config file with CLI flags (CLI flags win)
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using Checkov native config: {self.native_config} (extends YAVS settings)")
            base_cmd += f" --config-file {self.native_config}"

        # Add extra flags last (highest priority - can override everything)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Checkov JSON output into normalized format.

        Checkov output structure:
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_23",
                        "check_name": "Ensure Security Group has description",
                        "check_result": {"result": "FAILED"},
                        "file_path": "/terraform/main.tf",
                        "file_line_range": [10, 15],
                        "resource": "aws_security_group.example",
                        "guideline": "https://...",
                        "severity": "LOW"
                    }
                ],
                "passed_checks": [...],
                "skipped_checks": [...]
            }
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        # Handle different Checkov output formats
        # Format 1: {"check_type": "...", "results": {"failed_checks": [...]}}
        # Format 2: {"passed": 0, "failed": 0, ...} (no results key)
        # Format 3: Edge case where "results" might be a list

        if not isinstance(data, dict):
            self.logger.warning(f"Unexpected Checkov output type: {type(data)}")
            return []

        # Check for format with "results" key
        results = data.get("results", {})

        # Defensive: Handle if results is unexpectedly a list
        if isinstance(results, list):
            self.logger.warning("Checkov returned results as list, treating as failed_checks")
            failed_checks = results
        elif isinstance(results, dict):
            # Normal case: results is a dict with failed_checks
            failed_checks = results.get("failed_checks", [])
        else:
            # Format 2: No results key, no findings
            failed_checks = []

        for check in failed_checks:
            # Skip if check is not a dict (defensive programming)
            if not isinstance(check, dict):
                self.logger.warning(f"Skipping non-dict check item: {type(check)}")
                continue

            # Get severity, default to MEDIUM if not specified
            severity = check.get("severity") or "MEDIUM"
            # Handle case where severity is None or empty string
            if severity:
                severity = str(severity).upper()
            else:
                severity = "MEDIUM"

            # Normalize severity values
            if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                severity = "MEDIUM"

            # Get file path
            file_path = check.get("file_path", "")
            # Remove leading slash if present for consistency
            if file_path and file_path.startswith("/"):
                file_path = file_path[1:]

            # Get line number (use first line of range)
            line_range = check.get("file_line_range", [])
            line = line_range[0] if (line_range and isinstance(line_range, list) and len(line_range) > 0) else None

            # Build description with guideline
            message = check.get("check_name", "Compliance check failed")
            guideline = check.get("guideline")

            # Determine category based on check_id
            check_id = check.get("check_id", "")
            category = self._determine_category(check_id)

            finding = {
                "tool": self.tool_name,
                "category": category,
                "severity": severity,
                "file": file_path,
                "line": line,
                "message": message,
                "rule_id": check_id,
                "description": guideline,
            }

            # Add IaC-specific metadata
            finding["metadata"] = {
                "resource": check.get("resource"),
                "check_class": check.get("check_class"),
                "file_line_range": line_range,
            }

            # Add package info for SCA findings
            if category == "dependency":
                finding["package"] = check.get("resource")

            findings.append(finding)

        return findings

    def _determine_category(self, check_id: str) -> str:
        """
        Determine the category based on Checkov check_id prefix.

        Categories:
        - CKV_SECRET_* → secret (hardcoded credentials in IaC)
        - CKV_CVE_*, CKV_SCA_* → dependency (package/image vulnerabilities)
        - All others → compliance (IaC policy violations)
        """
        if check_id.startswith("CKV_SECRET_"):
            return "secret"
        elif check_id.startswith("CKV_CVE_") or check_id.startswith("CKV_SCA_"):
            return "dependency"
        else:
            return "compliance"
