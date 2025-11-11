"""Trivy scanner for dependencies, secrets, and configuration issues."""

from typing import List, Dict, Any, Optional
from pathlib import Path

from .base import BaseScanner
from ..utils.scanner_installer import ensure_trivy


class TrivyScanner(BaseScanner):
    """
    Trivy scanner integration for:
    - Software Composition Analysis (SCA)
    - Dependency vulnerabilities (CVEs in packages)
    - Secret detection (hardcoded credentials, API keys)
    - License compliance
    - Configuration misconfigurations (when security_checks includes 'config')
    - Docker image scanning
    """

    def __init__(
        self,
        target_path: Path,
        timeout: int = 300,
        extra_flags: str = "",
        security_checks: str = "vuln,secret,license",
        scan_type: str = "fs",
        native_config: Optional[Path] = None
    ):
        """
        Initialize Trivy scanner with auto-install support.

        Args:
            target_path: Path to scan (directory) or image name
            timeout: Timeout in seconds
            extra_flags: Additional CLI flags
            security_checks: Comma-separated list of checks (vuln,secret,config,license)
            scan_type: Type of scan - "fs" (filesystem) or "image" (Docker image)
            native_config: Path to trivy.yaml config file (overrides YAVS settings)
        """
        super().__init__(target_path, timeout, extra_flags, native_config)
        self._trivy_path: Optional[str] = None
        self.security_checks = security_checks
        self.scan_type = scan_type

        if scan_type not in ["fs", "image"]:
            raise ValueError(f"Invalid scan_type: {scan_type}. Must be 'fs' or 'image'")

    @property
    def tool_name(self) -> str:
        return "trivy"

    @property
    def category(self) -> str:
        return "dependency"

    def check_available(self) -> bool:
        """Check if Trivy is available, install if necessary."""
        # Try to ensure Trivy is available (with auto-install)
        self._trivy_path = ensure_trivy(auto_install=True, ask_consent=True)
        return self._trivy_path is not None

    def get_command(self) -> str:
        """
        Build Trivy command using managed binary if needed.

        Configuration precedence (Trivy's native behavior):
        1. CLI flags (highest priority) - YAVS extra_flags
        2. Config file - native_config
        3. Environment variables
        4. Built-in defaults (lowest priority)

        This means:
        - YAVS provides baseline settings via CLI flags
        - Native config extends/overrides those settings
        - Extra flags can override everything
        """
        # Use the specific trivy path if we have one
        trivy_cmd = self._trivy_path if self._trivy_path else "trivy"

        # Build base command with YAVS defaults
        if self.scan_type == "image":
            # For image scanning, target_path is the image name
            base_cmd = f"{trivy_cmd} image --security-checks {self.security_checks} --format json"
        else:
            # For filesystem scanning
            base_cmd = f"{trivy_cmd} fs --security-checks {self.security_checks} --format json"

        # Add native config if provided (extends YAVS settings)
        # Trivy will merge config file with CLI flags (CLI flags win)
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using Trivy native config: {self.native_config} (extends YAVS settings)")
            base_cmd += f" --config {self.native_config}"

        # Add extra flags last (highest priority - can override everything)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        # Add target
        if self.scan_type == "image":
            base_cmd += f" {self.target_path}"
        else:
            base_cmd += " ."

        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Trivy JSON output into normalized format.

        Trivy output structure:
        {
            "Results": [
                {
                    "Target": "path/to/file",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.19.0",
                            "FixedVersion": "2.20.0",
                            "Severity": "HIGH",
                            "Title": "CVE title",
                            "Description": "..."
                        }
                    ],
                    "Secrets": [...],
                    "Misconfigurations": [...]
                }
            ]
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "unknown")

            # Process vulnerabilities
            vulnerabilities = result.get("Vulnerabilities") or []
            for vuln in vulnerabilities:
                finding = {
                    "tool": self.tool_name,
                    "category": "dependency",
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "file": target,
                    "message": vuln.get("Title") or vuln.get("VulnerabilityID", "Unknown vulnerability"),
                    "rule_id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "description": vuln.get("Description"),
                }
                findings.append(finding)

            # Process secrets
            secrets = result.get("Secrets") or []
            for secret in secrets:
                finding = {
                    "tool": self.tool_name,
                    "category": "secret",
                    "severity": secret.get("Severity", "HIGH").upper(),
                    "file": target,
                    "line": secret.get("StartLine"),
                    "message": f"Secret detected: {secret.get('Title', 'Unknown secret type')}",
                    "rule_id": secret.get("RuleID"),
                }
                findings.append(finding)

            # Process misconfigurations
            misconfigs = result.get("Misconfigurations") or []
            for misconfig in misconfigs:
                finding = {
                    "tool": self.tool_name,
                    "category": "config",
                    "severity": misconfig.get("Severity", "MEDIUM").upper(),
                    "file": target,
                    "line": misconfig.get("CauseMetadata", {}).get("StartLine"),
                    "message": misconfig.get("Title") or misconfig.get("ID", "Configuration issue"),
                    "rule_id": misconfig.get("ID"),
                    "description": misconfig.get("Description"),
                }
                findings.append(finding)

            # Process licenses
            licenses = result.get("Licenses") or []
            for license_finding in licenses:
                # Only report problematic licenses (e.g., GPL, restrictive)
                severity = license_finding.get("Severity", "LOW").upper()
                if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    finding = {
                        "tool": self.tool_name,
                        "category": "license",
                        "severity": severity,
                        "file": target,
                        "message": f"License issue: {license_finding.get('Name', 'Unknown license')}",
                        "rule_id": license_finding.get("Name"),
                        "package": license_finding.get("PkgName"),
                        "description": f"Package {license_finding.get('PkgName')} uses {license_finding.get('Name')} license",
                    }
                    findings.append(finding)

        return findings
