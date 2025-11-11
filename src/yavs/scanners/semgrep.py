"""Semgrep scanner for Static Application Security Testing (SAST)."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class SemgrepScanner(BaseScanner):
    """
    Semgrep scanner integration for SAST.

    Detects:
    - Code quality issues
    - Security vulnerabilities
    - Common coding mistakes
    - Dangerous patterns
    """

    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def category(self) -> str:
        return "sast"

    def get_command(self) -> str:
        """
        Build Semgrep command.

        Configuration precedence (Semgrep's native behavior):
        1. CLI flags (highest priority) - YAVS extra_flags
        2. Config file - native_config
        3. Built-in defaults (lowest priority)

        This means:
        - YAVS provides baseline settings via CLI flags
        - Native config extends/overrides those settings
        - Extra flags can override everything
        """
        # Build base command with YAVS defaults
        base_cmd = "semgrep --json --quiet"

        # Determine config: native_config, extra_flags, or auto
        if self.native_config and self.native_config.exists():
            # Use native config (extends YAVS settings)
            self.logger.info(f"Using Semgrep native config: {self.native_config} (extends YAVS settings)")
            base_cmd += f" --config {self.native_config}"
        elif self.extra_flags:
            # Use extra flags (highest priority - can override everything)
            base_cmd += f" {self.extra_flags}"
        else:
            # Use auto config to get registry rules (YAVS baseline)
            base_cmd += " --config=auto"

        # Add target
        base_cmd += " ."
        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Semgrep JSON output into normalized format.

        Semgrep output structure:
        {
            "results": [
                {
                    "check_id": "python.lang.security.injection.sql.sql-injection",
                    "path": "src/main.py",
                    "start": {"line": 42, "col": 10},
                    "end": {"line": 42, "col": 50},
                    "extra": {
                        "message": "Potential SQL injection vulnerability",
                        "severity": "ERROR",
                        "metadata": {...}
                    }
                }
            ]
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        results = data.get("results", [])

        for result in results:
            # Extract severity from extra metadata
            extra = result.get("extra", {})
            severity = extra.get("severity", "INFO")

            # Normalize severity using global mapping
            normalized_severity = self.normalize_severity(severity)

            # Get message
            message = extra.get("message", "Security issue detected")

            # Get metadata if available
            metadata = extra.get("metadata", {})
            cwe = metadata.get("cwe")
            owasp = metadata.get("owasp")

            # Build description
            description_parts = []
            if cwe:
                description_parts.append(f"CWE: {cwe}")
            if owasp:
                description_parts.append(f"OWASP: {', '.join(owasp) if isinstance(owasp, list) else owasp}")

            description = " | ".join(description_parts) if description_parts else None

            finding = {
                "tool": self.tool_name,
                "category": self.category,
                "severity": normalized_severity,
                "file": result.get("path"),
                "line": result.get("start", {}).get("line"),
                "message": message,
                "rule_id": result.get("check_id"),
                "description": description,
            }

            # Add additional metadata
            if metadata:
                finding["metadata"] = {
                    "cwe": cwe,
                    "owasp": owasp,
                    "confidence": metadata.get("confidence"),
                    "likelihood": metadata.get("likelihood"),
                    "impact": metadata.get("impact"),
                }

            findings.append(finding)

        return findings
