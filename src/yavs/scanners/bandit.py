"""Bandit scanner for Python Static Application Security Testing (SAST)."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class BanditScanner(BaseScanner):
    """
    Bandit scanner integration for Python SAST.

    Detects:
    - Hardcoded passwords
    - SQL injection vulnerabilities
    - Shell injection vulnerabilities
    - Insecure deserialization
    - Use of insecure cryptographic functions
    - Common security issues in Python code
    """

    @property
    def tool_name(self) -> str:
        return "bandit"

    @property
    def category(self) -> str:
        return "sast"

    def get_command(self) -> str:
        """
        Build Bandit command.

        Configuration precedence (Bandit's native behavior):
        1. CLI flags (highest priority) - YAVS extra_flags
        2. Config file - native_config (.bandit)
        3. Built-in defaults (lowest priority)

        This means:
        - YAVS provides baseline settings via CLI flags
        - Native config extends/overrides those settings
        - Extra flags can override everything
        """
        # Build base command with YAVS defaults
        # -r: recursive
        # -f json: JSON output format
        # -q: quiet mode (no progress)
        base_cmd = "bandit -r -f json -q"

        # Add native config if provided (extends YAVS settings)
        # Bandit will merge config file with CLI flags (CLI flags win)
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using Bandit native config: {self.native_config} (extends YAVS settings)")
            base_cmd += f" -c {self.native_config}"

        # Add extra flags last (highest priority - can override everything)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        # Add target
        base_cmd += " ."
        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Bandit JSON output into normalized format.

        Bandit output structure:
        {
            "results": [
                {
                    "code": "123 sql_query = f'SELECT * FROM users WHERE id={user_id}'",
                    "col_offset": 4,
                    "end_col_offset": 60,
                    "filename": "./app/database.py",
                    "issue_confidence": "HIGH",
                    "issue_cwe": {
                        "id": 89,
                        "link": "https://cwe.mitre.org/data/definitions/89.html"
                    },
                    "issue_severity": "MEDIUM",
                    "issue_text": "Use of insecure string formatting for SQL queries...",
                    "line_number": 123,
                    "line_range": [123, 123],
                    "more_info": "https://bandit.readthedocs.io/...",
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions"
                }
            ],
            "metrics": {...}
        }
        """
        if not output or not output.strip():
            return []

        data = self._parse_json_output(output)
        findings = []

        results = data.get("results", [])

        for result in results:
            # Get severity
            severity = result.get("issue_severity", "INFO").upper()

            # Normalize severity values
            if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                severity = "MEDIUM"

            # Get file path and remove leading ./ if present
            file_path = result.get("filename", "")
            if file_path.startswith("./"):
                file_path = file_path[2:]

            # Get line number
            line = result.get("line_number")

            # Get message
            message = result.get("issue_text", "Security issue detected")

            # Get CWE info if available
            cwe_info = result.get("issue_cwe", {})
            cwe_id = cwe_info.get("id")
            cwe_link = cwe_info.get("link")

            # Build description
            description_parts = []
            if cwe_id:
                description_parts.append(f"CWE-{cwe_id}")
            if cwe_link:
                description_parts.append(f"Link: {cwe_link}")

            more_info = result.get("more_info")
            if more_info:
                description_parts.append(f"More info: {more_info}")

            description = " | ".join(description_parts) if description_parts else None

            finding = {
                "tool": self.tool_name,
                "category": self.category,
                "severity": severity,
                "file": file_path,
                "line": line,
                "message": message,
                "rule_id": result.get("test_id"),
                "description": description,
            }

            # Add Bandit-specific metadata
            finding["metadata"] = {
                "test_name": result.get("test_name"),
                "confidence": result.get("issue_confidence"),
                "cwe": cwe_id,
                "line_range": result.get("line_range"),
                "code": result.get("code"),
            }

            findings.append(finding)

        return findings
