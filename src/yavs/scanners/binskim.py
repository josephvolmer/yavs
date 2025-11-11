"""BinSkim scanner for binary security analysis."""

from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner


class BinSkimScanner(BaseScanner):
    """
    BinSkim scanner integration for binary security analysis.

    Analyzes:
    - Windows PE (Portable Executable) files
    - *nix ELF (Executable and Linkable Format) files

    Detects:
    - Insecure compiler settings
    - Missing security mitigations (DEP, ASLR, etc.)
    - Outdated compiler toolsets
    - Weak cryptographic signing
    - Missing or incorrect security flags
    """

    @property
    def tool_name(self) -> str:
        return "binskim"

    @property
    def category(self) -> str:
        return "sast"

    def get_command(self) -> str:
        """
        Build BinSkim command.

        Configuration precedence (BinSkim's native behavior):
        1. CLI flags (highest priority) - YAVS extra_flags
        2. Config file - native_config (.gdnconfig)
        3. Built-in defaults (lowest priority)

        This means:
        - YAVS provides baseline settings via CLI flags
        - Native config extends/overrides those settings
        - Extra flags can override everything
        """
        # Build base command with YAVS defaults
        # BinSkim analyzes binaries in the target directory
        # Output SARIF format
        base_cmd = "binskim analyze --output binskim-results.sarif --sarif-output-version 2.1.0 --recurse"

        # Add native config if provided (extends YAVS settings)
        # BinSkim will merge config file with CLI flags (CLI flags win)
        if self.native_config and self.native_config.exists():
            self.logger.info(f"Using BinSkim native config: {self.native_config} (extends YAVS settings)")
            base_cmd += f" --config {self.native_config}"

        # Add extra flags last (highest priority - can override everything)
        if self.extra_flags:
            base_cmd += f" {self.extra_flags}"

        # Analyze all binaries in current directory
        base_cmd += " ."
        return base_cmd

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse BinSkim SARIF output into normalized format.

        SARIF 2.1.0 structure:
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BinSkim",
                            "version": "..."
                        }
                    },
                    "results": [
                        {
                            "ruleId": "BA2002",
                            "level": "error",
                            "message": {
                                "text": "..."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "file:///path/to/binary.exe"
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        """
        # BinSkim writes to a SARIF file instead of stdout
        # We need to read the SARIF file
        sarif_path = self.target_path / "binskim-results.sarif"

        if not sarif_path.exists():
            # If no SARIF file, check if output contains JSON
            if output and output.strip():
                try:
                    data = self._parse_json_output(output)
                    return self._parse_sarif_data(data)
                except Exception:
                    return []
            return []

        try:
            with open(sarif_path, 'r') as f:
                data = self._parse_json_output(f.read())
            return self._parse_sarif_data(data)
        except Exception as e:
            self.logger.warning(f"Failed to parse BinSkim SARIF output: {e}")
            return []

    def _parse_sarif_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse SARIF data structure into normalized findings."""
        findings = []

        runs = data.get("runs", [])
        for run in runs:
            results = run.get("results", [])

            for result in results:
                # Get severity from SARIF level
                level = result.get("level", "warning")
                severity = self.normalize_severity(level)

                # Get message
                message_obj = result.get("message", {})
                message = message_obj.get("text", "Binary security issue detected")

                # Get file path from locations
                locations = result.get("locations", [])
                file_path = "unknown"
                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    artifact_loc = phys_loc.get("artifactLocation", {})
                    uri = artifact_loc.get("uri", "")

                    # Clean up file:/// prefix and convert to relative path
                    if uri.startswith("file:///"):
                        file_path = uri[8:]  # Remove file:///
                    elif uri.startswith("file://"):
                        file_path = uri[7:]  # Remove file://
                    else:
                        file_path = uri

                    # Convert to relative path
                    try:
                        file_path = str(Path(file_path).relative_to(self.target_path))
                    except ValueError:
                        # If not relative, just use the filename
                        file_path = Path(file_path).name

                # Get rule ID
                rule_id = result.get("ruleId", "BINSKIM-UNKNOWN")

                # Build description from rule info
                description = None
                rule = result.get("rule")
                if rule:
                    help_text = rule.get("helpUri")
                    if help_text:
                        description = f"Help: {help_text}"

                finding = {
                    "tool": self.tool_name,
                    "category": self.category,
                    "severity": severity,
                    "file": file_path,
                    "line": None,  # Binary analysis doesn't have line numbers
                    "message": message,
                    "rule_id": rule_id,
                    "description": description,
                }

                # Add SARIF-specific metadata
                finding["metadata"] = {
                    "sarif_level": level,
                    "kind": result.get("kind", "fail"),
                }

                findings.append(finding)

        return findings
