"""Base scanner class for all vulnerability scanners."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from ..utils.subprocess_runner import run_command, check_tool_available, CommandExecutionError
from ..utils.path_utils import normalize_path
from ..utils.logging import LoggerMixin


class ScannerError(Exception):
    """Base exception for scanner errors."""
    pass


class BaseScanner(ABC, LoggerMixin):
    """
    Abstract base class for all security scanners.

    Each scanner must implement:
    - get_command(): Return the command to execute
    - parse_output(): Parse scanner output into unified format
    """

    # Class-level severity mapping (can be overridden by config)
    _severity_mapping: Optional[Dict[str, str]] = None

    @classmethod
    def set_severity_mapping(cls, mapping: Dict[str, str]):
        """
        Set the global severity mapping for all scanners.

        Args:
            mapping: Dictionary mapping scanner severities to YAVS severities
        """
        cls._severity_mapping = mapping

    def __init__(
        self,
        target_path: Path,
        timeout: int = 300,
        extra_flags: str = "",
        native_config: Optional[Path] = None
    ):
        """
        Initialize scanner.

        Args:
            target_path: Path to scan
            timeout: Maximum execution time in seconds
            extra_flags: Additional command-line flags
            native_config: Path to tool's native config file (overrides YAVS settings)
        """
        self.target_path = normalize_path(target_path)
        self.timeout = timeout
        self.extra_flags = extra_flags
        self.native_config = Path(native_config) if native_config else None
        self._raw_output: Optional[str] = None
        self._results: List[Dict[str, Any]] = []

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the scanner tool."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """
        Return the category of findings this scanner produces.

        Options: dependency, sast, compliance, secret
        """
        pass

    @abstractmethod
    def get_command(self) -> str:
        """
        Build the command to execute the scanner.

        Returns:
            Command string to execute
        """
        pass

    @abstractmethod
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse scanner output into normalized YAVS format.

        Expected format for each finding:
        {
            "tool": str,           # Scanner name
            "category": str,       # Finding category
            "severity": str,       # CRITICAL, HIGH, MEDIUM, LOW, INFO
            "file": str,           # Affected file path
            "line": int,           # Line number (optional)
            "message": str,        # Human-readable description
            "rule_id": str,        # Rule/CVE identifier (optional)
            "package": str,        # Package name (for dependency scanners)
            "version": str,        # Package version (for dependency scanners)
            "fixed_version": str,  # Fixed version (optional)
        }

        Args:
            output: Raw scanner output

        Returns:
            List of normalized findings
        """
        pass

    def check_available(self) -> bool:
        """
        Check if the scanner tool is available.

        Returns:
            True if available, False otherwise
        """
        return check_tool_available(self.tool_name)

    def run(self) -> List[Dict[str, Any]]:
        """
        Execute the scanner and return normalized results.

        Returns:
            List of normalized findings

        Raises:
            ScannerError: If scanner execution fails
        """
        if not self.check_available():
            raise ScannerError(
                f"{self.tool_name} is not installed or not in PATH. "
                f"Please install it first."
            )

        if not self.target_path.exists():
            raise ScannerError(f"Target path does not exist: {self.target_path}")

        self.logger.info(f"Running {self.tool_name} on {self.target_path}")

        try:
            command = self.get_command()
            self.logger.debug(f"Executing: {command}")

            returncode, stdout, stderr = run_command(
                command,
                cwd=self.target_path,
                timeout=self.timeout,
                check=False  # Some scanners return non-zero on findings
            )

            self._raw_output = stdout

            # Parse output
            self._results = self.parse_output(stdout)

            self.logger.info(
                f"{self.tool_name} found {len(self._results)} finding(s)"
            )

            return self._results

        except CommandExecutionError as e:
            # Some scanners might return non-zero even on success
            # Try to parse anyway
            if e.returncode != 0 and self._raw_output:
                try:
                    self._results = self.parse_output(self._raw_output)
                    return self._results
                except Exception:
                    pass

            raise ScannerError(
                f"{self.tool_name} execution failed: {str(e)}"
            ) from e

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the cached results from the last run.

        Returns:
            List of normalized findings
        """
        return self._results

    def get_raw_output(self) -> Optional[str]:
        """
        Get the raw scanner output.

        Returns:
            Raw output string or None if not yet run
        """
        return self._raw_output

    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """
        Helper method to parse JSON output safely.

        Args:
            output: JSON string

        Returns:
            Parsed JSON data

        Raises:
            ScannerError: If JSON parsing fails
        """
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            raise ScannerError(
                f"Failed to parse {self.tool_name} JSON output: {str(e)}"
            ) from e

    def normalize_severity(self, severity: str) -> str:
        """
        Normalize severity level using configured severity mapping.

        Args:
            severity: Original severity level from scanner

        Returns:
            Normalized severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        if not self._severity_mapping:
            # No mapping configured, use default normalization
            severity = severity.upper()
            if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                return severity
            return "LOW"  # Default for unknown severities

        # Use configured mapping
        return self._severity_mapping.get(severity,
            self._severity_mapping.get(severity.upper(),
                self._severity_mapping.get(severity.lower(), "LOW")))
