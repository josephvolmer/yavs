"""SBOM (Software Bill of Materials) generator using Trivy."""

import subprocess
from typing import Optional, Dict, Any
from pathlib import Path

from ..utils.logging import LoggerMixin
from ..utils.scanner_installer import ensure_trivy


class SBOMGenerator(LoggerMixin):
    """
    Generate SBOM using Trivy.

    Supports CycloneDX and SPDX formats.
    """

    def __init__(
        self,
        target_path: Path,
        format: str = "cyclonedx",
        timeout: int = 300
    ):
        """
        Initialize SBOM generator.

        Args:
            target_path: Path to scan
            format: SBOM format ('cyclonedx' or 'spdx')
            timeout: Command timeout in seconds
        """
        self.target_path = Path(target_path)
        self.format = format.lower()
        self.timeout = timeout
        self._trivy_path: Optional[str] = None

        if self.format not in ["cyclonedx", "spdx"]:
            raise ValueError(f"Unsupported SBOM format: {format}")

    def check_available(self) -> bool:
        """Check if Trivy is available for SBOM generation."""
        self._trivy_path = ensure_trivy(auto_install=True, ask_consent=True)
        return self._trivy_path is not None

    def generate(self, output_path: Path) -> Dict[str, Any]:
        """
        Generate SBOM and write to file.

        Args:
            output_path: Path where SBOM will be written

        Returns:
            Metadata about the generated SBOM
        """
        if not self.check_available():
            raise RuntimeError("Trivy is not available for SBOM generation")

        output_path = Path(output_path).resolve()  # Convert to absolute path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine format flag
        if self.format == "cyclonedx":
            format_flag = "cyclonedx"
        else:
            format_flag = "spdx-json"

        # Build command
        trivy_cmd = self._trivy_path if self._trivy_path else "trivy"
        cmd = [
            trivy_cmd,
            "fs",
            "--format", format_flag,
            "--output", str(output_path),  # Now absolute path
            str(self.target_path)
        ]

        self.logger.info(f"Generating {self.format.upper()} SBOM...")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.target_path,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode != 0:
                self.logger.error(f"SBOM generation failed: {result.stderr}")
                raise RuntimeError(f"Trivy SBOM generation failed: {result.stderr}")

            # Verify output was created
            if not output_path.exists():
                raise RuntimeError(f"SBOM file was not created at {output_path}")

            # Get file size
            size_bytes = output_path.stat().st_size

            self.logger.info(f"SBOM generated: {output_path} ({size_bytes} bytes)")

            return {
                "format": self.format.upper(),
                "location": str(output_path),
                "size_bytes": size_bytes,
                "tool": "trivy"
            }

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"SBOM generation timed out after {self.timeout}s")
        except Exception as e:
            raise RuntimeError(f"SBOM generation failed: {str(e)}")
