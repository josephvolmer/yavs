"""Baseline management for tracking security findings over time."""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime


class FindingFingerprint:
    """
    Generate unique fingerprints for findings to track them across scans.

    A fingerprint is a hash of the key identifying characteristics of a finding:
    - file path
    - line number
    - rule_id
    - severity
    - message (optional, for better precision)
    """

    @staticmethod
    def generate(finding: Dict[str, Any], include_message: bool = False) -> str:
        """
        Generate a unique fingerprint for a finding.

        Args:
            finding: Finding dictionary
            include_message: Include message in fingerprint (more precise but less stable)

        Returns:
            SHA256 hex digest fingerprint
        """
        components = [
            finding.get("file", ""),
            str(finding.get("line", "")),
            finding.get("rule_id", ""),
            finding.get("severity", ""),
            finding.get("tool", ""),
        ]

        if include_message:
            components.append(finding.get("message", ""))

        # Join and hash
        fingerprint_string = "|".join(components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()


class Baseline:
    """Manage security finding baselines."""

    def __init__(self, baseline_path: Path = None):
        """
        Initialize baseline manager.

        Args:
            baseline_path: Path to baseline file
        """
        self.baseline_path = baseline_path
        self.baseline_data: Dict[str, Any] = {}
        self.fingerprints: Set[str] = set()

        if baseline_path and baseline_path.exists():
            self.load(baseline_path)

    def load(self, baseline_path: Path):
        """
        Load baseline from file.

        Args:
            baseline_path: Path to baseline JSON file
        """
        with open(baseline_path, 'r') as f:
            self.baseline_data = json.load(f)

        # Extract fingerprints
        self.fingerprints = set(self.baseline_data.get("fingerprints", []))

        # Also load suppressed findings if present
        suppressed = self.baseline_data.get("suppressed_findings", [])
        self.fingerprints.update(suppressed)

    def generate(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any] = None,
        output_path: Path = None
    ) -> Dict[str, Any]:
        """
        Generate a baseline from current findings.

        Args:
            findings: List of findings to baseline
            metadata: Optional metadata about the scan
            output_path: Optional path to save baseline file

        Returns:
            Baseline dictionary
        """
        # Generate fingerprints for all findings
        fingerprints = [FindingFingerprint.generate(f) for f in findings]

        baseline = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
            "fingerprints": fingerprints,
            "metadata": metadata or {},
            "severity_breakdown": self._calculate_severity_breakdown(findings),
        }

        # Save if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(baseline, f, indent=2)

        self.baseline_data = baseline
        self.fingerprints = set(fingerprints)

        return baseline

    def compare(self, current_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compare current findings against baseline.

        Args:
            current_findings: List of current scan findings

        Returns:
            Comparison results with new, fixed, and existing findings
        """
        if not self.fingerprints:
            raise ValueError("No baseline loaded. Use load() or generate() first.")

        # Generate fingerprints for current findings
        current_fingerprints = {}
        for finding in current_findings:
            fp = FindingFingerprint.generate(finding)
            current_fingerprints[fp] = finding

        current_fps = set(current_fingerprints.keys())

        # Calculate differences
        new_fps = current_fps - self.fingerprints
        fixed_fps = self.fingerprints - current_fps
        existing_fps = current_fps & self.fingerprints

        # Build result lists
        new_findings = [current_fingerprints[fp] for fp in new_fps]
        existing_findings = [current_fingerprints[fp] for fp in existing_fps]

        # Sort by severity
        new_findings = sorted(new_findings, key=lambda x: self._severity_rank(x.get("severity", "LOW")), reverse=True)
        existing_findings = sorted(existing_findings, key=lambda x: self._severity_rank(x.get("severity", "LOW")), reverse=True)

        return {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_fps),
            "existing_count": len(existing_findings),
            "total_current": len(current_findings),
            "total_baseline": len(self.fingerprints),
            "new_findings": new_findings,
            "existing_findings": existing_findings,
            "fixed_fingerprints": list(fixed_fps),
            "comparison_date": datetime.utcnow().isoformat() + "Z",
            "baseline_created": self.baseline_data.get("created_at"),
        }

    def filter_new_only(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter findings to return only new ones not in baseline.

        Args:
            findings: List of findings to filter

        Returns:
            List of findings not present in baseline
        """
        if not self.fingerprints:
            return findings  # No baseline, all findings are "new"

        new_findings = []
        for finding in findings:
            fp = FindingFingerprint.generate(finding)
            if fp not in self.fingerprints:
                new_findings.append(finding)

        return new_findings

    def suppress_findings(self, findings_to_suppress: List[Dict[str, Any]]):
        """
        Add findings to the suppression list in baseline.

        Args:
            findings_to_suppress: Findings to suppress in future scans
        """
        if "suppressed_findings" not in self.baseline_data:
            self.baseline_data["suppressed_findings"] = []

        for finding in findings_to_suppress:
            fp = FindingFingerprint.generate(finding)
            if fp not in self.fingerprints:
                self.fingerprints.add(fp)
                self.baseline_data["suppressed_findings"].append(fp)

    def save(self, output_path: Path):
        """
        Save current baseline to file.

        Args:
            output_path: Path to save baseline
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.baseline_data, f, indent=2)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        """Return numeric rank for severity (higher = more severe)."""
        ranks = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }
        return ranks.get(severity.upper(), 1)

    @staticmethod
    def _calculate_severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown from findings."""
        breakdown = {}
        for finding in findings:
            severity = finding.get("severity", "UNKNOWN").upper()
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown


def diff_scans(
    baseline_path: Path,
    current_path: Path
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Diff two scan result files.

    Args:
        baseline_path: Path to baseline scan results
        current_path: Path to current scan results

    Returns:
        Tuple of (new_findings, fixed_findings, existing_findings)
    """
    # Load both scan results
    with open(baseline_path, 'r') as f:
        baseline_data = json.load(f)

    with open(current_path, 'r') as f:
        current_data = json.load(f)

    # Extract findings from different formats
    baseline_findings = _extract_findings(baseline_data)
    current_findings = _extract_findings(current_data)

    # Use Baseline class for comparison
    baseline = Baseline()
    baseline.generate(baseline_findings)

    comparison = baseline.compare(current_findings)

    return (
        comparison["new_findings"],
        [],  # Fixed findings aren't returned as finding objects, just counts
        comparison["existing_findings"]
    )


def _extract_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract findings from scan results (handles both structured and flat formats).

    Args:
        data: Scan results data

    Returns:
        List of findings
    """
    # Structured format (nested under "findings")
    if "findings" in data and isinstance(data["findings"], dict):
        all_findings = []
        for category_findings in data["findings"].values():
            if isinstance(category_findings, list):
                all_findings.extend(category_findings)
        return all_findings

    # Structured format (categories at top level: sast, compliance, sbom, dependency)
    category_keys = ["sast", "compliance", "sbom", "dependency", "secret", "license", "config"]
    all_findings = []
    for key in category_keys:
        if key in data and isinstance(data[key], list):
            all_findings.extend(data[key])
    if all_findings:
        return all_findings

    # Flat format with data array
    if "data" in data and isinstance(data["data"], list):
        return data["data"]

    # Direct array of findings
    if isinstance(data, list):
        return data

    # Unknown format
    return []
