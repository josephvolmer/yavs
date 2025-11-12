"""
Tool version management for YAVS scanner dependencies.

This module defines tested and compatible version ranges for all external
scanner tools used by YAVS. Each YAVS release ships with tested versions
that are known to work correctly with YAVS's output parsing and features.

Version Strategy:
- 'tested': Known working version shipped with YAVS
- 'min': Minimum compatible version
- 'max': Maximum compatible version (allows patches within minor version)

Users can:
- Install tested versions (default): yavs tools install
- Upgrade within safe ranges: yavs tools upgrade
- Override to specific versions: yavs tools install --tool <name> --version <ver>
"""

from typing import Dict, Optional, Tuple
from packaging import version as pkg_version


# Tool version definitions
# Updated: November 2025
TOOL_VERSIONS = {
    "trivy": {
        "tested": "0.67.2",      # Latest stable as of Nov 2025
        "min": "0.55.0",         # Minimum compatible
        "max": "0.67.999",       # Allow patches in 0.67.x
        "description": "Comprehensive vulnerability scanner for containers, IaC, and dependencies",
    },
    "semgrep": {
        "tested": "1.142.1",     # Latest stable as of Nov 2025
        "min": "1.140.0",        # Minimum compatible
        "max": "1.142.999",      # Allow patches in 1.142.x
        "description": "Static analysis tool for finding bugs and enforcing code standards",
    },
    "bandit": {
        "tested": "1.8.6",       # Latest stable as of July 2025
        "min": "1.7.0",          # Minimum compatible
        "max": "1.8.999",        # Allow patches in 1.8.x
        "description": "Security linter for Python code",
    },
    "checkov": {
        "tested": "3.2.492",     # Latest stable as of Nov 2025
        "min": "3.2.0",          # Minimum compatible
        "max": "3.2.999",        # Allow patches in 3.2.x
        "description": "Static code analysis tool for IaC misconfigurations",
    },
    "binskim": {
        "tested": None,          # User-installed via dotnet
        "min": None,
        "max": None,
        "description": "Binary static analysis tool for Windows binaries (optional)",
    },
}


def get_tested_version(tool: str) -> Optional[str]:
    """
    Get the tested version for a tool.

    Args:
        tool: Tool name (trivy, semgrep, bandit, checkov, binskim)

    Returns:
        Tested version string or None if tool not found or not versioned
    """
    tool_info = TOOL_VERSIONS.get(tool.lower())
    if not tool_info:
        return None
    return tool_info.get("tested")


def get_version_range(tool: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Get the compatible version range for a tool.

    Args:
        tool: Tool name

    Returns:
        Tuple of (min_version, max_version), both may be None
    """
    tool_info = TOOL_VERSIONS.get(tool.lower())
    if not tool_info:
        return (None, None)
    return (tool_info.get("min"), tool_info.get("max"))


def is_version_compatible(tool: str, installed_version: str) -> Tuple[bool, str]:
    """
    Check if an installed tool version is compatible with YAVS.

    Args:
        tool: Tool name
        installed_version: Version string to check

    Returns:
        Tuple of (is_compatible, message)
    """
    tool_info = TOOL_VERSIONS.get(tool.lower())
    if not tool_info:
        return (True, f"Unknown tool: {tool}")

    min_ver = tool_info.get("min")
    max_ver = tool_info.get("max")
    tested_ver = tool_info.get("tested")

    # If no version constraints, assume compatible
    if not min_ver and not max_ver:
        return (True, f"{tool} version {installed_version} (not version-managed)")

    try:
        installed = pkg_version.parse(installed_version)

        # Check if within range
        in_range = True
        if min_ver:
            in_range = in_range and installed >= pkg_version.parse(min_ver)
        if max_ver:
            in_range = in_range and installed <= pkg_version.parse(max_ver)

        if not in_range:
            return (
                False,
                f"{tool} version {installed_version} is outside tested range "
                f"({min_ver} to {max_ver}). Tested version: {tested_ver}"
            )

        # Check if it's the tested version
        if installed == pkg_version.parse(tested_ver):
            return (True, f"{tool} version {installed_version} (tested)")

        # Within range but not tested version
        return (
            True,
            f"{tool} version {installed_version} is compatible "
            f"(tested: {tested_ver}, range: {min_ver} to {max_ver})"
        )

    except Exception as e:
        return (False, f"Error parsing {tool} version {installed_version}: {str(e)}")


def get_pip_version_specifier(tool: str) -> str:
    """
    Get pip version specifier for a tool (e.g., "semgrep>=1.140.0,<1.143.0").

    Args:
        tool: Tool name

    Returns:
        Version specifier string for pip install
    """
    tool_info = TOOL_VERSIONS.get(tool.lower())
    if not tool_info:
        return tool  # Just the tool name

    tested = tool_info.get("tested")
    min_ver = tool_info.get("min")
    max_ver = tool_info.get("max")

    # For exact version installation (tested)
    if tested:
        # Calculate max from tested version (allow patches in same minor)
        parts = tested.split(".")
        if len(parts) >= 2:
            # e.g., "1.142.1" -> "1.142.999"
            max_minor = f"{parts[0]}.{parts[1]}.999"
            return f"{tool}>={tested},<={max_minor}"

    # Fallback to min/max if available
    if min_ver and max_ver:
        return f"{tool}>={min_ver},<={max_ver}"
    elif min_ver:
        return f"{tool}>={min_ver}"

    return tool


def get_all_tools() -> list:
    """
    Get list of all managed tools.

    Returns:
        List of tool names
    """
    return list(TOOL_VERSIONS.keys())


def get_tool_description(tool: str) -> Optional[str]:
    """
    Get description for a tool.

    Args:
        tool: Tool name

    Returns:
        Description string or None
    """
    tool_info = TOOL_VERSIONS.get(tool.lower())
    if not tool_info:
        return None
    return tool_info.get("description")
