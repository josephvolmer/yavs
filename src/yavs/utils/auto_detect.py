"""
Auto-Detect Module

Intelligently detects project type and recommends appropriate scanners.
"""

from pathlib import Path
from typing import Set, Dict, List
import logging

logger = logging.getLogger(__name__)


def detect_project_type(target_path: Path) -> Set[str]:
    """
    Auto-detect scanners based on project structure.

    Args:
        target_path: Directory to analyze

    Returns:
        Set of recommended scanner names
    """
    scanners = set()

    if not target_path.is_dir():
        logger.warning(f"Target path is not a directory: {target_path}")
        return scanners

    # Python projects
    if any([
        (target_path / "requirements.txt").exists(),
        (target_path / "pyproject.toml").exists(),
        (target_path / "setup.py").exists(),
        (target_path / "Pipfile").exists(),
        (target_path / "poetry.lock").exists(),
        any(target_path.glob("**/*.py"))
    ]):
        scanners.add("bandit")
        scanners.add("semgrep")
        logger.info("Detected Python project")

    # JavaScript/TypeScript/Node.js
    if any([
        (target_path / "package.json").exists(),
        (target_path / "package-lock.json").exists(),
        (target_path / "yarn.lock").exists(),
        (target_path / "pnpm-lock.yaml").exists(),
        any(target_path.glob("**/*.js")),
        any(target_path.glob("**/*.ts"))
    ]):
        scanners.add("semgrep")
        scanners.add("trivy")  # For npm dependencies
        logger.info("Detected JavaScript/TypeScript project")

    # Go projects
    if any([
        (target_path / "go.mod").exists(),
        (target_path / "go.sum").exists(),
        any(target_path.glob("**/*.go"))
    ]):
        scanners.add("semgrep")
        scanners.add("trivy")
        logger.info("Detected Go project")

    # Java projects
    if any([
        (target_path / "pom.xml").exists(),
        (target_path / "build.gradle").exists(),
        (target_path / "build.gradle.kts").exists(),
        any(target_path.glob("**/*.java"))
    ]):
        scanners.add("semgrep")
        scanners.add("trivy")
        logger.info("Detected Java project")

    # .NET/C# projects
    if any([
        any(target_path.glob("**/*.csproj")),
        any(target_path.glob("**/*.sln")),
        any(target_path.glob("**/*.cs")),
        (target_path / "packages.config").exists()
    ]):
        scanners.add("semgrep")
        scanners.add("binskim")  # .NET binary analysis
        logger.info("Detected .NET/C# project")

    # Ruby projects
    if any([
        (target_path / "Gemfile").exists(),
        (target_path / "Gemfile.lock").exists(),
        any(target_path.glob("**/*.rb"))
    ]):
        scanners.add("semgrep")
        scanners.add("trivy")
        logger.info("Detected Ruby project")

    # IaC - Terraform
    if any(target_path.glob("**/*.tf")) or any(target_path.glob("**/*.tfvars")):
        scanners.add("checkov")
        scanners.add("terrascan")
        logger.info("Detected Terraform files")

    # IaC - CloudFormation
    cf_patterns = [
        "**/*cloudformation*.yaml",
        "**/*cloudformation*.yml",
        "**/*cloudformation*.json",
        "**/template.yaml",
        "**/template.yml"
    ]
    for pattern in cf_patterns:
        if any(target_path.glob(pattern)):
            scanners.add("checkov")
            scanners.add("terrascan")
            logger.info("Detected CloudFormation templates")
            break

    # IaC - Kubernetes
    k8s_indicators = ["kind:", "apiVersion:", "metadata:"]
    for yaml_file in list(target_path.glob("**/*.yaml")) + list(target_path.glob("**/*.yml")):
        try:
            content = yaml_file.read_text()
            if any(indicator in content for indicator in k8s_indicators):
                scanners.add("checkov")
                scanners.add("terrascan")
                logger.info("Detected Kubernetes manifests")
                break
        except:
            pass

    # IaC - Docker
    if any([
        (target_path / "Dockerfile").exists(),
        any(target_path.glob("**/Dockerfile")),
        any(target_path.glob("**/*.dockerfile")),
        (target_path / "docker-compose.yml").exists(),
        (target_path / "docker-compose.yaml").exists()
    ]):
        scanners.add("trivy")
        logger.info("Detected Docker files")

    # IaC - Azure ARM/Bicep
    has_bicep = any(target_path.glob("**/*.bicep"))
    has_arm = False
    # Check for ARM templates (JSON with $schema)
    for json_file in target_path.glob("**/*.json"):
        try:
            content = json_file.read_text()
            if '"$schema"' in content and 'deploymentTemplate' in content:
                has_arm = True
                break
        except:
            pass

    if has_bicep or has_arm:
        scanners.add("template-analyzer")
        logger.info("Detected Azure ARM/Bicep templates")

    # Always suggest trivy for dependency scanning if package files exist
    package_files = [
        "package.json", "requirements.txt", "go.mod", "pom.xml",
        "build.gradle", "Gemfile", "Cargo.toml", "composer.json"
    ]
    if any((target_path / pf).exists() for pf in package_files):
        scanners.add("trivy")
        logger.info("Detected package manager files - recommending Trivy")

    return scanners


def get_scanner_categories(scanners: Set[str]) -> Dict[str, bool]:
    """
    Map detected scanners to scan mode categories.

    Args:
        scanners: Set of scanner names

    Returns:
        Dictionary mapping scan modes to boolean values
    """
    categories = {
        "sast": False,
        "sbom": False,
        "compliance": False,
        "secrets": False
    }

    # Map scanners to categories
    if any(s in scanners for s in ["semgrep", "bandit", "binskim"]):
        categories["sast"] = True

    if "trivy" in scanners:
        categories["sbom"] = True
        categories["secrets"] = True

    if "checkov" in scanners:
        categories["compliance"] = True

    return categories


def get_recommended_flags(target_path: Path) -> List[str]:
    """
    Get recommended CLI flags based on detected project type.

    Args:
        target_path: Directory to analyze

    Returns:
        List of recommended CLI flags
    """
    scanners = detect_project_type(target_path)
    categories = get_scanner_categories(scanners)

    flags = []

    if categories["sast"]:
        flags.append("--sast")

    if categories["sbom"]:
        flags.append("--sbom")

    if categories["compliance"]:
        flags.append("--compliance")

    # If multiple categories detected, suggest --all
    active_count = sum(1 for v in categories.values() if v)
    if active_count >= 2:
        flags = ["--all"]

    return flags
