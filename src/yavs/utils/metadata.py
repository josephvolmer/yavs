"""Project metadata extraction utilities."""

import subprocess
from pathlib import Path
from typing import Optional
from datetime import datetime


def get_git_commit_hash(project_path: Path) -> Optional[str]:
    """
    Get the current git commit hash.

    Args:
        project_path: Path to the project

    Returns:
        Commit hash or None if not a git repo
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_git_branch(project_path: Path) -> Optional[str]:
    """
    Get the current git branch name.

    Args:
        project_path: Path to the project

    Returns:
        Branch name or None if not a git repo
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_project_name(project_path: Path) -> str:
    """
    Get the project name from the directory.

    Args:
        project_path: Path to the project

    Returns:
        Project name (directory name)
    """
    return project_path.resolve().name


def get_build_timestamp() -> str:
    """
    Get the current UTC timestamp in ISO format.

    Returns:
        ISO 8601 timestamp with Z suffix
    """
    return datetime.utcnow().isoformat() + "Z"


def extract_project_metadata(
    project_path: Path,
    project_name: Optional[str] = None,
    branch: Optional[str] = None,
    commit_hash: Optional[str] = None
) -> dict:
    """
    Extract all project metadata.

    Args:
        project_path: Path to the project
        project_name: Optional project name override (auto-detect if None)
        branch: Optional branch name override (auto-detect if None)
        commit_hash: Optional commit hash override (auto-detect if None)

    Returns:
        Dictionary with project metadata
    """
    project_path = Path(project_path)

    metadata = {
        "project": project_name if project_name else get_project_name(project_path),
        "build_cycle": get_build_timestamp(),
        "commit_hash": commit_hash if commit_hash else get_git_commit_hash(project_path),
        "branch": branch if branch else get_git_branch(project_path),
        "project_path": str(project_path.resolve())
    }

    return metadata
