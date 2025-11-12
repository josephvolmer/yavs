"""
Git Blame Module

Provides git blame attribution for findings to enable team accountability.
"""

import subprocess
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def get_git_blame(file_path: Path, line_number: int, repo_root: Optional[Path] = None) -> Optional[Dict]:
    """
    Get git blame information for a specific file and line.

    Args:
        file_path: Path to the file
        line_number: Line number to blame
        repo_root: Repository root directory (for relative path calculation)

    Returns:
        Dictionary with: commit, author, email, date, subject
        None if git blame fails or file is not in git
    """
    try:
        # Make file_path relative to repo root if provided
        if repo_root:
            try:
                file_path = file_path.relative_to(repo_root)
            except ValueError:
                # File is outside repo root, use absolute path
                pass

        # Run git blame with porcelain format for easy parsing
        result = subprocess.run(
            ["git", "blame", "-L", f"{line_number},{line_number}",
             "--porcelain", str(file_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            cwd=repo_root if repo_root else file_path.parent
        )

        if result.returncode != 0:
            return None

        # Parse porcelain output
        lines = result.stdout.split('\n')
        if not lines:
            return None

        # First line contains commit hash
        commit = lines[0].split()[0]
        blame_info = {'commit': commit}

        # Parse metadata lines
        for line in lines[1:]:
            if line.startswith('author '):
                blame_info['author'] = line.replace('author ', '', 1)
            elif line.startswith('author-mail '):
                email = line.replace('author-mail ', '', 1)
                blame_info['email'] = email.strip('<>')
            elif line.startswith('author-time '):
                timestamp = int(line.replace('author-time ', '', 1))
                blame_info['date'] = datetime.fromtimestamp(timestamp).isoformat()
            elif line.startswith('summary '):
                blame_info['subject'] = line.replace('summary ', '', 1)

        return blame_info

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"Git blame failed for {file_path}:{line_number}: {e}")
        return None


def is_git_repository(path: Path) -> bool:
    """
    Check if path is within a git repository.

    Args:
        path: Directory path to check

    Returns:
        True if path is in a git repository
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=path if path.is_dir() else path.parent,
            capture_output=True,
            timeout=2,
            check=False
        )
        return result.returncode == 0
    except:
        return False


def get_git_root(path: Path) -> Optional[Path]:
    """
    Get root directory of git repository.

    Args:
        path: Any path within the repository

    Returns:
        Path to repository root, or None if not in a git repo
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=path if path.is_dir() else path.parent,
            capture_output=True,
            text=True,
            timeout=2,
            check=False
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except:
        pass
    return None


def enrich_findings_with_blame(findings: list, repo_root: Path) -> list:
    """
    Add git blame information to findings.

    Args:
        findings: List of finding dictionaries
        repo_root: Repository root directory

    Returns:
        List of findings enriched with git_blame field
    """
    if not is_git_repository(repo_root):
        logger.debug(f"{repo_root} is not a git repository, skipping blame enrichment")
        return findings

    enriched = []
    for finding in findings:
        file_path = finding.get('file')
        line = finding.get('line')

        if file_path and line:
            # Handle both absolute and relative paths
            full_path = Path(file_path)
            if not full_path.is_absolute():
                full_path = repo_root / file_path

            if full_path.exists():
                blame_info = get_git_blame(full_path, line, repo_root)
                if blame_info:
                    finding['git_blame'] = blame_info

        enriched.append(finding)

    return enriched
