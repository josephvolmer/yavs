"""Simple unit tests for git blame functionality."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from yavs.utils.git_blame import get_git_blame, is_git_repository, enrich_findings_with_blame


class TestGitBlameSimple:
    """Test git blame functionality with mocks."""

    @patch('yavs.utils.git_blame.subprocess.run')
    def test_get_git_blame_success(self, mock_run):
        """Test successful git blame retrieval."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""abc123def456 1 1 1
author Alice Developer
author-mail <alice@example.com>
author-time 1640000000
summary Initial version"""
        )

        result = get_git_blame(Path("/repo/code.py"), 1, Path("/repo"))

        assert result is not None
        assert result["author"] == "Alice Developer"
        assert result["commit"] == "abc123def456"
        assert result["email"] == "alice@example.com"
        assert "2021" in result["date"]

    @patch('yavs.utils.git_blame.subprocess.run')
    def test_get_git_blame_failure(self, mock_run):
        """Test git blame failure."""
        mock_run.return_value = MagicMock(returncode=128)

        result = get_git_blame(Path("/not/a/repo/file.py"), 1)
        assert result is None

    @patch('yavs.utils.git_blame.subprocess.run')
    def test_is_git_repository_true(self, mock_run):
        """Test is_git_repository returns True for git repos."""
        mock_run.return_value = MagicMock(returncode=0)

        assert is_git_repository(Path("/path/to/repo")) is True

    @patch('yavs.utils.git_blame.subprocess.run')
    def test_is_git_repository_false(self, mock_run):
        """Test is_git_repository returns False for non-git dirs."""
        mock_run.return_value = MagicMock(returncode=128)

        assert is_git_repository(Path("/path/to/nonrepo")) is False

