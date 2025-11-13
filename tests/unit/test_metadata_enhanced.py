"""Enhanced tests for metadata utilities."""
import pytest
from pathlib import Path
from unittest.mock import patch, Mock
from yavs.utils.metadata import (
    extract_project_metadata,
    get_git_branch,
    get_git_commit_hash,
    get_build_timestamp
)

class TestExtractProjectMetadata:
    def test_extract_metadata_basic(self, tmp_path):
        """Test extracting basic project metadata."""
        metadata = extract_project_metadata(tmp_path)
        assert isinstance(metadata, dict)
        assert "build_cycle" in metadata
        assert "project" in metadata

    def test_extract_metadata_with_project_name(self, tmp_path):
        """Test extracting metadata with project name."""
        metadata = extract_project_metadata(tmp_path, project_name="test-project")
        assert metadata["project"] == "test-project"

    def test_extract_metadata_auto_detect(self, tmp_path):
        """Test extracting metadata with auto-detection."""
        # Create a package.json to trigger auto-detection
        package_json = tmp_path / "package.json"
        package_json.write_text('{"name": "my-project"}')

        metadata = extract_project_metadata(tmp_path)
        assert isinstance(metadata, dict)
        assert "project" in metadata

class TestGetGitBranch:
    @patch('subprocess.run')
    def test_get_git_branch_success(self, mock_run):
        """Test getting git branch successfully."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="main\n",
            stderr=""
        )
        branch = get_git_branch(Path("."))
        assert branch == "main"

    @patch('subprocess.run')
    def test_get_git_branch_failure(self, mock_run):
        """Test getting git branch when not in repo."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
        branch = get_git_branch(Path("."))
        assert branch is None

class TestGetGitCommitHash:
    @patch('subprocess.run')
    def test_get_commit_hash_success(self, mock_run):
        """Test getting git commit hash."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="abc123def456\n",
            stderr=""
        )
        commit = get_git_commit_hash(Path("."))
        assert commit == "abc123def456"

    @patch('subprocess.run')
    def test_get_commit_hash_failure(self, mock_run):
        """Test getting commit hash when not in repo."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="")
        commit = get_git_commit_hash(Path("."))
        assert commit is None

class TestGetBuildTimestamp:
    def test_get_build_timestamp(self):
        """Test getting build timestamp."""
        timestamp = get_build_timestamp()
        assert isinstance(timestamp, str)
        assert len(timestamp) > 0
        # Should be ISO format with Z suffix
        assert timestamp.endswith("Z")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
