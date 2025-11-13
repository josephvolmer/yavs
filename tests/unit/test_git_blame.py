"""Tests for git blame utilities."""
import pytest
from pathlib import Path
from yavs.utils.git_blame import get_git_blame, enrich_findings_with_blame, is_git_repository, get_git_root

class TestGetGitBlame:
    def test_get_git_blame_returns_dict_or_none(self, tmp_path):
        """Test get_git_blame returns dict or None."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        result = get_git_blame(test_file, 1)
        assert result is None or isinstance(result, dict)

    def test_get_git_blame_nonexistent_file(self):
        """Test get_git_blame with nonexistent file."""
        result = get_git_blame(Path("/nonexistent/file.py"), 1)
        assert result is None

class TestIsGitRepository:
    def test_is_git_repository_in_repo(self):
        """Test is_git_repository returns bool."""
        result = is_git_repository(Path("."))
        assert isinstance(result, bool)

    def test_get_git_root_returns_path_or_none(self):
        """Test get_git_root returns Path or None."""
        result = get_git_root(Path("."))
        assert result is None or isinstance(result, Path)

class TestEnrichFindingsWithBlame:
    def test_enrich_findings_returns_list(self):
        """Test enrich_findings_with_blame returns list."""
        findings = [
            {"file": "test.py", "line": 10, "message": "test"}
        ]
        result = enrich_findings_with_blame(findings, Path("."))
        assert isinstance(result, list)
        assert len(result) == 1

    def test_enrich_empty_findings(self):
        """Test enriching empty findings list."""
        result = enrich_findings_with_blame([], Path("."))
        assert result == []

    def test_enrich_findings_without_file(self):
        """Test enriching findings without file field."""
        findings = [{"message": "test"}]
        result = enrich_findings_with_blame(findings, Path("."))
        assert isinstance(result, list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
