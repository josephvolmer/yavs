"""Tests for additional utility modules (auto_detect, timeout, tool_versions)."""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from yavs.utils.auto_detect import detect_project_type, get_scanner_categories, get_recommended_flags
from yavs.utils.timeout import timeout_handler, TimeoutError as YAVSTimeoutError
from yavs.utils.tool_versions import (
    get_tested_version,
    is_version_compatible,
    get_all_tools,
    get_tool_description
)


class TestAutoDetect:
    """Tests for project type auto-detection."""

    def test_detect_project_type_empty_dir(self, tmp_path):
        """Test detection on empty directory."""
        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_project_type_python(self, tmp_path):
        """Test Python project detection."""
        # Create Python project files
        (tmp_path / "requirements.txt").write_text("pytest\nrequests")
        (tmp_path / "main.py").write_text("print('hello')")

        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_detect_project_type_javascript(self, tmp_path):
        """Test JavaScript project detection."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        (tmp_path / "index.js").write_text("console.log('test');")

        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_detect_project_type_go(self, tmp_path):
        """Test Go project detection."""
        (tmp_path / "go.mod").write_text("module test")
        (tmp_path / "main.go").write_text("package main")

        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_detect_project_type_java(self, tmp_path):
        """Test Java project detection."""
        (tmp_path / "pom.xml").write_text("<project></project>")

        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_detect_project_type_dotnet(self, tmp_path):
        """Test .NET project detection."""
        (tmp_path / "test.csproj").write_text("<Project></Project>")

        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners

    def test_detect_project_type_terraform(self, tmp_path):
        """Test Terraform project detection."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "test" {}')

        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners or "terrascan" in scanners

    def test_detect_project_type_docker(self, tmp_path):
        """Test Docker project detection."""
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:20.04")

        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners or "semgrep" in scanners

    def test_detect_project_type_not_directory(self, tmp_path):
        """Test detection on file instead of directory."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        scanners = detect_project_type(test_file)
        assert isinstance(scanners, set)

    def test_get_scanner_categories_empty(self):
        """Test getting categories for empty scanner set."""
        categories = get_scanner_categories(set())
        assert isinstance(categories, dict)

    def test_get_scanner_categories_python(self):
        """Test getting categories for Python scanners."""
        scanners = {"bandit", "semgrep"}
        categories = get_scanner_categories(scanners)
        assert isinstance(categories, dict)

    def test_get_recommended_flags(self, tmp_path):
        """Test getting recommended flags."""
        flags = get_recommended_flags(tmp_path)
        assert isinstance(flags, list)


class TestTimeout:
    """Tests for timeout utilities."""

    def test_timeout_handler_basic(self):
        """Test creating timeout handler."""
        handler = timeout_handler(60)
        assert handler is not None

    def test_timeout_handler_with_message(self):
        """Test timeout handler with custom message."""
        handler = timeout_handler(30, error_message="Custom timeout")
        assert handler is not None

    def test_timeout_handler_none(self):
        """Test timeout handler with None (no timeout)."""
        handler = timeout_handler(None)
        assert handler is not None

    def test_timeout_error_exception(self):
        """Test TimeoutError exception class."""
        error = YAVSTimeoutError("Test timeout")
        assert isinstance(error, Exception)
        assert "Test timeout" in str(error)


class TestToolVersions:
    """Tests for tool version management."""

    def test_get_tested_version(self):
        """Test getting tested version for a tool."""
        version = get_tested_version("bandit")
        assert isinstance(version, (str, type(None)))

    def test_get_tested_version_unknown_tool(self):
        """Test getting version for unknown tool."""
        version = get_tested_version("unknown-tool-xyz")
        assert version is None

    def test_is_version_compatible(self):
        """Test version compatibility check."""
        is_compat, msg = is_version_compatible("bandit", "1.7.5")
        assert isinstance(is_compat, bool)
        assert isinstance(msg, str)

    def test_is_version_compatible_bad_version(self):
        """Test compatibility check with invalid version."""
        is_compat, msg = is_version_compatible("bandit", "invalid")
        assert isinstance(is_compat, bool)
        assert isinstance(msg, str)

    def test_get_all_tools(self):
        """Test getting all tools list."""
        tools = get_all_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_get_tool_description(self):
        """Test getting tool description."""
        desc = get_tool_description("bandit")
        assert isinstance(desc, (str, type(None)))

    def test_get_tool_description_unknown(self):
        """Test getting description for unknown tool."""
        desc = get_tool_description("unknown-tool")
        assert desc is None


class TestAutoDetectComprehensive:
    """Additional comprehensive tests for auto-detection."""

    def test_detect_ruby_project(self, tmp_path):
        """Test Ruby project detection."""
        (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'")

        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_rust_project(self, tmp_path):
        """Test Rust project detection."""
        (tmp_path / "Cargo.toml").write_text("[package]\nname = 'test'")

        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_php_project(self, tmp_path):
        """Test PHP project detection."""
        (tmp_path / "composer.json").write_text('{"name": "test"}')

        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_kubernetes_manifests(self, tmp_path):
        """Test Kubernetes manifest detection."""
        (tmp_path / "deployment.yaml").write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
""")

        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_cloudformation(self, tmp_path):
        """Test CloudFormation template detection."""
        (tmp_path / "template.yaml").write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
""")

        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_detect_mixed_project(self, tmp_path):
        """Test mixed language project."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        (tmp_path / "requirements.txt").write_text("requests")
        (tmp_path / "Dockerfile").write_text("FROM node:14")

        scanners = detect_project_type(tmp_path)
        # Should detect multiple scanner types
        assert len(scanners) > 0

    def test_detect_nested_structure(self, tmp_path):
        """Test detection with nested directory structure."""
        backend = tmp_path / "backend"
        backend.mkdir()
        (backend / "main.py").write_text("print('test')")

        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "package.json").write_text('{}')

        # Should still detect at root
        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
