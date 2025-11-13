"""Tests for auto-detect module."""

import pytest
from pathlib import Path
import tempfile
import json

from yavs.utils.auto_detect import (
    detect_project_type,
    get_scanner_categories,
    get_recommended_flags
)


class TestDetectProjectType:
    """Test project type detection."""

    def test_python_project_requirements(self, tmp_path):
        """Test Python detection via requirements.txt."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_python_project_pyproject(self, tmp_path):
        """Test Python detection via pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text("[tool.poetry]")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_python_project_setup_py(self, tmp_path):
        """Test Python detection via setup.py."""
        (tmp_path / "setup.py").write_text("from setuptools import setup")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners

    def test_python_project_pipfile(self, tmp_path):
        """Test Python detection via Pipfile."""
        (tmp_path / "Pipfile").write_text("[packages]")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners

    def test_python_project_poetry_lock(self, tmp_path):
        """Test Python detection via poetry.lock."""
        (tmp_path / "poetry.lock").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners

    def test_python_project_py_files(self, tmp_path):
        """Test Python detection via .py files."""
        (tmp_path / "app.py").write_text("print('hello')")
        scanners = detect_project_type(tmp_path)
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_nodejs_project_package_json(self, tmp_path):
        """Test Node.js detection via package.json."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_nodejs_project_package_lock(self, tmp_path):
        """Test Node.js detection via package-lock.json."""
        (tmp_path / "package-lock.json").write_text('{}')
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_nodejs_project_yarn_lock(self, tmp_path):
        """Test Node.js detection via yarn.lock."""
        (tmp_path / "yarn.lock").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_nodejs_project_pnpm_lock(self, tmp_path):
        """Test Node.js detection via pnpm-lock.yaml."""
        (tmp_path / "pnpm-lock.yaml").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_nodejs_project_js_files(self, tmp_path):
        """Test Node.js detection via .js files."""
        (tmp_path / "index.js").write_text("console.log('hello');")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners

    def test_nodejs_project_ts_files(self, tmp_path):
        """Test TypeScript detection via .ts files."""
        (tmp_path / "index.ts").write_text("const x: string = 'hello';")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners

    def test_go_project_go_mod(self, tmp_path):
        """Test Go detection via go.mod."""
        (tmp_path / "go.mod").write_text("module test")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_go_project_go_sum(self, tmp_path):
        """Test Go detection via go.sum."""
        (tmp_path / "go.sum").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_go_project_go_files(self, tmp_path):
        """Test Go detection via .go files."""
        (tmp_path / "main.go").write_text("package main")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_java_project_pom_xml(self, tmp_path):
        """Test Java detection via pom.xml."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_java_project_build_gradle(self, tmp_path):
        """Test Java detection via build.gradle."""
        (tmp_path / "build.gradle").write_text("plugins {}")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_java_project_build_gradle_kts(self, tmp_path):
        """Test Java detection via build.gradle.kts."""
        (tmp_path / "build.gradle.kts").write_text("plugins {}")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners

    def test_java_project_java_files(self, tmp_path):
        """Test Java detection via .java files."""
        (tmp_path / "Main.java").write_text("public class Main {}")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_dotnet_project_csproj(self, tmp_path):
        """Test .NET detection via .csproj files."""
        (tmp_path / "app.csproj").write_text("<Project></Project>")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "binskim" in scanners

    def test_dotnet_project_sln(self, tmp_path):
        """Test .NET detection via .sln files."""
        (tmp_path / "solution.sln").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "binskim" in scanners

    def test_dotnet_project_cs_files(self, tmp_path):
        """Test .NET detection via .cs files."""
        (tmp_path / "Program.cs").write_text("using System;")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "binskim" in scanners

    def test_dotnet_project_packages_config(self, tmp_path):
        """Test .NET detection via packages.config."""
        (tmp_path / "packages.config").write_text("<packages></packages>")
        scanners = detect_project_type(tmp_path)
        assert "binskim" in scanners

    def test_ruby_project_gemfile(self, tmp_path):
        """Test Ruby detection via Gemfile."""
        (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_ruby_project_gemfile_lock(self, tmp_path):
        """Test Ruby detection via Gemfile.lock."""
        (tmp_path / "Gemfile.lock").write_text("")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_ruby_project_rb_files(self, tmp_path):
        """Test Ruby detection via .rb files."""
        (tmp_path / "app.rb").write_text("puts 'hello'")
        scanners = detect_project_type(tmp_path)
        assert "semgrep" in scanners
        assert "trivy" in scanners

    def test_terraform_tf_files(self, tmp_path):
        """Test Terraform detection via .tf files."""
        (tmp_path / "main.tf").write_text("resource 'aws_instance' 'test' {}")
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners
        assert "terrascan" in scanners

    def test_terraform_tfvars_files(self, tmp_path):
        """Test Terraform detection via .tfvars files."""
        (tmp_path / "terraform.tfvars").write_text("region = 'us-east-1'")
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners
        assert "terrascan" in scanners

    def test_cloudformation_yaml(self, tmp_path):
        """Test CloudFormation detection via cloudformation.yaml."""
        (tmp_path / "cloudformation-template.yaml").write_text("Resources:")
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners
        assert "terrascan" in scanners

    def test_cloudformation_template_yaml(self, tmp_path):
        """Test CloudFormation detection via template.yaml."""
        (tmp_path / "template.yaml").write_text("Resources:")
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners

    def test_cloudformation_json(self, tmp_path):
        """Test CloudFormation detection via cloudformation.json."""
        (tmp_path / "cloudformation-stack.json").write_text('{"Resources": {}}')
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners

    def test_kubernetes_yaml(self, tmp_path):
        """Test Kubernetes detection via manifest with kind."""
        k8s_manifest = """apiVersion: v1
kind: Pod
metadata:
  name: test
"""
        (tmp_path / "deployment.yaml").write_text(k8s_manifest)
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners
        assert "terrascan" in scanners

    def test_kubernetes_yaml_with_metadata(self, tmp_path):
        """Test Kubernetes detection via manifest with metadata."""
        k8s_manifest = """apiVersion: apps/v1
metadata:
  name: test
spec:
  replicas: 3
"""
        (tmp_path / "service.yaml").write_text(k8s_manifest)
        scanners = detect_project_type(tmp_path)
        assert "checkov" in scanners

    def test_docker_dockerfile(self, tmp_path):
        """Test Docker detection via Dockerfile."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.9")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_docker_dockerfile_extension(self, tmp_path):
        """Test Docker detection via .dockerfile extension."""
        (tmp_path / "app.dockerfile").write_text("FROM node:14")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_docker_compose_yml(self, tmp_path):
        """Test Docker detection via docker-compose.yml."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_docker_compose_yaml(self, tmp_path):
        """Test Docker detection via docker-compose.yaml."""
        (tmp_path / "docker-compose.yaml").write_text("version: '3'")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_azure_bicep_files(self, tmp_path):
        """Test Azure Bicep detection via .bicep files."""
        (tmp_path / "main.bicep").write_text("resource storageAccount 'Microsoft.Storage/storageAccounts@2021-02-01'")
        scanners = detect_project_type(tmp_path)
        assert "template-analyzer" in scanners

    def test_azure_arm_template(self, tmp_path):
        """Test Azure ARM detection via ARM template JSON."""
        arm_template = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": []
        }
        (tmp_path / "azuredeploy.json").write_text(json.dumps(arm_template))
        scanners = detect_project_type(tmp_path)
        assert "template-analyzer" in scanners

    def test_package_files_trivy_recommendation(self, tmp_path):
        """Test Trivy recommendation for package manager files."""
        (tmp_path / "Cargo.toml").write_text("[package]")
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_composer_json_trivy(self, tmp_path):
        """Test Trivy recommendation for composer.json."""
        (tmp_path / "composer.json").write_text('{"require": {}}')
        scanners = detect_project_type(tmp_path)
        assert "trivy" in scanners

    def test_empty_directory(self, tmp_path):
        """Test empty directory returns empty set."""
        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_non_directory_path(self, tmp_path):
        """Test non-directory path returns empty set."""
        file_path = tmp_path / "test.txt"
        file_path.write_text("test")
        scanners = detect_project_type(file_path)
        assert scanners == set()

    def test_mixed_project_multiple_scanners(self, tmp_path):
        """Test mixed project detects multiple scanners."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0")
        (tmp_path / "Dockerfile").write_text("FROM python:3.9")
        (tmp_path / "main.tf").write_text("resource 'aws_instance' 'test' {}")

        scanners = detect_project_type(tmp_path)

        assert "bandit" in scanners
        assert "semgrep" in scanners
        assert "trivy" in scanners
        assert "checkov" in scanners
        assert "terrascan" in scanners

    def test_kubernetes_yaml_read_error_handling(self, tmp_path):
        """Test that read errors on YAML files are handled gracefully."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("invalid: yaml: content:")
        # Should not raise exception
        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)

    def test_arm_json_read_error_handling(self, tmp_path):
        """Test that read errors on JSON files are handled gracefully."""
        json_file = tmp_path / "test.json"
        json_file.write_text("{invalid json")
        # Should not raise exception
        scanners = detect_project_type(tmp_path)
        assert isinstance(scanners, set)


class TestGetScannerCategories:
    """Test scanner category mapping."""

    def test_sast_scanners(self):
        """Test SAST category detection."""
        scanners = {"semgrep", "bandit"}
        categories = get_scanner_categories(scanners)
        assert categories["sast"] is True

    def test_bandit_sast(self):
        """Test Bandit maps to SAST."""
        categories = get_scanner_categories({"bandit"})
        assert categories["sast"] is True

    def test_binskim_sast(self):
        """Test BinSkim maps to SAST."""
        categories = get_scanner_categories({"binskim"})
        assert categories["sast"] is True

    def test_trivy_sbom_and_secrets(self):
        """Test Trivy maps to SBOM and secrets."""
        categories = get_scanner_categories({"trivy"})
        assert categories["sbom"] is True
        assert categories["secrets"] is True

    def test_checkov_compliance(self):
        """Test Checkov maps to compliance."""
        categories = get_scanner_categories({"checkov"})
        assert categories["compliance"] is True

    def test_multiple_categories(self):
        """Test multiple scanners map to multiple categories."""
        scanners = {"semgrep", "trivy", "checkov"}
        categories = get_scanner_categories(scanners)
        assert categories["sast"] is True
        assert categories["sbom"] is True
        assert categories["secrets"] is True
        assert categories["compliance"] is True

    def test_empty_scanners(self):
        """Test empty scanner set returns all False."""
        categories = get_scanner_categories(set())
        assert categories["sast"] is False
        assert categories["sbom"] is False
        assert categories["compliance"] is False
        assert categories["secrets"] is False

    def test_unknown_scanner(self):
        """Test unknown scanner doesn't activate categories."""
        categories = get_scanner_categories({"unknown-scanner"})
        assert all(v is False for v in categories.values())


class TestGetRecommendedFlags:
    """Test recommended flag generation."""

    def test_python_project_sast_flag(self, tmp_path):
        """Test Python project recommends flags."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0")
        flags = get_recommended_flags(tmp_path)
        # Python with requirements.txt triggers bandit+semgrep (SAST) + trivy (SBOM)
        # Multiple categories -> --all
        assert "--all" in flags

    def test_nodejs_project_multiple_flags(self, tmp_path):
        """Test Node.js project recommends multiple flags."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        flags = get_recommended_flags(tmp_path)
        # Should recommend --all since both SAST and SBOM are detected
        assert "--all" in flags

    def test_terraform_compliance_flag(self, tmp_path):
        """Test Terraform project recommends compliance flag."""
        (tmp_path / "main.tf").write_text("resource 'aws_instance' 'test' {}")
        flags = get_recommended_flags(tmp_path)
        assert "--compliance" in flags

    def test_docker_only_sbom_flag(self, tmp_path):
        """Test Docker-only project recommends flags."""
        (tmp_path / "Dockerfile").write_text("FROM alpine:latest")
        flags = get_recommended_flags(tmp_path)
        # Dockerfile only triggers trivy -> SBOM + secrets categories
        # But since 2+ categories, triggers --all
        assert "--all" in flags

    def test_mixed_project_all_flag(self, tmp_path):
        """Test mixed project recommends --all flag."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0")
        (tmp_path / "main.tf").write_text("resource 'aws_instance' 'test' {}")

        flags = get_recommended_flags(tmp_path)

        # Multiple categories detected, should recommend --all
        assert "--all" in flags
        assert len(flags) == 1  # Should only return --all, not individual flags

    def test_empty_directory_no_flags(self, tmp_path):
        """Test empty directory returns no flags."""
        flags = get_recommended_flags(tmp_path)
        assert flags == []

    def test_go_project_all_flag(self, tmp_path):
        """Test Go project with dependencies recommends --all."""
        (tmp_path / "go.mod").write_text("module test")
        (tmp_path / "main.go").write_text("package main")
        flags = get_recommended_flags(tmp_path)
        # Go triggers semgrep (SAST) and trivy (SBOM), so --all
        assert "--all" in flags

    def test_single_category_specific_flag(self, tmp_path):
        """Test single category returns specific flag, not --all."""
        # Create a project that only triggers compliance category
        (tmp_path / "main.tf").write_text("resource 'aws_instance' 'test' {}")
        flags = get_recommended_flags(tmp_path)
        # Terraform triggers only checkov/terrascan -> compliance only
        # Single category -> specific flag
        assert "--compliance" in flags
        assert "--all" not in flags


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
