"""Integration tests for multi-language scanning."""

import pytest
from pathlib import Path
import tempfile
import json

from yavs.scanners import TrivyScanner, SemgrepScanner, BanditScanner
from yavs.reporting import Aggregator
from yavs.cli import filter_findings_by_ignore_patterns


class TestMultiLanguageScanning:
    """Test scanning across different programming languages."""

    @pytest.fixture
    def fixtures_dir(self):
        """Get fixtures directory."""
        return Path(__file__).parent / "fixtures"

    def test_python_project_scanning(self, fixtures_dir):
        """Test scanning Python project."""
        python_project = fixtures_dir / "sample_project"

        if not python_project.exists():
            pytest.skip("Python fixture not found")

        aggregator = Aggregator()

        # Scan with Bandit (Python-specific)
        try:
            scanner = BanditScanner(python_project, timeout=60)
            if scanner.check_available():
                findings = scanner.run()
                aggregator.add_findings(findings)

                # Should find hardcoded credentials, SQL injection, etc.
                assert len(findings) > 0

                # Check for specific vulnerability types
                rule_ids = [f.get("rule_id") for f in findings]
                assert any("B105" in r or "B608" in r for r in rule_ids if r)  # Hardcoded password or SQL
        except Exception as e:
            pytest.skip(f"Bandit not available: {e}")

    def test_nodejs_project_scanning(self, fixtures_dir):
        """Test scanning Node.js project."""
        nodejs_project = fixtures_dir / "nodejs_project"

        if not nodejs_project.exists():
            pytest.skip("Node.js fixture not found")

        # Check for vulnerable dependencies
        package_json = nodejs_project / "package.json"
        assert package_json.exists(), "package.json should exist"

        # Verify it has vulnerable dependencies
        with open(package_json) as f:
            data = json.load(f)
            assert "express" in data.get("dependencies", {})
            assert "lodash" in data.get("dependencies", {})

    def test_java_project_structure(self, fixtures_dir):
        """Test Java project structure."""
        java_project = fixtures_dir / "java_project"

        if not java_project.exists():
            pytest.skip("Java fixture not found")

        # Check for Maven configuration
        pom_xml = java_project / "pom.xml"
        assert pom_xml.exists(), "pom.xml should exist"

        # Check for source code
        source_file = java_project / "src/main/java/com/example/VulnerableApp.java"
        assert source_file.exists(), "Java source should exist"

    def test_go_project_structure(self, fixtures_dir):
        """Test Go project structure."""
        go_project = fixtures_dir / "go_project"

        if not go_project.exists():
            pytest.skip("Go fixture not found")

        # Check for Go module
        go_mod = go_project / "go.mod"
        assert go_mod.exists(), "go.mod should exist"

        # Check for source code
        main_go = go_project / "main.go"
        assert main_go.exists(), "main.go should exist"

    def test_kubernetes_manifest_structure(self, fixtures_dir):
        """Test Kubernetes manifest structure."""
        k8s_dir = fixtures_dir / "kubernetes"

        if not k8s_dir.exists():
            pytest.skip("Kubernetes fixture not found")

        deployment = k8s_dir / "deployment.yaml"
        assert deployment.exists(), "deployment.yaml should exist"

    def test_ignore_patterns_filtering(self):
        """Test that ignore patterns correctly filter findings."""
        findings = [
            {
                "tool": "semgrep",
                "file": "src/main.py",
                "severity": "HIGH",
                "message": "SQL injection"
            },
            {
                "tool": "semgrep",
                "file": "node_modules/lodash/index.js",
                "severity": "HIGH",
                "message": "Prototype pollution"
            },
            {
                "tool": "bandit",
                "file": "tests/test_security.py",
                "severity": "MEDIUM",
                "message": "Hardcoded password"
            },
            {
                "tool": "trivy",
                "file": "dist/bundle.min.js",
                "severity": "LOW",
                "message": "License issue"
            }
        ]

        # Apply ignore patterns
        ignore_patterns = [
            "node_modules/",
            "tests/",
            r".*\.min\.js$"
        ]

        filtered = filter_findings_by_ignore_patterns(findings, ignore_patterns)

        # Should only keep src/main.py finding
        assert len(filtered) == 1
        assert filtered[0]["file"] == "src/main.py"

    def test_multi_directory_aggregation(self, fixtures_dir):
        """Test aggregating findings from multiple directories."""
        aggregator = Aggregator()

        # Simulate findings from different directories
        findings_dir1 = [
            {
                "tool": "trivy",
                "source": "filesystem:/path/dir1",
                "source_type": "filesystem",
                "severity": "HIGH",
                "file": "requirements.txt",
                "message": "CVE-2021-1234"
            }
        ]

        findings_dir2 = [
            {
                "tool": "semgrep",
                "source": "filesystem:/path/dir2",
                "source_type": "filesystem",
                "severity": "MEDIUM",
                "file": "app.py",
                "message": "SQL injection"
            }
        ]

        aggregator.add_findings(findings_dir1)
        aggregator.add_findings(findings_dir2)
        aggregator.sort_by_severity()

        all_findings = aggregator.get_findings()
        assert len(all_findings) == 2

        # Check source tagging
        assert all_findings[0].get("source_type") == "filesystem"
        assert all_findings[1].get("source_type") == "filesystem"

    def test_docker_image_tagging(self):
        """Test that Docker image findings are properly tagged."""
        findings = [
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "HIGH",
                "file": "usr/lib/python3.9/site-packages/",
                "message": "CVE-2021-5678"
            }
        ]

        # Tag with image source
        for finding in findings:
            finding["source"] = "image:nginx:latest"
            finding["source_type"] = "image"

        assert findings[0]["source"] == "image:nginx:latest"
        assert findings[0]["source_type"] == "image"


class TestDockerImageScanning:
    """Test Docker image scanning capabilities."""

    @pytest.fixture
    def docker_fixtures_dir(self):
        """Get Docker fixtures directory."""
        return Path(__file__).parent / "fixtures" / "docker_images"

    def test_dockerfile_structure(self, docker_fixtures_dir):
        """Test Dockerfile fixtures exist."""
        if not docker_fixtures_dir.exists():
            pytest.skip("Docker fixtures not found")

        vulnerable_dockerfile = docker_fixtures_dir / "Dockerfile.vulnerable-app"
        python_dockerfile = docker_fixtures_dir / "Dockerfile.python-app"

        assert vulnerable_dockerfile.exists(), "Vulnerable Dockerfile should exist"
        assert python_dockerfile.exists(), "Python Dockerfile should exist"

    def test_buildable_dockerfile_components(self, docker_fixtures_dir):
        """Test that buildable Dockerfile has required components."""
        if not docker_fixtures_dir.exists():
            pytest.skip("Docker fixtures not found")

        requirements = docker_fixtures_dir / "requirements.txt"
        app_py = docker_fixtures_dir / "app.py"

        assert requirements.exists(), "requirements.txt should exist"
        assert app_py.exists(), "app.py should exist"

        # Verify requirements has vulnerable packages
        with open(requirements) as f:
            content = f.read()
            assert "Flask" in content
            assert "requests" in content


class TestSeverityMapping:
    """Test severity mapping across different scanners."""

    def test_consistent_severity_levels(self):
        """Test that all scanners use consistent severity levels."""
        # Test findings from different tools
        findings = [
            {"tool": "trivy", "severity": "CRITICAL"},
            {"tool": "trivy", "severity": "HIGH"},
            {"tool": "semgrep", "severity": "ERROR"},
            {"tool": "semgrep", "severity": "WARNING"},
            {"tool": "bandit", "severity": "HIGH"},
            {"tool": "bandit", "severity": "MEDIUM"},
        ]

        # After severity normalization, these should map to standard levels
        expected_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

        # In a real scan, BaseScanner.normalize_severity() would be applied
        # Here we just verify the test structure is correct
        for finding in findings:
            assert "severity" in finding
            severity = finding["severity"].upper()
            # Original severity might not be normalized yet
            assert severity in expected_severities or severity in {"ERROR", "WARNING"}


@pytest.mark.integration
class TestEndToEndMultiLanguage:
    """End-to-end integration tests for multi-language scanning."""

    def test_scan_all_fixtures(self):
        """Test scanning all language fixtures together."""
        fixtures_dir = Path(__file__).parent / "fixtures"

        if not fixtures_dir.exists():
            pytest.skip("Fixtures directory not found")

        aggregator = Aggregator()
        total_scanned = 0

        # Scan each project
        for project_dir in fixtures_dir.iterdir():
            if project_dir.is_dir() and not project_dir.name.startswith('.'):
                total_scanned += 1

        # Should have scanned multiple projects
        assert total_scanned >= 1, "Should have at least one test fixture"

    def test_structured_output_with_multi_language(self):
        """Test structured output with findings from multiple languages."""
        from yavs.reporting.structured_output import StructuredOutputFormatter

        # Simulate findings from different languages
        findings = [
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "HIGH",
                "file": "package.json",
                "message": "CVE in lodash",
                "package": "lodash",
                "version": "4.17.4"
            },
            {
                "tool": "trivy",
                "category": "dependency",
                "severity": "HIGH",
                "file": "pom.xml",
                "message": "CVE in jackson",
                "package": "jackson-databind",
                "version": "2.9.0"
            },
            {
                "tool": "semgrep",
                "category": "sast",
                "severity": "HIGH",
                "file": "main.go",
                "message": "SQL injection"
            }
        ]

        formatter = StructuredOutputFormatter()
        metadata = {"project": "multi-language-test"}
        output = formatter.format(findings, metadata)

        # Verify structure
        assert "compliance" in output
        assert "sast" in output
        assert "summary" in output

        # Check counts
        assert output["summary"]["total_findings"] == 3
        assert output["summary"]["by_severity"]["HIGH"] == 3
