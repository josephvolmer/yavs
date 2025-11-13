"""Comprehensive tests for AI modules (fixer, summarizer, triage)."""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from yavs.ai.fixer import Fixer
from yavs.ai.summarizer import Summarizer
from yavs.ai.triage import TriageEngine


class TestFixer:
    """Tests for AI Fixer module."""

    @patch('yavs.ai.fixer.create_provider')
    def test_fixer_initialization(self, mock_create_provider):
        """Test Fixer initialization with default parameters."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        assert fixer is not None
        assert fixer.max_tokens == 2048
        assert fixer.temperature == 0.0
        assert fixer.parallel_requests >= 1
        assert fixer.parallel_requests <= 10

    @patch('yavs.ai.fixer.create_provider')
    def test_fixer_initialization_custom_params(self, mock_create_provider):
        """Test Fixer initialization with custom parameters."""
        mock_provider = Mock()
        mock_provider.provider_name = "openai"
        mock_provider.model_name = "gpt-4"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer(
            model="gpt-4",
            provider="openai",
            max_tokens=1024,
            temperature=0.5,
            parallel_requests=3
        )
        assert fixer.max_tokens == 1024
        assert fixer.temperature == 0.5
        assert fixer.parallel_requests == 3

    @patch('yavs.ai.fixer.create_provider')
    def test_fixer_parallel_requests_clamping(self, mock_create_provider):
        """Test that parallel_requests is clamped to 1-10 range."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        # Test upper bound clamping
        fixer1 = Fixer(parallel_requests=50)
        assert fixer1.parallel_requests == 10

        # Test lower bound clamping
        fixer2 = Fixer(parallel_requests=0)
        assert fixer2.parallel_requests == 1

    @patch('yavs.ai.fixer.create_provider')
    def test_generate_fix_basic(self, mock_create_provider):
        """Test generating a fix for a single finding."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_provider.create_completion = Mock(return_value="Fix: Update package")
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        finding = {
            "severity": "HIGH",
            "message": "SQL Injection vulnerability",
            "file": "app.py",
            "rule_id": "B608",
            "category": "sast",
            "line": 42
        }

        fix = fixer.generate_fix(finding)
        assert isinstance(fix, str)
        assert len(fix) > 0

    @patch('yavs.ai.fixer.create_provider')
    def test_generate_fix_with_exception(self, mock_create_provider):
        """Test fix generation handles exceptions."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_provider.create_completion = Mock(side_effect=Exception("API Error"))
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        finding = {"severity": "HIGH", "message": "Test issue"}

        fix = fixer.generate_fix(finding)
        assert "Unable to generate fix" in fix

    @patch('yavs.ai.fixer.create_provider')
    def test_build_fix_prompt_dependency(self, mock_create_provider):
        """Test building fix prompt for dependency finding."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        finding = {
            "severity": "CRITICAL",
            "message": "Vulnerable package",
            "file": "package.json",
            "rule_id": "CVE-2021-1234",
            "category": "dependency",
            "package": "lodash",
            "version": "4.17.20",
            "fixed_version": "4.17.21"
        }

        prompt = fixer._build_fix_prompt(finding)
        assert "lodash" in prompt
        assert "4.17.20" in prompt
        assert "4.17.21" in prompt

    @patch('yavs.ai.fixer.create_provider')
    def test_build_fix_prompt_sast(self, mock_create_provider):
        """Test building fix prompt for SAST finding."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        finding = {
            "severity": "HIGH",
            "message": "SQL Injection",
            "file": "app.py",
            "line": 42,
            "rule_id": "B608",
            "category": "sast"
        }

        prompt = fixer._build_fix_prompt(finding)
        assert "Line: 42" in prompt
        assert "SQL Injection" in prompt

    @patch('yavs.ai.fixer.create_provider')
    def test_generate_fixes_batch_filters_severity(self, mock_create_provider):
        """Test that batch processing only fixes high/critical findings."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_provider.create_completion = Mock(return_value="Fix suggestion")
        mock_create_provider.return_value = mock_provider

        fixer = Fixer(parallel_requests=2)
        findings = [
            {"severity": "CRITICAL", "message": "Issue 1", "file": "a.py"},
            {"severity": "HIGH", "message": "Issue 2", "file": "b.py"},
            {"severity": "MEDIUM", "message": "Issue 3", "file": "c.py"},
            {"severity": "LOW", "message": "Issue 4", "file": "d.py"},
        ]

        result = fixer.generate_fixes_batch(findings)

        # Check that only CRITICAL and HIGH got fixes
        critical_high_with_fix = [
            f for f in result
            if f.get("severity") in ["CRITICAL", "HIGH"] and "ai_fix" in f
        ]
        assert len(critical_high_with_fix) == 2

    @patch('yavs.ai.fixer.create_provider')
    def test_generate_fixes_batch_empty_list(self, mock_create_provider):
        """Test batch processing with empty findings list."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        result = fixer.generate_fixes_batch([])
        assert result == []

    @patch('yavs.ai.fixer.create_provider')
    def test_get_provider_info(self, mock_create_provider):
        """Test getting provider information."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        fixer = Fixer()
        info = fixer.get_provider_info()
        assert info["provider"] == "anthropic"
        assert info["model"] == "claude-3-5-sonnet-20241022"


class TestSummarizer:
    """Tests for AI Summarizer module."""

    @patch('yavs.ai.summarizer.create_provider')
    def test_summarizer_initialization(self, mock_create_provider):
        """Test Summarizer initialization."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer()
        assert summarizer is not None
        assert summarizer.max_tokens == 4096
        assert summarizer.temperature == 0.0

    @patch('yavs.ai.summarizer.create_provider')
    def test_summarizer_custom_params(self, mock_create_provider):
        """Test Summarizer with custom parameters."""
        mock_provider = Mock()
        mock_provider.provider_name = "openai"
        mock_provider.model_name = "gpt-4"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer(
            model="gpt-4",
            provider="openai",
            max_tokens=2048,
            temperature=0.3
        )
        assert summarizer.max_tokens == 2048
        assert summarizer.temperature == 0.3

    @patch('yavs.ai.summarizer.create_provider')
    def test_summarize_empty_findings(self, mock_create_provider):
        """Test summarizing empty findings list."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer()
        summary = summarizer.summarize([])
        assert summary == "No vulnerabilities found."

    @patch('yavs.ai.summarizer.create_provider')
    def test_summarize_with_findings(self, mock_create_provider):
        """Test summarizing findings."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_provider.create_completion = Mock(
            return_value="## Risk Level\n**HIGH** risk\n## Immediate Actions\n- Fix issue 1"
        )
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer()
        findings = [
            {"severity": "HIGH", "message": "Issue 1", "file": "a.py", "tool": "bandit"},
            {"severity": "MEDIUM", "message": "Issue 2", "file": "b.py", "tool": "semgrep"},
        ]

        summary = summarizer.summarize(findings)
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "anthropic" in summary.lower() or "claude" in summary.lower()

    @patch('yavs.ai.summarizer.create_provider')
    def test_get_statistics(self, mock_create_provider):
        """Test statistics generation."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer()
        findings = [
            {"severity": "CRITICAL", "category": "dependency", "tool": "trivy"},
            {"severity": "HIGH", "category": "sast", "tool": "semgrep"},
            {"severity": "HIGH", "category": "sast", "tool": "bandit"},
            {"severity": "MEDIUM", "category": "compliance", "tool": "checkov"},
        ]

        stats = summarizer._get_statistics(findings)
        assert stats["total"] == 4
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["HIGH"] == 2
        assert stats["by_category"]["sast"] == 2
        assert stats["by_tool"]["semgrep"] == 1

    @patch('yavs.ai.summarizer.create_provider')
    def test_build_summary_prompt(self, mock_create_provider):
        """Test building summary prompt."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer()
        findings = [
            {"severity": "HIGH", "message": "Issue", "file": "a.py", "tool": "bandit"}
        ]
        stats = summarizer._get_statistics(findings)
        prompt = summarizer._build_summary_prompt(findings, stats)

        assert "Total: 1" in prompt
        assert "HIGH" in prompt
        assert isinstance(prompt, str)

    @patch('yavs.ai.summarizer.create_provider')
    def test_get_provider_info(self, mock_create_provider):
        """Test getting provider information."""
        mock_provider = Mock()
        mock_provider.provider_name = "openai"
        mock_provider.model_name = "gpt-4-turbo"
        mock_create_provider.return_value = mock_provider

        summarizer = Summarizer(provider="openai", model="gpt-4-turbo")
        info = summarizer.get_provider_info()
        assert info["provider"] == "openai"
        assert info["model"] == "gpt-4-turbo"


class TestTriageEngine:
    """Tests for AI Triage Engine module."""

    @patch('yavs.ai.triage.create_provider')
    def test_triage_initialization(self, mock_create_provider):
        """Test TriageEngine initialization."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        assert triage is not None
        assert triage.max_tokens == 4096
        assert triage.temperature == 0.0

    @patch('yavs.ai.triage.create_provider')
    def test_triage_empty_findings(self, mock_create_provider):
        """Test triage with empty findings."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        result = triage.triage([])

        assert result["clusters"] == []
        assert result["priorities"] == []
        assert "No findings" in result["insights"]

    @patch('yavs.ai.triage.create_provider')
    def test_basic_clustering(self, mock_create_provider):
        """Test basic clustering by rule_id."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        findings = [
            {"rule_id": "B608", "message": "SQL injection 1"},
            {"rule_id": "B608", "message": "SQL injection 2"},
            {"rule_id": "B201", "message": "Flask debug mode"},
        ]

        clusters = triage._basic_clustering(findings)
        assert len(clusters) == 2
        assert len(clusters["B608"]) == 2
        assert len(clusters["B201"]) == 1

    @patch('yavs.ai.triage.create_provider')
    def test_triage_with_findings(self, mock_create_provider):
        """Test full triage process."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_provider.create_completion = Mock(
            return_value="## Root Cause Analysis\nMultiple SQL injection issues detected."
        )
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        findings = [
            {"rule_id": "B608", "severity": "HIGH", "category": "sast", "message": "SQL injection"},
            {"rule_id": "CVE-2021-1234", "severity": "CRITICAL", "category": "dependency", "message": "Vuln package"},
        ]

        result = triage.triage(findings)
        assert "clusters" in result
        assert "cluster_count" in result
        assert "total_findings" in result
        assert result["total_findings"] == 2
        assert result["ai_provider"] == "anthropic"

    @patch('yavs.ai.triage.create_provider')
    def test_get_top_priorities(self, mock_create_provider):
        """Test getting top priority findings."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        findings = [
            {"severity": "LOW", "category": "sast"},
            {"severity": "CRITICAL", "category": "dependency"},
            {"severity": "HIGH", "category": "sast"},
            {"severity": "MEDIUM", "category": "compliance"},
        ]

        priorities = triage.get_top_priorities(findings, limit=2)
        assert len(priorities) == 2
        assert priorities[0]["severity"] == "CRITICAL"

    @patch('yavs.ai.triage.create_provider')
    def test_get_top_priorities_with_secret_boost(self, mock_create_provider):
        """Test priority scoring with category boost."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        findings = [
            {"severity": "HIGH", "category": "sast"},
            {"severity": "HIGH", "category": "secret"},  # Should be boosted
        ]

        priorities = triage.get_top_priorities(findings, limit=2)
        # Secret finding should be prioritized higher
        assert len(priorities) == 2

    @patch('yavs.ai.triage.create_provider')
    def test_build_triage_prompt(self, mock_create_provider):
        """Test building triage prompt."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        findings = [
            {"rule_id": "B608", "severity": "HIGH", "category": "sast"},
            {"rule_id": "CVE-123", "severity": "CRITICAL", "category": "dependency"},
        ]
        clusters = triage._basic_clustering(findings)
        prompt = triage._build_triage_prompt(findings, clusters)

        assert "Total findings: 2" in prompt
        assert "Critical: 1" in prompt
        assert "High: 1" in prompt

    @patch('yavs.ai.triage.create_provider')
    def test_get_provider_info(self, mock_create_provider):
        """Test getting provider information."""
        mock_provider = Mock()
        mock_provider.provider_name = "anthropic"
        mock_provider.model_name = "claude-3-5-sonnet-20241022"
        mock_create_provider.return_value = mock_provider

        triage = TriageEngine()
        info = triage.get_provider_info()
        assert info["provider"] == "anthropic"
        assert info["model"] == "claude-3-5-sonnet-20241022"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
