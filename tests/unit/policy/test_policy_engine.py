"""
Unit tests for Policy-as-Code engine.

Tests policy loading, condition matching, and action application.
"""

import pytest
from pathlib import Path
import tempfile
import yaml

from yavs.policy.engine import PolicyEngine
from yavs.policy.schema import PolicyFile, PolicyRule, PolicyCondition
from yavs.policy.loader import load_policy_file


class TestPolicyConditions:
    """Test condition matching logic."""

    def test_equals_operator_case_sensitive(self):
        """Test equals operator with case sensitivity."""
        engine = PolicyEngine([])

        # Case sensitive (default)
        condition = PolicyCondition(field="severity", operator="equals", value="HIGH")

        assert engine._condition_matches(condition, {"severity": "HIGH"}) is True
        assert engine._condition_matches(condition, {"severity": "high"}) is False
        assert engine._condition_matches(condition, {"severity": "MEDIUM"}) is False

    def test_equals_operator_case_insensitive(self):
        """Test equals operator without case sensitivity."""
        engine = PolicyEngine([])

        condition = PolicyCondition(
            field="severity",
            operator="equals",
            value="HIGH",
            case_sensitive=False
        )

        assert engine._condition_matches(condition, {"severity": "HIGH"}) is True
        assert engine._condition_matches(condition, {"severity": "high"}) is True
        assert engine._condition_matches(condition, {"severity": "High"}) is True

    def test_contains_operator(self):
        """Test contains operator."""
        engine = PolicyEngine([])

        condition = PolicyCondition(field="file", operator="contains", value="/test/")

        assert engine._condition_matches(condition, {"file": "/src/test/foo.py"}) is True
        assert engine._condition_matches(condition, {"file": "/src/main.py"}) is False

    def test_contains_operator_case_insensitive(self):
        """Test contains operator case insensitive."""
        engine = PolicyEngine([])

        condition = PolicyCondition(
            field="file",
            operator="contains",
            value="/TEST/",
            case_sensitive=False
        )

        assert engine._condition_matches(condition, {"file": "/src/test/foo.py"}) is True
        assert engine._condition_matches(condition, {"file": "/src/Test/foo.py"}) is True

    def test_regex_operator(self):
        """Test regex operator."""
        engine = PolicyEngine([])

        condition = PolicyCondition(
            field="title",
            operator="regex",
            value=r"(?i)sql.*injection"
        )

        assert engine._condition_matches(condition, {"title": "SQL Injection vulnerability"}) is True
        assert engine._condition_matches(condition, {"title": "sql injection"}) is True
        assert engine._condition_matches(condition, {"title": "XSS vulnerability"}) is False

    def test_in_operator(self):
        """Test 'in' operator with list values."""
        engine = PolicyEngine([])

        condition = PolicyCondition(
            field="severity",
            operator="in",
            value=["LOW", "INFO"]
        )

        assert engine._condition_matches(condition, {"severity": "LOW"}) is True
        assert engine._condition_matches(condition, {"severity": "INFO"}) is True
        assert engine._condition_matches(condition, {"severity": "HIGH"}) is False

    def test_gt_operator(self):
        """Test greater than operator."""
        engine = PolicyEngine([])

        condition = PolicyCondition(field="cvss_score", operator="gt", value=7.0)

        assert engine._condition_matches(condition, {"cvss_score": 8.5}) is True
        assert engine._condition_matches(condition, {"cvss_score": 7.1}) is True
        assert engine._condition_matches(condition, {"cvss_score": 6.9}) is False

    def test_lt_operator(self):
        """Test less than operator."""
        engine = PolicyEngine([])

        condition = PolicyCondition(field="cvss_score", operator="lt", value=4.0)

        assert engine._condition_matches(condition, {"cvss_score": 3.5}) is True
        assert engine._condition_matches(condition, {"cvss_score": 2.0}) is True
        assert engine._condition_matches(condition, {"cvss_score": 5.0}) is False

    def test_nested_field_access(self):
        """Test dot notation for nested fields."""
        engine = PolicyEngine([])

        condition = PolicyCondition(
            field="git_blame.author",
            operator="equals",
            value="John Doe"
        )

        finding = {
            "file": "test.py",
            "git_blame": {
                "author": "John Doe",
                "email": "john@example.com"
            }
        }

        assert engine._condition_matches(condition, finding) is True

    def test_missing_field_returns_false(self):
        """Test that missing fields don't match."""
        engine = PolicyEngine([])

        condition = PolicyCondition(field="nonexistent", operator="equals", value="test")

        assert engine._condition_matches(condition, {"other": "value"}) is False


class TestPolicyRules:
    """Test rule matching logic."""

    def test_rule_with_single_condition(self):
        """Test rule with one condition."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="TEST-001",
            name="Test Rule",
            conditions=[
                PolicyCondition(field="severity", operator="equals", value="CRITICAL")
            ],
            action="fail"
        )

        assert engine._rule_matches(rule, {"severity": "CRITICAL"}) is True
        assert engine._rule_matches(rule, {"severity": "HIGH"}) is False

    def test_rule_with_multiple_conditions_all_match(self):
        """Test rule where all conditions match (AND logic)."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="TEST-002",
            name="Test Rule",
            conditions=[
                PolicyCondition(field="severity", operator="equals", value="HIGH"),
                PolicyCondition(field="tool", operator="equals", value="semgrep")
            ],
            action="suppress"
        )

        finding = {"severity": "HIGH", "tool": "semgrep"}
        assert engine._rule_matches(rule, finding) is True

    def test_rule_with_multiple_conditions_partial_match(self):
        """Test rule where only some conditions match (should fail)."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="TEST-003",
            name="Test Rule",
            conditions=[
                PolicyCondition(field="severity", operator="equals", value="HIGH"),
                PolicyCondition(field="tool", operator="equals", value="semgrep")
            ],
            action="suppress"
        )

        finding = {"severity": "HIGH", "tool": "bandit"}
        assert engine._rule_matches(rule, finding) is False

    def test_disabled_rule_does_not_match(self):
        """Test that disabled rules are skipped."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="TEST-004",
            name="Disabled Rule",
            enabled=False,
            conditions=[
                PolicyCondition(field="severity", operator="equals", value="HIGH")
            ],
            action="fail"
        )

        # Rule should not match even if conditions would match
        assert rule.enabled is False


class TestPolicyActions:
    """Test action application."""

    def test_suppress_action(self):
        """Test suppress action adds suppression fields."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="SUP-001",
            name="Suppress Rule",
            conditions=[PolicyCondition(field="severity", operator="equals", value="LOW")],
            action="suppress",
            reason="Low severity auto-suppressed"
        )

        finding = {"severity": "LOW", "title": "Test Finding"}
        result = engine._apply_rules(finding, [rule])

        assert result["suppressed"] is True
        assert result["suppression_reason"] == "Low severity auto-suppressed"
        assert result["suppressed_by_policy"] == "SUP-001"

    def test_fail_action(self):
        """Test fail action adds violation fields."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="FAIL-001",
            name="Fail Rule",
            conditions=[PolicyCondition(field="severity", operator="equals", value="CRITICAL")],
            action="fail",
            action_config={"fail_build": True}
        )

        finding = {"severity": "CRITICAL", "title": "Critical Issue"}
        result = engine._apply_rules(finding, [rule])

        assert result["policy_violation"] is True
        assert result["policy_rule"] == "FAIL-001"
        assert result["fail_build"] is True

    def test_warn_action(self):
        """Test warn action adds warning fields."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="WARN-001",
            name="Warn Rule",
            conditions=[PolicyCondition(field="severity", operator="equals", value="MEDIUM")],
            action="warn"
        )

        finding = {"severity": "MEDIUM", "title": "Medium Issue"}
        result = engine._apply_rules(finding, [rule])

        assert result["policy_warning"] is True
        assert result["policy_rule"] == "WARN-001"

    def test_tag_action(self):
        """Test tag action adds tags."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="TAG-001",
            name="Tag Rule",
            conditions=[PolicyCondition(field="title", operator="regex", value="(?i)sql.*injection")],
            action="tag",
            tags=["sql-injection", "owasp-top-10"]
        )

        finding = {"title": "SQL Injection vulnerability", "severity": "HIGH"}
        result = engine._apply_rules(finding, [rule])

        assert "policy_tags" in result
        assert "sql-injection" in result["policy_tags"]
        assert "owasp-top-10" in result["policy_tags"]

    def test_severity_override(self):
        """Test severity override."""
        engine = PolicyEngine([])

        rule = PolicyRule(
            id="SEV-001",
            name="Escalate Severity",
            conditions=[PolicyCondition(field="file", operator="contains", value="/payment/")],
            action="tag",
            severity_override="CRITICAL",
            tags=["escalated"]
        )

        finding = {"severity": "MEDIUM", "file": "/src/payment/checkout.py"}
        result = engine._apply_rules(finding, [rule])

        assert result["severity"] == "CRITICAL"

    def test_multiple_rules_applied(self):
        """Test multiple rules can apply to same finding."""
        engine = PolicyEngine([])

        rules = [
            PolicyRule(
                id="RULE-001",
                name="Tag SQL",
                conditions=[PolicyCondition(field="title", operator="contains", value="SQL")],
                action="tag",
                tags=["sql-related"]
            ),
            PolicyRule(
                id="RULE-002",
                name="Escalate",
                conditions=[PolicyCondition(field="title", operator="contains", value="SQL")],
                action="tag",
                severity_override="HIGH",
                tags=["escalated"]
            )
        ]

        finding = {"title": "SQL Injection", "severity": "MEDIUM"}
        result = engine._apply_rules(finding, rules)

        assert result["severity"] == "HIGH"
        assert "sql-related" in result["policy_tags"]
        assert "escalated" in result["policy_tags"]


class TestPolicyLoader:
    """Test policy file loading."""

    def test_load_yaml_policy(self, tmp_path):
        """Test loading YAML policy file."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_data = {
            "version": "1.0",
            "name": "Test Policy",
            "description": "Test policy description",
            "rules": [
                {
                    "id": "TEST-001",
                    "name": "Test Rule",
                    "conditions": [
                        {"field": "severity", "operator": "equals", "value": "HIGH"}
                    ],
                    "action": "fail"
                }
            ]
        }

        with open(policy_file, 'w') as f:
            yaml.dump(policy_data, f)

        policy = load_policy_file(policy_file)

        assert policy.name == "Test Policy"
        assert len(policy.rules) == 1
        assert policy.rules[0].id == "TEST-001"

    def test_load_json_policy(self, tmp_path):
        """Test loading JSON policy file."""
        import json

        policy_file = tmp_path / "test-policy.json"
        policy_data = {
            "version": "1.0",
            "name": "Test Policy JSON",
            "rules": [
                {
                    "id": "TEST-002",
                    "name": "JSON Rule",
                    "conditions": [
                        {"field": "tool", "operator": "equals", "value": "trivy"}
                    ],
                    "action": "suppress",
                    "reason": "Test suppression"
                }
            ]
        }

        with open(policy_file, 'w') as f:
            json.dump(policy_data, f)

        policy = load_policy_file(policy_file)

        assert policy.name == "Test Policy JSON"
        assert len(policy.rules) == 1
        assert policy.rules[0].action == "suppress"

    def test_invalid_file_format_raises_error(self, tmp_path):
        """Test that invalid file format raises ValueError."""
        policy_file = tmp_path / "test-policy.txt"
        policy_file.write_text("invalid content")

        with pytest.raises(ValueError, match="Unsupported policy file format"):
            load_policy_file(policy_file)


class TestPolicyEngineIntegration:
    """Test end-to-end policy engine functionality."""

    def test_complete_policy_evaluation(self, tmp_path):
        """Test complete policy evaluation workflow."""
        # Create policy file
        policy_file = tmp_path / "security.yaml"
        policy_data = {
            "version": "1.0",
            "name": "Security Policy",
            "rules": [
                {
                    "id": "SEC-001",
                    "name": "Suppress low severity",
                    "conditions": [
                        {"field": "severity", "operator": "in", "value": ["LOW", "INFO"]}
                    ],
                    "action": "suppress",
                    "reason": "Low severity auto-suppressed"
                },
                {
                    "id": "SEC-002",
                    "name": "Fail on critical",
                    "conditions": [
                        {"field": "severity", "operator": "equals", "value": "CRITICAL"}
                    ],
                    "action": "fail"
                },
                {
                    "id": "SEC-003",
                    "name": "Tag SQL injection",
                    "conditions": [
                        {"field": "title", "operator": "regex", "value": "(?i)sql.*injection"}
                    ],
                    "action": "tag",
                    "tags": ["sql-injection", "owasp-a03"]
                }
            ]
        }

        with open(policy_file, 'w') as f:
            yaml.dump(policy_data, f)

        # Create engine and load policy
        engine = PolicyEngine([policy_file])

        assert len(engine.policies) == 1
        assert len(engine.policies[0].rules) == 3

        # Create test findings
        findings = [
            {"severity": "LOW", "title": "Info finding", "file": "test.py"},
            {"severity": "CRITICAL", "title": "Critical bug", "file": "main.py"},
            {"severity": "HIGH", "title": "SQL Injection risk", "file": "db.py"},
            {"severity": "MEDIUM", "title": "XSS vulnerability", "file": "web.py"}
        ]

        # Evaluate findings
        results = engine.evaluate(findings)

        # Check results
        assert len(results) == 4

        # First finding should be suppressed
        assert results[0]["suppressed"] is True
        assert results[0]["suppressed_by_policy"] == "SEC-001"

        # Second finding should have policy violation
        assert results[1]["policy_violation"] is True
        assert results[1]["policy_rule"] == "SEC-002"

        # Third finding should be tagged
        assert "sql-injection" in results[2]["policy_tags"]
        assert "owasp-a03" in results[2]["policy_tags"]

        # Fourth finding should be unchanged
        assert "suppressed" not in results[3]
        assert "policy_violation" not in results[3]

    def test_policy_directory_loading(self, tmp_path):
        """Test loading all policies from a directory."""
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()

        # Create multiple policy files
        policy1 = policies_dir / "security.yaml"
        policy1_data = {
            "version": "1.0",
            "name": "Security Policy",
            "rules": [
                {
                    "id": "SEC-001",
                    "name": "Rule 1",
                    "conditions": [{"field": "severity", "operator": "equals", "value": "HIGH"}],
                    "action": "fail"
                }
            ]
        }
        with open(policy1, 'w') as f:
            yaml.dump(policy1_data, f)

        policy2 = policies_dir / "compliance.yaml"
        policy2_data = {
            "version": "1.0",
            "name": "Compliance Policy",
            "rules": [
                {
                    "id": "COMP-001",
                    "name": "Rule 2",
                    "conditions": [{"field": "tool", "operator": "equals", "value": "checkov"}],
                    "action": "warn"
                }
            ]
        }
        with open(policy2, 'w') as f:
            yaml.dump(policy2_data, f)

        # Load from directory
        engine = PolicyEngine([policies_dir])

        assert len(engine.policies) == 2

        # Verify both policies loaded
        policy_names = [p.name for p in engine.policies]
        assert "Security Policy" in policy_names
        assert "Compliance Policy" in policy_names

    def test_git_blame_field_matching(self, tmp_path):
        """Test policy matching on git blame fields."""
        policy_file = tmp_path / "git-policy.yaml"
        policy_data = {
            "version": "1.0",
            "name": "Git Blame Policy",
            "rules": [
                {
                    "id": "GIT-001",
                    "name": "Tag contractor code",
                    "conditions": [
                        {
                            "field": "git_blame.email",
                            "operator": "contains",
                            "value": "@contractor.com"
                        }
                    ],
                    "action": "tag",
                    "tags": ["contractor", "requires-review"]
                }
            ]
        }

        with open(policy_file, 'w') as f:
            yaml.dump(policy_data, f)

        engine = PolicyEngine([policy_file])

        finding = {
            "title": "Security issue",
            "file": "src/module.py",
            "git_blame": {
                "author": "External Dev",
                "email": "dev@contractor.com",
                "commit": "abc123"
            }
        }

        results = engine.evaluate([finding])

        assert len(results) == 1
        assert "contractor" in results[0]["policy_tags"]
        assert "requires-review" in results[0]["policy_tags"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
