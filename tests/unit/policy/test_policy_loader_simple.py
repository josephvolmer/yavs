"""Simple unit tests for policy loader."""

import json
from pathlib import Path

import pytest
import yaml

from yavs.policy.loader import load_policy_file
from yavs.policy.schema import PolicyFile, PolicyRule


class TestPolicyLoaderSimple:
    """Test policy loading functionality."""

    def test_load_policy_from_yaml(self, tmp_path):
        """Test loading a valid YAML policy file."""
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text("""
name: "Test Policy"
version: "1.0"
rules:
  - id: "TEST-001"
    name: "Test Rule"
    conditions:
      - field: "severity"
        operator: "equals"
        value: "HIGH"
    action: "fail"
""")

        policy = load_policy_file(policy_file)

        assert policy.name == "Test Policy"
        assert policy.version == "1.0"
        assert len(policy.rules) == 1
        assert policy.rules[0].id == "TEST-001"

    def test_load_policy_from_json(self, tmp_path):
        """Test loading a valid JSON policy file."""
        policy_file = tmp_path / "test.json"
        policy_data = {
            "name": "JSON Policy",
            "version": "2.0",
            "rules": [
                {
                    "id": "JSON-001",
                    "name": "JSON Rule",
                    "conditions": [],
                    "action": "suppress"
                }
            ]
        }
        policy_file.write_text(json.dumps(policy_data))

        policy = load_policy_file(policy_file)

        assert policy.name == "JSON Policy"
        assert isinstance(policy, PolicyFile)

    def test_load_policy_with_multiple_rules(self, tmp_path):
        """Test loading policy with multiple rules."""
        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text("""
name: "Multi-Rule Policy"
version: "1.0"
rules:
  - id: "RULE-001"
    name: "Rule 1"
    action: "suppress"
  - id: "RULE-002"
    name: "Rule 2"
    action: "warn"
  - id: "RULE-003"
    name: "Rule 3"
    action: "fail"
""")

        policy = load_policy_file(policy_file)
        assert len(policy.rules) == 3

    def test_load_policy_invalid_yaml(self, tmp_path):
        """Test loading invalid YAML."""
        policy_file = tmp_path / "invalid.yaml"
        policy_file.write_text("invalid: yaml: content: [")

        with pytest.raises(Exception):
            load_policy_file(policy_file)

    def test_load_policy_unsupported_extension(self, tmp_path):
        """Test loading policy with unsupported file extension."""
        policy_file = tmp_path / "policy.txt"
        policy_file.write_text("not a valid format")

        with pytest.raises(ValueError):
            load_policy_file(policy_file)

    def test_policy_validation(self, tmp_path):
        """Test that loaded policies are validated."""
        policy_file = tmp_path / "validate.yaml"
        policy_file.write_text("""
name: "Valid Policy"
version: "1.0"
rules:
  - id: "VALID-001"
    name: "Valid Rule"
    conditions:
      - field: "severity"
        operator: "equals"
        value: "HIGH"
    action: "fail"
""")

        policy = load_policy_file(policy_file)

        assert isinstance(policy, PolicyFile)
        assert isinstance(policy.rules[0], PolicyRule)

    def test_load_builtin_security_policy(self):
        """Test loading built-in security policy."""
        builtin_path = Path("src/yavs/policy/builtins/security.yaml")
        if builtin_path.exists():
            policy = load_policy_file(builtin_path)
            assert policy.name is not None
            assert len(policy.rules) > 0

    def test_load_builtin_compliance_policy(self):
        """Test loading built-in compliance policy."""
        builtin_path = Path("src/yavs/policy/builtins/compliance.yaml")
        if builtin_path.exists():
            policy = load_policy_file(builtin_path)
            assert policy.name is not None
            assert len(policy.rules) > 0

    def test_load_policy_with_tags(self, tmp_path):
        """Test loading policy with tags."""
        policy_file = tmp_path / "tags.yaml"
        policy_file.write_text("""
name: "Tagged Policy"
version: "1.0"
rules:
  - id: "TAG-001"
    name: "Tagging Rule"
    action: "tag"
    tags: ["legacy-code", "needs-review"]
""")

        policy = load_policy_file(policy_file)
        assert len(policy.rules[0].tags) == 2

    def test_load_policy_with_description(self, tmp_path):
        """Test loading policy with description fields."""
        policy_file = tmp_path / "desc.yaml"
        policy_file.write_text("""
name: "Described Policy"
version: "1.0"
description: "This is a test policy"
rules:
  - id: "DESC-001"
    name: "Described Rule"
    description: "This is a test rule"
    action: "suppress"
""")

        policy = load_policy_file(policy_file)
        assert policy.description == "This is a test policy"
        assert policy.rules[0].description == "This is a test rule"
