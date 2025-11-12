"""Core policy evaluation engine."""

import re
from typing import List, Dict, Any
from pathlib import Path
import logging

from .schema import PolicyFile, PolicyRule, PolicyCondition
from .loader import load_policy_file

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Core policy evaluation engine."""

    def __init__(self, policy_paths: List[Path]):
        self.policies: List[PolicyFile] = []
        self.load_policies(policy_paths)

    def load_policies(self, paths: List[Path]) -> None:
        """Load all policy files."""
        for path in paths:
            if path.is_dir():
                # Load all YAML/JSON files in directory
                for policy_file in list(path.glob("**/*.yaml")) + list(path.glob("**/*.yml")) + list(path.glob("**/*.json")):
                    try:
                        policy = load_policy_file(policy_file)
                        self.policies.append(policy)
                        logger.info(f"Loaded policy: {policy.name} ({len(policy.rules)} rules)")
                    except Exception as e:
                        logger.error(f"Failed to load policy {policy_file}: {e}")
            else:
                try:
                    policy = load_policy_file(path)
                    self.policies.append(policy)
                    logger.info(f"Loaded policy: {policy.name} ({len(policy.rules)} rules)")
                except Exception as e:
                    logger.error(f"Failed to load policy {path}: {e}")

    def evaluate(self, findings: List[Dict]) -> List[Dict]:
        """Apply policies to findings."""
        processed = []

        for finding in findings:
            # Apply all matching rules
            matched_rules = self._find_matching_rules(finding)

            if matched_rules:
                finding = self._apply_rules(finding, matched_rules)

            processed.append(finding)

        return processed

    def _find_matching_rules(self, finding: Dict) -> List[PolicyRule]:
        """Find all rules that match a finding."""
        matched = []

        for policy in self.policies:
            for rule in policy.rules:
                if not rule.enabled:
                    continue

                if self._rule_matches(rule, finding):
                    matched.append(rule)

        return matched

    def _rule_matches(self, rule: PolicyRule, finding: Dict) -> bool:
        """Check if all conditions in a rule match the finding."""
        if not rule.conditions:
            return False

        # All conditions must match (AND logic)
        for condition in rule.conditions:
            if not self._condition_matches(condition, finding):
                return False

        return True

    def _condition_matches(self, condition: PolicyCondition, finding: Dict) -> bool:
        """Check if a single condition matches."""
        # Extract field value from finding (support nested keys)
        field_value = self._get_field_value(finding, condition.field)

        if field_value is None:
            return False

        # Apply operator
        if condition.operator == "equals":
            return self._compare_equals(field_value, condition.value, condition.case_sensitive)

        elif condition.operator == "contains":
            return self._compare_contains(field_value, condition.value, condition.case_sensitive)

        elif condition.operator == "regex":
            return self._compare_regex(field_value, condition.value)

        elif condition.operator == "gt":
            return field_value > condition.value

        elif condition.operator == "lt":
            return field_value < condition.value

        elif condition.operator == "in":
            return field_value in condition.value

        return False

    def _apply_rules(self, finding: Dict, rules: List[PolicyRule]) -> Dict:
        """Apply matched rules to a finding."""
        for rule in rules:
            if rule.action == "suppress":
                finding["suppressed"] = True
                finding["suppression_reason"] = rule.reason or f"Policy: {rule.name}"
                finding["suppressed_by_policy"] = rule.id

            elif rule.action == "fail":
                finding["policy_violation"] = True
                finding["policy_rule"] = rule.id
                finding["fail_build"] = rule.action_config.get("fail_build", True)

            elif rule.action == "warn":
                finding["policy_warning"] = True
                finding["policy_rule"] = rule.id

            elif rule.action == "tag":
                if "policy_tags" not in finding:
                    finding["policy_tags"] = []
                finding["policy_tags"].extend(rule.tags)

            # Apply severity override
            if rule.severity_override:
                finding["severity"] = rule.severity_override

        return finding

    def _get_field_value(self, obj: Dict, field_path: str) -> Any:
        """Extract nested field value using dot notation."""
        parts = field_path.split(".")
        value = obj

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

        return value

    def _compare_equals(self, a: Any, b: Any, case_sensitive: bool) -> bool:
        """Case-aware equality comparison."""
        if isinstance(a, str) and isinstance(b, str) and not case_sensitive:
            return a.lower() == b.lower()
        return a == b

    def _compare_contains(self, haystack: str, needle: str, case_sensitive: bool) -> bool:
        """Case-aware substring matching."""
        if not isinstance(haystack, str):
            haystack = str(haystack)
        if not case_sensitive:
            return needle.lower() in haystack.lower()
        return needle in haystack

    def _compare_regex(self, value: str, pattern: str) -> bool:
        """Regular expression matching."""
        if not isinstance(value, str):
            value = str(value)
        try:
            return bool(re.search(pattern, value))
        except re.error:
            logger.error(f"Invalid regex pattern: {pattern}")
            return False
