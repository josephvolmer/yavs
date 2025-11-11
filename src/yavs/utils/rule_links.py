"""Generate external links to rule documentation."""

from typing import Optional


def get_rule_documentation_url(tool: str, rule_id: str) -> Optional[str]:
    """
    Get the external documentation URL for a security rule.

    Args:
        tool: Scanner tool name (e.g., "Trivy", "Checkov", "Semgrep")
        rule_id: Rule/CVE identifier

    Returns:
        URL to rule documentation, or None if not available
    """
    tool_lower = tool.lower()

    # Trivy - CVE and vulnerability database
    if tool_lower == "trivy":
        if rule_id.startswith("CVE-"):
            # NVD (National Vulnerability Database)
            return f"https://nvd.nist.gov/vuln/detail/{rule_id}"
        elif rule_id.startswith("GHSA-"):
            # GitHub Security Advisory
            return f"https://github.com/advisories/{rule_id}"
        elif rule_id.startswith("DLA-") or rule_id.startswith("DSA-"):
            # Debian Security Advisory
            return f"https://security-tracker.debian.org/tracker/{rule_id}"

    # Checkov - policy documentation
    elif tool_lower == "checkov":
        # Checkov rules are in format CKV_AWS_123 or CKV2_AWS_123
        if rule_id.startswith("CKV"):
            # Extract the provider (AWS, AZURE, GCP, etc.)
            parts = rule_id.split("_")
            if len(parts) >= 2:
                # Checkov docs are organized by provider
                return f"https://docs.prismacloud.io/en/enterprise-edition/policy-reference/ci-cd-pipeline-policy-reference/{rule_id.lower()}"

    # Semgrep - rule registry
    elif tool_lower == "semgrep":
        if rule_id:
            # Semgrep rules are usually in format: category.subcategory.rule-name
            # Link to the Semgrep registry
            return f"https://semgrep.dev/r?q={rule_id}"

    # Bandit - security issue types
    elif tool_lower == "bandit":
        if rule_id.startswith("B"):
            # Bandit uses B### format (e.g., B201, B301)
            # Link to Bandit documentation
            return f"https://bandit.readthedocs.io/en/latest/plugins/{rule_id.lower()}.html"

    return None


def format_rule_link_html(tool: str, rule_id: str) -> str:
    """
    Format a rule identifier with an optional external link.

    Args:
        tool: Scanner tool name
        rule_id: Rule/CVE identifier

    Returns:
        HTML string with link if available, otherwise just the rule ID
    """
    if not rule_id or rule_id == "N/A":
        return rule_id or "N/A"

    url = get_rule_documentation_url(tool, rule_id)

    if url:
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer" style="color: #2563eb; text-decoration: underline;">{rule_id} <i class="ti ti-external-link" style="font-size: 0.75rem;"></i></a>'

    return rule_id
