"""Tests for tool version management."""

import pytest
from yavs.utils.tool_versions import (
    get_tested_version,
    get_version_range,
    is_version_compatible,
    get_pip_version_specifier,
    get_all_tools,
    get_tool_description,
    TOOL_VERSIONS
)


class TestGetTestedVersion:
    """Test get_tested_version function."""

    def test_trivy_tested_version(self):
        """Test getting tested version for trivy."""
        version = get_tested_version("trivy")
        assert version is not None
        assert isinstance(version, str)
        assert version == TOOL_VERSIONS["trivy"]["tested"]

    def test_semgrep_tested_version(self):
        """Test getting tested version for semgrep."""
        version = get_tested_version("semgrep")
        assert version is not None
        assert version == TOOL_VERSIONS["semgrep"]["tested"]

    def test_bandit_tested_version(self):
        """Test getting tested version for bandit."""
        version = get_tested_version("bandit")
        assert version is not None
        assert version == TOOL_VERSIONS["bandit"]["tested"]

    def test_checkov_tested_version(self):
        """Test getting tested version for checkov."""
        version = get_tested_version("checkov")
        assert version is not None
        assert version == TOOL_VERSIONS["checkov"]["tested"]

    def test_binskim_no_tested_version(self):
        """Test binskim has no tested version (user-installed)."""
        version = get_tested_version("binskim")
        assert version is None

    def test_unknown_tool(self):
        """Test unknown tool returns None."""
        version = get_tested_version("unknown-tool")
        assert version is None

    def test_case_insensitive(self):
        """Test tool name is case-insensitive."""
        version_lower = get_tested_version("trivy")
        version_upper = get_tested_version("TRIVY")
        version_mixed = get_tested_version("Trivy")
        assert version_lower == version_upper == version_mixed


class TestGetVersionRange:
    """Test get_version_range function."""

    def test_trivy_version_range(self):
        """Test getting version range for trivy."""
        min_ver, max_ver = get_version_range("trivy")
        assert min_ver is not None
        assert max_ver is not None
        assert min_ver == TOOL_VERSIONS["trivy"]["min"]
        assert max_ver == TOOL_VERSIONS["trivy"]["max"]

    def test_semgrep_version_range(self):
        """Test getting version range for semgrep."""
        min_ver, max_ver = get_version_range("semgrep")
        assert min_ver is not None
        assert max_ver is not None

    def test_binskim_no_version_range(self):
        """Test binskim has no version range."""
        min_ver, max_ver = get_version_range("binskim")
        assert min_ver is None
        assert max_ver is None

    def test_unknown_tool_returns_none(self):
        """Test unknown tool returns (None, None)."""
        min_ver, max_ver = get_version_range("unknown-tool")
        assert min_ver is None
        assert max_ver is None

    def test_case_insensitive(self):
        """Test tool name is case-insensitive."""
        range1 = get_version_range("bandit")
        range2 = get_version_range("BANDIT")
        assert range1 == range2


class TestIsVersionCompatible:
    """Test is_version_compatible function."""

    def test_exact_tested_version(self):
        """Test exact tested version is compatible."""
        tested = get_tested_version("trivy")
        is_compat, msg = is_version_compatible("trivy", tested)
        assert is_compat is True
        assert "tested" in msg.lower()

    def test_version_within_range(self):
        """Test version within range is compatible."""
        # Use a version within trivy's range
        min_ver, max_ver = get_version_range("trivy")
        # Parse min version and increment patch
        parts = min_ver.split(".")
        test_ver = f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
        is_compat, msg = is_version_compatible("trivy", test_ver)
        assert is_compat is True
        assert "compatible" in msg.lower()

    def test_version_below_minimum(self):
        """Test version below minimum is incompatible."""
        is_compat, msg = is_version_compatible("trivy", "0.1.0")
        assert is_compat is False
        assert "outside tested range" in msg.lower()

    def test_version_above_maximum(self):
        """Test version above maximum is incompatible."""
        is_compat, msg = is_version_compatible("trivy", "99.99.99")
        assert is_compat is False
        assert "outside tested range" in msg.lower()

    def test_unknown_tool_is_compatible(self):
        """Test unknown tool is marked as compatible."""
        is_compat, msg = is_version_compatible("unknown-tool", "1.0.0")
        assert is_compat is True
        assert "unknown tool" in msg.lower()

    def test_binskim_any_version(self):
        """Test binskim accepts any version (not version-managed)."""
        is_compat, msg = is_version_compatible("binskim", "1.0.0")
        assert is_compat is True
        assert "not version-managed" in msg.lower()

    def test_invalid_version_string(self):
        """Test invalid version string is handled."""
        is_compat, msg = is_version_compatible("trivy", "invalid.version")
        assert is_compat is False
        assert "error parsing" in msg.lower()

    def test_semgrep_tested_version(self):
        """Test semgrep tested version."""
        tested = get_tested_version("semgrep")
        is_compat, msg = is_version_compatible("semgrep", tested)
        assert is_compat is True
        assert "tested" in msg.lower()

    def test_bandit_tested_version(self):
        """Test bandit tested version."""
        tested = get_tested_version("bandit")
        is_compat, msg = is_version_compatible("bandit", tested)
        assert is_compat is True

    def test_checkov_tested_version(self):
        """Test checkov tested version."""
        tested = get_tested_version("checkov")
        is_compat, msg = is_version_compatible("checkov", tested)
        assert is_compat is True


class TestGetPipVersionSpecifier:
    """Test get_pip_version_specifier function."""

    def test_trivy_specifier(self):
        """Test trivy pip specifier."""
        spec = get_pip_version_specifier("trivy")
        assert "trivy" in spec
        assert ">=" in spec
        assert "<=" in spec
        # Should include tested version
        tested = get_tested_version("trivy")
        assert tested in spec

    def test_semgrep_specifier(self):
        """Test semgrep pip specifier."""
        spec = get_pip_version_specifier("semgrep")
        assert "semgrep" in spec
        tested = get_tested_version("semgrep")
        assert tested in spec

    def test_bandit_specifier(self):
        """Test bandit pip specifier."""
        spec = get_pip_version_specifier("bandit")
        assert "bandit" in spec
        assert ">=" in spec

    def test_checkov_specifier(self):
        """Test checkov pip specifier."""
        spec = get_pip_version_specifier("checkov")
        assert "checkov" in spec

    def test_binskim_no_specifier(self):
        """Test binskim returns just tool name."""
        spec = get_pip_version_specifier("binskim")
        assert spec == "binskim"

    def test_unknown_tool(self):
        """Test unknown tool returns tool name."""
        spec = get_pip_version_specifier("unknown-tool")
        assert spec == "unknown-tool"

    def test_specifier_format(self):
        """Test specifier has correct format."""
        spec = get_pip_version_specifier("trivy")
        # Should be like "trivy>=0.67.2,<=0.67.999"
        parts = spec.split(">=")
        assert len(parts) == 2
        assert "trivy" in parts[0]
        version_parts = parts[1].split(",<=")
        assert len(version_parts) == 2

    def test_case_insensitive(self):
        """Test tool name is case-insensitive."""
        spec1 = get_pip_version_specifier("trivy")
        spec2 = get_pip_version_specifier("TRIVY")
        # Should be functionally equivalent (lowercase tool name)
        assert "trivy" in spec1.lower()
        assert "trivy" in spec2.lower()


class TestGetAllTools:
    """Test get_all_tools function."""

    def test_returns_list(self):
        """Test returns a list."""
        tools = get_all_tools()
        assert isinstance(tools, list)

    def test_contains_known_tools(self):
        """Test contains expected tools."""
        tools = get_all_tools()
        assert "trivy" in tools
        assert "semgrep" in tools
        assert "bandit" in tools
        assert "checkov" in tools
        assert "binskim" in tools

    def test_tool_count(self):
        """Test expected number of tools."""
        tools = get_all_tools()
        assert len(tools) == len(TOOL_VERSIONS)
        assert len(tools) >= 5  # At least 5 tools


class TestGetToolDescription:
    """Test get_tool_description function."""

    def test_trivy_description(self):
        """Test trivy has description."""
        desc = get_tool_description("trivy")
        assert desc is not None
        assert isinstance(desc, str)
        assert len(desc) > 0
        assert "vulnerability" in desc.lower() or "scanner" in desc.lower()

    def test_semgrep_description(self):
        """Test semgrep has description."""
        desc = get_tool_description("semgrep")
        assert desc is not None
        assert "static analysis" in desc.lower() or "analysis" in desc.lower()

    def test_bandit_description(self):
        """Test bandit has description."""
        desc = get_tool_description("bandit")
        assert desc is not None
        assert "python" in desc.lower()

    def test_checkov_description(self):
        """Test checkov has description."""
        desc = get_tool_description("checkov")
        assert desc is not None
        assert "iac" in desc.lower() or "infrastructure" in desc.lower()

    def test_binskim_description(self):
        """Test binskim has description."""
        desc = get_tool_description("binskim")
        assert desc is not None
        assert "binary" in desc.lower()

    def test_unknown_tool(self):
        """Test unknown tool returns None."""
        desc = get_tool_description("unknown-tool")
        assert desc is None

    def test_case_insensitive(self):
        """Test tool name is case-insensitive."""
        desc1 = get_tool_description("trivy")
        desc2 = get_tool_description("TRIVY")
        desc3 = get_tool_description("Trivy")
        assert desc1 == desc2 == desc3


class TestToolVersionsData:
    """Test TOOL_VERSIONS data structure."""

    def test_all_tools_have_required_fields(self):
        """Test all tools have required fields."""
        for tool, info in TOOL_VERSIONS.items():
            assert "tested" in info
            assert "min" in info
            assert "max" in info
            assert "description" in info

    def test_descriptions_not_empty(self):
        """Test all tools have non-empty descriptions."""
        for tool, info in TOOL_VERSIONS.items():
            desc = info["description"]
            assert desc is not None
            assert isinstance(desc, str)
            assert len(desc) > 10  # Reasonable description length

    def test_version_consistency(self):
        """Test version consistency (tested within min-max range)."""
        for tool, info in TOOL_VERSIONS.items():
            tested = info["tested"]
            min_ver = info["min"]
            max_ver = info["max"]

            # Skip tools without version management
            if tested is None:
                assert min_ver is None
                assert max_ver is None
                continue

            # Tested version should be within range
            from packaging import version as pkg_version
            tested_v = pkg_version.parse(tested)
            if min_ver:
                min_v = pkg_version.parse(min_ver)
                assert tested_v >= min_v, f"{tool}: tested {tested} < min {min_ver}"
            if max_ver:
                max_v = pkg_version.parse(max_ver)
                assert tested_v <= max_v, f"{tool}: tested {tested} > max {max_ver}"

    def test_version_strings_parseable(self):
        """Test all version strings are parseable."""
        from packaging import version as pkg_version

        for tool, info in TOOL_VERSIONS.items():
            for key in ["tested", "min", "max"]:
                ver = info[key]
                if ver is not None:
                    # Should not raise exception
                    pkg_version.parse(ver)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
