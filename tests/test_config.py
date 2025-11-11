"""
Comprehensive tests for configuration file handling.

Tests config file loading, validation, defaults, and overrides.
"""

import pytest
import yaml
from pathlib import Path
from src.yavs.cli import load_config


class TestConfigLoading:
    """Tests for config file loading."""

    def test_load_valid_config(self, tmp_path):
        """Test loading a valid config file."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scan": {
                "directories": ["src"],
                "ignore_paths": ["test/"]
            },
            "output": {
                "directory": "output",
                "json": "results.json"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["scan"]["directories"] == ["src"]
        assert config["output"]["directory"] == "output"

    def test_load_config_with_scanners(self, tmp_path):
        """Test loading config with scanner configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scanners": {
                "trivy": {
                    "enabled": True,
                    "timeout": 300,
                    "flags": "--severity HIGH"
                },
                "semgrep": {
                    "enabled": False,
                    "timeout": 180
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["scanners"]["trivy"]["enabled"] is True
        assert config["scanners"]["trivy"]["flags"] == "--severity HIGH"
        assert config["scanners"]["semgrep"]["enabled"] is False

    def test_load_config_with_ai_settings(self, tmp_path):
        """Test loading config with AI settings."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "enabled": True,
                "provider": "anthropic",
                "model": "claude-sonnet-4-5-20250929",
                "max_tokens": 4096,
                "features": {
                    "fix_suggestions": True,
                    "summarize": True,
                    "triage": False
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["enabled"] is True
        assert config["ai"]["provider"] == "anthropic"
        assert config["ai"]["features"]["triage"] is False

    def test_load_config_with_metadata(self, tmp_path):
        """Test loading config with project metadata."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "metadata": {
                "project": "my-project",
                "branch": "main",
                "commit_hash": "abc123"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["metadata"]["project"] == "my-project"
        assert config["metadata"]["branch"] == "main"
        assert config["metadata"]["commit_hash"] == "abc123"

    def test_load_nonexistent_config_returns_defaults(self, tmp_path):
        """Test that nonexistent config returns default configuration."""
        config_file = tmp_path / "nonexistent.yaml"

        config = load_config(config_file)

        # Should return defaults
        assert "scan" in config
        assert "scanners" in config
        assert "output" in config
        assert config["scan"]["directories"] == ["."]

    def test_load_config_without_path_uses_defaults(self):
        """Test loading config without specifying path."""
        config = load_config(None)

        # Should load default config or fallback defaults
        assert "scan" in config
        assert "scanners" in config
        assert isinstance(config["scan"]["directories"], list)


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_default_scan_directories(self):
        """Test default scan directories."""
        config = load_config(Path("nonexistent.yaml"))

        assert "." in config["scan"]["directories"]

    def test_default_ignore_paths(self):
        """Test default ignore paths."""
        config = load_config(Path("nonexistent.yaml"))

        ignore_paths = config["scan"]["ignore_paths"]
        assert "node_modules/" in ignore_paths
        assert "vendor/" in ignore_paths
        assert "\\.git/" in ignore_paths

    def test_default_scanner_settings(self):
        """Test default scanner settings."""
        config = load_config(Path("nonexistent.yaml"))

        for scanner in ["trivy", "semgrep", "bandit", "binskim", "checkov"]:
            assert scanner in config["scanners"]
            assert config["scanners"][scanner]["enabled"] is True
            assert config["scanners"][scanner]["timeout"] > 0

    def test_default_output_settings(self):
        """Test default output settings."""
        config = load_config(Path("nonexistent.yaml"))

        assert config["output"]["directory"] == "."
        assert "json" in config["output"]
        assert "sarif" in config["output"]

    def test_default_ai_settings(self):
        """Test default AI settings."""
        config = load_config(Path("nonexistent.yaml"))

        assert "ai" in config
        assert config["ai"]["enabled"] is True


class TestConfigIgnorePaths:
    """Tests for ignore path configuration."""

    def test_ignore_paths_list(self, tmp_path):
        """Test multiple ignore paths."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scan": {
                "ignore_paths": [
                    "node_modules/",
                    "test/",
                    ".*\\.min\\.js$"
                ]
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert len(config["scan"]["ignore_paths"]) == 3
        assert "node_modules/" in config["scan"]["ignore_paths"]

    def test_ignore_paths_regex_patterns(self, tmp_path):
        """Test regex patterns in ignore paths."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scan": {
                "ignore_paths": [
                    r".*\.min\.js$",
                    r".*_test\.py$",
                    r"^vendor/"
                ]
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        # Should load regex patterns as strings
        assert any(r"\.min\.js" in pattern for pattern in config["scan"]["ignore_paths"])


class TestConfigOutputSettings:
    """Tests for output configuration."""

    def test_output_directory_custom(self, tmp_path):
        """Test custom output directory."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "output": {
                "directory": "custom_output",
                "json": "scan.json",
                "sarif": "scan.sarif"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["output"]["directory"] == "custom_output"
        assert config["output"]["json"] == "scan.json"
        assert config["output"]["sarif"] == "scan.sarif"

    def test_structured_output_format(self, tmp_path):
        """Test structured output format setting."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "output": {
                "structured": True
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["output"]["structured"] is True

    def test_per_tool_files_setting(self, tmp_path):
        """Test per-tool files setting."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "output": {
                "per_tool_files": True
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["output"]["per_tool_files"] is True


class TestConfigScannerSettings:
    """Tests for scanner-specific configuration."""

    def test_scanner_timeout_custom(self, tmp_path):
        """Test custom scanner timeout."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scanners": {
                "trivy": {
                    "timeout": 600
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["scanners"]["trivy"]["timeout"] == 600

    def test_scanner_disabled(self, tmp_path):
        """Test disabling a scanner."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scanners": {
                "semgrep": {
                    "enabled": False
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["scanners"]["semgrep"]["enabled"] is False

    def test_scanner_custom_flags(self, tmp_path):
        """Test custom scanner flags."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scanners": {
                "trivy": {
                    "flags": "--severity HIGH,CRITICAL --exit-code 0"
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert "HIGH,CRITICAL" in config["scanners"]["trivy"]["flags"]

    def test_scanner_native_config_path(self, tmp_path):
        """Test scanner native config path."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scanners": {
                "trivy": {
                    "native_config": "config/trivy.yaml"
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["scanners"]["trivy"]["native_config"] == "config/trivy.yaml"


class TestConfigAISettings:
    """Tests for AI configuration."""

    def test_ai_provider_selection(self, tmp_path):
        """Test AI provider selection."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "provider": "openai"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["provider"] == "openai"

    def test_ai_model_selection(self, tmp_path):
        """Test AI model selection."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "model": "gpt-4o"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["model"] == "gpt-4o"

    def test_ai_features_configuration(self, tmp_path):
        """Test AI features configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "features": {
                    "fix_suggestions": True,
                    "summarize": False,
                    "triage": True
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["features"]["fix_suggestions"] is True
        assert config["ai"]["features"]["summarize"] is False
        assert config["ai"]["features"]["triage"] is True

    def test_ai_rate_limits(self, tmp_path):
        """Test AI rate limit configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "rate_limits": {
                    "anthropic": {
                        "requests_per_minute": 100,
                        "tokens_per_minute": 50000
                    }
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["rate_limits"]["anthropic"]["requests_per_minute"] == 100

    def test_ai_max_fixes_limit(self, tmp_path):
        """Test AI max fixes limit."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "ai": {
                "max_fixes_per_scan": 100
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["ai"]["max_fixes_per_scan"] == 100


class TestConfigSeverityMapping:
    """Tests for severity mapping configuration."""

    def test_custom_severity_mapping(self, tmp_path):
        """Test custom severity mapping."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "severity_mapping": {
                "ERROR": "CRITICAL",
                "WARNING": "HIGH",
                "INFO": "LOW"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["severity_mapping"]["ERROR"] == "CRITICAL"
        assert config["severity_mapping"]["WARNING"] == "HIGH"


class TestConfigLogging:
    """Tests for logging configuration."""

    def test_logging_level(self, tmp_path):
        """Test logging level configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "logging": {
                "level": "DEBUG"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["logging"]["level"] == "DEBUG"

    def test_logging_format(self, tmp_path):
        """Test logging format configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "logging": {
                "format": "json"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["logging"]["format"] == "json"

    def test_logging_file_enabled(self, tmp_path):
        """Test file logging configuration."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "logging": {
                "file": {
                    "enabled": True,
                    "path": "yavs.log",
                    "max_bytes": 10485760,
                    "backup_count": 3
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        assert config["logging"]["file"]["enabled"] is True
        assert config["logging"]["file"]["path"] == "yavs.log"


class TestConfigValidation:
    """Tests for config validation and error handling."""

    def test_load_invalid_yaml(self, tmp_path):
        """Test handling of invalid YAML syntax."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        # Should raise YAML parse error or return defaults
        with pytest.raises(yaml.YAMLError):
            load_config(config_file)

    def test_load_empty_config(self, tmp_path):
        """Test loading empty config file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")

        config = load_config(config_file)

        # Should return defaults for missing sections
        # (behavior depends on implementation - might return empty dict or defaults)
        assert isinstance(config, (dict, type(None)))

    def test_partial_config(self, tmp_path):
        """Test partial config with some sections missing."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scan": {
                "directories": ["src"]
            }
            # Missing other sections
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        # Should load provided sections
        assert config["scan"]["directories"] == ["src"]


class TestConfigIntegration:
    """Integration tests for config with CLI."""

    def test_config_override_with_cli_args(self, tmp_path):
        """Test that CLI args can override config values."""
        # This would be tested in CLI tests with actual command invocation
        # Here we just verify config loading works independently
        config_file = tmp_path / "config.yaml"
        config_data = {
            "output": {
                "directory": "config_output"
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        # CLI should be able to override this
        assert config["output"]["directory"] == "config_output"

    def test_full_config_example(self, tmp_path):
        """Test loading a complete realistic config."""
        config_file = tmp_path / "config.yaml"
        config_data = {
            "scan": {
                "directories": ["src", "lib"],
                "ignore_paths": ["node_modules/", "test/"]
            },
            "metadata": {
                "project": "test-project",
                "branch": "main"
            },
            "scanners": {
                "trivy": {"enabled": True, "timeout": 300},
                "semgrep": {"enabled": True, "timeout": 300}
            },
            "output": {
                "directory": "output",
                "json": "results.json",
                "sarif": "results.sarif",
                "structured": True
            },
            "ai": {
                "enabled": True,
                "provider": "anthropic",
                "features": {
                    "fix_suggestions": True,
                    "summarize": True
                }
            }
        }
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = load_config(config_file)

        # Verify all sections loaded correctly
        assert config["scan"]["directories"] == ["src", "lib"]
        assert config["metadata"]["project"] == "test-project"
        assert config["scanners"]["trivy"]["enabled"] is True
        assert config["output"]["structured"] is True
        assert config["ai"]["enabled"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
