"""Tests for logging utilities."""
import pytest
from yavs.utils.logging import LoggerMixin, configure_logging, get_logger, set_log_level

class TestLoggerMixin:
    """Test LoggerMixin class."""

    def test_logger_creation(self):
        """Test logger mixin creates logger."""
        class TestClass(LoggerMixin):
            pass
        obj = TestClass()
        assert hasattr(obj, 'logger')
        assert obj.logger is not None

    def test_logger_name(self):
        """Test logger has correct name."""
        class TestClass(LoggerMixin):
            pass
        obj = TestClass()
        assert 'TestClass' in obj.logger.name


class TestConfigureLogging:
    """Test configure_logging function."""

    def test_configure_logging_with_config(self):
        """Test configure_logging with config dict."""
        config = {
            "level": "INFO",
            "file": None
        }
        configure_logging(config)
        # Should not raise

    def test_configure_logging_idempotent(self):
        """Test configure_logging can be called multiple times."""
        config = {"level": "INFO"}
        configure_logging(config)
        configure_logging(config)
        # Should not raise


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger(self):
        """Test get_logger returns logger."""
        logger = get_logger("test")
        assert logger is not None
        assert logger.name == "test"

    def test_get_logger_different_names(self):
        """Test get_logger with different names."""
        logger1 = get_logger("test1")
        logger2 = get_logger("test2")
        assert logger1.name != logger2.name


class TestSetLogLevel:
    """Test set_log_level function."""

    def test_set_log_level_info(self):
        """Test setting log level to INFO."""
        set_log_level("INFO")
        # Should not raise

    def test_set_log_level_debug(self):
        """Test setting log level to DEBUG."""
        set_log_level("DEBUG")
        # Should not raise

    def test_set_log_level_warning(self):
        """Test setting log level to WARNING."""
        set_log_level("WARNING")
        # Should not raise


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
