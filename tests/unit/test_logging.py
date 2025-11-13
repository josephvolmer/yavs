"""Tests for logging utilities."""
import pytest
from yavs.utils.logging import LoggerMixin, setup_logging, get_logger

class TestLoggerMixin:
    def test_logger_creation(self):
        """Test logger mixin creates logger."""
        class TestClass(LoggerMixin):
            pass
        obj = TestClass()
        assert hasattr(obj, 'logger')
        assert obj.logger is not None

class TestSetupLogging:
    def test_setup_logging_returns_logger(self):
        """Test setup_logging returns logger."""
        logger = setup_logging()
        assert logger is not None

class TestGetLogger:
    def test_get_logger(self):
        """Test get_logger returns logger."""
        logger = get_logger("test")
        assert logger is not None
        assert logger.name == "test"
