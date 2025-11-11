"""Logging utilities with Rich formatting."""

import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler
from rich.console import Console


# Global console instance
console = Console()

# Global flag to track if logging has been initialized
_logging_initialized = False


def configure_logging(config: Dict[str, Any]):
    """
    Configure logging based on config settings.

    Args:
        config: Logging configuration dict from config.yaml
    """
    global _logging_initialized

    if _logging_initialized:
        return

    level = config.get("level", "INFO").upper()
    log_format = config.get("format", "rich").lower()
    file_config = config.get("file", {})

    # Set root logger level
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level))

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Configure console handler
    if log_format == "rich":
        console_handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            show_time=True,
            show_path=False
        )
        console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
    else:
        # JSON format
        console_handler = logging.StreamHandler(sys.stdout)
        json_formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
        console_handler.setFormatter(json_formatter)

    console_handler.setLevel(getattr(logging, level))
    root_logger.addHandler(console_handler)

    # Configure file handler if enabled
    if file_config.get("enabled", False):
        file_path = Path(file_config.get("path", "yavs.log"))
        max_bytes = file_config.get("max_bytes", 10485760)  # 10MB default
        backup_count = file_config.get("backup_count", 3)

        # Create parent directory if it doesn't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(getattr(logging, level))

        # Use structured format for file logs
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    _logging_initialized = True


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Get a configured logger.

    Args:
        name: Logger name (usually __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR) - only used if logging not initialized

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # If global logging not initialized, use simple Rich handler
    if not _logging_initialized and not logger.handlers:
        logger.setLevel(getattr(logging, level.upper()))

        handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
            show_time=True,
            show_path=False
        )

        formatter = logging.Formatter("%(message)s", datefmt="[%X]")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def set_log_level(level: str):
    """
    Set the global logging level.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    logging.root.setLevel(getattr(logging, level.upper()))
    for handler in logging.root.handlers:
        handler.setLevel(getattr(logging, level.upper()))


class LoggerMixin:
    """Mixin to add logging capabilities to a class."""

    @property
    def logger(self) -> logging.Logger:
        """Get logger for this class."""
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger
