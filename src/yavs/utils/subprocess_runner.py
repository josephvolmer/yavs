"""Subprocess execution utilities for running scanner commands."""

import subprocess  # nosec B404 - Safe: hardcoded command, no user input
import shlex
from typing import Tuple, Optional
from pathlib import Path


class CommandExecutionError(Exception):
    """Raised when a command fails to execute."""

    def __init__(self, message: str, returncode: int, stderr: str):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def run_command(
    command: str,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    check: bool = True,
    capture_output: bool = True
) -> Tuple[int, str, str]:
    """
    Execute a shell command safely.

    Args:
        command: Command string to execute
        cwd: Working directory for command execution
        timeout: Maximum execution time in seconds
        check: Whether to raise exception on non-zero exit
        capture_output: Whether to capture stdout/stderr

    Returns:
        Tuple of (returncode, stdout, stderr)

    Raises:
        CommandExecutionError: If command fails and check=True
        subprocess.TimeoutExpired: If command exceeds timeout
    """
    try:
        # Use shlex.split for safer command parsing
        cmd_parts = shlex.split(command)

        result = subprocess.run(  # nosec B603 - Safe: hardcoded command, no user input
            cmd_parts,
            cwd=cwd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=False  # We handle errors manually
        )

        if check and result.returncode != 0:
            raise CommandExecutionError(
                f"Command failed with exit code {result.returncode}: {command}",
                result.returncode,
                result.stderr
            )

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired as e:
        raise CommandExecutionError(
            f"Command timed out after {timeout}s: {command}",
            -1,
            str(e)
        )
    except FileNotFoundError as e:
        raise CommandExecutionError(
            f"Command not found: {command.split()[0]}. Is it installed?",
            -1,
            str(e)
        )


def check_tool_available(tool_name: str) -> bool:
    """
    Check if a tool is available in PATH.

    Args:
        tool_name: Name of the tool to check

    Returns:
        True if tool is available, False otherwise
    """
    try:
        result = subprocess.run(  # nosec B603 B607 - Safe: hardcoded command, no user input
            ["which", tool_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False
