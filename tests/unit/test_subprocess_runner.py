"""Tests for subprocess runner utilities."""

import pytest
from pathlib import Path
import tempfile

from yavs.utils.subprocess_runner import (
    run_command,
    check_tool_available,
    CommandExecutionError
)


class TestRunCommand:
    """Test run_command function."""

    def test_successful_command(self):
        """Test successful command execution."""
        returncode, stdout, stderr = run_command("echo 'hello'", check=True)
        assert returncode == 0
        assert "hello" in stdout
        assert stderr == ""

    def test_command_with_output(self):
        """Test command produces expected output."""
        returncode, stdout, stderr = run_command("python -c \"print('test')\"")
        assert returncode == 0
        assert "test" in stdout

    def test_command_failure_with_check(self):
        """Test command failure raises exception when check=True."""
        with pytest.raises(CommandExecutionError) as exc_info:
            run_command("python -c \"import sys; sys.exit(1)\"", check=True)

        assert exc_info.value.returncode == 1
        assert "exit code 1" in str(exc_info.value).lower()

    def test_command_failure_without_check(self):
        """Test command failure doesn't raise when check=False."""
        returncode, stdout, stderr = run_command("python -c \"import sys; sys.exit(42)\"", check=False)
        assert returncode == 42
        # Should not raise exception

    def test_command_with_cwd(self, tmp_path):
        """Test command execution with custom working directory."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        returncode, stdout, stderr = run_command("ls test.txt", cwd=tmp_path, check=True)
        assert returncode == 0
        assert "test.txt" in stdout

    def test_command_timeout(self):
        """Test command timeout."""
        with pytest.raises(CommandExecutionError, match="timed out"):
            run_command("sleep 10", timeout=1, check=True)

    def test_command_not_found(self):
        """Test command not found error."""
        with pytest.raises(CommandExecutionError, match="not found"):
            run_command("nonexistent-command-12345", check=True)

    def test_complex_command_with_args(self):
        """Test complex command with arguments."""
        returncode, stdout, stderr = run_command("python -c \"import sys; print(sys.version_info[0])\"")
        assert returncode == 0
        assert stdout.strip() in ["3", "2"]  # Python 2 or 3

    def test_command_with_pipes(self):
        """Test command with shell features (uses shlex.split)."""
        # Note: shlex.split doesn't support pipes, so this tests the limitation
        returncode, stdout, stderr = run_command("echo test", check=True)
        assert "test" in stdout

    def test_capture_output_true(self):
        """Test capture_output=True captures stdout/stderr."""
        returncode, stdout, stderr = run_command("echo output", capture_output=True)
        assert "output" in stdout

    def test_returncode_is_integer(self):
        """Test returncode is an integer."""
        returncode, stdout, stderr = run_command("echo test")
        assert isinstance(returncode, int)

    def test_stdout_is_string(self):
        """Test stdout is a string."""
        returncode, stdout, stderr = run_command("echo test")
        assert isinstance(stdout, str)

    def test_stderr_is_string(self):
        """Test stderr is a string."""
        returncode, stdout, stderr = run_command("echo test")
        assert isinstance(stderr, str)

    def test_error_has_returncode(self):
        """Test CommandExecutionError has returncode attribute."""
        with pytest.raises(CommandExecutionError) as exc_info:
            run_command("python -c \"import sys; sys.exit(5)\"", check=True)
        assert exc_info.value.returncode == 5

    def test_error_has_stderr(self):
        """Test CommandExecutionError has stderr attribute."""
        with pytest.raises(CommandExecutionError) as exc_info:
            run_command("python -c \"import sys; sys.stderr.write('error'); sys.exit(1)\"", check=True)
        assert hasattr(exc_info.value, 'stderr')
        assert "error" in exc_info.value.stderr


class TestCheckToolAvailable:
    """Test check_tool_available function."""

    def test_python_is_available(self):
        """Test that python is available."""
        assert check_tool_available("python") or check_tool_available("python3")

    def test_nonexistent_tool(self):
        """Test nonexistent tool returns False."""
        result = check_tool_available("nonexistent-tool-xyz-12345")
        assert result is False

    def test_returns_boolean(self):
        """Test returns boolean."""
        result = check_tool_available("python")
        assert isinstance(result, bool)

    def test_common_tools(self):
        """Test detection of common tools."""
        # At least one of these should be available on most systems
        tools = ["ls", "echo", "cat", "pwd", "python", "python3", "sh"]
        results = [check_tool_available(tool) for tool in tools]
        assert any(results), "At least one common tool should be available"

    def test_handles_exception_gracefully(self):
        """Test that exceptions are handled gracefully."""
        # Even with unusual input, should not raise
        result = check_tool_available("")
        assert isinstance(result, bool)

    def test_git_available_in_repo(self):
        """Test git is available (since we're in a git repo)."""
        # This should pass on most dev systems
        result = check_tool_available("git")
        # Don't assert True because CI might not have git
        assert isinstance(result, bool)


class TestCommandExecutionError:
    """Test CommandExecutionError exception."""

    def test_is_exception(self):
        """Test that CommandExecutionError is an Exception."""
        assert issubclass(CommandExecutionError, Exception)

    def test_has_returncode_attribute(self):
        """Test exception has returncode attribute."""
        error = CommandExecutionError("test", 1, "stderr")
        assert error.returncode == 1

    def test_has_stderr_attribute(self):
        """Test exception has stderr attribute."""
        error = CommandExecutionError("test", 1, "stderr output")
        assert error.stderr == "stderr output"

    def test_message_is_preserved(self):
        """Test exception message is preserved."""
        msg = "Custom error message"
        error = CommandExecutionError(msg, 1, "")
        assert str(error) == msg

    def test_can_be_raised(self):
        """Test exception can be raised and caught."""
        with pytest.raises(CommandExecutionError) as exc_info:
            raise CommandExecutionError("test error", 42, "stderr")
        assert exc_info.value.returncode == 42
        assert exc_info.value.stderr == "stderr"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_command(self):
        """Test empty command."""
        with pytest.raises(Exception):  # Could be CommandExecutionError or IndexError
            run_command("", check=True)

    def test_command_with_special_characters(self):
        """Test command with special characters."""
        returncode, stdout, stderr = run_command("echo 'test & special'")
        assert returncode == 0

    def test_very_short_timeout(self):
        """Test very short timeout."""
        with pytest.raises(CommandExecutionError, match="timed out"):
            run_command("sleep 1", timeout=0.1)

    def test_command_with_quotes(self):
        """Test command with quotes."""
        returncode, stdout, stderr = run_command("echo \"hello world\"")
        assert returncode == 0
        assert "hello world" in stdout

    def test_multiline_output(self):
        """Test command with multiline output."""
        returncode, stdout, stderr = run_command("python -c \"print('line1'); print('line2')\"")
        assert returncode == 0
        assert "line1" in stdout
        assert "line2" in stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
