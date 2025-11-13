"""Tests for timeout utilities."""

import pytest
import time
import signal
import threading

from yavs.utils.timeout import (
    ScanTimeout,
    TimeoutError,
    timeout_handler
)


class TestScanTimeout:
    """Test ScanTimeout class."""

    def test_no_timeout_none(self):
        """Test that None timeout doesn't raise."""
        with ScanTimeout(seconds=None):
            time.sleep(0.1)
        # Should complete without exception

    def test_no_timeout_zero(self):
        """Test that zero timeout doesn't raise."""
        with ScanTimeout(seconds=0):
            time.sleep(0.1)
        # Should complete without exception

    def test_no_timeout_negative(self):
        """Test that negative timeout doesn't raise."""
        with ScanTimeout(seconds=-1):
            time.sleep(0.1)
        # Should complete without exception

    def test_timeout_triggers(self):
        """Test that timeout raises TimeoutError."""
        with pytest.raises(TimeoutError, match="Test timeout"):
            with ScanTimeout(seconds=1, error_message="Test timeout"):
                time.sleep(2)

    def test_timeout_no_trigger_fast_operation(self):
        """Test that fast operation completes without timeout."""
        with ScanTimeout(seconds=2, error_message="Should not see this"):
            time.sleep(0.1)
        # Should complete successfully

    def test_custom_error_message(self):
        """Test custom error message appears in exception."""
        custom_msg = "Custom scan timeout message"
        with pytest.raises(TimeoutError, match=custom_msg):
            with ScanTimeout(seconds=1, error_message=custom_msg):
                time.sleep(2)

    def test_default_error_message(self):
        """Test default error message."""
        with pytest.raises(TimeoutError, match="Scan timeout"):
            with ScanTimeout(seconds=1):
                time.sleep(2)

    def test_signal_alarm_cleanup(self):
        """Test that signal alarm is cleaned up properly."""
        if not hasattr(signal, 'SIGALRM'):
            pytest.skip("SIGALRM not available on this platform")

        with ScanTimeout(seconds=5):
            pass

        # Alarm should be canceled
        # If we set another alarm, it should work
        def handler(signum, frame):
            pass

        old = signal.signal(signal.SIGALRM, handler)
        signal.alarm(1)
        signal.alarm(0)  # Cancel it immediately
        signal.signal(signal.SIGALRM, old)

    def test_timer_cleanup(self):
        """Test that timer is properly cleaned up."""
        timeout = ScanTimeout(seconds=5)
        with timeout:
            pass

        # Timer should be canceled
        if timeout.timer:
            assert not timeout.timer.is_alive()

    def test_exception_propagation(self):
        """Test that exceptions inside context are propagated."""
        with pytest.raises(ValueError, match="Test exception"):
            with ScanTimeout(seconds=5):
                raise ValueError("Test exception")

    def test_enter_returns_self(self):
        """Test that __enter__ returns self."""
        timeout = ScanTimeout(seconds=5)
        with timeout as t:
            assert t is timeout

    def test_exit_returns_false(self):
        """Test that __exit__ returns False (doesn't suppress exceptions)."""
        timeout = ScanTimeout(seconds=5)
        result = timeout.__exit__(None, None, None)
        assert result is False


class TestTimeoutHandler:
    """Test timeout_handler function."""

    def test_creates_scan_timeout(self):
        """Test that timeout_handler creates ScanTimeout."""
        handler = timeout_handler(seconds=10)
        assert isinstance(handler, ScanTimeout)
        assert handler.seconds == 10

    def test_custom_error_message(self):
        """Test custom error message."""
        handler = timeout_handler(seconds=10, error_message="Custom message")
        assert handler.error_message == "Custom message"

    def test_default_error_message(self):
        """Test default error message."""
        handler = timeout_handler(seconds=10)
        assert handler.error_message == "Operation timeout"

    def test_none_timeout(self):
        """Test None timeout."""
        handler = timeout_handler(seconds=None)
        assert handler.seconds is None

    def test_usage_as_context_manager(self):
        """Test usage as context manager."""
        with timeout_handler(seconds=2) as handler:
            assert isinstance(handler, ScanTimeout)
            time.sleep(0.1)

    def test_timeout_triggers_with_handler(self):
        """Test timeout triggers with handler."""
        with pytest.raises(TimeoutError):
            with timeout_handler(seconds=1, error_message="Handler timeout"):
                time.sleep(2)


class TestTimeoutError:
    """Test TimeoutError exception."""

    def test_is_exception(self):
        """Test that TimeoutError is an Exception."""
        assert issubclass(TimeoutError, Exception)

    def test_can_be_raised(self):
        """Test that TimeoutError can be raised."""
        with pytest.raises(TimeoutError):
            raise TimeoutError("Test")

    def test_message_is_preserved(self):
        """Test that error message is preserved."""
        msg = "Custom timeout message"
        with pytest.raises(TimeoutError, match=msg):
            raise TimeoutError(msg)


class TestCrossplatformBehavior:
    """Test cross-platform timeout behavior."""

    def test_uses_signal_on_unix(self):
        """Test that Unix systems use signal.SIGALRM."""
        if not hasattr(signal, 'SIGALRM'):
            pytest.skip("Not a Unix system")

        timeout = ScanTimeout(seconds=10)
        with timeout:
            # On Unix, should use signal.alarm
            assert timeout.timer is None

    def test_uses_timer_on_windows(self):
        """Test behavior when SIGALRM not available."""
        # This test is harder to simulate without mocking
        # Just verify the Timer path exists
        if hasattr(signal, 'SIGALRM'):
            pytest.skip("Not a Windows system")

        timeout = ScanTimeout(seconds=1)
        with timeout:
            assert timeout.timer is not None
            assert isinstance(timeout.timer, threading.Timer)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
