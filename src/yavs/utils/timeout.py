"""Cross-platform timeout handler for scan operations."""

import threading
import signal
import sys
from typing import Optional, Callable


class TimeoutError(Exception):
    """Raised when a timeout occurs."""
    pass


class ScanTimeout:
    """
    Cross-platform timeout handler.

    Uses signal.SIGALRM on Unix/Linux/Mac and threading.Timer on Windows.
    """

    def __init__(self, seconds: Optional[int] = None, error_message: str = "Scan timeout"):
        self.seconds = seconds
        self.error_message = error_message
        self.timer: Optional[threading.Timer] = None
        self.old_handler = None

    def _timeout_handler(self, signum=None, frame=None):
        """Handler called when timeout is reached."""
        raise TimeoutError(self.error_message)

    def __enter__(self):
        """Start the timeout."""
        if self.seconds is None or self.seconds <= 0:
            return self

        # Try signal-based timeout first (Unix/Linux/Mac)
        if hasattr(signal, 'SIGALRM'):
            self.old_handler = signal.signal(signal.SIGALRM, self._timeout_handler)
            signal.alarm(self.seconds)
        else:
            # Fallback to threading.Timer for Windows
            self.timer = threading.Timer(self.seconds, self._timeout_handler)
            self.timer.daemon = True
            self.timer.start()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cancel the timeout."""
        if self.seconds is None or self.seconds <= 0:
            return False

        # Cancel signal-based timeout
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            if self.old_handler is not None:
                signal.signal(signal.SIGALRM, self.old_handler)
        # Cancel timer-based timeout
        elif self.timer:
            self.timer.cancel()

        # Don't suppress exceptions
        return False


def timeout_handler(seconds: Optional[int], error_message: str = "Operation timeout") -> ScanTimeout:
    """
    Create a timeout context manager.

    Args:
        seconds: Timeout in seconds (None or 0 = no timeout)
        error_message: Message for TimeoutError exception

    Returns:
        ScanTimeout context manager

    Example:
        with timeout_handler(300, "Scan timeout after 5 minutes"):
            # Your code here
            scan_all_the_things()
    """
    return ScanTimeout(seconds, error_message)
