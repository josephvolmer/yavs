"""Path manipulation utilities for consistent file handling."""

from pathlib import Path
from typing import Union


def normalize_path(path: Union[str, Path]) -> Path:
    """
    Normalize a file path to an absolute Path object.

    Args:
        path: Path string or Path object

    Returns:
        Absolute Path object
    """
    p = Path(path)
    return p.resolve()


def make_relative(path: Union[str, Path], base: Union[str, Path] = None) -> str:
    """
    Convert an absolute path to a relative path.

    Args:
        path: Path to convert
        base: Base directory (defaults to current working directory)

    Returns:
        Relative path string suitable for SARIF output
    """
    path_obj = Path(path)
    base_obj = Path(base) if base else Path.cwd()

    try:
        # Make both paths absolute for comparison
        abs_path = path_obj.resolve()
        abs_base = base_obj.resolve()

        # Calculate relative path
        relative = abs_path.relative_to(abs_base)

        # Convert to forward slashes for SARIF compliance
        return str(relative).replace("\\", "/")
    except ValueError:
        # If path is not relative to base, return the absolute path
        # but still use forward slashes
        return str(path_obj).replace("\\", "/")


def is_file_in_directory(file_path: Union[str, Path], directory: Union[str, Path]) -> bool:
    """
    Check if a file is within a directory tree.

    Args:
        file_path: File path to check
        directory: Directory to check against

    Returns:
        True if file is within directory, False otherwise
    """
    try:
        file_abs = Path(file_path).resolve()
        dir_abs = Path(directory).resolve()
        file_abs.relative_to(dir_abs)
        return True
    except ValueError:
        return False


def ensure_directory(path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path

    Returns:
        Absolute Path object
    """
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj.resolve()
