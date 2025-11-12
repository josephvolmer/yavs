"""Scanner installation and management utilities."""

import os
import platform
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional, Tuple
import requests

from .logging import get_logger

logger = get_logger(__name__)

# Trivy release information
TRIVY_VERSION = "0.48.0"
TRIVY_GITHUB_RELEASES = "https://github.com/aquasecurity/trivy/releases/download"

# Installation directory
YAVS_BIN_DIR = Path.home() / ".yavs" / "bin"
AUTO_INSTALL_CONSENT_FILE = Path.home() / ".yavs" / ".auto-install-ok"


def get_platform_info() -> Tuple[str, str, str]:
    """
    Get current platform information.

    Returns:
        Tuple of (os_name, arch, file_extension)
    """
    system = platform.system()
    machine = platform.machine().lower()

    # Determine OS
    if system == "Darwin":
        os_name = "macOS"
    elif system == "Linux":
        os_name = "Linux"
    elif system == "Windows":
        os_name = "Windows"
    else:
        raise RuntimeError(f"Unsupported operating system: {system}")

    # Determine architecture
    if machine in ("x86_64", "amd64"):
        arch = "64bit"
    elif machine in ("arm64", "aarch64"):
        arch = "ARM64"
    elif machine in ("i386", "i686"):
        arch = "32bit"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    # Determine file extension
    extension = "zip" if system == "Windows" else "tar.gz"

    return os_name, arch, extension


def get_trivy_download_url() -> Tuple[str, str]:
    """
    Get Trivy download URL for current platform.

    Returns:
        Tuple of (download_url, binary_name)
    """
    os_name, arch, extension = get_platform_info()

    # Construct filename
    # Example: trivy_0.48.0_macOS-ARM64.tar.gz
    filename = f"trivy_{TRIVY_VERSION}_{os_name}-{arch}.{extension}"
    url = f"{TRIVY_GITHUB_RELEASES}/v{TRIVY_VERSION}/{filename}"

    binary_name = "trivy.exe" if os_name == "Windows" else "trivy"

    return url, binary_name


def has_user_consent() -> bool:
    """Check if user has given consent for auto-installation."""
    return AUTO_INSTALL_CONSENT_FILE.exists()


def save_user_consent():
    """Save user consent for auto-installation."""
    AUTO_INSTALL_CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTO_INSTALL_CONSENT_FILE.touch()


def ask_for_consent() -> bool:
    """
    Ask user for consent to auto-download Trivy.

    Returns:
        True if user consents, False otherwise
    """
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print()
    console.print(
        Panel(
            "[bold cyan]Trivy Scanner Not Found[/bold cyan]\n\n"
            "YAVS can automatically download Trivy for you.\n\n"
            f"• Download from: GitHub Releases (aquasecurity/trivy)\n"
            f"• Version: {TRIVY_VERSION}\n"
            f"• Install to: {YAVS_BIN_DIR}\n"
            f"• Size: ~50MB\n\n"
            "[dim]You can also install manually:[/dim]\n"
            "  macOS: brew install trivy\n"
            "  Linux: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
            title="Auto-Install Trivy?",
            border_style="cyan",
        )
    )

    console.print("[bold]Download and install Trivy automatically? [y/n]:[/bold] ", end="")

    try:
        response = input().strip().lower()
        if response in ("y", "yes"):
            save_user_consent()
            return True
        return False
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Installation cancelled.[/yellow]")
        return False


def download_file(url: str, destination: Path, show_progress: bool = True) -> bool:
    """
    Download a file with progress bar.

    Args:
        url: URL to download from
        destination: Path to save file
        show_progress: Whether to show progress bar

    Returns:
        True if successful, False otherwise
    """
    try:
        from rich.progress import (
            Progress,
            DownloadColumn,
            BarColumn,
            TextColumn,
            TimeRemainingColumn,
        )

        logger.info(f"Downloading from {url}")

        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))

        destination.parent.mkdir(parents=True, exist_ok=True)

        if show_progress:
            with Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("Downloading Trivy...", total=total_size)

                with open(destination, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            progress.update(task, advance=len(chunk))
        else:
            with open(destination, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

        logger.info(f"Downloaded to {destination}")
        return True

    except requests.RequestException as e:
        logger.error(f"Download failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during download: {e}")
        return False


def extract_archive(archive_path: Path, extract_to: Path, binary_name: str) -> Optional[Path]:
    """
    Extract Trivy binary from archive.

    Args:
        archive_path: Path to downloaded archive
        extract_to: Directory to extract to
        binary_name: Name of binary to extract

    Returns:
        Path to extracted binary, or None if failed
    """
    try:
        logger.info(f"Extracting {archive_path}")

        extract_to.mkdir(parents=True, exist_ok=True)

        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                # Validate all paths before extraction to prevent path traversal
                for member in zip_ref.namelist():
                    member_path = (extract_to / member).resolve()
                    if not member_path.is_relative_to(extract_to.resolve()):
                        raise ValueError(f"Path traversal attempt detected: {member}")
                zip_ref.extractall(extract_to)
        else:  # .tar.gz
            with tarfile.open(archive_path, "r:gz") as tar_ref:
                # Validate all paths before extraction to prevent path traversal
                for member in tar_ref.getmembers():
                    member_path = (extract_to / member.name).resolve()
                    if not member_path.is_relative_to(extract_to.resolve()):
                        raise ValueError(f"Path traversal attempt detected: {member.name}")
                tar_ref.extractall(extract_to)

        # Find the binary
        binary_path = extract_to / binary_name

        if not binary_path.exists():
            # Try to find it in subdirectories
            for file in extract_to.rglob(binary_name):
                binary_path = file
                break

        if not binary_path.exists():
            logger.error(f"Binary {binary_name} not found in archive")
            return None

        # Make executable (Unix systems)
        if platform.system() != "Windows":
            binary_path.chmod(0o755)

        logger.info(f"Extracted binary to {binary_path}")
        return binary_path

    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        return None


def download_and_install_trivy(force: bool = False) -> Optional[Path]:
    """
    Download and install Trivy binary.

    Args:
        force: Force installation even if already exists

    Returns:
        Path to installed binary, or None if failed
    """
    from rich.console import Console

    console = Console()

    # Check if already installed
    installed_binary = YAVS_BIN_DIR / ("trivy.exe" if platform.system() == "Windows" else "trivy")

    if installed_binary.exists() and not force:
        logger.info(f"Trivy already installed at {installed_binary}")
        return installed_binary

    # Get download URL
    try:
        download_url, binary_name = get_trivy_download_url()
    except RuntimeError as e:
        console.print(f"[red]✗ {str(e)}[/red]")
        return None

    # Download archive
    archive_path = YAVS_BIN_DIR / f"trivy-{TRIVY_VERSION}.tar.gz"

    console.print(f"[cyan]Downloading Trivy {TRIVY_VERSION}...[/cyan]")

    if not download_file(download_url, archive_path):
        console.print("[red]✗ Download failed[/red]")
        return None

    # Extract binary
    console.print("[cyan]Extracting binary...[/cyan]")

    binary_path = extract_archive(archive_path, YAVS_BIN_DIR, binary_name)

    if not binary_path:
        console.print("[red]✗ Extraction failed[/red]")
        return None

    # Clean up archive
    try:
        archive_path.unlink()
    except Exception:
        pass

    console.print(f"[green]✓ Trivy installed to {binary_path}[/green]")

    return binary_path


def find_trivy_binary() -> Optional[str]:
    """
    Find Trivy binary in various locations.

    Returns:
        Path to Trivy binary, or None if not found
    """
    # Check if in PATH
    trivy_in_path = shutil.which("trivy")
    if trivy_in_path:
        logger.debug(f"Found Trivy in PATH: {trivy_in_path}")
        return trivy_in_path

    # Check YAVS-managed installation
    managed_binary = YAVS_BIN_DIR / ("trivy.exe" if platform.system() == "Windows" else "trivy")
    if managed_binary.exists():
        logger.debug(f"Found YAVS-managed Trivy: {managed_binary}")
        return str(managed_binary)

    return None


def ensure_trivy(auto_install: bool = True, ask_consent: bool = True) -> Optional[str]:
    """
    Ensure Trivy is available, install if necessary.

    Args:
        auto_install: Whether to auto-install if not found
        ask_consent: Whether to ask for consent before installing

    Returns:
        Path to Trivy binary, or None if not available
    """
    # Try to find existing binary
    trivy_path = find_trivy_binary()
    if trivy_path:
        return trivy_path

    if not auto_install:
        return None

    # Check/ask for consent
    if ask_consent and not has_user_consent():
        if not ask_for_consent():
            return None

    # Download and install
    binary_path = download_and_install_trivy()

    return str(binary_path) if binary_path else None


def install_via_package_manager() -> bool:
    """
    Attempt to install Trivy via system package manager.

    Returns:
        True if successful, False otherwise
    """
    import subprocess
    from rich.console import Console

    console = Console()
    system = platform.system()

    try:
        if system == "Darwin":
            console.print("[cyan]Installing Trivy via Homebrew...[/cyan]")
            result = subprocess.run(
                ["brew", "install", "trivy"], capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                console.print("[green]✓ Trivy installed via Homebrew[/green]")
                return True
            else:
                console.print(f"[red]✗ Homebrew installation failed: {result.stderr}[/red]")
                return False

        elif system == "Linux":
            # Try apt-get (Debian/Ubuntu)
            console.print("[cyan]Installing Trivy via apt...[/cyan]")

            commands = [
                "sudo apt-get install -y wget apt-transport-https gnupg lsb-release",
                'wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -',
                'echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list',
                "sudo apt-get update",
                "sudo apt-get install -y trivy",
            ]

            for cmd in commands:
                # nosec B602 - shell=True is required for pipe/redirect operations
                # All commands are hardcoded literals with no user input
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)  # noqa: S602
                if result.returncode != 0:
                    console.print(f"[yellow]Command failed: {cmd}[/yellow]")

            # Check if installed
            if shutil.which("trivy"):
                console.print("[green]✓ Trivy installed via apt[/green]")
                return True
            else:
                console.print("[red]✗ apt installation failed[/red]")
                return False

        else:
            console.print(f"[yellow]Package manager installation not supported for {system}[/yellow]")
            return False

    except subprocess.TimeoutExpired:
        console.print("[red]✗ Installation timed out[/red]")
        return False
    except FileNotFoundError:
        console.print("[red]✗ Package manager not found[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Installation error: {e}[/red]")
        return False
