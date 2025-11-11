"""Pre-flight checks for YAVS scan operations."""

import os
import shutil
from typing import Dict, List, Tuple, Optional
from rich.console import Console
from rich.panel import Panel

console = Console()


def check_scanner_availability(
    sbom: bool = False,
    sast: bool = False,
    compliance: bool = False,
    config: Optional[Dict] = None
) -> Tuple[bool, List[str]]:
    """
    Check if required scanners are available.

    Args:
        sbom: Whether SBOM scanning is requested
        sast: Whether SAST scanning is requested
        compliance: Whether compliance scanning is requested
        config: Configuration dict to check enabled status

    Returns:
        Tuple of (all_available: bool, missing_tools: List[str])
    """
    missing_tools = []
    config = config or {}
    scanner_config = config.get("scanners", {})

    # Check Trivy (required for SBOM)
    if sbom:
        if not scanner_config.get("trivy", {}).get("enabled", True):
            pass  # Disabled in config, skip check
        elif not shutil.which("trivy"):
            # Also check YAVS-installed location
            from .scanner_installer import find_trivy_binary
            if not find_trivy_binary():
                missing_tools.append("trivy")

    # Check SAST scanners
    if sast:
        # Semgrep
        if scanner_config.get("semgrep", {}).get("enabled", True):
            if not shutil.which("semgrep"):
                missing_tools.append("semgrep")

        # Bandit
        if scanner_config.get("bandit", {}).get("enabled", True):
            if not shutil.which("bandit"):
                missing_tools.append("bandit")

        # BinSkim (optional)
        # Note: We don't fail if BinSkim is missing, it's optional

    # Check Checkov (required for compliance)
    if compliance:
        if scanner_config.get("checkov", {}).get("enabled", True):
            if not shutil.which("checkov"):
                missing_tools.append("checkov")

    return (len(missing_tools) == 0, missing_tools)


def check_ai_configuration(
    ai_enabled: bool,
    config: Dict
) -> Tuple[bool, Optional[str]]:
    """
    Check if AI features are properly configured with API keys.

    Args:
        ai_enabled: Whether AI features are enabled
        config: Configuration dict

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str])
    """
    if not ai_enabled:
        return (True, None)  # AI disabled, no checks needed

    ai_config = config.get("ai", {})

    # Check if AI features are enabled in config
    if not ai_config.get("enabled", True):
        return (True, None)  # AI disabled in config

    # Get provider from config
    provider = ai_config.get("provider")
    if provider:
        provider = provider.lower()
    else:
        provider = ""

    # Auto-detect if not specified
    if not provider:
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")

        if anthropic_key:
            provider = "anthropic"
        elif openai_key:
            provider = "openai"
        else:
            return (False, "No AI provider API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")

    # Check provider-specific API keys
    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return (False, "Anthropic provider selected but ANTHROPIC_API_KEY environment variable is not set.")
    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return (False, "OpenAI provider selected but OPENAI_API_KEY environment variable is not set.")
    else:
        return (False, f"Unknown AI provider '{provider}'. Must be 'anthropic' or 'openai'.")

    return (True, None)


def run_preflight_checks(
    sbom: bool = False,
    sast: bool = False,
    compliance: bool = False,
    ai_enabled: bool = True,
    config: Optional[Dict] = None
) -> bool:
    """
    Run all pre-flight checks before starting scan.

    Args:
        sbom: Whether SBOM scanning is requested
        sast: Whether SAST scanning is requested
        compliance: Whether compliance scanning is requested
        ai_enabled: Whether AI features are enabled
        config: Configuration dict

    Returns:
        bool: True if all checks pass, raises Exit if any fail
    """
    config = config or {}
    errors = []

    # Check scanner availability
    scanners_ok, missing_tools = check_scanner_availability(sbom, sast, compliance, config)

    if not scanners_ok:
        error_msg = "\n".join([
            "[bold red]✗ Missing required scanner tools:[/bold red]",
            ""
        ])

        for tool in missing_tools:
            if tool == "trivy":
                error_msg += f"  • [red]{tool}[/red] - Run 'yavs tools install' to install automatically\n"
                error_msg += f"    Or install manually: brew install trivy\n"
            elif tool == "semgrep":
                error_msg += f"  • [red]{tool}[/red] - Included with YAVS: pip install yavs\n"
                error_msg += f"    Or install manually: pip install semgrep\n"
            elif tool == "bandit":
                error_msg += f"  • [red]{tool}[/red] - Included with YAVS: pip install yavs\n"
                error_msg += f"    Or install manually: pip install bandit\n"
            elif tool == "checkov":
                error_msg += f"  • [red]{tool}[/red] - Included with YAVS: pip install yavs\n"
                error_msg += f"    Or install manually: pip install checkov\n"
            else:
                error_msg += f"  • [red]{tool}[/red]\n"

        error_msg += "\n[yellow]Run 'yavs tools install' to install missing dependencies automatically.[/yellow]"
        errors.append(error_msg)

    # Check AI configuration
    ai_ok, ai_error = check_ai_configuration(ai_enabled, config)

    if not ai_ok:
        error_msg = "\n".join([
            f"[bold red]✗ AI Configuration Error:[/bold red]",
            f"  {ai_error}",
            "",
            "[yellow]Fix options:[/yellow]",
            "  • Set environment variable: export ANTHROPIC_API_KEY='your-key'",
            "  • Or use OpenAI: export OPENAI_API_KEY='your-key'",
            "  • Or disable AI features: yavs scan --no-ai",
        ])
        errors.append(error_msg)

    # Display all errors and exit if any found
    if errors:
        console.print()
        console.print(Panel(
            "\n\n".join(errors),
            title="[bold red]Pre-Flight Check Failed[/bold red]",
            border_style="red",
            expand=False
        ))
        console.print()

        import typer
        raise typer.Exit(1)

    return True
