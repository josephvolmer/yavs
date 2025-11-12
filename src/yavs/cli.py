"""YAVS CLI - Main command-line interface."""

import os
import sys
import re
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import yaml

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.align import Align
from rich.text import Text

from . import __version__
from .scanners import TrivyScanner, SemgrepScanner, CheckovScanner, BanditScanner, BinSkimScanner
from .scanners.base import BaseScanner
from .scanners.sbom import SBOMGenerator
from .reporting import Aggregator, SARIFConverter
from .reporting.structured_output import StructuredOutputFormatter
from .ai import Summarizer, Fixer, TriageEngine
from .utils.logging import get_logger, console, configure_logging
from .utils.schema_validator import validate_sarif
from .utils.metadata import extract_project_metadata

# Create Typer app
app = typer.Typer(
    name="yavs",
    help="YAVS - Yet Another Vulnerability Scanner\n\nAI-enhanced security scanning with SARIF output.",
    add_completion=False,
    no_args_is_help=True
)

logger = get_logger(__name__)


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """
    Main callback that runs before any command.
    Shows banner when help is displayed or no command is given.
    """
    # Show banner if no command is given or if help is being displayed
    if ctx.invoked_subcommand is None:
        print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")
        # Typer will automatically show help after this


def print_banner(subtitle: Optional[str] = None):
    """
    Print the YAVS ASCII art banner.

    Args:
        subtitle: Optional subtitle to display below the banner
    """
    # Create ASCII art lines
    lines = [
        "██╗   ██╗ █████╗ ██╗   ██╗███████╗",
        "╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝",
        " ╚████╔╝ ███████║██║   ██║███████╗",
        "  ╚██╔╝  ██╔══██║╚██╗ ██╔╝╚════██║",
        "   ██║   ██║  ██║ ╚████╔╝ ███████║",
        "   ╚═╝   ╚═╝  ╚═╝  ╚═══╝  ╚══════╝"
    ]

    # Build banner with proper centering
    banner_parts = []
    for line in lines:
        text = Text(line, style="bold cyan")
        banner_parts.append(Align.center(text))

    # Add subtitle if provided
    if subtitle:
        banner_parts.append(Text(""))  # Empty line
        subtitle_text = Text(subtitle, style="bold white")
        banner_parts.append(Align.center(subtitle_text))

    # Create a group of centered elements
    from rich.console import Group
    banner_group = Group(*banner_parts)

    console.print(Panel(banner_group, border_style="bold cyan", padding=(1, 2)))


def filter_findings_by_ignore_patterns(
    findings: List[Dict[str, Any]],
    ignore_patterns: List[str]
) -> List[Dict[str, Any]]:
    """
    Filter findings by removing those matching ignore patterns.

    Args:
        findings: List of finding dictionaries
        ignore_patterns: List of regex patterns to match against file paths

    Returns:
        Filtered list of findings
    """
    if not ignore_patterns:
        return findings

    # Compile regex patterns
    compiled_patterns = []
    for pattern in ignore_patterns:
        try:
            compiled_patterns.append(re.compile(pattern))
        except re.error as e:
            logger.warning(f"Invalid ignore pattern '{pattern}': {e}")

    if not compiled_patterns:
        return findings

    filtered_findings = []
    ignored_count = 0

    for finding in findings:
        file_path = finding.get("file", "")

        # Check if file path matches any ignore pattern
        should_ignore = False
        for pattern in compiled_patterns:
            if pattern.search(file_path):
                should_ignore = True
                ignored_count += 1
                break

        if not should_ignore:
            filtered_findings.append(finding)

    if ignored_count > 0:
        logger.debug(f"Filtered out {ignored_count} findings matching ignore patterns")

    return filtered_findings


def get_mode_config(config: dict, mode: str, scanner: str = None) -> dict:
    """
    Get mode-specific configuration.

    Args:
        config: Full YAVS configuration
        mode: Mode name (sbom, sast, compliance, all)
        scanner: Optional scanner name to get scanner-specific mode config

    Returns:
        Mode configuration dict, or empty dict if not configured
    """
    modes = config.get("modes", {})
    mode_config = modes.get(mode, {})

    if scanner:
        return mode_config.get(scanner, {})
    return mode_config


def should_run_scanner_in_mode(config: dict, mode: str, scanner_name: str) -> bool:
    """
    Check if a scanner should run in the given mode.

    Args:
        config: Full YAVS configuration
        mode: Mode name (sbom, sast, compliance, all)
        scanner_name: Scanner name (trivy, semgrep, bandit, checkov)

    Returns:
        True if scanner should run in this mode
    """
    # Check if scanner is globally enabled
    if not config["scanners"].get(scanner_name, {}).get("enabled", False):
        return False

    # Get mode-specific scanner list
    mode_config = get_mode_config(config, mode)
    scanner_list = mode_config.get("scanners")

    # If no mode config, fall back to hardcoded defaults
    if scanner_list is None:
        # Hardcoded defaults (backward compatibility)
        if mode == "sbom":
            return scanner_name == "trivy"
        elif mode == "sast":
            return scanner_name in ["semgrep", "bandit"]
        elif mode == "compliance":
            return scanner_name in ["checkov", "trivy"]
        elif mode == "all":
            # In all mode, check if inherit is true or scanner list is defined
            if mode_config.get("inherit", True):
                # Run all enabled scanners
                return True
            else:
                # Use explicit scanner list if defined
                return scanner_name in mode_config.get("scanners", [])

    return scanner_name in scanner_list


def get_trivy_security_checks(config: dict, sbom: bool, sast: bool, compliance: bool) -> list:
    """
    Determine Trivy security checks based on mode configuration.

    Args:
        config: Full YAVS configuration
        sbom: SBOM mode enabled
        sast: SAST mode enabled
        compliance: Compliance mode enabled

    Returns:
        List of security check strings
    """
    trivy_checks = []

    # Determine active mode(s)
    if sbom:
        mode_config = get_mode_config(config, "sbom", "trivy")
        checks = mode_config.get("security_checks")
        if checks:
            trivy_checks.extend(checks)
        else:
            # Fallback to defaults
            trivy_checks.extend(["vuln", "secret", "license"])

    if compliance:
        mode_config = get_mode_config(config, "compliance", "trivy")
        checks = mode_config.get("security_checks")
        if checks:
            trivy_checks.extend(checks)
        else:
            # Fallback to defaults
            trivy_checks.append("config")

    # Remove duplicates while preserving order
    trivy_checks = list(dict.fromkeys(trivy_checks))

    return trivy_checks


def load_config(config_path: Optional[Path] = None) -> dict:
    """Load configuration from YAML file."""
    if config_path is None:
        # Try to find config.yaml in current directory or package directory
        config_path = Path("config.yaml")
        if not config_path.exists():
            # Use default config from package
            package_dir = Path(__file__).parent.parent.parent
            config_path = package_dir / "config.yaml"

    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        # Return default config
        return {
            "scan": {
                "directories": ["."],
                "ignore_paths": [
                    "node_modules/", "vendor/", "\\.venv/", "venv/",
                    "__pycache__/", "\\.git/", "dist/", "build/", "target/",
                    "\\.egg-info/", ".*\\.min\\.js$", ".*\\.min\\.css$"
                ]
            },
            "metadata": {
                "project": None,
                "branch": None,
                "commit_hash": None
            },
            "scanners": {
                "trivy": {"enabled": True, "timeout": 300, "flags": ""},
                "semgrep": {"enabled": True, "timeout": 300, "flags": ""},
                "bandit": {"enabled": True, "timeout": 300, "flags": ""},
                "binskim": {"enabled": True, "timeout": 300, "flags": ""},
                "checkov": {"enabled": True, "timeout": 300, "flags": ""}
            },
            "modes": {
                "sbom": {
                    "scanners": ["trivy"],
                    "trivy": {
                        "security_checks": ["vuln", "secret", "license"]
                    }
                },
                "sast": {
                    "scanners": ["semgrep", "bandit"]
                },
                "compliance": {
                    "scanners": ["checkov", "trivy"],
                    "trivy": {
                        "security_checks": ["config"]
                    }
                },
                "all": {
                    "inherit": True
                }
            },
            "output": {
                "directory": ".",
                "json": "yavs-results.json",
                "sarif": "yavs-results.sarif"
            },
            "ai": {
                "enabled": True,
                "provider": None,
                "model": None,
                "max_tokens": 4096,
                "temperature": 0.0,
                "features": {
                    "fix_suggestions": True,
                    "summarize": True,
                    "triage": True
                }
            },
            "severity_mapping": {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "error": "HIGH",
                "warning": "MEDIUM",
                "note": "LOW",
                "none": "INFO",
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "INFO": "INFO",
                "UNKNOWN": "LOW"
            },
            "logging": {
                "level": "INFO",
                "format": "rich",
                "file": {
                    "enabled": False,
                    "path": "yavs.log",
                    "max_bytes": 10485760,
                    "backup_count": 3
                }
            }
        }


@app.command()
def scan(
    targets: Optional[List[Path]] = typer.Argument(
        None,
        help="Directory/directories to scan (default: from config or current directory)",
        exists=True,
        file_okay=False,
        dir_okay=True
    ),
    sast: bool = typer.Option(False, "--sast", help="Run SAST scanner (Semgrep)"),
    sbom: bool = typer.Option(False, "--sbom", help="Scan dependencies + generate SBOM (Trivy)"),
    compliance: bool = typer.Option(False, "--compliance", help="Run IaC compliance scanner (Checkov)"),
    all_scanners: bool = typer.Option(False, "--all", help="Run all scanners (SBOM + SAST + Compliance)"),
    images: Optional[List[str]] = typer.Option(None, "--images", help="Docker image(s) to scan (e.g., nginx:latest python:3.11)"),
    images_file: Optional[Path] = typer.Option(None, "--images-file", help="File containing list of images (one per line)"),
    ignore: Optional[List[str]] = typer.Option(None, "--ignore", help="Path patterns to ignore (regex, can be specified multiple times)"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Output directory for results"),
    json_path: Optional[Path] = typer.Option(None, "--json", help="Path to JSON output file"),
    sarif_path: Optional[Path] = typer.Option(None, "--sarif", help="Path to SARIF output file"),
    sbom_path: Optional[Path] = typer.Option(None, "--sbom-output", help="Path to SBOM output file"),
    flat: bool = typer.Option(False, "--flat", help="Use flat array format (default: structured from config)"),
    per_tool_files: bool = typer.Option(False, "--per-tool-files", help="Generate individual output files per tool"),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config file"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI features"),
    validate: bool = typer.Option(True, "--validate/--no-validate", help="Validate SARIF output"),
    project: Optional[str] = typer.Option(None, "--project", help="Project name (default: auto-detect from directory)"),
    branch: Optional[str] = typer.Option(None, "--branch", help="Git branch name (default: auto-detect from git)"),
    commit_hash: Optional[str] = typer.Option(None, "--commit-hash", help="Git commit hash (default: auto-detect from git)"),
    # Production/CI-CD features
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with code 1 if findings at or above this severity (CRITICAL|HIGH|MEDIUM|LOW|NONE)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Only report findings of these severities (comma-separated: CRITICAL,HIGH,MEDIUM,LOW,INFO)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output (only summary and errors)"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Overall scan timeout in seconds"),
    continue_on_error: bool = typer.Option(False, "--continue-on-error", help="Continue scan even if a scanner fails"),
    # Suppression baseline
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Suppression baseline file (.yavs-baseline.yaml) to filter findings"),
):
    """
    Scan filesystem and/or Docker images for vulnerabilities.

    Scanner flags:
        --sbom         : Scan dependencies + generate SBOM (Trivy)
        --sast         : Run static analysis (Semgrep, Bandit, BinSkim)
        --compliance   : Run IaC compliance checks (Checkov)
        --all          : Run all scanners

    Target options:
        [targets...]   : Directory/directories to scan (default: from config)
        --images       : Docker image(s) to scan
        --images-file  : File with list of images
        --ignore       : Path patterns to ignore (regex)

    Output options:
        --flat            : Use flat format with data array (default: structured from config)
        --per-tool-files  : Generate individual files per tool (trivy.json, semgrep.json, etc.)
        --output-dir      : Output directory for results

    Examples:

        yavs scan --all                                    # Scan with default structured output
        yavs scan /path/to/code --all                      # Scan specific directory
        yavs scan /path/dir1 /path/dir2 --all              # Scan multiple directories
        yavs scan --all --ignore "test/" --ignore ".*_test\\.py$"  # Ignore test files
        yavs scan --images nginx:latest                    # Scan Docker image only
        yavs scan --images nginx:latest python:3.11        # Scan multiple images
        yavs scan --images-file images.txt                 # Scan images from file
        yavs scan --all --images nginx:latest              # Scan directories AND images
        yavs scan /path/to/code --all --images nginx:latest  # Scan specific directory AND image
        yavs scan --all --flat -o ./results                # Use flat format with metadata
        yavs scan --all --per-tool-files -o ./results      # Generate per-tool JSON files
    """
    # Load configuration first
    config = load_config(config_path)

    # Initialize logging from config
    if "logging" in config:
        configure_logging(config["logging"])

    # Set severity mapping for all scanners
    if "severity_mapping" in config:
        BaseScanner.set_severity_mapping(config["severity_mapping"])

    # Determine output format
    # If --flat is specified, use flat format. Otherwise use config default.
    if flat:
        use_structured = False
    else:
        use_structured = config.get("output", {}).get("structured", True)

    # Per-tool files: use flag if specified, otherwise use config default
    if not per_tool_files:
        per_tool_files = config.get("output", {}).get("per_tool_files", False)

    if not quiet:
        print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")

    # Determine which scanners to run
    scanners_to_run = []

    if all_scanners:
        sast = sbom = compliance = True

    if not any([sast, sbom, compliance]):
        console.print("[yellow]No scanners specified. Use --all or specify --sbom, --sast, or --compliance[/yellow]")
        raise typer.Exit(2)  # Exit code 2 for configuration errors

    # Run pre-flight checks - validate tools and configuration BEFORE starting any scans
    from .utils.preflight import run_preflight_checks
    ai_enabled = not no_ai and config.get("ai", {}).get("enabled", True)
    run_preflight_checks(
        sbom=sbom,
        sast=sast,
        compliance=compliance,
        ai_enabled=ai_enabled,
        config=config
    )

    # Determine which directories to scan
    directories_to_scan = []

    if targets:
        # Use CLI arguments (convert to absolute paths)
        directories_to_scan = [Path(t).resolve() for t in targets]
    else:
        # Use config directories
        config_dirs = config.get("scan", {}).get("directories", ["."])
        directories_to_scan = [Path(d).resolve() for d in config_dirs]

    # Combine ignore patterns from config and CLI
    ignore_patterns = config.get("scan", {}).get("ignore_paths", [])
    if ignore:
        # Add CLI ignore patterns
        ignore_patterns = list(ignore_patterns) + list(ignore)

    if ignore_patterns:
        logger.info(f"Using {len(ignore_patterns)} ignore pattern(s)")

    # Initialize aggregator
    aggregator = Aggregator()

    # Display what we're scanning
    if not quiet:
        if len(directories_to_scan) == 1:
            console.print(f"\n[bold]Scanning:[/bold] {directories_to_scan[0]}\n")
        else:
            console.print(f"\n[bold]Scanning {len(directories_to_scan)} directories:[/bold]")
            for dir_path in directories_to_scan:
                console.print(f"  • {dir_path}")
            console.print()

    # Import timeout handler for cross-platform timeout support
    from .utils.timeout import timeout_handler, TimeoutError as ScanTimeoutError

    # Wrap scanning in timeout context (cross-platform)
    try:
        with timeout_handler(timeout, f"Scan timeout after {timeout} seconds" if timeout else ""):
            # Run scanners on each directory
            from contextlib import nullcontext
            scanner_status = console.status("[bold green]Running scanners...") if not quiet else nullcontext()
            with scanner_status as status:
                for target in directories_to_scan:
                    if len(directories_to_scan) > 1:
                        console.print(f"\n[bold cyan]Directory: {target}[/bold cyan]")

                    # Trivy: Run once with all needed security checks
                    # Determine active mode for scanner selection
                    active_mode = "all" if (sbom and sast and compliance) else ("sbom" if sbom else ("compliance" if compliance else "sast"))

                    if (sbom or compliance) and should_run_scanner_in_mode(config, active_mode, "trivy"):
                        # Get Trivy security checks from mode configuration
                        trivy_checks = get_trivy_security_checks(config, sbom, sast, compliance)
                        security_checks = ",".join(trivy_checks)

                        try:
                            if not quiet:
                                status.update(f"[bold green]Running Trivy ({security_checks})...")
                            scanner = TrivyScanner(
                                target,
                                timeout=config["scanners"].get("trivy", {}).get("timeout", 300),
                                extra_flags=config["scanners"].get("trivy", {}).get("flags", ""),
                                security_checks=security_checks,
                                native_config=config["scanners"].get("trivy", {}).get("native_config")
                            )
                            results = scanner.run()

                            # Tag findings with filesystem source
                            for finding in results:
                                finding["source"] = f"filesystem:{target}"
                                finding["source_type"] = "filesystem"

                            # Filter findings based on ignore patterns
                            results = filter_findings_by_ignore_patterns(results, ignore_patterns)

                            # Register scanner and add findings (even if 0 findings)
                            if "vuln" in security_checks or "secret" in security_checks or "license" in security_checks:
                                dep_findings = [f for f in results if f.get("category") == "dependency"]
                                secret_findings = [f for f in results if f.get("category") == "secret"]
                                license_findings = [f for f in results if f.get("category") == "license"]

                                aggregator.register_scanner("Trivy", "dependency", len(dep_findings))
                                if secret_findings:
                                    aggregator.register_scanner("Trivy", "secret", len(secret_findings))
                                if license_findings:
                                    aggregator.register_scanner("Trivy", "license", len(license_findings))

                            if "config" in security_checks:
                                config_findings = [f for f in results if f.get("category") == "config"]
                                aggregator.register_scanner("Trivy", "config", len(config_findings))

                            aggregator.add_findings(results)

                            # Count findings by category for display
                            dep_count = sum(1 for f in results if f.get("category") == "dependency")
                            secret_count = sum(1 for f in results if f.get("category") == "secret")
                            license_count = sum(1 for f in results if f.get("category") == "license")
                            config_count = sum(1 for f in results if f.get("category") == "config")

                            # Display counts
                            if not quiet:
                                if dep_count or secret_count or license_count:
                                    console.print(f"✓ Trivy: {dep_count} vuln, {secret_count} secret, {license_count} license")
                                if config_count:
                                    console.print(f"✓ Trivy (Config): {config_count} finding(s)")
                        except Exception as e:
                            # Register as failed
                            aggregator.register_scanner("Trivy", "dependency", 0, status="failed", error=str(e))
                            console.print(f"[red]✗ Trivy failed: {str(e)}[/red]")
                            if not continue_on_error:
                                console.print("[red]Scan failed. Use --continue-on-error to continue despite scanner failures.[/red]")
                                raise typer.Exit(2)

                    # Semgrep (SAST)
                    if sast and should_run_scanner_in_mode(config, active_mode, "semgrep"):
                        try:
                            if not quiet:
                                status.update("[bold green]Running Semgrep (SAST)...")
                            scanner = SemgrepScanner(
                                target,
                                timeout=config["scanners"].get("semgrep", {}).get("timeout", 300),
                                extra_flags=config["scanners"].get("semgrep", {}).get("flags", ""),
                                native_config=config["scanners"].get("semgrep", {}).get("native_config")
                            )
                            results = scanner.run()

                            # Tag findings with filesystem source
                            for finding in results:
                                finding["source"] = f"filesystem:{target}"
                                finding["source_type"] = "filesystem"

                            # Filter findings based on ignore patterns
                            results = filter_findings_by_ignore_patterns(results, ignore_patterns)

                            # Register scanner (even if 0 findings)
                            aggregator.register_scanner("Semgrep", "sast", len(results))
                            aggregator.add_findings(results)
                            if not quiet:
                                console.print(f"✓ Semgrep: {len(results)} finding(s)")
                        except Exception as e:
                            # Register as failed
                            aggregator.register_scanner("Semgrep", "sast", 0, status="failed", error=str(e))
                            console.print(f"[red]✗ Semgrep failed: {str(e)}[/red]")
                            if not continue_on_error:
                                console.print("[red]Scan failed. Use --continue-on-error to continue despite scanner failures.[/red]")
                                raise typer.Exit(2)

                    # Bandit (Python SAST)
                    if sast and should_run_scanner_in_mode(config, active_mode, "bandit"):
                        try:
                            if not quiet:
                                status.update("[bold green]Running Bandit (Python SAST)...")
                            scanner = BanditScanner(
                                target,
                                timeout=config["scanners"].get("bandit", {}).get("timeout", 300),
                                extra_flags=config["scanners"].get("bandit", {}).get("flags", ""),
                                native_config=config["scanners"].get("bandit", {}).get("native_config")
                            )
                            results = scanner.run()

                            # Tag findings with filesystem source
                            for finding in results:
                                finding["source"] = f"filesystem:{target}"
                                finding["source_type"] = "filesystem"

                            # Filter findings based on ignore patterns
                            results = filter_findings_by_ignore_patterns(results, ignore_patterns)

                            # Register scanner (even if 0 findings)
                            aggregator.register_scanner("Bandit", "sast", len(results))
                            aggregator.add_findings(results)
                            if not quiet:
                                console.print(f"✓ Bandit: {len(results)} finding(s)")
                        except Exception as e:
                            # Register as failed
                            aggregator.register_scanner("Bandit", "sast", 0, status="failed", error=str(e))
                            console.print(f"[red]✗ Bandit failed: {str(e)}[/red]")
                            if not continue_on_error:
                                console.print("[red]Scan failed. Use --continue-on-error to continue despite scanner failures.[/red]")
                                raise typer.Exit(2)

                    # BinSkim (Binary Analysis)
                    if sast and should_run_scanner_in_mode(config, active_mode, "binskim"):
                        try:
                            if not quiet:
                                status.update("[bold green]Running BinSkim (Binary Analysis)...")
                            scanner = BinSkimScanner(
                                target,
                                timeout=config["scanners"].get("binskim", {}).get("timeout", 300),
                                extra_flags=config["scanners"].get("binskim", {}).get("flags", ""),
                                native_config=config["scanners"].get("binskim", {}).get("native_config")
                            )
                            results = scanner.run()

                            # Tag findings with filesystem source
                            for finding in results:
                                finding["source"] = f"filesystem:{target}"
                                finding["source_type"] = "filesystem"

                            # Filter findings based on ignore patterns
                            results = filter_findings_by_ignore_patterns(results, ignore_patterns)

                            # Register scanner (even if 0 findings)
                            aggregator.register_scanner("BinSkim", "sast", len(results))
                            aggregator.add_findings(results)
                            if not quiet:
                                console.print(f"✓ BinSkim: {len(results)} finding(s)")
                        except Exception as e:
                            # Register as failed
                            aggregator.register_scanner("BinSkim", "sast", 0, status="failed", error=str(e))
                            console.print(f"[red]✗ BinSkim failed: {str(e)}[/red]")
                            if not continue_on_error:
                                console.print("[red]Scan failed. Use --continue-on-error to continue despite scanner failures.[/red]")
                                raise typer.Exit(2)

                    # Checkov (IaC Compliance)
                    if compliance and should_run_scanner_in_mode(config, active_mode, "checkov"):
                        try:
                            if not quiet:
                                status.update("[bold green]Running Checkov (IaC Compliance)...")
                            scanner = CheckovScanner(
                                target,
                                timeout=config["scanners"].get("checkov", {}).get("timeout", 300),
                                extra_flags=config["scanners"].get("checkov", {}).get("flags", ""),
                                native_config=config["scanners"].get("checkov", {}).get("native_config")
                            )
                            results = scanner.run()

                            # Tag findings with filesystem source
                            for finding in results:
                                finding["source"] = f"filesystem:{target}"
                                finding["source_type"] = "filesystem"

                            # Filter findings based on ignore patterns
                            results = filter_findings_by_ignore_patterns(results, ignore_patterns)

                            # Register scanner (even if 0 findings)
                            aggregator.register_scanner("Checkov", "compliance", len(results))
                            aggregator.add_findings(results)
                            if not quiet:
                                console.print(f"✓ Checkov: {len(results)} finding(s)")
                        except Exception as e:
                            # Register as failed
                            aggregator.register_scanner("Checkov", "compliance", 0, status="failed", error=str(e))
                            console.print(f"[red]✗ Checkov failed: {str(e)}[/red]")
                            if not continue_on_error:
                                console.print("[red]Scan failed. Use --continue-on-error to continue despite scanner failures.[/red]")
                                raise typer.Exit(2)

        # Docker Image Scanning (if --images or --images-file provided)
        images_to_scan = []

        # Collect images from command line
        if images:
            images_to_scan.extend(images)

        # Collect images from file
        if images_file:
            if not images_file.exists():
                console.print(f"[red]✗ Images file not found: {images_file}[/red]")
            else:
                with open(images_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):  # Skip empty lines and comments
                            images_to_scan.append(line)

        # Scan Docker images
        if images_to_scan and (sbom or compliance):
            if not quiet:
                console.print(f"\n[bold]Scanning {len(images_to_scan)} Docker image(s)[/bold]")

            for image in images_to_scan:
                try:
                    if not quiet:
                        status.update(f"[bold green]Scanning image: {image}...")

                    # Determine which security checks we need (same as filesystem)
                    trivy_checks = []
                    if sbom:
                        trivy_checks.extend(["vuln", "secret", "license"])
                    if compliance:
                        trivy_checks.append("config")
                    trivy_checks = list(dict.fromkeys(trivy_checks))
                    security_checks = ",".join(trivy_checks)

                    # Trivy image scan
                    scanner = TrivyScanner(
                        Path(image),  # Image name as Path
                        timeout=config["scanners"].get("trivy", {}).get("timeout", 300),
                        extra_flags=config["scanners"].get("trivy", {}).get("flags", ""),
                        security_checks=security_checks,
                        scan_type="image"
                    )
                    results = scanner.run()

                    # Tag all findings with image source
                    for finding in results:
                        finding["source"] = f"image:{image}"
                        finding["source_type"] = "image"

                    aggregator.add_findings(results)

                    # Count findings
                    dep_count = sum(1 for f in results if f.get("category") == "dependency")
                    secret_count = sum(1 for f in results if f.get("category") == "secret")
                    license_count = sum(1 for f in results if f.get("category") == "license")
                    config_count = sum(1 for f in results if f.get("category") == "config")

                    if not quiet:
                        console.print(f"✓ {image}: {dep_count} vuln, {secret_count} secret, {license_count} license, {config_count} config")

                except Exception as e:
                    console.print(f"[red]✗ {image} failed: {str(e)}[/red]")

        # Process findings
        aggregator.deduplicate()
        aggregator.sort_by_severity()
        findings = aggregator.get_findings()

        # Apply severity filtering if specified
        if severity:
            allowed_severities = [s.strip().upper() for s in severity.split(',')]
            original_count = len(findings)
            findings = [f for f in findings if f.get('severity', 'UNKNOWN').upper() in allowed_severities]
            filtered_count = original_count - len(findings)
            if filtered_count > 0 and not quiet:
                logger.info(f"Filtered out {filtered_count} findings not matching severity filter: {severity}")
            # Update aggregator with filtered findings for statistics
            aggregator.findings = findings

        # Apply suppression baseline filtering if specified
        if baseline:
            try:
                with open(baseline, 'r') as f:
                    baseline_data = yaml.safe_load(f)
                    suppressions = baseline_data.get('suppressions', [])

                if suppressions:
                    suppressed_ids = {s['id'] for s in suppressions}
                    original_count = len(findings)

                    # Filter findings by suppressed IDs
                    def is_suppressed(finding):
                        finding_id = (finding.get('rule_id') or
                                    finding.get('vulnerability_id') or
                                    finding.get('id') or
                                    finding.get('package', '') + ':' + finding.get('severity', ''))
                        return finding_id in suppressed_ids

                    findings = [f for f in findings if not is_suppressed(f)]
                    filtered_count = original_count - len(findings)

                    if not quiet:
                        console.print(f"\n[bold cyan]Suppression Baseline:[/bold cyan]")
                        console.print(f"  Baseline: {baseline}")
                        console.print(f"  Suppressions: {len(suppressed_ids)}")
                        console.print(f"  Total findings: {original_count}")
                        console.print(f"  After filtering: {len(findings)}")
                        console.print(f"  Suppressed: {filtered_count}")

                    # Update aggregator with filtered findings
                    aggregator.findings = findings
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to load baseline: {str(e)}[/yellow]")
                console.print("[yellow]Continuing with all findings...[/yellow]")

        # Display statistics
        stats = aggregator.get_statistics()
        if not quiet:
            display_statistics(stats)
        else:
            # Quiet mode: only show summary line
            console.print(f"Found {stats['total']} findings ({stats['by_severity'].get('CRITICAL', 0)} CRITICAL, {stats['by_severity'].get('HIGH', 0)} HIGH, {stats['by_severity'].get('MEDIUM', 0)} MEDIUM)")

        # Determine output directory early (needed for SBOM and results)
        out_dir = Path(output_dir or config["output"].get("directory", "."))
        out_dir.mkdir(parents=True, exist_ok=True)

        # AI Enhancement
        ai_features = config["ai"].get("features", {})
        ai_summary_text = None

        if not no_ai and config["ai"]["enabled"] and findings:
            if not quiet:
                console.print("\n[bold cyan]Generating AI insights...[/bold cyan]")

            # Get rate limits for the detected/configured provider
            provider_name = config["ai"].get("provider", "anthropic") or "anthropic"
            rate_limits = config["ai"].get("rate_limits", {}).get(provider_name, {})

            try:
                # Generate fix suggestions for high/critical findings
                if ai_features.get("fix_suggestions", True):
                    fixer = Fixer(
                        provider=config["ai"].get("provider"),
                        model=config["ai"].get("model"),
                        max_tokens=config["ai"].get("max_tokens", 4096),
                        temperature=config["ai"].get("temperature", 0.0),
                        parallel_requests=config["ai"].get("parallel_requests", 5),
                        rate_limit_rpm=rate_limits.get("requests_per_minute", 50),
                        rate_limit_tpm=rate_limits.get("tokens_per_minute", 40000)
                    )
                    max_fixes = config["ai"].get("max_fixes_per_scan", 50)
                    findings = fixer.generate_fixes_batch(findings, limit=max_fixes)
                    if not quiet:
                        console.print("✓ AI fix suggestions generated")

                # Generate executive summary
                if ai_features.get("summarize", True):
                    if not quiet:
                        console.print("\n[bold cyan]Generating executive summary...[/bold cyan]")
                    summarizer = Summarizer(
                        provider=config["ai"].get("provider"),
                        model=config["ai"].get("model"),
                        max_tokens=config["ai"].get("max_tokens", 4096),
                        temperature=config["ai"].get("temperature", 0.0)
                    )
                    ai_summary_text = summarizer.summarize(findings)
                    if not quiet:
                        console.print("✓ Executive summary generated")

            except Exception as e:
                console.print(f"[yellow]⚠ AI feature generation failed: {str(e)}[/yellow]")

        # SBOM Generation
        sbom_info = None
        if sbom:
            if not quiet:
                console.print("\n[bold cyan]Generating SBOM...[/bold cyan]")
            try:
                # Generate SBOM for the first directory (or primary scan target)
                # Note: SBOM represents the first scanned directory's dependencies
                sbom_target = directories_to_scan[0]
                sbom_generator = SBOMGenerator(sbom_target, format="cyclonedx")
                # Respect output directory
                if sbom_path:
                    sbom_output = Path(sbom_path)
                else:
                    sbom_output = out_dir / "sbom.json"
                sbom_info = sbom_generator.generate(sbom_output)
                if not quiet:
                    console.print(f"✓ SBOM: {sbom_output}")
                    if len(directories_to_scan) > 1:
                        console.print(f"  [dim]Note: SBOM generated for {sbom_target}[/dim]")
            except Exception as e:
                console.print(f"[yellow]⚠ SBOM generation failed: {str(e)}[/yellow]")

        # Build output paths
        if json_path:
            json_output = Path(json_path)
        else:
            json_output = out_dir / config["output"]["json"]

        if sarif_path:
            sarif_output = Path(sarif_path)
        else:
            sarif_output = out_dir / config["output"]["sarif"]

        if not quiet:
            console.print(f"\n[bold]Writing outputs...[/bold]")

        # Choose output format
        if use_structured:
            # Structured output format
            # Use first directory for metadata extraction
            # Precedence: CLI args > config > auto-detect
            config_metadata = config.get("metadata", {})
            metadata = extract_project_metadata(
                directories_to_scan[0],
                project_name=project or config_metadata.get("project"),
                branch=branch or config_metadata.get("branch"),
                commit_hash=commit_hash or config_metadata.get("commit_hash")
            )
            formatter = StructuredOutputFormatter()
            executed_scanners = aggregator.get_executed_scanners()
            structured_output = formatter.format(findings, metadata, sbom_info, ai_summary_text, executed_scanners)
            formatter.write_json(structured_output, json_output)
            if not quiet:
                console.print(f"✓ Structured JSON: {json_output}")
        else:
            # Flat array output with metadata
            # Use first directory for metadata extraction
            # Precedence: CLI args > config > auto-detect
            config_metadata = config.get("metadata", {})
            metadata = extract_project_metadata(
                directories_to_scan[0],
                project_name=project or config_metadata.get("project"),
                branch=branch or config_metadata.get("branch"),
                commit_hash=commit_hash or config_metadata.get("commit_hash")
            )

            executed_scanners = aggregator.get_executed_scanners()
            flat_output = {
                "build_cycle": datetime.utcnow().isoformat() + "Z",
                "project": metadata.get("project_name", "unknown"),
                "commit_hash": metadata.get("commit_hash"),
                "branch": metadata.get("branch"),
                "sbom": sbom_info if sbom_info else None,
                "scanners_executed": executed_scanners,
                "data": findings
            }

            import json
            with open(json_output, 'w') as f:
                json.dump(flat_output, f, indent=2)

            if not quiet:
                console.print(f"✓ Flat JSON: {json_output}")

        # Per-tool output files (if enabled)
        if per_tool_files and findings:
            # Group findings by tool
            findings_by_tool = {}
            for finding in findings:
                tool = finding.get("tool", "unknown")
                if tool not in findings_by_tool:
                    findings_by_tool[tool] = []
                findings_by_tool[tool].append(finding)

            # Write individual tool files
            for tool_name, tool_findings in findings_by_tool.items():
                tool_filename = f"{tool_name.lower()}.json"
                tool_output = out_dir / tool_filename

                with open(tool_output, 'w') as f:
                    json.dump(tool_findings, f, indent=2)

                if not quiet:
                    console.print(f"✓ {tool_name.capitalize()}: {tool_output} ({len(tool_findings)} findings)")

        # SARIF output
        # Use first directory as base path for relative file paths
        sarif_converter = SARIFConverter(base_path=directories_to_scan[0])
        sarif_converter.convert_and_write(
            findings,
            sarif_output,
            include_ai_summary=not no_ai
        )
        if not quiet:
            console.print(f"✓ SARIF: {sarif_output}")

        # Validate SARIF
        if validate and not quiet:
            is_valid, message = validate_sarif(Path(sarif_output))
            if is_valid:
                console.print(f"✓ SARIF validation: [green]{message}[/green]")
            else:
                console.print(f"⚠ SARIF validation: [yellow]{message}[/yellow]")

        # Summary
        if not quiet:
            console.print(f"\n[bold green]Scan completed![/bold green]")
            console.print(f"Found {stats['total']} total finding(s)")
        else:
            console.print(f"Results: {json_output}")

        # Determine exit code based on --fail-on threshold
        exit_code = 0
        if fail_on and fail_on.upper() != "NONE":
            # Define severity hierarchy (higher index = higher severity)
            severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            fail_threshold = fail_on.upper()

            if fail_threshold not in severity_levels:
                console.print(f"[yellow]Warning: Invalid --fail-on value '{fail_on}'. Valid values: CRITICAL, HIGH, MEDIUM, LOW, NONE[/yellow]")
            else:
                threshold_index = severity_levels.index(fail_threshold)
                # Check if any findings meet or exceed the threshold
                for severity_name, count in stats['by_severity'].items():
                    if count > 0 and severity_name in severity_levels:
                        severity_index = severity_levels.index(severity_name)
                        if severity_index >= threshold_index:
                            exit_code = 1
                            if not quiet:
                                console.print(f"[yellow]Failing due to {count} {severity_name} finding(s) (threshold: {fail_threshold})[/yellow]")
                            break

        if exit_code != 0:
            raise typer.Exit(exit_code)

    except ScanTimeoutError as e:
        console.print(f"\n[red]✗ {str(e)}[/red]")
        console.print("[yellow]Scan terminated due to timeout. Use --timeout to adjust or remove it.[/yellow]")
        raise typer.Exit(2)


@app.command()
def summarize(
    results_file: Path = typer.Argument(
        ...,
        help="Path to YAVS JSON results file",
        exists=True
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="AI provider: 'anthropic' or 'openai' (auto-detects if not specified)"
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="AI model to use (provider-specific, uses default if not specified)"
    ),
    triage: bool = typer.Option(True, "--triage/--no-triage", help="Include triage analysis"),
    enrich: bool = typer.Option(False, "--enrich", help="Add summary to scan results file instead of separate file"),
    output_dir: Optional[Path] = typer.Option(
        None,
        "-o", "--output-dir",
        help="Output directory for summary file (default: current directory or from config)"
    ),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config file"),
):
    """
    Generate AI-powered summary and analysis of scan results.

    Uses Anthropic Claude or OpenAI GPT based on available API keys.
    Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.

    By default, saves summary to a separate JSON file (yavs-ai-summary.json).
    Use --enrich to add summary data directly to the scan results file.

    Examples:

        yavs summarize yavs-results.json

        yavs summarize yavs-results.json -o artifacts/summaries

        yavs summarize yavs-results.json --provider openai --model gpt-4o

        yavs summarize yavs-results.json --no-triage

        yavs summarize yavs-results.json --enrich
    """
    print_banner("AI-Powered Summary Generator")

    # Load configuration
    config = load_config(config_path)

    # Load results
    aggregator = Aggregator()
    aggregator.read_json(results_file)
    findings = aggregator.get_findings()

    if not findings:
        console.print("[yellow]No findings to summarize.[/yellow]")
        return

    console.print(f"\nAnalyzing {len(findings)} findings with AI...\n")

    # Use CLI args if provided, otherwise use config
    ai_provider = provider or config["ai"].get("provider")
    ai_model = model or config["ai"].get("model")
    ai_max_tokens = config["ai"].get("max_tokens", 4096)
    ai_temperature = config["ai"].get("temperature", 0.0)
    ai_features = config["ai"].get("features", {})

    # Storage for summary data
    import json
    from datetime import datetime
    summary_data = {
        "build_cycle": datetime.utcnow().isoformat() + "Z",
        "findings_count": len(findings),
    }

    # Generate summary (if enabled)
    summary_text = None
    if ai_features.get("summarize", True):
        try:
            summarizer = Summarizer(
                provider=ai_provider,
                model=ai_model,
                max_tokens=ai_max_tokens,
                temperature=ai_temperature
            )
            summary_text = summarizer.summarize(findings)
            summary_data["executive_summary"] = summary_text
            summary_data["ai_provider"] = summarizer.provider.provider_name
            summary_data["ai_model"] = summarizer.provider.model_name

            console.print(Panel(
                Markdown(summary_text),
                title="Executive Summary",
                border_style="green"
            ))
        except Exception as e:
            console.print(f"[red]Failed to generate summary: {str(e)}[/red]")
            raise typer.Exit(1)
    else:
        console.print("[yellow]Summary generation is disabled in config (ai.features.summarize)[/yellow]")

    # Triage analysis (if enabled and requested)
    triage_results = None
    if triage and ai_features.get("triage", True):
        try:
            console.print("\n[bold]Running triage analysis...[/bold]")
            triage_engine = TriageEngine(
                provider=ai_provider,
                model=ai_model,
                max_tokens=ai_max_tokens,
                temperature=ai_temperature
            )
            triage_results = triage_engine.triage(findings)
            summary_data["triage"] = triage_results

            # Show provider info
            console.print(f"[dim]Using {triage_results.get('ai_provider', 'AI')} ({triage_results.get('ai_model', 'unknown')})[/dim]\n")

            console.print(Panel(
                Markdown(triage_results["ai_analysis"]),
                title=f"Triage Analysis ({triage_results['cluster_count']} clusters)",
                border_style="yellow"
            ))
        except Exception as e:
            console.print(f"[yellow]Triage analysis failed: {str(e)}[/yellow]")
    elif triage and not ai_features.get("triage", True):
        console.print("[yellow]Triage analysis is disabled in config (ai.features.triage)[/yellow]")

    # Determine if we should enrich or save separately
    should_enrich = enrich or config.get("ai", {}).get("summary", {}).get("enrich_scan_results", False)

    if should_enrich:
        # Warn if output_dir is specified with --enrich (it will be ignored)
        if output_dir:
            console.print("[yellow]⚠ Warning: --output-dir is ignored when using --enrich.[/yellow]")
            console.print("[yellow]  The scan results file will be modified in place.[/yellow]")

        # Read the original scan results file and add summary data
        console.print("\n[bold]Enriching scan results file with summary...[/bold]")
        try:
            with open(results_file, 'r') as f:
                scan_results = json.load(f)

            # Add summary data to scan results
            scan_results["ai_summary"] = summary_data

            # Write back to the same file
            with open(results_file, 'w') as f:
                json.dump(scan_results, f, indent=2)

            console.print(f"[green]✓ Enriched scan results saved to:[/green] {results_file}")
        except Exception as e:
            console.print(f"[red]Failed to enrich scan results: {str(e)}[/red]")
            raise typer.Exit(1)
    else:
        # Save to separate file
        # Determine output directory: CLI arg > config > current directory
        if output_dir:
            summary_dir = Path(output_dir)
        else:
            summary_dir = Path(config.get("output", {}).get("directory", "."))

        # Ensure directory exists
        summary_dir.mkdir(parents=True, exist_ok=True)

        # Get filename from config
        default_summary_file = config.get("ai", {}).get("summary", {}).get("output_file", "yavs-ai-summary.json")
        summary_output_path = summary_dir / default_summary_file

        console.print(f"\n[bold]Saving summary to:[/bold] {summary_output_path}")
        try:
            with open(summary_output_path, 'w') as f:
                json.dump(summary_data, f, indent=2)

            console.print(f"[green]✓ Summary saved to:[/green] {summary_output_path}")
        except Exception as e:
            console.print(f"[red]Failed to save summary: {str(e)}[/red]")
            raise typer.Exit(1)


@app.command()
def report(
    results_file: Path = typer.Argument(
        ...,
        help="Path to YAVS JSON results file (structured or flat format)",
        exists=True
    ),
    output: Path = typer.Option(
        None,
        "-o", "--output",
        help="Output HTML file path (default: yavs-report.html in results directory)"
    ),
    summary_file: Optional[Path] = typer.Option(
        None,
        "--summary",
        help="Path to separate AI summary file (optional, if not enriched)",
        exists=False
    ),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config file"),
):
    """
    Generate beautiful HTML security report from scan results.

    Works with all YAVS output formats:
    - Structured output (default)
    - Flat output format
    - Enriched results (with ai_summary embedded)
    - Separate summary file (merged automatically)

    Examples:

        yavs report yavs-results.json

        yavs report yavs-results.json -o security-report.html

        yavs report yavs-results.json --summary yavs-ai-summary.json

        yavs report enriched-results.json -o report.html
    """
    print_banner("HTML Report Generator")

    # Load configuration
    config = load_config(config_path)

    # Determine output path
    if output:
        output_path = Path(output)
    else:
        # Default: same directory as results file, named yavs-report.html
        output_path = results_file.parent / "yavs-report.html"

    console.print(f"\n[bold]Generating HTML report...[/bold]")
    console.print(f"  Input: {results_file}")
    if summary_file:
        console.print(f"  Summary: {summary_file}")
    console.print(f"  Output: {output_path}")

    try:
        from .reporting.html_report import generate_html_report

        # Generate the report
        generate_html_report(
            scan_results=results_file,
            output=output_path,
            summary=summary_file
        )

        console.print(f"\n[green]✓ HTML report generated successfully![/green]")
        console.print(f"[green]  Open:[/green] file://{output_path.absolute()}")

    except FileNotFoundError as e:
        console.print(f"[red]✗ File not found: {e}[/red]")
        raise typer.Exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON in results file: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]✗ Failed to generate report: {str(e)}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)


# Create tools subcommand group
tools_app = typer.Typer(help="Manage scanner tools (install, check, upgrade, pin versions)")
app.add_typer(tools_app, name="tools")


@tools_app.command("install")
def tools_install(
    install_trivy: bool = typer.Option(True, "--trivy/--no-trivy", help="Install Trivy scanner"),
    install_python_tools: bool = typer.Option(True, "--python-tools/--no-python-tools", help="Install Python scanners (semgrep, bandit, checkov)"),
    use_package_manager: bool = typer.Option(False, "--use-brew/--no-brew", help="Use package manager (brew/apt) for Trivy"),
    force: bool = typer.Option(False, "--force", help="Force reinstall if already exists"),
):
    """
    Install scanner dependencies.

    Installs Trivy and Python-based scanners (semgrep, bandit, checkov).

    Examples:

        yavs tools install               # Install all tools
        yavs tools install --use-brew    # Use package manager for Trivy
        yavs tools install --no-trivy    # Only install Python tools
        yavs tools install --force       # Force reinstall all tools
    """
    print_banner("Install Scanner Tools")

    from .utils.scanner_installer import (
        download_and_install_trivy,
        install_via_package_manager,
        find_trivy_binary,
    )

    console.print()

    # Check current status
    trivy_path = find_trivy_binary()
    if trivy_path and not force:
        console.print(f"[green]✓ Trivy already installed:[/green] {trivy_path}")
        if not install_trivy:
            console.print("[dim]Use --force to reinstall[/dim]")
            return
    elif trivy_path:
        console.print(f"[yellow]⚠ Trivy found at {trivy_path}, reinstalling...[/yellow]")

    if install_trivy:
        console.print("\n[bold]Installing Trivy...[/bold]")

        if use_package_manager:
            # Try package manager first
            success = install_via_package_manager()
            if not success:
                console.print("[yellow]Package manager installation failed, trying direct download...[/yellow]")
                binary_path = download_and_install_trivy(force=force)
                if not binary_path:
                    console.print("[red]✗ Trivy installation failed[/red]")
                    raise typer.Exit(1)
        else:
            # Direct download
            binary_path = download_and_install_trivy(force=force)
            if not binary_path:
                console.print("[red]✗ Trivy installation failed[/red]")
                console.print("[yellow]Try using --use-brew to install via package manager[/yellow]")
                raise typer.Exit(1)

    # Verify installation
    console.print("\n[bold]Verifying installation...[/bold]")

    # Check Trivy
    trivy_path = find_trivy_binary()
    if trivy_path:
        console.print(f"[green]✓ Trivy:[/green] {trivy_path}")
        # Test it
        from .utils.subprocess_runner import run_command
        try:
            returncode, stdout, stderr = run_command(f"{trivy_path} --version", check=False, timeout=10)
            if returncode == 0:
                version_line = stdout.strip().split('\n')[0]
                console.print(f"  [dim]{version_line}[/dim]")
        except Exception:  # nosec B110 - Safe: hardcoded command, no user input
            pass
    else:
        console.print("[yellow]⚠ Trivy not found[/yellow]")

    # Check and install Python scanners
    import shutil
    import subprocess  # nosec B404 - Safe: hardcoded command, no user input

    python_tools = {
        "semgrep": {"package": "semgrep", "check": "semgrep"},
        "bandit": {"package": "bandit", "check": "bandit"},
        "checkov": {"package": "checkov", "check": "checkov"},
    }

    missing_tools = []

    for tool_name, tool_info in python_tools.items():
        tool_path = shutil.which(tool_info["check"])
        if tool_path:
            console.print(f"[green]✓ {tool_name.capitalize()}:[/green] {tool_path}")
        else:
            console.print(f"[yellow]⚠ {tool_name.capitalize()} not found[/yellow]")
            missing_tools.append(tool_info["package"])
            console.print(f"  [dim]Install with: pip install {tool_info['package']}[/dim]")

    # Auto-install missing Python tools if requested
    if missing_tools and install_python_tools:
        console.print(f"\n[bold]Installing {len(missing_tools)} missing Python scanner(s)...[/bold]")
        for package in missing_tools:
            try:
                console.print(f"[cyan]Installing {package}...[/cyan]")
                result = subprocess.run(  # nosec B603 - Safe: hardcoded command, no user input
                    [sys.executable, "-m", "pip", "install", package],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                if result.returncode == 0:
                    console.print(f"[green]✓ {package} installed successfully[/green]")
                else:
                    console.print(f"[red]✗ Failed to install {package}[/red]")
                    console.print(f"  [dim]{result.stderr}[/dim]")
            except subprocess.TimeoutExpired:
                console.print(f"[red]✗ Installation of {package} timed out[/red]")
            except Exception as e:
                console.print(f"[red]✗ Error installing {package}: {str(e)}[/red]")

        # Re-check after installation
        console.print("\n[bold]Verifying Python scanners...[/bold]")
        for tool_name, tool_info in python_tools.items():
            tool_path = shutil.which(tool_info["check"])
            if tool_path:
                console.print(f"[green]✓ {tool_name.capitalize()}:[/green] {tool_path}")
            else:
                console.print(f"[red]✗ {tool_name.capitalize()} still not found[/red]")

    # Check BinSkim (optional)
    binskim_path = shutil.which("binskim")
    if binskim_path:
        console.print(f"[green]✓ BinSkim:[/green] {binskim_path}")
    else:
        console.print("[dim]○ BinSkim not found (optional, for Windows binary analysis)[/dim]")
        console.print("  [dim]Install with: dotnet tool install --global Microsoft.CodeAnalysis.BinSkim[/dim]")

    console.print()
    console.print("[bold green]Installation complete![/bold green]")
    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("[dim]  • Run 'yavs tools status' to verify installations[/dim]")
    console.print("[dim]  • Run 'yavs scan --all' to start scanning[/dim]")


@tools_app.command("status")
def tools_status():
    """
    Check versions of all installed scanner tools.

    Shows current versions of: Trivy, Semgrep, Bandit, Checkov, BinSkim

    Examples:

        yavs tools status
    """
    import subprocess  # nosec B404 - Safe: hardcoded command, no user input
    from rich.table import Table

    print_banner("Scanner Tool Versions")
    console.print()

    table = Table(title="Installed Scanner Tools", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="bold", width=15)
    table.add_column("Version", width=30)
    table.add_column("Status", width=15)

    tools = [
        ("Trivy", ["trivy", "--version"]),
        ("Semgrep", ["semgrep", "--version"]),
        ("Bandit", ["bandit", "--version"]),
        ("Checkov", ["checkov", "--version"]),
        ("BinSkim", ["binskim", "--version"]),
    ]

    for tool_name, cmd in tools:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)  # nosec B603 - Safe: hardcoded command, no user input
            if result.returncode == 0:
                # Extract version from output
                output = result.stdout.strip() or result.stderr.strip()
                version = output.split('\n')[0]  # First line usually has version
                table.add_row(tool_name, version, "[green]✓ Installed[/green]")
            else:
                table.add_row(tool_name, "[dim]—[/dim]", "[red]✗ Not found[/red]")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            table.add_row(tool_name, "[dim]—[/dim]", "[red]✗ Not installed[/red]")

    console.print(table)
    console.print()
    console.print("[dim]Tip: Use 'yavs tools install' to install missing tools[/dim]")
    console.print("[dim]Tip: Use 'yavs tools upgrade' to update all tools[/dim]")


@tools_app.command("upgrade")
def tools_upgrade(
    yes: bool = typer.Option(False, "-y", "--yes", help="Skip confirmation prompt")
):
    """
    Update all scanner tools to their latest versions.

    Updates: Semgrep, Bandit, Checkov (via pip)
    Note: Trivy should be updated via system package manager

    Examples:

        yavs tools upgrade

        yavs tools upgrade -y  # Skip confirmation
    """
    import subprocess  # nosec B404 - Safe: hardcoded command, no user input

    print_banner("Update Scanner Tools")
    console.print()

    if not yes:
        console.print("[yellow]This will upgrade the following tools:[/yellow]")
        console.print("  • Semgrep")
        console.print("  • Bandit")
        console.print("  • Checkov")
        console.print()
        console.print("[dim]Note: Trivy must be updated via system package manager (brew, apt, etc.)[/dim]")
        console.print()

        confirm = typer.confirm("Continue with upgrade?")
        if not confirm:
            console.print("[yellow]Upgrade cancelled[/yellow]")
            raise typer.Exit(0)

    tools_to_upgrade = ["semgrep", "bandit", "checkov"]

    console.print("[bold]Upgrading scanner tools...[/bold]\n")

    for tool in tools_to_upgrade:
        console.print(f"[cyan]Upgrading {tool}...[/cyan]")
        try:
            result = subprocess.run(  # nosec B603 B607 - Safe: hardcoded command, no user input
                ["pip", "install", "--upgrade", tool],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                console.print(f"[green]✓ {tool} upgraded successfully[/green]")
            else:
                console.print(f"[red]✗ Failed to upgrade {tool}[/red]")
                if result.stderr:
                    console.print(f"[dim]{result.stderr}[/dim]")
        except Exception as e:
            console.print(f"[red]✗ Error upgrading {tool}: {e}[/red]")
        console.print()

    console.print("[bold green]Upgrade complete![/bold green]")
    console.print()
    console.print("[dim]Run 'yavs tools status' to verify new versions[/dim]")
    console.print("[dim]Run 'yavs tools pin' to save current versions[/dim]")


@tools_app.command("pin")
def tools_pin(
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path (default: requirements-scanners.txt)"
    )
):
    """
    Create requirements file with current scanner tool versions.

    Generates a requirements.txt file with pinned versions for reproducible builds.
    Commit this file to lock scanner versions across your team and CI/CD.

    Examples:

        yavs tools pin

        yavs tools pin -o my-requirements.txt
    """
    import subprocess  # nosec B404 - Safe: hardcoded command, no user input
    from datetime import datetime

    print_banner("Pin Scanner Tool Versions")
    console.print()

    output_file = output or Path("requirements-scanners.txt")

    console.print(f"[bold]Creating {output_file}...[/bold]\n")

    # Get versions
    versions = {}
    tools = ["semgrep", "bandit", "checkov"]

    for tool in tools:
        try:
            result = subprocess.run(  # nosec B603 B607 - Safe: hardcoded command, no user input
                ["pip", "show", tool],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Version:'):
                        version = line.split(':', 1)[1].strip()
                        versions[tool] = version
                        console.print(f"[green]✓ {tool}=={version}[/green]")
                        break
        except Exception as e:
            console.print(f"[yellow]⚠ Could not determine version for {tool}[/yellow]")

    if not versions:
        console.print("[red]✗ No scanner tools found[/red]")
        console.print("[dim]Run 'yavs tools install' to install scanner tools[/dim]")
        raise typer.Exit(1)

    # Write requirements file
    console.print()
    with open(output_file, 'w') as f:
        f.write(f"# Scanner tool versions - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Install with: pip install -r {output_file}\n")
        f.write("\n")

        for tool, version in versions.items():
            f.write(f"{tool}=={version}\n")

        f.write("\n")
        f.write("# Note: Trivy should be installed via system package manager\n")
        f.write("# See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/\n")

    console.print(f"[bold green]✓ Pinned versions saved to {output_file}[/bold green]")
    console.print()
    console.print("[dim]Commit this file to your repository for reproducible builds[/dim]")
    console.print("[dim]Install pinned versions with: pip install -r requirements-scanners.txt[/dim]")


# ============================================================================
# Config Management Commands
# ============================================================================

# Create config subcommand group
config_app = typer.Typer(help="Manage YAVS configuration files")
app.add_typer(config_app, name="config")

@config_app.command("init")
def config_init(
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output path (default: ./yavs.yaml)"),
    global_config: bool = typer.Option(False, "--global", help="Create global config in ~/.yavs/config.yaml"),
    force: bool = typer.Option(False, "-f", "--force", help="Overwrite existing config file"),
    minimal: bool = typer.Option(False, "--minimal", help="Create minimal config with only essential settings"),
):
    """
    Create a new YAVS configuration file.

    Creates a yavs.yaml file with all available settings and documentation.
    By default creates in current directory, or use --global for ~/.yavs/config.yaml

    Examples:
        yavs config init                    # Create ./yavs.yaml
        yavs config init --global           # Create ~/.yavs/config.yaml
        yavs config init -o my-config.yaml  # Custom path
        yavs config init --minimal          # Only essential settings
    """
    print_banner("Initialize Configuration")

    # Determine output path
    if global_config:
        config_dir = Path.home() / ".yavs"
        config_dir.mkdir(exist_ok=True)
        config_path = config_dir / "config.yaml"
    elif output:
        config_path = output
    else:
        config_path = Path("yavs.yaml")

    # Check if file exists
    if config_path.exists() and not force:
        console.print(f"[yellow]✗ Config file already exists: {config_path}[/yellow]")
        console.print(f"[yellow]  Use --force to overwrite[/yellow]")
        raise typer.Exit(1)

    # Load default config
    default_config = load_config()

    if minimal:
        # Create minimal config with only essentials
        config_content = """# YAVS Configuration File
# Minimal configuration with essential settings only

scan:
  # Directories to scan (default: current directory)
  directories:
    - "."

  # Patterns to ignore during scanning
  ignore_paths:
    - "node_modules/"
    - ".venv/"
    - "__pycache__/"
    - ".git/"

# Scanner configuration
scanners:
  trivy:
    enabled: true
    timeout: 300
  semgrep:
    enabled: true
    timeout: 300
  bandit:
    enabled: true
    timeout: 300
  checkov:
    enabled: true
    timeout: 300

# AI features (requires ANTHROPIC_API_KEY or OPENAI_API_KEY)
ai:
  enabled: true
  features:
    fix_suggestions: true
    summarize: true
    triage: true

# Output configuration
output:
  directory: "."
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"
"""
    else:
        # Create full config with all options and documentation
        config_content = f"""# YAVS Configuration File
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Documentation: https://github.com/YAVS-OSS/yavs

# Scan Configuration
scan:
  # Directories to scan (relative to config file or absolute paths)
  directories:
{yaml.dump(default_config['scan']['directories'], default_flow_style=False, indent=4)}

  # Patterns to ignore during scanning (glob patterns and regex supported)
  ignore_paths:
{yaml.dump(default_config['scan']['ignore_paths'], default_flow_style=False, indent=4)}

# Project Metadata (used in reports and SARIF output)
metadata:
  project: {default_config['metadata']['project'] or 'null  # e.g., "my-awesome-project"'}
  branch: {default_config['metadata']['branch'] or 'null  # e.g., "main"'}
  commit_hash: {default_config['metadata']['commit_hash'] or 'null  # e.g., "abc123..."'}

# Scanner Configuration
# Each scanner can be enabled/disabled and have custom timeouts and flags
scanners:
  trivy:
    enabled: {default_config['scanners']['trivy']['enabled']}
    timeout: {default_config['scanners']['trivy']['timeout']}
    flags: "{default_config['scanners']['trivy']['flags']}"  # Additional CLI flags
    # Native config: ~/.trivy/trivy.yaml (takes precedence)

  semgrep:
    enabled: {default_config['scanners']['semgrep']['enabled']}
    timeout: {default_config['scanners']['semgrep']['timeout']}
    flags: "{default_config['scanners']['semgrep']['flags']}"
    # Native config: .semgrep.yaml or .semgrepignore

  bandit:
    enabled: {default_config['scanners']['bandit']['enabled']}
    timeout: {default_config['scanners']['bandit']['timeout']}
    flags: "{default_config['scanners']['bandit']['flags']}"
    # Native config: .bandit or bandit.yaml

  binskim:
    enabled: {default_config['scanners']['binskim']['enabled']}
    timeout: {default_config['scanners']['binskim']['timeout']}
    flags: "{default_config['scanners']['binskim']['flags']}"
    # Windows only - binary analysis

  checkov:
    enabled: {default_config['scanners']['checkov']['enabled']}
    timeout: {default_config['scanners']['checkov']['timeout']}
    flags: "{default_config['scanners']['checkov']['flags']}"
    # Native config: .checkov.yaml

# Output Configuration
output:
  directory: "{default_config['output']['directory']}"  # Output directory
  json: "{default_config['output']['json']}"  # JSON results file
  sarif: "{default_config['output']['sarif']}"  # SARIF 2.1.0 output

# AI Features (requires API keys)
# Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable
ai:
  enabled: {default_config['ai']['enabled']}
  provider: {default_config['ai']['provider'] or 'null  # "anthropic" or "openai" (auto-detected)'}
  model: {default_config['ai']['model'] or 'null  # Custom model (default: provider default)'}
  max_tokens: {default_config['ai']['max_tokens']}
  temperature: {default_config['ai']['temperature']}

  features:
    fix_suggestions: {default_config['ai']['features']['fix_suggestions']}  # Generate fix suggestions
    summarize: {default_config['ai']['features']['summarize']}  # Executive summaries
    triage: {default_config['ai']['features']['triage']}  # Intelligent clustering

# Severity Mapping
# Map tool-specific severities to standard levels
severity_mapping:
{yaml.dump(default_config['severity_mapping'], default_flow_style=False, indent=2)}

# Logging Configuration
logging:
  level: "{default_config['logging']['level']}"  # DEBUG, INFO, WARNING, ERROR
  format: "{default_config['logging']['format']}"  # "rich" or "plain"

  file:
    enabled: {default_config['logging']['file']['enabled']}
    path: "{default_config['logging']['file']['path']}"
    max_bytes: {default_config['logging']['file']['max_bytes']}  # 10MB
    backup_count: {default_config['logging']['file']['backup_count']}
"""

    # Write config file
    with open(config_path, 'w') as f:
        f.write(config_content)

    console.print()
    console.print(f"[bold green]✓ Configuration file created: {config_path}[/bold green]")
    console.print()

    # Show usage instructions
    if global_config:
        console.print("[cyan]Global configuration created. YAVS will use this as default.[/cyan]")
    else:
        console.print("[cyan]Use this config file with:[/cyan]")
        console.print(f"  yavs scan --config {config_path} --all")

    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print(f"  1. Edit {config_path} to customize settings")
    console.print(f"  2. Run: yavs config validate {config_path}")
    console.print(f"  3. Run: yavs scan --all")


@config_app.command("validate")
def config_validate(
    config_file: Optional[Path] = typer.Argument(None, help="Config file to validate (default: auto-detect)")
):
    """
    Validate a YAVS configuration file.

    Checks for syntax errors, invalid settings, and provides suggestions.

    Examples:
        yavs config validate                  # Validate auto-detected config
        yavs config validate yavs.yaml        # Validate specific file
        yavs config validate ~/.yavs/config.yaml
    """
    print_banner("Validate Configuration")

    # Determine which config to validate
    if config_file:
        if not config_file.exists():
            console.print(f"[red]✗ Config file not found: {config_file}[/red]")
            raise typer.Exit(1)
        config_path = config_file
    else:
        # Auto-detect config
        candidates = [
            Path("yavs.yaml"),
            Path("config.yaml"),
            Path.home() / ".yavs" / "config.yaml"
        ]

        config_path = None
        for candidate in candidates:
            if candidate.exists():
                config_path = candidate
                break

        if not config_path:
            console.print("[yellow]No config file found in:[/yellow]")
            for candidate in candidates:
                console.print(f"  • {candidate}")
            console.print()
            console.print("[cyan]Create a config with: yavs config init[/cyan]")
            raise typer.Exit(1)

    console.print(f"[cyan]Validating: {config_path}[/cyan]")
    console.print()

    errors = []
    warnings = []

    try:
        # Load and parse YAML
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        if not isinstance(config, dict):
            errors.append("Config file must contain a YAML dictionary")
        else:
            # Validate structure
            expected_sections = ['scan', 'metadata', 'scanners', 'output', 'ai', 'severity_mapping', 'logging']

            # Check for required sections
            if 'scan' not in config:
                warnings.append("Missing 'scan' section (will use defaults)")
            if 'output' not in config:
                warnings.append("Missing 'output' section (will use defaults)")

            # Validate scanners section
            if 'scanners' in config:
                valid_scanners = ['trivy', 'semgrep', 'bandit', 'binskim', 'checkov']
                for scanner in config['scanners']:
                    if scanner not in valid_scanners:
                        warnings.append(f"Unknown scanner: {scanner}")

                    scanner_config = config['scanners'][scanner]
                    if not isinstance(scanner_config, dict):
                        errors.append(f"Scanner '{scanner}' config must be a dictionary")
                    else:
                        if 'timeout' in scanner_config and not isinstance(scanner_config['timeout'], int):
                            errors.append(f"Scanner '{scanner}' timeout must be an integer")

            # Validate AI section
            if 'ai' in config:
                ai_config = config['ai']
                if 'provider' in ai_config and ai_config['provider'] not in [None, 'anthropic', 'openai']:
                    errors.append(f"Invalid AI provider: {ai_config['provider']} (must be 'anthropic' or 'openai')")

                if 'temperature' in ai_config:
                    temp = ai_config['temperature']
                    if not isinstance(temp, (int, float)) or temp < 0 or temp > 1:
                        errors.append(f"AI temperature must be between 0 and 1, got: {temp}")

            # Validate severity mapping
            if 'severity_mapping' in config:
                valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                for key, value in config['severity_mapping'].items():
                    if value not in valid_severities:
                        errors.append(f"Invalid severity mapping '{key}' -> '{value}' (must be one of {valid_severities})")

            # Validate logging
            if 'logging' in config:
                log_config = config['logging']
                if 'level' in log_config and log_config['level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
                    errors.append(f"Invalid log level: {log_config['level']}")

    except yaml.YAMLError as e:
        errors.append(f"YAML syntax error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")

    # Show results
    if errors:
        console.print("[bold red]✗ Validation failed with errors:[/bold red]")
        console.print()
        for i, error in enumerate(errors, 1):
            console.print(f"  {i}. [red]{error}[/red]")
        console.print()

    if warnings:
        console.print("[bold yellow]⚠ Warnings:[/bold yellow]")
        console.print()
        for i, warning in enumerate(warnings, 1):
            console.print(f"  {i}. [yellow]{warning}[/yellow]")
        console.print()

    if not errors and not warnings:
        console.print("[bold green]✓ Configuration is valid![/bold green]")
        console.print()
        console.print("[dim]Run 'yavs config show' to see effective configuration[/dim]")
    elif not errors:
        console.print("[bold green]✓ Configuration is valid (with warnings)[/bold green]")

    if errors:
        raise typer.Exit(1)


@config_app.command("show")
def config_show(
    config_file: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
    section: Optional[str] = typer.Option(None, "-s", "--section", help="Show specific section only"),
):
    """
    Display current YAVS configuration.

    Shows the effective configuration (defaults + overrides).
    Useful for debugging and understanding current settings.

    Examples:
        yavs config show                    # Show all config
        yavs config show --section ai       # Show only AI config
        yavs config show --config yavs.yaml # Show specific file
    """
    print_banner("Current Configuration")

    # Load config (will merge defaults + file)
    config = load_config(config_file)

    # Show config source
    if config_file and config_file.exists():
        console.print(f"[cyan]Config source: {config_file}[/cyan]")
    else:
        # Try to detect which config was loaded
        candidates = [
            Path("yavs.yaml"),
            Path("config.yaml"),
            Path.home() / ".yavs" / "config.yaml"
        ]

        config_source = "defaults (no file found)"
        for candidate in candidates:
            if candidate.exists():
                config_source = str(candidate)
                break

        console.print(f"[cyan]Config source: {config_source}[/cyan]")
    console.print()

    # Filter by section if requested
    if section:
        if section not in config:
            console.print(f"[red]✗ Section '{section}' not found[/red]")
            console.print(f"[yellow]Available sections: {', '.join(config.keys())}[/yellow]")
            raise typer.Exit(1)

        config = {section: config[section]}

    # Display config as formatted YAML
    yaml_output = yaml.dump(config, default_flow_style=False, sort_keys=False, indent=2)
    console.print(yaml_output)

    # Show helpful tips
    console.print("[dim]Tip: Create custom config with: yavs config init[/dim]")


@config_app.command("path")
def config_path():
    """
    Show configuration file search paths.

    Displays where YAVS looks for config files and their priority order.
    """
    print_banner("Configuration Paths")

    table = Table(title="Config File Search Order", show_header=True, header_style="bold cyan")
    table.add_column("Priority", style="bold", width=10)
    table.add_column("Path", width=50)
    table.add_column("Status", width=15)

    search_paths = [
        ("1", Path("yavs.yaml"), "Highest"),
        ("2", Path("config.yaml"), "High"),
        ("3", Path.home() / ".yavs" / "config.yaml", "Medium"),
        ("4", "Built-in defaults", "Fallback")
    ]

    for priority, path, desc in search_paths:
        if isinstance(path, str):
            status = "Always available"
            path_str = path
        elif path.exists():
            status = "[green]✓ Found[/green]"
            path_str = str(path)
        else:
            status = "[dim]✗ Not found[/dim]"
            path_str = str(path)

        table.add_row(priority, path_str, status)

    console.print(table)
    console.print()

    console.print("[cyan]Priority:[/cyan] YAVS uses the first config file found.")
    console.print("[cyan]Override:[/cyan] Use --config flag to specify exact file.")
    console.print()
    console.print("[dim]Create config with: yavs config init[/dim]")
    console.print("[dim]Create global config with: yavs config init --global[/dim]")


@config_app.command("edit")
def config_edit(
    config_file: Optional[Path] = typer.Argument(None, help="Config file to edit (default: auto-detect)"),
):
    """
    Open configuration file in your default editor.

    Uses $EDITOR environment variable, falls back to common editors.

    Examples:
        yavs config edit                # Edit auto-detected config
        yavs config edit yavs.yaml      # Edit specific file
    """
    import subprocess  # nosec B404 - Safe: hardcoded command, no user input

    print_banner("Edit Configuration")

    # Determine which config to edit
    if config_file:
        if not config_file.exists():
            console.print(f"[yellow]Config file doesn't exist: {config_file}[/yellow]")
            create = typer.confirm("Create it now?")
            if create:
                # Call config init
                config_init(output=config_file)
                return
            else:
                raise typer.Exit(1)
        target_file = config_file
    else:
        # Auto-detect config
        candidates = [
            Path("yavs.yaml"),
            Path("config.yaml"),
            Path.home() / ".yavs" / "config.yaml"
        ]

        target_file = None
        for candidate in candidates:
            if candidate.exists():
                target_file = candidate
                break

        if not target_file:
            console.print("[yellow]No config file found.[/yellow]")
            create = typer.confirm("Create yavs.yaml in current directory?")
            if create:
                config_init(output=Path("yavs.yaml"))
                target_file = Path("yavs.yaml")
            else:
                raise typer.Exit(1)

    # Get editor
    editor = os.environ.get('EDITOR') or os.environ.get('VISUAL')

    if not editor:
        # Try common editors
        for candidate_editor in ['nano', 'vim', 'vi', 'emacs', 'code']:
            try:
                subprocess.run(['which', candidate_editor], check=True, capture_output=True)  # nosec B603 B607 - Safe: hardcoded command, no user input
                editor = candidate_editor
                break
            except subprocess.CalledProcessError:
                continue

    if not editor:
        console.print(f"[yellow]No editor found. Please edit manually:[/yellow]")
        console.print(f"  {target_file}")
        console.print()
        console.print("[dim]Set EDITOR environment variable to use this command[/dim]")
        raise typer.Exit(1)

    console.print(f"[cyan]Opening {target_file} with {editor}...[/cyan]")
    console.print()

    try:
        subprocess.run([editor, str(target_file)])  # nosec B603 - Safe: hardcoded command, no user input
        console.print()
        console.print("[green]✓ Done editing[/green]")
        console.print()
        console.print("[dim]Validate your changes with: yavs config validate[/dim]")
    except Exception as e:
        console.print(f"[red]✗ Failed to open editor: {e}[/red]")
        raise typer.Exit(1)


# ============================================================================
# Statistics Command
# ============================================================================

@app.command()
def stats(
    results_file: Path = typer.Argument(
        ...,
        help="Scan results file (JSON)",
        exists=True
    ),
    by_severity: bool = typer.Option(False, "--by-severity", help="Group by severity"),
    by_scanner: bool = typer.Option(False, "--by-scanner", help="Group by scanner"),
    by_category: bool = typer.Option(False, "--by-category", help="Group by category"),
    summary: bool = typer.Option(False, "--summary", help="One-line summary only"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Show statistics from scan results.

    Quickly view statistics without opening the full results file.
    Supports grouping by severity, scanner, or category.

    Examples:
        yavs stats results.json
        yavs stats results.json --by-severity
        yavs stats results.json --by-scanner
        yavs stats results.json --summary
        yavs stats results.json --json
    """
    print_banner("Scan Statistics")

    # Load results
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]✗ Failed to load results: {e}[/red]")
        raise typer.Exit(1)

    # Extract findings (support both flat and structured formats)
    findings = []
    if isinstance(data, list):
        # Flat format
        findings = data
    elif isinstance(data, dict):
        # Could be structured format or have findings key
        if 'findings' in data:
            findings = data['findings']
        elif 'sbom' in data or 'sast' in data or 'compliance' in data:
            # Structured format
            for category in ['sbom', 'sast', 'compliance', 'secrets', 'licenses']:
                if category in data:
                    if isinstance(data[category], dict):
                        # Has subcategories
                        for subcat, items in data[category].items():
                            if isinstance(items, list):
                                findings.extend(items)
                    elif isinstance(data[category], list):
                        findings.extend(data[category])

    if not findings:
        console.print("[yellow]No findings in results file[/yellow]")
        return

    total_findings = len(findings)

    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Count by scanner
    scanner_counts = {}
    for finding in findings:
        tool = finding.get('tool', 'unknown')
        scanner_counts[tool] = scanner_counts.get(tool, 0) + 1

    # Count by category
    category_counts = {}
    for finding in findings:
        category = finding.get('category', 'other')
        category_counts[category] = category_counts.get(category, 0) + 1

    # Summary mode - one line
    if summary:
        console.print(f"Total: {total_findings} findings | "
                     f"Critical: {severity_counts.get('CRITICAL', 0)} | "
                     f"High: {severity_counts.get('HIGH', 0)} | "
                     f"Medium: {severity_counts.get('MEDIUM', 0)} | "
                     f"Low: {severity_counts.get('LOW', 0)}")
        return

    # JSON output
    if json_output:
        stats_data = {
            "total": total_findings,
            "by_severity": severity_counts,
            "by_scanner": scanner_counts,
            "by_category": category_counts
        }
        console.print(json.dumps(stats_data, indent=2))
        return

    # Default: Show overview table
    if not by_severity and not by_scanner and not by_category:
        table = Table(title=f"Scan Results Overview: {results_file.name}", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold", width=20)
        table.add_column("Count", justify="right", width=15)

        table.add_row("Total Findings", str(total_findings))
        table.add_row("", "")  # Spacer

        # Severity breakdown
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
        for sev in severity_order:
            if sev in severity_counts:
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange1',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue',
                    'INFO': 'dim',
                    'UNKNOWN': 'dim'
                }.get(sev, 'white')
                table.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{severity_counts[sev]}[/{color}]")

        console.print()
        console.print(table)
        console.print()

        # Top scanners
        if scanner_counts:
            console.print("[cyan]Top Scanners:[/cyan]")
            for scanner, count in sorted(scanner_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                console.print(f"  • {scanner}: {count}")
            console.print()

        # Top categories
        if category_counts:
            console.print("[cyan]Top Categories:[/cyan]")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                console.print(f"  • {category}: {count}")
            console.print()

    # By severity
    elif by_severity:
        table = Table(title="Findings by Severity", show_header=True, header_style="bold cyan")
        table.add_column("Severity", style="bold", width=15)
        table.add_column("Count", justify="right", width=10)
        table.add_column("Percentage", justify="right", width=12)

        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
        for sev in severity_order:
            if sev in severity_counts:
                count = severity_counts[sev]
                percentage = (count / total_findings) * 100
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'orange1',
                    'MEDIUM': 'yellow',
                    'LOW': 'blue',
                    'INFO': 'dim',
                    'UNKNOWN': 'dim'
                }.get(sev, 'white')
                table.add_row(
                    f"[{color}]{sev}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                    f"[{color}]{percentage:.1f}%[/{color}]"
                )

        console.print()
        console.print(table)
        console.print()
        console.print(f"[dim]Total: {total_findings} findings[/dim]")

    # By scanner
    elif by_scanner:
        table = Table(title="Findings by Scanner", show_header=True, header_style="bold cyan")
        table.add_column("Scanner", style="bold", width=15)
        table.add_column("Count", justify="right", width=10)
        table.add_column("Percentage", justify="right", width=12)

        for scanner, count in sorted(scanner_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_findings) * 100
            table.add_row(scanner, str(count), f"{percentage:.1f}%")

        console.print()
        console.print(table)
        console.print()
        console.print(f"[dim]Total: {total_findings} findings[/dim]")

    # By category
    elif by_category:
        table = Table(title="Findings by Category", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="bold", width=20)
        table.add_column("Count", justify="right", width=10)
        table.add_column("Percentage", justify="right", width=12)

        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_findings) * 100
            table.add_row(category, str(count), f"{percentage:.1f}%")

        console.print()
        console.print(table)
        console.print()
        console.print(f"[dim]Total: {total_findings} findings[/dim]")


# ============================================================================
# Baseline/Ignore Management Commands
# ============================================================================

# Create ignore subcommand group
ignore_app = typer.Typer(help="Manage suppressed findings and baselines")
app.add_typer(ignore_app, name="ignore")

@ignore_app.command("add")
def ignore_add(
    finding_id: str = typer.Argument(..., help="Finding ID to suppress (CVE, CWE, rule ID)"),
    reason: Optional[str] = typer.Option(None, "-r", "--reason", help="Reason for suppression"),
    baseline: Path = typer.Option(Path(".yavs-baseline.yaml"), "-b", "--baseline", help="Baseline file path"),
):
    """
    Add a finding to the suppression baseline.

    Suppressed findings will be filtered out of future scans when using --baseline flag.

    Examples:
        yavs ignore add CVE-2023-1234 --reason "False positive"
        yavs ignore add CWE-89 --reason "Sanitized in production"
        yavs ignore add semgrep.rule-123 -r "Accepted risk"
    """
    print_banner("Add to Baseline")

    # Load existing baseline
    suppressions = []
    if baseline.exists():
        try:
            with open(baseline, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'suppressions' in data:
                    suppressions = data['suppressions']
        except Exception as e:
            console.print(f"[yellow]⚠ Could not load existing baseline: {e}[/yellow]")

    # Check if already suppressed
    for suppression in suppressions:
        if suppression['id'] == finding_id:
            console.print(f"[yellow]Finding {finding_id} is already suppressed[/yellow]")
            console.print(f"[dim]Reason: {suppression.get('reason', 'N/A')}[/dim]")
            return

    # Add new suppression
    new_suppression = {
        'id': finding_id,
        'reason': reason or "No reason provided",
        'added_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'added_by': os.environ.get('USER', 'unknown')
    }
    suppressions.append(new_suppression)

    # Write baseline
    baseline_data = {
        'version': '1.0',
        'description': 'YAVS suppression baseline',
        'suppressions': suppressions
    }

    try:
        with open(baseline, 'w') as f:
            yaml.dump(baseline_data, f, default_flow_style=False, sort_keys=False)
        console.print(f"[green]✓ Added {finding_id} to baseline: {baseline}[/green]")
        console.print(f"[dim]Total suppressions: {len(suppressions)}[/dim]")
        console.print()
        console.print("[cyan]Use in scans with:[/cyan]")
        console.print(f"  yavs scan --all --baseline {baseline}")
    except Exception as e:
        console.print(f"[red]✗ Failed to write baseline: {e}[/red]")
        raise typer.Exit(1)


@ignore_app.command("remove")
def ignore_remove(
    finding_id: str = typer.Argument(..., help="Finding ID to remove from suppression"),
    baseline: Path = typer.Option(Path(".yavs-baseline.yaml"), "-b", "--baseline", help="Baseline file path"),
):
    """
    Remove a finding from the suppression baseline.

    Examples:
        yavs ignore remove CVE-2023-1234
        yavs ignore remove CWE-89 --baseline custom-baseline.yaml
    """
    print_banner("Remove from Baseline")

    if not baseline.exists():
        console.print(f"[red]✗ Baseline file not found: {baseline}[/red]")
        raise typer.Exit(1)

    # Load baseline
    try:
        with open(baseline, 'r') as f:
            data = yaml.safe_load(f)
            suppressions = data.get('suppressions', [])
    except Exception as e:
        console.print(f"[red]✗ Failed to load baseline: {e}[/red]")
        raise typer.Exit(1)

    # Find and remove
    original_count = len(suppressions)
    suppressions = [s for s in suppressions if s['id'] != finding_id]

    if len(suppressions) == original_count:
        console.print(f"[yellow]Finding {finding_id} not found in baseline[/yellow]")
        return

    # Write updated baseline
    data['suppressions'] = suppressions
    try:
        with open(baseline, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        console.print(f"[green]✓ Removed {finding_id} from baseline[/green]")
        console.print(f"[dim]Remaining suppressions: {len(suppressions)}[/dim]")
    except Exception as e:
        console.print(f"[red]✗ Failed to write baseline: {e}[/red]")
        raise typer.Exit(1)


@ignore_app.command("list")
def ignore_list(
    baseline: Path = typer.Option(Path(".yavs-baseline.yaml"), "-b", "--baseline", help="Baseline file path"),
    show_details: bool = typer.Option(False, "--details", help="Show full details"),
):
    """
    List all suppressed findings.

    Examples:
        yavs ignore list
        yavs ignore list --details
        yavs ignore list --baseline custom-baseline.yaml
    """
    print_banner("Suppression Baseline")

    if not baseline.exists():
        console.print(f"[yellow]No baseline file found: {baseline}[/yellow]")
        console.print()
        console.print("[cyan]Create suppressions with:[/cyan]")
        console.print("  yavs ignore add CVE-2023-1234 --reason 'False positive'")
        return

    # Load baseline
    try:
        with open(baseline, 'r') as f:
            data = yaml.safe_load(f)
            suppressions = data.get('suppressions', [])
    except Exception as e:
        console.print(f"[red]✗ Failed to load baseline: {e}[/red]")
        raise typer.Exit(1)

    if not suppressions:
        console.print(f"[yellow]No suppressions in baseline: {baseline}[/yellow]")
        return

    console.print(f"[cyan]Baseline: {baseline}[/cyan]")
    console.print(f"[dim]Total suppressions: {len(suppressions)}[/dim]")
    console.print()

    if show_details:
        # Detailed table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID", style="bold", width=25)
        table.add_column("Reason", width=35)
        table.add_column("Added By", width=12)
        table.add_column("Date", width=18)

        for s in suppressions:
            table.add_row(
                s['id'],
                s.get('reason', 'N/A'),
                s.get('added_by', 'N/A'),
                s.get('added_date', 'N/A')
            )

        console.print(table)
    else:
        # Simple list
        for s in suppressions:
            console.print(f"  • {s['id']}")
            if s.get('reason'):
                console.print(f"    [dim]{s['reason']}[/dim]")


@ignore_app.command("clear")
def ignore_clear(
    baseline: Path = typer.Option(Path(".yavs-baseline.yaml"), "-b", "--baseline", help="Baseline file path"),
    yes: bool = typer.Option(False, "-y", "--yes", help="Skip confirmation"),
):
    """
    Clear all suppressions from baseline.

    Examples:
        yavs ignore clear
        yavs ignore clear -y  # Skip confirmation
    """
    print_banner("Clear Baseline")

    if not baseline.exists():
        console.print(f"[yellow]Baseline file not found: {baseline}[/yellow]")
        return

    # Load current count
    try:
        with open(baseline, 'r') as f:
            data = yaml.safe_load(f)
            count = len(data.get('suppressions', []))
    except:
        count = 0

    if count == 0:
        console.print("[yellow]Baseline is already empty[/yellow]")
        return

    # Confirm
    if not yes:
        console.print(f"[yellow]⚠  This will remove all {count} suppressions from {baseline}[/yellow]")
        confirm = typer.confirm("Are you sure?")
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            return

    # Clear
    try:
        baseline_data = {
            'version': '1.0',
            'description': 'YAVS suppression baseline',
            'suppressions': []
        }
        with open(baseline, 'w') as f:
            yaml.dump(baseline_data, f, default_flow_style=False, sort_keys=False)
        console.print(f"[green]✓ Cleared {count} suppressions from baseline[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to clear baseline: {e}[/red]")
        raise typer.Exit(1)


@ignore_app.command("export")
def ignore_export(
    results_file: Path = typer.Argument(..., help="Scan results file", exists=True),
    output: Path = typer.Option(Path(".yavs-baseline.yaml"), "-o", "--output", help="Output baseline file"),
    ids: Optional[str] = typer.Option(None, "--ids", help="Comma-separated finding IDs to export"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Only export findings of this severity"),
):
    """
    Export findings from scan results to baseline.

    Useful for creating baselines from existing scan results.

    Examples:
        yavs ignore export results.json -o baseline.yaml
        yavs ignore export results.json --ids CVE-123,CVE-456
        yavs ignore export results.json --severity LOW
    """
    print_banner("Export to Baseline")

    # Load results
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]✗ Failed to load results: {e}[/red]")
        raise typer.Exit(1)

    # Extract findings
    findings = []
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict) and 'findings' in data:
        findings = data['findings']

    if not findings:
        console.print("[yellow]No findings in results file[/yellow]")
        return

    # Filter findings
    if ids:
        id_list = [i.strip() for i in ids.split(',')]
        findings = [f for f in findings if f.get('rule_id') in id_list or f.get('vulnerability_id') in id_list]

    if severity:
        findings = [f for f in findings if f.get('severity', '').upper() == severity.upper()]

    if not findings:
        console.print("[yellow]No findings match filter criteria[/yellow]")
        return

    # Create suppressions
    suppressions = []
    for finding in findings:
        finding_id = finding.get('rule_id') or finding.get('vulnerability_id') or finding.get('id', 'unknown')
        suppressions.append({
            'id': finding_id,
            'reason': f"Exported from {results_file.name}",
            'added_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'added_by': os.environ.get('USER', 'unknown')
        })

    # Write baseline
    baseline_data = {
        'version': '1.0',
        'description': f'YAVS baseline exported from {results_file.name}',
        'suppressions': suppressions
    }

    try:
        with open(output, 'w') as f:
            yaml.dump(baseline_data, f, default_flow_style=False, sort_keys=False)
        console.print(f"[green]✓ Exported {len(suppressions)} findings to {output}[/green]")
        console.print()
        console.print("[cyan]Use in future scans with:[/cyan]")
        console.print(f"  yavs scan --all --baseline {output}")
    except Exception as e:
        console.print(f"[red]✗ Failed to write baseline: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def diff(
    baseline_file: Path = typer.Argument(
        ...,
        help="Baseline scan results file",
        exists=True
    ),
    current_file: Path = typer.Argument(
        ...,
        help="Current scan results file",
        exists=True
    ),
    show_all: bool = typer.Option(False, "--show-all", help="Show all findings (new, fixed, and existing)"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save comparison report to file"),
):
    """
    Compare two scan results to show what changed.

    Shows new findings, fixed findings, and optionally existing findings.

    Examples:

        yavs diff baseline.json current.json

        yavs diff old.json new.json --show-all

        yavs diff baseline.json current.json -o comparison.json
    """
    print_banner("Scan Comparison")

    from .utils.baseline import Baseline

    try:
        # Load baseline and compare
        console.print(f"\n[bold]Comparing scans:[/bold]")
        console.print(f"  Baseline: {baseline_file}")
        console.print(f"  Current:  {current_file}")

        # Load current scan findings
        with open(current_file, 'r') as f:
            current_data = json.load(f)

        from .utils.baseline import _extract_findings
        current_findings = _extract_findings(current_data)

        # Create baseline and compare
        baseline_obj = Baseline(baseline_file)
        comparison = baseline_obj.compare(current_findings)

        # Display results
        console.print(f"\n[bold cyan]Comparison Results:[/bold cyan]")
        console.print(f"  Baseline findings: {comparison['total_baseline']}")
        console.print(f"  Current findings:  {comparison['total_current']}")
        console.print()

        # New findings
        if comparison['new_count'] > 0:
            console.print(f"[bold red]✗ New findings: {comparison['new_count']}[/bold red]")
            table = Table(title="New Findings", show_header=True, header_style="bold red")
            table.add_column("Severity", style="red")
            table.add_column("File")
            table.add_column("Line", justify="right")
            table.add_column("Rule ID")
            table.add_column("Message")

            for finding in comparison['new_findings'][:20]:  # Show first 20
                table.add_row(
                    finding.get("severity", "UNKNOWN"),
                    finding.get("file", ""),
                    str(finding.get("line", "")),
                    finding.get("rule_id", ""),
                    finding.get("message", "")[:60]
                )

            console.print(table)
            if comparison['new_count'] > 20:
                console.print(f"  [dim]... and {comparison['new_count'] - 20} more[/dim]")
        else:
            console.print(f"[bold green]✓ No new findings[/bold green]")

        console.print()

        # Fixed findings
        if comparison['fixed_count'] > 0:
            console.print(f"[bold green]✓ Fixed findings: {comparison['fixed_count']}[/bold green]")
        else:
            console.print(f"[dim]No fixed findings[/dim]")

        # Existing findings
        if show_all and comparison['existing_count'] > 0:
            console.print()
            console.print(f"[bold yellow]Existing findings: {comparison['existing_count']}[/bold yellow]")

        # Save to file if requested
        if output:
            with open(output, 'w') as f:
                json.dump(comparison, f, indent=2)
            console.print(f"\n[green]✓ Comparison saved to:[/green] {output}")

        # Exit with code 1 if new findings
        if comparison['new_count'] > 0:
            raise typer.Exit(1)

    except FileNotFoundError as e:
        console.print(f"[red]✗ File not found: {e}[/red]")
        raise typer.Exit(2)
    except Exception as e:
        console.print(f"[red]✗ Comparison failed: {str(e)}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(2)


@app.command()
def version():
    """Show YAVS version."""
    print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")


@app.command()
def man(
    section: Optional[str] = typer.Argument(
        None,
        help="Show specific section: commands, config, examples, ci, ai, scanners, or all"
    )
):
    """Show detailed YAVS documentation with pagination."""
    from rich.markdown import Markdown

    # If no section specified, show interactive menu
    if section is None:
        show_man_menu()
        return

    # Show specific section or all
    section = section.lower()
    if section == "all":
        show_full_man()
    elif section == "commands":
        show_man_section("commands")
    elif section == "config":
        show_man_section("config")
    elif section == "examples":
        show_man_section("examples")
    elif section == "ci":
        show_man_section("ci")
    elif section == "ai":
        show_man_section("ai")
    elif section == "scanners":
        show_man_section("scanners")
    else:
        console.print(f"[red]Unknown section: {section}[/red]")
        console.print("Available sections: commands, config, examples, ci, ai, scanners, all")
        raise typer.Exit(1)


def show_man_menu():
    """Display interactive menu for documentation sections."""
    # Show ASCII banner
    print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")
    console.print()

    console.print("[bold cyan]YAVS Documentation[/bold cyan]\n")
    console.print("Select a section to view:\n")

    menu_items = [
        ("1", "Quick Start", "Essential commands and basic usage"),
        ("2", "All Commands", "Complete command reference"),
        ("3", "Configuration", "Config file format and options"),
        ("4", "Examples", "Real-world usage examples"),
        ("5", "CI/CD Integration", "Production and pipeline setup"),
        ("6", "AI Features", "AI-powered analysis capabilities"),
        ("7", "Scanner Details", "Individual scanner documentation"),
        ("8", "Full Manual", "Complete documentation (paginated)"),
        ("q", "Quit", "Exit documentation"),
    ]

    from rich.table import Table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", width=3)
    table.add_column("Section", style="bold white", width=20)
    table.add_column("Description", style="dim")

    for key, section, desc in menu_items:
        table.add_row(key, section, desc)

    console.print(table)
    console.print()

    choice = console.input("[bold cyan]Enter selection[/bold cyan] [dim](1-8 or q)[/dim]: ").strip().lower()

    if choice == "q":
        return
    elif choice == "1":
        show_man_section("quickstart")
    elif choice == "2":
        show_man_section("commands")
    elif choice == "3":
        show_man_section("config")
    elif choice == "4":
        show_man_section("examples")
    elif choice == "5":
        show_man_section("ci")
    elif choice == "6":
        show_man_section("ai")
    elif choice == "7":
        show_man_section("scanners")
    elif choice == "8":
        show_full_man()
    else:
        console.print("[red]Invalid selection[/red]")


def show_full_man():
    """Show full documentation with pagination."""
    from rich.markdown import Markdown

    # Show ASCII banner
    print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")
    console.print()

    docs = """
# YAVS - Yet Another Vulnerability Scanner

## NAME
    yavs - AI-enhanced security vulnerability scanner with SARIF output

## SYNOPSIS
    yavs [COMMAND] [OPTIONS]

## DESCRIPTION
    YAVS is a comprehensive security scanning tool that combines multiple scanners
    (Trivy, Semgrep, Bandit, BinSkim, Checkov) with AI-powered analysis to detect
    vulnerabilities, generate SBOM, and provide actionable remediation guidance.

## COMMANDS

### scan
    Scan filesystem and/or Docker images for vulnerabilities.

    Options:
      --sast              Run SAST scanners (Semgrep, Bandit, BinSkim)
      --sbom              Scan dependencies and generate SBOM (Trivy)
      --compliance        Run IaC compliance checks (Checkov)
      --all               Run all scanners
      --images TEXT       Docker image(s) to scan
      --images-file PATH  File containing list of images
      --ignore TEXT       Path patterns to ignore (regex)
      --output-dir PATH   Output directory for results
      --json PATH         JSON output file path
      --sarif PATH        SARIF output file path
      --flat              Use flat array format
      --config PATH       Path to config file
      --quiet, -q         Minimal output

    Production/CI Features:
      --fail-on SEVERITY  Exit with code 1 if findings >= severity
                          (CRITICAL|HIGH|MEDIUM|LOW|NONE)
      --severity TEXT     Only report specified severities (comma-separated)
      --timeout INT       Overall scan timeout in seconds
      --continue-on-error Continue if a scanner fails

    Baseline Features:
      --baseline PATH     Compare against baseline, show only new findings
      --baseline-generate PATH  Generate baseline file from scan results

    Examples:
      yavs scan --all                           # Scan current directory
      yavs scan /path/to/code --all             # Scan specific directory
      yavs scan --all --fail-on HIGH            # Fail CI if HIGH+ findings
      yavs scan --images nginx:latest           # Scan Docker image
      yavs scan --baseline baseline.json --all  # Compare against baseline

### summarize
    Generate AI-powered summary and triage of scan results.

    Options:
      --provider TEXT     AI provider: anthropic or openai
      --model TEXT        AI model to use
      --output, -o PATH   Output file path
      --enrich            Enrich scan results file instead of separate output

    Examples:
      yavs summarize yavs-results.json
      yavs summarize yavs-results.json --provider anthropic
      yavs summarize yavs-results.json -o summary.json

### report
    Generate HTML security assessment report.

    Options:
      --output, -o PATH   Output HTML file path
      --summary PATH      Path to separate AI summary file

    Examples:
      yavs report yavs-results.json
      yavs report yavs-results.json -o report.html
      yavs report yavs-results.json --summary ai-summary.json

### stats
    Show statistics from scan results.

    Usage:
      yavs stats results.json               # Overview stats
      yavs stats results.json --by-severity # Group by severity
      yavs stats results.json --by-scanner  # Group by scanner
      yavs stats results.json --summary     # One-line summary
      yavs stats results.json --json        # JSON output

### ignore
    Manage suppressed findings and baselines.

    Subcommands:
      yavs ignore add CVE-2023-1234 -r "False positive"
      yavs ignore list
      yavs ignore list --details
      yavs ignore remove CVE-2023-1234
      yavs ignore clear
      yavs ignore export results.json -o baseline.yaml

    Examples:
      yavs ignore add CVE-2023-1234 --reason "Not exploitable"
      yavs ignore add CWE-89 -r "Input is sanitized"
      yavs ignore export results.json --severity LOW
      yavs scan --all --baseline .yavs-baseline.yaml

### diff
    Compare two scan results to identify new and fixed findings.

    Options:
      --show-all          Show all findings (new, fixed, and existing)
      --output, -o PATH   Save comparison report to file

    Examples:
      yavs diff baseline.json current.json
      yavs diff old.json new.json --show-all

### tools
    Manage scanner tools (install, check, upgrade, pin versions).

    Subcommands:
      yavs tools install            # Install scanner tools
      yavs tools status             # Check scanner versions
      yavs tools upgrade            # Update all scanners
      yavs tools pin                # Pin versions to requirements file

    Examples:
      yavs tools install            # Install all tools
      yavs tools install --use-brew # Use package manager for Trivy
      yavs tools status             # Check current versions
      yavs tools upgrade            # Upgrade all scanners
      yavs tools upgrade -y         # Upgrade without confirmation
      yavs tools pin                # Create requirements-scanners.txt

### config
    Manage YAVS configuration files.

    Subcommands:
      yavs config init              # Create new config file
      yavs config validate          # Validate config file
      yavs config show              # Display current config
      yavs config path              # Show config search paths
      yavs config edit              # Open config in editor

    Examples:
      yavs config init                     # Create yavs.yaml
      yavs config init --global            # Create ~/.yavs/config.yaml
      yavs config init --minimal           # Minimal config
      yavs config validate                 # Validate auto-detected config
      yavs config show --section ai        # Show only AI config
      yavs config path                     # Show search order
      yavs config edit                     # Open in $EDITOR

### version
    Show YAVS version information.

### man
    Show this detailed documentation.

## CONFIGURATION FILE

YAVS can be configured via a YAML config file (default: config.yaml):

    scan:
      directories: ["."]           # Directories to scan
      ignore_paths:                # Regex patterns to ignore
        - "node_modules/"
        - "vendor/"
        - "\\\\.git/"

    scanners:
      trivy:
        enabled: true
        timeout: 300
        flags: ""                  # Additional CLI flags
      semgrep:
        enabled: true
        timeout: 300
      bandit:
        enabled: true
        timeout: 300

    output:
      directory: "."
      json: "yavs-results.json"
      sarif: "yavs-results.sarif"
      structured: true             # Structured vs flat format
      per_tool_files: false        # Generate per-tool output files

    ai:
      enabled: true
      provider: null               # anthropic or openai (auto-detect)
      model: null                  # Provider-specific model
      features:
        fix_suggestions: true
        summarize: true
        triage: true
      max_fixes_per_scan: 50

    metadata:
      project: null                # Auto-detect from directory
      branch: null                 # Auto-detect from git
      commit_hash: null            # Auto-detect from git

Load custom config:
    yavs scan --config path/to/config.yaml --all

## OUTPUT FORMATS

### Structured JSON (default)
    {
      "build_cycle": "2025-11-09T12:00:00Z",
      "project": "my-project",
      "sast": [...],
      "compliance": [...],
      "sbom": {...},
      "summary": {...}
    }

### Flat JSON (--flat)
    {
      "build_cycle": "2025-11-09T12:00:00Z",
      "data": [...]
    }

### SARIF
    Standard Static Analysis Results Interchange Format
    Compatible with GitHub Code Scanning, Azure DevOps, etc.

### HTML Report
    Interactive web-based security assessment report with:
    - Executive summary
    - Severity breakdown
    - Detailed findings by category
    - AI-powered fix suggestions
    - SBOM visualization

## BASELINE WORKFLOW

Generate baseline from current state:
    yavs scan --all --baseline-generate baseline.json

Compare future scans against baseline (show only new findings):
    yavs scan --all --baseline baseline.json

Diff two scan results:
    yavs diff baseline.json current.json

## CI/CD INTEGRATION

Fail CI pipeline on HIGH or CRITICAL findings:
    yavs scan --all --fail-on HIGH --quiet

Only report CRITICAL findings:
    yavs scan --all --severity CRITICAL

Set scan timeout:
    yavs scan --all --timeout 600

Continue on scanner failure:
    yavs scan --all --continue-on-error

## ENVIRONMENT VARIABLES

    ANTHROPIC_API_KEY    API key for Claude AI features
    OPENAI_API_KEY       API key for OpenAI GPT features

AI features are optional. YAVS works without AI but won't generate:
- Fix suggestions
- Executive summaries
- Finding triage/clustering

## EXIT CODES

    0    Success
    1    Findings at or above --fail-on severity threshold
    2    Error during execution

## FILES

    config.yaml              Default configuration file
    yavs-results.json        Default JSON output
    yavs-results.sarif       Default SARIF output
    sbom.json                Software Bill of Materials
    yavs-ai-summary.json     AI-generated summary
    yavs-report.html         HTML security report
    yavs.log                 Log file (if file logging enabled)

## EXAMPLES

### Basic Scanning
    # Scan current directory with all scanners
    yavs scan --all

    # Scan specific directory
    yavs scan /path/to/code --all

    # Scan multiple directories
    yavs scan ./src ./lib --all

### Docker Image Scanning
    # Scan single image
    yavs scan --images nginx:latest --sbom

    # Scan multiple images
    yavs scan --images nginx:latest --images python:3.11 --sbom

    # Scan images from file
    echo "nginx:latest" > images.txt
    echo "python:3.11" >> images.txt
    yavs scan --images-file images.txt --sbom

### Ignore Patterns
    # Ignore specific paths
    yavs scan --all --ignore "node_modules/" --ignore "test/"

    # Use regex patterns
    yavs scan --all --ignore ".*\\\\.min\\\\.js$" --ignore "vendor/"

### CI/CD Workflows
    # Fail CI on HIGH or CRITICAL findings
    yavs scan --all --fail-on HIGH -q || exit 1

    # Scan and generate baseline for first run
    yavs scan --all --baseline-generate baseline.json

    # Compare against baseline in future runs
    yavs scan --all --baseline baseline.json

### Complete Workflow
    # 1. Scan with all tools
    yavs scan --all --output-dir ./security-results

    # 2. Generate AI summary and triage
    yavs summarize ./security-results/yavs-results.json

    # 3. Generate HTML report
    yavs report ./security-results/yavs-results.json \\
                --summary ./security-results/yavs-ai-summary.json

### Custom Output
    # Use flat format
    yavs scan --all --flat

    # Generate per-tool files
    yavs scan --all --per-tool-files

    # Custom output paths
    yavs scan --all \\
              --json ./custom/results.json \\
              --sarif ./custom/results.sarif \\
              --sbom-output ./custom/sbom.json

## SCANNER DETAILS

### Trivy (Dependency/SBOM Scanner)
    - Scans: Dependencies, containers, filesystems
    - Detects: CVEs, secrets, licenses, misconfigurations
    - SBOM: CycloneDX format
    - Languages: All major languages

### Semgrep (Multi-Language SAST)
    - Languages: 20+ including Python, JavaScript, Java, Go, etc.
    - Rules: OWASP Top 10, CWE coverage
    - Custom: Supports custom rule definitions

### Bandit (Python SAST)
    - Focused Python security scanner
    - Detects: SQL injection, hardcoded secrets, command injection
    - Integration: Works alongside Semgrep for comprehensive Python coverage

### BinSkim (Binary Analysis)
    - Analyzes: PE (Windows) and ELF (Linux) binaries
    - Checks: Security features, compiler flags, vulnerable libraries

### Checkov (IaC/Compliance)
    - Scans: Terraform, Kubernetes, Docker, CloudFormation, ARM
    - Policies: Cloud security best practices, CIS benchmarks

## AI FEATURES

When configured with API keys, YAVS provides:

### Fix Suggestions
    Actionable remediation guidance for each finding:
    - What: Description of the vulnerability
    - Why: Security impact
    - How: Step-by-step fix instructions
    - Code: Example secure code snippets

### Triage & Clustering
    Intelligent grouping of similar findings:
    - Reduces noise by clustering related issues
    - Prioritizes by severity and exploitability
    - Identifies root cause patterns

### Executive Summary
    High-level security posture analysis:
    - Key findings summary
    - Risk assessment
    - Recommended next steps
    - Trend analysis (when used with baselines)

## MAKEFILE COMMANDS

For development and automation, YAVS includes 37 Makefile commands:

### Tool Management
    make verify-tools    # Check scanner versions (Trivy, Semgrep, Bandit, etc.)
    make update-tools    # Update all scanners to latest versions
    make pin-tools       # Create requirements-scanners.txt with pinned versions

### Installation & Setup
    make install         # Install YAVS in development mode
    make install-dev     # Install with dev dependencies (pytest, black, ruff)
    make setup           # Install scanner dependencies

### Development Tools
    make lint            # Run ruff linter
    make format          # Auto-format with black
    make format-check    # Check formatting (no changes)
    make build           # Build wheel and source distribution
    make build-check     # Build and verify package
    make upload-test     # Upload to Test PyPI
    make upload          # Upload to production PyPI

### Scanning & Testing
    make scan            # Quick scan (no AI)
    make scan-ai         # Scan with AI features
    make test            # Run pytest test suite
    make test-all        # All tests (pytest + combinations)
    make test-coverage   # With coverage report

### Cleanup
    make clean           # Clean build artifacts and temp files
    make clean-all       # Clean everything
    make clean-artifacts # Remove scan results

Run 'make help' for complete list of all 37 commands.

## SUPPORT

    Documentation: https://github.com/anthropics/yavs
    Issues: https://github.com/anthropics/yavs/issues
    Version: {version}

## SEE ALSO

    trivy(1), semgrep(1), bandit(1), checkov(1)

    SARIF specification: https://sarifweb.azurewebsites.net/
    CycloneDX SBOM: https://cyclonedx.org/
"""

    # Replace version placeholder
    docs = docs.replace("{version}", __version__)

    # Print markdown without pager - let terminal handle scrolling
    console.print(Markdown(docs))


def show_man_section(section: str):
    """Show a specific documentation section with pagination."""
    from rich.markdown import Markdown

    # Show ASCII banner
    print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")
    console.print()

    sections = get_man_sections()

    if section not in sections:
        console.print(f"[red]Unknown section: {section}[/red]")
        return

    content = sections[section]
    content = content.replace("{version}", __version__)

    # Print markdown without pager - let terminal handle scrolling
    console.print(Markdown(content))


def get_man_sections():
    """Get documentation sections as a dictionary."""
    return {
        "quickstart": """
# Quick Start Guide

## Installation
    pip install yavs

## Initial Setup
    # Install scanner dependencies
    yavs tools install

    # Or use Makefile (for development)
    make install-dev
    make setup

## Basic Usage
    # Scan current directory with all scanners
    yavs scan --all

    # Scan and generate HTML report
    yavs scan --all
    yavs report yavs-results.json

## Most Common Commands
    yavs scan --all                    # Full security scan
    yavs scan --all --fail-on HIGH     # CI/CD mode
    yavs summarize yavs-results.json   # AI analysis
    yavs report yavs-results.json      # HTML report
    yavs tools status                  # Check scanner versions
    yavs man commands                  # Full command reference

## Tool Management
    yavs tools install   # Install scanner tools
    yavs tools status    # Check scanner versions
    yavs tools upgrade   # Update all scanners
    yavs tools pin       # Pin versions for reproducibility

## Quick Examples
    # Scan with baseline tracking
    yavs scan --all --baseline-generate baseline.json  # First run
    yavs scan --all --baseline baseline.json           # Future runs

    # Docker image scanning
    yavs scan --images nginx:latest --sbom

    # Ignore test files
    yavs scan --all --ignore "test/" --ignore ".*_test\\.py$"

## Next Steps
    - Run 'yavs man config' to learn about configuration
    - Run 'yavs man examples' for more usage examples
    - Run 'yavs man ci' for CI/CD integration guide
""",

        "commands": """
# Command Reference

## scan
Scan filesystem and/or Docker images for vulnerabilities.

### Scanner Selection
    --sast              Run SAST scanners (Semgrep, Bandit, BinSkim)
    --sbom              Scan dependencies + generate SBOM (Trivy)
    --compliance        Run IaC compliance checks (Checkov)
    --all               Run all scanners

### Target Options
    [TARGETS...]        Directories to scan (default: current directory)
    --images TEXT       Docker image(s) to scan
    --images-file PATH  File with list of images (one per line)
    --ignore TEXT       Regex patterns to ignore (repeatable)

### Output Options
    --output-dir PATH   Output directory (default: current directory)
    --json PATH         JSON output path
    --sarif PATH        SARIF output path
    --sbom-output PATH  SBOM output path
    --flat              Use flat array format (vs structured)
    --per-tool-files    Generate separate files per scanner

### Production Features
    --fail-on SEVERITY  Exit code 1 if findings >= severity
                        Options: CRITICAL, HIGH, MEDIUM, LOW, NONE
    --severity TEXT     Only report specified severities (comma-separated)
    --quiet, -q         Minimal output (only summary and errors)
    --timeout INT       Overall scan timeout in seconds
    --continue-on-error Continue even if a scanner fails

### Baseline Features
    --baseline PATH            Compare against baseline (show only new)
    --baseline-generate PATH   Generate baseline from scan results

### Configuration
    --config PATH       Path to YAML config file
    --no-ai             Disable AI features
    --validate/--no-validate   Validate SARIF output (default: true)

### Metadata
    --project TEXT      Project name (default: auto-detect)
    --branch TEXT       Git branch (default: auto-detect)
    --commit-hash TEXT  Git commit hash (default: auto-detect)

## summarize
Generate AI-powered summary and triage of scan results.

    yavs summarize [OPTIONS] RESULTS_FILE

### Options
    --provider TEXT     AI provider: anthropic or openai (default: auto)
    --model TEXT        Model to use (provider-specific, default: best)
    --output, -o PATH   Output file path
    --enrich            Add summary to scan results file (not separate)

## report
Generate HTML security assessment report.

    yavs report [OPTIONS] RESULTS_FILE

### Options
    --output, -o PATH   HTML output path (default: yavs-report.html)
    --summary PATH      Separate AI summary file to include

## stats
Show statistics from scan results.

    yavs stats RESULTS_FILE [OPTIONS]

Quickly view scan statistics without opening the full results file.

**Options:**
- `--by-severity` - Group findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `--by-scanner` - Group findings by scanner (Trivy, Semgrep, etc.)
- `--by-category` - Group findings by category (dependency, sast, compliance)
- `--summary` - One-line summary only
- `--json` - Output statistics as JSON

**Examples:**
```bash
yavs stats results.json                  # Overview with severity breakdown
yavs stats results.json --by-severity    # Detailed severity table
yavs stats results.json --by-scanner     # Group by scanner tool
yavs stats results.json --summary        # Quick one-liner
yavs stats results.json --json           # JSON for scripting
```

**Output Example:**
```
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric         ┃ Count ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Findings │   259 │
├────────────────┼───────┤
│   CRITICAL     │    41 │
│   HIGH         │   103 │
│   MEDIUM       │    96 │
│   LOW          │    19 │
└────────────────┴───────┘
```

## ignore
Manage suppressed findings and baselines.

    yavs ignore [COMMAND]

Suppress false positives and create baseline files to filter findings in future scans.

### Subcommands

#### ignore add
Add a finding to the suppression baseline.

    yavs ignore add FINDING_ID [OPTIONS]

**Options:**
- `--reason, -r TEXT` - Reason for suppression (recommended)
- `--baseline, -b PATH` - Baseline file path (default: .yavs-baseline.yaml)

**Examples:**
```bash
yavs ignore add CVE-2023-1234 --reason "False positive - not used"
yavs ignore add CWE-89 -r "Input is sanitized in production"
yavs ignore add semgrep.rule-123 -r "Accepted risk"
```

#### ignore remove
Remove a finding from the suppression baseline.

    yavs ignore remove FINDING_ID [OPTIONS]

**Examples:**
```bash
yavs ignore remove CVE-2023-1234
yavs ignore remove CWE-89 --baseline custom-baseline.yaml
```

#### ignore list
List all suppressed findings.

    yavs ignore list [OPTIONS]

**Options:**
- `--details` - Show full details (reason, date, added by)
- `--baseline, -b PATH` - Baseline file path

**Examples:**
```bash
yavs ignore list                  # Simple list
yavs ignore list --details        # Full table with metadata
```

#### ignore clear
Clear all suppressions from baseline.

    yavs ignore clear [OPTIONS]

**Options:**
- `--yes, -y` - Skip confirmation prompt
- `--baseline, -b PATH` - Baseline file path

**Examples:**
```bash
yavs ignore clear           # Prompts for confirmation
yavs ignore clear -y        # No confirmation
```

#### ignore export
Export findings from scan results to baseline.

    yavs ignore export RESULTS_FILE [OPTIONS]

Useful for creating baselines from existing scan results.

**Options:**
- `--output, -o PATH` - Output baseline file (default: .yavs-baseline.yaml)
- `--ids TEXT` - Comma-separated finding IDs to export
- `--severity TEXT` - Only export findings of this severity

**Examples:**
```bash
yavs ignore export results.json -o baseline.yaml
yavs ignore export results.json --ids CVE-123,CVE-456
yavs ignore export results.json --severity LOW
yavs ignore export results.json --severity MEDIUM -o accepted-risks.yaml
```

### Baseline File Format

Suppressions are stored in YAML format:

```yaml
version: '1.0'
description: YAVS suppression baseline
suppressions:
  - id: CVE-2023-1234
    reason: False positive - package not used
    added_date: '2025-11-09 12:30:00'
    added_by: developer
  - id: CWE-89
    reason: Input is sanitized
    added_date: '2025-11-09 12:31:00'
    added_by: developer
```

### Using Baselines in Scans

Apply baseline during scan to filter suppressed findings:

```bash
yavs scan --all --baseline .yavs-baseline.yaml
```

The scan will automatically exclude any findings listed in the baseline file.

**Team Workflow:**
1. Create baseline: `yavs ignore add CVE-2023-1234 -r "False positive"`
2. Commit baseline: `git add .yavs-baseline.yaml && git commit`
3. Team scans: `yavs scan --all --baseline .yavs-baseline.yaml`

## diff
Compare two scan results to identify changes.

    yavs diff [OPTIONS] BASELINE_FILE CURRENT_FILE

### Options
    --show-all          Show all findings (new, fixed, existing)
    --output, -o PATH   Save comparison report to file

## tools
Manage scanner tools (install, check, upgrade, pin).

    yavs tools [COMMAND]

### Subcommands

#### tools install
Install scanner dependencies.

    yavs tools install                 # Install all tools
    yavs tools install --use-brew      # Use package manager for Trivy
    yavs tools install --no-trivy      # Only install Python tools
    yavs tools install --force         # Force reinstall

Installs: Trivy, Semgrep, Bandit, Checkov

#### tools status
Check versions of all installed scanner tools.

    yavs tools status

Shows current versions of: Trivy, Semgrep, Bandit, Checkov, BinSkim

#### tools upgrade
Update all scanner tools to their latest versions.

    yavs tools upgrade
    yavs tools upgrade -y  # Skip confirmation

Updates: Semgrep, Bandit, Checkov (via pip)
Note: Trivy must be updated via system package manager

#### tools pin
Create requirements file with current scanner tool versions.

    yavs tools pin
    yavs tools pin -o my-requirements.txt

Generates requirements-scanners.txt with pinned versions for reproducible builds.
Commit this file to lock scanner versions across team and CI/CD.

## config
Manage YAVS configuration files.

    yavs config [COMMAND]

### Subcommands

#### config init
Create a new YAVS configuration file.

    yavs config init                     # Create yavs.yaml in current directory
    yavs config init --global            # Create ~/.yavs/config.yaml
    yavs config init -o my-config.yaml   # Custom path
    yavs config init --minimal           # Minimal config with essentials only
    yavs config init --force             # Overwrite existing file

Creates a yavs.yaml file with all available settings and inline documentation.

**Options:**
- `--global` - Create global config in ~/.yavs/config.yaml (used as default)
- `--minimal` - Create minimal config with only essential settings
- `--output, -o PATH` - Specify custom output path
- `--force, -f` - Overwrite existing config file

#### config validate
Validate a YAVS configuration file.

    yavs config validate                  # Validate auto-detected config
    yavs config validate yavs.yaml        # Validate specific file
    yavs config validate ~/.yavs/config.yaml

Checks for:
- YAML syntax errors
- Invalid settings (wrong types, invalid values)
- Unknown scanner names
- Invalid severity mappings
- Out-of-range temperature values

Provides warnings for:
- Missing optional sections
- Deprecated settings

#### config show
Display current YAVS configuration.

    yavs config show                    # Show all config
    yavs config show --section ai       # Show only AI section
    yavs config show --section scanners # Show scanner config
    yavs config show --config yavs.yaml # Show specific file

Shows the effective configuration (defaults merged with file settings).
Useful for debugging and understanding current settings.

**Available sections:**
- `scan` - Scan directories and ignore patterns
- `metadata` - Project metadata
- `scanners` - Scanner configuration
- `output` - Output file paths
- `ai` - AI features
- `severity_mapping` - Severity normalization
- `logging` - Logging configuration

#### config path
Show configuration file search paths.

    yavs config path

Displays where YAVS looks for config files and their priority order:
1. `yavs.yaml` (current directory) - Highest priority
2. `config.yaml` (current directory)
3. `~/.yavs/config.yaml` (global config)
4. Built-in defaults - Always available fallback

**Override:** Use `--config` flag on scan command to specify exact file.

#### config edit
Open configuration file in your default editor.

    yavs config edit                # Edit auto-detected config
    yavs config edit yavs.yaml      # Edit specific file

Uses `$EDITOR` environment variable, or searches for: nano, vim, vi, emacs, code.
If config doesn't exist, prompts to create it with `config init`.

### Configuration File Format

YAVS uses YAML configuration with the following sections:

**scan:**
```yaml
scan:
  directories:
    - "."
  ignore_paths:
    - "node_modules/"
    - ".venv/"
```

**scanners:**
```yaml
scanners:
  trivy:
    enabled: true
    timeout: 300
    flags: ""  # Additional CLI flags
  semgrep:
    enabled: true
    timeout: 300
```

**ai:**
```yaml
ai:
  enabled: true
  provider: "anthropic"  # or "openai"
  model: null  # Use provider default
  features:
    fix_suggestions: true
    summarize: true
    triage: true
```

**output:**
```yaml
output:
  directory: "."
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"
```

### Configuration Precedence

YAVS merges configuration in this order (later overrides earlier):
1. Built-in defaults
2. Global config (`~/.yavs/config.yaml`)
3. Local config (`yavs.yaml` or `config.yaml`)
4. Command-line flags (highest priority)

## version
Show YAVS version information.

    yavs version

## man
Show detailed documentation.

    yavs man [SECTION]

### Sections
    quickstart    Quick start guide
    commands      This command reference
    config        Configuration file format
    examples      Usage examples
    ci            CI/CD integration guide
    ai            AI features documentation
    scanners      Scanner details
    all           Complete manual (paginated)

# Makefile Commands

For development and automation, YAVS includes a comprehensive Makefile with 37 commands.

## Tool Management

### verify-tools
Check versions of all installed scanner tools.

    make verify-tools

Shows versions of: Trivy, Semgrep, Bandit, Checkov, BinSkim

### update-tools
Update all scanner tools to their latest versions.

    make update-tools

Updates: Semgrep, Bandit, Checkov (via pip)
Note: Trivy must be updated via system package manager

### pin-tools
Create requirements-scanners.txt with current tool versions.

    make pin-tools

Generates a requirements file for reproducible builds. Commit this file to lock
scanner versions across your team and CI/CD environments.

## Installation & Setup

    make install          # Install YAVS in development mode
    make install-dev      # Install with dev dependencies (pytest, black, ruff)
    make setup            # Install scanner dependencies

## Development Tools

### Code Quality
    make lint             # Run ruff linter on src/ and tests/
    make format           # Auto-format code with black
    make format-check     # Check formatting without making changes

### Build & Release
    make build            # Build wheel and source distribution
    make build-check      # Build and verify package contents
    make upload-test      # Upload to Test PyPI
    make upload           # Upload to production PyPI (with confirmation)

## Scanning Commands

    make scan             # Quick scan (no AI)
    make scan-ai          # Scan with AI features
    make scan-images      # Scan Docker images
    make scan-all-fixtures # Comprehensive scan of test fixtures
    make scan-multi-dir   # Test multi-directory scanning

## Testing

    make test             # Run pytest test suite
    make test-all         # All tests (pytest + combinations)
    make test-coverage    # Run with coverage report
    make test-combinations # Run 41 combination scenarios

## Cleanup

    make clean            # Clean build artifacts and temp files
    make clean-all        # Clean everything (build + artifacts + results)
    make clean-artifacts  # Remove scan results only

## Common Workflows

### Development Setup
    make install-dev
    make setup
    make verify-tools

### Pre-Release Workflow
    make clean-all
    make format
    make lint
    make test-all
    make build-check
    make upload-test

### Update Scanner Tools
    make verify-tools     # Check current versions
    make update-tools     # Update to latest
    make pin-tools        # Pin new versions
    make test-all         # Verify everything works

Run `make help` to see all available commands.
""",

        "config": """
# Configuration File

YAVS uses a YAML configuration file (default: config.yaml in current directory).

## File Structure

```yaml
scan:
  directories: ["."]
  ignore_paths:
    - "node_modules/"
    - "vendor/"
    - "\\\\.git/"
    - "dist/"
    - "build/"

metadata:
  project: null      # Auto-detect from directory name
  branch: null       # Auto-detect from git
  commit_hash: null  # Auto-detect from git

scanners:
  trivy:
    enabled: true
    timeout: 300
    flags: ""                    # Additional CLI flags
    native_config: null          # Path to trivy.yaml

  semgrep:
    enabled: true
    timeout: 300
    flags: ""
    native_config: null          # Path to .semgrep.yml

  bandit:
    enabled: true
    timeout: 300
    flags: ""
    native_config: null          # Path to .bandit

  binskim:
    enabled: true
    timeout: 300
    flags: ""
    native_config: null

  checkov:
    enabled: true
    timeout: 300
    flags: ""
    native_config: null          # Path to .checkov.yaml

output:
  directory: "."
  json: "yavs-results.json"
  sarif: "yavs-results.sarif"
  structured: true               # Use structured format
  per_tool_files: false          # Generate per-tool files

ai:
  enabled: true
  provider: null                 # anthropic or openai (auto-detect)
  model: null                    # Provider-specific model
  max_tokens: 4096
  temperature: 0.0

  features:
    fix_suggestions: true
    summarize: true
    triage: true

  max_fixes_per_scan: 50
  parallel_requests: 5

  rate_limits:
    anthropic:
      requests_per_minute: 50
      tokens_per_minute: 40000
    openai:
      requests_per_minute: 500
      tokens_per_minute: 30000

  summary:
    output_file: "yavs-ai-summary.json"
    enrich_scan_results: false

severity_mapping:
  ERROR: "HIGH"
  WARNING: "MEDIUM"
  error: "HIGH"
  warning: "MEDIUM"
  note: "LOW"
  none: "INFO"

logging:
  level: "INFO"
  format: "rich"                 # or "json"
  file:
    enabled: false
    path: "yavs.log"
    max_bytes: 10485760
    backup_count: 3
```

## Loading Custom Config
    yavs scan --config /path/to/config.yaml --all

## Configuration Precedence
    CLI arguments > Config file > Defaults
""",

        "examples": """
# Usage Examples

## Basic Scanning

### Scan current directory
    yavs scan --all

### Scan specific directory
    yavs scan /path/to/code --all

### Scan multiple directories
    yavs scan ./src ./lib ./tests --all

### Scan with specific scanners
    yavs scan --sast --sbom
    yavs scan --compliance
    yavs scan --sbom  # Dependencies only

## Docker Image Scanning

### Single image
    yavs scan --images nginx:latest --sbom

### Multiple images
    yavs scan --images nginx:latest --images python:3.11 --sbom

### Images from file
    cat > images.txt <<EOF
    nginx:latest
    python:3.11
    redis:7
    EOF
    yavs scan --images-file images.txt --sbom

### Mixed filesystem + images
    yavs scan . --all --images nginx:latest

## Filtering and Ignoring

### Ignore patterns
    yavs scan --all --ignore "node_modules/" --ignore "vendor/"

### Multiple patterns
    yavs scan --all \\
      --ignore "test/" \\
      --ignore ".*\\\\.min\\\\.js$" \\
      --ignore "__pycache__/"

### Severity filtering
    yavs scan --all --severity CRITICAL,HIGH

## Baseline Workflow

### Initial baseline
    yavs scan --all --baseline-generate baseline.json

### Compare against baseline
    yavs scan --all --baseline baseline.json

### Show only new findings
    yavs scan --all --baseline baseline.json --quiet

### Diff two scans
    yavs diff baseline.json current.json
    yavs diff baseline.json current.json --show-all

## CI/CD Integration

### Fail on HIGH+ findings
    yavs scan --all --fail-on HIGH || exit 1

### Quiet mode for CI
    yavs scan --all --fail-on HIGH --quiet

### With timeout
    yavs scan --all --timeout 600 --fail-on CRITICAL

### Continue on error
    yavs scan --all --continue-on-error --fail-on HIGH

## Complete Workflow

### 1. Full scan
    yavs scan --all --output-dir ./security-scan

### 2. Generate AI summary
    yavs summarize ./security-scan/yavs-results.json

### 3. Create HTML report
    yavs report ./security-scan/yavs-results.json \\
                --summary ./security-scan/yavs-ai-summary.json \\
                -o ./security-scan/report.html

### 4. View results
    open ./security-scan/report.html

## Custom Output

### Flat format
    yavs scan --all --flat

### Per-tool files
    yavs scan --all --per-tool-files

### Custom paths
    yavs scan --all \\
      --json ./custom/scan.json \\
      --sarif ./custom/scan.sarif \\
      --sbom-output ./custom/sbom.json \\
      --output-dir ./custom

## Advanced Usage

### With custom config
    yavs scan --config my-config.yaml --all

### Disable AI
    yavs scan --all --no-ai

### Skip SARIF validation
    yavs scan --all --no-validate

### Custom metadata
    yavs scan --all \\
      --project my-app \\
      --branch feature/security \\
      --commit-hash abc123
""",

        "ci": """
# CI/CD Integration Guide

## GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install YAVS
        run: pip install yavs

      - name: Install Scanners
        run: yavs tools install

      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          yavs scan --all --fail-on HIGH --quiet
          yavs summarize yavs-results.json
          yavs report yavs-results.json

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            yavs-results.json
            yavs-results.sarif
            yavs-report.html
            yavs-ai-summary.json

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: yavs-results.sarif
```

## GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install yavs
    - yavs tools install
  script:
    - yavs scan --all --fail-on HIGH --quiet
    - yavs summarize yavs-results.json
    - yavs report yavs-results.json
  artifacts:
    when: always
    paths:
      - yavs-results.json
      - yavs-results.sarif
      - yavs-report.html
      - yavs-ai-summary.json
    reports:
      sast: yavs-results.sarif
```

## Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install yavs'
                sh 'yavs tools install'
            }
        }

        stage('Security Scan') {
            steps {
                sh 'yavs scan --all --fail-on HIGH'
                sh 'yavs summarize yavs-results.json'
                sh 'yavs report yavs-results.json'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json,*.html,*.sarif',
                           allowEmptyArchive: true
            publishHTML([
                reportName: 'Security Report',
                reportDir: '.',
                reportFiles: 'yavs-report.html'
            ])
        }
    }
}
```

## CircleCI

```yaml
version: 2.1

jobs:
  security_scan:
    docker:
      - image: python:3.11
    steps:
      - checkout
      - run:
          name: Install YAVS
          command: pip install yavs
      - run:
          name: Install Scanners
          command: yavs tools install
      - run:
          name: Run Scan
          command: |
            yavs scan --all --fail-on HIGH --quiet
            yavs summarize yavs-results.json
            yavs report yavs-results.json
      - store_artifacts:
          path: yavs-results.json
      - store_artifacts:
          path: yavs-report.html
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'

- script: |
    pip install yavs
    yavs tools install
  displayName: 'Install YAVS'

- script: |
    yavs scan --all --fail-on HIGH
    yavs summarize yavs-results.json
    yavs report yavs-results.json
  displayName: 'Security Scan'
  env:
    ANTHROPIC_API_KEY: $(ANTHROPIC_API_KEY)

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.SourcesDirectory)'
    artifactName: 'security-reports'
  condition: always()
```

## Baseline Tracking in CI

### First Run (Create Baseline)
```bash
yavs scan --all --baseline-generate baseline.json
git add baseline.json
git commit -m "Add security baseline"
```

### Subsequent Runs (Compare)
```bash
yavs scan --all --baseline baseline.json --fail-on HIGH
```

## Exit Codes

    0 - Success, no issues or below threshold
    1 - Findings at or above --fail-on threshold
    2 - Error during execution

## Best Practices

1. **Start with baseline**: Generate baseline on clean build
2. **Use --fail-on**: Set appropriate severity threshold
3. **Store baselines in git**: Track security posture over time
4. **Upload artifacts**: Keep scan results for analysis
5. **Use --quiet in CI**: Reduce log noise
6. **Set timeouts**: Prevent hanging builds
7. **Upload SARIF**: Integrate with code scanning tools
8. **Generate HTML reports**: For human review
""",

        "ai": """
# AI Features Documentation

## Overview
When configured with API keys, YAVS provides AI-powered analysis:
- Fix suggestions for each finding
- Executive summaries
- Intelligent triage and clustering

## Setup

### Anthropic (Claude)
    export ANTHROPIC_API_KEY=sk-ant-...
    yavs scan --all
    yavs summarize yavs-results.json

### OpenAI (GPT)
    export OPENAI_API_KEY=sk-...
    yavs scan --all
    yavs summarize yavs-results.json --provider openai

## Fix Suggestions
AI generates actionable remediation guidance:

### What You Get
- **What**: Clear description of the vulnerability
- **Why**: Security impact and risk assessment
- **How**: Step-by-step fix instructions
- **Code**: Example secure code snippets
- **Prevention**: Best practices to avoid similar issues

### Example
```json
{
  "ai_fix": {
    "what": "SQL injection vulnerability in user input",
    "why": "Allows attackers to manipulate database queries",
    "how": [
      "1. Use parameterized queries",
      "2. Validate and sanitize input",
      "3. Use ORM frameworks"
    ],
    "code_example": "query = 'SELECT * FROM users WHERE id = ?'\\ncursor.execute(query, (user_id,))",
    "prevention": "Always use parameterized queries for database operations"
  }
}
```

## Executive Summary
High-level security posture analysis:

### Contents
- Key findings overview
- Risk assessment
- Severity distribution
- Recommended priorities
- Trend analysis (with baselines)

### Generation
    yavs summarize yavs-results.json

### Output
    {
      "executive_summary": "Found 12 security issues...",
      "findings_count": 12,
      "ai_provider": "anthropic",
      "ai_model": "claude-sonnet-4-5-20250929"
    }

## Triage & Clustering
Intelligent grouping of related findings:

### Features
- Groups similar issues together
- Identifies root cause patterns
- Prioritizes by severity and exploitability
- Reduces noise in large scans

### Example Output
```json
{
  "triage": {
    "clusters": [
      {
        "name": "SQL Injection Vulnerabilities",
        "count": 5,
        "severity": "HIGH",
        "findings": [0, 3, 7, 12, 15],
        "ai_analysis": "All related to unsanitized user input"
      }
    ]
  }
}
```

## Configuration

### In config.yaml
```yaml
ai:
  enabled: true
  provider: anthropic  # or openai
  model: claude-sonnet-4-5-20250929

  features:
    fix_suggestions: true
    summarize: true
    triage: true

  max_fixes_per_scan: 50
  parallel_requests: 5

  rate_limits:
    anthropic:
      requests_per_minute: 50
      tokens_per_minute: 40000
```

### Rate Limiting
YAVS automatically respects API rate limits:
- Queues requests when limit approached
- Retries with exponential backoff
- Configurable per provider

## Disabling AI
    yavs scan --all --no-ai
    yavs scan --all  # Without API keys

## Best Practices

1. **Use for important scans**: AI analysis adds time
2. **Review suggestions**: AI is helpful but not infallible
3. **Set max_fixes**: Limit parallel API calls
4. **Cache results**: Summarize once, reuse report
5. **Monitor costs**: AI API calls have usage costs

## Models

### Anthropic (Recommended)
- claude-sonnet-4-5-20250929 (default, best)
- claude-3-5-sonnet-20241022 (fast, good)
- claude-3-opus-20240229 (most capable)

### OpenAI
- gpt-4o (default, best)
- gpt-4-turbo (fast, good)
- gpt-4 (capable)

## Costs
Typical scan with 50 findings:
- Fix suggestions: ~$0.10-0.50
- Summary: ~$0.05-0.15
- Triage: ~$0.10-0.30
- Total: ~$0.25-1.00

Costs vary by:
- Number of findings
- Model selected
- Finding complexity
- Provider pricing
""",

        "scanners": """
# Scanner Details

## Trivy
**Purpose**: Dependency scanning and SBOM generation

### What it Scans
- Dependencies in all major languages
- Container images
- Filesystem vulnerabilities
- Secrets and credentials
- License compliance
- Configuration issues

### Supported Languages
Python, JavaScript/Node.js, Go, Rust, Java, Ruby, PHP, .NET, and more

### SBOM Format
CycloneDX JSON

### Configuration
```yaml
scanners:
  trivy:
    enabled: true
    timeout: 300
    flags: "--severity HIGH,CRITICAL"
    native_config: "config/trivy.yaml"
```

### Example Output
```json
{
  "tool": "Trivy",
  "severity": "HIGH",
  "rule_id": "CVE-2021-44228",
  "package": "log4j-core",
  "version": "2.14.0",
  "fixed_version": "2.17.1"
}
```

## Semgrep
**Purpose**: Multi-language SAST (Static Application Security Testing)

### Supported Languages
Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, Kotlin, Scala, and 20+ more

### Rules
- OWASP Top 10
- CWE coverage
- Framework-specific rules
- Custom rule support

### Configuration
```yaml
scanners:
  semgrep:
    enabled: true
    timeout: 300
    flags: "--config=p/owasp-top-10"
    native_config: ".semgrep.yml"
```

### Detects
- SQL injection
- XSS vulnerabilities
- Command injection
- Path traversal
- Insecure deserialization
- And many more

## Bandit
**Purpose**: Python-focused security scanner

### Specialization
Deep Python security analysis complementing Semgrep

### Detects
- Hardcoded secrets
- SQL injection
- Command injection
- Insecure cryptography
- Assert statements in production
- Dangerous imports

### Configuration
```yaml
scanners:
  bandit:
    enabled: true
    timeout: 300
    flags: "--severity-level high"
    native_config: ".bandit"
```

### Example Output
```json
{
  "tool": "Bandit",
  "rule_id": "B105",
  "severity": "HIGH",
  "file": "app.py",
  "line": 42,
  "message": "Possible hardcoded password"
}
```

## BinSkim
**Purpose**: Binary security analysis

### Supported Formats
- PE (Windows executables)
- ELF (Linux binaries)

### Analyzes
- Compiler security flags
- Stack protection
- DEP/ASLR configuration
- Signature verification
- Library versions
- Security features

### Configuration
```yaml
scanners:
  binskim:
    enabled: true
    timeout: 300
    flags: ""
    native_config: ".gdnconfig"
```

### Use Cases
- Analyzing compiled applications
- Verifying build security
- Supply chain validation

## Checkov
**Purpose**: Infrastructure as Code (IaC) and compliance scanning

### Supported Formats
- Terraform
- Kubernetes manifests
- Docker/Dockerfiles
- CloudFormation
- Azure ARM templates
- Helm charts
- Ansible

### Detects
- Insecure configurations
- CIS benchmark violations
- Cloud security best practices
- Compliance issues

### Configuration
```yaml
scanners:
  checkov:
    enabled: true
    timeout: 300
    flags: "--framework terraform kubernetes"
    native_config: ".checkov.yaml"
```

### Example Checks
- Open security groups
- Unencrypted storage
- Missing logging
- Weak password policies
- Public S3 buckets

## Scanner Selection

### Use All (--all)
Comprehensive security coverage across all vectors

### Use --sbom
Dependency scanning only (fast, for dependency checks)

### Use --sast
Source code analysis only (for code review)

### Use --compliance
Infrastructure/config only (for IaC pipelines)

## Performance Tips

1. **Use specific scanners**: Faster than --all
2. **Set timeouts**: Prevent hangs on large codebases
3. **Use ignore patterns**: Skip generated/vendor code
4. **Per-tool files**: Parallel analysis of results
5. **Native configs**: Fine-tune scanner behavior
"""
    }


def display_statistics(stats: dict):
    """Display scan statistics in a table."""
    table = Table(title="Scan Results Summary", show_header=True, header_style="bold magenta")

    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="green")

    # Total
    table.add_row("Total Findings", str(stats["total"]))
    table.add_section()

    # By severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats["by_severity"].get(severity, 0)
        if count > 0:
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "white"
            }.get(severity, "white")
            table.add_row(f"  {severity}", f"[{color}]{count}[/{color}]")

    table.add_section()

    # By category
    for category, count in stats["by_category"].items():
        table.add_row(f"  {category.title()}", str(count))

    console.print()
    console.print(table)


def main():
    """
    Main entry point for YAVS CLI.
    Shows banner before displaying help or running commands.
    """
    import sys

    # Check if help is requested or no arguments provided
    args = sys.argv[1:]
    if not args or '--help' in args or '-h' in args:
        print_banner(f"v{__version__} - Yet Another Vulnerability Scanner")
        console.print()  # Add spacing

    app()


if __name__ == "__main__":
    main()
