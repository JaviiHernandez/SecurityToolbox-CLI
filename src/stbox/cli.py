"""Command-line interface for SecurityToolbox CLI.

Usage:
    stbox scan https://example.com
    stbox scan https://example.com --mode standard --out report.html
    stbox scan https://example.com --mode active --i-have-permission \\
        --out report.html --json results.json
    stbox doctor                # check which binaries are available
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows consoles so Rich glyphs (✓ ✗ │ ─) render without
# UnicodeEncodeError on the default cp1252 codepage.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from stbox import __version__
from stbox.config import TOOL_BINARIES, Config, which
from stbox.models import Mode
from stbox.orchestrator import run_scan
from stbox.report.html import render_html
from stbox.report.json_ import render_json
from stbox.report.markdown import render_markdown
from stbox.scope import ScopeError


app = typer.Typer(
    name="stbox",
    help="SecurityToolbox CLI — orchestrates pentest tooling into a unified report.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="URL or hostname to scan"),
    mode: Mode = typer.Option(
        Mode.PASSIVE,
        "--mode", "-m",
        help="Scan aggressiveness: passive (default), standard, or active",
        case_sensitive=False,
    ),
    out: Path = typer.Option(
        Path("report.html"), "--out", "-o",
        help="HTML report output path",
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", help="Optional JSON export path",
    ),
    md_out: Optional[Path] = typer.Option(
        None, "--md", help="Optional Markdown export path",
    ),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Required for --mode active. Confirms written authorization.",
    ),
    allow_internal: bool = typer.Option(
        False, "--allow-internal",
        help="Allow scanning RFC1918 / loopback addresses (your own lab only).",
    ),
    workdir: Path = typer.Option(
        Path("stbox-runs"), "--workdir",
        help="Where to dump raw tool stdout/stderr for forensic review",
    ),
    timeout: int = typer.Option(
        300, "--timeout", help="Per-tool timeout in seconds",
    ),
    rate_limit: float = typer.Option(
        10.0, "--rate-limit", help="Requests per second for our own probes",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a full scan. Default mode is `passive` — no payloads, no bruteforce."""
    _setup_logging(verbose)

    cfg = Config.from_env()
    cfg.workdir = workdir
    cfg.tool_timeout = timeout
    cfg.rate_limit_rps = rate_limit

    console.print(f"[bold cyan]stbox {__version__}[/] scanning [bold]{target}[/] in [yellow]{mode.value}[/] mode")

    try:
        result = asyncio.run(
            run_scan(
                target, mode, cfg,
                allow_internal=allow_internal,
                permission_ack=i_have_permission,
                console=console,
            )
        )
    except ScopeError as e:
        console.print(f"[bold red]scope error:[/] {e}")
        raise typer.Exit(code=2) from e
    except PermissionError as e:
        console.print(f"[bold red]{e}[/]")
        raise typer.Exit(code=3) from e

    # Summary table
    table = Table(title="Findings summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev, count in result.counts_by_severity().items():
        if count == 0:
            continue
        style = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "green",
            "info": "cyan",
        }.get(sev, "white")
        table.add_row(f"[{style}]{sev.upper()}[/]", str(count))
    console.print(table)

    # Write outputs
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(result), encoding="utf-8")
    console.print(f"[green]✓[/] HTML report: [bold]{out}[/]")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(render_json(result), encoding="utf-8")
        console.print(f"[green]✓[/] JSON report: [bold]{json_out}[/]")

    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(render_markdown(result), encoding="utf-8")
        console.print(f"[green]✓[/] Markdown report: [bold]{md_out}[/]")


@app.command()
def doctor() -> None:
    """Check which external tools are available on $PATH."""
    table = Table(title="External tool availability", show_header=True)
    table.add_column("Tool")
    table.add_column("Path")
    table.add_column("Status", style="bold")

    missing = 0
    for name, binary in TOOL_BINARIES.items():
        path = which(binary)
        if path:
            table.add_row(name, path, "[green]✓ available[/]")
        else:
            missing += 1
            table.add_row(name, "-", "[red]✗ missing[/]")

    console.print(table)
    if missing:
        console.print(
            f"\n[yellow]{missing} tools missing.[/] "
            "Install with [bold]./install-linux.sh[/] or "
            "[bold]powershell -File install-windows.ps1[/], "
            "or use the Docker image."
        )
    else:
        console.print("\n[green]All external tools are available.[/]")


@app.command()
def version() -> None:
    """Print version and exit."""
    console.print(f"stbox {__version__}")


if __name__ == "__main__":
    app()
