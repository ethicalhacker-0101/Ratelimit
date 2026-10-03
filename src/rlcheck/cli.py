"""RLCheck Pro — CLI interface built with Click.

Commands
--------
- ``auth``   : Full authentication-flow assessment (login → OTP → analysis)
- ``login``  : Login-only rate-limit test
- ``otp``    : OTP-only rate-limit test
- ``web``    : Launch local web dashboard
- ``report`` : Re-render / convert a saved JSON report
- ``version``: Print version string
"""
from __future__ import annotations

import sys

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rlcheck import __version__, __tool_name__
from rlcheck.engine.safety import SafetyConfig, validate_safety

console = Console()

# ── Shared options ──────────────────────────────────────────────────────────

_common_options = [
    click.option("--user", "-u", default=None, help="Username / email for login form."),
    click.option("--password", "-p", default=None, help="Password for login form (test credential)."),
    click.option("--test-otp", default="000000", show_default=True,
                 help="Deliberately invalid OTP value for controlled testing."),
    click.option("--attempts", "-a", default=10, show_default=True, type=int,
                 help="Maximum invalid-OTP / login attempts per stage."),
    click.option("--interval", "-i", default=2.0, show_default=True, type=float,
                 help="Minimum seconds between requests."),
    click.option("--timeout", default=15, show_default=True, type=int,
                 help="HTTP request timeout in seconds."),
    click.option("--format", "report_format", default="all",
                 type=click.Choice(["json", "html", "all", "none"], case_sensitive=False),
                 show_default=True, help="Report output format."),
    click.option("--output", "-o", default="reports", show_default=True,
                 help="Directory for saved reports."),
    click.option("--insecure", is_flag=True, default=False,
                 help="Allow insecure TLS (skip certificate verification)."),
    click.option("--yes", "-y", is_flag=True, default=False,
                 help="Skip interactive confirmation prompt."),
    click.option("--verbose", "-v", is_flag=True, default=False,
                 help="Enable verbose / debug output."),
]


def _add_options(options):
    """Decorator that applies a list of Click options to a command."""
    def wrapper(func):
        for opt in reversed(options):
            func = opt(func)
        return func
    return wrapper


def _banner():
    """Print the RLCheck Pro banner."""
    title = Text(__tool_name__, style="bold bright_cyan")
    subtitle = Text(f"v{__version__}  —  Real-Time Authentication & OTP Security Assessment",
                    style="dim")
    panel = Panel(
        Text.assemble(title, "\n", subtitle),
        border_style="bright_cyan",
        padding=(1, 2),
    )
    console.print(panel)


def _authorization_warning(auto_confirm: bool) -> bool:
    """Display the authorization warning and return True if the user confirms."""
    console.print()
    console.print("[bold yellow]⚠  AUTHORIZED SECURITY TESTING ONLY[/bold yellow]")
    console.print("[dim]Controlled request mode enabled — low-volume, non-destructive testing.[/dim]")
    console.print()
    if auto_confirm:
        console.print("[dim]Auto-confirmed via --yes flag.[/dim]")
        return True
    return click.confirm("Do you have explicit authorization to test this target?", default=False)


# ── CLI group ───────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """RLCheck Pro — Real-Time Authentication & OTP Security Assessment Tool."""
    if ctx.invoked_subcommand is None:
        _banner()
        click.echo(ctx.get_help())


# ── auth command ────────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@_add_options(_common_options)
def auth(url, user, password, test_otp, attempts, interval, timeout,
         report_format, output, insecure, yes, verbose):
    """Full authentication-flow assessment (login → OTP → analysis)."""
    _banner()

    safety = SafetyConfig(
        max_attempts=attempts,
        min_interval=interval,
        timeout=timeout,
    )
    ok, msg = validate_safety(safety)
    if not ok:
        console.print(f"[bold red]Safety check failed:[/bold red] {msg}")
        sys.exit(1)

    if not _authorization_warning(yes):
        console.print("[yellow]Aborted — authorization not confirmed.[/yellow]")
        sys.exit(0)

    # Lazy import to keep CLI startup fast
    from rlcheck.engine.auth_flow import run_full_assessment
    run_full_assessment(
        url=url,
        user=user,
        password=password,
        test_otp=test_otp,
        safety=safety,
        report_format=report_format,
        output_dir=output,
        insecure=insecure,
        verbose=verbose,
    )


# ── login command ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@_add_options(_common_options)
def login(url, user, password, test_otp, attempts, interval, timeout,
          report_format, output, insecure, yes, verbose):
    """Login-only rate-limit assessment."""
    _banner()

    safety = SafetyConfig(
        max_attempts=attempts,
        min_interval=interval,
        timeout=timeout,
    )
    ok, msg = validate_safety(safety)
    if not ok:
        console.print(f"[bold red]Safety check failed:[/bold red] {msg}")
        sys.exit(1)

    if not _authorization_warning(yes):
        console.print("[yellow]Aborted — authorization not confirmed.[/yellow]")
        sys.exit(0)

    from rlcheck.engine.auth_flow import run_login_assessment
    run_login_assessment(
        url=url,
        user=user,
        password=password,
        safety=safety,
        report_format=report_format,
        output_dir=output,
        insecure=insecure,
        verbose=verbose,
    )


# ── otp command ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@_add_options(_common_options)
def otp(url, user, password, test_otp, attempts, interval, timeout,
        report_format, output, insecure, yes, verbose):
    """OTP-only rate-limit assessment."""
    _banner()

    safety = SafetyConfig(
        max_attempts=attempts,
        min_interval=interval,
        timeout=timeout,
    )
    ok, msg = validate_safety(safety)
    if not ok:
        console.print(f"[bold red]Safety check failed:[/bold red] {msg}")
        sys.exit(1)

    if not _authorization_warning(yes):
        console.print("[yellow]Aborted — authorization not confirmed.[/yellow]")
        sys.exit(0)

    from rlcheck.engine.auth_flow import run_otp_assessment
    run_otp_assessment(
        url=url,
        user=user,
        password=password,
        test_otp=test_otp,
        safety=safety,
        report_format=report_format,
        output_dir=output,
        insecure=insecure,
        verbose=verbose,
    )


# ── web command ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address (only localhost for safety).")
@click.option("--port", default=8080, show_default=True, type=int,
              help="Port for the web dashboard.")
def web(host, port):
    """Launch the local web dashboard."""
    _banner()
    if host != "127.0.0.1":
        console.print("[bold red]Safety restriction:[/bold red] The web interface "
                      "must bind to 127.0.0.1 only.")
        sys.exit(1)
    from rlcheck.web.app import create_app
    app = create_app()
    console.print(f"[bold green]Starting web dashboard at http://{host}:{port}[/bold green]")
    app.run(host=host, port=port, debug=False)


# ── report command ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "report_format", default="html",
              type=click.Choice(["json", "html"], case_sensitive=False),
              show_default=True, help="Output format to convert to.")
def report(file, report_format):
    """Re-render or convert a saved JSON report."""
    _banner()
    from rlcheck.reporters.json import load_report
    from rlcheck.reporters.html import render_html_report
    import json

    data = load_report(file)
    if report_format == "html":
        out = render_html_report(data)
        out_path = file.replace(".json", ".html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(out)
        console.print(f"[green]HTML report written to {out_path}[/green]")
    else:
        console.print(json.dumps(data, indent=2))


# ── version command ─────────────────────────────────────────────────────────

@cli.command()
def version():
    """Print version information."""
    console.print(f"{__tool_name__} v{__version__}")
