"""Command-line interface for Numsec."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import metadata
from pathlib import Path

import click

from . import __version__
from .analyze import AnalysisResult, analyze_project, redact
from .deps import DependencyReport, scan_dependencies
from .detect import Severity, scan_project
from .exceptions import NetworkError, NumsecError, PluginError
from .plugins import ENTRY_POINT_GROUP, iter_plugin_entry_points, load_plugin_rules, resolve_rules
from .templates import get_available_templates, init_project
from .utils import ensure_python_version

ASCII_BANNER = """
███╗   ██╗██╗   ██╗███╗   ███╗███████╗███████╗ ██████╗
████╗  ██║██║   ██║████╗ ████║██╔════╝██╔════╝██╔════╝
██╔██╗ ██║██║   ██║██╔████╔██║███████╗█████╗  ██║
██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║██╔══╝  ██║
██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████║███████╗╚██████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝
"""

ensure_python_version((3, 11))

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}

SEVERITY_CHOICES = click.Choice([severity.value for severity in Severity], case_sensitive=False)

EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_NETWORK = 3

_SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _resolved_version() -> str:
    """Prefer the installed distribution version, fall back to the source tree."""
    try:
        return metadata.version("numsec")
    except metadata.PackageNotFoundError:
        return __version__


def _print_version(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"Numsec v{_resolved_version()}")
    ctx.exit()


def _silence_stdout() -> None:
    """Point stdout at /dev/null so the interpreter's final flush stays quiet.

    ``numsec lint | head`` closes the pipe early. That is normal Unix behaviour, not
    an error, but Python raises BrokenPipeError on the next write and then complains
    again while flushing at exit.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):  # pragma: no cover - in-memory streams in tests
        pass


@contextmanager
def _errors(ctx: click.Context) -> Iterator[None]:
    """Translate internal errors into exit codes, but never swallow click aborts.

    ``click.Abort`` is a ``RuntimeError``: a bare ``except Exception`` around a
    command turns "user said no" into an internal error message, which is exactly
    the bug this replaces.
    """
    try:
        yield
    except (click.Abort, click.UsageError, click.exceptions.Exit):
        raise
    except BrokenPipeError:
        _silence_stdout()
        ctx.exit(1)
    except NetworkError as exc:
        click.secho(f"Network error: {exc}", fg="red", err=True)
        ctx.exit(EXIT_NETWORK)
    except NumsecError as exc:
        message = str(exc)
        if ctx.obj and ctx.obj.get("VERBOSE"):
            import traceback

            message = f"{message}\n{traceback.format_exc()}"
        click.secho(f"Error: {message}", fg="red", err=True)
        ctx.exit(EXIT_ERROR)
    except Exception as exc:
        message = str(exc)
        if ctx.obj and ctx.obj.get("VERBOSE"):
            import traceback

            message = f"{message}\n{traceback.format_exc()}"
        click.secho(f"Error: {message}", fg="red", err=True)
        ctx.exit(EXIT_ERROR)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--version",
    is_flag=True,
    callback=_print_version,
    expose_value=False,
    is_eager=True,
    help="Show version and exit.",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Automated STRIDE threat modeling for Python projects."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose


@cli.command()
@click.argument("project_name")
@click.option(
    "--template",
    "template_name",
    default="basic",
    show_default=True,
    help="Project template to use.",
)
@click.option("--force", is_flag=True, help="Continue even if the directory is not empty.")
@click.option("--no-git", is_flag=True, help="Do not run 'git init' in the new project.")
@click.pass_context
def init(
    ctx: click.Context,
    project_name: str,
    template_name: str,
    force: bool,
    no_git: bool,
) -> None:
    """Initialize a new security project from a template."""
    with _errors(ctx):
        project_path = Path(project_name).expanduser().resolve()

        if project_path.exists() and any(project_path.iterdir()) and not force:
            click.confirm(
                f"Directory '{project_name}' is not empty. Continue?",
                abort=True,
            )

        init_project(project_path, template_name, run_git=not no_git)
        click.echo(ASCII_BANNER)
        click.secho(f"✓ Created project at {project_path}", fg="green")
        click.echo("  Next: cd into it and run 'numsec analyze'")


@cli.command("list-templates")
def list_templates() -> None:
    """List all available project templates."""
    templates = get_available_templates()
    if not templates:
        click.secho("No templates available.", fg="yellow")
        return

    click.echo("Available templates:")
    for template in templates:
        click.echo(f"  - {template}")


def _echo_analysis(result: AnalysisResult) -> None:
    findings = len(result.scan.findings)
    click.secho(
        f"✓ Scanned {result.scan.files_scanned} Python file(s): "
        f"{findings} finding(s) in {len(result.threats)} threat(s)",
        fg="green",
    )

    if result.threats:
        click.echo(f"  Written to {result.threats_dir}")
        for threat in result.threats:
            color = _SEVERITY_COLORS[threat.severity]
            click.echo(
                f"  {threat.threat_id}  "
                + click.style(f"{threat.severity.value.upper():<8}", fg=color)
                + f" {threat.title} ({len(threat.occurrences)} occurrence(s))"
            )
    else:
        click.echo("  No findings: nothing was written.")

    if result.removed:
        click.echo(f"  Refreshed: {len(result.removed)} previously generated threat(s)")
    for kept in result.preserved:
        click.secho(f"  Kept (not generated by numsec): {kept}", fg="yellow")

    if result.scan.findings:
        click.secho(
            "  Treat findings as leads: confirm each one before opening a change.", fg="cyan"
        )


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--ai-format", is_flag=True, help="Emit machine-readable JSON for IDE assistants.")
@click.option(
    "--fail-on",
    type=SEVERITY_CHOICES,
    default=None,
    metavar="LEVEL",
    help="Exit 1 when a finding at LEVEL or above is found (low|medium|high|critical).",
)
@click.pass_context
def analyze(ctx: click.Context, path: Path, ai_format: bool, fail_on: str | None) -> None:
    """Scan a project and write numsec/threats/THREAT-*/threat.md."""
    with _errors(ctx):
        result = analyze_project(path, rules=resolve_rules())

        if ai_format:
            click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            _echo_analysis(result)

        if fail_on is not None and result.scan.exceeds(Severity(fail_on.lower())):
            ctx.exit(EXIT_FINDINGS)


@cli.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON.")
@click.option(
    "--fail-on",
    type=SEVERITY_CHOICES,
    default=None,
    metavar="LEVEL",
    help="Exit 1 when a finding at LEVEL or above is found.",
)
@click.option("--max-items", type=click.IntRange(1, 1000), default=100, show_default=True)
@click.pass_context
def lint(
    ctx: click.Context, path: Path, as_json: bool, fail_on: str | None, max_items: int
) -> None:
    """Report findings to stdout; writes no files (safe for CI)."""
    with _errors(ctx):
        scan = scan_project(path, resolve_rules())

        if as_json:
            payload = {
                "status": "ok",
                "project_root": str(path.resolve()),
                "files_scanned": scan.files_scanned,
                "findings": [
                    {
                        "rule": finding.rule.id,
                        "severity": finding.severity.value,
                        "stride": finding.rule.stride,
                        "location": finding.location,
                        "excerpt": redact(finding),
                    }
                    for finding in scan.findings[:max_items]
                ],
            }
            click.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            click.secho(
                f"Scanned {scan.files_scanned} Python file(s): {len(scan.findings)} finding(s)",
                fg="blue",
            )
            for finding in scan.findings[:max_items]:
                color = _SEVERITY_COLORS[finding.severity]
                click.echo(
                    f"  {click.style(f'{finding.severity.value.upper():<8}', fg=color)}"
                    f" {finding.rule.id:<22} {finding.location}"
                )
                click.echo(f"           {redact(finding)}")
            hidden = len(scan.findings) - max_items
            if hidden > 0:
                click.secho(f"  … {hidden} more finding(s) not shown", fg="yellow")

        if fail_on is not None and scan.exceeds(Severity(fail_on.lower())):
            ctx.exit(EXIT_FINDINGS)


def _vulnerable_entries(reports: list[DependencyReport]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for report in reports:
        version = report.requirement.pinned_version
        for vulnerability in report.vulnerabilities:
            entries.append(
                {
                    "package": report.requirement.name,
                    "version": version,
                    "id": vulnerability.id,
                    "severity": vulnerability.severity,
                    "summary": vulnerability.summary,
                    "aliases": list(vulnerability.aliases),
                    "source": report.requirement.source,
                }
            )
    return entries


@cli.command("scan-deps")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.option("--timeout", type=click.FloatRange(1.0, 60.0), default=10.0, show_default=True)
@click.option("--include-dev", is_flag=True, help="Also check optional/dev dependency groups.")
@click.pass_context
def scan_deps(
    ctx: click.Context,
    path: Path,
    as_json: bool,
    timeout: float,
    include_dev: bool,
) -> None:
    """Check pinned dependencies for known vulnerabilities (OSV.dev)."""
    with _errors(ctx):
        reports = scan_dependencies(path, timeout=timeout, include_optional=include_dev)
        pinned = [report for report in reports if report.requirement.pinned_version]
        unpinned = [report for report in reports if report.skipped_reason]
        vulnerable = [report for report in reports if report.vulnerable]
        entries = _vulnerable_entries(vulnerable)

        if as_json:
            payload = {
                "status": "ok",
                "project_root": str(path.resolve()),
                "checked": len(pinned),
                "skipped": [
                    {"package": report.requirement.display, "reason": report.skipped_reason}
                    for report in unpinned
                ],
                "vulnerable": entries,
            }
            click.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        elif not reports:
            click.secho(
                "No dependencies found (looked for pyproject.toml and requirements*.txt).",
                fg="yellow",
            )
        else:
            click.echo(f"Checked {len(pinned)} pinned, skipped {len(unpinned)} not pinned")
            if entries:
                click.secho(f"✗ {len(entries)} known vulnerabilit(ies)", fg="red")
                for entry in entries:
                    click.echo(
                        f"  {entry['package']}=={entry['version']}  "
                        f"{str(entry['severity']).upper():<8} {entry['id']}"
                    )
                    click.echo(f"      {entry['summary']}")
            else:
                click.secho("✓ No known vulnerabilities in pinned dependencies", fg="green")

        if entries:
            ctx.exit(EXIT_FINDINGS)


@cli.group()
def plugin() -> None:
    """Manage detector plugins."""


@plugin.command("list")
def list_plugins() -> None:
    """Show built-in detectors and installed plugins."""
    builtin = resolve_rules(include_plugins=False)
    click.echo(f"Built-in detectors ({len(builtin)}):")
    for rule in builtin:
        click.echo(f"  {rule.severity.value.upper():<8} {rule.id:<22} {rule.title}")

    entry_points = iter_plugin_entry_points()
    if not entry_points:
        click.echo(f"\nPlugins: none (entry point group '{ENTRY_POINT_GROUP}').")
        return

    loaded = load_plugin_rules()
    click.echo(f"\nPlugins: {len(entry_points)} entry point(s), {len(loaded)} rule(s)")
    for entry_point in entry_points:
        click.echo(f"  {entry_point.name:<22} {entry_point.value}")


@plugin.command("install")
@click.argument("plugin_name")
@click.pass_context
def install_plugin(ctx: click.Context, plugin_name: str) -> None:
    """Explain how to install a detector plugin."""
    with _errors(ctx):
        raise PluginError(
            "Installing plugins from the CLI is not implemented. "
            f"Run 'pip install {plugin_name}': any distribution that declares a "
            f"'{ENTRY_POINT_GROUP}' entry point is picked up by analyze/lint automatically."
        )


if __name__ == "__main__":
    cli()
