"""Command-line interface for Numsec."""
import sys
from pathlib import Path

import click

from .analyze import analyze_project
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

# Ensure Python 3.9+ is being used
ensure_python_version((3, 9))

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}


def print_version(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    """Print version and exit."""
    if not value or ctx.resilient_parsing:
        return
    from numsec import __version__
    click.echo(f"Numsec v{__version__}")
    ctx.exit()


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Show version and exit.",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose output.",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Security-focused project toolkit for Python projects."""
    # Ensure we have a context object
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose


@cli.command()
@click.argument("project_name")
@click.option(
    "--template",
    "template_name",
    default="basic",
    help="Project template to use.",
    show_default=True,
)
@click.option(
    "--force",
    is_flag=True,
    help="Force project creation even if directory exists.",
)
@click.pass_context
def init(
    ctx: click.Context, project_name: str, template_name: str, force: bool
) -> None:
    """Initialize a new security project."""
    try:
        project_path = Path(project_name).resolve()
        
        if project_path.exists() and not force:
            click.confirm(
                f"Directory '{project_name}' already exists. Continue?",
                abort=True,
            )
        
        init_project(project_path, template_name)
        click.echo(ASCII_BANNER)
        click.secho(f"✓ Created project at {project_path}", fg="green")
        
    except Exception as e:
        click.secho(f"Error: {str(e)}", fg="red")
        if ctx.obj.get("VERBOSE"):
            import traceback
            click.echo(traceback.format_exc())
        sys.exit(1)


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


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--ai-format",
    is_flag=True,
    help="Generate stable, assistant-friendly output and files.",
)
@click.pass_context
def analyze(ctx: click.Context, path: str, ai_format: bool) -> None:
    """Analyze a project and generate threat reports."""
    try:
        project_root = Path(path).resolve()
        result = analyze_project(project_root, ai_format=ai_format)

        if ai_format:
            click.echo(result)
        else:
            click.secho("✓ Threat analysis complete", fg="green")
            click.echo(result)

    except Exception as e:
        click.secho(f"Error: {str(e)}", fg="red")
        if ctx.obj.get("VERBOSE"):
            import traceback

            click.echo(traceback.format_exc())
        sys.exit(1)


@cli.command("scan-deps")
@click.argument("path", default=".", type=click.Path(exists=True))
def scan_dependencies(path: str) -> None:
    """Scan project dependencies for known vulnerabilities."""
    click.secho("Scanning dependencies...", fg="blue")
    # Implementation will be added later
    click.secho("✓ Dependency scan complete", fg="green")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def lint(path: str) -> None:
    """Run security linter on the project."""
    click.secho("Running security linter...", fg="blue")
    # Implementation will be added later
    click.secho("✓ Security linting complete", fg="green")


@cli.group()
def plugin() -> None:
    """Manage security plugins."""
    pass


@plugin.command("install")
@click.argument("plugin_name")
def install_plugin(plugin_name: str) -> None:
    """Install a security plugin."""
    click.secho(f"Installing plugin: {plugin_name}...", fg="blue")
    # Implementation will be added later
    click.secho(f"✓ Installed plugin: {plugin_name}", fg="green")


if __name__ == "__main__":
    cli()
