"""Project templates for Numsec.

A template is a plain directory tree that is copied verbatim. Nothing is executed
and nothing is renamed: what lives in the template is exactly what a user gets.
That is deliberate — the previous loader mapped an ``openspec`` directory to
``numsec``, which silently did nothing because no template ever contained one.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..exceptions import TemplateError

_TEMPLATES_ROOT = Path(__file__).parent / "templates"
_PLACEHOLDER = "{{project_name}}"
_RENDERABLE_SUFFIXES = frozenset(
    {".md", ".mdc", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".json", ".py"}
)


def get_available_templates() -> list[str]:
    """Return the names of the bundled templates, sorted."""
    if not _TEMPLATES_ROOT.is_dir():
        return []
    return sorted(
        child.name
        for child in _TEMPLATES_ROOT.iterdir()
        if child.is_dir() and not child.name.startswith((".", "__"))
    )


def validate_template(template_name: str) -> bool:
    """Return True when ``template_name`` is one of the bundled templates."""
    return template_name in get_available_templates()


def get_template_path(template_name: str) -> Path:
    """Resolve a template name to its directory.

    Raises:
        TemplateError: If the template does not exist.
    """
    if not validate_template(template_name):
        available = ", ".join(get_available_templates()) or "none"
        raise TemplateError(f"Template '{template_name}' not found (available: {available}).")
    return _TEMPLATES_ROOT / template_name


def _render_placeholders(path: Path, project_name: str) -> None:
    """Substitute ``{{project_name}}`` in text files, leave everything else alone."""
    if path.suffix not in _RENDERABLE_SUFFIXES:
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    if _PLACEHOLDER not in text:
        return
    path.write_text(text.replace(_PLACEHOLDER, project_name), encoding="utf-8")


def _git_init(project_path: Path) -> bool:
    """Initialise a repository, quietly, without failing the whole init if git is absent."""
    if shutil.which("git") is None:
        return False
    result = subprocess.run(
        ["git", "init", "--quiet"],
        cwd=project_path,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def init_project(
    project_path: Path,
    template_name: str = "basic",
    *,
    run_git: bool = True,
) -> list[Path]:
    """Copy ``template_name`` into ``project_path``.

    Args:
        project_path: Destination directory (created if missing).
        template_name: Bundled template to copy.
        run_git: Run ``git init`` in the destination.

    Returns:
        Absolute paths of the copied template files.

    Raises:
        TemplateError: If the template is unknown or the copy fails.
    """
    template_path = get_template_path(template_name)

    try:
        project_path.mkdir(parents=True, exist_ok=True)
        copied: list[Path] = []

        for item in sorted(template_path.iterdir()):
            destination = project_path / item.name
            if item.is_dir():
                shutil.copytree(item, destination, dirs_exist_ok=True)
                copied.extend(path for path in sorted(destination.rglob("*")) if path.is_file())
            else:
                shutil.copy2(item, destination)
                copied.append(destination)
    except OSError as exc:
        raise TemplateError(f"Failed to initialize project: {exc}") from exc

    for path in copied:
        _render_placeholders(path, project_path.name)

    (project_path / "numsec" / "changes").mkdir(parents=True, exist_ok=True)

    if run_git:
        _git_init(project_path)

    return copied
