"""The bundled template must contain exactly what the docs promise."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from numsec.cli import cli
from numsec.exceptions import TemplateError
from numsec.templates import (
    get_available_templates,
    get_template_path,
    init_project,
    validate_template,
)

EXPECTED_FILES = {
    ".cursor/rules/numsec.mdc",
    ".gitignore",
    ".windsurf/workflows/numsec.md",
    "NUMSEC.md",
    "README.md",
    "requirements.txt",
    "numsec/architecture.md",
    "numsec/changes/README.md",
    "numsec/project.md",
    "numsec/security-requirements.md",
    "numsec/threats/README.md",
    "src/app/__init__.py",
    "src/app/main.py",
}


def test_basic_template_is_available() -> None:
    assert get_available_templates() == ["basic"]
    assert validate_template("basic") is True
    assert validate_template("nope") is False


def test_unknown_template_raises_a_readable_error() -> None:
    with pytest.raises(TemplateError, match="not found"):
        get_template_path("nope")


def test_template_ships_every_documented_file() -> None:
    template = get_template_path("basic")

    present = {
        path.relative_to(template).as_posix() for path in template.rglob("*") if path.is_file()
    }

    assert present == EXPECTED_FILES


def test_init_copies_the_whole_tree(tmp_path: Path) -> None:
    project = tmp_path / "demo"

    copied = init_project(project, "basic", run_git=False)

    assert len(copied) == len(EXPECTED_FILES)
    assert {path.relative_to(project).as_posix() for path in copied} == EXPECTED_FILES
    assert (project / "numsec" / "changes").is_dir()


def test_init_renders_the_project_name(tmp_path: Path) -> None:
    project = tmp_path / "my-service"

    init_project(project, "basic", run_git=False)

    readme = (project / "README.md").read_text("utf-8")
    assert readme.startswith("# my-service")
    assert not any(
        "{{project_name}}" in path.read_text("utf-8", errors="ignore")
        for path in project.rglob("*")
        if path.is_file()
    )


def test_init_into_an_existing_directory_keeps_user_files(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "notes.md").write_text("mine\n", "utf-8")

    init_project(project, "basic", run_git=False)

    assert (project / "notes.md").read_text("utf-8") == "mine\n"
    assert (project / "NUMSEC.md").is_file()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_init_creates_a_repository_quietly(tmp_path: Path) -> None:
    project = tmp_path / "demo"

    init_project(project, "basic")

    assert (project / ".git").is_dir()
    assert (project / ".gitignore").is_file()


def test_init_can_skip_git(tmp_path: Path) -> None:
    project = tmp_path / "demo"

    init_project(project, "basic", run_git=False)

    assert not (project / ".git").exists()


def test_cli_init_end_to_end(tmp_path: Path) -> None:
    project = tmp_path / "demo"

    result = CliRunner().invoke(cli, ["init", str(project), "--no-git"])

    assert result.exit_code == 0, result.output
    assert "Created project" in result.output
    assert (project / "numsec" / "project.md").is_file()


def test_cli_init_force_merges_into_a_busy_directory(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "notes.md").write_text("mine\n", "utf-8")

    result = CliRunner().invoke(cli, ["init", str(project), "--force", "--no-git"])

    assert result.exit_code == 0, result.output
    assert (project / "notes.md").is_file()
    assert (project / "NUMSEC.md").is_file()


def test_cli_init_rejects_an_unknown_template(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["init", str(tmp_path / "demo"), "--template", "nope"])

    assert result.exit_code == 2
    combined = result.output + getattr(result, "stderr", "")
    assert "not found" in combined
