"""Shared fixtures for the Numsec test-suite."""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest


@pytest.fixture
def make_project(tmp_path: Path) -> Callable[..., Path]:
    """Create a throwaway project tree from a ``{relative_path: content}`` mapping."""

    def _make(files: dict[str, str], *, root: Path | None = None) -> Path:
        project = (root or tmp_path) / "project"
        project.mkdir(parents=True, exist_ok=True)
        for relative, content in files.items():
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content), encoding="utf-8")
        return project

    return _make
