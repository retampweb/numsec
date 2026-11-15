"""Utility helpers for Numsec."""

from __future__ import annotations

import sys


def ensure_python_version(min_version: tuple[int, int]) -> None:
    """Ensure the running Python version is at least ``min_version``.

    ``requires-python`` in ``pyproject.toml`` already blocks stale interpreters on
    install, but running straight from a source checkout bypasses that check.

    Raises:
        RuntimeError: If the current Python version is lower than required.
    """
    major, minor = min_version
    if sys.version_info < (major, minor):
        raise RuntimeError(
            "Numsec requires Python "
            f"{major}.{minor}+ (current: {sys.version_info.major}.{sys.version_info.minor})."
        )


def shorten(text: str, limit: int = 160) -> str:
    """Collapse whitespace and trim ``text`` so it fits a single report line."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "\u2026"
