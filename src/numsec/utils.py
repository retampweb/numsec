"""Utility helpers for Numsec."""

from __future__ import annotations

import sys
from collections.abc import Iterator, Sequence
from typing import TypeVar

T = TypeVar("T")


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


def chunked(items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    """Yield consecutive slices of at most ``size`` items."""
    if size < 1:
        raise ValueError("size must be a positive integer")
    for start in range(0, len(items), size):
        yield items[start : start + size]


def shorten(text: str, limit: int = 160) -> str:
    """Collapse whitespace and trim ``text`` so it fits a single report line."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"
