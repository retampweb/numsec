"""Small helpers."""

from __future__ import annotations

import pytest

from numsec.utils import ensure_python_version, shorten


def test_current_interpreter_satisfies_the_floor() -> None:
    ensure_python_version((3, 11))


def test_an_impossible_floor_raises() -> None:
    with pytest.raises(RuntimeError, match=r"requires Python 99\.0\+"):
        ensure_python_version((99, 0))


def test_shorten_collapses_whitespace() -> None:
    assert shorten("  a \n\t b  ") == "a b"


def test_shorten_trims_long_lines() -> None:
    shortened = shorten("x" * 300, limit=20)

    assert len(shortened) == 20
    assert shortened.endswith("\u2026")
