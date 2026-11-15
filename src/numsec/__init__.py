"""Numsec - security-first spec-driven toolkit."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.2.0"

__all__ = ["NumsecError", "__version__", "cli"]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .cli import cli
    from .exceptions import NumsecError


def __getattr__(name: str) -> Any:
    """Resolve public re-exports lazily.

    Importing ``numsec`` should stay cheap: the CLI pulls in ``click`` and the
    detection rules, neither of which a library consumer of ``scan_project`` needs
    unless it asks for them.
    """
    if name == "cli":
        from .cli import cli

        return cli
    if name == "NumsecError":
        from .exceptions import NumsecError

        return NumsecError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
