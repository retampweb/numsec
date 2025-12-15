"""Utility helpers for Numsec."""

import sys
from typing import Tuple


def ensure_python_version(min_version: Tuple[int, int]) -> None:
    """Ensure the running Python version is at least min_version.

    Args:
        min_version: Minimum (major, minor) version tuple.

    Raises:
        RuntimeError: If the current Python version is lower than required.
    """
    major, minor = min_version
    if sys.version_info < (major, minor):
        raise RuntimeError(
            f"Numsec requires Python {major}.{minor}+ (current: {sys.version_info.major}.{sys.version_info.minor})."
        )
