"""
Numsec - security-first spec-driven toolkit.
"""

__version__ = "0.1.0"

# Core components
from .cli import cli
from .exceptions import NumsecError

__all__ = ["cli", "NumsecError"]
