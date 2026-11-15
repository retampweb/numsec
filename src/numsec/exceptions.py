"""Custom exceptions for Numsec."""


class NumsecError(Exception):
    """Base exception for all Numsec errors."""


class TemplateError(NumsecError):
    """Raised when there is an error with project templates."""


class ValidationError(NumsecError):
    """Raised when validation of input or configuration fails."""


class DependencyError(NumsecError):
    """Raised when there are issues with dependencies."""


class NetworkError(NumsecError):
    """Raised when a remote service (e.g. OSV.dev) cannot be reached."""


class PluginError(NumsecError):
    """Raised when a plugin cannot be listed, loaded or installed."""
