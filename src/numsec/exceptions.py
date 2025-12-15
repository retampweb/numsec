"""Custom exceptions for Numsec."""


class NumsecError(Exception):
    """Base exception for all Numsec errors."""


SecPeckitError = NumsecError


class TemplateError(NumsecError):
    """Raised when there's an error with project templates."""
    pass


class ValidationError(NumsecError):
    """Raised when validation of input or configuration fails."""
    pass


class DependencyError(NumsecError):
    """Raised when there are issues with dependencies."""
    pass
