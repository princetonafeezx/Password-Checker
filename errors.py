"""Shared DataGuard exceptions."""


class DataGuardError(Exception):
    """Base exception for friendly CLI failures."""


class InputError(DataGuardError):
    """Raised when an input file cannot be read, or a report cannot be written."""


class ParseError(DataGuardError):
    """Raised when data cannot be parsed."""


class ValidationError(DataGuardError):
    """Raised when CLI arguments or options fail validation before analysis."""
