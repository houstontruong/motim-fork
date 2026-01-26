"""Package-level exceptions for MOTIM.

The library generally raises standard exceptions (e.g. FileNotFoundError) for
common situations. Custom exceptions are subclasses of those built-ins where
appropriate so existing code can keep catching the built-in types.
"""

from __future__ import annotations


class MOTIMError(Exception):
    """Base exception for MOTIM."""


class ConfigError(ValueError, MOTIMError):
    """Raised for configuration errors."""


class AuthError(MOTIMError):
    """Raised for authentication-related errors."""


class AuthMissingError(AuthError):
    """Raised when no authentication has been captured for a service."""


class AuthExpiredError(AuthError):
    """Raised when captured authentication appears expired."""


class ServiceNotFoundError(FileNotFoundError, MOTIMError):
    """Raised when a requested service/spec cannot be found."""

    def __init__(self, service: str, *, suggestions: list[str] | None = None):
        self.service = service
        self.suggestions = suggestions or []

        msg = f"No spec found for service: {service}"
        if self.suggestions:
            msg += f". Did you mean: {', '.join(self.suggestions)}?"
        super().__init__(msg)
