"""Centralized domain and security exception types."""

from __future__ import annotations


class VForgeError(Exception):
    """Base application error mapped cleanly to HTTP responses without leaking internals."""

    status_code: int = 400
    error_code: str = "bad_request"

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code


class UnauthorizedError(VForgeError):
    status_code = 401
    error_code = "unauthorized"


class ForbiddenError(VForgeError):
    status_code = 403
    error_code = "forbidden"


class NotFoundError(VForgeError):
    status_code = 404
    error_code = "not_found"


class ConflictError(VForgeError):
    status_code = 409
    error_code = "conflict"


class ValidationError(VForgeError):
    status_code = 422
    error_code = "validation_error"


class RateLimitExceededError(VForgeError):
    status_code = 429
    error_code = "rate_limit_exceeded"

    def __init__(self, message: str = "Too many requests", *, retry_after: int = 60) -> None:
        super().__init__(message)
        self.retry_after = retry_after
