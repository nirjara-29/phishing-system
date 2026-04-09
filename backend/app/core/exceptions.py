"""Application exception classes and FastAPI exception handlers.

Defines a hierarchy of domain-specific exceptions that map cleanly to
HTTP status codes, plus global exception handlers for consistent error
response formatting.
"""

from typing import Any, Dict, Optional

import structlog
from fastapi import Request, status
from fastapi.responses import ORJSONResponse

logger = structlog.get_logger(__name__)


class PhishNetException(Exception):
    """Base exception for all PhishNet application errors."""

    def __init__(
        self,
        message: str = "An unexpected error occurred",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(self.message)


class NotFoundException(PhishNetException):
    """Resource not found."""

    def __init__(self, resource: str = "Resource", identifier: Any = None):
        detail = {"resource": resource}
        if identifier is not None:
            detail["identifier"] = str(identifier)
        message = f"{resource} not found"
        if identifier:
            message = f"{resource} with id '{identifier}' not found"
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )


class DuplicateException(PhishNetException):
    """Resource already exists."""

    def __init__(self, resource: str = "Resource", field: str = ""):
        super().__init__(
            message=f"{resource} with this {field} already exists",
            status_code=status.HTTP_409_CONFLICT,
            detail={"resource": resource, "field": field},
        )


class AuthenticationError(PhishNetException):
    """Authentication failure."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AuthorizationError(PhishNetException):
    """Insufficient permissions."""

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ValidationError(PhishNetException):
    """Request validation failure."""

    def __init__(self, message: str = "Validation error", errors: Optional[list] = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"errors": errors or []},
        )


class ScanError(PhishNetException):
    """Error during URL or email scanning."""

    def __init__(self, message: str = "Scan failed", scan_id: Optional[str] = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"scan_id": scan_id} if scan_id else {},
        )


class ExternalServiceError(PhishNetException):
    """Error communicating with an external service (WHOIS, DNS, etc.)."""

    def __init__(self, service: str, message: str = "External service error"):
        super().__init__(
            message=f"{service}: {message}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"service": service},
        )


class RateLimitError(PhishNetException):
    """Rate limit exceeded."""

    def __init__(self, retry_after: int = 60):
        super().__init__(
            message="Rate limit exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"retry_after": retry_after},
        )


class ModelNotReadyError(PhishNetException):
    """ML model is not loaded or ready for inference."""

    def __init__(self, model_name: str = ""):
        super().__init__(
            message=f"ML model '{model_name}' is not ready",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"model": model_name},
        )


# =============================================================================
# Exception Handlers
# =============================================================================


async def phishnet_exception_handler(request: Request, exc: PhishNetException) -> ORJSONResponse:
    """Handle PhishNet-specific exceptions with structured error responses."""
    logger.warning(
        "PhishNet exception",
        error=exc.message,
        status_code=exc.status_code,
        path=request.url.path,
        detail=exc.detail,
    )
    return ORJSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.message,
            "detail": exc.detail,
            "path": request.url.path,
        },
    )


async def validation_exception_handler(request: Request, exc: ValueError) -> ORJSONResponse:
    """Handle ValueError as a 422 validation error."""
    logger.warning("Validation error", error=str(exc), path=request.url.path)
    return ORJSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": True,
            "message": "Validation error",
            "detail": {"errors": [str(exc)]},
            "path": request.url.path,
        },
    )


async def generic_exception_handler(request: Request, exc: Exception) -> ORJSONResponse:
    """Catch-all handler for unhandled exceptions."""
    logger.exception(
        "Unhandled exception",
        error=str(exc),
        path=request.url.path,
        exc_type=type(exc).__name__,
    )
    return ORJSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "message": "Internal server error",
            "detail": {},
            "path": request.url.path,
        },
    )
