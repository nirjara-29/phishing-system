"""Security utilities: password hashing, JWT token management, API key generation.

All cryptographic operations are centralized here to ensure consistent
algorithm choices and secret management across the application.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import structlog
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

logger = structlog.get_logger(__name__)

# Password hashing context using bcrypt
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


# =============================================================================
# Password Hashing
# =============================================================================


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.warning("Password verification error", error=str(e))
        return False


# =============================================================================
# JWT Token Management
# =============================================================================


def create_access_token(
    subject: str | int,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        subject: The token subject (usually user ID).
        extra_claims: Additional claims to include in the payload.
        expires_delta: Custom expiration time. Defaults to config value.

    Returns:
        Encoded JWT string.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "access",
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(subject: str | int) -> str:
    """Create a long-lived refresh token.

    Refresh tokens have a longer expiration and are used to obtain
    new access tokens without re-authenticating.
    """
    expires_delta = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token.

    Returns:
        The decoded payload dict, or None if the token is invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        # Verify this is an access token
        if payload.get("type") != "access":
            logger.warning("Token type mismatch", expected="access", got=payload.get("type"))
            return None

        return payload

    except JWTError as e:
        logger.debug("JWT decode error", error=str(e))
        return None


def decode_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT refresh token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        if payload.get("type") != "refresh":
            return None

        return payload

    except JWTError:
        return None


# =============================================================================
# API Key Management
# =============================================================================


def generate_api_key() -> str:
    """Generate a cryptographically secure API key.

    Format: phishnet_{48 hex chars} (prefix makes it easy to identify and rotate).
    """
    return f"phishnet_{secrets.token_hex(24)}"


def hash_api_key(api_key: str) -> str:
    """Create a SHA-256 hash of an API key for storage.

    We store the hash so that even if the database is compromised,
    the raw API keys are not exposed.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()


# =============================================================================
# Utility Functions
# =============================================================================


def generate_scan_id() -> str:
    """Generate a unique scan identifier (UUID-like hex string)."""
    return secrets.token_hex(18)


def compute_hash(value: str) -> str:
    """Compute a SHA-256 hash of an arbitrary string value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
