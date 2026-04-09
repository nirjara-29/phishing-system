"""Authentication service: user registration, login, token management."""

from datetime import datetime, timezone
from typing import Optional, Tuple

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, DuplicateException, NotFoundException
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    generate_api_key,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, TokenResponse

logger = structlog.get_logger(__name__)


class AuthService:
    """Handles user authentication, registration, and token management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(self, data: UserCreate) -> User:
        """Register a new user account.

        Validates uniqueness of email and username, hashes the password,
        and creates the user record.
        """
        # Check for existing email
        existing = await self.db.execute(
            select(User).where(User.email == data.email)
        )
        if existing.scalar_one_or_none():
            raise DuplicateException("User", "email")

        # Check for existing username
        existing = await self.db.execute(
            select(User).where(User.username == data.username)
        )
        if existing.scalar_one_or_none():
            raise DuplicateException("User", "username")

        user = User(
            email=data.email,
            username=data.username,
            full_name=data.full_name,
            hashed_password=hash_password(data.password),
            role="analyst",
            is_active=True,
        )

        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)

        logger.info("User registered", user_id=user.id, username=user.username)
        return user

    async def authenticate(self, data: UserLogin) -> Tuple[User, TokenResponse]:
        """Authenticate a user and return JWT tokens.

        Looks up the user by username, verifies the password, and
        generates access + refresh tokens.
        """
        stmt = select(User).where(User.username == data.username)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None:
            raise AuthenticationError("Invalid username or password")

        if not user.is_active:
            raise AuthenticationError("Account is disabled")

        if not verify_password(data.password, user.hashed_password):
            raise AuthenticationError("Invalid username or password")

        # Update last login
        user.update_last_login()
        await self.db.flush()

        # Generate tokens
        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role, "username": user.username},
        )
        refresh_token = create_refresh_token(subject=user.id)

        from app.config import settings

        token_response = TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

        logger.info("User authenticated", user_id=user.id)
        return user, token_response

    async def refresh_tokens(self, refresh_token: str) -> TokenResponse:
        """Generate new access and refresh tokens from a valid refresh token."""
        payload = decode_refresh_token(refresh_token)
        if payload is None:
            raise AuthenticationError("Invalid or expired refresh token")

        user_id = int(payload["sub"])
        user = await self.db.get(User, user_id)

        if user is None:
            raise AuthenticationError("User not found")

        if not user.is_active:
            raise AuthenticationError("Account is disabled")

        access_token = create_access_token(
            subject=user.id,
            extra_claims={"role": user.role, "username": user.username},
        )
        new_refresh_token = create_refresh_token(subject=user.id)

        from app.config import settings

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    async def generate_user_api_key(self, user_id: int) -> str:
        """Generate a new API key for the user.

        Replaces any existing API key.
        """
        user = await self.db.get(User, user_id)
        if user is None:
            raise NotFoundException("User", user_id)

        api_key = generate_api_key()
        user.api_key = api_key
        await self.db.flush()

        logger.info("API key generated", user_id=user_id)
        return api_key

    async def change_password(
        self, user_id: int, current_password: str, new_password: str
    ) -> None:
        """Change a user's password after verifying the current one."""
        user = await self.db.get(User, user_id)
        if user is None:
            raise NotFoundException("User", user_id)

        if not verify_password(current_password, user.hashed_password):
            raise AuthenticationError("Current password is incorrect")

        user.hashed_password = hash_password(new_password)
        await self.db.flush()

        logger.info("Password changed", user_id=user_id)

    async def get_user_by_id(self, user_id: int) -> User:
        """Retrieve a user by their ID."""
        user = await self.db.get(User, user_id)
        if user is None:
            raise NotFoundException("User", user_id)
        return user
