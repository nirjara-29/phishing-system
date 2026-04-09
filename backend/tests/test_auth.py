"""Tests for authentication: registration, login, token refresh, API keys."""

import pytest
import pytest_asyncio
from httpx import AsyncClient

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    verify_password,
    generate_api_key,
    hash_api_key,
)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_password_returns_bcrypt_string(self):
        hashed = hash_password("MySecret123!")
        assert hashed.startswith("$2b$")
        assert len(hashed) > 50

    def test_verify_correct_password(self):
        hashed = hash_password("MySecret123!")
        assert verify_password("MySecret123!", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("MySecret123!")
        assert verify_password("WrongPassword!", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("Same1234!")
        h2 = hash_password("Same1234!")
        assert h1 != h2  # bcrypt uses random salt


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------

class TestJWTTokens:
    def test_create_and_decode_access_token(self):
        token = create_access_token(subject=42, extra_claims={"role": "analyst"})
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["sub"] == "42"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"

    def test_decode_access_rejects_refresh_token(self):
        token = create_refresh_token(subject=42)
        payload = decode_access_token(token)
        assert payload is None

    def test_create_and_decode_refresh_token(self):
        token = create_refresh_token(subject=99)
        payload = decode_refresh_token(token)
        assert payload is not None
        assert payload["sub"] == "99"
        assert payload["type"] == "refresh"
        assert "jti" in payload

    def test_decode_refresh_rejects_access_token(self):
        token = create_access_token(subject=99)
        payload = decode_refresh_token(token)
        assert payload is None

    def test_decode_invalid_token_returns_none(self):
        assert decode_access_token("not.a.real.jwt") is None


# ---------------------------------------------------------------------------
# API key utilities
# ---------------------------------------------------------------------------

class TestAPIKeys:
    def test_generate_api_key_format(self):
        key = generate_api_key()
        assert key.startswith("phishnet_")
        assert len(key) == len("phishnet_") + 48

    def test_hash_api_key_deterministic(self):
        key = "phishnet_abc123"
        h1 = hash_api_key(key)
        h2 = hash_api_key(key)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_different_keys_different_hashes(self):
        k1 = generate_api_key()
        k2 = generate_api_key()
        assert hash_api_key(k1) != hash_api_key(k2)


# ---------------------------------------------------------------------------
# Registration endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRegistrationEndpoint:
    async def test_register_success(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/register", json={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "StrongPass1!",
            "password_confirm": "StrongPass1!",
        })
        assert response.status_code in (200, 201)
        data = response.json()
        assert data.get("username") == "newuser" or "access_token" in data

    async def test_register_password_mismatch(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/register", json={
            "email": "mismatch@example.com",
            "username": "mismatch",
            "password": "StrongPass1!",
            "password_confirm": "Different1!",
        })
        assert response.status_code == 422

    async def test_register_weak_password(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/register", json={
            "email": "weak@example.com",
            "username": "weakuser",
            "password": "short",
            "password_confirm": "short",
        })
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestLoginEndpoint:
    async def test_login_success(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "Test1234!",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "WrongPassword1!",
        })
        assert response.status_code in (401, 400)

    async def test_login_nonexistent_user(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/login", json={
            "username": "ghost",
            "password": "DoesNotMatter1!",
        })
        assert response.status_code in (401, 400)
