"""Shared pytest fixtures for the PhishNet test suite.

Provides a test database (SQLite async), an authenticated HTTP client,
factory helpers for users and scans, and common mock objects for
external services (WHOIS, DNS, HTTP fetching).
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Force testing config before any app imports
os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_phishnet.db"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["SECRET_KEY"] = "test-app-secret"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

from app.config import Settings
from app.core.security import create_access_token, hash_password
from app.database import Base
from app.main import create_app
from app.models.user import User
from app.models.url_scan import URLScan
from app.models.email_scan import EmailScan
from app.models.threat import ThreatIndicator


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///./test_phishnet.db"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a clean database session for each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# Application & HTTP client fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def app():
    """Create a fresh FastAPI application for testing."""
    application = create_app()
    return application


@pytest_asyncio.fixture(scope="function")
async def client(app, db_session) -> AsyncGenerator[AsyncClient, None]:
    """Provide an async HTTP test client wired to the test database."""
    from app.database import get_db

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# User & auth fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create and persist a standard test user."""
    user = User(
        email="testuser@phishnet.io",
        username="testuser",
        hashed_password=hash_password("Test1234!"),
        full_name="Test User",
        role="analyst",
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Create and persist an admin user."""
    user = User(
        email="admin@phishnet.io",
        username="admin",
        hashed_password=hash_password("Admin1234!"),
        full_name="Admin User",
        role="admin",
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
def auth_headers(test_user: User) -> Dict[str, str]:
    """Return Authorization headers with a valid JWT for test_user."""
    token = create_access_token(
        subject=test_user.id,
        extra_claims={"role": test_user.role, "username": test_user.username},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
def admin_headers(admin_user: User) -> Dict[str, str]:
    """Return Authorization headers with a valid JWT for admin_user."""
    token = create_access_token(
        subject=admin_user.id,
        extra_claims={"role": admin_user.role, "username": admin_user.username},
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def phishing_url() -> str:
    return "http://secure-paypa1-login.tk/verify/account?id=abc123"


@pytest.fixture
def safe_url() -> str:
    return "https://www.google.com/search?q=phishing+detection"


@pytest.fixture
def phishing_email_raw() -> str:
    return (
        "From: PayPal Security <security@paypa1-alerts.tk>\r\n"
        "To: victim@example.com\r\n"
        "Subject: URGENT: Your account has been compromised\r\n"
        "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Dear Customer,\r\n\r\n"
        "We detected unauthorized transaction on your PayPal account. "
        "Your account will be suspended within 24 hours unless you verify "
        "your identity immediately.\r\n\r\n"
        "Click here to verify: http://paypa1-secure.tk/verify\r\n\r\n"
        "PayPal Security Team"
    )


@pytest.fixture
def safe_email_raw() -> str:
    return (
        "From: Google <noreply@google.com>\r\n"
        "To: user@example.com\r\n"
        "Subject: Your monthly security checkup\r\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hi there,\r\n\r\n"
        "Here is your monthly Google account security summary. "
        "No issues were found. Visit https://myaccount.google.com for details.\r\n\r\n"
        "Thanks,\r\nThe Google Accounts Team"
    )


@pytest.fixture
def mock_whois_response():
    """Simulated python-whois response for a suspicious domain."""
    class FakeWhois:
        creation_date = datetime(2025, 12, 1, tzinfo=timezone.utc)
        expiration_date = datetime(2026, 6, 1, tzinfo=timezone.utc)
        registrar = "NameCheap Inc."
        org = "WhoisGuard Protected"
        name = "WhoisGuard Protected"
        country = "PA"
    return FakeWhois()


@pytest.fixture
def mock_whois_legit():
    """Simulated python-whois response for a well-established domain."""
    class FakeWhois:
        creation_date = datetime(2004, 8, 15, tzinfo=timezone.utc)
        expiration_date = datetime(2034, 8, 15, tzinfo=timezone.utc)
        registrar = "MarkMonitor Inc."
        org = "Google LLC"
        name = "Google LLC"
        country = "US"
    return FakeWhois()
