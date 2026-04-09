"""Tests for REST API endpoints.

Covers health checks, URL scanning, email scanning, threat management,
dashboard, and reports endpoints. All tests use the async HTTP client
from conftest with database overrides.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient

from app.models.url_scan import URLScan
from app.models.email_scan import EmailScan
from app.models.threat import ThreatIndicator
from app.core.security import generate_scan_id, compute_hash


# ---------------------------------------------------------------------------
# Health check endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHealthEndpoints:
    async def test_health(self, client: AsyncClient):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    async def test_readiness(self, client: AsyncClient):
        response = await client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "checks" in data


# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAuthAPI:
    async def test_register_and_login(self, client: AsyncClient):
        # Register
        reg_response = await client.post("/api/v1/auth/register", json={
            "email": "apitest@phishnet.io",
            "username": "apitest",
            "password": "ApiTest1234!",
            "password_confirm": "ApiTest1234!",
        })
        assert reg_response.status_code in (200, 201)

        # Login
        login_response = await client.post("/api/v1/auth/login", json={
            "username": "apitest",
            "password": "ApiTest1234!",
        })
        assert login_response.status_code == 200
        data = login_response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_protected_endpoint_without_auth(self, client: AsyncClient):
        response = await client.get("/api/v1/dashboard/stats")
        assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# URL scanning endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestURLScanAPI:
    async def test_scan_url(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/urls/scan",
            json={"url": "https://example.com", "async_mode": False},
            headers=auth_headers,
        )
        assert response.status_code in (200, 201, 202)
        data = response.json()
        assert "scan_id" in data

    async def test_scan_url_validation(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/urls/scan",
            json={"url": "not-a-url"},
            headers=auth_headers,
        )
        # Should either reject or auto-prepend https://
        assert response.status_code in (200, 201, 202, 422)

    async def test_get_scan_result(self, client: AsyncClient, auth_headers, db_session):
        # Create a scan directly in the DB
        scan = URLScan(
            scan_id=generate_scan_id(),
            url="https://test.com",
            domain="test.com",
            status="completed",
            verdict="safe",
            confidence_score=0.95,
            risk_level="low",
        )
        db_session.add(scan)
        await db_session.flush()
        await db_session.refresh(scan)

        response = await client.get(
            f"/api/v1/urls/{scan.scan_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan.scan_id
        assert data["verdict"] == "safe"

    async def test_get_nonexistent_scan(self, client: AsyncClient, auth_headers):
        response = await client.get(
            "/api/v1/urls/nonexistent-scan-id-12345",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Email scanning endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestEmailScanAPI:
    async def test_scan_email(self, client: AsyncClient, auth_headers, phishing_email_raw):
        response = await client.post(
            "/api/v1/emails/scan",
            json={"raw_email": phishing_email_raw},
            headers=auth_headers,
        )
        assert response.status_code in (200, 201, 202)

    async def test_scan_email_with_fields(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/emails/scan",
            json={
                "sender": "test@example.com",
                "subject": "Hello",
                "body_text": "Regular email content.",
            },
            headers=auth_headers,
        )
        assert response.status_code in (200, 201, 202)


# ---------------------------------------------------------------------------
# Threat endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestThreatAPI:
    async def test_create_threat_indicator(
        self, client: AsyncClient, admin_headers, db_session
    ):
        response = await client.post(
            "/api/v1/threats",
            json={
                "indicator_type": "domain",
                "value": "evil-phishing.tk",
                "severity": "high",
                "source": "manual",
            },
            headers=admin_headers,
        )
        assert response.status_code in (200, 201)

    async def test_list_threats(self, client: AsyncClient, auth_headers, db_session):
        # Seed an indicator
        indicator = ThreatIndicator(
            indicator_type="url",
            value="http://bad.tk/phish",
            value_hash=compute_hash("http://bad.tk/phish"),
            severity="high",
            source="test",
            is_active=True,
        )
        db_session.add(indicator)
        await db_session.flush()

        response = await client.get("/api/v1/threats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data or isinstance(data, list)

    async def test_create_threat_requires_admin(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/threats",
            json={
                "indicator_type": "domain",
                "value": "not-allowed.tk",
                "severity": "high",
            },
            headers=auth_headers,  # regular user
        )
        assert response.status_code in (403, 401)


# ---------------------------------------------------------------------------
# Dashboard endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDashboardAPI:
    async def test_dashboard_stats(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/dashboard/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_url_scans" in data

    async def test_threat_trend(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/dashboard/trend", headers=auth_headers)
        assert response.status_code == 200

    async def test_recent_scans(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/dashboard/recent", headers=auth_headers)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Reports endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestReportsAPI:
    async def test_generate_report(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/reports/generate",
            json={
                "report_type": "weekly",
                "include_details": False,
                "format": "json",
            },
            headers=auth_headers,
        )
        assert response.status_code in (200, 201)


# ---------------------------------------------------------------------------
# Extension endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestExtensionAPI:
    async def test_quick_check(self, client: AsyncClient, auth_headers):
        response = await client.post(
            "/api/v1/extension/check",
            json={"url": "https://example.com", "check_cache": True},
            headers=auth_headers,
        )
        assert response.status_code in (200, 201)
        data = response.json()
        assert set(data.keys()) == {"url", "verdict", "confidence", "risk_level"}
        assert data["url"] == "https://example.com"
        assert data["verdict"] in {"phishing", "safe", "suspicious"}
        assert 0.0 <= data["confidence"] <= 1.0
        assert data["risk_level"] in {"low", "medium", "high"}
