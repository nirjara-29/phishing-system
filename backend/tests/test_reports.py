"""Tests for the report generation service.

Validates dashboard stats computation, threat trend data, top threat
aggregation, recent scan merging, and full report generation.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_scan_id
from app.models.url_scan import URLScan
from app.models.email_scan import EmailScan
from app.models.threat import ThreatIndicator
from app.services.report_service import ReportService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _seed_url_scans(db: AsyncSession, count: int = 5):
    """Create URL scan records for testing."""
    scans = []
    for i in range(count):
        verdict = "phishing" if i % 3 == 0 else ("suspicious" if i % 3 == 1 else "safe")
        scan = URLScan(
            scan_id=generate_scan_id(),
            url=f"https://test-{i}.example.com",
            domain=f"test-{i}.example.com",
            status="completed",
            verdict=verdict,
            confidence_score=0.5 + (i * 0.08),
            risk_level="high" if verdict == "phishing" else "low",
            scan_duration_ms=100 + i * 50,
            created_at=datetime.now(timezone.utc) - timedelta(hours=i),
        )
        db.add(scan)
        scans.append(scan)
    await db.flush()
    return scans


async def _seed_email_scans(db: AsyncSession, count: int = 3):
    """Create email scan records for testing."""
    scans = []
    for i in range(count):
        scan = EmailScan(
            scan_id=generate_scan_id(),
            sender=f"sender-{i}@example.com",
            subject=f"Test Email {i}",
            status="completed",
            verdict="safe",
            confidence_score=0.9,
            risk_level="low",
            created_at=datetime.now(timezone.utc) - timedelta(hours=i),
        )
        db.add(scan)
        scans.append(scan)
    await db.flush()
    return scans


async def _seed_threats(db: AsyncSession, count: int = 2):
    """Create threat indicators for testing."""
    indicators = []
    for i in range(count):
        from app.core.security import compute_hash
        indicator = ThreatIndicator(
            indicator_type="domain",
            value=f"evil-{i}.tk",
            value_hash=compute_hash(f"evil-{i}.tk"),
            severity="high",
            source="test",
            is_active=True,
        )
        db.add(indicator)
        indicators.append(indicator)
    await db.flush()
    return indicators


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDashboardStats:
    async def test_stats_with_data(self, db_session):
        await _seed_url_scans(db_session, 6)
        await _seed_email_scans(db_session, 3)
        await _seed_threats(db_session, 2)

        service = ReportService(db_session)
        stats = await service.get_dashboard_stats()

        assert stats.total_url_scans == 6
        assert stats.total_email_scans == 3
        assert stats.phishing_detected >= 1
        assert stats.total_threats == 2
        assert 0.0 <= stats.detection_rate <= 1.0
        assert stats.avg_scan_time_ms >= 0

    async def test_stats_empty_database(self, db_session):
        service = ReportService(db_session)
        stats = await service.get_dashboard_stats()
        assert stats.total_url_scans == 0
        assert stats.detection_rate == 0.0


@pytest.mark.asyncio
class TestThreatTrend:
    async def test_trend_data(self, db_session):
        await _seed_url_scans(db_session, 10)

        service = ReportService(db_session)
        trend = await service.get_threat_trend(days=3)

        assert len(trend) == 3
        for point in trend:
            assert hasattr(point, "date")
            assert hasattr(point, "phishing")
            assert hasattr(point, "total")


@pytest.mark.asyncio
class TestTopThreats:
    async def test_top_threats(self, db_session):
        # Create multiple scans for the same domain
        for _ in range(5):
            scan = URLScan(
                scan_id=generate_scan_id(),
                url="https://evil-repeat.tk/phish",
                domain="evil-repeat.tk",
                status="completed",
                verdict="phishing",
                confidence_score=0.95,
                risk_level="critical",
                created_at=datetime.now(timezone.utc),
            )
            db_session.add(scan)
        await db_session.flush()

        service = ReportService(db_session)
        top = await service.get_top_threats(limit=5, days=30)

        assert len(top) >= 1
        assert top[0].domain == "evil-repeat.tk"
        assert top[0].count == 5


@pytest.mark.asyncio
class TestRecentScans:
    async def test_recent_scans_merged(self, db_session):
        await _seed_url_scans(db_session, 3)
        await _seed_email_scans(db_session, 3)

        service = ReportService(db_session)
        recent = await service.get_recent_scans(limit=10)

        assert len(recent) == 6
        # Should be sorted by created_at desc
        for i in range(len(recent) - 1):
            assert recent[i].created_at >= recent[i + 1].created_at


@pytest.mark.asyncio
class TestReportGeneration:
    async def test_generate_report(self, db_session):
        await _seed_url_scans(db_session, 5)
        await _seed_threats(db_session, 1)

        service = ReportService(db_session)
        now = datetime.now(timezone.utc)
        report = await service.generate_report(
            start_date=now - timedelta(days=7),
            end_date=now,
            include_details=True,
        )

        assert "report_id" in report
        assert "summary" in report
        assert report["summary"]["total_scans"] >= 5
        assert "scan_details" in report
