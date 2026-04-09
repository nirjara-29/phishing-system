"""Report generation service for analytics and compliance.

Generates periodic reports summarizing scan activity, detection rates,
threat trends, and model performance metrics.
"""

from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import func, select, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_scan_id
from app.models.url_scan import URLScan
from app.models.email_scan import EmailScan
from app.models.threat import ThreatIndicator
from app.schemas.report import (
    DashboardStats,
    ThreatTrendPoint,
    TopThreatEntry,
    RecentScanEntry,
    ReportSummary,
)

logger = structlog.get_logger(__name__)


class ReportService:
    """Generate reports, dashboard statistics, and analytics data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_dashboard_stats(self) -> DashboardStats:
        """Compute aggregate dashboard statistics."""
        # URL scan counts
        url_counts = await self.db.execute(
            select(
                func.count(URLScan.id).label("total"),
                func.count(case((URLScan.verdict == "phishing", 1))).label("phishing"),
                func.count(case((URLScan.verdict == "suspicious", 1))).label("suspicious"),
                func.count(case((URLScan.verdict == "safe", 1))).label("safe"),
                func.avg(URLScan.confidence_score).label("avg_confidence"),
                func.avg(URLScan.scan_duration_ms).label("avg_duration"),
            )
        )
        url_row = url_counts.one()

        # Email scan counts
        email_counts = await self.db.execute(
            select(func.count(EmailScan.id).label("total"))
        )
        email_total = email_counts.scalar() or 0

        # Today's scans
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today_url = await self.db.execute(
            select(func.count(URLScan.id)).where(
                URLScan.created_at >= today_start
            )
        )
        today_email = await self.db.execute(
            select(func.count(EmailScan.id)).where(
                EmailScan.created_at >= today_start
            )
        )
        scans_today = (today_url.scalar() or 0) + (today_email.scalar() or 0)

        # Active threats
        threat_count = await self.db.execute(
            select(func.count(ThreatIndicator.id)).where(
                ThreatIndicator.is_active.is_(True)
            )
        )

        total_scans = (url_row.total or 0) + email_total
        phishing = url_row.phishing or 0
        detection_rate = phishing / total_scans if total_scans > 0 else 0.0

        return DashboardStats(
            total_url_scans=url_row.total or 0,
            total_email_scans=email_total,
            phishing_detected=phishing,
            suspicious_detected=url_row.suspicious or 0,
            safe_detected=url_row.safe or 0,
            total_threats=threat_count.scalar() or 0,
            scans_today=scans_today,
            detection_rate=round(detection_rate, 4),
            avg_confidence=round(url_row.avg_confidence or 0, 4),
            avg_scan_time_ms=round(url_row.avg_duration or 0, 1),
        )

    async def get_threat_trend(self, days: int = 7) -> List[ThreatTrendPoint]:
        """Get daily threat detection trend over the specified period."""
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        points = []

        for i in range(days):
            day_start = start_date + timedelta(days=i)
            day_end = day_start + timedelta(days=1)

            result = await self.db.execute(
                select(
                    func.count(case((URLScan.verdict == "phishing", 1))).label("phishing"),
                    func.count(case((URLScan.verdict == "suspicious", 1))).label("suspicious"),
                    func.count(case((URLScan.verdict == "safe", 1))).label("safe"),
                    func.count(URLScan.id).label("total"),
                ).where(
                    and_(
                        URLScan.created_at >= day_start,
                        URLScan.created_at < day_end,
                    )
                )
            )
            row = result.one()

            points.append(ThreatTrendPoint(
                date=day_start.strftime("%Y-%m-%d"),
                phishing=row.phishing or 0,
                suspicious=row.suspicious or 0,
                safe=row.safe or 0,
                total=row.total or 0,
            ))

        return points

    async def get_top_threats(self, limit: int = 10, days: int = 7) -> List[TopThreatEntry]:
        """Get the most frequently detected threat domains."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self.db.execute(
            select(
                URLScan.domain,
                func.count(URLScan.id).label("count"),
                func.max(URLScan.created_at).label("last_seen"),
            )
            .where(
                and_(
                    URLScan.verdict == "phishing",
                    URLScan.created_at >= since,
                    URLScan.domain.isnot(None),
                )
            )
            .group_by(URLScan.domain)
            .order_by(func.count(URLScan.id).desc())
            .limit(limit)
        )

        entries = []
        for row in result:
            entries.append(TopThreatEntry(
                domain=row.domain,
                count=row.count,
                severity="high" if row.count >= 5 else "medium",
                last_seen=row.last_seen,
            ))

        return entries

    async def get_recent_scans(self, limit: int = 20) -> List[RecentScanEntry]:
        """Get the most recent scan activity across URL and email scans."""
        # Recent URL scans
        url_result = await self.db.execute(
            select(URLScan)
            .order_by(URLScan.created_at.desc())
            .limit(limit)
        )
        url_scans = url_result.scalars().all()

        # Recent email scans
        email_result = await self.db.execute(
            select(EmailScan)
            .order_by(EmailScan.created_at.desc())
            .limit(limit)
        )
        email_scans = email_result.scalars().all()

        # Merge and sort
        entries = []
        for scan in url_scans:
            entries.append(RecentScanEntry(
                scan_id=scan.scan_id,
                scan_type="url",
                target=scan.url[:100],
                verdict=scan.verdict,
                confidence_score=scan.confidence_score,
                risk_level=scan.risk_level,
                created_at=scan.created_at,
            ))
        for scan in email_scans:
            entries.append(RecentScanEntry(
                scan_id=scan.scan_id,
                scan_type="email",
                target=scan.sender or scan.subject or "Unknown",
                verdict=scan.verdict,
                confidence_score=scan.confidence_score,
                risk_level=scan.risk_level,
                created_at=scan.created_at,
            ))

        entries.sort(key=lambda x: x.created_at, reverse=True)
        return entries[:limit]

    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        include_details: bool = True,
    ) -> Dict[str, Any]:
        """Generate a comprehensive report for the specified time period."""
        report_id = generate_scan_id()

        # URL scan statistics for the period
        url_stats = await self.db.execute(
            select(
                func.count(URLScan.id).label("total"),
                func.count(case((URLScan.verdict == "phishing", 1))).label("phishing"),
                func.count(case((URLScan.verdict == "suspicious", 1))).label("suspicious"),
                func.count(case((URLScan.verdict == "safe", 1))).label("safe"),
                func.count(case((URLScan.status == "error", 1))).label("errors"),
                func.avg(URLScan.confidence_score).label("avg_confidence"),
            ).where(
                and_(
                    URLScan.created_at >= start_date,
                    URLScan.created_at <= end_date,
                )
            )
        )
        url_row = url_stats.one()

        # Email scan statistics
        email_stats = await self.db.execute(
            select(func.count(EmailScan.id)).where(
                and_(
                    EmailScan.created_at >= start_date,
                    EmailScan.created_at <= end_date,
                )
            )
        )
        email_count = email_stats.scalar() or 0

        # Top threat domains for the period
        top_threats = await self.get_top_threats(limit=10, days=30)

        # New indicators added
        new_indicators = await self.db.execute(
            select(func.count(ThreatIndicator.id)).where(
                and_(
                    ThreatIndicator.created_at >= start_date,
                    ThreatIndicator.created_at <= end_date,
                )
            )
        )

        total_scans = (url_row.total or 0) + email_count

        summary = ReportSummary(
            period_start=start_date,
            period_end=end_date,
            total_scans=total_scans,
            url_scans=url_row.total or 0,
            email_scans=email_count,
            phishing_count=url_row.phishing or 0,
            suspicious_count=url_row.suspicious or 0,
            safe_count=url_row.safe or 0,
            error_count=url_row.errors or 0,
            detection_rate=round(
                (url_row.phishing or 0) / total_scans if total_scans > 0 else 0, 4
            ),
            avg_confidence=round(url_row.avg_confidence or 0, 4),
            top_threat_domains=top_threats,
            new_threat_indicators=new_indicators.scalar() or 0,
        )

        report = {
            "report_id": report_id,
            "report_type": "custom",
            "summary": summary.model_dump(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        if include_details:
            # Include individual scan details
            url_scans = await self.db.execute(
                select(URLScan).where(
                    and_(
                        URLScan.created_at >= start_date,
                        URLScan.created_at <= end_date,
                    )
                ).order_by(URLScan.created_at.desc()).limit(500)
            )
            report["scan_details"] = [
                {
                    "scan_id": s.scan_id,
                    "url": s.url,
                    "verdict": s.verdict,
                    "confidence": s.confidence_score,
                    "created_at": s.created_at.isoformat(),
                }
                for s in url_scans.scalars().all()
            ]

        logger.info("Report generated", report_id=report_id, total_scans=total_scans)
        return report
