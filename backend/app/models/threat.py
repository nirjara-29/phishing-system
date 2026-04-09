"""Threat intelligence models.

Stores known phishing indicators (URLs, domains, IPs, hashes) from
threat intelligence feeds and manual submissions.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatIndicator(Base):
    """A known threat indicator (IOC) from threat intelligence feeds.

    Indicator types include: url, domain, ip, email, file_hash.
    Severity levels: critical, high, medium, low, info.
    """

    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    indicator_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    value_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    threat_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    feed_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")

    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata_", JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Valid indicator types
    VALID_TYPES = {"url", "domain", "ip", "email", "file_hash"}
    SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}

    def __repr__(self) -> str:
        return (
            f"<ThreatIndicator(type='{self.indicator_type}', "
            f"value='{self.value[:40]}...', severity='{self.severity}')>"
        )

    @property
    def is_stale(self) -> bool:
        """Check if the indicator hasn't been seen in over 90 days."""
        if self.last_seen is None:
            return True
        delta = datetime.now(timezone.utc) - self.last_seen
        return delta.days > 90

    @property
    def severity_weight(self) -> float:
        """Numeric weight for the severity level, used in scoring."""
        weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }
        return weights.get(self.severity, 0.0)

    def touch(self) -> None:
        """Update the last_seen timestamp."""
        self.last_seen = datetime.now(timezone.utc)


class ThreatFeed(Base):
    """Configuration for a threat intelligence feed.

    Feeds are periodically fetched and their indicators are ingested
    into the ThreatIndicator table.
    """

    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    feed_type: Mapped[str] = mapped_column(String(50), nullable=False)

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    refresh_interval_hours: Mapped[int] = mapped_column(Integer, default=24, server_default="24")
    last_fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    indicator_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    auth_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Feed types
    FEED_TYPES = {"csv", "json", "stix", "taxii", "custom"}

    def __repr__(self) -> str:
        return f"<ThreatFeed(name='{self.name}', type='{self.feed_type}', enabled={self.is_enabled})>"

    @property
    def needs_refresh(self) -> bool:
        """Check if the feed should be refreshed based on its interval."""
        if self.last_fetched_at is None:
            return True
        delta = datetime.now(timezone.utc) - self.last_fetched_at
        return delta.total_seconds() >= self.refresh_interval_hours * 3600

    def mark_fetched(self, count: int) -> None:
        """Update fetch metadata after a successful feed refresh."""
        self.last_fetched_at = datetime.now(timezone.utc)
        self.indicator_count = count
