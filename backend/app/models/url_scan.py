"""URL scan result models.

Stores the results of URL phishing analysis including feature vectors,
model scores, and the final verdict.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class URLScan(Base):
    """URL phishing scan result.

    Each scan runs the URL through feature extraction, ML ensemble,
    and produces a verdict with confidence score.
    """

    __tablename__ = "url_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    final_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Scan lifecycle
    status: Mapped[str] = mapped_column(
        String(20), default="pending", server_default="pending", index=True
    )
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Individual model scores
    rf_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    gb_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    bert_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Detailed results stored as JSON
    features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    redirect_chain: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    screenshot_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scan_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="api", server_default="api")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    user = relationship("User", back_populates="url_scans")
    feature_record = relationship(
        "URLFeatureRecord",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<URLScan(id={self.id}, url='{self.url[:50]}', verdict='{self.verdict}')>"

    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "error")

    @property
    def is_phishing(self) -> bool:
        return self.verdict == "phishing"

    def mark_completed(self, verdict: str, confidence: float) -> None:
        """Mark the scan as completed with a final verdict."""
        self.status = "completed"
        self.verdict = verdict
        self.confidence_score = confidence
        self.completed_at = datetime.now(timezone.utc)

        # Determine risk level from confidence
        if verdict == "phishing":
            if confidence >= 0.9:
                self.risk_level = "critical"
            elif confidence >= 0.7:
                self.risk_level = "high"
            else:
                self.risk_level = "medium"
        elif verdict == "suspicious":
            self.risk_level = "medium"
        else:
            self.risk_level = "low"

    def mark_error(self, error_message: str) -> None:
        """Mark the scan as failed."""
        self.status = "error"
        self.error_message = error_message
        self.completed_at = datetime.now(timezone.utc)


class URLFeatureRecord(Base):
    """Detailed feature vector extracted during URL analysis.

    Stored separately to keep the main scan table lean while preserving
    the full feature set for model retraining and audit purposes.
    """

    __tablename__ = "url_feature_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("url_scans.id", ondelete="CASCADE"), nullable=False
    )

    # Lexical features
    url_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    domain_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    subdomain_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    digit_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    special_char_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    has_ip_address: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_punycode: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tld_category: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Domain features
    domain_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    has_whois_privacy: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Certificate features
    ssl_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ssl_issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssl_days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Content features
    page_title_match: Mapped[float | None] = mapped_column(Float, nullable=True)
    has_login_form: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    external_resource_ratio: Mapped[float | None] = mapped_column(Float, nullable=True)
    brand_similarity_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    scan = relationship("URLScan", back_populates="feature_record")

    def to_feature_vector(self) -> dict:
        """Convert to a flat dictionary suitable for ML model input."""
        return {
            "url_length": self.url_length or 0,
            "domain_length": self.domain_length or 0,
            "path_length": self.path_length or 0,
            "subdomain_count": self.subdomain_count or 0,
            "digit_ratio": self.digit_ratio or 0.0,
            "special_char_ratio": self.special_char_ratio or 0.0,
            "entropy": self.entropy or 0.0,
            "has_ip_address": int(self.has_ip_address or False),
            "is_punycode": int(self.is_punycode or False),
            "domain_age_days": self.domain_age_days or -1,
            "has_whois_privacy": int(self.has_whois_privacy or False),
            "ssl_valid": int(self.ssl_valid or False),
            "ssl_days_remaining": self.ssl_days_remaining or -1,
            "page_title_match": self.page_title_match or 0.0,
            "has_login_form": int(self.has_login_form or False),
            "external_resource_ratio": self.external_resource_ratio or 0.0,
            "brand_similarity_score": self.brand_similarity_score or 0.0,
        }
