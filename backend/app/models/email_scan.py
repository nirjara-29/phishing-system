"""Email scan result models.

Stores the results of email phishing analysis including header validation,
NLP features, and attachment analysis.
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


class EmailScan(Base):
    """Email phishing scan result.

    Analyzes email headers (SPF/DKIM/DMARC), body content for urgency
    and brand impersonation, extracts and scans embedded URLs, and
    checks attachments for suspicious content.
    """

    __tablename__ = "email_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Email metadata
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    sender_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recipient: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_headers: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scan status and verdict
    status: Mapped[str] = mapped_column(
        String(20), default="pending", server_default="pending"
    )
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Authentication results
    spf_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dmarc_result: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # NLP analysis scores
    urgency_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    brand_impersonation_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Link analysis
    link_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    suspicious_link_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extracted_urls: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Full feature set
    features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    scan_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    user = relationship("User", back_populates="email_scans")
    attachments = relationship(
        "EmailAttachment",
        back_populates="email_scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<EmailScan(id={self.id}, sender='{self.sender}', verdict='{self.verdict}')>"

    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "error")

    @property
    def auth_passed(self) -> bool:
        """Check if all email authentication mechanisms passed."""
        return (
            self.spf_result == "pass"
            and self.dkim_result == "pass"
            and self.dmarc_result == "pass"
        )

    @property
    def has_suspicious_attachments(self) -> bool:
        return any(att.is_suspicious for att in self.attachments)

    def mark_completed(self, verdict: str, confidence: float) -> None:
        self.status = "completed"
        self.verdict = verdict
        self.confidence_score = confidence
        self.completed_at = datetime.now(timezone.utc)

        if verdict == "phishing":
            self.risk_level = "critical" if confidence >= 0.9 else "high"
        elif verdict == "suspicious":
            self.risk_level = "medium"
        else:
            self.risk_level = "low"

    def mark_error(self, error_message: str) -> None:
        self.status = "error"
        self.error_message = error_message
        self.completed_at = datetime.now(timezone.utc)

    def to_feature_dict(self) -> dict:
        """Compile all features into a dictionary for ML input."""
        features = {
            "spf_pass": int(self.spf_result == "pass"),
            "dkim_pass": int(self.dkim_result == "pass"),
            "dmarc_pass": int(self.dmarc_result == "pass"),
            "urgency_score": self.urgency_score or 0.0,
            "brand_impersonation_score": self.brand_impersonation_score or 0.0,
            "link_count": self.link_count or 0,
            "suspicious_link_count": self.suspicious_link_count or 0,
            "has_attachments": int(len(self.attachments) > 0),
            "has_suspicious_attachments": int(self.has_suspicious_attachments),
            "attachment_count": len(self.attachments),
        }
        # Merge in detailed features if available
        if self.features:
            features.update(self.features)
        return features


class EmailAttachment(Base):
    """Email attachment metadata and analysis result.

    Stores file metadata, hash for deduplication, and results of
    macro / suspicious content analysis.
    """

    __tablename__ = "email_attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email_scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("email_scans.id", ondelete="CASCADE"), nullable=False
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_hash_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    is_suspicious: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    has_macros: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    analysis_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    email_scan = relationship("EmailScan", back_populates="attachments")

    def __repr__(self) -> str:
        return f"<EmailAttachment(filename='{self.filename}', suspicious={self.is_suspicious})>"

    # Known suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".hta",
        ".cpl", ".reg", ".inf", ".lnk",
    }

    MACRO_EXTENSIONS = {
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".dotm", ".xlam", ".ppam",
    }

    @property
    def extension(self) -> str:
        """Extract the file extension in lowercase."""
        if "." in self.filename:
            return "." + self.filename.rsplit(".", 1)[-1].lower()
        return ""

    @property
    def is_executable(self) -> bool:
        return self.extension in self.SUSPICIOUS_EXTENSIONS

    @property
    def could_have_macros(self) -> bool:
        return self.extension in self.MACRO_EXTENSIONS
