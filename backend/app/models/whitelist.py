"""Whitelist model for trusted domains.

Whitelisted domains bypass phishing detection to reduce false positives
for known-safe domains (e.g., company intranet, verified partners).
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class WhitelistEntry(Base):
    """A whitelisted domain that should be excluded from phishing detection.

    Entries can be manual (added by admins) or automatic (based on repeated
    safe scan results). Entries can optionally expire.
    """

    __tablename__ = "whitelist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    entry_type: Mapped[str] = mapped_column(
        String(50), default="manual", server_default="manual"
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    added_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    added_by_user = relationship("User", back_populates="whitelist_entries")

    # Valid entry types
    ENTRY_TYPES = {"manual", "automatic", "verified", "partner"}

    def __repr__(self) -> str:
        return f"<WhitelistEntry(domain='{self.domain}', type='{self.entry_type}')>"

    @property
    def is_expired(self) -> bool:
        """Check if the whitelist entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_effective(self) -> bool:
        """Check if the entry is both active and not expired."""
        return self.is_active and not self.is_expired

    @classmethod
    def matches_domain(cls, domain: str, whitelist_domain: str) -> bool:
        """Check if a domain matches a whitelist entry.

        Supports exact match and wildcard subdomain matching.
        E.g., whitelist 'example.com' matches 'sub.example.com'.
        """
        domain = domain.lower().strip()
        whitelist_domain = whitelist_domain.lower().strip()

        if domain == whitelist_domain:
            return True

        # Subdomain matching: 'sub.example.com' matches 'example.com'
        if domain.endswith(f".{whitelist_domain}"):
            return True

        return False
