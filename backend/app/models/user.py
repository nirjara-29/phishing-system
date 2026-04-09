"""User model for authentication and authorization."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    """Application user account.

    Supports both JWT-based authentication (web UI) and API key
    authentication (browser extension, integrations).
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    role: Mapped[str] = mapped_column(String(50), default="analyst", server_default="analyst")
    api_key: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)

    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    url_scans = relationship("URLScan", back_populates="user", lazy="dynamic")
    email_scans = relationship("EmailScan", back_populates="user", lazy="dynamic")
    whitelist_entries = relationship("WhitelistEntry", back_populates="added_by_user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"

    @property
    def is_admin(self) -> bool:
        return self.is_superuser or self.role == "admin"

    def update_last_login(self) -> None:
        self.last_login = datetime.now(timezone.utc)
