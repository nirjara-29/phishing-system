"""SQLAlchemy ORM models for PhishNet."""

from app.models.user import User
from app.models.url_scan import URLScan, URLFeatureRecord
from app.models.email_scan import EmailScan, EmailAttachment
from app.models.threat import ThreatIndicator, ThreatFeed
from app.models.whitelist import WhitelistEntry

__all__ = [
    "User",
    "URLScan",
    "URLFeatureRecord",
    "EmailScan",
    "EmailAttachment",
    "ThreatIndicator",
    "ThreatFeed",
    "WhitelistEntry",
]
