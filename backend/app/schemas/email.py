"""Email scanning schemas for request validation and response serialization."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EmailScanRequest(BaseModel):
    """Schema for initiating an email scan.

    Accepts either raw email content (headers + body) or structured
    fields for sender, subject, body, etc.
    """

    email_text: Optional[str] = Field(None, description="Plain email text for lightweight scans")
    raw_email: Optional[str] = Field(None, description="Full raw email content including headers")
    subject: Optional[str] = Field(None, max_length=1000)
    sender: Optional[str] = Field(None, max_length=255)
    recipient: Optional[str] = Field(None, max_length=255)
    body_text: Optional[str] = Field(None, max_length=100000)
    body_html: Optional[str] = Field(None, max_length=500000)
    headers: Optional[Dict[str, str]] = None
    async_mode: bool = False


class AttachmentInfo(BaseModel):
    """Schema for email attachment analysis results."""

    filename: str
    content_type: Optional[str] = None
    file_size: Optional[int] = None
    file_hash_sha256: Optional[str] = None
    is_suspicious: bool = False
    has_macros: bool = False
    is_executable: bool = False
    analysis_result: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}


class EmailAuthResult(BaseModel):
    """Email authentication check results."""

    spf_result: Optional[str] = None
    spf_details: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_details: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_details: Optional[str] = None
    all_passed: bool = False


class EmailScanResponse(BaseModel):
    """Schema for email scan result."""

    scan_id: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None

    status: str
    verdict: Optional[str] = None
    confidence_score: Optional[float] = None
    confidence: Optional[float] = None
    risk_level: Optional[str] = None
    reasons: Optional[List[str]] = None

    # Authentication
    auth_result: Optional[EmailAuthResult] = None

    # NLP scores
    urgency_score: Optional[float] = None
    brand_impersonation_score: Optional[float] = None

    # Link analysis
    link_count: Optional[int] = None
    suspicious_link_count: Optional[int] = None
    extracted_urls: Optional[List[str]] = None

    # Attachments
    attachments: Optional[List[AttachmentInfo]] = None

    scan_duration_ms: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class EmailScanListResponse(BaseModel):
    """Paginated list of email scan results."""

    items: List[EmailScanResponse]
    total: int
    page: int
    page_size: int
    pages: int


class EmailScanSummary(BaseModel):
    """Abbreviated email scan result for lists."""

    scan_id: str
    subject: Optional[str]
    sender: Optional[str]
    verdict: Optional[str]
    confidence_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}
