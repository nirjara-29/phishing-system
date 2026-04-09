"""URL scanning schemas for request validation and response serialization."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class URLScanRequest(BaseModel):
    """Schema for initiating a URL scan."""

    url: str = Field(..., min_length=5, max_length=2048, description="The URL to scan for phishing")
    async_mode: bool = Field(False, description="Run scan asynchronously via Celery")
    source: str = Field("api", description="Source of the scan request")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        # Basic URL structure validation
        if "." not in v.split("//", 1)[-1].split("/", 1)[0]:
            raise ValueError("Invalid URL: must contain a valid domain")
        return v


class URLBatchScanRequest(BaseModel):
    """Schema for batch URL scanning."""

    urls: List[str] = Field(..., min_length=1, max_length=100)
    async_mode: bool = True


class URLFeatureResponse(BaseModel):
    """Detailed feature breakdown from URL analysis."""

    # Lexical features
    url_length: Optional[int] = None
    domain_length: Optional[int] = None
    path_length: Optional[int] = None
    subdomain_count: Optional[int] = None
    digit_ratio: Optional[float] = None
    special_char_ratio: Optional[float] = None
    entropy: Optional[float] = None
    has_ip_address: Optional[bool] = None
    is_punycode: Optional[bool] = None
    tld_category: Optional[str] = None

    # Domain features
    domain_age_days: Optional[int] = None
    has_whois_privacy: Optional[bool] = None
    registrar: Optional[str] = None

    # Certificate features
    ssl_valid: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    ssl_days_remaining: Optional[int] = None

    # Content features
    page_title_match: Optional[float] = None
    has_login_form: Optional[bool] = None
    external_resource_ratio: Optional[float] = None
    brand_similarity_score: Optional[float] = None

    model_config = {"from_attributes": True}


class URLScanResponse(BaseModel):
    """Schema for URL scan result."""

    scan_id: str
    url: str
    final_url: Optional[str] = None
    domain: Optional[str] = None
    status: str
    verdict: Optional[str] = None
    confidence_score: Optional[float] = None
    risk_level: Optional[str] = None

    # Model scores
    rf_score: Optional[float] = None
    gb_score: Optional[float] = None
    bert_score: Optional[float] = None

    # Feature breakdown
    features: Optional[URLFeatureResponse] = None
    redirect_chain: Optional[List[str]] = None

    scan_duration_ms: Optional[int] = None
    source: str = "api"
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class URLScanListResponse(BaseModel):
    """Paginated list of URL scan results."""

    items: List[URLScanResponse]
    total: int
    page: int
    page_size: int
    pages: int


class URLScanSummary(BaseModel):
    """Abbreviated scan result for lists and recent activity."""

    scan_id: str
    url: str
    domain: Optional[str]
    verdict: Optional[str]
    confidence_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class QuickCheckRequest(BaseModel):
    """Quick URL check from browser extension — minimal payload."""

    url: str
    check_cache: bool = True

    @field_validator("url")
    @classmethod
    def validate_quick_check_url(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        if "." not in value.split("//", 1)[-1].split("/", 1)[0]:
            raise ValueError("Invalid URL: must contain a valid domain")
        return value


class QuickCheckResponse(BaseModel):
    """Quick URL check response — fast, lightweight."""

    url: str
    verdict: str
    confidence: float
    risk_level: str
