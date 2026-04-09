"""Threat intelligence schemas for managing indicators and feeds."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ThreatIndicatorCreate(BaseModel):
    """Schema for creating a new threat indicator."""

    indicator_type: str = Field(..., description="Type: url, domain, ip, email, file_hash")
    value: str = Field(..., min_length=1, max_length=2048)
    threat_type: Optional[str] = Field(None, description="E.g., phishing, malware, c2")
    severity: str = Field("medium", description="critical, high, medium, low, info")
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[Dict[str, Any]] = None

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, v: str) -> str:
        valid_types = {"url", "domain", "ip", "email", "file_hash"}
        if v not in valid_types:
            raise ValueError(f"Invalid indicator type. Must be one of: {valid_types}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid_levels = {"critical", "high", "medium", "low", "info"}
        if v not in valid_levels:
            raise ValueError(f"Invalid severity. Must be one of: {valid_levels}")
        return v


class ThreatIndicatorUpdate(BaseModel):
    """Schema for updating an existing threat indicator."""

    threat_type: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[Dict[str, Any]] = None


class ThreatIndicatorResponse(BaseModel):
    """Schema for threat indicator in API responses."""

    id: int
    indicator_type: str
    value: str
    threat_type: Optional[str]
    severity: Optional[str]
    source: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    is_active: bool
    tags: Optional[List[str]]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatIndicatorListResponse(BaseModel):
    """Paginated list of threat indicators."""

    items: List[ThreatIndicatorResponse]
    total: int
    page: int
    page_size: int
    pages: int


class ThreatFeedCreate(BaseModel):
    """Schema for adding a new threat feed."""

    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=5, max_length=2048)
    feed_type: str = Field(..., description="csv, json, stix, taxii, custom")
    refresh_interval_hours: int = Field(24, ge=1, le=720)
    is_enabled: bool = True
    auth_config: Optional[Dict[str, Any]] = None

    @field_validator("feed_type")
    @classmethod
    def validate_feed_type(cls, v: str) -> str:
        valid_types = {"csv", "json", "stix", "taxii", "custom"}
        if v not in valid_types:
            raise ValueError(f"Invalid feed type. Must be one of: {valid_types}")
        return v


class ThreatFeedResponse(BaseModel):
    """Schema for threat feed in API responses."""

    id: int
    name: str
    url: str
    feed_type: str
    is_enabled: bool
    refresh_interval_hours: int
    last_fetched_at: Optional[datetime]
    indicator_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatLookupRequest(BaseModel):
    """Schema for looking up a value against the threat database."""

    value: str = Field(..., min_length=1)
    indicator_type: Optional[str] = None


class ThreatLookupResponse(BaseModel):
    """Response for threat lookup queries."""

    found: bool
    matches: List[ThreatIndicatorResponse] = []
    total_matches: int = 0
