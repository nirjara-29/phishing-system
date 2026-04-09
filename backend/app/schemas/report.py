"""Report and dashboard schemas for analytics and visualization."""

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DashboardStats(BaseModel):
    """Overview statistics for the dashboard."""

    total_url_scans: int = 0
    total_email_scans: int = 0
    phishing_detected: int = 0
    suspicious_detected: int = 0
    safe_detected: int = 0
    total_threats: int = 0
    scans_today: int = 0
    detection_rate: float = 0.0
    avg_confidence: float = 0.0
    avg_scan_time_ms: float = 0.0


class ThreatTrendPoint(BaseModel):
    """Single data point for threat trend chart."""

    date: str
    phishing: int = 0
    suspicious: int = 0
    safe: int = 0
    total: int = 0


class ThreatTrendResponse(BaseModel):
    """Time-series threat trend data."""

    period: str = "7d"
    data: List[ThreatTrendPoint] = []


class TopThreatEntry(BaseModel):
    """A frequently-detected threat domain or URL."""

    domain: str
    count: int
    severity: str
    last_seen: Optional[datetime] = None


class TopThreatsResponse(BaseModel):
    """Top detected threat domains."""

    items: List[TopThreatEntry] = []
    period: str = "7d"


class RecentScanEntry(BaseModel):
    """Recent scan activity for dashboard feed."""

    scan_id: str
    scan_type: str  # "url" or "email"
    target: str  # URL or sender email
    verdict: Optional[str]
    confidence_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime


class RecentScansResponse(BaseModel):
    """List of recent scan activity."""

    items: List[RecentScanEntry] = []


class ReportRequest(BaseModel):
    """Schema for generating a report."""

    report_type: str = Field(..., description="daily, weekly, monthly, custom")
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    include_details: bool = True
    format: str = Field("json", description="json, csv, pdf")


class ReportSummary(BaseModel):
    """Summary section of a generated report."""

    period_start: datetime
    period_end: datetime
    total_scans: int
    url_scans: int
    email_scans: int
    phishing_count: int
    suspicious_count: int
    safe_count: int
    error_count: int
    detection_rate: float
    avg_confidence: float
    top_threat_domains: List[TopThreatEntry]
    new_threat_indicators: int


class ReportResponse(BaseModel):
    """Full generated report."""

    report_id: str
    report_type: str
    summary: ReportSummary
    generated_at: datetime
    scan_details: Optional[List[Dict[str, Any]]] = None


class ModelPerformanceMetrics(BaseModel):
    """ML model performance metrics for monitoring."""

    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    total_predictions: int
    last_trained: Optional[datetime] = None
    last_evaluated: Optional[datetime] = None


class SystemHealthResponse(BaseModel):
    """System health and performance metrics."""

    api_healthy: bool
    database_healthy: bool
    redis_healthy: bool
    celery_healthy: bool
    models_loaded: Dict[str, bool]
    uptime_seconds: float
    active_scans: int
    queue_size: int
