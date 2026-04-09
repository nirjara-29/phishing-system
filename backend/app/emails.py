"""Email scanning API endpoints."""

from typing import List

from fastapi import APIRouter
from pydantic import BaseModel, Field
from app.schemas.email import EmailScanRequest, EmailScanResponse
from app.services.email_service import EmailScanService

router = APIRouter()


class EmailQuickScanRequest(BaseModel):
    """Minimal email scan payload used by the frontend analyzer."""

    email_text: str = Field(..., min_length=1)


class EmailQuickScanResponse(BaseModel):
    """Compact email scan response for lightweight frontend consumption."""

    verdict: str
    confidence: float
    risk_level: str
    reasons: List[str] = Field(default_factory=list)


def _extract_reasons(features: dict | None) -> List[str]:
    """Convert notable feature flags into short, user-facing reasons."""
    if not features:
        return []

    if isinstance(features.get("analysis_reasons"), list) and features["analysis_reasons"]:
        return [str(reason) for reason in features["analysis_reasons"]]

    reasons: List[str] = []

    if features.get("has_mismatched_urls"):
        reasons.append("Links appear to point somewhere different than they claim.")
    if features.get("has_ip_url"):
        reasons.append("Contains a link that uses an IP address instead of a domain.")
    if features.get("has_shortened_url"):
        reasons.append("Contains a shortened link that can hide the real destination.")
    if features.get("subject_has_urgency") or (features.get("urgency_score") or 0) >= 0.5:
        reasons.append("Uses urgent language intended to pressure the recipient.")
    if (features.get("brand_impersonation_score") or 0) >= 0.4:
        reasons.append("Shows signs of brand impersonation.")
    if features.get("sender_name_email_mismatch"):
        reasons.append("Sender display name does not match the underlying email address.")
    if features.get("sender_suspicious_pattern"):
        reasons.append("Sender address follows a suspicious pattern.")
    if features.get("suspicious_link_count", 0) > 0:
        reasons.append("Contains suspicious embedded links.")
    if features.get("spf_result") == "fail":
        reasons.append("SPF validation failed.")
    if features.get("dkim_result") == "fail":
        reasons.append("DKIM validation failed.")
    if features.get("dmarc_result") == "fail":
        reasons.append("DMARC validation failed.")

    return reasons


@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(
    payload: EmailScanRequest,
) -> EmailScanResponse:
    """Run a full email scan using either raw email or structured fields."""
    service = EmailScanService()
    email_text = payload.email_text.strip() if payload.email_text else None
    scan = await service.scan_email(
        raw_email=payload.raw_email or email_text,
        subject=payload.subject,
        sender=payload.sender,
        recipient=payload.recipient,
        body_text=payload.body_text or email_text,
        body_html=payload.body_html,
        headers=payload.headers,
    )
    data = EmailScanResponse.model_validate(scan, from_attributes=True).model_dump()
    data["confidence"] = scan.confidence_score
    data["reasons"] = _extract_reasons(scan.features)
    return EmailScanResponse(**data)


@router.post("/scan-quick", response_model=EmailQuickScanResponse)
async def scan_email_quick(
    payload: EmailQuickScanRequest,
) -> EmailQuickScanResponse:
    """Provide a compact response shape for lightweight clients."""
    service = EmailScanService()
    scan = await service.scan_email(raw_email=payload.email_text, body_text=payload.email_text)
    return EmailQuickScanResponse(
        verdict=scan.verdict or "suspicious",
        confidence=scan.confidence_score or 0.0,
        risk_level=scan.risk_level or "medium",
        reasons=_extract_reasons(scan.features),
    )
