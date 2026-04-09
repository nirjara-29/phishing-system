"""Browser-extension API endpoints."""

import structlog
from fastapi import APIRouter

from app.extension_detector import get_url_detector
from app.schemas.url import QuickCheckRequest, QuickCheckResponse

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/check", response_model=QuickCheckResponse)
def check_url(data: QuickCheckRequest) -> QuickCheckResponse:
    """Return a quick phishing verdict for the browser extension."""
    detector = get_url_detector()
    result = detector.predict(data.url)
    logger.info("Extension quick-check served", url=result.url, verdict=result.verdict)
    return QuickCheckResponse(
        url=result.url,
        verdict=result.verdict,
        confidence=result.confidence,
        risk_level=result.risk_level,
    )
