"""Email scan orchestration service.

Coordinates email phishing analysis: header parsing, NLP content analysis,
link extraction, attachment scanning, ML classification, and result storage.
"""

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException, ScanError
from app.core.security import generate_scan_id
from app.extension_detector import get_url_detector
from app.features.email_features import EmailFeatureExtractor
from app.ml.email_nlp_model import EmailNLPModel
from app.models.email_scan import EmailScan

logger = structlog.get_logger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s]+")


class EmailScanService:
    """Orchestrate the email phishing detection pipeline."""

    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db
        self._email_extractor = EmailFeatureExtractor()
        self._email_nlp_model = EmailNLPModel()
        self._email_pipeline = None

        try:
            self._email_pipeline = self._load_or_retrain_pipeline()
        except Exception as exc:
            logger.warning("Email NLP model unavailable, using fallback scoring", error=str(exc))
            self._email_pipeline = None

    async def scan_email(
        self,
        user_id: Optional[int] = None,
        raw_email: Optional[str] = None,
        subject: Optional[str] = None,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> EmailScan:
        """Execute the full email scanning pipeline.

        Accepts either raw email text or individual components.

        Steps:
        1. Create scan record
        2. Parse email content
        3. Extract authentication features (SPF/DKIM/DMARC)
        4. Run NLP analysis (urgency, brand impersonation)
        5. Extract and analyze embedded URLs
        6. Analyze attachments
        7. Run ML classifier
        8. Persist results
        """
        start_time = time.time()
        scan_id = generate_scan_id()

        # Create scan record
        normalized_email_text = self._compose_email_text(
            raw_email=raw_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        scan = EmailScan(
            scan_id=scan_id,
            user_id=user_id,
            subject=subject or self._extract_subject_from_raw(raw_email),
            sender=sender,
            recipient=recipient,
            body_text=body_text or normalized_email_text,
            body_html=body_html,
            raw_headers=str(headers) if headers else None,
            status="processing",
            created_at=datetime.now(timezone.utc),
        )

        # Extract sender domain
        if sender and "@" in sender:
            import re
            email_match = re.search(r"[\w.+-]+@([\w.-]+)", sender)
            if email_match:
                scan.sender_domain = email_match.group(1).lower()

        await self._try_persist_initial_scan(scan)

        try:
            # Extract features
            features = self._email_extractor.extract(
                raw_email=raw_email or normalized_email_text,
                sender=sender or "",
                subject=scan.subject or "",
                body_text=body_text or normalized_email_text,
                body_html=body_html or "",
                headers=headers or {},
            )

            # Update scan with extracted data
            scan.spf_result = features.get("spf_result")
            scan.dkim_result = features.get("dkim_result")
            scan.dmarc_result = features.get("dmarc_result")
            scan.urgency_score = features.get("urgency_score")
            scan.brand_impersonation_score = features.get("brand_impersonation_score")
            scan.link_count = features.get("link_count", 0)
            scan.suspicious_link_count = features.get("suspicious_link_count", 0)
            scan.extracted_urls = features.get("extracted_urls", [])
            scan.features = features

            if not scan.sender_domain and features.get("sender_domain"):
                scan.sender_domain = features["sender_domain"]

            nlp_prediction = self._predict_email_nlp_result(normalized_email_text)
            nlp_score = nlp_prediction["confidence"]
            extracted_urls = self._extract_urls(normalized_email_text)
            if extracted_urls:
                features["extracted_urls"] = extracted_urls
                features["link_count"] = len(extracted_urls)
            scan.extracted_urls = features.get("extracted_urls", [])

            link_analysis = self._analyze_links(features.get("extracted_urls", []))
            url_score = link_analysis["url_score"]
            final_score = round((0.8 * nlp_score) + (0.2 * url_score), 4)
            verdict = self._determine_verdict(final_score)
            confidence = round(final_score, 2)

            scan.mark_completed(verdict, confidence)
            scan.risk_level = self._determine_risk_level(verdict)
            features["email_nlp_score"] = nlp_score
            features["email_nlp_source"] = nlp_prediction["source"]
            features["link_analysis_scores"] = link_analysis["scores"]
            features["url_score"] = url_score
            features["analysis_reasons"] = self._build_reasons(
                nlp_score=nlp_score,
                url_score=url_score,
            )
            scan.features = features

            logger.info(
                "Email phishing scores",
                ml_text_score=round(nlp_score, 4),
                url_score=round(url_score, 4),
                final_score=round(final_score, 4),
            )

            duration_ms = int((time.time() - start_time) * 1000)
            scan.scan_duration_ms = duration_ms

            await self._try_finalize_scan(scan)

            logger.info(
                "Email scan completed",
                scan_id=scan_id,
                sender=sender,
                verdict=scan.verdict,
                confidence=scan.confidence_score,
            )

        except Exception as e:
            logger.error("Email scan failed", scan_id=scan_id, error=str(e))
            scan.mark_error(str(e))
            await self._safe_rollback()
            raise ScanError(message=str(e), scan_id=scan_id)

        return scan

    async def get_scan(self, scan_id: str) -> EmailScan:
        """Retrieve an email scan by scan_id."""
        stmt = select(EmailScan).where(EmailScan.scan_id == scan_id)
        result = await self.db.execute(stmt)
        scan = result.scalar_one_or_none()
        if scan is None:
            raise NotFoundException("Email Scan", scan_id)
        return scan

    async def list_scans(
        self,
        user_id: Optional[int] = None,
        page: int = 1,
        page_size: int = 20,
        verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List email scans with pagination."""
        stmt = select(EmailScan)

        if user_id:
            stmt = stmt.where(EmailScan.user_id == user_id)
        if verdict:
            stmt = stmt.where(EmailScan.verdict == verdict)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar()

        stmt = stmt.order_by(EmailScan.created_at.desc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(stmt)
        scans = result.scalars().all()

        return {
            "items": scans,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
        }

    def _predict_email_nlp_result(self, email_text: str) -> Dict[str, Any]:
        """Predict phishing probability from raw email text using a fitted pipeline."""
        cleaned_text = self._email_nlp_model._clean_text(email_text)
        if not cleaned_text:
            return self._fallback_nlp_result()

        pipeline = self._email_pipeline
        if pipeline is None:
            try:
                pipeline = self._load_or_retrain_pipeline()
                self._email_pipeline = pipeline
            except Exception as exc:
                logger.warning("Email NLP model reload failed", error=str(exc))
                return self._fallback_nlp_result()

        if pipeline is None:
            return self._fallback_nlp_result()

        try:
            probability = float(pipeline.predict_proba([cleaned_text])[0][1])
            logger.info("Email NLP inference completed", ml_text_score=round(probability, 4))
            return {
                "verdict": "phishing" if probability >= 0.5 else "safe",
                "confidence": round(probability, 4),
                "source": "model",
            }
        except Exception as exc:
            logger.warning("Email NLP inference failed, retraining pipeline", error=str(exc))
            try:
                pipeline = self._load_or_retrain_pipeline(force_retrain=True)
                self._email_pipeline = pipeline
                probability = float(pipeline.predict_proba([cleaned_text])[0][1])
                logger.info("Email NLP inference completed", ml_text_score=round(probability, 4))
                return {
                    "verdict": "phishing" if probability >= 0.5 else "safe",
                    "confidence": round(probability, 4),
                    "source": "model",
                }
            except Exception as retrain_exc:
                logger.warning("Email NLP retrain after inference failure failed", error=str(retrain_exc))
                return self._fallback_nlp_result()

    @staticmethod
    def _fallback_nlp_result() -> Dict[str, Any]:
        return {
            "verdict": "safe",
            "confidence": 0.5,
            "source": "fallback",
        }

    def _load_or_retrain_pipeline(self, force_retrain: bool = False):
        """Load a valid sklearn pipeline or retrain it if missing/invalid."""
        model_path = self._email_nlp_model.model_path

        if force_retrain or not Path(model_path).exists():
            self._email_nlp_model.train_and_save()

        loaded = joblib.load(model_path)
        pipeline = loaded.get("pipeline") if isinstance(loaded, dict) else loaded

        if not hasattr(pipeline, "predict_proba"):
            logger.warning("Loaded email NLP artifact missing predict_proba, retraining", path=str(model_path))
            self._email_nlp_model.train_and_save()
            loaded = joblib.load(model_path)
            pipeline = loaded.get("pipeline") if isinstance(loaded, dict) else loaded

        if not hasattr(pipeline, "predict_proba"):
            raise RuntimeError("Email NLP model artifact is invalid after retraining")

        return pipeline

    def _analyze_links(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze embedded URLs using the existing URL ML detector only."""
        unique_urls: List[str] = []
        for url in urls:
            cleaned = (url or "").strip().rstrip(").,>\"'")
            if cleaned and cleaned not in unique_urls:
                unique_urls.append(cleaned)
            if len(unique_urls) >= 10:
                break

        scores: List[Dict[str, Any]] = []
        url_score = 0.0

        if not unique_urls:
            return {"scores": scores, "url_score": 0.0}

        detector = get_url_detector()

        for url in unique_urls:
            try:
                result = detector.predict(url)
                phishing_probability = self._phishing_probability_from_url_result(
                    result.verdict,
                    float(result.confidence),
                )
                score = self._normalize_url_probability(phishing_probability)
                scores.append(
                    {
                        "url": url,
                        "verdict": result.verdict,
                        "confidence": phishing_probability,
                        "score": score,
                    }
                )
                url_score = max(url_score, score)
            except Exception as exc:
                logger.warning("Email link analysis failed", url=url, error=str(exc))

        return {"scores": scores, "url_score": round(url_score, 4)}

    @staticmethod
    def _extract_urls(email_text: str) -> List[str]:
        """Extract URLs from email text using the lightweight API regex."""
        matches = URL_PATTERN.findall(email_text or "")
        unique_urls: List[str] = []
        for match in matches:
            cleaned = match.strip().rstrip(").,>\"'")
            if cleaned and cleaned not in unique_urls:
                unique_urls.append(cleaned)
            if len(unique_urls) >= 10:
                break
        return unique_urls

    @staticmethod
    def _phishing_probability_from_url_result(verdict: str, confidence: float) -> float:
        """Convert detector output into phishing probability."""
        bounded_confidence = min(max(confidence, 0.0), 1.0)

        if verdict == "phishing":
            return bounded_confidence
        if verdict == "safe":
            return round(1.0 - bounded_confidence, 4)
        if verdict == "suspicious":
            return round(max(0.4, bounded_confidence), 4)
        return 0.0

    @staticmethod
    def _normalize_url_probability(phishing_probability: float) -> float:
        """Map URL ML confidence into an email URL contribution score."""
        if phishing_probability < 0.2:
            return 0.0
        if phishing_probability < 0.6:
            return round(phishing_probability * 0.5, 4)
        return round(phishing_probability, 4)

    @staticmethod
    def _determine_verdict(final_score: float) -> str:
        if final_score > 0.75:
            return "phishing"
        if final_score >= 0.4:
            return "suspicious"
        return "safe"

    @staticmethod
    def _determine_risk_level(verdict: str) -> str:
        if verdict == "phishing":
            return "high"
        if verdict == "suspicious":
            return "medium"
        return "low"

    @staticmethod
    def _build_reasons(nlp_score: float, url_score: float) -> List[str]:
        reasons: List[str] = []

        if nlp_score >= 0.5:
            reasons.append("Suspicious language detected")
        if url_score >= 0.6:
            reasons.append("Contains phishing links")

        if not reasons:
            reasons.append("Email could not be confidently verified")

        return reasons

    @staticmethod
    def _compose_email_text(
        raw_email: Optional[str],
        subject: Optional[str],
        body_text: Optional[str],
        body_html: Optional[str],
    ) -> str:
        if raw_email:
            return raw_email

        parts = [subject or "", body_text or "", body_html or ""]
        return "\n".join(part for part in parts if part).strip()

    @staticmethod
    def _extract_subject_from_raw(raw_email: Optional[str]) -> Optional[str]:
        if not raw_email:
            return None

        match = re.search(r"^Subject:\s*(.+)$", raw_email, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    async def _try_persist_initial_scan(self, scan: EmailScan) -> None:
        """Persist the initial scan record when a DB session is available."""
        if self.db is None:
            return

        try:
            self.db.add(scan)
            await self.db.flush()
        except Exception as exc:
            logger.warning("Email scan persistence unavailable, continuing in-memory", error=str(exc))
            await self._safe_rollback()
            self.db = None

    async def _try_finalize_scan(self, scan: EmailScan) -> None:
        """Flush final scan state when persistence is available."""
        if self.db is None:
            return

        try:
            await self.db.flush()
            await self.db.refresh(scan)
        except Exception as exc:
            logger.warning("Email scan finalization unavailable, returning in-memory result", error=str(exc))
            await self._safe_rollback()
            self.db = None

    async def _safe_rollback(self) -> None:
        """Rollback the session if one is active, ignoring rollback failures."""
        if self.db is None:
            return

        try:
            await self.db.rollback()
        except Exception:
            logger.warning("Email scan rollback failed")
