"""URL scan orchestration service.

Coordinates the full URL scanning pipeline: feature extraction across
all modules, ML classification, threat intelligence lookup, whitelist
checking, and result persistence.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import NotFoundException, ScanError
from app.core.security import generate_scan_id, compute_hash
from app.features.url_features import URLFeatureExtractor
from app.features.domain_features import DomainFeatureExtractor
from app.features.content_features import ContentFeatureExtractor
from app.features.cert_features import CertificateFeatureExtractor
from app.ml.url_classifier import URLClassifier
from app.ml.bert_classifier import BERTURLClassifier
from app.ml.confidence_aggregator import ConfidenceAggregator
from app.models.url_scan import URLScan, URLFeatureRecord
from app.models.whitelist import WhitelistEntry
from app.models.threat import ThreatIndicator

logger = structlog.get_logger(__name__)


class URLScanService:
    """Orchestrate the full URL phishing detection pipeline."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._url_extractor = URLFeatureExtractor()
        self._domain_extractor = DomainFeatureExtractor()
        self._content_extractor = ContentFeatureExtractor()
        self._cert_extractor = CertificateFeatureExtractor()
        self._url_classifier = URLClassifier()
        self._bert_classifier = BERTURLClassifier()
        self._aggregator = ConfidenceAggregator()

        # Try to load pre-trained models
        try:
            self._url_classifier.load()
        except Exception:
            logger.warning("URL classifier model not available")
        try:
            self._bert_classifier.load()
        except Exception:
            logger.warning("BERT classifier model not available")

    async def scan_url(
        self,
        url: str,
        user_id: Optional[int] = None,
        source: str = "api",
    ) -> URLScan:
        """Execute the full URL scanning pipeline.

        Steps:
        1. Create scan record
        2. Extract URL lexical features
        3. Extract domain features (WHOIS, DNS)
        4. Extract certificate features
        5. Fetch and analyze page content
        6. Check threat intelligence database
        7. Check whitelist
        8. Run ML classifiers
        9. Aggregate confidence scores
        10. Persist results

        Returns:
            The completed URLScan model with all results populated.
        """
        start_time = time.time()
        scan_id = generate_scan_id()

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        # Create scan record
        scan = URLScan(
            scan_id=scan_id,
            user_id=user_id,
            url=url,
            domain=domain,
            status="processing",
            source=source,
        )
        self.db.add(scan)
        await self.db.flush()

        try:
            # Step 1: Lexical feature extraction
            url_features = self._url_extractor.extract(url)

            # Step 2: Domain features
            domain_features = await self._domain_extractor.extract(domain)
            if domain_features.get("ip_address"):
                scan.ip_address = domain_features["ip_address"]

            # Step 3: Certificate features
            cert_features = await self._cert_extractor.extract(domain)

            # Step 4: Content features
            content_features = await self._content_extractor.extract(url)
            if content_features.get("final_url"):
                scan.final_url = content_features["final_url"]
            if content_features.get("redirect_chain"):
                scan.redirect_chain = content_features["redirect_chain"]

            # Merge all features
            all_features = {}
            all_features.update(url_features)
            all_features.update(domain_features)
            all_features.update(cert_features)
            all_features.update(content_features)

            # Step 5: Threat intelligence lookup
            threat_match = await self._check_threat_intel(url, domain)

            # Step 6: Whitelist check
            is_whitelisted = await self._check_whitelist(domain)

            # Step 7: ML classification
            rf_score = None
            gb_score = None
            bert_score = None

            if self._url_classifier.is_ready:
                url_pred = self._url_classifier.predict(all_features)
                rf_score = url_pred["rf_score"]
                gb_score = url_pred["gb_score"]

            if self._bert_classifier.is_ready:
                bert_pred = self._bert_classifier.predict(url)
                bert_score = bert_pred["bert_score"]

            # Step 8: Aggregate
            prediction = self._aggregator.aggregate(
                rf_score=rf_score,
                gb_score=gb_score,
                bert_score=bert_score,
                threat_intel_match=threat_match,
                is_whitelisted=is_whitelisted,
            )

            # Update scan with results
            scan.rf_score = prediction.rf_score
            scan.gb_score = prediction.gb_score
            scan.bert_score = prediction.bert_score
            scan.features = all_features
            scan.mark_completed(prediction.verdict, prediction.confidence)

            # Store feature record
            feature_record = URLFeatureRecord(
                scan_id=scan.id,
                url_length=url_features.get("url_length"),
                domain_length=url_features.get("domain_length"),
                path_length=url_features.get("path_length"),
                subdomain_count=url_features.get("subdomain_count"),
                digit_ratio=url_features.get("digit_ratio"),
                special_char_ratio=url_features.get("special_char_ratio"),
                entropy=url_features.get("url_entropy"),
                has_ip_address=url_features.get("has_ip_address"),
                is_punycode=url_features.get("is_punycode"),
                tld_category=url_features.get("tld_category"),
                domain_age_days=domain_features.get("domain_age_days"),
                has_whois_privacy=domain_features.get("has_whois_privacy"),
                registrar=domain_features.get("registrar"),
                ssl_valid=cert_features.get("ssl_valid"),
                ssl_issuer=cert_features.get("ssl_issuer"),
                ssl_days_remaining=cert_features.get("ssl_days_remaining"),
                page_title_match=content_features.get("page_title_match"),
                has_login_form=content_features.get("has_login_form"),
                external_resource_ratio=content_features.get("external_resource_ratio"),
                brand_similarity_score=content_features.get("brand_similarity_score"),
            )
            self.db.add(feature_record)

            duration_ms = int((time.time() - start_time) * 1000)
            scan.scan_duration_ms = duration_ms

            await self.db.flush()
            await self.db.refresh(scan)

            logger.info(
                "URL scan completed",
                scan_id=scan_id,
                url=url[:80],
                verdict=scan.verdict,
                confidence=scan.confidence_score,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.error("URL scan failed", scan_id=scan_id, error=str(e))
            scan.mark_error(str(e))
            await self.db.flush()
            raise ScanError(message=str(e), scan_id=scan_id)

        return scan

    async def get_scan(self, scan_id: str) -> URLScan:
        """Retrieve a scan by its scan_id."""
        stmt = select(URLScan).where(URLScan.scan_id == scan_id)
        result = await self.db.execute(stmt)
        scan = result.scalar_one_or_none()
        if scan is None:
            raise NotFoundException("URL Scan", scan_id)
        return scan

    async def list_scans(
        self,
        user_id: Optional[int] = None,
        page: int = 1,
        page_size: int = 20,
        verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List URL scans with pagination and filtering."""
        stmt = select(URLScan)

        if user_id:
            stmt = stmt.where(URLScan.user_id == user_id)
        if verdict:
            stmt = stmt.where(URLScan.verdict == verdict)

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar()

        # Paginate
        stmt = stmt.order_by(URLScan.created_at.desc())
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

    async def _check_threat_intel(self, url: str, domain: str) -> bool:
        """Check if the URL or domain is in the threat intelligence database."""
        url_hash = compute_hash(url)
        domain_hash = compute_hash(domain)

        stmt = select(ThreatIndicator).where(
            ThreatIndicator.is_active.is_(True),
            ThreatIndicator.value_hash.in_([url_hash, domain_hash]),
        )
        result = await self.db.execute(stmt)
        match = result.scalar_one_or_none()

        if match:
            match.touch()
            logger.info("Threat intel match found", domain=domain, indicator_id=match.id)
            return True

        return False

    async def _check_whitelist(self, domain: str) -> bool:
        """Check if the domain is whitelisted."""
        stmt = select(WhitelistEntry).where(
            WhitelistEntry.is_active.is_(True),
        )
        result = await self.db.execute(stmt)
        entries = result.scalars().all()

        for entry in entries:
            if entry.is_effective and WhitelistEntry.matches_domain(domain, entry.domain):
                logger.debug("Domain whitelisted", domain=domain, whitelist_entry=entry.domain)
                return True

        return False
