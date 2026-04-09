"""Threat intelligence feed integration service.

Manages threat intelligence feeds, ingests indicators, and provides
lookup capabilities against the threat database.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import func, select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import DuplicateException, NotFoundException
from app.core.security import compute_hash
from app.models.threat import ThreatFeed, ThreatIndicator

logger = structlog.get_logger(__name__)


class ThreatIntelService:
    """Manage threat intelligence feeds and indicator lookups."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # Indicator Management
    # =========================================================================

    async def add_indicator(
        self,
        indicator_type: str,
        value: str,
        threat_type: Optional[str] = None,
        severity: str = "medium",
        source: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ThreatIndicator:
        """Add a single threat indicator to the database."""
        value_hash = compute_hash(value.lower().strip())

        # Check for duplicate
        existing = await self.db.execute(
            select(ThreatIndicator).where(ThreatIndicator.value_hash == value_hash)
        )
        if existing.scalar_one_or_none():
            raise DuplicateException("ThreatIndicator", "value")

        indicator = ThreatIndicator(
            indicator_type=indicator_type,
            value=value.strip(),
            value_hash=value_hash,
            threat_type=threat_type,
            severity=severity,
            source=source or "manual",
            tags=tags,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        self.db.add(indicator)
        await self.db.flush()
        await self.db.refresh(indicator)

        logger.info(
            "Threat indicator added",
            id=indicator.id,
            type=indicator_type,
            severity=severity,
        )
        return indicator

    async def bulk_add_indicators(
        self,
        indicators: List[Dict[str, Any]],
        source: str = "feed",
        feed_id: Optional[int] = None,
    ) -> Dict[str, int]:
        """Bulk-insert threat indicators, skipping duplicates."""
        added = 0
        skipped = 0
        errors = 0

        for ind_data in indicators:
            try:
                value = ind_data.get("value", "").strip()
                if not value:
                    errors += 1
                    continue

                value_hash = compute_hash(value.lower())

                existing = await self.db.execute(
                    select(ThreatIndicator).where(
                        ThreatIndicator.value_hash == value_hash
                    )
                )
                if existing.scalar_one_or_none():
                    skipped += 1
                    continue

                indicator = ThreatIndicator(
                    indicator_type=ind_data.get("indicator_type", "url"),
                    value=value,
                    value_hash=value_hash,
                    threat_type=ind_data.get("threat_type", "phishing"),
                    severity=ind_data.get("severity", "medium"),
                    source=source,
                    feed_id=feed_id,
                    tags=ind_data.get("tags"),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                )
                self.db.add(indicator)
                added += 1

            except Exception as e:
                logger.warning("Error adding indicator", error=str(e))
                errors += 1

        await self.db.flush()

        logger.info(
            "Bulk indicator import complete",
            added=added,
            skipped=skipped,
            errors=errors,
        )
        return {"added": added, "skipped": skipped, "errors": errors}

    async def lookup(
        self,
        value: str,
        indicator_type: Optional[str] = None,
    ) -> List[ThreatIndicator]:
        """Look up a value against the threat indicator database.

        Checks exact match by hash. Optionally filters by indicator type.
        """
        value_hash = compute_hash(value.lower().strip())

        stmt = select(ThreatIndicator).where(
            ThreatIndicator.value_hash == value_hash,
            ThreatIndicator.is_active.is_(True),
        )

        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)

        result = await self.db.execute(stmt)
        indicators = result.scalars().all()

        # Update last_seen
        for ind in indicators:
            ind.touch()
        if indicators:
            await self.db.flush()

        return list(indicators)

    async def search_indicators(
        self,
        query: Optional[str] = None,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_active: Optional[bool] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """Search threat indicators with filtering and pagination."""
        stmt = select(ThreatIndicator)

        if query:
            stmt = stmt.where(ThreatIndicator.value.ilike(f"%{query}%"))
        if indicator_type:
            stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
        if severity:
            stmt = stmt.where(ThreatIndicator.severity == severity)
        if is_active is not None:
            stmt = stmt.where(ThreatIndicator.is_active.is_(is_active))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.db.execute(count_stmt)).scalar()

        stmt = stmt.order_by(ThreatIndicator.last_seen.desc().nullslast())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(stmt)
        indicators = result.scalars().all()

        return {
            "items": list(indicators),
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
        }

    async def deactivate_indicator(self, indicator_id: int) -> None:
        """Deactivate a threat indicator."""
        indicator = await self.db.get(ThreatIndicator, indicator_id)
        if indicator is None:
            raise NotFoundException("ThreatIndicator", indicator_id)
        indicator.is_active = False
        await self.db.flush()

    # =========================================================================
    # Feed Management
    # =========================================================================

    async def add_feed(self, **kwargs) -> ThreatFeed:
        """Register a new threat intelligence feed."""
        feed = ThreatFeed(**kwargs)
        self.db.add(feed)
        await self.db.flush()
        await self.db.refresh(feed)
        logger.info("Threat feed added", feed_id=feed.id, name=feed.name)
        return feed

    async def list_feeds(self) -> List[ThreatFeed]:
        """List all configured threat feeds."""
        result = await self.db.execute(
            select(ThreatFeed).order_by(ThreatFeed.name)
        )
        return list(result.scalars().all())

    async def refresh_feed(self, feed_id: int) -> Dict[str, int]:
        """Fetch and ingest indicators from a threat feed.

        Dispatches to the appropriate parser based on feed_type.
        """
        feed = await self.db.get(ThreatFeed, feed_id)
        if feed is None:
            raise NotFoundException("ThreatFeed", feed_id)

        if not feed.is_enabled:
            logger.info("Feed is disabled, skipping", feed_id=feed_id)
            return {"added": 0, "skipped": 0, "errors": 0}

        try:
            indicators = await self._fetch_feed_data(feed)
            result = await self.bulk_add_indicators(
                indicators, source=feed.name, feed_id=feed.id
            )
            feed.mark_fetched(result["added"])
            await self.db.flush()
            return result

        except Exception as e:
            logger.error("Feed refresh failed", feed_id=feed_id, error=str(e))
            raise

    async def _fetch_feed_data(self, feed: ThreatFeed) -> List[Dict[str, Any]]:
        """Fetch and parse data from a threat feed URL."""
        import aiohttp

        indicators = []

        try:
            headers = {}
            if feed.auth_config:
                api_key = feed.auth_config.get("api_key")
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    feed.url, headers=headers, timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status != 200:
                        logger.warning(
                            "Feed fetch returned non-200",
                            feed_id=feed.id,
                            status=response.status,
                        )
                        return []

                    content = await response.text()

            # Parse based on feed type
            if feed.feed_type == "csv":
                indicators = self._parse_csv_feed(content)
            elif feed.feed_type == "json":
                indicators = self._parse_json_feed(content)
            else:
                logger.warning("Unsupported feed type", feed_type=feed.feed_type)

        except Exception as e:
            logger.error("Feed data fetch failed", error=str(e))

        return indicators

    @staticmethod
    def _parse_csv_feed(content: str) -> List[Dict[str, Any]]:
        """Parse a CSV threat feed (one indicator per line)."""
        indicators = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            parts = line.split(",")
            value = parts[0].strip()
            if value:
                indicators.append({
                    "value": value,
                    "indicator_type": "url" if "://" in value else "domain",
                    "threat_type": "phishing",
                    "severity": parts[1].strip() if len(parts) > 1 else "medium",
                })
        return indicators

    @staticmethod
    def _parse_json_feed(content: str) -> List[Dict[str, Any]]:
        """Parse a JSON threat feed."""
        import json

        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return data.get("indicators", data.get("data", []))
        except json.JSONDecodeError:
            logger.error("Failed to parse JSON feed")
        return []
