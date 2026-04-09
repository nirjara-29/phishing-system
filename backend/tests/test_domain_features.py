"""Tests for domain feature extraction: WHOIS parsing, DNS resolution, risk scoring.

All external calls (WHOIS, DNS) are mocked to keep tests fast and deterministic.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.features.domain_features import (
    DomainFeatureExtractor,
    HIGH_RISK_REGISTRARS,
    PRIVACY_INDICATORS,
)


@pytest.fixture
def extractor():
    return DomainFeatureExtractor(whois_timeout=2, dns_timeout=2)


# ---------------------------------------------------------------------------
# WHOIS feature extraction
# ---------------------------------------------------------------------------

class TestWHOISFeatures:
    @pytest.mark.asyncio
    async def test_whois_young_domain(self, extractor, mock_whois_response):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.return_value = mock_whois_response
            features = await extractor._extract_whois_features("suspicious.tk")

        assert features["whois_available"] is True
        assert features["domain_age_days"] >= 0
        assert features["domain_age_days"] < 365

    @pytest.mark.asyncio
    async def test_whois_established_domain(self, extractor, mock_whois_legit):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.return_value = mock_whois_legit
            features = await extractor._extract_whois_features("google.com")

        assert features["whois_available"] is True
        assert features["domain_age_days"] > 3000

    @pytest.mark.asyncio
    async def test_whois_privacy_detected(self, extractor, mock_whois_response):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.return_value = mock_whois_response
            features = await extractor._extract_whois_features("hidden.tk")

        assert features["has_whois_privacy"] is True

    @pytest.mark.asyncio
    async def test_whois_high_risk_registrar(self, extractor, mock_whois_response):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.return_value = mock_whois_response
            features = await extractor._extract_whois_features("phishy.tk")

        assert features["registrar_is_high_risk"] is True

    @pytest.mark.asyncio
    async def test_whois_timeout_returns_defaults(self, extractor):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.side_effect = asyncio.TimeoutError()
            features = await extractor._extract_whois_features("timeout.tk")

        assert features["whois_available"] is False
        assert features["domain_age_days"] == -1

    @pytest.mark.asyncio
    async def test_whois_failure_returns_defaults(self, extractor):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.side_effect = Exception("Connection refused")
            features = await extractor._extract_whois_features("fail.tk")

        assert features["whois_available"] is False

    @pytest.mark.asyncio
    async def test_whois_expiration_days(self, extractor, mock_whois_response):
        with patch("app.features.domain_features.whois") as mock_whois:
            mock_whois.whois.return_value = mock_whois_response
            features = await extractor._extract_whois_features("expiring.tk")

        # Expiration date is 2026-06-01, so expiration_days depends on "now"
        assert isinstance(features["expiration_days"], int)


# ---------------------------------------------------------------------------
# DNS feature extraction
# ---------------------------------------------------------------------------

class TestDNSFeatures:
    @pytest.mark.asyncio
    async def test_dns_resolves(self, extractor):
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "93.184.216.34"

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([mock_a])
        mock_answer.rrset = mock_rrset

        with patch("app.features.domain_features.dns.asyncresolver.Resolver") as MockResolver:
            resolver = AsyncMock()
            resolver.resolve = AsyncMock(return_value=mock_answer)
            MockResolver.return_value = resolver

            features = await extractor._extract_dns_features("example.com")

        assert features["dns_resolves"] is True
        assert features["ip_address"] == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_dns_failure_returns_defaults(self, extractor):
        with patch("app.features.domain_features.dns.asyncresolver.Resolver") as MockResolver:
            resolver = AsyncMock()
            resolver.resolve = AsyncMock(side_effect=Exception("NXDOMAIN"))
            MockResolver.return_value = resolver

            features = await extractor._extract_dns_features("doesnotexist.invalid")

        assert features["dns_resolves"] is False
        assert features["ip_address"] is None


# ---------------------------------------------------------------------------
# Domain risk scoring
# ---------------------------------------------------------------------------

class TestDomainRiskScore:
    def test_young_domain_high_risk(self, extractor):
        features = {
            "domain_age_days": 7,
            "registrar_is_high_risk": True,
            "has_whois_privacy": True,
            "dns_resolves": True,
            "has_mx_record": False,
            "has_spf": False,
            "has_dmarc": False,
            "expiration_days": 30,
        }
        risk = extractor._compute_domain_risk(features)
        assert risk >= 0.6

    def test_established_domain_low_risk(self, extractor):
        features = {
            "domain_age_days": 5000,
            "registrar_is_high_risk": False,
            "has_whois_privacy": False,
            "dns_resolves": True,
            "has_mx_record": True,
            "has_spf": True,
            "has_dmarc": True,
            "expiration_days": 3000,
        }
        risk = extractor._compute_domain_risk(features)
        assert risk <= 0.1

    def test_unknown_age_moderate_risk(self, extractor):
        features = {
            "domain_age_days": -1,
            "registrar_is_high_risk": False,
            "has_whois_privacy": False,
            "dns_resolves": True,
            "has_mx_record": True,
            "has_spf": True,
            "has_dmarc": True,
            "expiration_days": -1,
        }
        risk = extractor._compute_domain_risk(features)
        assert 0.1 <= risk <= 0.3

    def test_risk_capped_at_one(self, extractor):
        features = {
            "domain_age_days": 1,
            "registrar_is_high_risk": True,
            "has_whois_privacy": True,
            "dns_resolves": False,
            "has_mx_record": False,
            "has_spf": False,
            "has_dmarc": False,
            "expiration_days": 10,
        }
        risk = extractor._compute_domain_risk(features)
        assert risk <= 1.0


# ---------------------------------------------------------------------------
# Utility methods
# ---------------------------------------------------------------------------

class TestDomainUtilities:
    def test_is_private_ip(self):
        assert DomainFeatureExtractor.is_private_ip("192.168.1.1") is True
        assert DomainFeatureExtractor.is_private_ip("127.0.0.1") is True
        assert DomainFeatureExtractor.is_private_ip("8.8.8.8") is False

    def test_is_private_ip_invalid(self):
        assert DomainFeatureExtractor.is_private_ip("not-an-ip") is False
