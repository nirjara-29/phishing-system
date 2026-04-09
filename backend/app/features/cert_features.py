"""SSL/TLS certificate feature extraction.

Analyzes the SSL certificate of a domain to identify characteristics
common in phishing: free DV certificates, short validity periods,
mismatched SANs, and suspicious issuers.
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# Certificate issuers commonly used by legitimate sites
TRUSTED_ISSUERS = {
    "digicert",
    "comodo",
    "sectigo",
    "globalsign",
    "entrust",
    "godaddy",
    "thawte",
    "geotrust",
    "symantec",
    "amazon",
    "google trust services",
    "cloudflare",
    "microsoft",
}

# Free DV certificate issuers (commonly abused by phishing)
FREE_CERT_ISSUERS = {
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "buypass",
    "ssl.com",
    "cloudflare",
}

# Certificate validation levels
CERT_VALIDATION_LEVELS = {
    "DV": "Domain Validated",
    "OV": "Organization Validated",
    "EV": "Extended Validation",
}


class CertificateFeatureExtractor:
    """Extract SSL/TLS certificate features for phishing detection.

    Connects to the target domain, retrieves the certificate, and extracts
    features including issuer, validity period, SAN matching, and
    validation level.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def extract(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Extract certificate features for the given domain.

        Returns a dictionary of certificate-related features suitable
        for use as ML model input.
        """
        features = self._default_features()

        try:
            cert_info = await self._fetch_certificate(domain, port)
            if cert_info is None:
                features["ssl_available"] = False
                return features

            features["ssl_available"] = True

            # Parse issuer
            issuer = self._parse_name(cert_info.get("issuer", ()))
            features["ssl_issuer"] = issuer.get("O", issuer.get("CN", "unknown"))
            features["ssl_issuer_cn"] = issuer.get("CN", "")
            features["ssl_issuer_org"] = issuer.get("O", "")
            features["ssl_issuer_country"] = issuer.get("C", "")

            # Issuer trust analysis
            issuer_lower = features["ssl_issuer"].lower()
            features["is_trusted_issuer"] = any(
                trusted in issuer_lower for trusted in TRUSTED_ISSUERS
            )
            features["is_free_cert"] = any(
                free in issuer_lower for free in FREE_CERT_ISSUERS
            )

            # Parse subject
            subject = self._parse_name(cert_info.get("subject", ()))
            features["ssl_subject_cn"] = subject.get("CN", "")
            features["ssl_subject_org"] = subject.get("O", "")

            # Validity period
            not_before = cert_info.get("notBefore", "")
            not_after = cert_info.get("notAfter", "")

            if not_before and not_after:
                start = self._parse_cert_date(not_before)
                end = self._parse_cert_date(not_after)

                if start and end:
                    now = datetime.now(timezone.utc)
                    features["ssl_valid"] = start <= now <= end
                    features["ssl_days_remaining"] = (end - now).days
                    features["ssl_validity_days"] = (end - start).days
                    features["ssl_not_before"] = start.isoformat()
                    features["ssl_not_after"] = end.isoformat()

                    # Short validity (under 90 days) is common for phishing
                    features["ssl_short_validity"] = (end - start).days < 90

            # Subject Alternative Names
            san_list = self._extract_sans(cert_info)
            features["ssl_san_count"] = len(san_list)
            features["ssl_sans"] = san_list[:20]  # Cap at 20
            features["ssl_wildcard"] = any(s.startswith("*.") for s in san_list)

            # SAN matching - check if domain matches any SAN
            features["ssl_san_match"] = self._domain_matches_san(domain, san_list)

            # Determine validation level
            features["ssl_validation_level"] = self._determine_validation_level(
                cert_info, issuer
            )

            # Version and serial
            features["ssl_version"] = cert_info.get("version", -1)
            features["ssl_serial_number"] = cert_info.get("serialNumber", "")

            # Compute certificate risk score
            features["cert_risk_score"] = self._compute_cert_risk(features)

        except Exception as e:
            logger.warning(
                "Certificate extraction failed", domain=domain, error=str(e)
            )
            features["ssl_available"] = False
            features["ssl_error"] = str(e)

        logger.debug(
            "Certificate features extracted",
            domain=domain,
            valid=features.get("ssl_valid"),
            issuer=features.get("ssl_issuer"),
        )

        return features

    async def _fetch_certificate(self, domain: str, port: int) -> Optional[Dict]:
        """Connect to the domain and retrieve the SSL certificate."""
        try:
            loop = asyncio.get_event_loop()
            cert_info = await asyncio.wait_for(
                loop.run_in_executor(None, self._get_cert_sync, domain, port),
                timeout=self.timeout,
            )
            return cert_info
        except asyncio.TimeoutError:
            logger.warning("Certificate fetch timed out", domain=domain)
            return None
        except Exception as e:
            logger.warning("Certificate fetch failed", domain=domain, error=str(e))
            return None

    @staticmethod
    def _get_cert_sync(domain: str, port: int) -> Optional[Dict]:
        """Synchronous certificate retrieval using stdlib ssl."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert is None:
                        # Try getting binary cert and parsing
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            return {"raw_der": True, "available": True}
                    return cert
        except Exception:
            return None

    @staticmethod
    def _parse_name(name_tuples: tuple) -> Dict[str, str]:
        """Parse an X.509 name field (issuer/subject) into a dictionary."""
        result = {}
        for field_set in name_tuples:
            if isinstance(field_set, tuple):
                for field in field_set if isinstance(field_set[0], tuple) else [field_set]:
                    if isinstance(field, tuple) and len(field) == 2:
                        result[field[0]] = field[1]
        return result

    @staticmethod
    def _parse_cert_date(date_str: str) -> Optional[datetime]:
        """Parse an SSL certificate date string."""
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_sans(cert_info: Dict) -> List[str]:
        """Extract Subject Alternative Names from the certificate."""
        sans = []
        subject_alt = cert_info.get("subjectAltName", ())
        for san_type, san_value in subject_alt:
            if san_type.lower() == "dns":
                sans.append(san_value.lower())
        return sans

    @staticmethod
    def _domain_matches_san(domain: str, san_list: List[str]) -> bool:
        """Check if the domain matches any SAN entry (including wildcards)."""
        domain = domain.lower()
        for san in san_list:
            san = san.lower()
            if domain == san:
                return True
            if san.startswith("*."):
                wildcard_base = san[2:]
                if domain == wildcard_base or domain.endswith(f".{wildcard_base}"):
                    return True
        return False

    @staticmethod
    def _determine_validation_level(cert_info: Dict, issuer: Dict) -> str:
        """Determine the certificate validation level (DV, OV, EV)."""
        # Check for EV indicators in policy OIDs
        # EV certificates contain specific policy OIDs
        subject = {}
        for field_set in cert_info.get("subject", ()):
            if isinstance(field_set, tuple):
                for field in field_set if isinstance(field_set[0], tuple) else [field_set]:
                    if isinstance(field, tuple) and len(field) == 2:
                        subject[field[0]] = field[1]

        # EV certs have Organization and serialNumber in subject
        if subject.get("serialNumber") and subject.get("O"):
            return "EV"

        # OV certs have Organization in subject
        if subject.get("O"):
            return "OV"

        # Default: DV
        return "DV"

    def _compute_cert_risk(self, features: Dict[str, Any]) -> float:
        """Compute a certificate-based risk score."""
        risk = 0.0

        if not features.get("ssl_available"):
            return 0.5

        if not features.get("ssl_valid"):
            risk += 0.3

        if features.get("is_free_cert"):
            risk += 0.15

        if not features.get("ssl_san_match"):
            risk += 0.25

        if features.get("ssl_short_validity"):
            risk += 0.15

        if features.get("ssl_validation_level") == "DV":
            risk += 0.05

        days_remaining = features.get("ssl_days_remaining", -1)
        if 0 < days_remaining < 7:
            risk += 0.10

        return min(risk, 1.0)

    @staticmethod
    def _default_features() -> Dict[str, Any]:
        """Return default feature values when extraction fails."""
        return {
            "ssl_available": False,
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_days_remaining": -1,
            "ssl_san_match": False,
            "ssl_validation_level": "unknown",
            "is_free_cert": False,
            "cert_risk_score": 0.5,
        }
