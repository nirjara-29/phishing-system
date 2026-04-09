"""Domain-level feature extraction: WHOIS, DNS, registrar analysis.

Queries external services (WHOIS databases, DNS resolvers) to gather
information about the domain hosting a URL. New/young domains, privacy-
protected registrations, and certain registrars correlate with phishing.
"""

import asyncio
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# Registrars frequently associated with abuse
HIGH_RISK_REGISTRARS = {
    "namecheap",
    "namesilo",
    "enom",
    "tucows",
    "pdr ltd",
    "alibaba",
    "reg.ru",
    "hostinger",
    "publicdomainregistry",
}

# DNS record types we check
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

# WHOIS privacy protection service indicators
PRIVACY_INDICATORS = {
    "whoisguard",
    "privacy protect",
    "domains by proxy",
    "contact privacy",
    "perfect privacy",
    "withheld for privacy",
    "redacted for privacy",
    "gdpr",
    "data protected",
    "private registration",
}


class DomainFeatureExtractor:
    """Extract domain registration and DNS features.

    Features include domain age, registrar reputation, WHOIS privacy
    status, DNS record analysis, and hosting infrastructure details.
    """

    def __init__(self, whois_timeout: int = 10, dns_timeout: int = 5):
        self.whois_timeout = whois_timeout
        self.dns_timeout = dns_timeout

    async def extract(self, domain: str) -> Dict[str, Any]:
        """Extract all domain-level features for the given domain.

        Runs WHOIS and DNS lookups concurrently to minimize latency.
        """
        features = {}

        # Run lookups concurrently
        whois_task = asyncio.create_task(self._extract_whois_features(domain))
        dns_task = asyncio.create_task(self._extract_dns_features(domain))

        whois_features = await whois_task
        dns_features = await dns_task

        features.update(whois_features)
        features.update(dns_features)

        # Compute composite risk signals
        features["domain_risk_score"] = self._compute_domain_risk(features)

        logger.debug(
            "Domain features extracted",
            domain=domain,
            age_days=features.get("domain_age_days"),
            risk=features.get("domain_risk_score"),
        )

        return features

    async def _extract_whois_features(self, domain: str) -> Dict[str, Any]:
        """Query WHOIS for domain registration details."""
        features = {
            "domain_age_days": -1,
            "registrar": None,
            "registrar_is_high_risk": False,
            "has_whois_privacy": False,
            "registration_country": None,
            "expiration_days": -1,
            "whois_available": False,
            "registrant_name": None,
        }

        try:
            import whois

            loop = asyncio.get_event_loop()
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain),
                timeout=self.whois_timeout,
            )

            if w is None:
                return features

            features["whois_available"] = True

            # Domain age
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                if isinstance(creation_date, datetime):
                    age = datetime.now(timezone.utc) - creation_date.replace(
                        tzinfo=timezone.utc
                    )
                    features["domain_age_days"] = age.days

            # Expiration
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if expiration_date:
                if isinstance(expiration_date, datetime):
                    remaining = expiration_date.replace(
                        tzinfo=timezone.utc
                    ) - datetime.now(timezone.utc)
                    features["expiration_days"] = remaining.days

            # Registrar
            registrar = w.registrar
            if registrar:
                features["registrar"] = registrar
                registrar_lower = registrar.lower()
                features["registrar_is_high_risk"] = any(
                    risk in registrar_lower for risk in HIGH_RISK_REGISTRARS
                )

            # Privacy protection
            org = str(w.org or "").lower()
            name = str(w.name or "").lower()
            registrant_text = f"{org} {name}"
            features["has_whois_privacy"] = any(
                indicator in registrant_text for indicator in PRIVACY_INDICATORS
            )

            # Registration country
            if w.country:
                country = w.country if isinstance(w.country, str) else w.country[0]
                features["registration_country"] = country

            # Registrant name
            if w.name and not features["has_whois_privacy"]:
                features["registrant_name"] = (
                    w.name if isinstance(w.name, str) else w.name[0]
                )

        except asyncio.TimeoutError:
            logger.warning("WHOIS lookup timed out", domain=domain)
        except Exception as e:
            logger.warning("WHOIS lookup failed", domain=domain, error=str(e))

        return features

    async def _extract_dns_features(self, domain: str) -> Dict[str, Any]:
        """Query DNS for domain resolution details."""
        features = {
            "dns_resolves": False,
            "ip_address": None,
            "ip_addresses": [],
            "has_mx_record": False,
            "mx_count": 0,
            "ns_count": 0,
            "nameservers": [],
            "has_spf": False,
            "has_dmarc": False,
            "ttl_seconds": -1,
        }

        try:
            import dns.resolver
            import dns.asyncresolver

            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.dns_timeout

            # A record lookup
            try:
                a_records = await resolver.resolve(domain, "A")
                features["dns_resolves"] = True
                ips = [str(r) for r in a_records]
                features["ip_address"] = ips[0] if ips else None
                features["ip_addresses"] = ips
                features["ttl_seconds"] = a_records.rrset.ttl if a_records.rrset else -1
            except Exception:
                pass

            # MX records
            try:
                mx_records = await resolver.resolve(domain, "MX")
                features["has_mx_record"] = True
                features["mx_count"] = len(mx_records)
            except Exception:
                pass

            # NS records
            try:
                ns_records = await resolver.resolve(domain, "NS")
                features["ns_count"] = len(ns_records)
                features["nameservers"] = [str(r).rstrip(".") for r in ns_records]
            except Exception:
                pass

            # TXT records (for SPF and DMARC)
            try:
                txt_records = await resolver.resolve(domain, "TXT")
                for record in txt_records:
                    txt = str(record).lower()
                    if "v=spf1" in txt:
                        features["has_spf"] = True
                    if "v=dmarc1" in txt or "_dmarc" in domain:
                        features["has_dmarc"] = True
            except Exception:
                pass

            # Check DMARC subdomain explicitly
            try:
                dmarc_records = await resolver.resolve(f"_dmarc.{domain}", "TXT")
                if dmarc_records:
                    features["has_dmarc"] = True
            except Exception:
                pass

        except Exception as e:
            logger.warning("DNS lookup failed", domain=domain, error=str(e))

        return features

    def _compute_domain_risk(self, features: Dict[str, Any]) -> float:
        """Compute a composite domain risk score from individual features.

        Score ranges from 0.0 (safe) to 1.0 (very risky).
        """
        risk = 0.0

        # Young domains are risky
        age_days = features.get("domain_age_days", -1)
        if age_days == -1:
            risk += 0.15  # Unknown age is moderately suspicious
        elif age_days < 30:
            risk += 0.30  # Very young domain
        elif age_days < 90:
            risk += 0.20
        elif age_days < 365:
            risk += 0.05

        # High-risk registrar
        if features.get("registrar_is_high_risk"):
            risk += 0.15

        # Privacy-protected registration
        if features.get("has_whois_privacy"):
            risk += 0.10

        # No DNS resolution
        if not features.get("dns_resolves"):
            risk += 0.10

        # No MX record (legitimate domains usually have email)
        if not features.get("has_mx_record"):
            risk += 0.05

        # No SPF record
        if not features.get("has_spf"):
            risk += 0.05

        # No DMARC record
        if not features.get("has_dmarc"):
            risk += 0.05

        # Short expiration (phishing domains often have minimal registration)
        exp_days = features.get("expiration_days", -1)
        if 0 < exp_days < 90:
            risk += 0.10

        return min(risk, 1.0)

    @staticmethod
    async def reverse_dns_lookup(ip: str) -> Optional[str]:
        """Perform a reverse DNS lookup for an IP address."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip),
            )
            return result[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if an IP address is in a private/reserved range."""
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return False
