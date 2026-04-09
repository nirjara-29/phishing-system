"""Lexical URL feature extraction for phishing detection.

Extracts structural features from the URL string itself without making
any network requests. These features capture patterns commonly found in
phishing URLs such as excessive length, high entropy, IP address usage,
punycode encoding, and suspicious character distributions.
"""

import math
import re
from collections import Counter
from typing import Any, Dict, Optional
from urllib.parse import urlparse, unquote

import structlog
import tldextract

logger = structlog.get_logger(__name__)

# Common phishing TLDs ranked by frequency in phishing datasets
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".club", ".online", ".site",
    ".icu", ".buzz", ".work", ".info",
    ".bid", ".stream", ".download", ".racing",
    ".win", ".party", ".review", ".science",
}

# Trusted TLDs less commonly used in phishing
TRUSTED_TLDS = {
    ".gov", ".edu", ".mil", ".int",
    ".museum", ".aero", ".coop",
}

# Brand names frequently impersonated in phishing attacks
IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "citibank",
    "usps", "fedex", "dhl", "ups",
    "outlook", "office365", "onedrive", "icloud",
    "coinbase", "binance", "blockchain",
    "steam", "epicgames", "roblox",
}

# Suspicious keywords in URL paths
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify",
    "account", "update", "secure", "security", "confirm",
    "banking", "password", "credential", "authenticate",
    "suspend", "locked", "unusual", "alert", "urgent",
    "wallet", "recover", "restore",
}

# IP address regex patterns
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IPV4_HEX_PATTERN = re.compile(r"0x[0-9a-fA-F]+(?:\.0x[0-9a-fA-F]+){3}")
IPV4_OCTAL_PATTERN = re.compile(r"\b0[0-7]+(?:\.0[0-7]+){3}\b")


class URLFeatureExtractor:
    """Extract lexical features from a URL string.

    Features are computed purely from the URL text without network I/O,
    making this extractor fast and suitable for real-time classification.
    """

    def __init__(self):
        self._tld_extractor = tldextract.TLDExtract(
            cache_dir=None,
            include_psl_private_domains=True,
        )

    def extract(self, url: str) -> Dict[str, Any]:
        """Extract all lexical features from the given URL.

        Returns a flat dictionary of feature names to values suitable
        for direct use as ML model input.
        """
        try:
            decoded_url = unquote(url)
            parsed = urlparse(decoded_url)
            extracted = self._tld_extractor(decoded_url)

            domain = extracted.registered_domain or parsed.netloc
            subdomain = extracted.subdomain
            suffix = extracted.suffix
            fqdn = extracted.fqdn

            features = {}

            # Length-based features
            features["url_length"] = len(decoded_url)
            features["domain_length"] = len(domain)
            features["path_length"] = len(parsed.path)
            features["query_length"] = len(parsed.query)
            features["fragment_length"] = len(parsed.fragment)
            features["hostname_length"] = len(parsed.hostname or "")

            # Subdomain analysis
            subdomains = [s for s in subdomain.split(".") if s]
            features["subdomain_count"] = len(subdomains)
            features["subdomain_length"] = len(subdomain)
            features["max_subdomain_length"] = max((len(s) for s in subdomains), default=0)

            # Path analysis
            path_segments = [s for s in parsed.path.split("/") if s]
            features["path_depth"] = len(path_segments)
            features["max_path_segment_length"] = max(
                (len(s) for s in path_segments), default=0
            )

            # Character distribution features
            features.update(self._compute_char_features(decoded_url))

            # Entropy
            features["url_entropy"] = self._shannon_entropy(decoded_url)
            features["domain_entropy"] = self._shannon_entropy(domain)
            features["path_entropy"] = self._shannon_entropy(parsed.path)

            # IP address detection
            features["has_ip_address"] = self._contains_ip_address(
                parsed.hostname or ""
            )

            # Punycode / IDN detection
            features["is_punycode"] = self._is_punycode(parsed.hostname or "")
            features["has_homograph_chars"] = self._has_homograph_characters(
                parsed.hostname or ""
            )

            # TLD analysis
            features["tld"] = suffix
            features["tld_category"] = self._categorize_tld(f".{suffix}")
            features["is_suspicious_tld"] = f".{suffix}" in SUSPICIOUS_TLDS

            # Protocol
            features["uses_https"] = parsed.scheme == "https"
            features["has_port"] = ":" in (parsed.netloc.split("@")[-1] or "")

            # Brand impersonation
            features["brand_in_domain"] = self._detect_brand_in_text(domain)
            features["brand_in_subdomain"] = self._detect_brand_in_text(subdomain)
            features["brand_in_path"] = self._detect_brand_in_text(parsed.path)
            features["brand_name"] = self._identify_brand(decoded_url)

            # Suspicious patterns
            features["suspicious_keyword_count"] = self._count_suspicious_keywords(
                decoded_url
            )
            features["has_at_symbol"] = "@" in parsed.netloc
            features["has_double_slash_redirect"] = "//" in parsed.path
            features["has_hex_encoding"] = "%" in decoded_url
            features["consecutive_dots"] = ".." in decoded_url
            features["dash_count_in_domain"] = domain.count("-")
            features["dot_count_in_url"] = decoded_url.count(".")

            # URL shortener detection
            features["is_shortened"] = self._is_url_shortener(domain)

            # Data URI detection
            features["is_data_uri"] = decoded_url.startswith("data:")

            logger.debug("URL features extracted", url=url[:80], feature_count=len(features))
            return features

        except Exception as e:
            logger.error("URL feature extraction failed", url=url[:80], error=str(e))
            return self._default_features()

    def _compute_char_features(self, text: str) -> Dict[str, float]:
        """Compute character distribution metrics."""
        if not text:
            return {
                "digit_ratio": 0.0,
                "letter_ratio": 0.0,
                "special_char_ratio": 0.0,
                "uppercase_ratio": 0.0,
            }

        total = len(text)
        digits = sum(1 for c in text if c.isdigit())
        letters = sum(1 for c in text if c.isalpha())
        uppercase = sum(1 for c in text if c.isupper())
        special = total - digits - letters

        return {
            "digit_ratio": digits / total,
            "letter_ratio": letters / total,
            "special_char_ratio": special / total,
            "uppercase_ratio": uppercase / total if letters > 0 else 0.0,
        }

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate the Shannon entropy of a string.

        Higher entropy suggests random or obfuscated content, which is
        common in phishing URLs that use random subdomains or paths.
        """
        if not text:
            return 0.0

        freq = Counter(text)
        total = len(text)
        entropy = 0.0

        for count in freq.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    @staticmethod
    def _contains_ip_address(hostname: str) -> bool:
        """Check if the hostname contains an IP address (decimal, hex, or octal)."""
        if IPV4_PATTERN.match(hostname):
            return True
        if IPV4_HEX_PATTERN.match(hostname):
            return True
        if IPV4_OCTAL_PATTERN.match(hostname):
            return True
        # Check for decimal-encoded IP
        try:
            int(hostname)
            return True
        except (ValueError, TypeError):
            pass
        return False

    @staticmethod
    def _is_punycode(hostname: str) -> bool:
        """Detect punycode-encoded (internationalized) domain names."""
        if not hostname:
            return False
        return any(part.startswith("xn--") for part in hostname.split("."))

    @staticmethod
    def _has_homograph_characters(hostname: str) -> bool:
        """Detect potential homograph attack characters (non-ASCII lookalikes)."""
        try:
            hostname.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    @staticmethod
    def _categorize_tld(tld: str) -> str:
        """Categorize TLD into risk buckets."""
        if tld in TRUSTED_TLDS:
            return "trusted"
        if tld in SUSPICIOUS_TLDS:
            return "suspicious"
        if tld in {".com", ".net", ".org"}:
            return "common"
        if len(tld) == 3:  # .uk, .de, .fr etc.
            return "country"
        return "other"

    @staticmethod
    def _detect_brand_in_text(text: str) -> bool:
        """Check if any impersonated brand name appears in the given text."""
        text_lower = text.lower()
        return any(brand in text_lower for brand in IMPERSONATED_BRANDS)

    @staticmethod
    def _identify_brand(url: str) -> Optional[str]:
        """Identify which brand (if any) the URL is trying to impersonate."""
        url_lower = url.lower()
        for brand in IMPERSONATED_BRANDS:
            if brand in url_lower:
                return brand
        return None

    @staticmethod
    def _count_suspicious_keywords(url: str) -> int:
        """Count suspicious keywords found in the URL."""
        url_lower = url.lower()
        return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    @staticmethod
    def _is_url_shortener(domain: str) -> bool:
        """Check if the domain is a known URL shortener."""
        shorteners = {
            "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
            "tiny.cc", "rb.gy", "bl.ink", "soo.gd",
        }
        return domain.lower() in shorteners

    @staticmethod
    def _default_features() -> Dict[str, Any]:
        """Return default feature values when extraction fails."""
        return {
            "url_length": 0,
            "domain_length": 0,
            "path_length": 0,
            "subdomain_count": 0,
            "digit_ratio": 0.0,
            "special_char_ratio": 0.0,
            "url_entropy": 0.0,
            "has_ip_address": False,
            "is_punycode": False,
            "tld_category": "unknown",
            "uses_https": False,
            "brand_in_domain": False,
            "suspicious_keyword_count": 0,
            "is_shortened": False,
        }
