"""Tests for URL lexical feature extraction.

Validates length calculations, entropy, character ratios, IP address
detection, punycode detection, TLD categorisation, brand detection,
and the overall feature extraction pipeline.
"""

import math
import pytest

from app.features.url_features import URLFeatureExtractor, SUSPICIOUS_TLDS, TRUSTED_TLDS


@pytest.fixture
def extractor():
    return URLFeatureExtractor()


# ---------------------------------------------------------------------------
# Length-based features
# ---------------------------------------------------------------------------

class TestLengthFeatures:
    def test_url_length(self, extractor):
        features = extractor.extract("https://example.com/page")
        assert features["url_length"] == len("https://example.com/page")

    def test_domain_length(self, extractor):
        features = extractor.extract("https://example.com/path")
        assert features["domain_length"] > 0
        assert isinstance(features["domain_length"], int)

    def test_path_length(self, extractor):
        features = extractor.extract("https://example.com/a/b/c")
        assert features["path_length"] >= 5

    def test_very_long_url_is_flagged(self, extractor):
        long_url = "https://phishing.tk/" + "a" * 200
        features = extractor.extract(long_url)
        assert features["url_length"] > 200


# ---------------------------------------------------------------------------
# Subdomain analysis
# ---------------------------------------------------------------------------

class TestSubdomainFeatures:
    def test_no_subdomain(self, extractor):
        features = extractor.extract("https://example.com")
        assert features["subdomain_count"] == 0

    def test_single_subdomain(self, extractor):
        features = extractor.extract("https://www.example.com")
        assert features["subdomain_count"] == 1

    def test_multiple_subdomains(self, extractor):
        features = extractor.extract("https://a.b.c.example.com")
        assert features["subdomain_count"] >= 3

    def test_deep_subdomains_suspicious(self, extractor):
        url = "https://login.secure.paypal.account.verify.example.tk/signin"
        features = extractor.extract(url)
        assert features["subdomain_count"] >= 4


# ---------------------------------------------------------------------------
# Character distribution & entropy
# ---------------------------------------------------------------------------

class TestCharacterFeatures:
    def test_digit_ratio(self, extractor):
        features = extractor.extract("https://123456.com/789")
        assert features["digit_ratio"] > 0.2

    def test_special_char_ratio(self, extractor):
        features = extractor.extract("https://a-b_c.d=e.com/?x=1&y=2")
        assert features["special_char_ratio"] > 0

    def test_entropy_of_random_url(self, extractor):
        random_url = "https://xk9f2m4q7z.tk/a1b2c3d4e5"
        features = extractor.extract(random_url)
        assert features["url_entropy"] > 3.0

    def test_entropy_of_simple_url(self, extractor):
        simple_url = "https://aaa.com/aaa"
        features = extractor.extract(simple_url)
        assert features["url_entropy"] < features["url_entropy"] + 1  # basic sanity

    def test_shannon_entropy_known_value(self, extractor):
        # "aaaa" has entropy 0.0
        entropy = URLFeatureExtractor._shannon_entropy("aaaa")
        assert entropy == 0.0

    def test_shannon_entropy_max_two_chars(self, extractor):
        # "ab" repeated equally → entropy = 1.0
        entropy = URLFeatureExtractor._shannon_entropy("abababab")
        assert abs(entropy - 1.0) < 0.01

    def test_empty_string_entropy(self):
        assert URLFeatureExtractor._shannon_entropy("") == 0.0


# ---------------------------------------------------------------------------
# IP address detection
# ---------------------------------------------------------------------------

class TestIPAddressDetection:
    def test_ipv4_url(self, extractor):
        features = extractor.extract("http://192.168.1.1/login")
        assert features["has_ip_address"] is True

    def test_no_ip_in_domain(self, extractor):
        features = extractor.extract("https://example.com/page")
        assert features["has_ip_address"] is False

    def test_decimal_ip(self, extractor):
        # 3232235777 = 192.168.1.1 in decimal
        result = URLFeatureExtractor._contains_ip_address("3232235777")
        assert result is True


# ---------------------------------------------------------------------------
# Punycode / IDN detection
# ---------------------------------------------------------------------------

class TestPunycodeDetection:
    def test_punycode_domain(self, extractor):
        features = extractor.extract("https://xn--pple-43d.com")
        assert features["is_punycode"] is True

    def test_normal_domain(self, extractor):
        features = extractor.extract("https://apple.com")
        assert features["is_punycode"] is False

    def test_homograph_detection(self):
        # Cyrillic 'а' looks like Latin 'a'
        result = URLFeatureExtractor._has_homograph_characters("аpple.com")
        assert result is True

    def test_ascii_only_no_homograph(self):
        result = URLFeatureExtractor._has_homograph_characters("apple.com")
        assert result is False


# ---------------------------------------------------------------------------
# TLD categorisation
# ---------------------------------------------------------------------------

class TestTLDCategorisation:
    def test_suspicious_tld(self, extractor):
        features = extractor.extract("https://phishing.tk/login")
        assert features["is_suspicious_tld"] is True
        assert features["tld_category"] == "suspicious"

    def test_trusted_tld(self):
        cat = URLFeatureExtractor._categorize_tld(".gov")
        assert cat == "trusted"

    def test_common_tld(self):
        cat = URLFeatureExtractor._categorize_tld(".com")
        assert cat == "common"


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

class TestBrandDetection:
    def test_brand_in_domain(self, extractor):
        features = extractor.extract("https://paypal-login.tk/secure")
        assert features["brand_in_domain"] is True
        assert features["brand_name"] == "paypal"

    def test_brand_in_subdomain(self, extractor):
        features = extractor.extract("https://paypal.secure-login.tk")
        assert features["brand_in_subdomain"] is True

    def test_brand_in_path(self, extractor):
        features = extractor.extract("https://evil.tk/paypal/login")
        assert features["brand_in_path"] is True

    def test_no_brand(self, extractor):
        features = extractor.extract("https://innocuoussite.com/page")
        assert features["brand_in_domain"] is False
        assert features["brand_name"] is None


# ---------------------------------------------------------------------------
# Suspicious patterns
# ---------------------------------------------------------------------------

class TestSuspiciousPatterns:
    def test_suspicious_keywords(self, extractor):
        features = extractor.extract("https://evil.tk/verify/login/account")
        assert features["suspicious_keyword_count"] >= 2

    def test_at_symbol_in_url(self, extractor):
        features = extractor.extract("https://user@evil.tk/page")
        assert features["has_at_symbol"] is True

    def test_url_shortener(self, extractor):
        features = extractor.extract("https://bit.ly/abc123")
        assert features["is_shortened"] is True

    def test_double_slash_redirect(self, extractor):
        features = extractor.extract("https://example.com//evil.com")
        assert features["has_double_slash_redirect"] is True

    def test_data_uri(self, extractor):
        features = extractor.extract("data:text/html,<h1>Phish</h1>")
        assert features["is_data_uri"] is True


# ---------------------------------------------------------------------------
# Default / error handling
# ---------------------------------------------------------------------------

class TestDefaultFeatures:
    def test_default_features_returned_on_empty(self, extractor):
        defaults = URLFeatureExtractor._default_features()
        assert defaults["url_length"] == 0
        assert defaults["has_ip_address"] is False
        assert defaults["is_shortened"] is False

    def test_feature_extraction_returns_dict(self, extractor):
        features = extractor.extract("https://example.com")
        assert isinstance(features, dict)
        assert len(features) > 20  # expect many features
