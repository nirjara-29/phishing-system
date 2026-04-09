"""Tests for email feature extraction.

Covers SPF/DKIM/DMARC parsing, urgency keyword detection, brand
impersonation scoring, URL extraction from email bodies, and
sender analysis.
"""

import pytest

from app.features.email_features import (
    EmailFeatureExtractor,
    URGENCY_KEYWORDS,
    BRAND_PATTERNS,
)


@pytest.fixture
def extractor():
    return EmailFeatureExtractor()


# ---------------------------------------------------------------------------
# SPF / DKIM / DMARC authentication parsing
# ---------------------------------------------------------------------------

class TestAuthenticationParsing:
    def test_all_pass(self, extractor):
        headers = {
            "authentication-results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
        }
        features = extractor._analyze_authentication(headers)
        assert features["spf_result"] == "pass"
        assert features["dkim_result"] == "pass"
        assert features["dmarc_result"] == "pass"
        assert features["auth_results_present"] is True

    def test_all_fail(self, extractor):
        headers = {
            "authentication-results": "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
        }
        features = extractor._analyze_authentication(headers)
        assert features["spf_result"] == "fail"
        assert features["dkim_result"] == "fail"
        assert features["dmarc_result"] == "fail"

    def test_softfail(self, extractor):
        headers = {
            "authentication-results": "mx.example.com; spf=softfail; dkim=none; dmarc=none"
        }
        features = extractor._analyze_authentication(headers)
        assert features["spf_result"] == "softfail"
        assert features["dkim_result"] == "none"

    def test_received_spf_header_fallback(self, extractor):
        headers = {"received-spf": "Pass (domain of example.com)"}
        features = extractor._analyze_authentication(headers)
        assert features["spf_result"] == "pass"

    def test_no_auth_headers(self, extractor):
        features = extractor._analyze_authentication({})
        assert features["spf_result"] == "none"
        assert features["dkim_result"] == "none"
        assert features["dmarc_result"] == "none"
        assert features["auth_results_present"] is False

    def test_dkim_signature_present(self, extractor):
        headers = {"dkim-signature": "v=1; a=rsa-sha256; d=example.com"}
        features = extractor._analyze_authentication(headers)
        # Should detect DKIM is at least present
        assert features["dkim_result"] in ("present", "none")


# ---------------------------------------------------------------------------
# Urgency detection
# ---------------------------------------------------------------------------

class TestUrgencyDetection:
    def test_tier1_urgency(self, extractor):
        features = extractor._analyze_body(
            "Your account has been compromised. Immediate action required within 24 hours.",
            ""
        )
        assert features["body_urgency_tier1_count"] >= 2

    def test_tier2_urgency(self, extractor):
        features = extractor._analyze_body(
            "We detected unusual activity on your account. Please verify your account.",
            ""
        )
        assert features["body_urgency_tier2_count"] >= 2

    def test_tier3_urgency(self, extractor):
        features = extractor._analyze_body(
            "Important notice: action required. Please click the link below.",
            ""
        )
        assert features["body_urgency_tier3_count"] >= 2

    def test_no_urgency(self, extractor):
        features = extractor._analyze_body(
            "Thank you for your recent purchase. Your order has shipped.",
            ""
        )
        assert features["body_urgency_tier1_count"] == 0
        assert features["body_urgency_tier2_count"] == 0

    def test_urgency_score_computation(self, extractor):
        features = {
            "body_urgency_tier1_count": 3,
            "body_urgency_tier2_count": 2,
            "body_urgency_tier3_count": 1,
            "subject_urgency_word_count": 2,
            "subject_all_caps_ratio": 0.8,
            "subject_has_special_chars": True,
        }
        score = extractor._compute_urgency_score(features)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # should be high given all the urgency


# ---------------------------------------------------------------------------
# Brand impersonation scoring
# ---------------------------------------------------------------------------

class TestBrandImpersonation:
    def test_paypal_impersonation(self, extractor):
        features = extractor._score_brand_impersonation(
            sender="security@paypa1-alerts.tk",
            subject="PayPal Account Alert",
            body="Your paypal account needs verification at paypal.com",
        )
        assert features["brand_impersonation_score"] > 0.3
        assert features["impersonated_brand"] == "paypal"

    def test_microsoft_impersonation(self, extractor):
        features = extractor._score_brand_impersonation(
            sender="support@micr0soft-help.xyz",
            subject="Microsoft Office 365 Security Alert",
            body="Your microsoft.com account has been compromised",
        )
        assert features["brand_impersonation_score"] > 0.3
        assert features["impersonated_brand"] == "microsoft"

    def test_no_brand_impersonation(self, extractor):
        features = extractor._score_brand_impersonation(
            sender="john@personalsite.com",
            subject="Meeting Tomorrow",
            body="Hey, just wanted to confirm our meeting time.",
        )
        assert features["brand_impersonation_score"] == 0.0
        assert features["impersonated_brand"] is None

    def test_brand_score_capped_at_one(self, extractor):
        features = extractor._score_brand_impersonation(
            sender="apple-support@apple-verify.tk",
            subject="Apple ID Security - iCloud Alert",
            body="Visit apple.com to verify your Apple ID and iCloud account",
        )
        assert features["brand_impersonation_score"] <= 1.0


# ---------------------------------------------------------------------------
# Sender analysis
# ---------------------------------------------------------------------------

class TestSenderAnalysis:
    def test_freemail_detected(self, extractor):
        features = extractor._analyze_sender("John Doe <john@gmail.com>")
        assert features["sender_is_freemail"] is True

    def test_corporate_email(self, extractor):
        features = extractor._analyze_sender("Jane <jane@company.com>")
        assert features["sender_is_freemail"] is False

    def test_display_name_domain_mismatch(self, extractor):
        features = extractor._analyze_sender("security@paypal.com <fake@evil.tk>")
        assert features["sender_name_email_mismatch"] is True

    def test_empty_sender(self, extractor):
        features = extractor._analyze_sender("")
        assert features["sender_domain"] == ""


# ---------------------------------------------------------------------------
# Subject analysis
# ---------------------------------------------------------------------------

class TestSubjectAnalysis:
    def test_subject_urgency(self, extractor):
        features = extractor._analyze_subject("URGENT: Your account will be closed")
        assert features["subject_has_urgency"] is True
        assert features["subject_urgency_word_count"] >= 1

    def test_subject_re_fwd(self, extractor):
        features = extractor._analyze_subject("Re: Follow-up on proposal")
        assert features["subject_has_re_fwd"] is True

    def test_subject_all_caps(self, extractor):
        features = extractor._analyze_subject("VERIFY YOUR ACCOUNT NOW")
        assert features["subject_all_caps_ratio"] > 0.8


# ---------------------------------------------------------------------------
# URL extraction from body
# ---------------------------------------------------------------------------

class TestURLExtraction:
    def test_extract_urls(self, extractor):
        text = "Visit https://evil.tk/login or http://phish.ml/verify for details."
        features = extractor._extract_and_analyze_urls(text)
        assert features["link_count"] == 2
        assert features["suspicious_link_count"] >= 1

    def test_ip_based_url(self, extractor):
        text = "Click http://192.168.1.1/phish to verify."
        features = extractor._extract_and_analyze_urls(text)
        assert features["has_ip_url"] is True

    def test_shortened_url(self, extractor):
        text = "See details: https://bit.ly/xyz123"
        features = extractor._extract_and_analyze_urls(text)
        assert features["has_shortened_url"] is True


# ---------------------------------------------------------------------------
# Full pipeline with raw email
# ---------------------------------------------------------------------------

class TestFullEmailExtraction:
    def test_phishing_email_raw(self, extractor, phishing_email_raw):
        features = extractor.extract(raw_email=phishing_email_raw)
        assert features["spf_result"] == "fail"
        assert features["urgency_score"] > 0.2
        assert features["brand_impersonation_score"] > 0.0
        assert features["email_risk_score"] > 0.3

    def test_safe_email_raw(self, extractor, safe_email_raw):
        features = extractor.extract(raw_email=safe_email_raw)
        assert features["spf_result"] == "pass"
        assert features["urgency_score"] < 0.3
        assert features["email_risk_score"] < 0.4

    def test_kwargs_mode(self, extractor):
        features = extractor.extract(
            sender="test@example.com",
            subject="Hello World",
            body_text="Just a regular email with no threats.",
            body_html="",
            headers={},
        )
        assert isinstance(features, dict)
        assert features["urgency_score"] < 0.2
