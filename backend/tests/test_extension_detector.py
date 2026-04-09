"""Tests for the extension detector's post-ML decision rules."""

from app.extension_detector.model import URLPhishingDetector


class TestExtensionDetectorRules:
    def test_safe_verdict_always_maps_to_low_risk(self):
        assert URLPhishingDetector._risk_level("safe", 0.99) == "low"

    def test_suspicious_verdict_always_maps_to_medium_risk(self):
        assert URLPhishingDetector._risk_level("suspicious", 0.2) == "medium"

    def test_phishing_risk_level_uses_confidence_bands(self):
        assert URLPhishingDetector._risk_level("phishing", 0.9) == "high"
        assert URLPhishingDetector._risk_level("phishing", 0.7) == "medium"
        assert URLPhishingDetector._risk_level("phishing", 0.4) == "low"

    def test_safe_low_confidence_with_signal_becomes_suspicious(self):
        verdict = URLPhishingDetector._apply_rule_overrides("safe", 0.75, ["keyword"])
        assert verdict == "suspicious"

    def test_multiple_signals_force_phishing(self):
        verdict = URLPhishingDetector._apply_rule_overrides(
            "safe",
            0.76,
            ["keyword", "suspicious_tld"],
        )
        assert verdict == "phishing"

    def test_brand_domain_signal_detects_unusual_paypal_domain(self):
        assert URLPhishingDetector._has_unusual_brand_domain("paypal-secure-login.xyz") is True
        assert URLPhishingDetector._has_unusual_brand_domain("www.paypal.com") is False
