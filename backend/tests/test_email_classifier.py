"""Tests for the email phishing classifier.

Trains a small model on synthetic email features and validates prediction
output format, verdicts, risk levels, and model persistence.
"""

import random
import tempfile
from pathlib import Path
from typing import Dict

import pytest

from app.ml.email_classifier import EmailClassifier


# ---------------------------------------------------------------------------
# Synthetic data
# ---------------------------------------------------------------------------

def _phishing_email_features() -> Dict:
    return {
        "urgency_score": random.uniform(0.5, 1.0),
        "brand_impersonation_score": random.uniform(0.4, 1.0),
        "link_count": random.randint(2, 10),
        "suspicious_link_count": random.randint(1, 5),
        "unique_domain_count": random.randint(2, 6),
        "subject_length": random.randint(30, 80),
        "subject_all_caps_ratio": random.uniform(0.5, 1.0),
        "subject_urgency_word_count": random.randint(2, 5),
        "body_length": random.randint(200, 1000),
        "body_urgency_tier1_count": random.randint(1, 4),
        "body_urgency_tier2_count": random.randint(1, 3),
        "body_urgency_tier3_count": random.randint(0, 2),
        "html_to_text_ratio": random.uniform(0.0, 0.3),
        "email_risk_score": random.uniform(0.5, 1.0),
        "spf_pass": 0,
        "dkim_pass": 0,
        "dmarc_pass": 0,
        "auth_results_present": 1,
        "sender_name_email_mismatch": 1,
        "sender_is_freemail": random.choice([0, 1]),
        "sender_suspicious_pattern": 1,
        "sender_has_numbers": 1,
        "subject_has_urgency": 1,
        "subject_has_re_fwd": 0,
        "subject_has_special_chars": 1,
        "has_html_body": 1,
        "has_hidden_text": random.choice([0, 1]),
        "has_image_only_body": 0,
        "has_mismatched_urls": 1,
        "has_ip_url": random.choice([0, 1]),
        "has_shortened_url": random.choice([0, 1]),
    }


def _safe_email_features() -> Dict:
    return {
        "urgency_score": random.uniform(0.0, 0.15),
        "brand_impersonation_score": random.uniform(0.0, 0.1),
        "link_count": random.randint(0, 2),
        "suspicious_link_count": 0,
        "unique_domain_count": random.randint(0, 1),
        "subject_length": random.randint(10, 40),
        "subject_all_caps_ratio": random.uniform(0.0, 0.1),
        "subject_urgency_word_count": 0,
        "body_length": random.randint(50, 300),
        "body_urgency_tier1_count": 0,
        "body_urgency_tier2_count": 0,
        "body_urgency_tier3_count": 0,
        "html_to_text_ratio": random.uniform(0.3, 0.8),
        "email_risk_score": random.uniform(0.0, 0.2),
        "spf_pass": 1,
        "dkim_pass": 1,
        "dmarc_pass": 1,
        "auth_results_present": 1,
        "sender_name_email_mismatch": 0,
        "sender_is_freemail": 0,
        "sender_suspicious_pattern": 0,
        "sender_has_numbers": 0,
        "subject_has_urgency": 0,
        "subject_has_re_fwd": 0,
        "subject_has_special_chars": 0,
        "has_html_body": 1,
        "has_hidden_text": 0,
        "has_image_only_body": 0,
        "has_mismatched_urls": 0,
        "has_ip_url": 0,
        "has_shortened_url": 0,
    }


def _generate_email_dataset(n: int = 100):
    features, labels = [], []
    for _ in range(n // 2):
        features.append(_phishing_email_features())
        labels.append(1)
    for _ in range(n // 2):
        features.append(_safe_email_features())
        labels.append(0)
    return features, labels


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def trained_email_clf():
    clf = EmailClassifier()
    features, labels = _generate_email_dataset(200)
    clf.train(features, labels)
    return clf


class TestEmailClassifierTraining:
    def test_train_returns_metrics(self):
        clf = EmailClassifier()
        features, labels = _generate_email_dataset(100)
        metrics = clf.train(features, labels)
        assert "accuracy" in metrics
        assert "f1" in metrics
        assert "auc_roc" in metrics
        assert metrics["accuracy"] > 0.5

    def test_is_ready(self, trained_email_clf):
        assert trained_email_clf.is_ready is True


class TestEmailClassifierPrediction:
    def test_predict_phishing(self, trained_email_clf):
        result = trained_email_clf.predict(_phishing_email_features())
        assert "phishing_score" in result
        assert "verdict" in result
        assert "risk_level" in result
        assert result["verdict"] in ("phishing", "suspicious", "safe", "unknown")

    def test_predict_safe(self, trained_email_clf):
        result = trained_email_clf.predict(_safe_email_features())
        assert result["verdict"] in ("safe", "suspicious", "phishing")

    def test_predict_batch(self, trained_email_clf):
        batch = [_phishing_email_features(), _safe_email_features()]
        results = trained_email_clf.predict_batch(batch)
        assert len(results) == 2

    def test_untrained_returns_default(self):
        clf = EmailClassifier()
        result = clf.predict(_safe_email_features())
        assert result["verdict"] == "unknown"
        assert result["confidence"] == 0.5

    def test_risk_level_values(self, trained_email_clf):
        result = trained_email_clf.predict(_phishing_email_features())
        assert result["risk_level"] in ("critical", "high", "medium", "low", "unknown")


class TestEmailFeatureImportance:
    def test_feature_importance_list(self, trained_email_clf):
        importance = trained_email_clf.get_feature_importance(top_n=10)
        assert len(importance) <= 10

    def test_empty_when_untrained(self):
        clf = EmailClassifier()
        assert clf.get_feature_importance() == []


class TestEmailModelPersistence:
    def test_save_and_load(self, trained_email_clf):
        with tempfile.TemporaryDirectory() as tmpdir:
            trained_email_clf.save(path=tmpdir)
            assert (Path(tmpdir) / "email_classifier.joblib").exists()

            new_clf = EmailClassifier()
            new_clf.load(path=tmpdir)
            assert new_clf.is_ready is True

            result = new_clf.predict(_phishing_email_features())
            assert result["verdict"] in ("phishing", "suspicious", "safe", "unknown")
