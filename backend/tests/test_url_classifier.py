"""Tests for the URL phishing classifier (Random Forest + Gradient Boosting ensemble).

Uses synthetic feature data to train a small model and verify prediction
format, ensemble scoring, feature importance, and model persistence.
"""

import os
import random
import tempfile
from pathlib import Path
from typing import Dict, List

import numpy as np
import pytest

from app.ml.url_classifier import URLClassifier
from app.ml.preprocessor import FeaturePreprocessor, URL_NUMERIC_FEATURES, URL_BOOLEAN_FEATURES


# ---------------------------------------------------------------------------
# Synthetic data helpers
# ---------------------------------------------------------------------------

def _make_phishing_features() -> Dict:
    """Generate a synthetic phishing-like feature dictionary."""
    return {
        "url_length": random.randint(80, 200),
        "domain_length": random.randint(20, 60),
        "path_length": random.randint(20, 80),
        "query_length": random.randint(10, 60),
        "hostname_length": random.randint(15, 50),
        "subdomain_count": random.randint(2, 6),
        "subdomain_length": random.randint(10, 40),
        "path_depth": random.randint(3, 8),
        "digit_ratio": random.uniform(0.15, 0.4),
        "letter_ratio": random.uniform(0.3, 0.5),
        "special_char_ratio": random.uniform(0.15, 0.35),
        "uppercase_ratio": random.uniform(0.0, 0.1),
        "url_entropy": random.uniform(4.0, 5.5),
        "domain_entropy": random.uniform(3.5, 5.0),
        "path_entropy": random.uniform(3.0, 4.5),
        "suspicious_keyword_count": random.randint(2, 5),
        "dash_count_in_domain": random.randint(2, 5),
        "dot_count_in_url": random.randint(4, 8),
        "domain_age_days": random.randint(-1, 30),
        "expiration_days": random.randint(10, 90),
        "has_ip_address": random.choice([True, False]),
        "is_punycode": random.choice([True, False]),
        "is_suspicious_tld": True,
        "uses_https": False,
        "brand_in_domain": True,
        "has_login_form": True,
        "external_resource_ratio": random.uniform(0.5, 0.9),
        "brand_similarity_score": random.uniform(0.5, 1.0),
    }


def _make_safe_features() -> Dict:
    """Generate a synthetic safe-like feature dictionary."""
    return {
        "url_length": random.randint(20, 60),
        "domain_length": random.randint(5, 15),
        "path_length": random.randint(1, 20),
        "query_length": random.randint(0, 10),
        "hostname_length": random.randint(5, 15),
        "subdomain_count": random.randint(0, 1),
        "subdomain_length": random.randint(0, 5),
        "path_depth": random.randint(0, 2),
        "digit_ratio": random.uniform(0.0, 0.05),
        "letter_ratio": random.uniform(0.6, 0.85),
        "special_char_ratio": random.uniform(0.05, 0.15),
        "uppercase_ratio": random.uniform(0.0, 0.05),
        "url_entropy": random.uniform(2.5, 3.5),
        "domain_entropy": random.uniform(2.0, 3.0),
        "path_entropy": random.uniform(1.0, 2.5),
        "suspicious_keyword_count": 0,
        "dash_count_in_domain": random.randint(0, 1),
        "dot_count_in_url": random.randint(1, 3),
        "domain_age_days": random.randint(365, 5000),
        "expiration_days": random.randint(365, 3650),
        "has_ip_address": False,
        "is_punycode": False,
        "is_suspicious_tld": False,
        "uses_https": True,
        "brand_in_domain": False,
        "has_login_form": False,
        "external_resource_ratio": random.uniform(0.0, 0.2),
        "brand_similarity_score": random.uniform(0.0, 0.1),
    }


def _generate_dataset(n: int = 100):
    """Return feature_dicts and labels for training."""
    feature_dicts = []
    labels = []
    for _ in range(n // 2):
        feature_dicts.append(_make_phishing_features())
        labels.append(1)
    for _ in range(n // 2):
        feature_dicts.append(_make_safe_features())
        labels.append(0)
    return feature_dicts, labels


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def trained_classifier():
    """Train a classifier once for the module."""
    clf = URLClassifier(rf_weight=0.5, gb_weight=0.5)
    features, labels = _generate_dataset(200)
    clf.train(features, labels, calibrate=False)
    return clf


class TestURLClassifierTraining:
    def test_train_returns_metrics(self):
        clf = URLClassifier()
        features, labels = _generate_dataset(100)
        metrics = clf.train(features, labels, calibrate=False)
        assert "ensemble_accuracy" in metrics
        assert "ensemble_f1" in metrics
        assert "ensemble_auc" in metrics
        assert metrics["ensemble_accuracy"] > 0.5

    def test_is_ready_after_training(self, trained_classifier):
        assert trained_classifier.is_ready is True

    def test_is_not_ready_before_training(self):
        clf = URLClassifier()
        assert clf.is_ready is False


class TestURLClassifierPrediction:
    def test_predict_phishing(self, trained_classifier):
        result = trained_classifier.predict(_make_phishing_features())
        assert "rf_score" in result
        assert "gb_score" in result
        assert "ensemble_score" in result
        assert "prediction" in result
        assert "confidence" in result
        assert "label" in result
        assert result["prediction"] in (0, 1)

    def test_predict_safe(self, trained_classifier):
        result = trained_classifier.predict(_make_safe_features())
        assert result["prediction"] in (0, 1)

    def test_predict_batch(self, trained_classifier):
        batch = [_make_phishing_features(), _make_safe_features()]
        results = trained_classifier.predict_batch(batch)
        assert len(results) == 2
        for r in results:
            assert 0.0 <= r["rf_score"] <= 1.0
            assert 0.0 <= r["gb_score"] <= 1.0

    def test_untrained_returns_default(self):
        clf = URLClassifier()
        result = clf.predict(_make_safe_features())
        assert result["label"] == "unknown"
        assert result["confidence"] == 0.5


class TestFeatureImportance:
    def test_feature_importance_list(self, trained_classifier):
        importance = trained_classifier.get_feature_importance(top_n=10)
        assert len(importance) <= 10
        assert all(isinstance(pair, tuple) and len(pair) == 2 for pair in importance)

    def test_feature_importance_sorted_descending(self, trained_classifier):
        importance = trained_classifier.get_feature_importance(top_n=20)
        values = [v for _, v in importance]
        assert values == sorted(values, reverse=True)


class TestModelPersistence:
    def test_save_and_load(self, trained_classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            trained_classifier.save(path=tmpdir)
            assert (Path(tmpdir) / "url_classifier.joblib").exists()

            new_clf = URLClassifier()
            assert new_clf.is_ready is False
            new_clf.load(path=tmpdir)
            assert new_clf.is_ready is True

            result = new_clf.predict(_make_phishing_features())
            assert result["prediction"] in (0, 1)

    def test_load_missing_file(self):
        clf = URLClassifier()
        clf.load(path="/tmp/nonexistent_model_dir_phishnet")
        assert clf.is_ready is False
