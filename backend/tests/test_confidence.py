"""Tests for the confidence aggregation module.

Validates weighted ensemble scoring, model agreement calculation,
threat intelligence overrides, whitelist suppression, verdict mapping,
and risk level determination.
"""

import pytest
import numpy as np

from app.ml.confidence_aggregator import ConfidenceAggregator, AggregatedPrediction


@pytest.fixture
def aggregator():
    return ConfidenceAggregator(
        rf_weight=0.3, gb_weight=0.3, bert_weight=0.4, threshold=0.7
    )


# ---------------------------------------------------------------------------
# Basic aggregation
# ---------------------------------------------------------------------------

class TestBasicAggregation:
    def test_all_models_high_scores(self, aggregator):
        result = aggregator.aggregate(rf_score=0.9, gb_score=0.85, bert_score=0.92)
        assert isinstance(result, AggregatedPrediction)
        assert result.verdict == "phishing"
        assert result.confidence > 0.7
        assert result.contributing_models == 3

    def test_all_models_low_scores(self, aggregator):
        result = aggregator.aggregate(rf_score=0.1, gb_score=0.05, bert_score=0.12)
        assert result.verdict == "safe"
        assert result.risk_level == "low"

    def test_mixed_scores_suspicious(self, aggregator):
        result = aggregator.aggregate(rf_score=0.5, gb_score=0.45, bert_score=0.55)
        assert result.verdict in ("suspicious", "safe")

    def test_single_model_available(self, aggregator):
        result = aggregator.aggregate(rf_score=0.9, gb_score=None, bert_score=None)
        assert result.verdict == "phishing"
        assert result.contributing_models == 1

    def test_no_models_available(self, aggregator):
        result = aggregator.aggregate(rf_score=None, gb_score=None, bert_score=None)
        assert result.verdict == "unknown"
        assert result.confidence == 0.0
        assert result.contributing_models == 0

    def test_two_models_available(self, aggregator):
        result = aggregator.aggregate(rf_score=0.8, gb_score=0.85, bert_score=None)
        assert result.contributing_models == 2
        assert result.verdict == "phishing"


# ---------------------------------------------------------------------------
# Model agreement
# ---------------------------------------------------------------------------

class TestModelAgreement:
    def test_perfect_agreement(self, aggregator):
        result = aggregator.aggregate(rf_score=0.9, gb_score=0.9, bert_score=0.9)
        assert result.model_agreement == 1.0

    def test_high_disagreement(self, aggregator):
        result = aggregator.aggregate(rf_score=0.1, gb_score=0.9, bert_score=0.5)
        assert result.model_agreement < 0.5

    def test_compute_agreement_two_scores(self):
        agreement = ConfidenceAggregator._compute_agreement([0.5, 0.5])
        assert agreement == 1.0

    def test_compute_agreement_single_score(self):
        agreement = ConfidenceAggregator._compute_agreement([0.8])
        assert agreement == 1.0

    def test_agreement_bonus_applied(self, aggregator):
        # When models strongly agree on phishing
        result = aggregator.aggregate(rf_score=0.85, gb_score=0.87, bert_score=0.86)
        assert result.ensemble_score >= 0.85  # should get agreement boost


# ---------------------------------------------------------------------------
# Threat intelligence override
# ---------------------------------------------------------------------------

class TestThreatIntelOverride:
    def test_threat_intel_boosts_score(self, aggregator):
        normal = aggregator.aggregate(rf_score=0.3, gb_score=0.3, bert_score=0.3)
        boosted = aggregator.aggregate(
            rf_score=0.3, gb_score=0.3, bert_score=0.3, threat_intel_match=True
        )
        assert boosted.ensemble_score >= 0.85
        assert boosted.verdict == "phishing"
        assert normal.verdict != "phishing"

    def test_threat_intel_already_high(self, aggregator):
        result = aggregator.aggregate(
            rf_score=0.95, gb_score=0.95, bert_score=0.95, threat_intel_match=True
        )
        assert result.verdict == "phishing"
        assert result.ensemble_score >= 0.85


# ---------------------------------------------------------------------------
# Whitelist override
# ---------------------------------------------------------------------------

class TestWhitelistOverride:
    def test_whitelist_suppresses_score(self, aggregator):
        result = aggregator.aggregate(
            rf_score=0.9, gb_score=0.9, bert_score=0.9, is_whitelisted=True
        )
        assert result.ensemble_score <= 0.1
        assert result.verdict == "safe"

    def test_whitelist_overrides_threat_intel(self, aggregator):
        result = aggregator.aggregate(
            rf_score=0.9, gb_score=0.9, bert_score=0.9,
            threat_intel_match=True, is_whitelisted=True,
        )
        # Whitelist is applied after threat intel boost
        assert result.ensemble_score <= 0.1


# ---------------------------------------------------------------------------
# Verdict and risk level
# ---------------------------------------------------------------------------

class TestVerdictMapping:
    def test_phishing_verdict(self, aggregator):
        verdict = aggregator._determine_verdict(0.85)
        assert verdict == "phishing"

    def test_suspicious_verdict(self, aggregator):
        verdict = aggregator._determine_verdict(0.55)
        assert verdict == "suspicious"

    def test_safe_verdict(self, aggregator):
        verdict = aggregator._determine_verdict(0.2)
        assert verdict == "safe"

    def test_risk_level_critical(self):
        level = ConfidenceAggregator._determine_risk_level("phishing", 0.95)
        assert level == "critical"

    def test_risk_level_high(self):
        level = ConfidenceAggregator._determine_risk_level("phishing", 0.8)
        assert level == "high"

    def test_risk_level_medium(self):
        level = ConfidenceAggregator._determine_risk_level("suspicious", 0.5)
        assert level == "medium"

    def test_risk_level_low(self):
        level = ConfidenceAggregator._determine_risk_level("safe", 0.1)
        assert level == "low"


# ---------------------------------------------------------------------------
# Batch aggregation
# ---------------------------------------------------------------------------

class TestBatchAggregation:
    def test_batch_aggregation(self, aggregator):
        predictions = [
            {"rf_score": 0.9, "gb_score": 0.85, "bert_score": 0.88},
            {"rf_score": 0.1, "gb_score": 0.15, "bert_score": 0.08},
        ]
        results = aggregator.aggregate_batch(predictions)
        assert len(results) == 2
        assert results[0].verdict == "phishing"
        assert results[1].verdict == "safe"


# ---------------------------------------------------------------------------
# Weight updating
# ---------------------------------------------------------------------------

class TestWeightUpdating:
    def test_update_weights(self, aggregator):
        aggregator.update_weights(0.5, 0.3, 0.2)
        total = aggregator.rf_weight + aggregator.gb_weight + aggregator.bert_weight
        assert abs(total - 1.0) < 0.001
