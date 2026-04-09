"""Confidence aggregation for multi-model ensemble predictions.

Combines predictions from Random Forest, Gradient Boosting, and BERT
models using configurable weighted averaging with optional calibration.
Produces a final verdict and confidence score.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


@dataclass
class AggregatedPrediction:
    """Result of confidence aggregation across all models."""

    verdict: str
    confidence: float
    risk_level: str
    rf_score: Optional[float]
    gb_score: Optional[float]
    bert_score: Optional[float]
    ensemble_score: float
    model_agreement: float
    contributing_models: int


class ConfidenceAggregator:
    """Aggregate predictions from multiple models into a final verdict.

    Uses configurable weights per model and applies several correction
    factors: model agreement bonus, threat intelligence boost, and
    whitelist overrides.
    """

    def __init__(
        self,
        rf_weight: Optional[float] = None,
        gb_weight: Optional[float] = None,
        bert_weight: Optional[float] = None,
        threshold: Optional[float] = None,
        suspicious_threshold: float = 0.4,
    ):
        self.rf_weight = rf_weight or settings.ENSEMBLE_WEIGHTS_RF
        self.gb_weight = gb_weight or settings.ENSEMBLE_WEIGHTS_GB
        self.bert_weight = bert_weight or settings.ENSEMBLE_WEIGHTS_BERT
        self.threshold = threshold or settings.ML_CONFIDENCE_THRESHOLD
        self.suspicious_threshold = suspicious_threshold

        # Normalize weights to sum to 1
        total = self.rf_weight + self.gb_weight + self.bert_weight
        if total > 0:
            self.rf_weight /= total
            self.gb_weight /= total
            self.bert_weight /= total

    def aggregate(
        self,
        rf_score: Optional[float] = None,
        gb_score: Optional[float] = None,
        bert_score: Optional[float] = None,
        threat_intel_match: bool = False,
        is_whitelisted: bool = False,
    ) -> AggregatedPrediction:
        """Combine model scores into a final prediction.

        Args:
            rf_score: Random Forest phishing probability (0-1).
            gb_score: Gradient Boosting phishing probability (0-1).
            bert_score: BERT phishing probability (0-1).
            threat_intel_match: Whether the URL/domain was found in threat intel.
            is_whitelisted: Whether the domain is in the whitelist.

        Returns:
            AggregatedPrediction with final verdict, confidence, and details.
        """
        # Collect available scores
        scores = []
        weights = []
        contributing = 0

        if rf_score is not None:
            scores.append(rf_score)
            weights.append(self.rf_weight)
            contributing += 1

        if gb_score is not None:
            scores.append(gb_score)
            weights.append(self.gb_weight)
            contributing += 1

        if bert_score is not None:
            scores.append(bert_score)
            weights.append(self.bert_weight)
            contributing += 1

        if not scores:
            # No model predictions available
            return AggregatedPrediction(
                verdict="unknown",
                confidence=0.0,
                risk_level="unknown",
                rf_score=rf_score,
                gb_score=gb_score,
                bert_score=bert_score,
                ensemble_score=0.0,
                model_agreement=0.0,
                contributing_models=0,
            )

        # Normalize weights for available models
        weight_sum = sum(weights)
        weights = [w / weight_sum for w in weights]

        # Weighted average
        ensemble_score = sum(s * w for s, w in zip(scores, weights))

        # Model agreement: how closely the models agree
        model_agreement = self._compute_agreement(scores)

        # Agreement bonus: boost confidence when models strongly agree
        agreement_adjusted = ensemble_score
        if model_agreement > 0.85 and contributing >= 2:
            # Models agree strongly — boost the score toward their consensus
            if ensemble_score > 0.5:
                agreement_adjusted = min(ensemble_score * 1.1, 1.0)
            else:
                agreement_adjusted = max(ensemble_score * 0.9, 0.0)

        # Threat intelligence override
        if threat_intel_match:
            agreement_adjusted = max(agreement_adjusted, 0.85)
            logger.info("Threat intel match boosted score", original=ensemble_score, boosted=agreement_adjusted)

        # Whitelist override
        if is_whitelisted:
            agreement_adjusted = min(agreement_adjusted, 0.1)
            logger.info("Whitelisted domain, score capped", original=ensemble_score, capped=agreement_adjusted)

        # Determine verdict
        verdict = self._determine_verdict(agreement_adjusted)
        risk_level = self._determine_risk_level(verdict, agreement_adjusted)

        final_confidence = self._compute_confidence(
            agreement_adjusted, verdict, model_agreement
        )

        return AggregatedPrediction(
            verdict=verdict,
            confidence=round(final_confidence, 4),
            risk_level=risk_level,
            rf_score=round(rf_score, 4) if rf_score is not None else None,
            gb_score=round(gb_score, 4) if gb_score is not None else None,
            bert_score=round(bert_score, 4) if bert_score is not None else None,
            ensemble_score=round(agreement_adjusted, 4),
            model_agreement=round(model_agreement, 4),
            contributing_models=contributing,
        )

    def aggregate_batch(
        self,
        predictions: List[Dict[str, Optional[float]]],
    ) -> List[AggregatedPrediction]:
        """Aggregate predictions for a batch of URLs."""
        return [
            self.aggregate(
                rf_score=p.get("rf_score"),
                gb_score=p.get("gb_score"),
                bert_score=p.get("bert_score"),
                threat_intel_match=p.get("threat_intel_match", False),
                is_whitelisted=p.get("is_whitelisted", False),
            )
            for p in predictions
        ]

    def _determine_verdict(self, score: float) -> str:
        """Map the ensemble score to a verdict label."""
        if score >= self.threshold:
            return "phishing"
        elif score >= self.suspicious_threshold:
            return "suspicious"
        else:
            return "safe"

    @staticmethod
    def _determine_risk_level(verdict: str, score: float) -> str:
        """Map verdict and score to a risk level."""
        if verdict == "phishing":
            if score >= 0.9:
                return "critical"
            elif score >= 0.75:
                return "high"
            else:
                return "high"
        elif verdict == "suspicious":
            return "medium"
        else:
            return "low"

    @staticmethod
    def _compute_agreement(scores: List[float]) -> float:
        """Compute how closely the models agree (0=total disagreement, 1=perfect agreement)."""
        if len(scores) < 2:
            return 1.0

        std = np.std(scores)
        # Map std to 0-1 range where 0 std = 1.0 agreement
        agreement = max(0.0, 1.0 - 2.0 * std)
        return agreement

    @staticmethod
    def _compute_confidence(
        ensemble_score: float, verdict: str, agreement: float
    ) -> float:
        """Compute the final confidence value.

        Confidence represents how sure we are about the verdict, not
        just the phishing probability.
        """
        if verdict == "phishing":
            # Confidence is how far above threshold we are
            base_confidence = ensemble_score
        elif verdict == "suspicious":
            # Moderate confidence in the suspicious range
            base_confidence = 0.5 + (ensemble_score - 0.4) * 0.5
        else:
            # Confidence in "safe" is based on how far below threshold
            base_confidence = 1.0 - ensemble_score

        # Adjust for model agreement
        confidence = base_confidence * (0.7 + 0.3 * agreement)

        return max(0.0, min(1.0, confidence))

    def update_weights(
        self, rf_weight: float, gb_weight: float, bert_weight: float
    ) -> None:
        """Update model weights (e.g., after evaluating model performance)."""
        total = rf_weight + gb_weight + bert_weight
        self.rf_weight = rf_weight / total
        self.gb_weight = gb_weight / total
        self.bert_weight = bert_weight / total

        logger.info(
            "Aggregator weights updated",
            rf=self.rf_weight,
            gb=self.gb_weight,
            bert=self.bert_weight,
        )
