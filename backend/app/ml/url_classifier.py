"""URL phishing classifier using Random Forest and Gradient Boosting ensemble.

Trains and serves an ensemble of tree-based classifiers on URL features.
The ensemble combines predictions from both models using weighted averaging
for more robust classification than either model alone.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import structlog
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from app.config import settings
from app.ml.preprocessor import FeaturePreprocessor, create_url_preprocessor

logger = structlog.get_logger(__name__)


class URLClassifier:
    """Ensemble URL phishing classifier combining Random Forest and Gradient Boosting.

    Provides a unified interface for training, prediction, and model
    persistence. Both models are probability-calibrated for reliable
    confidence scores.
    """

    def __init__(
        self,
        rf_params: Optional[Dict[str, Any]] = None,
        gb_params: Optional[Dict[str, Any]] = None,
        rf_weight: float = 0.5,
        gb_weight: float = 0.5,
    ):
        # Random Forest configuration
        self.rf_params = rf_params or {
            "n_estimators": 200,
            "max_depth": 20,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "max_features": "sqrt",
            "class_weight": "balanced",
            "n_jobs": -1,
            "random_state": 42,
        }

        # Gradient Boosting configuration
        self.gb_params = gb_params or {
            "n_estimators": 150,
            "max_depth": 6,
            "learning_rate": 0.1,
            "min_samples_split": 5,
            "min_samples_leaf": 3,
            "subsample": 0.8,
            "max_features": "sqrt",
            "random_state": 42,
        }

        self.rf_weight = rf_weight
        self.gb_weight = gb_weight

        self._rf_model: Optional[CalibratedClassifierCV] = None
        self._gb_model: Optional[CalibratedClassifierCV] = None
        self._preprocessor: FeaturePreprocessor = create_url_preprocessor()
        self._is_trained = False

        # Feature importance tracking
        self._rf_importances: Optional[np.ndarray] = None
        self._gb_importances: Optional[np.ndarray] = None

    @property
    def is_ready(self) -> bool:
        return self._is_trained

    def train(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
        calibrate: bool = True,
    ) -> Dict[str, float]:
        """Train both models on the provided feature dictionaries.

        Args:
            feature_dicts: List of feature dictionaries from URL extraction.
            labels: Binary labels (0=safe, 1=phishing).
            calibrate: Whether to calibrate probabilities using cross-validation.

        Returns:
            Dictionary of training metrics.
        """
        logger.info("Training URL classifier", samples=len(labels))

        # Preprocess features
        X = self._preprocessor.fit_transform(feature_dicts)
        y = np.array(labels)

        # Train Random Forest
        logger.info("Training Random Forest", params=self.rf_params)
        rf = RandomForestClassifier(**self.rf_params)
        if calibrate:
            self._rf_model = CalibratedClassifierCV(rf, cv=5, method="isotonic")
        else:
            self._rf_model = CalibratedClassifierCV(rf, cv=3, method="sigmoid")
        self._rf_model.fit(X, y)

        # Store feature importances from the base estimator
        self._rf_importances = np.mean(
            [est.feature_importances_ for est in self._rf_model.calibrated_classifiers_],
            axis=0,
        ) if hasattr(self._rf_model, "calibrated_classifiers_") else None

        # Train Gradient Boosting
        logger.info("Training Gradient Boosting", params=self.gb_params)
        gb = GradientBoostingClassifier(**self.gb_params)
        if calibrate:
            self._gb_model = CalibratedClassifierCV(gb, cv=5, method="isotonic")
        else:
            self._gb_model = CalibratedClassifierCV(gb, cv=3, method="sigmoid")
        self._gb_model.fit(X, y)

        self._gb_importances = np.mean(
            [est.feature_importances_ for est in self._gb_model.calibrated_classifiers_],
            axis=0,
        ) if hasattr(self._gb_model, "calibrated_classifiers_") else None

        self._is_trained = True

        # Compute training metrics
        metrics = self._evaluate(X, y)
        logger.info("URL classifier training complete", metrics=metrics)
        return metrics

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Predict phishing probability for a single URL.

        Returns:
            Dictionary with 'rf_score', 'gb_score', 'ensemble_score',
            'prediction' (0 or 1), and 'confidence'.
        """
        if not self._is_trained:
            logger.warning("URL classifier not trained, returning default")
            return self._default_prediction()

        X = self._preprocessor.transform_single(feature_dict).reshape(1, -1)

        # Get probability scores from each model
        rf_proba = self._rf_model.predict_proba(X)[0]
        gb_proba = self._gb_model.predict_proba(X)[0]

        rf_phishing_score = float(rf_proba[1])
        gb_phishing_score = float(gb_proba[1])

        # Weighted ensemble
        ensemble_score = (
            self.rf_weight * rf_phishing_score
            + self.gb_weight * gb_phishing_score
        )

        prediction = 1 if ensemble_score >= settings.ML_CONFIDENCE_THRESHOLD else 0

        return {
            "rf_score": round(rf_phishing_score, 4),
            "gb_score": round(gb_phishing_score, 4),
            "ensemble_score": round(ensemble_score, 4),
            "prediction": prediction,
            "confidence": round(ensemble_score if prediction == 1 else 1 - ensemble_score, 4),
            "label": "phishing" if prediction == 1 else "safe",
        }

    def predict_batch(
        self, feature_dicts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Predict phishing probabilities for a batch of URLs."""
        if not self._is_trained:
            return [self._default_prediction() for _ in feature_dicts]

        X = self._preprocessor.transform(feature_dicts)

        rf_probas = self._rf_model.predict_proba(X)
        gb_probas = self._gb_model.predict_proba(X)

        results = []
        for i in range(len(feature_dicts)):
            rf_score = float(rf_probas[i][1])
            gb_score = float(gb_probas[i][1])
            ensemble = self.rf_weight * rf_score + self.gb_weight * gb_score
            prediction = 1 if ensemble >= settings.ML_CONFIDENCE_THRESHOLD else 0

            results.append({
                "rf_score": round(rf_score, 4),
                "gb_score": round(gb_score, 4),
                "ensemble_score": round(ensemble, 4),
                "prediction": prediction,
                "confidence": round(
                    ensemble if prediction == 1 else 1 - ensemble, 4
                ),
                "label": "phishing" if prediction == 1 else "safe",
            })

        return results

    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """Get the most important features from both models.

        Returns a sorted list of (feature_name, importance) tuples.
        """
        if self._rf_importances is None and self._gb_importances is None:
            return []

        feature_names = self._preprocessor.feature_names

        # Average importance across both models
        if self._rf_importances is not None and self._gb_importances is not None:
            combined = (
                self.rf_weight * self._rf_importances
                + self.gb_weight * self._gb_importances
            )
        elif self._rf_importances is not None:
            combined = self._rf_importances
        else:
            combined = self._gb_importances

        # Handle length mismatch
        n = min(len(feature_names), len(combined))
        pairs = list(zip(feature_names[:n], combined[:n].tolist()))
        pairs.sort(key=lambda x: x[1], reverse=True)

        return pairs[:top_n]

    def save(self, path: Optional[str] = None) -> str:
        """Save the trained model to disk."""
        if not self._is_trained:
            raise RuntimeError("Cannot save untrained model")

        model_dir = Path(path or settings.MODEL_DIR)
        model_dir.mkdir(parents=True, exist_ok=True)
        filepath = model_dir / "url_classifier.joblib"

        state = {
            "rf_model": self._rf_model,
            "gb_model": self._gb_model,
            "preprocessor_state": self._preprocessor.get_state(),
            "rf_weight": self.rf_weight,
            "gb_weight": self.gb_weight,
            "rf_importances": self._rf_importances,
            "gb_importances": self._gb_importances,
        }

        joblib.dump(state, filepath)
        logger.info("URL classifier saved", path=str(filepath))
        return str(filepath)

    def load(self, path: Optional[str] = None) -> None:
        """Load a trained model from disk."""
        model_dir = Path(path or settings.MODEL_DIR)
        filepath = model_dir / "url_classifier.joblib"

        if not filepath.exists():
            logger.warning("URL classifier model file not found", path=str(filepath))
            return

        state = joblib.load(filepath)
        self._rf_model = state["rf_model"]
        self._gb_model = state["gb_model"]
        self._preprocessor.load_state(state["preprocessor_state"])
        self.rf_weight = state["rf_weight"]
        self.gb_weight = state["gb_weight"]
        self._rf_importances = state.get("rf_importances")
        self._gb_importances = state.get("gb_importances")
        self._is_trained = True

        logger.info("URL classifier loaded", path=str(filepath))

    def _evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """Compute evaluation metrics on the given data."""
        rf_preds = self._rf_model.predict(X)
        gb_preds = self._gb_model.predict(X)

        # Ensemble predictions
        rf_proba = self._rf_model.predict_proba(X)[:, 1]
        gb_proba = self._gb_model.predict_proba(X)[:, 1]
        ensemble_proba = self.rf_weight * rf_proba + self.gb_weight * gb_proba
        ensemble_preds = (ensemble_proba >= settings.ML_CONFIDENCE_THRESHOLD).astype(int)

        return {
            "rf_accuracy": round(accuracy_score(y, rf_preds), 4),
            "rf_f1": round(f1_score(y, rf_preds, zero_division=0), 4),
            "gb_accuracy": round(accuracy_score(y, gb_preds), 4),
            "gb_f1": round(f1_score(y, gb_preds, zero_division=0), 4),
            "ensemble_accuracy": round(accuracy_score(y, ensemble_preds), 4),
            "ensemble_precision": round(precision_score(y, ensemble_preds, zero_division=0), 4),
            "ensemble_recall": round(recall_score(y, ensemble_preds, zero_division=0), 4),
            "ensemble_f1": round(f1_score(y, ensemble_preds, zero_division=0), 4),
            "ensemble_auc": round(roc_auc_score(y, ensemble_proba), 4),
        }

    @staticmethod
    def _default_prediction() -> Dict[str, Any]:
        return {
            "rf_score": 0.5,
            "gb_score": 0.5,
            "ensemble_score": 0.5,
            "prediction": 0,
            "confidence": 0.5,
            "label": "unknown",
        }
