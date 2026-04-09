"""Email phishing classifier combining header and content features.

Uses a Gradient Boosting model trained on email-specific features including
authentication results, NLP urgency scores, brand impersonation metrics,
and link analysis.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import structlog
from sklearn.ensemble import GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from app.config import settings
from app.ml.preprocessor import FeaturePreprocessor, create_email_preprocessor

logger = structlog.get_logger(__name__)


class EmailClassifier:
    """Email phishing classifier using Gradient Boosting and Logistic Regression.

    Combines a Gradient Boosting model (captures non-linear feature interactions)
    with a Logistic Regression model (provides stable probability estimates)
    via soft voting for robust email classification.
    """

    def __init__(
        self,
        gb_params: Optional[Dict[str, Any]] = None,
        lr_params: Optional[Dict[str, Any]] = None,
    ):
        self.gb_params = gb_params or {
            "n_estimators": 100,
            "max_depth": 5,
            "learning_rate": 0.1,
            "min_samples_split": 10,
            "min_samples_leaf": 5,
            "subsample": 0.8,
            "random_state": 42,
        }

        self.lr_params = lr_params or {
            "C": 1.0,
            "max_iter": 1000,
            "class_weight": "balanced",
            "random_state": 42,
        }

        self._model: Optional[VotingClassifier] = None
        self._preprocessor: FeaturePreprocessor = create_email_preprocessor()
        self._is_trained = False
        self._feature_importances: Optional[np.ndarray] = None
        self._classification_threshold = 0.6

    @property
    def is_ready(self) -> bool:
        return self._is_trained

    def train(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
    ) -> Dict[str, float]:
        """Train the email classifier on labeled feature data.

        Args:
            feature_dicts: List of email feature dictionaries.
            labels: Binary labels (0=safe, 1=phishing).

        Returns:
            Training metrics dictionary.
        """
        logger.info("Training email classifier", samples=len(labels))

        X = self._preprocessor.fit_transform(feature_dicts)
        y = np.array(labels)

        # Build ensemble
        gb = GradientBoostingClassifier(**self.gb_params)
        lr = LogisticRegression(**self.lr_params)

        self._model = VotingClassifier(
            estimators=[("gb", gb), ("lr", lr)],
            voting="soft",
            weights=[0.6, 0.4],
        )
        self._model.fit(X, y)

        # Extract feature importances from GB
        gb_fitted = self._model.named_estimators_["gb"]
        self._feature_importances = gb_fitted.feature_importances_

        self._is_trained = True

        metrics = self._evaluate(X, y)
        logger.info("Email classifier training complete", metrics=metrics)
        return metrics

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Predict phishing probability for a single email."""
        if not self._is_trained:
            return self._default_prediction()

        X = self._preprocessor.transform_single(feature_dict).reshape(1, -1)
        proba = self._model.predict_proba(X)[0]
        phishing_score = float(proba[1])
        prediction = 1 if phishing_score >= self._classification_threshold else 0

        # Determine verdict and risk level
        if prediction == 1 and phishing_score >= 0.85:
            verdict = "phishing"
            risk_level = "critical"
        elif prediction == 1 and phishing_score >= 0.65:
            verdict = "phishing"
            risk_level = "high"
        elif phishing_score >= 0.4:
            verdict = "suspicious"
            risk_level = "medium"
        else:
            verdict = "safe"
            risk_level = "low"

        return {
            "phishing_score": round(phishing_score, 4),
            "prediction": prediction,
            "confidence": round(
                phishing_score if prediction == 1 else 1 - phishing_score, 4
            ),
            "verdict": verdict,
            "risk_level": risk_level,
        }

    def predict_batch(
        self, feature_dicts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Predict phishing probabilities for a batch of emails."""
        if not self._is_trained:
            return [self._default_prediction() for _ in feature_dicts]

        X = self._preprocessor.transform(feature_dicts)
        probas = self._model.predict_proba(X)

        results = []
        for i in range(len(feature_dicts)):
            phishing_score = float(probas[i][1])
            prediction = 1 if phishing_score >= self._classification_threshold else 0

            if prediction == 1 and phishing_score >= 0.85:
                verdict, risk_level = "phishing", "critical"
            elif prediction == 1:
                verdict, risk_level = "phishing", "high"
            elif phishing_score >= 0.4:
                verdict, risk_level = "suspicious", "medium"
            else:
                verdict, risk_level = "safe", "low"

            results.append({
                "phishing_score": round(phishing_score, 4),
                "prediction": prediction,
                "confidence": round(
                    phishing_score if prediction == 1 else 1 - phishing_score, 4
                ),
                "verdict": verdict,
                "risk_level": risk_level,
            })

        return results

    def get_feature_importance(self, top_n: int = 15) -> List[tuple]:
        """Get most important email features."""
        if self._feature_importances is None:
            return []

        names = self._preprocessor.feature_names
        n = min(len(names), len(self._feature_importances))
        pairs = list(zip(names[:n], self._feature_importances[:n].tolist()))
        pairs.sort(key=lambda x: x[1], reverse=True)
        return pairs[:top_n]

    def save(self, path: Optional[str] = None) -> str:
        """Save the trained model to disk."""
        if not self._is_trained:
            raise RuntimeError("Cannot save untrained model")

        model_dir = Path(path or settings.MODEL_DIR)
        model_dir.mkdir(parents=True, exist_ok=True)
        filepath = model_dir / "email_classifier.joblib"

        state = {
            "model": self._model,
            "preprocessor_state": self._preprocessor.get_state(),
            "feature_importances": self._feature_importances,
            "threshold": self._classification_threshold,
        }
        joblib.dump(state, filepath)
        logger.info("Email classifier saved", path=str(filepath))
        return str(filepath)

    def load(self, path: Optional[str] = None) -> None:
        """Load a trained model from disk."""
        model_dir = Path(path or settings.MODEL_DIR)
        filepath = model_dir / "email_classifier.joblib"

        if not filepath.exists():
            logger.warning("Email classifier model not found", path=str(filepath))
            return

        state = joblib.load(filepath)
        self._model = state["model"]
        self._preprocessor.load_state(state["preprocessor_state"])
        self._feature_importances = state.get("feature_importances")
        self._classification_threshold = state.get("threshold", 0.6)
        self._is_trained = True

        logger.info("Email classifier loaded", path=str(filepath))

    def _evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """Compute evaluation metrics."""
        preds = self._model.predict(X)
        proba = self._model.predict_proba(X)[:, 1]

        return {
            "accuracy": round(accuracy_score(y, preds), 4),
            "precision": round(precision_score(y, preds, zero_division=0), 4),
            "recall": round(recall_score(y, preds, zero_division=0), 4),
            "f1": round(f1_score(y, preds, zero_division=0), 4),
            "auc_roc": round(roc_auc_score(y, proba), 4),
        }

    @staticmethod
    def _default_prediction() -> Dict[str, Any]:
        return {
            "phishing_score": 0.5,
            "prediction": 0,
            "confidence": 0.5,
            "verdict": "unknown",
            "risk_level": "unknown",
        }
