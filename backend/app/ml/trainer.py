"""Model training pipeline with cross-validation and experiment tracking.

Orchestrates the full training pipeline: data loading, preprocessing,
model training, evaluation, and model persistence. Supports both
URL and email classifiers.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog
from sklearn.model_selection import StratifiedKFold

from app.config import settings
from app.ml.url_classifier import URLClassifier
from app.ml.email_classifier import EmailClassifier
from app.ml.bert_classifier import BERTURLClassifier
from app.ml.preprocessor import create_url_preprocessor, create_email_preprocessor

logger = structlog.get_logger(__name__)


class TrainingPipeline:
    """End-to-end model training pipeline.

    Handles data splitting, cross-validation, hyperparameter selection,
    training, evaluation, and model serialization.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir or settings.MODEL_DIR)
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def train_url_classifier(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
        n_folds: int = 5,
        save_model: bool = True,
    ) -> Dict[str, Any]:
        """Train the URL classifier with cross-validation.

        Args:
            feature_dicts: Feature dictionaries from URL extraction.
            labels: Binary labels (0=safe, 1=phishing).
            n_folds: Number of cross-validation folds.
            save_model: Whether to save the final model to disk.

        Returns:
            Training report with cross-validation metrics.
        """
        start_time = time.time()
        logger.info(
            "Starting URL classifier training pipeline",
            samples=len(labels),
            folds=n_folds,
        )

        labels_arr = np.array(labels)
        pos_count = int(labels_arr.sum())
        neg_count = len(labels_arr) - pos_count

        # Cross-validation
        cv_results = self._cross_validate_url(feature_dicts, labels, n_folds)

        # Train final model on all data
        classifier = URLClassifier(
            rf_weight=settings.ENSEMBLE_WEIGHTS_RF,
            gb_weight=settings.ENSEMBLE_WEIGHTS_GB,
        )
        final_metrics = classifier.train(feature_dicts, labels)

        if save_model:
            model_path = classifier.save(str(self.model_dir))
        else:
            model_path = None

        # Feature importance
        importance = classifier.get_feature_importance(top_n=20)

        duration = time.time() - start_time

        report = {
            "model_type": "url_classifier",
            "training_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "dataset": {
                "total_samples": len(labels),
                "positive_samples": pos_count,
                "negative_samples": neg_count,
                "positive_ratio": round(pos_count / len(labels), 4),
            },
            "cross_validation": cv_results,
            "final_metrics": final_metrics,
            "feature_importance": importance,
            "model_path": model_path,
        }

        # Save training report
        report_path = self.model_dir / "url_training_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(
            "URL classifier training complete",
            duration=f"{duration:.1f}s",
            final_f1=final_metrics.get("ensemble_f1"),
        )

        return report

    def train_email_classifier(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
        n_folds: int = 5,
        save_model: bool = True,
    ) -> Dict[str, Any]:
        """Train the email classifier with cross-validation."""
        start_time = time.time()
        logger.info(
            "Starting email classifier training pipeline",
            samples=len(labels),
        )

        labels_arr = np.array(labels)
        pos_count = int(labels_arr.sum())
        neg_count = len(labels_arr) - pos_count

        # Cross-validation
        cv_results = self._cross_validate_email(feature_dicts, labels, n_folds)

        # Train final model
        classifier = EmailClassifier()
        final_metrics = classifier.train(feature_dicts, labels)

        if save_model:
            model_path = classifier.save(str(self.model_dir))
        else:
            model_path = None

        importance = classifier.get_feature_importance(top_n=15)
        duration = time.time() - start_time

        report = {
            "model_type": "email_classifier",
            "training_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "dataset": {
                "total_samples": len(labels),
                "positive_samples": pos_count,
                "negative_samples": neg_count,
            },
            "cross_validation": cv_results,
            "final_metrics": final_metrics,
            "feature_importance": importance,
            "model_path": model_path,
        }

        report_path = self.model_dir / "email_training_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Email classifier training complete", duration=f"{duration:.1f}s")
        return report

    def train_bert_classifier(
        self,
        urls: List[str],
        labels: List[int],
        epochs: int = 5,
        batch_size: int = 32,
        save_model: bool = True,
    ) -> Dict[str, Any]:
        """Train the BERT URL classifier."""
        start_time = time.time()
        logger.info(
            "Starting BERT classifier training",
            samples=len(urls),
            epochs=epochs,
        )

        classifier = BERTURLClassifier(
            epochs=epochs,
            batch_size=batch_size,
        )
        training_result = classifier.train(urls, labels)

        if save_model:
            model_path = classifier.save(str(self.model_dir))
        else:
            model_path = None

        duration = time.time() - start_time

        report = {
            "model_type": "bert_url_classifier",
            "training_date": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "dataset_size": len(urls),
            "training_result": training_result,
            "model_path": model_path,
        }

        report_path = self.model_dir / "bert_training_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("BERT classifier training complete", duration=f"{duration:.1f}s")
        return report

    def _cross_validate_url(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
        n_folds: int,
    ) -> Dict[str, Any]:
        """Perform stratified K-fold cross-validation for the URL classifier."""
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

        preprocessor = create_url_preprocessor()
        X = preprocessor.fit_transform(feature_dicts)
        y = np.array(labels)

        skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

        fold_metrics = []
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]

            # Train on fold
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

            rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            gb = GradientBoostingClassifier(n_estimators=80, random_state=42)

            rf.fit(X_train, y_train)
            gb.fit(X_train, y_train)

            # Ensemble prediction
            rf_proba = rf.predict_proba(X_val)[:, 1]
            gb_proba = gb.predict_proba(X_val)[:, 1]
            ensemble_proba = 0.5 * rf_proba + 0.5 * gb_proba
            ensemble_preds = (ensemble_proba >= 0.5).astype(int)

            fold_result = {
                "fold": fold + 1,
                "accuracy": round(accuracy_score(y_val, ensemble_preds), 4),
                "f1": round(f1_score(y_val, ensemble_preds, zero_division=0), 4),
                "auc_roc": round(roc_auc_score(y_val, ensemble_proba), 4),
                "val_size": len(y_val),
            }
            fold_metrics.append(fold_result)

            logger.debug(f"URL CV Fold {fold + 1}", **fold_result)

        # Aggregate
        avg_metrics = {
            "mean_accuracy": round(np.mean([m["accuracy"] for m in fold_metrics]), 4),
            "std_accuracy": round(np.std([m["accuracy"] for m in fold_metrics]), 4),
            "mean_f1": round(np.mean([m["f1"] for m in fold_metrics]), 4),
            "std_f1": round(np.std([m["f1"] for m in fold_metrics]), 4),
            "mean_auc": round(np.mean([m["auc_roc"] for m in fold_metrics]), 4),
            "std_auc": round(np.std([m["auc_roc"] for m in fold_metrics]), 4),
        }

        return {"folds": fold_metrics, "summary": avg_metrics}

    def _cross_validate_email(
        self,
        feature_dicts: List[Dict[str, Any]],
        labels: List[int],
        n_folds: int,
    ) -> Dict[str, Any]:
        """Perform cross-validation for the email classifier."""
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
        from sklearn.ensemble import GradientBoostingClassifier

        preprocessor = create_email_preprocessor()
        X = preprocessor.fit_transform(feature_dicts)
        y = np.array(labels)

        skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

        fold_metrics = []
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]

            model = GradientBoostingClassifier(
                n_estimators=100, max_depth=5, random_state=42
            )
            model.fit(X_train, y_train)

            proba = model.predict_proba(X_val)[:, 1]
            preds = (proba >= 0.5).astype(int)

            fold_result = {
                "fold": fold + 1,
                "accuracy": round(accuracy_score(y_val, preds), 4),
                "f1": round(f1_score(y_val, preds, zero_division=0), 4),
                "auc_roc": round(roc_auc_score(y_val, proba), 4),
            }
            fold_metrics.append(fold_result)

        avg_metrics = {
            "mean_accuracy": round(np.mean([m["accuracy"] for m in fold_metrics]), 4),
            "mean_f1": round(np.mean([m["f1"] for m in fold_metrics]), 4),
            "mean_auc": round(np.mean([m["auc_roc"] for m in fold_metrics]), 4),
        }

        return {"folds": fold_metrics, "summary": avg_metrics}

    def evaluate_models(self) -> Dict[str, Any]:
        """Load and evaluate all saved models."""
        results = {}

        # URL classifier
        url_clf = URLClassifier()
        url_clf.load(str(self.model_dir))
        results["url_classifier"] = {
            "loaded": url_clf.is_ready,
            "importance": url_clf.get_feature_importance(5) if url_clf.is_ready else [],
        }

        # Email classifier
        email_clf = EmailClassifier()
        email_clf.load(str(self.model_dir))
        results["email_classifier"] = {
            "loaded": email_clf.is_ready,
            "importance": email_clf.get_feature_importance(5) if email_clf.is_ready else [],
        }

        # BERT classifier
        bert_clf = BERTURLClassifier()
        bert_clf.load(str(self.model_dir))
        results["bert_classifier"] = {"loaded": bert_clf.is_ready}

        return results
