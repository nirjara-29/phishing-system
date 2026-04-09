"""Unified TF-IDF training pipeline for phishing email detection."""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from typing import Any, Iterable, List

import joblib
import structlog
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

logger = structlog.get_logger(__name__)

_csv_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_csv_limit)
        break
    except OverflowError:
        _csv_limit //= 10

STRING_LABEL_MAP = {
    "spam": 1,
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "fraud": 1,
    "scam": 1,
    "legitimate": 0,
    "ham": 0,
    "safe": 0,
    "benign": 0,
    "normal": 0,
}


class EmailNLPModel:
    """Train, persist, load, and score phishing emails from unified CSV data."""

    def __init__(self) -> None:
        self.backend_dir = Path(__file__).resolve().parents[2]
        self.data_dir = self.backend_dir / "data"
        self.model_path = self.backend_dir / "models" / "email_classifier.joblib"
        self.pipeline: Pipeline | None = None

    @property
    def is_ready(self) -> bool:
        return self.pipeline is not None

    def ensure_ready(self) -> None:
        """Load the trained model, or train it from CSV datasets if missing."""
        if self.pipeline is not None:
            return

        if self.model_path.exists():
            self.load()
            return

        logger.warning("Email classifier model not found", path=str(self.model_path))
        self.train_and_save()

    def predict_score(self, email_text: str) -> float:
        """Return phishing probability for normalized email text."""
        self.ensure_ready()
        probabilities = self.pipeline.predict_proba([self._clean_text(email_text)])[0]
        return round(float(probabilities[1]), 4)

    def train_and_save(self) -> dict[str, float]:
        """Train the model on all supported CSVs and persist it."""
        texts, labels = self._load_training_data()
        if len(texts) < 10 or len(set(labels)) < 2:
            raise RuntimeError("Insufficient labeled email text data to train classifier")

        cleaned_texts = [self._clean_text(text) for text in texts]
        x_train, x_test, y_train, y_test = train_test_split(
            cleaned_texts,
            labels,
            test_size=0.2,
            random_state=42,
            stratify=labels,
        )

        self.pipeline = Pipeline(
            steps=[
                ("tfidf", TfidfVectorizer(max_features=10000)),
                ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
            ]
        )
        self.pipeline.fit(x_train, y_train)

        predictions = self.pipeline.predict(x_test)
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
            "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        }

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)

        print(f"Email classifier accuracy: {metrics['accuracy']:.4f}")
        print(f"Email classifier precision: {metrics['precision']:.4f}")
        print(f"Email classifier recall: {metrics['recall']:.4f}")
        logger.info("Unified email classifier trained", path=str(self.model_path), samples=len(labels), metrics=metrics)
        return metrics

    def load(self) -> None:
        """Load the persisted email classifier bundle."""
        loaded = joblib.load(self.model_path)
        if isinstance(loaded, Pipeline):
            self.pipeline = loaded
        elif isinstance(loaded, dict) and isinstance(loaded.get("pipeline"), Pipeline):
            # Backward compatibility with older saved bundle format.
            self.pipeline = loaded["pipeline"]
        else:
            raise RuntimeError("Saved email classifier is not a fitted sklearn Pipeline")
        logger.info("Unified email classifier loaded", path=str(self.model_path))

    def _load_training_data(self) -> tuple[List[str], List[int]]:
        """Load and standardize all usable CSV datasets from backend/data."""
        texts: List[str] = []
        labels: List[int] = []

        for path in sorted(self.data_dir.glob("*.csv")):
            dataset_rows = self._load_single_dataset(path)
            if not dataset_rows:
                logger.info("Skipping dataset for NLP model", path=str(path))
                continue

            dataset_texts, dataset_labels = zip(*dataset_rows)
            texts.extend(dataset_texts)
            labels.extend(dataset_labels)
            logger.info("Loaded dataset", path=str(path), samples=len(dataset_rows))

        if texts and len(set(labels)) >= 2:
            return texts, labels

        logger.warning("Falling back to synthetic email dataset because CSV loading produced insufficient data")
        return self._synthetic_dataset()

    def _load_single_dataset(self, path: Path) -> List[tuple[str, int]]:
        """Load and standardize one CSV file."""
        frame = self._read_with_pandas(path)
        if frame is not None:
            return self._rows_from_pandas_frame(frame)
        return self._rows_from_csv_reader(path)

    def _read_with_pandas(self, path: Path):
        """Attempt pandas-based CSV loading first, with graceful fallback."""
        try:
            import pandas as pd

            return pd.read_csv(path, low_memory=False)
        except Exception as exc:
            logger.warning("Pandas CSV loading failed, falling back to csv module", path=str(path), error=str(exc))
            return None

    def _rows_from_pandas_frame(self, frame) -> List[tuple[str, int]]:
        rows: List[tuple[str, int]] = []
        columns = {str(column).strip().lower(): column for column in frame.columns}
        label_key = self._find_label_key(columns.keys())
        if label_key is None:
            return rows

        text_parts = self._select_text_keys(columns.keys())
        if not text_parts:
            return rows

        for _, row in frame.iterrows():
            label = self._normalize_label(row[columns[label_key]])
            if label is None:
                continue

            text = self._build_text_from_mapping(row, columns, text_parts)
            if not text:
                continue

            rows.append((text, label))

        return rows

    def _rows_from_csv_reader(self, path: Path) -> List[tuple[str, int]]:
        rows: List[tuple[str, int]] = []
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                return rows

            columns = {str(column).strip().lower(): column for column in reader.fieldnames}
            label_key = self._find_label_key(columns.keys())
            if label_key is None:
                return rows

            text_parts = self._select_text_keys(columns.keys())
            if not text_parts:
                return rows

            for row in reader:
                label = self._normalize_label(row.get(columns[label_key]))
                if label is None:
                    continue

                text = self._build_text_from_mapping(row, columns, text_parts)
                if not text:
                    continue

                rows.append((text, label))

        return rows

    @staticmethod
    def _find_label_key(columns: Iterable[str]) -> str | None:
        for candidate in ("label", "labels", "target", "class", "is_phishing", "result"):
            if candidate in columns:
                return candidate
        return None

    @staticmethod
    def _select_text_keys(columns: Iterable[str]) -> List[str]:
        column_set = set(columns)

        if "text_combined" in column_set:
            return ["text_combined"]
        if "email_text" in column_set:
            return ["email_text"]

        parts: List[str] = []
        if "subject" in column_set:
            parts.append("subject")
        if "body" in column_set:
            parts.append("body")
        if "urls" in column_set:
            parts.append("urls")
        if parts:
            return parts

        if "body" in column_set:
            return ["body"]

        return []

    def _build_text_from_mapping(self, row: Any, columns: dict[str, Any], text_keys: List[str]) -> str:
        parts: List[str] = []
        for key in text_keys:
            value = row[columns[key]] if columns[key] in row else row.get(columns[key])
            if value is None:
                continue
            text = str(value).strip()
            if text and text.lower() != "nan":
                parts.append(text)

        return self._clean_text(" ".join(parts))

    @staticmethod
    def _normalize_label(value: Any) -> int | None:
        if value is None:
            return None

        if isinstance(value, bool):
            return int(value)

        text = str(value).strip().lower()
        if text == "":
            return None

        if text in STRING_LABEL_MAP:
            return STRING_LABEL_MAP[text]

        try:
            numeric = int(float(text))
        except ValueError:
            return None

        if numeric in (1, -1):
            return 1
        if numeric == 0:
            return 0
        return None

    def _synthetic_dataset(self) -> tuple[List[str], List[int]]:
        """Fallback when external CSVs are unusable."""
        phishing_samples = [
            "account suspended verify now urgent click link",
            "urgent security alert verify your identity immediately",
            "click link now to restore access to your account",
            "aws billing alert update payment details urgently",
        ]
        safe_samples = [
            "meeting schedule updated for tomorrow",
            "invoice attached for your review",
            "project update and sprint planning notes",
            "weekly newsletter and product updates",
        ]

        texts: List[str] = []
        labels: List[int] = []
        for _ in range(100):
            for sample in phishing_samples:
                texts.append(sample)
                labels.append(1)
            for sample in safe_samples:
                texts.append(sample)
                labels.append(0)
        return texts, labels

    @staticmethod
    def _clean_text(text: str) -> str:
        lowered = (text or "").lower()
        lowered = re.sub(r"[^a-z0-9\s:/._-]", " ", lowered)
        return re.sub(r"\s+", " ", lowered).strip()
