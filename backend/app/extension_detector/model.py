"""RandomForest-backed phishing detector for the browser extension."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List
from urllib.parse import urlparse

import joblib
import pandas as pd
import structlog
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

from app.extension_detector.features import extract_features

logger = structlog.get_logger(__name__)

SUSPICIOUS_KEYWORDS = ("login", "verify", "account", "secure")
SUSPICIOUS_TLDS = (".xyz", ".tk", ".ml", ".cf", ".gq")
BRAND_KEYWORDS = ("paypal", "bank", "google")


@dataclass
class PredictionResult:
    """Exact response payload for the extension check endpoint."""

    url: str
    verdict: str
    confidence: float
    risk_level: str


class URLPhishingDetector:
    """Train, persist, load, and query the extension URL detector."""

    def __init__(self) -> None:
        self.base_dir = Path(__file__).resolve().parents[2]
        self.dataset_path = self.base_dir / "data" / "phishing_data.csv"
        self.model_dir = self.base_dir / "models"
        self.model_path = self.model_dir / "extension_random_forest.joblib"
        self.model: RandomForestClassifier | None = None
        self.feature_columns: List[str] = []

    def predict(self, url: str) -> PredictionResult:
        """Run a model prediction for one URL."""
        self._ensure_ready()

        feature_map = extract_features(url, self.feature_columns)
        features = pd.DataFrame(
            [[feature_map[column] for column in self.feature_columns]],
            columns=self.feature_columns,
        )

        prediction = int(self.model.predict(features)[0])
        probabilities = self.model.predict_proba(features)[0]
        class_probabilities = dict(zip(self.model.classes_, probabilities))
        phishing_probability = float(class_probabilities.get(-1, 0.0))
        predicted_probability = float(class_probabilities.get(prediction, 0.0))

        ml_verdict = self._ml_verdict(prediction, phishing_probability)
        confidence = round(predicted_probability, 4)
        signals = self._rule_signals(url, feature_map)
        verdict = self._apply_rule_overrides(ml_verdict, confidence, signals)
        risk_level = self._risk_level(verdict, confidence)

        logger.info(
            "Extension URL evaluated",
            url=url,
            extracted_features=feature_map,
            ml_prediction=prediction,
            ml_verdict=ml_verdict,
            suspicious_signals=signals,
            verdict=verdict,
            confidence=confidence,
            risk_level=risk_level,
            phishing_probability=round(phishing_probability, 4),
        )

        return PredictionResult(
            url=url,
            verdict=verdict,
            confidence=confidence,
            risk_level=risk_level,
        )

    def _ensure_ready(self) -> None:
        if self.model is not None and self.feature_columns:
            return
        if self.model_path.exists():
            self.load()
            return
        self.train()

    def train(self) -> None:
        """Train a RandomForest model from the local CSV dataset."""
        logger.info("Training browser-extension URL detector", dataset_path=str(self.dataset_path))

        data = pd.read_csv(self.dataset_path)
        data.columns = [self._canonicalize_column_name(column) for column in data.columns]
        data = data.loc[:, ~data.columns.duplicated()]

        if "index" in data.columns:
            data = data.drop(columns=["index"])
        if "Result" not in data.columns:
            raise ValueError("Dataset must contain a Result column")

        feature_frame = data.drop(columns=["Result"]).apply(pd.to_numeric, errors="coerce").fillna(0)
        labels = pd.to_numeric(data["Result"], errors="coerce").fillna(1).astype(int)

        x_train, x_test, y_train, y_test = train_test_split(
            feature_frame,
            labels,
            test_size=0.2,
            random_state=42,
            stratify=labels,
        )

        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=18,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(x_train, y_train)

        predictions = model.predict(x_test)
        accuracy = accuracy_score(y_test, predictions)
        print(f"Extension phishing model accuracy: {accuracy:.4f}")
        logger.info("Extension phishing model trained", accuracy=round(float(accuracy), 4))

        self.model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": model,
                "feature_columns": list(feature_frame.columns),
                "accuracy": float(accuracy),
            },
            self.model_path,
        )

        self.model = model
        self.feature_columns = list(feature_frame.columns)

    def load(self) -> None:
        """Load a previously trained detector bundle from disk."""
        bundle = joblib.load(self.model_path)
        self.model = bundle["model"]
        self.feature_columns = list(bundle["feature_columns"])
        logger.info(
            "Loaded browser-extension URL detector",
            model_path=str(self.model_path),
            feature_count=len(self.feature_columns),
        )

    @staticmethod
    def _ml_verdict(prediction: int, phishing_probability: float) -> str:
        if 0.4 < phishing_probability < 0.7:
            return "suspicious"
        return "phishing" if prediction == -1 else "safe"

    @staticmethod
    def _apply_rule_overrides(ml_verdict: str, confidence: float, signals: List[str]) -> str:
        if len(signals) >= 2:
            return "phishing"
        if ml_verdict == "safe" and confidence < 0.8 and signals:
            return "suspicious"
        return ml_verdict

    @staticmethod
    def _risk_level(verdict: str, confidence: float) -> str:
        if verdict == "safe":
            return "low"
        if verdict == "suspicious":
            return "medium"
        if confidence > 0.85:
            return "high"
        if confidence > 0.6:
            return "medium"
        return "low"

    @staticmethod
    def _rule_signals(url: str, feature_map: dict[str, int]) -> List[str]:
        parsed = urlparse(url.strip())
        hostname = (parsed.hostname or "").lower()
        url_lower = url.lower()
        signals: List[str] = []

        if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
            signals.append("keyword")
        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            signals.append("suspicious_tld")
        if URLPhishingDetector._has_unusual_brand_domain(hostname):
            signals.append("brand_domain")
        if feature_map.get("having_IP_Address") == -1:
            signals.append("ip_address")

        return signals

    @staticmethod
    def _has_unusual_brand_domain(hostname: str) -> bool:
        for brand in BRAND_KEYWORDS:
            if brand in hostname and not hostname.endswith(f"{brand}.com"):
                return True
        return False

    @staticmethod
    def _canonicalize_column_name(name: Any) -> str:
        raw = str(name).strip()
        collapsed = raw.replace(" ", "")
        lowered = collapsed.lower()

        patterns = [
            ("index", "index"),
            ("having_iphaving_ip_address", "having_IP_Address"),
            ("having_ip_address", "having_IP_Address"),
            ("urlurl_length", "URL_Length"),
            ("url_length", "URL_Length"),
            ("shortining_service", "Shortining_Service"),
            ("having_at_symbol", "having_At_Symbol"),
            ("double_slash_redirecting", "double_slash_redirecting"),
            ("prefix_suffix", "Prefix_Suffix"),
            ("having_sub_domain", "having_Sub_Domain"),
            ("sslfinal_state", "SSLfinal_State"),
            ("domain_registeration_length", "Domain_registeration_length"),
            ("favicon", "Favicon"),
            ("port", "port"),
            ("https_token", "HTTPS_token"),
            ("request_url", "Request_URL"),
            ("url_of_anchor", "URL_of_Anchor"),
            ("links_in_tags", "Links_in_tags"),
            ("sfh", "SFH"),
            ("submitting_to_email", "Submitting_to_email"),
            ("abnormal_url", "Abnormal_URL"),
            ("redirect", "Redirect"),
            ("on_mouseover", "on_mouseover"),
            ("rightclick", "RightClick"),
            ("popupwidnow", "popUpWidnow"),
            ("iframe", "Iframe"),
            ("age_of_domain", "age_of_domain"),
            ("dnsrecord", "DNSRecord"),
            ("web_traffic", "web_traffic"),
            ("page_rank", "Page_Rank"),
            ("google_index", "Google_Index"),
            ("links_pointing_to_page", "Links_pointing_to_page"),
            ("statistical_report", "Statistical_report"),
            ("result", "Result"),
        ]

        for needle, canonical in patterns:
            if lowered == needle or needle in lowered:
                return canonical

        return raw


_DETECTOR: URLPhishingDetector | None = None


def get_url_detector() -> URLPhishingDetector:
    """Return a process-wide detector instance."""
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = URLPhishingDetector()
    return _DETECTOR
