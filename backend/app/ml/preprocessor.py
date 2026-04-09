"""Feature preprocessing pipeline for ML models.

Handles feature scaling, encoding, missing value imputation, and
feature selection. Ensures consistent transformation between training
and inference.
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

# Feature groups for URL classification
URL_NUMERIC_FEATURES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "hostname_length",
    "subdomain_count",
    "subdomain_length",
    "path_depth",
    "digit_ratio",
    "letter_ratio",
    "special_char_ratio",
    "uppercase_ratio",
    "url_entropy",
    "domain_entropy",
    "path_entropy",
    "suspicious_keyword_count",
    "dash_count_in_domain",
    "dot_count_in_url",
    "domain_age_days",
    "expiration_days",
    "ssl_days_remaining",
    "ssl_validity_days",
    "ssl_san_count",
    "external_resource_ratio",
    "brand_similarity_score",
    "page_title_match",
    "domain_risk_score",
    "cert_risk_score",
    "phishing_keyword_count",
    "form_count",
    "external_link_count",
    "null_link_count",
    "obfuscation_score",
    "redirect_count",
    "content_length",
    "word_count",
]

URL_BOOLEAN_FEATURES = [
    "has_ip_address",
    "is_punycode",
    "has_homograph_chars",
    "is_suspicious_tld",
    "uses_https",
    "has_port",
    "brand_in_domain",
    "brand_in_subdomain",
    "brand_in_path",
    "is_shortened",
    "is_data_uri",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_hex_encoding",
    "consecutive_dots",
    "dns_resolves",
    "has_mx_record",
    "has_spf",
    "has_dmarc",
    "registrar_is_high_risk",
    "has_whois_privacy",
    "ssl_available",
    "ssl_valid",
    "is_free_cert",
    "is_trusted_issuer",
    "ssl_san_match",
    "ssl_wildcard",
    "ssl_short_validity",
    "content_available",
    "has_login_form",
    "has_password_field",
    "has_external_form_action",
    "has_empty_action",
    "brand_logo_found",
    "has_urgency_language",
    "has_meta_refresh",
    "has_noindex",
    "has_eval",
    "has_document_write",
    "has_base64_data",
]

# Feature groups for email classification
EMAIL_NUMERIC_FEATURES = [
    "urgency_score",
    "brand_impersonation_score",
    "link_count",
    "suspicious_link_count",
    "unique_domain_count",
    "subject_length",
    "subject_all_caps_ratio",
    "subject_urgency_word_count",
    "body_length",
    "body_urgency_tier1_count",
    "body_urgency_tier2_count",
    "body_urgency_tier3_count",
    "html_to_text_ratio",
    "email_risk_score",
]

EMAIL_BOOLEAN_FEATURES = [
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "auth_results_present",
    "sender_name_email_mismatch",
    "sender_is_freemail",
    "sender_suspicious_pattern",
    "sender_has_numbers",
    "subject_has_urgency",
    "subject_has_re_fwd",
    "subject_has_special_chars",
    "has_html_body",
    "has_hidden_text",
    "has_image_only_body",
    "has_mismatched_urls",
    "has_ip_url",
    "has_shortened_url",
]


class FeaturePreprocessor:
    """Transform raw feature dictionaries into normalized numeric arrays.

    Handles missing values, boolean encoding, numeric scaling, and
    feature ordering for consistent ML model input.
    """

    def __init__(
        self,
        numeric_features: Optional[List[str]] = None,
        boolean_features: Optional[List[str]] = None,
        scale: bool = True,
    ):
        self.numeric_features = numeric_features or URL_NUMERIC_FEATURES
        self.boolean_features = boolean_features or URL_BOOLEAN_FEATURES
        self.all_features = self.numeric_features + self.boolean_features
        self.scale = scale

        # Statistics for normalization (populated during fit)
        self._means: Optional[np.ndarray] = None
        self._stds: Optional[np.ndarray] = None
        self._is_fitted = False

    @property
    def feature_count(self) -> int:
        return len(self.all_features)

    @property
    def feature_names(self) -> List[str]:
        return list(self.all_features)

    def fit(self, feature_dicts: List[Dict[str, Any]]) -> "FeaturePreprocessor":
        """Compute normalization statistics from training data."""
        matrix = self._dicts_to_matrix(feature_dicts)

        num_cols = len(self.numeric_features)
        numeric_part = matrix[:, :num_cols]

        self._means = np.nanmean(numeric_part, axis=0)
        self._stds = np.nanstd(numeric_part, axis=0)

        # Avoid division by zero
        self._stds[self._stds == 0] = 1.0

        self._is_fitted = True
        logger.info(
            "Preprocessor fitted",
            samples=len(feature_dicts),
            features=self.feature_count,
        )
        return self

    def transform(self, feature_dicts: List[Dict[str, Any]]) -> np.ndarray:
        """Transform feature dictionaries into a normalized numpy array."""
        matrix = self._dicts_to_matrix(feature_dicts)

        if self.scale and self._is_fitted:
            num_cols = len(self.numeric_features)
            matrix[:, :num_cols] = (
                matrix[:, :num_cols] - self._means
            ) / self._stds

        return matrix

    def transform_single(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """Transform a single feature dictionary into a 1D array."""
        result = self.transform([feature_dict])
        return result[0]

    def fit_transform(self, feature_dicts: List[Dict[str, Any]]) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(feature_dicts)
        return self.transform(feature_dicts)

    def _dicts_to_matrix(self, feature_dicts: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dictionaries to a 2D numpy array."""
        n_samples = len(feature_dicts)
        n_features = self.feature_count
        matrix = np.zeros((n_samples, n_features), dtype=np.float64)

        for i, fdict in enumerate(feature_dicts):
            for j, feat_name in enumerate(self.numeric_features):
                value = fdict.get(feat_name)
                matrix[i, j] = self._coerce_numeric(value)

            offset = len(self.numeric_features)
            for j, feat_name in enumerate(self.boolean_features):
                value = fdict.get(feat_name)
                matrix[i, offset + j] = self._coerce_boolean(value)

        return matrix

    @staticmethod
    def _coerce_numeric(value: Any) -> float:
        """Safely convert a value to float, handling None and invalid types."""
        if value is None:
            return 0.0
        try:
            result = float(value)
            if np.isnan(result) or np.isinf(result):
                return 0.0
            return result
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _coerce_boolean(value: Any) -> float:
        """Convert a boolean-like value to 0.0 or 1.0."""
        if value is None:
            return 0.0
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            return 1.0 if value else 0.0
        if isinstance(value, str):
            return 1.0 if value.lower() in ("true", "1", "yes") else 0.0
        return 0.0

    def get_state(self) -> Dict[str, Any]:
        """Serialize preprocessor state for persistence."""
        return {
            "numeric_features": self.numeric_features,
            "boolean_features": self.boolean_features,
            "means": self._means.tolist() if self._means is not None else None,
            "stds": self._stds.tolist() if self._stds is not None else None,
            "is_fitted": self._is_fitted,
        }

    def load_state(self, state: Dict[str, Any]) -> None:
        """Restore preprocessor state from a serialized dictionary."""
        self.numeric_features = state["numeric_features"]
        self.boolean_features = state["boolean_features"]
        self.all_features = self.numeric_features + self.boolean_features
        self._means = np.array(state["means"]) if state["means"] else None
        self._stds = np.array(state["stds"]) if state["stds"] else None
        self._is_fitted = state["is_fitted"]


def create_url_preprocessor() -> FeaturePreprocessor:
    """Create a preprocessor configured for URL features."""
    return FeaturePreprocessor(
        numeric_features=URL_NUMERIC_FEATURES,
        boolean_features=URL_BOOLEAN_FEATURES,
    )


def create_email_preprocessor() -> FeaturePreprocessor:
    """Create a preprocessor configured for email features."""
    return FeaturePreprocessor(
        numeric_features=EMAIL_NUMERIC_FEATURES,
        boolean_features=EMAIL_BOOLEAN_FEATURES,
    )
