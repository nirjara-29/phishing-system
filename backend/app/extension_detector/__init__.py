"""Browser-extension URL detection helpers."""

from app.extension_detector.features import extract_features
from app.extension_detector.model import URLPhishingDetector, get_url_detector

__all__ = ["URLPhishingDetector", "extract_features", "get_url_detector"]
