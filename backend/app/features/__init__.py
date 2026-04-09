"""Feature extraction modules for phishing detection.

Each module extracts a different category of features from URLs and emails:
- url_features: Lexical analysis (length, entropy, character ratios)
- domain_features: WHOIS, DNS, and domain age lookups
- content_features: Page content analysis and brand detection
- cert_features: SSL/TLS certificate validation
- email_features: Header authentication and NLP analysis
"""

from app.features.url_features import URLFeatureExtractor
from app.features.domain_features import DomainFeatureExtractor
from app.features.content_features import ContentFeatureExtractor
from app.features.cert_features import CertificateFeatureExtractor
from app.features.email_features import EmailFeatureExtractor

__all__ = [
    "URLFeatureExtractor",
    "DomainFeatureExtractor",
    "ContentFeatureExtractor",
    "CertificateFeatureExtractor",
    "EmailFeatureExtractor",
]
