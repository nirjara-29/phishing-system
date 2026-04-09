"""Machine learning models and pipelines for phishing detection."""

__all__ = []

try:
    from app.ml.url_classifier import URLClassifier

    __all__.append("URLClassifier")
except Exception:
    URLClassifier = None

try:
    from app.ml.bert_classifier import BERTURLClassifier

    __all__.append("BERTURLClassifier")
except Exception:
    BERTURLClassifier = None

try:
    from app.ml.email_classifier import EmailClassifier

    __all__.append("EmailClassifier")
except Exception:
    EmailClassifier = None

try:
    from app.ml.confidence_aggregator import ConfidenceAggregator

    __all__.append("ConfidenceAggregator")
except Exception:
    ConfidenceAggregator = None
