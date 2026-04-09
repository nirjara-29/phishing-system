"""Train and persist the TF-IDF email NLP phishing model."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml.email_nlp_model import EmailNLPModel


def main() -> None:
    model = EmailNLPModel()
    model.train_and_save()


if __name__ == "__main__":
    main()
