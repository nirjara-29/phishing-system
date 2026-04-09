"""BERT-based URL phishing classifier.

Fine-tunes a pre-trained BERT model to classify URLs as phishing or safe
based on the URL string itself (character-level patterns). Uses the
transformers library for model management and PyTorch for training.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, random_split

from app.config import settings

logger = structlog.get_logger(__name__)


class URLDataset(Dataset):
    """PyTorch dataset for URL classification.

    Tokenizes URLs and pairs them with binary labels for training.
    """

    def __init__(self, urls: List[str], labels: List[int], tokenizer, max_length: int = 128):
        self.urls = urls
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.urls)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        url = self.urls[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            url,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(label, dtype=torch.long),
        }


class URLBERTModel(nn.Module):
    """BERT-based neural network for URL classification.

    Architecture:
    - Pre-trained BERT encoder
    - Dropout layer for regularization
    - Linear classification head (768 -> 256 -> 2)
    """

    def __init__(self, model_name: str = "bert-base-uncased", num_labels: int = 2, dropout: float = 0.3):
        super().__init__()
        from transformers import BertModel

        self.bert = BertModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Sequential(
            nn.Linear(self.bert.config.hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_labels),
        )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        # Use [CLS] token representation
        cls_output = outputs.last_hidden_state[:, 0, :]
        cls_output = self.dropout(cls_output)
        logits = self.classifier(cls_output)
        return logits


class BERTURLClassifier:
    """High-level interface for BERT URL classification.

    Manages model loading, training, and inference. Supports GPU
    acceleration when available.
    """

    def __init__(
        self,
        model_name: str = None,
        max_length: int = None,
        batch_size: int = 32,
        learning_rate: float = 2e-5,
        epochs: int = 5,
    ):
        self.model_name = model_name or settings.BERT_MODEL_NAME
        self.max_length = max_length or settings.BERT_MAX_LENGTH
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.epochs = epochs

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._model: Optional[URLBERTModel] = None
        self._tokenizer = None
        self._is_trained = False

        logger.info("BERT classifier initialized", device=str(self.device))

    @property
    def is_ready(self) -> bool:
        return self._is_trained and self._model is not None

    def _ensure_tokenizer(self):
        """Lazy-load the tokenizer."""
        if self._tokenizer is None:
            from transformers import BertTokenizer
            self._tokenizer = BertTokenizer.from_pretrained(self.model_name)

    def train(
        self,
        urls: List[str],
        labels: List[int],
        val_split: float = 0.15,
    ) -> Dict[str, Any]:
        """Fine-tune BERT on URL classification data.

        Args:
            urls: List of URL strings.
            labels: Binary labels (0=safe, 1=phishing).
            val_split: Fraction of data to use for validation.

        Returns:
            Dictionary of training metrics per epoch.
        """
        logger.info(
            "Starting BERT training",
            samples=len(urls),
            epochs=self.epochs,
            device=str(self.device),
        )

        self._ensure_tokenizer()

        # Create dataset and split
        dataset = URLDataset(urls, labels, self._tokenizer, self.max_length)
        val_size = int(len(dataset) * val_split)
        train_size = len(dataset) - val_size
        train_dataset, val_dataset = random_split(
            dataset, [train_size, val_size],
            generator=torch.Generator().manual_seed(42),
        )

        train_loader = DataLoader(
            train_dataset, batch_size=self.batch_size, shuffle=True, num_workers=0
        )
        val_loader = DataLoader(
            val_dataset, batch_size=self.batch_size, shuffle=False, num_workers=0
        )

        # Initialize model
        self._model = URLBERTModel(self.model_name).to(self.device)

        # Optimizer with differential learning rates
        optimizer = torch.optim.AdamW(
            [
                {"params": self._model.bert.parameters(), "lr": self.learning_rate},
                {"params": self._model.classifier.parameters(), "lr": self.learning_rate * 10},
            ],
            weight_decay=0.01,
        )

        # Learning rate scheduler
        total_steps = len(train_loader) * self.epochs
        scheduler = torch.optim.lr_scheduler.OneCycleLR(
            optimizer,
            max_lr=self.learning_rate * 10,
            total_steps=total_steps,
        )

        criterion = nn.CrossEntropyLoss()
        history = {"train_loss": [], "val_loss": [], "val_accuracy": [], "val_f1": []}

        best_val_f1 = 0.0

        for epoch in range(self.epochs):
            # Training phase
            self._model.train()
            train_losses = []

            for batch in train_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                batch_labels = batch["label"].to(self.device)

                optimizer.zero_grad()
                logits = self._model(input_ids, attention_mask)
                loss = criterion(logits, batch_labels)
                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self._model.parameters(), max_norm=1.0)

                optimizer.step()
                scheduler.step()
                train_losses.append(loss.item())

            # Validation phase
            val_metrics = self._validate(val_loader, criterion)

            avg_train_loss = np.mean(train_losses)
            history["train_loss"].append(avg_train_loss)
            history["val_loss"].append(val_metrics["loss"])
            history["val_accuracy"].append(val_metrics["accuracy"])
            history["val_f1"].append(val_metrics["f1"])

            logger.info(
                f"Epoch {epoch + 1}/{self.epochs}",
                train_loss=f"{avg_train_loss:.4f}",
                val_loss=f"{val_metrics['loss']:.4f}",
                val_acc=f"{val_metrics['accuracy']:.4f}",
                val_f1=f"{val_metrics['f1']:.4f}",
            )

            # Save best model
            if val_metrics["f1"] > best_val_f1:
                best_val_f1 = val_metrics["f1"]

        self._is_trained = True
        logger.info("BERT training complete", best_f1=f"{best_val_f1:.4f}")

        return {
            "history": history,
            "best_val_f1": round(best_val_f1, 4),
            "final_val_accuracy": round(history["val_accuracy"][-1], 4),
        }

    def predict(self, url: str) -> Dict[str, Any]:
        """Predict phishing probability for a single URL."""
        if not self.is_ready:
            return {"bert_score": 0.5, "prediction": 0, "label": "unknown"}

        self._model.eval()
        self._ensure_tokenizer()

        encoding = self._tokenizer(
            url,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        input_ids = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)

        with torch.no_grad():
            logits = self._model(input_ids, attention_mask)
            probabilities = torch.softmax(logits, dim=1)
            phishing_prob = probabilities[0][1].item()

        prediction = 1 if phishing_prob >= settings.ML_CONFIDENCE_THRESHOLD else 0

        return {
            "bert_score": round(phishing_prob, 4),
            "prediction": prediction,
            "confidence": round(phishing_prob if prediction == 1 else 1 - phishing_prob, 4),
            "label": "phishing" if prediction == 1 else "safe",
        }

    def predict_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Predict phishing probabilities for a batch of URLs."""
        if not self.is_ready:
            return [{"bert_score": 0.5, "prediction": 0, "label": "unknown"} for _ in urls]

        self._model.eval()
        self._ensure_tokenizer()

        results = []
        # Process in batches
        for i in range(0, len(urls), self.batch_size):
            batch_urls = urls[i : i + self.batch_size]

            encodings = self._tokenizer(
                batch_urls,
                max_length=self.max_length,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )

            input_ids = encodings["input_ids"].to(self.device)
            attention_mask = encodings["attention_mask"].to(self.device)

            with torch.no_grad():
                logits = self._model(input_ids, attention_mask)
                probabilities = torch.softmax(logits, dim=1)

            for j in range(len(batch_urls)):
                phishing_prob = probabilities[j][1].item()
                prediction = 1 if phishing_prob >= settings.ML_CONFIDENCE_THRESHOLD else 0
                results.append({
                    "bert_score": round(phishing_prob, 4),
                    "prediction": prediction,
                    "confidence": round(
                        phishing_prob if prediction == 1 else 1 - phishing_prob, 4
                    ),
                    "label": "phishing" if prediction == 1 else "safe",
                })

        return results

    def _validate(self, val_loader: DataLoader, criterion) -> Dict[str, float]:
        """Run validation and compute metrics."""
        self._model.eval()
        all_preds = []
        all_labels = []
        total_loss = 0.0
        n_batches = 0

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                batch_labels = batch["label"].to(self.device)

                logits = self._model(input_ids, attention_mask)
                loss = criterion(logits, batch_labels)
                total_loss += loss.item()
                n_batches += 1

                preds = torch.argmax(logits, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(batch_labels.cpu().numpy())

        from sklearn.metrics import accuracy_score, f1_score

        return {
            "loss": total_loss / max(n_batches, 1),
            "accuracy": accuracy_score(all_labels, all_preds),
            "f1": f1_score(all_labels, all_preds, zero_division=0),
        }

    def save(self, path: Optional[str] = None) -> str:
        """Save the BERT model and tokenizer."""
        if not self.is_ready:
            raise RuntimeError("Cannot save untrained model")

        model_dir = Path(path or settings.MODEL_DIR) / "bert_url_classifier"
        model_dir.mkdir(parents=True, exist_ok=True)

        torch.save(self._model.state_dict(), model_dir / "model.pt")
        self._tokenizer.save_pretrained(str(model_dir))

        logger.info("BERT model saved", path=str(model_dir))
        return str(model_dir)

    def load(self, path: Optional[str] = None) -> None:
        """Load a saved BERT model."""
        model_dir = Path(path or settings.MODEL_DIR) / "bert_url_classifier"
        model_path = model_dir / "model.pt"

        if not model_path.exists():
            logger.warning("BERT model not found", path=str(model_path))
            return

        try:
            from transformers import BertTokenizer

            self._tokenizer = BertTokenizer.from_pretrained(str(model_dir))
            self._model = URLBERTModel(self.model_name).to(self.device)
            self._model.load_state_dict(
                torch.load(model_path, map_location=self.device, weights_only=True)
            )
            self._model.eval()
            self._is_trained = True

            logger.info("BERT model loaded", path=str(model_dir))
        except Exception as e:
            logger.error("Failed to load BERT model", error=str(e))
