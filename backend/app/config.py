"""Application configuration using Pydantic settings management.

Loads configuration from environment variables and .env files with
validation and type coercion. All settings are centralized here to
ensure consistency across the application.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Main application settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "PhishNet"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_VERSION: str = "1.0.0"
    SECRET_KEY: str = "change-me-in-production"
    API_PREFIX: str = "/api/v1"

    # -------------------------------------------------------------------------
    # Server
    # -------------------------------------------------------------------------
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    RELOAD: bool = True

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "postgresql+asyncpg://phishnet:phishnet_pass@localhost:5432/phishnet"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_ECHO: bool = False

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 3600

    # -------------------------------------------------------------------------
    # Celery
    # -------------------------------------------------------------------------
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"
    CELERY_TASK_ALWAYS_EAGER: bool = False

    # -------------------------------------------------------------------------
    # JWT Authentication
    # -------------------------------------------------------------------------
    JWT_SECRET_KEY: str = "change-me-jwt-secret"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------------------------------------------------------
    # ML Models
    # -------------------------------------------------------------------------
    MODEL_DIR: str = "./models"
    BERT_MODEL_NAME: str = "bert-base-uncased"
    BERT_MAX_LENGTH: int = 128
    ML_CONFIDENCE_THRESHOLD: float = 0.7
    ENSEMBLE_WEIGHTS_RF: float = 0.3
    ENSEMBLE_WEIGHTS_GB: float = 0.3
    ENSEMBLE_WEIGHTS_BERT: float = 0.4

    # -------------------------------------------------------------------------
    # Feature Extraction
    # -------------------------------------------------------------------------
    WHOIS_TIMEOUT: int = 10
    DNS_TIMEOUT: int = 5
    CONTENT_FETCH_TIMEOUT: int = 15
    MAX_REDIRECTS: int = 5

    # -------------------------------------------------------------------------
    # Threat Intelligence
    # -------------------------------------------------------------------------
    THREATINTEL_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "./logs/phishnet.log"

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10

    # -------------------------------------------------------------------------
    # Email (SMTP)
    # -------------------------------------------------------------------------
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "noreply@phishnet.io"

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS_ORIGINS string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    @property
    def model_path(self) -> Path:
        """Get the resolved model directory path."""
        path = Path(self.MODEL_DIR)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_testing(self) -> bool:
        return self.APP_ENV == "testing"

    @field_validator("ENSEMBLE_WEIGHTS_RF", "ENSEMBLE_WEIGHTS_GB", "ENSEMBLE_WEIGHTS_BERT")
    @classmethod
    def validate_weight(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Ensemble weight must be between 0 and 1")
        return v


@lru_cache()
def get_settings() -> Settings:
    """Create cached settings instance. Use dependency injection in FastAPI."""
    return Settings()


settings = get_settings()
