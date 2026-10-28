"""
Configuration management for Glasshouse Broker.

This module loads settings from environment variables and provides
type-safe configuration throughout the application.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    All sensitive values (signing keys) must be provided via environment
    or .env file. Never hardcode secrets here.
    """

    # Broker settings
    broker_host: str = "0.0.0.0"
    broker_port: int = 8000
    environment: str = "development"

    # Ollama settings
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout: int = 30

    # Security settings
    token_signing_key: str  # REQUIRED - no default
    audit_signing_key: str  # REQUIRED - no default
    token_expiration_seconds: int = 300

    # Audit log settings
    audit_db_path: str = "./data/audit.db"

    # Timing normalization
    timing_normalization_enabled: bool = True
    timing_normalization_target: float = 2.0

    # Policy configuration
    policy_file_path: str = "./config/policy.json"

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = False


def get_settings() -> Settings:
    """
    Load and return application settings.

    Raises:
        ValueError: If required settings (signing keys) are missing
    """
    try:
        settings = Settings()

        # Validate that required secrets are present
        if not settings.token_signing_key or settings.token_signing_key == "REPLACE_WITH_GENERATED_KEY":
            raise ValueError(
                "TOKEN_SIGNING_KEY is not configured. "
                "Run 'python scripts/generate_keys.py' to generate keys."
            )

        if not settings.audit_signing_key or settings.audit_signing_key == "REPLACE_WITH_GENERATED_KEY":
            raise ValueError(
                "AUDIT_SIGNING_KEY is not configured. "
                "Run 'python scripts/generate_keys.py' to generate keys."
            )

        return settings

    except Exception as e:
        raise ValueError(f"Configuration error: {e}")


# Global settings instance
# This will be imported by other modules
settings = get_settings()
