"""RAGuard configuration settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class RAGuardSettings(BaseSettings):
    """Global settings for RAGuard scanner."""

    model_config = SettingsConfigDict(
        env_prefix="RAGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # HTTP settings
    timeout: float = 30.0
    max_retries: int = 3
    concurrent_scans: int = 5

    # Scan settings
    severity_threshold: str = "low"
    max_documents_test: int = 50
    max_queries_test: int = 20

    # Output settings
    output_format: str = "rich"
    verbose: bool = False
    debug: bool = False

    # CI mode
    ci_threshold: str = "high"

    # Embedding settings
    embedding_dimension: int = 1536
    similarity_threshold: float = 0.85
