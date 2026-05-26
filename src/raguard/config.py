"""RAGuard configuration settings."""

from __future__ import annotations

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class RAGuardSettings(BaseSettings):
    """Global settings for RAGuard scanner."""

    model_config = SettingsConfigDict(
        env_prefix="RAGUARD_",
        env_file=".env" if os.environ.get("RAGUARD_LOAD_ENV") else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # HTTP settings
    timeout: float = Field(default=30.0, ge=1.0, le=300.0, description="HTTP request timeout in seconds")
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry attempts")
    concurrent_scans: int = Field(default=5, ge=1, le=50, description="Maximum concurrent scans")

    # Scan settings
    severity_threshold: str = "low"
    max_documents_test: int = Field(default=50, ge=1, le=10000, description="Maximum test documents")
    max_queries_test: int = Field(default=20, ge=1, le=1000, description="Maximum test queries")

    # Output settings
    output_format: str = "rich"
    verbose: bool = False
    debug: bool = False

    # CI mode
    ci_threshold: str = "high"

    # Embedding settings
    embedding_dimension: int = Field(default=1536, ge=64, le=16384, description="Embedding vector dimension")
    similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0, description="Similarity threshold for detection")
