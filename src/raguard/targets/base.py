"""Abstract base class for RAG target implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from raguard.models import RAGTargetConfig


class BaseTarget(ABC):
    """Abstract base for all RAG target implementations."""

    name: str = "base"

    def __init__(self, config: RAGTargetConfig) -> None:
        self.config = config

    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the target RAG system.

        Returns:
            True if connection successful.
        """
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the target."""
        ...

    @abstractmethod
    async def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Query the RAG system.

        Args:
            text: Query text.
            top_k: Number of results to return.

        Returns:
            List of retrieved documents with metadata.
        """
        ...

    @abstractmethod
    async def insert(self, documents: list[dict[str, Any]]) -> bool:
        """Insert documents into the RAG system.

        Args:
            documents: List of documents with text and metadata.

        Returns:
            True if insertion successful.
        """
        ...

    @abstractmethod
    async def get_collection_info(self) -> dict[str, Any]:
        """Get information about the target collection.

        Returns:
            Dictionary with collection metadata.
        """
        ...
