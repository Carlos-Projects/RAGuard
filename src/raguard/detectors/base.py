"""Abstract base class for all RAG security detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from raguard.models import RAGFinding, RAGTargetConfig


class BaseDetector(ABC):
    """Abstract base for all RAG security detectors."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        """Run detection against a RAG target.

        Args:
            target: Configuration for the RAG system to test.

        Returns:
            List of security findings.
        """
        ...
