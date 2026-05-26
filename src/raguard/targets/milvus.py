"""Milvus target implementation for RAGuard."""

from __future__ import annotations

from typing import Any

from raguard.models import RAGTargetConfig
from raguard.targets.base import BaseTarget


class MilvusTarget(BaseTarget):
    """Milvus vector database target."""

    name = "milvus"

    def __init__(self, config: RAGTargetConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    async def connect(self) -> bool:
        """Connect to Milvus."""
        try:
            from pymilvus import connections

            connections.connect(
                alias="default",
                uri=self.config.url,
                token=self.config.api_key,
            )
            return True
        except ImportError:
            raise ImportError(
                "pymilvus is required for Milvus targets. Install with: pip install raguard-scanner[milvus]"
            )
        except Exception:
            return False

    async def disconnect(self) -> None:
        """Disconnect from Milvus."""
        try:
            from pymilvus import connections

            connections.disconnect("default")
        except Exception:
            pass

    async def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Query Milvus collection."""
        from pymilvus import Collection

        collection = Collection(self.config.collection_name)
        collection.load()

        # In real implementation, would embed text and search
        results = collection.search(
            data=[[0.0] * self.config.embedding_dimension],  # Placeholder
            anns_field="embedding",
            param={"metric_type": "L2", "params": {"nprobe": 10}},
            limit=top_k,
        )

        documents = []
        for hit in results[0]:
            documents.append(
                {
                    "id": str(hit.id),
                    "distance": hit.distance,
                    "metadata": hit.entity.to_dict() if hasattr(hit, "entity") else {},
                }
            )
        return documents

    async def insert(self, documents: list[dict[str, Any]]) -> bool:
        """Insert documents into Milvus."""
        # In real implementation, would embed and insert
        return True

    async def get_collection_info(self) -> dict[str, Any]:
        """Get Milvus collection info."""
        from pymilvus import Collection, utility

        if utility.has_collection(self.config.collection_name):
            collection = Collection(self.config.collection_name)
            return {
                "name": collection.name,
                "num_entities": collection.num_entities,
                "description": collection.description,
            }
        return {"name": self.config.collection_name, "exists": False}
