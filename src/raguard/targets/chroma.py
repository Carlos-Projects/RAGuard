"""ChromaDB target implementation for RAGuard."""

from __future__ import annotations

from typing import Any

from raguard.models import RAGTargetConfig
from raguard.targets.base import BaseTarget


class ChromaTarget(BaseTarget):
    """ChromaDB vector database target."""

    name = "chroma"

    def __init__(self, config: RAGTargetConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    async def connect(self) -> bool:
        """Connect to ChromaDB."""
        try:
            import chromadb

            if self.config.url.startswith("http"):
                self._client = chromadb.HttpClient(
                    host=self.config.url.replace("http://", "").replace("https://", "").split(":")[0],
                    port=int(self.config.url.split(":")[-1]) if ":" in self.config.url else 8000,
                )
            else:
                self._client = chromadb.PersistentClient(path=self.config.url)
            return True
        except ImportError:
            raise ImportError(
                "chromadb is required for ChromaDB targets. "
                "Install with: pip install raguard-scanner[chroma]"
            )
        except Exception:
            return False

    async def disconnect(self) -> None:
        """Disconnect from ChromaDB."""
        self._client = None

    async def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Query ChromaDB collection."""
        if not self._client:
            await self.connect()

        collection = self._client.get_or_create_collection(self.config.collection_name)
        results = collection.query(query_texts=[text], n_results=top_k)

        documents = []
        if results.get("documents"):
            for i, doc in enumerate(results["documents"][0]):
                documents.append({
                    "text": doc,
                    "metadata": results.get("metadatas", [[]])[0][i] if results.get("metadatas") else {},
                    "distance": results.get("distances", [[]])[0][i] if results.get("distances") else None,
                    "id": results.get("ids", [[]])[0][i] if results.get("ids") else "",
                })
        return documents

    async def insert(self, documents: list[dict[str, Any]]) -> bool:
        """Insert documents into ChromaDB."""
        if not self._client:
            await self.connect()

        collection = self._client.get_or_create_collection(self.config.collection_name)
        ids = [f"doc_{i}" for i in range(len(documents))]
        texts = [doc.get("text", "") for doc in documents]
        metadatas = [doc.get("metadata", {}) for doc in documents]

        collection.add(documents=texts, metadatas=metadatas, ids=ids)
        return True

    async def get_collection_info(self) -> dict[str, Any]:
        """Get ChromaDB collection info."""
        if not self._client:
            await self.connect()

        collection = self._client.get_or_create_collection(self.config.collection_name)
        return {
            "name": collection.name,
            "count": collection.count(),
            "metadata": collection.metadata or {},
        }
