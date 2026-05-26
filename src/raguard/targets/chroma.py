"""ChromaDB target implementation for RAGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from raguard.models import RAGTargetConfig
from raguard.targets.base import BaseTarget


class ChromaTarget(BaseTarget):
    """ChromaDB vector database target."""

    name = "chroma"

    def __init__(self, config: RAGTargetConfig) -> None:
        super().__init__(config)
        self._client: Any = None

    async def connect(self) -> bool:
        """Connect to ChromaDB with path safety checks."""
        try:
            import chromadb

            url = self.config.url
            if url.startswith("http://") or url.startswith("https://"):
                parsed = urlparse(url)
                host = parsed.hostname or "localhost"
                port = parsed.port or 8000
                self._client = chromadb.HttpClient(host=host, port=port)
            else:
                # Only allow relative paths for persistent client
                path = Path(url)
                if path.is_absolute():
                    raise ValueError(
                        "Absolute paths are not allowed for ChromaDB persistent client. "
                        "Use a relative path or an HTTP URL."
                    )
                safe_path = Path.cwd() / path
                self._client = chromadb.PersistentClient(path=str(safe_path))
            return True
        except ImportError:
            raise ImportError(
                "chromadb is required for ChromaDB targets. Install with: pip install raguard-scanner[chroma]"
            )
        except ValueError:
            raise
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
                documents.append(
                    {
                        "text": doc,
                        "metadata": results.get("metadatas", [[]])[0][i] if results.get("metadatas") else {},
                        "distance": results.get("distances", [[]])[0][i] if results.get("distances") else None,
                        "id": results.get("ids", [[]])[0][i] if results.get("ids") else "",
                    }
                )
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
