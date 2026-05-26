"""Generic RAG endpoint target implementation for RAGuard."""

from __future__ import annotations

from typing import Any

import httpx

from raguard.models import RAGTargetConfig
from raguard.targets.base import BaseTarget


class GenericRAGTarget(BaseTarget):
    """Generic RAG system target via HTTP API."""

    name = "generic"

    def __init__(self, config: RAGTargetConfig) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> bool:
        """Connect to the generic RAG endpoint."""
        try:
            self._client = httpx.AsyncClient(
                base_url=self.config.url,
                timeout=30.0,
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.config.api_key}"} if self.config.api_key else {}),
                },
            )
            # Test connectivity
            response = await self._client.get("/health")
            return response.status_code == 200
        except Exception:
            return False

    async def disconnect(self) -> None:
        """Disconnect from the RAG endpoint."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def query(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Query the RAG system via HTTP API."""
        if not self._client:
            await self.connect()

        try:
            response = await self._client.post(
                "/query",
                json={"query": text, "top_k": top_k},
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("results", data.get("documents", []))
        except Exception:
            pass
        return []

    async def insert(self, documents: list[dict[str, Any]]) -> bool:
        """Insert documents via HTTP API."""
        if not self._client:
            await self.connect()

        try:
            response = await self._client.post(
                "/ingest",
                json={"documents": documents},
            )
            return response.status_code in (200, 201)
        except Exception:
            return False

    async def get_collection_info(self) -> dict[str, Any]:
        """Get collection info via HTTP API."""
        if not self._client:
            await self.connect()

        try:
            response = await self._client.get("/collections/default")
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {"name": self.config.collection_name, "status": "unknown"}
