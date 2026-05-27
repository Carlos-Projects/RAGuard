"""Tests for target connect/disconnect/query/insert with mocked dependencies."""

from __future__ import annotations

from sys import modules
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from raguard.models import RAGTargetConfig, TargetType

# These tests mock external DB libraries by injecting into sys.modules
# before the methods that import them are called.


class TestChromaTargetConnect:
    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_connect_http_success(self) -> None:
        mock_chromadb = modules["chromadb"]
        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        result = await target.connect()
        assert result is True
        mock_chromadb.HttpClient.assert_called_once_with(host="localhost", port=8000)

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_connect_persistent_success(self) -> None:
        mock_chromadb = modules["chromadb"]
        config = RAGTargetConfig(url="./chroma_data", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        result = await target.connect()
        assert result is True
        mock_chromadb.PersistentClient.assert_called_once()

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_connect_absolute_path_raises(self) -> None:
        config = RAGTargetConfig(url="/absolute/path", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        with pytest.raises(ValueError, match="Absolute paths are not allowed"):
            await target.connect()

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_connect_exception_returns_false(self) -> None:
        mock_chromadb = modules["chromadb"]
        mock_chromadb.HttpClient.side_effect = RuntimeError("Connection refused")
        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        result = await target.connect()
        assert result is False

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_disconnect(self) -> None:
        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        await target.connect()
        assert target._client is not None
        await target.disconnect()
        assert target._client is None

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_query_auto_connect(self) -> None:
        mock_chromadb = modules["chromadb"]
        mock_collection = MagicMock()
        mock_collection.query.return_value = {
            "documents": [["doc1", "doc2"]],
            "metadatas": [[{"k": "v"}, {"k": "v2"}]],
            "distances": [[0.1, 0.2]],
            "ids": [["id1", "id2"]],
        }
        mock_chromadb.PersistentClient.return_value.get_or_create_collection.return_value = mock_collection

        config = RAGTargetConfig(url="./data", type=TargetType.CHROMA, collection_name="test_collection")
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        results = await target.query("test query", top_k=2)

        assert len(results) == 2
        assert results[0]["text"] == "doc1"
        assert results[0]["id"] == "id1"

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_insert_auto_connect(self) -> None:
        mock_chromadb = modules["chromadb"]
        mock_collection = MagicMock()
        mock_chromadb.PersistentClient.return_value.get_or_create_collection.return_value = mock_collection

        config = RAGTargetConfig(url="./data", type=TargetType.CHROMA)
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        docs = [{"text": "hello", "metadata": {"source": "test"}}]
        result = await target.insert(docs)

        assert result is True
        mock_collection.add.assert_called_once()

    @patch.dict("sys.modules", {"chromadb": MagicMock()})
    async def test_get_collection_info(self) -> None:
        mock_chromadb = modules["chromadb"]
        mock_collection = MagicMock()
        mock_collection.name = "test_collection"
        mock_collection.count.return_value = 42
        mock_collection.metadata = {"created": "today"}
        mock_chromadb.PersistentClient.return_value.get_or_create_collection.return_value = mock_collection

        config = RAGTargetConfig(url="./data", type=TargetType.CHROMA, collection_name="test_collection")
        from raguard.targets.chroma import ChromaTarget

        target = ChromaTarget(config)
        info = await target.get_collection_info()

        assert info["name"] == "test_collection"
        assert info["count"] == 42
        assert info["metadata"] == {"created": "today"}


class TestGenericRAGTarget:
    async def _make_mock_client(self) -> AsyncMock:
        client = AsyncMock()
        return client

    async def test_connect_success(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_http_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_http_client.get.return_value = mock_response

        with patch("raguard.targets.generic_rag.httpx.AsyncClient", return_value=mock_http_client):
            config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
            target = GenericRAGTarget(config)
            result = await target.connect()
            assert result is True
            mock_http_client.get.assert_called_once_with("/health")

    async def test_connect_failure(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_http_client = AsyncMock()
        mock_http_client.get.side_effect = RuntimeError("Connection failed")

        with patch("raguard.targets.generic_rag.httpx.AsyncClient", return_value=mock_http_client):
            config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
            target = GenericRAGTarget(config)
            result = await target.connect()
            assert result is False

    async def test_query_success(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": [{"text": "doc1"}]}
        mock_client.post.return_value = mock_response

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        results = await target.query("test", top_k=5)
        assert len(results) == 1
        mock_client.post.assert_called_once_with("/query", json={"query": "test", "top_k": 5})

    async def test_query_http_error_returns_empty(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_client.post.side_effect = RuntimeError("Timeout")

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        results = await target.query("test")
        assert results == []

    async def test_insert_success(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_client.post.return_value = mock_response

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        result = await target.insert([{"text": "doc1"}])
        assert result is True

    async def test_insert_failure(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_client.post.side_effect = RuntimeError("Error")

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        result = await target.insert([{"text": "doc1"}])
        assert result is False

    async def test_get_collection_info_success(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "default", "count": 42}
        mock_client.get.return_value = mock_response

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        info = await target.get_collection_info()
        assert info["name"] == "default"
        assert info["count"] == 42

    async def test_get_collection_info_failure_returns_default(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        mock_client.get.side_effect = RuntimeError("Error")

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC, collection_name="my_coll")
        target = GenericRAGTarget(config)
        target._client = mock_client
        info = await target.get_collection_info()
        assert info["name"] == "my_coll"
        assert info["status"] == "unknown"

    async def test_disconnect_closes_client(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        mock_client = AsyncMock()
        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        target._client = mock_client
        await target.disconnect()
        mock_client.aclose.assert_called_once()
        assert target._client is None

    async def test_disconnect_no_client(self) -> None:
        from raguard.targets.generic_rag import GenericRAGTarget

        config = RAGTargetConfig(url="http://localhost:8000", type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        await target.disconnect()
        assert target._client is None
