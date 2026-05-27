"""Tests for Qdrant target with mocked qdrant_client in sys.modules."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _fresh_qdrant_modules() -> dict[str, MagicMock]:
    mock_client = MagicMock()
    mock_models = MagicMock()
    mock_models.PointStruct = MagicMock()
    mock_client.models = mock_models
    return {
        "qdrant_client": mock_client,
        "qdrant_client.models": mock_models,
    }


class TestQdrantTarget:
    async def test_connect_success(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT)
            target = QdrantTarget(config)
            result = await target.connect()
            assert result is True
            mock_qdrant.QdrantClient.assert_called_once_with(url="http://localhost:6333", api_key=None)

    async def test_connect_with_api_key(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT, api_key="my-key")
            target = QdrantTarget(config)
            result = await target.connect()
            assert result is True
            mock_qdrant.QdrantClient.assert_called_once_with(url="http://localhost:6333", api_key="my-key")

    async def test_connect_exception_returns_false(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            mock_qdrant.QdrantClient.side_effect = RuntimeError("Connection failed")
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT)
            target = QdrantTarget(config)
            result = await target.connect()
            assert result is False

    async def test_disconnect(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT)
            target = QdrantTarget(config)
            target._client = MagicMock()
            await target.disconnect()
            assert target._client is None

    async def test_query(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            mock_hit = MagicMock()
            mock_hit.id = 1
            mock_hit.score = 0.95
            mock_hit.payload = {"text": "doc text"}
            mock_instance = MagicMock()
            mock_instance.search.return_value = [mock_hit]
            mock_qdrant.QdrantClient.return_value = mock_instance
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT, collection_name="my_coll")
            target = QdrantTarget(config)
            target._client = mock_instance
            results = await target.query("test query", top_k=5)
            assert len(results) == 1
            assert results[0]["id"] == "1"
            assert results[0]["score"] == 0.95

    async def test_query_auto_connect(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            mock_hit = MagicMock()
            mock_hit.id = 1
            mock_hit.score = 0.5
            mock_hit.payload = {}
            mock_instance = MagicMock()
            mock_instance.search.return_value = [mock_hit]
            mock_qdrant.QdrantClient.return_value = mock_instance
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT, collection_name="my_coll")
            target = QdrantTarget(config)
            results = await target.query("test", top_k=1)
            assert len(results) == 1

    async def test_insert(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            mock_instance = MagicMock()
            mock_qdrant.QdrantClient.return_value = mock_instance

            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT, collection_name="my_coll")
            target = QdrantTarget(config)
            target._client = mock_instance
            result = await target.insert([{"text": "doc1", "metadata": {"source": "test"}}])
            assert result is True
            mock_instance.upsert.assert_called_once()

    async def test_get_collection_info(self) -> None:
        mocks = _fresh_qdrant_modules()
        with patch.dict("sys.modules", mocks):
            mock_qdrant = mocks["qdrant_client"]
            mock_collection_info = MagicMock()
            mock_collection_info.vectors_count = 42
            mock_collection_info.status = "green"
            mock_instance = MagicMock()
            mock_instance.get_collection.return_value = mock_collection_info
            mock_qdrant.QdrantClient.return_value = mock_instance
            from raguard.models import RAGTargetConfig, TargetType
            from raguard.targets.qdrant import QdrantTarget

            config = RAGTargetConfig(url="http://localhost:6333", type=TargetType.QDRANT, collection_name="my_coll")
            target = QdrantTarget(config)
            target._client = mock_instance
            info = await target.get_collection_info()
            assert info["name"] == "my_coll"
            assert info["vectors_count"] == 42
            assert info["status"] == "green"
