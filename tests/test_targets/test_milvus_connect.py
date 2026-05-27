"""Tests for Milvus target with mocked pymilvus in sys.modules."""

from __future__ import annotations

from sys import modules
from unittest.mock import MagicMock, patch


class TestMilvusTarget:
    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_connect_success(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS)
        target = MilvusTarget(config)
        result = await target.connect()
        assert result is True
        mock_pymilvus.connections.connect.assert_called_once_with(
            alias="default", uri="http://localhost:19530", token=None
        )

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_connect_with_api_key(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS, api_key="my-token")
        target = MilvusTarget(config)
        result = await target.connect()
        assert result is True
        mock_pymilvus.connections.connect.assert_called_once_with(
            alias="default", uri="http://localhost:19530", token="my-token"
        )

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_connect_exception_returns_false(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        mock_pymilvus.connections.connect.side_effect = RuntimeError("Connection failed")
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS)
        target = MilvusTarget(config)
        result = await target.connect()
        assert result is False

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_disconnect(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS)
        target = MilvusTarget(config)
        await target.disconnect()
        mock_pymilvus.connections.disconnect.assert_called_once_with("default")

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_disconnect_exception_handled(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        mock_pymilvus.connections.disconnect.side_effect = RuntimeError("Already disconnected")
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS)
        target = MilvusTarget(config)
        await target.disconnect()

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_query(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        mock_collection = MagicMock()
        mock_hit = MagicMock()
        mock_hit.id = "doc_1"
        mock_hit.distance = 0.5
        mock_hit.entity.to_dict.return_value = {"text": "doc text"}
        mock_collection.search.return_value = [[mock_hit]]
        mock_pymilvus.Collection.return_value = mock_collection
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS, collection_name="my_coll")
        target = MilvusTarget(config)
        results = await target.query("test query", top_k=3)
        assert len(results) == 1
        assert results[0]["id"] == "doc_1"
        assert results[0]["distance"] == 0.5

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_insert(self) -> None:
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS)
        target = MilvusTarget(config)
        result = await target.insert([{"text": "doc1"}])
        assert result is True

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_get_collection_info_exists(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        mock_collection = MagicMock()
        mock_collection.name = "my_coll"
        mock_collection.num_entities = 100
        mock_collection.description = "test collection"
        mock_pymilvus.Collection.return_value = mock_collection
        mock_pymilvus.utility.has_collection.return_value = True
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS, collection_name="my_coll")
        target = MilvusTarget(config)
        info = await target.get_collection_info()
        assert info["name"] == "my_coll"
        assert info["num_entities"] == 100

    @patch.dict("sys.modules", {"pymilvus": MagicMock()})
    async def test_get_collection_info_not_exists(self) -> None:
        mock_pymilvus = modules["pymilvus"]
        mock_pymilvus.utility.has_collection.return_value = False
        from raguard.models import RAGTargetConfig, TargetType
        from raguard.targets.milvus import MilvusTarget

        config = RAGTargetConfig(url="http://localhost:19530", type=TargetType.MILVUS, collection_name="my_coll")
        target = MilvusTarget(config)
        info = await target.get_collection_info()
        assert info["exists"] is False
