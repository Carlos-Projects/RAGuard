"""Tests for RAGuard targets."""


from raguard.models import RAGTargetConfig, TargetType
from raguard.targets.base import BaseTarget
from raguard.targets.chroma import ChromaTarget
from raguard.targets.generic_rag import GenericRAGTarget
from raguard.targets.milvus import MilvusTarget
from raguard.targets.qdrant import QdrantTarget


class TestChromaTarget:
    def test_target_name(self) -> None:
        config = RAGTargetConfig(type=TargetType.CHROMA)
        target = ChromaTarget(config)
        assert target.name == "chroma"

    def test_config_passed(self) -> None:
        config = RAGTargetConfig(
            type=TargetType.CHROMA,
            url="http://chroma:8000",
            collection_name="test",
        )
        target = ChromaTarget(config)
        assert target.config.url == "http://chroma:8000"
        assert target.config.collection_name == "test"


class TestMilvusTarget:
    def test_target_name(self) -> None:
        config = RAGTargetConfig(type=TargetType.MILVUS)
        target = MilvusTarget(config)
        assert target.name == "milvus"


class TestQdrantTarget:
    def test_target_name(self) -> None:
        config = RAGTargetConfig(type=TargetType.QDRANT)
        target = QdrantTarget(config)
        assert target.name == "qdrant"


class TestGenericRAGTarget:
    def test_target_name(self) -> None:
        config = RAGTargetConfig(type=TargetType.GENERIC)
        target = GenericRAGTarget(config)
        assert target.name == "generic"

    def test_config_passed(self) -> None:
        config = RAGTargetConfig(
            type=TargetType.GENERIC,
            url="http://rag:8000",
            api_key="test-key",
        )
        target = GenericRAGTarget(config)
        assert target.config.api_key == "test-key"


class TestBaseTarget:
    def test_abstract_methods(self) -> None:
        config = RAGTargetConfig()

        class ConcreteTarget(BaseTarget):
            name = "concrete"

            async def connect(self) -> bool:
                return True

            async def disconnect(self) -> None:
                pass

            async def query(self, text: str, top_k: int = 5) -> list[dict]:
                return []

            async def insert(self, documents: list[dict]) -> bool:
                return True

            async def get_collection_info(self) -> dict:
                return {}

        target = ConcreteTarget(config)
        assert target.name == "concrete"
        assert target.config == config
