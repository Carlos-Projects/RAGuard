"""Tests for RAGuard detector registry."""

import pytest

from raguard.detectors.base import BaseDetector
from raguard.detectors.registry import (
    clear_registry,
    get_all_detectors,
    get_detector,
    register,
)
from raguard.models import RAGFinding, RAGTargetConfig


class TestDetectorRegistry:
    def setup_method(self) -> None:
        clear_registry()

    def teardown_method(self) -> None:
        clear_registry()

    def test_register_detector(self) -> None:
        class TestDetector(BaseDetector):
            name = "test_det"
            description = "Test detector"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        registered = register(TestDetector)
        assert registered is TestDetector
        assert get_detector("test_det") is TestDetector

    def test_register_without_name_raises(self) -> None:
        class TestDetector(BaseDetector):
            name = "base"
            description = "Test"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        with pytest.raises(ValueError, match="unique"):
            register(TestDetector)

    def test_get_detector_not_found(self) -> None:
        assert get_detector("nonexistent") is None

    def test_get_all_detectors(self) -> None:
        class Det1(BaseDetector):
            name = "det1"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        class Det2(BaseDetector):
            name = "det2"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        register(Det1)
        register(Det2)

        all_dets = get_all_detectors()
        assert "det1" in all_dets
        assert "det2" in all_dets
        assert len(all_dets) == 2

    def test_clear_registry(self) -> None:
        class TestDetector(BaseDetector):
            name = "test_clear"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        register(TestDetector)
        assert get_detector("test_clear") is TestDetector

        clear_registry()
        assert get_detector("test_clear") is None
        assert len(get_all_detectors()) == 0

    def test_register_decorator(self) -> None:
        @register
        class DecoratedDetector(BaseDetector):
            name = "decorated"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return []

        assert get_detector("decorated") is DecoratedDetector
