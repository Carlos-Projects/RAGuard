"""Registry for RAG security detectors."""

from __future__ import annotations

from raguard.detectors.base import BaseDetector

_registry: dict[str, type[BaseDetector]] = {}


def register(detector_cls: type[BaseDetector]) -> type[BaseDetector]:
    """Register a detector class.

    Usage:
        @register
        class MyDetector(BaseDetector):
            name = "my_detector"
            ...
    """
    if not detector_cls.name or detector_cls.name == "base":
        raise ValueError("Detector must have a unique 'name' attribute")
    _registry[detector_cls.name] = detector_cls
    return detector_cls


def get_detector(name: str) -> type[BaseDetector] | None:
    """Get a registered detector by name."""
    return _registry.get(name)


def get_all_detectors() -> dict[str, type[BaseDetector]]:
    """Get all registered detectors."""
    return dict(_registry)


def clear_registry() -> None:
    """Clear the detector registry (useful for testing)."""
    _registry.clear()
