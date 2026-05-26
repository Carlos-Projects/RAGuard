"""Core RAGuard scanning engine."""

from __future__ import annotations

import time

import raguard.detectors.context_overflow  # noqa: F401

# Import all detectors to register them
import raguard.detectors.data_poisoning  # noqa: F401
import raguard.detectors.membership_inference  # noqa: F401
import raguard.detectors.policy_bypass  # noqa: F401
import raguard.detectors.prompt_leakage  # noqa: F401
import raguard.detectors.retrieval_hijack  # noqa: F401
import raguard.detectors.vector_injection  # noqa: F401
from raguard.config import RAGuardSettings
from raguard.detectors.base import BaseDetector
from raguard.detectors.registry import get_all_detectors
from raguard.models import RAGScanReport, RAGTargetConfig, TargetType


class RAGuardScanner:
    """Main scanning engine that orchestrates detectors against RAG targets."""

    def __init__(
        self,
        settings: RAGuardSettings | None = None,
        detectors: list[type[BaseDetector]] | None = None,
    ) -> None:
        self.settings = settings or RAGuardSettings()
        self._detectors: list[type[BaseDetector]] = detectors if detectors is not None else []
        self._load_default_detectors()

    def _load_default_detectors(self) -> None:
        """Load all registered detectors if none specified."""
        if not self._detectors:
            all_detectors = get_all_detectors()
            self._detectors = list(all_detectors.values())

    def add_detector(self, detector_cls: type[BaseDetector]) -> None:
        """Add a detector to the scanner."""
        self._detectors.append(detector_cls)

    def clear_detectors(self) -> None:
        """Clear all detectors."""
        self._detectors.clear()

    async def scan(self, target: RAGTargetConfig) -> RAGScanReport:
        """Execute a full security scan against a RAG target.

        Args:
            target: Configuration for the RAG system to test.

        Returns:
            Complete scan report with all findings.
        """
        start_time = time.monotonic()
        all_findings = []

        for detector_cls in self._detectors:
            detector = detector_cls()
            try:
                findings = await detector.detect(target)
                all_findings.extend(findings)
            except Exception as exc:
                if self.settings.debug:
                    # Log only the exception type, not the message (may contain secrets)
                    print(f"[DEBUG] Detector {detector.name} failed: {type(exc).__name__}")

        elapsed_ms = (time.monotonic() - start_time) * 1000

        report = RAGScanReport(
            target_url=target.url,
            target_type=target.type,
            findings=all_findings,
            scan_duration_ms=elapsed_ms,
            config={
                "timeout": self.settings.timeout,
                "max_retries": self.settings.max_retries,
                "embedding_model": target.embedding_model,
                "context_window": target.context_window,
            },
        )
        report.compute_risk()
        return report

    async def scan_url(
        self,
        url: str,
        target_type: TargetType = TargetType.GENERIC,
        **kwargs: str,
    ) -> RAGScanReport:
        """Convenience method to scan by URL.

        Args:
            url: Target URL.
            target_type: Type of RAG system.
            **kwargs: Additional target config options.

        Returns:
            Scan report.
        """
        target = RAGTargetConfig(
            url=url,
            type=target_type,
            **{k: v for k, v in kwargs.items() if v is not None},
        )
        return await self.scan(target)
