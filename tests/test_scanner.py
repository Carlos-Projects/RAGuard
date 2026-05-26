"""Tests for RAGuard scanner engine."""

import pytest

from raguard.config import RAGuardSettings
from raguard.detectors.base import BaseDetector
from raguard.models import (
    Confidence,
    RAGAttackType,
    RAGFinding,
    RAGScanReport,
    RAGTargetConfig,
    Severity,
    TargetType,
)
from raguard.scanner import RAGuardScanner


class MockDetector(BaseDetector):
    """Mock detector for testing."""

    name = "mock_detector"
    description = "A mock detector for testing"

    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        return [
            RAGFinding(
                detector=self.name,
                attack_type=RAGAttackType.DATA_POISONING,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Mock finding",
                description="A mock finding for testing",
                target=target.url,
                risk_score=70,
            )
        ]


class MockFailingDetector(BaseDetector):
    """Mock detector that always fails."""

    name = "mock_failing"
    description = "A detector that always fails"

    async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
        raise RuntimeError("Detector failure simulation")


class TestRAGuardScanner:
    def test_scanner_default_init(self) -> None:
        scanner = RAGuardScanner()
        assert scanner.settings is not None
        assert isinstance(scanner.settings, RAGuardSettings)

    def test_scanner_custom_settings(self) -> None:
        settings = RAGuardSettings(timeout=60.0, verbose=True)
        scanner = RAGuardScanner(settings=settings)
        assert scanner.settings.timeout == 60.0
        assert scanner.settings.verbose is True

    def test_scanner_custom_detectors(self) -> None:
        scanner = RAGuardScanner(detectors=[MockDetector])
        assert len(scanner._detectors) == 1
        assert scanner._detectors[0] == MockDetector

    def test_add_detector(self) -> None:
        scanner = RAGuardScanner(detectors=[])
        before = len(scanner._detectors)
        scanner.add_detector(MockDetector)
        assert len(scanner._detectors) == before + 1
        assert scanner._detectors[-1] == MockDetector

    def test_clear_detectors(self) -> None:
        scanner = RAGuardScanner(detectors=[MockDetector])
        scanner.clear_detectors()
        assert len(scanner._detectors) == 0

    @pytest.mark.asyncio
    async def test_scan_with_mock_detector(self) -> None:
        scanner = RAGuardScanner(detectors=[MockDetector])
        target = RAGTargetConfig(
            url="http://test.com",
            type=TargetType.GENERIC,
        )
        report = await scanner.scan(target)

        assert isinstance(report, RAGScanReport)
        assert report.target_url == "http://test.com"
        assert report.target_type == TargetType.GENERIC
        assert report.total_findings == 1
        assert report.findings[0].detector == "mock_detector"
        assert report.scan_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_scan_with_failing_detector(self) -> None:
        settings = RAGuardSettings(debug=True)
        scanner = RAGuardScanner(
            settings=settings,
            detectors=[MockFailingDetector],
        )
        target = RAGTargetConfig(url="http://test.com")
        report = await scanner.scan(target)

        assert report.total_findings == 0
        assert report.risk_score == 0

    @pytest.mark.asyncio
    async def test_scan_url_convenience(self) -> None:
        scanner = RAGuardScanner(detectors=[MockDetector])
        report = await scanner.scan_url("http://test.com", target_type=TargetType.CHROMA)

        assert report.target_url == "http://test.com"
        assert report.target_type == TargetType.CHROMA

    @pytest.mark.asyncio
    async def test_scan_risk_computation(self) -> None:
        scanner = RAGuardScanner(detectors=[MockDetector])
        target = RAGTargetConfig(url="http://test.com")
        report = await scanner.scan(target)

        report.compute_risk()
        assert report.risk_score > 0
        assert report.risk_category in ("low", "medium", "high", "critical", "info", "none")

    @pytest.mark.asyncio
    async def test_scan_multiple_detectors(self) -> None:
        class SecondMockDetector(BaseDetector):
            name = "second_mock"
            description = "Second mock detector"

            async def detect(self, target: RAGTargetConfig) -> list[RAGFinding]:
                return [
                    RAGFinding(
                        detector=self.name,
                        attack_type=RAGAttackType.PROMPT_LEAKAGE,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        title="Second finding",
                        risk_score=85,
                    )
                ]

        scanner = RAGuardScanner(detectors=[MockDetector, SecondMockDetector])
        target = RAGTargetConfig(url="http://test.com")
        report = await scanner.scan(target)

        assert report.total_findings == 2
        assert report.findings[0].detector == "mock_detector"
        assert report.findings[1].detector == "second_mock"
