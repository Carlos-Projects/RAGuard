"""Tests for data poisoning detector."""

import pytest

from raguard.detectors.data_poisoning import DataPoisoningDetector
from raguard.models import RAGAttackType, RAGTargetConfig, TargetType


class TestDataPoisoningDetector:
    def test_detector_attributes(self) -> None:
        detector = DataPoisoningDetector()
        assert detector.name == "data_poisoning"
        assert detector.description != ""
        assert len(detector.POISONING_PATTERNS) > 0

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = DataPoisoningDetector()
        target = RAGTargetConfig(
            url="http://test.com",
            type=TargetType.GENERIC,
            context_window=4096,
        )
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.DATA_POISONING for f in findings)

    @pytest.mark.asyncio
    async def test_detect_vulnerable_target(self) -> None:
        detector = DataPoisoningDetector()
        target = RAGTargetConfig(
            url="http://test.com",
            type=TargetType.CHROMA,
            context_window=8192,
        )
        findings = await detector.detect(target)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = DataPoisoningDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "data_poisoning"
            assert finding.title != ""
            assert finding.description != ""
            assert finding.recommendation != ""
            assert finding.risk_score > 0

    @pytest.mark.asyncio
    async def test_pattern_injection_test(self) -> None:
        detector = DataPoisoningDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=4096)
        findings = await detector.detect(target)

        pattern_findings = [f for f in findings if f.details.get("test") == "pattern_injection"]
        assert len(pattern_findings) > 0
