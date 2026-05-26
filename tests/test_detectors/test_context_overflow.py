"""Tests for context overflow detector."""

import pytest

from raguard.detectors.context_overflow import ContextOverflowDetector
from raguard.models import RAGAttackType, RAGTargetConfig


class TestContextOverflowDetector:
    def test_detector_attributes(self) -> None:
        detector = ContextOverflowDetector()
        assert detector.name == "context_overflow"
        assert len(detector.VULNERABLE_CONTEXT_SIZES) > 0

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = ContextOverflowDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=4096)
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.CONTEXT_OVERFLOW for f in findings)

    @pytest.mark.asyncio
    async def test_small_context_window_finding(self) -> None:
        detector = ContextOverflowDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=4096)
        findings = await detector.detect(target)

        overflow_findings = [f for f in findings if "context_window" in f.details]
        assert len(overflow_findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = ContextOverflowDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "context_overflow"
            assert finding.title != ""
            assert finding.recommendation != ""

    @pytest.mark.asyncio
    async def test_truncation_evasion_method(self) -> None:
        detector = ContextOverflowDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=4096)
        findings = await detector.detect(target)

        truncation_findings = [f for f in findings if f.details.get("method") == "truncation_evasion"]
        assert len(truncation_findings) > 0
