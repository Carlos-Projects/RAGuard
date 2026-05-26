"""Tests for prompt leakage detector."""

import pytest

from raguard.detectors.prompt_leakage import PromptLeakageDetector
from raguard.models import RAGAttackType, RAGTargetConfig, Severity


class TestPromptLeakageDetector:
    def test_detector_attributes(self) -> None:
        detector = PromptLeakageDetector()
        assert detector.name == "prompt_leakage"
        assert len(detector.LEAKAGE_QUERIES) > 0
        assert len(detector.LEAKAGE_INDICATORS) > 0

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = PromptLeakageDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.PROMPT_LEAKAGE for f in findings)

    @pytest.mark.asyncio
    async def test_critical_severity_findings(self) -> None:
        detector = PromptLeakageDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=8192)
        findings = await detector.detect(target)

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = PromptLeakageDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "prompt_leakage"
            assert finding.title != ""
            assert finding.recommendation != ""

    @pytest.mark.asyncio
    async def test_direct_extraction_method(self) -> None:
        detector = PromptLeakageDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=8192)
        findings = await detector.detect(target)

        direct_findings = [f for f in findings if f.details.get("method") == "direct_extraction"]
        assert len(direct_findings) > 0
