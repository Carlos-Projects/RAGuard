"""Tests for vector injection detector."""

import pytest

from raguard.detectors.vector_injection import VectorInjectionDetector
from raguard.models import RAGAttackType, RAGTargetConfig, Severity, TargetType


class TestVectorInjectionDetector:
    def test_detector_attributes(self) -> None:
        detector = VectorInjectionDetector()
        assert detector.name == "vector_injection"
        assert detector.description != ""

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = VectorInjectionDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.VECTOR_INJECTION for f in findings)

    @pytest.mark.asyncio
    async def test_no_auth_critical_finding(self) -> None:
        detector = VectorInjectionDetector()
        target = RAGTargetConfig(url="http://test.com", api_key=None)
        findings = await detector.detect(target)

        auth_findings = [f for f in findings if f.details.get("has_auth") is False]
        assert len(auth_findings) > 0
        assert auth_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_chroma_injection_finding(self) -> None:
        detector = VectorInjectionDetector()
        target = RAGTargetConfig(
            url="http://test.com",
            type=TargetType.CHROMA,
            api_key="test-key",
        )
        findings = await detector.detect(target)

        injection_findings = [f for f in findings if f.details.get("method") == "direct_api_injection"]
        assert len(injection_findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = VectorInjectionDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "vector_injection"
            assert finding.title != ""
            assert finding.recommendation != ""
