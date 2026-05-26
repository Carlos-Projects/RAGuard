"""Tests for retrieval hijack detector."""

import pytest

from raguard.detectors.retrieval_hijack import RetrievalHijackDetector
from raguard.models import RAGAttackType, RAGTargetConfig


class TestRetrievalHijackDetector:
    def test_detector_attributes(self) -> None:
        detector = RetrievalHijackDetector()
        assert detector.name == "retrieval_hijack"
        assert detector.description != ""

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = RetrievalHijackDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.RETRIEVAL_HIJACK for f in findings)

    @pytest.mark.asyncio
    async def test_similarity_manipulation_finding(self) -> None:
        detector = RetrievalHijackDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        sim_findings = [f for f in findings if f.details.get("method") == "similarity_manipulation"]
        assert len(sim_findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = RetrievalHijackDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "retrieval_hijack"
            assert finding.title != ""
            assert finding.recommendation != ""

    @pytest.mark.asyncio
    async def test_multiple_finding_types(self) -> None:
        detector = RetrievalHijackDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        methods = {f.details.get("method") for f in findings}
        assert len(methods) >= 2
