"""Tests for membership inference detector."""

import pytest

from raguard.detectors.membership_inference import MembershipInferenceDetector
from raguard.models import RAGAttackType, RAGTargetConfig


class TestMembershipInferenceDetector:
    def test_detector_attributes(self) -> None:
        detector = MembershipInferenceDetector()
        assert detector.name == "membership_inference"
        assert detector.description != ""
        assert len(detector.MEMBERSHIP_QUERIES) == 5

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = MembershipInferenceDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.MEMBERSHIP_INFERENCE for f in findings)

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = MembershipInferenceDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "membership_inference"
            assert finding.title != ""
            assert finding.description != ""
            assert finding.recommendation != ""

    @pytest.mark.asyncio
    async def test_entailment_method_reference(self) -> None:
        detector = MembershipInferenceDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=4096)
        findings = await detector.detect(target)

        entailment_findings = [f for f in findings if f.details.get("method") == "entailment_queries"]
        assert len(entailment_findings) > 0

    @pytest.mark.asyncio
    async def test_references_research_paper(self) -> None:
        detector = MembershipInferenceDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        paper_refs = [f for f in findings if f.details.get("paper")]
        assert len(paper_refs) > 0
