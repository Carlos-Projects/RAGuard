"""Tests for policy bypass detector."""

import pytest

from raguard.detectors.policy_bypass import PolicyBypassDetector
from raguard.models import RAGAttackType, RAGTargetConfig


class TestPolicyBypassDetector:
    def test_detector_attributes(self) -> None:
        detector = PolicyBypassDetector()
        assert detector.name == "policy_bypass"
        assert detector.description != ""
        assert len(detector.BYPASS_INDICATORS) > 0

    @pytest.mark.asyncio
    async def test_detect_returns_findings(self) -> None:
        detector = PolicyBypassDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)
        assert len(findings) > 0
        assert all(f.attack_type == RAGAttackType.POLICY_BYPASS for f in findings)

    @pytest.mark.asyncio
    async def test_trusted_context_bypass_finding(self) -> None:
        detector = PolicyBypassDetector()
        target = RAGTargetConfig(url="http://test.com", context_window=8192)
        findings = await detector.detect(target)

        trusted_findings = [f for f in findings if f.details.get("method") == "trusted_context_bypass"]
        assert len(trusted_findings) > 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self) -> None:
        detector = PolicyBypassDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        for finding in findings:
            assert finding.detector == "policy_bypass"
            assert finding.title != ""
            assert finding.recommendation != ""

    @pytest.mark.asyncio
    async def test_multiple_finding_types(self) -> None:
        detector = PolicyBypassDetector()
        target = RAGTargetConfig(url="http://test.com")
        findings = await detector.detect(target)

        methods = {f.details.get("method") for f in findings}
        assert len(methods) >= 2
