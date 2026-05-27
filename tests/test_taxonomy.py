"""Tests for RAGuard taxonomy adapter."""

from mcp_taxonomy import AttackCategory
from mcp_taxonomy import Confidence as TaxConfidence
from mcp_taxonomy import Severity as TaxSeverity

from raguard.models import Confidence, RAGAttackType, RAGFinding, Severity
from raguard.taxonomy import ATTACK_TYPE_TO_CATEGORY, SEVERITY_MAP, normalize_finding


class TestTaxonomyMapping:
    def test_attack_type_mapping_complete(self) -> None:
        for attack_type in RAGAttackType:
            assert attack_type in ATTACK_TYPE_TO_CATEGORY

    def test_severity_mapping_complete(self) -> None:
        for severity in Severity:
            assert severity in SEVERITY_MAP

    def test_data_poisoning_maps_to_data_poisoning(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.DATA_POISONING] == AttackCategory.DATA_POISONING

    def test_membership_inference_maps_to_membership_inference(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.MEMBERSHIP_INFERENCE] == AttackCategory.MEMBERSHIP_INFERENCE

    def test_prompt_leakage_maps_to_exfiltration(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.PROMPT_LEAKAGE] == AttackCategory.EXFILTRATION

    def test_policy_bypass_maps_to_policy_violation(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.POLICY_BYPASS] == AttackCategory.POLICY_VIOLATION

    def test_context_overflow_maps_to_context_overflow(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.CONTEXT_OVERFLOW] == AttackCategory.CONTEXT_OVERFLOW

    def test_retrieval_hijack_maps_to_retrieval_hijack(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.RETRIEVAL_HIJACK] == AttackCategory.RETRIEVAL_HIJACK

    def test_vector_injection_maps_to_vector_injection(self) -> None:
        assert ATTACK_TYPE_TO_CATEGORY[RAGAttackType.VECTOR_INJECTION] == AttackCategory.VECTOR_INJECTION


class TestNormalizeFinding:
    def test_normalize_finding_returns_taxonomy_event(self) -> None:
        finding = RAGFinding(
            detector="test_detector",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test finding",
            description="Test description",
            recommendation="Test recommendation",
            target="http://test.com",
            risk_score=75,
        )
        event = normalize_finding(finding)

        assert event.source == "raguard"
        assert event.attack_category == AttackCategory.DATA_POISONING
        assert event.severity == TaxSeverity.HIGH
        assert event.confidence == TaxConfidence.HIGH
        assert event.title == "Test finding"
        assert event.description == "Test description"
        assert event.recommendation == "Test recommendation"
        assert event.target == "http://test.com"
        assert event.risk_score == 75

    def test_normalize_critical_finding(self) -> None:
        finding = RAGFinding(
            detector="test",
            attack_type=RAGAttackType.PROMPT_LEAKAGE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            title="Critical leak",
            risk_score=90,
        )
        event = normalize_finding(finding)

        assert event.severity == TaxSeverity.CRITICAL
        assert event.confidence == TaxConfidence.CERTAIN
        assert event.attack_category == AttackCategory.EXFILTRATION

    def test_normalize_with_details(self) -> None:
        finding = RAGFinding(
            detector="test",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Test",
            details={"snippet": "test snippet", "key": "value"},
        )
        event = normalize_finding(finding)

        assert event.raw is not None
        assert event.raw["snippet"] == "test snippet"
