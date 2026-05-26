"""Tests for RAGuard models."""


from raguard.models import (
    Confidence,
    RAGAttackType,
    RAGFinding,
    RAGScanReport,
    RAGTargetConfig,
    Severity,
    TargetType,
)


class TestSeverity:
    def test_severity_weights(self) -> None:
        assert Severity.CRITICAL.weight == 25
        assert Severity.HIGH.weight == 10
        assert Severity.MEDIUM.weight == 3
        assert Severity.LOW.weight == 1
        assert Severity.INFO.weight == 0

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestConfidence:
    def test_confidence_scores(self) -> None:
        assert Confidence.CERTAIN.score == 1.0
        assert Confidence.HIGH.score == 0.85
        assert Confidence.MEDIUM.score == 0.6
        assert Confidence.LOW.score == 0.3
        assert Confidence.NONE.score == 0.0


class TestRAGAttackType:
    def test_all_attack_types(self) -> None:
        assert RAGAttackType.DATA_POISONING.value == "data_poisoning"
        assert RAGAttackType.MEMBERSHIP_INFERENCE.value == "membership_inference"
        assert RAGAttackType.PROMPT_LEAKAGE.value == "prompt_leakage"
        assert RAGAttackType.CONTEXT_OVERFLOW.value == "context_overflow"
        assert RAGAttackType.RETRIEVAL_HIJACK.value == "retrieval_hijack"
        assert RAGAttackType.VECTOR_INJECTION.value == "vector_injection"
        assert RAGAttackType.POLICY_BYPASS.value == "policy_bypass"


class TestTargetType:
    def test_all_target_types(self) -> None:
        assert TargetType.CHROMA.value == "chroma"
        assert TargetType.MILVUS.value == "milvus"
        assert TargetType.QDRANT.value == "qdrant"
        assert TargetType.GENERIC.value == "generic"


class TestRAGTargetConfig:
    def test_default_config(self) -> None:
        config = RAGTargetConfig()
        assert config.type == TargetType.GENERIC
        assert config.url == "http://localhost:8000"
        assert config.api_key is None
        assert config.collection_name == "default"
        assert config.context_window == 4096

    def test_custom_config(self) -> None:
        config = RAGTargetConfig(
            type=TargetType.CHROMA,
            url="http://chroma:8000",
            api_key="test-key",
            collection_name="my_collection",
            context_window=8192,
        )
        assert config.type == TargetType.CHROMA
        assert config.url == "http://chroma:8000"
        assert config.api_key == "test-key"
        assert config.collection_name == "my_collection"
        assert config.context_window == 8192


class TestRAGFinding:
    def test_create_finding(self) -> None:
        finding = RAGFinding(
            detector="test_detector",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test finding",
            description="Test description",
            recommendation="Test recommendation",
            target="http://test.com",
        )
        assert finding.detector == "test_detector"
        assert finding.attack_type == RAGAttackType.DATA_POISONING
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.title == "Test finding"
        assert finding.risk_score > 0

    def test_finding_risk_calculation(self) -> None:
        finding = RAGFinding(
            detector="test",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            title="Critical finding",
        )
        assert finding.risk_score <= 100
        assert finding.risk_score > 0

    def test_finding_with_custom_risk(self) -> None:
        finding = RAGFinding(
            detector="test",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            risk_score=75,
        )
        assert finding.risk_score == 75

    def test_finding_details(self) -> None:
        finding = RAGFinding(
            detector="test",
            attack_type=RAGAttackType.DATA_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            details={"key": "value", "nested": {"a": 1}},
        )
        assert finding.details["key"] == "value"
        assert finding.details["nested"]["a"] == 1


class TestRAGScanReport:
    def test_empty_report(self) -> None:
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
        )
        assert report.total_findings == 0
        assert report.risk_score == 0
        assert report.risk_category == "none"
        assert report.critical_findings == []
        assert report.high_findings == []

    def test_report_with_findings(self) -> None:
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
            findings=[
                RAGFinding(
                    detector="test",
                    attack_type=RAGAttackType.DATA_POISONING,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Critical finding",
                    risk_score=85,
                ),
                RAGFinding(
                    detector="test",
                    attack_type=RAGAttackType.PROMPT_LEAKAGE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="High finding",
                    risk_score=70,
                ),
            ],
        )
        report.compute_risk()
        assert report.total_findings == 2
        assert len(report.critical_findings) == 1
        assert len(report.high_findings) == 1

    def test_report_risk_categories(self) -> None:
        # Test critical
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
            findings=[
                RAGFinding(
                    detector="test",
                    attack_type=RAGAttackType.DATA_POISONING,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CERTAIN,
                    title="Test",
                    risk_score=90,
                )
            ],
        )
        report.compute_risk()
        assert report.risk_category == "critical"

    def test_report_summary(self) -> None:
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
            findings=[
                RAGFinding(
                    detector="test",
                    attack_type=RAGAttackType.DATA_POISONING,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Test",
                ),
                RAGFinding(
                    detector="test",
                    attack_type=RAGAttackType.PROMPT_LEAKAGE,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    title="Test 2",
                ),
            ],
        )
        assert "critical" in report.summary
        assert "low" in report.summary

    def test_report_empty_summary(self) -> None:
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
        )
        assert "No security issues" in report.summary

    def test_report_config(self) -> None:
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
            config={"timeout": 30, "max_retries": 3},
        )
        assert report.config["timeout"] == 30
