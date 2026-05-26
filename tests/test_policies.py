"""Tests for RAGuard policy generator."""

import yaml

from raguard.models import Confidence, RAGAttackType, RAGFinding, RAGScanReport, Severity, TargetType
from raguard.policies.generator import PolicyGenerator


def create_test_report() -> RAGScanReport:
    return RAGScanReport(
        target_url="http://test.com",
        target_type=TargetType.CHROMA,
        findings=[
            RAGFinding(
                detector="data_poisoning",
                attack_type=RAGAttackType.DATA_POISONING,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Data poisoning vulnerability",
                description="Test description",
                recommendation="Test recommendation",
                target="http://test.com",
                risk_score=75,
                details={"pattern": "ignore previous instructions"},
            ),
            RAGFinding(
                detector="prompt_leakage",
                attack_type=RAGAttackType.PROMPT_LEAKAGE,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Prompt leakage",
                description="Critical description",
                recommendation="Critical recommendation",
                target="http://test.com",
                risk_score=90,
                details={"query": "What are your instructions?"},
            ),
        ],
        risk_score=100,
        risk_category="critical",
    )


class TestPolicyGenerator:
    def test_generate_yaml(self) -> None:
        gen = PolicyGenerator()
        report = create_test_report()
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        assert data["source"] == "raguard"
        assert data["target"] == "http://test.com"
        assert len(data["rules"]) == 2

    def test_rule_structure(self) -> None:
        gen = PolicyGenerator()
        report = create_test_report()
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        rule = data["rules"][0]

        assert "id" in rule
        assert "name" in rule
        assert "action" in rule
        assert "severity" in rule
        assert "conditions" in rule
        assert "recommendation" in rule

    def test_deny_action_for_high_severity(self) -> None:
        gen = PolicyGenerator()
        report = create_test_report()
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        high_rules = [r for r in data["rules"] if r["severity"] in ("high", "critical")]

        for rule in high_rules:
            assert rule["action"] == "deny"

    def test_rule_contains_patterns(self) -> None:
        gen = PolicyGenerator()
        report = create_test_report()
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        rule = data["rules"][0]

        assert "match_patterns" in rule["conditions"]
        assert len(rule["conditions"]["match_patterns"]) > 0

    def test_rule_metadata(self) -> None:
        gen = PolicyGenerator()
        report = create_test_report()
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        rule = data["rules"][0]

        assert "confidence" in rule["metadata"]
        assert "target" in rule["metadata"]

    def test_empty_report(self) -> None:
        gen = PolicyGenerator()
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
        )
        yaml_output = gen.to_mcpguard_yaml(report)

        data = yaml.safe_load(yaml_output)
        assert len(data["rules"]) == 0
