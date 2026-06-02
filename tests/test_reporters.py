"""Tests for RAGuard reporters."""

import json
import tempfile
from pathlib import Path

import pytest

from raguard.models import Confidence, RAGAttackType, RAGFinding, RAGScanReport, Severity, TargetType
from raguard.reporters.console import ConsoleReporter
from raguard.reporters.html import HTMLReporter
from raguard.reporters.json import JSONReporter
from raguard.reporters.sarif import SARIFReporter


def create_test_report() -> RAGScanReport:
    return RAGScanReport(
        target_url="http://test.com",
        target_type=TargetType.GENERIC,
        findings=[
            RAGFinding(
                detector="test_detector",
                attack_type=RAGAttackType.DATA_POISONING,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Test finding",
                description="Test description",
                recommendation="Test recommendation",
                target="http://test.com",
                risk_score=75,
            ),
            RAGFinding(
                detector="test_detector",
                attack_type=RAGAttackType.PROMPT_LEAKAGE,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Critical finding",
                description="Critical description",
                recommendation="Critical recommendation",
                target="http://test.com",
                risk_score=90,
            ),
        ],
        risk_score=100,
        risk_category="critical",
    )


class TestJSONReporter:
    def test_render_returns_valid_json(self) -> None:
        reporter = JSONReporter()
        report = create_test_report()
        output = reporter.render(report)

        data = json.loads(output)
        assert data["scanner"] == "raguard"
        assert data["target"]["url"] == "http://test.com"
        assert len(data["findings"]) == 2

    def test_render_finding_fields(self) -> None:
        reporter = JSONReporter()
        report = create_test_report()
        output = reporter.render(report)

        data = json.loads(output)
        finding = data["findings"][0]
        assert "id" in finding
        assert finding["detector"] == "test_detector"
        assert finding["attack_type"] == "data_poisoning"
        assert finding["severity"] == "high"


class TestHTMLReporter:
    def test_render_returns_html(self) -> None:
        reporter = HTMLReporter()
        report = create_test_report()
        output = reporter.render(report)

        assert "<!DOCTYPE html>" in output
        assert "RAGuard Scan Report" in output
        assert "Test finding" in output

    def test_render_to_file(self) -> None:
        reporter = HTMLReporter()
        report = create_test_report()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            reporter.render_to_file(report, f.name)
            content = Path(f.name).read_text()
            assert "<!DOCTYPE html>" in content
            Path(f.name).unlink()


class TestSARIFReporter:
    def test_render_returns_valid_sarif(self) -> None:
        reporter = SARIFReporter()
        report = create_test_report()
        output = reporter.render(report)

        data = json.loads(output)
        assert data["$schema"] is not None
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_sarif_rules(self) -> None:
        reporter = SARIFReporter()
        report = create_test_report()
        output = reporter.render(report)

        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 2

    def test_sarif_results(self) -> None:
        reporter = SARIFReporter()
        report = create_test_report()
        output = reporter.render(report)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"].startswith("RAGUARD_")


class TestConsoleReporter:
    def test_render_returns_string(self, capsys: pytest.CaptureFixture) -> None:
        reporter = ConsoleReporter()
        report = create_test_report()
        output = reporter.render(report)

        # The reporter prints to console and returns summary parts
        assert "RAGuard Scan Results" in output or "Scan Results" in output
        captured = capsys.readouterr()
        assert "Test finding" in captured.out

    def test_quiet_render_prints_findings_only(self, capsys: pytest.CaptureFixture) -> None:
        reporter = ConsoleReporter(quiet=True)
        report = create_test_report()
        output = reporter.render(report)

        assert output == "2 findings"
        captured = capsys.readouterr()
        assert "Findings (2)" in captured.out
        assert "Test finding" in captured.out
        assert "RAGuard Scan Results" not in captured.out
        assert "Summary" not in captured.out
        assert "Risk Score" not in captured.out

    def test_quiet_render_without_findings_prints_nothing(self, capsys: pytest.CaptureFixture) -> None:
        reporter = ConsoleReporter(quiet=True)
        report = RAGScanReport(
            target_url="http://test.com",
            target_type=TargetType.GENERIC,
            findings=[],
        )

        output = reporter.render(report)

        assert output == ""
        captured = capsys.readouterr()
        assert captured.out == ""
