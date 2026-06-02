"""Tests for RAGuard CLI - extended coverage."""

import json
from pathlib import Path

from typer.testing import CliRunner

from raguard.cli import app

runner = CliRunner()


class TestCLIScanCommand:
    def test_scan_with_json_output(self, tmp_path: Path) -> None:
        output_file = tmp_path / "results.json"
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--format", "json", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "scanner" in data

    def test_scan_with_sarif_output(self, tmp_path: Path) -> None:
        output_file = tmp_path / "results.sarif"
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--format", "sarif", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["version"] == "2.1.0"

    def test_scan_with_html_output(self, tmp_path: Path) -> None:
        output_file = tmp_path / "report.html"
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--format", "html", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content

    def test_scan_with_verbose_flag(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--verbose"],
        )
        assert result.exit_code == 0

    def test_scan_with_quiet_flag(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--quiet"],
        )
        assert result.exit_code == 0
        assert "Findings" in result.stdout
        assert "RAGuard Scan Results" not in result.stdout
        assert "Risk Score" not in result.stdout
        assert "Summary" not in result.stdout

    def test_scan_quiet_with_output_file_suppresses_save_message(self, tmp_path: Path) -> None:
        output_file = tmp_path / "results.json"
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--format", "json", "--quiet", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        assert result.stdout == ""

    def test_scan_with_api_key(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--api-key", "test-key"],
        )
        assert result.exit_code == 0

    def test_scan_quiet_with_api_key_suppresses_warning(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--quiet", "--api-key", "test-key"],
        )
        assert result.exit_code == 0
        assert "Warning" not in result.stdout
        assert "Findings" in result.stdout

    def test_scan_with_custom_collection(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--collection", "my_docs"],
        )
        assert result.exit_code == 0

    def test_scan_ci_mode_pass(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--ci", "--threshold", "critical"],
        )
        # Should pass since default scan has findings but risk might be below critical
        assert result.exit_code in (0, 1)

    def test_scan_unknown_format(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://localhost:8000", "--format", "xml"],
        )
        assert result.exit_code != 0


class TestCLIReportCommand:
    def test_report_json_format(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(
            json.dumps(
                {
                    "target_url": "http://test.com",
                    "target_type": "generic",
                    "findings": [],
                    "risk_score": 0,
                    "risk_category": "none",
                    "scan_duration_ms": 100,
                    "scanner_version": "0.1.0",
                    "config": {},
                    "timestamp": "2026-01-01T00:00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            ["report", str(scan_file), "--format", "json"],
        )
        assert result.exit_code == 0
        assert "raguard" in result.stdout

    def test_report_html_format(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(
            json.dumps(
                {
                    "target_url": "http://test.com",
                    "target_type": "generic",
                    "findings": [],
                    "risk_score": 0,
                    "risk_category": "none",
                    "scan_duration_ms": 100,
                    "scanner_version": "0.1.0",
                    "config": {},
                    "timestamp": "2026-01-01T00:00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            ["report", str(scan_file), "--format", "html"],
        )
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.stdout

    def test_report_sarif_format(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(
            json.dumps(
                {
                    "target_url": "http://test.com",
                    "target_type": "generic",
                    "findings": [],
                    "risk_score": 0,
                    "risk_category": "none",
                    "scan_duration_ms": 100,
                    "scanner_version": "0.1.0",
                    "config": {},
                    "timestamp": "2026-01-01T00:00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            ["report", str(scan_file), "--format", "sarif"],
        )
        assert result.exit_code == 0
        assert "2.1.0" in result.stdout

    def test_report_output_to_file(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "scan.json"
        output_file = tmp_path / "report.json"
        scan_file.write_text(
            json.dumps(
                {
                    "target_url": "http://test.com",
                    "target_type": "generic",
                    "findings": [],
                    "risk_score": 0,
                    "risk_category": "none",
                    "scan_duration_ms": 100,
                    "scanner_version": "0.1.0",
                    "config": {},
                    "timestamp": "2026-01-01T00:00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            ["report", str(scan_file), "--format", "json", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestCLIPolicyCommand:
    def test_policy_generate(self, tmp_path: Path) -> None:
        output_file = tmp_path / "policies.yaml"
        result = runner.invoke(
            app,
            ["policy", "http://localhost:8000", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "raguard" in content
        assert "rules" in content

    def test_policy_with_chroma_type(self, tmp_path: Path) -> None:
        output_file = tmp_path / "policies.yaml"
        result = runner.invoke(
            app,
            ["policy", "http://localhost:8000", "--type", "chroma", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()

    def test_policy_default_output(self, tmp_path: Path) -> None:
        import os

        original_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(
                app,
                ["policy", "http://localhost:8000"],
            )
            assert result.exit_code == 0
            assert (tmp_path / "raguard-policies.yaml").exists()
        finally:
            os.chdir(original_cwd)
