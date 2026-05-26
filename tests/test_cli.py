"""Tests for RAGuard CLI."""

from typer.testing import CliRunner

from raguard.cli import app

runner = CliRunner()


class TestCLI:
    def test_cli_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "RAGuard" in result.stdout

    def test_scan_help(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan a RAG system" in result.stdout

    def test_report_help(self) -> None:
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate a report" in result.stdout

    def test_policy_help(self) -> None:
        result = runner.invoke(app, ["policy", "--help"])
        assert result.exit_code == 0
        assert "MCPGuard-compatible" in result.stdout

    def test_scan_missing_target(self) -> None:
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_scan_invalid_format(self) -> None:
        result = runner.invoke(app, ["scan", "http://test.com", "--format", "invalid"])
        assert result.exit_code != 0

    def test_report_missing_file(self) -> None:
        result = runner.invoke(app, ["report", "nonexistent.json"])
        assert result.exit_code != 0

    def test_policy_missing_target(self) -> None:
        result = runner.invoke(app, ["policy"])
        assert result.exit_code != 0
