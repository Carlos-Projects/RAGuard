"""Additional CLI tests for edge case coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from raguard.cli import _get_api_key, _safe_write_text, _validate_api_key, main


class TestValidateApiKey:
    def test_none_key(self) -> None:
        assert _validate_api_key(None) is None

    def test_empty_key(self) -> None:
        assert _validate_api_key("") == ""

    def test_invalid_chars(self) -> None:
        with pytest.raises(ValueError, match="API key contains invalid characters"):
            _validate_api_key("bad key!")

    def test_valid_key_validates_without_printing_warning(self) -> None:
        with patch("raguard.cli.console.print") as mock_print:
            result = _validate_api_key("valid-key-123")
            assert result == "valid-key-123"
            mock_print.assert_not_called()


class TestGetApiKey:
    def test_cli_key_prints_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RAGUARD_API_KEY", raising=False)
        with patch("raguard.cli.console.print") as mock_print:
            result = _get_api_key("valid-key-123")
            assert result == "valid-key-123"
            mock_print.assert_called_once()

    def test_quiet_cli_key_suppresses_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RAGUARD_API_KEY", raising=False)
        with patch("raguard.cli.console.print") as mock_print:
            result = _get_api_key("valid-key-123", quiet=True)
            assert result == "valid-key-123"
            mock_print.assert_not_called()

    def test_env_key_wins_over_cli_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RAGUARD_API_KEY", "env-key")
        with patch("raguard.cli.console.print") as mock_print:
            result = _get_api_key("cli-key")
            assert result == "env-key"
            mock_print.assert_called_once()


class TestSafeWriteText:
    def test_write_normal(self, tmp_path: Path) -> None:
        path = tmp_path / "output.txt"
        _safe_write_text(path, "hello world")
        assert path.read_text() == "hello world"

    def test_write_too_large(self, tmp_path: Path) -> None:
        from raguard.cli import MAX_OUTPUT_SIZE

        path = tmp_path / "large.txt"
        large_content = "x" * (MAX_OUTPUT_SIZE + 1)
        with pytest.raises(ValueError, match="exceeds maximum size"):
            _safe_write_text(path, large_content)


class TestMainEntryPoint:
    @patch("raguard.cli.app")
    def test_main_calls_app(self, mock_app: MagicMock) -> None:
        main()
        mock_app.assert_called_once()
