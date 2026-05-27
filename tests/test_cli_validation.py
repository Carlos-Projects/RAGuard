"""Tests for CLI validation functions."""

import pytest

from raguard.cli import (
    _get_api_key,
    _validate_api_key,
    _validate_collection,
    _validate_detectors,
    _validate_format,
    _validate_output_path,
    _validate_target_type,
    _validate_target_url,
    _validate_threshold,
)


class TestValidateTargetURL:
    def test_valid_http_url(self) -> None:
        assert _validate_target_url("http://example.com:8000") == "http://example.com:8000"

    def test_valid_https_url(self) -> None:
        assert _validate_target_url("https://rag-system.internal/api") == "https://rag-system.internal/api"

    def test_localhost_allowed(self) -> None:
        assert _validate_target_url("http://localhost:8000") == "http://localhost:8000"

    def test_localhost_ip_allowed(self) -> None:
        assert _validate_target_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"

    def test_filesystem_path_allowed(self) -> None:
        assert _validate_target_url("./data/chroma") == "./data/chroma"

    def test_path_traversal_blocked(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            _validate_target_url("../../etc/passwd")

    def test_non_http_path_allowed_as_filesystem(self) -> None:
        """Non-HTTP paths are treated as filesystem paths (for ChromaDB)."""
        assert _validate_target_url("ftp://example.com") == "ftp://example.com"

    def test_empty_hostname_blocked(self) -> None:
        with pytest.raises(ValueError, match="hostname"):
            _validate_target_url("http:///path")


class TestValidateTargetType:
    def test_valid_types(self) -> None:
        for t in ("chroma", "milvus", "qdrant", "generic"):
            assert _validate_target_type(t) == t

    def test_invalid_type(self) -> None:
        with pytest.raises(ValueError, match="Invalid target type"):
            _validate_target_type("invalid")


class TestValidateThreshold:
    def test_valid_thresholds(self) -> None:
        for t in ("low", "medium", "high", "critical"):
            assert _validate_threshold(t) == t

    def test_invalid_threshold(self) -> None:
        with pytest.raises(ValueError, match="Invalid threshold"):
            _validate_threshold("extreme")


class TestValidateFormat:
    def test_valid_formats(self) -> None:
        for f in ("rich", "json", "html", "sarif"):
            assert _validate_format(f) == f

    def test_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid format"):
            _validate_format("xml")


class TestValidateCollection:
    def test_valid_names(self) -> None:
        for name in ("default", "my_collection", "docs-v2", "Test123"):
            assert _validate_collection(name) == name

    def test_name_too_long(self) -> None:
        with pytest.raises(ValueError, match="Invalid collection"):
            _validate_collection("a" * 200)

    def test_name_with_special_chars(self) -> None:
        with pytest.raises(ValueError, match="Invalid collection"):
            _validate_collection("my collection!")

    def test_empty_name(self) -> None:
        with pytest.raises(ValueError, match="Invalid collection"):
            _validate_collection("")


class TestValidateApiKey:
    def test_none_allowed(self) -> None:
        assert _validate_api_key(None) is None

    def test_valid_key(self) -> None:
        assert _validate_api_key("sk-abc123-XYZ") == "sk-abc123-XYZ"

    def test_empty_key(self) -> None:
        assert _validate_api_key("") == ""


class TestValidateDetectors:
    def test_none_allowed(self) -> None:
        assert _validate_detectors(None) is None

    def test_single_valid(self) -> None:
        assert _validate_detectors("data_poisoning") == "data_poisoning"

    def test_multiple_valid(self) -> None:
        result = _validate_detectors("data_poisoning,prompt_leakage")
        assert result == "data_poisoning,prompt_leakage"

    def test_invalid_detector(self) -> None:
        with pytest.raises(ValueError, match="Unknown detector"):
            _validate_detectors("nonexistent")

    def test_partial_invalid(self) -> None:
        with pytest.raises(ValueError, match="Unknown detector"):
            _validate_detectors("data_poisoning,bad_detector")


class TestValidateOutputPath:
    def test_relative_path_allowed(self) -> None:
        path = _validate_output_path("results.json")
        assert path.name == "results.json"

    def test_absolute_path_allowed(self) -> None:
        path = _validate_output_path("/tmp/results.json")
        assert path.name == "results.json"

    def test_traversal_blocked(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            _validate_output_path("../outside/file.txt")

    def test_deep_traversal_blocked(self) -> None:
        with pytest.raises(ValueError, match="traversal"):
            _validate_output_path("a/b/../../../../etc/passwd")


class TestGetApiKey:
    def test_cli_key_preferred(self) -> None:
        key = _get_api_key("cli-key")
        assert key == "cli-key"

    def test_env_var_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RAGUARD_API_KEY", "env-key")
        key = _get_api_key(None)
        assert key == "env-key"

    def test_env_var_overrides_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RAGUARD_API_KEY", "env-key")
        key = _get_api_key("cli-key")
        assert key == "env-key"
