"""Tests for RAGuard config."""


from raguard.config import RAGuardSettings


class TestRAGuardSettings:
    def test_default_settings(self) -> None:
        settings = RAGuardSettings()
        assert settings.timeout == 30.0
        assert settings.max_retries == 3
        assert settings.concurrent_scans == 5
        assert settings.severity_threshold == "low"
        assert settings.max_documents_test == 50
        assert settings.max_queries_test == 20
        assert settings.output_format == "rich"
        assert settings.verbose is False
        assert settings.debug is False
        assert settings.ci_threshold == "high"
        assert settings.embedding_dimension == 1536
        assert settings.similarity_threshold == 0.85

    def test_custom_settings(self) -> None:
        settings = RAGuardSettings(
            timeout=60.0,
            max_retries=5,
            verbose=True,
            debug=True,
        )
        assert settings.timeout == 60.0
        assert settings.max_retries == 5
        assert settings.verbose is True
        assert settings.debug is True

    def test_env_prefix(self) -> None:
        settings = RAGuardSettings()
        assert settings.model_config.get("env_prefix") == "RAGUARD_"
