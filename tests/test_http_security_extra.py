"""Additional HTTP security tests for retry and edge case coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from raguard.utils.http import RAGuardHTTPClient, validate_target_url


class TestValidateTargetURL:
    def test_missing_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="must have a scheme"):
            validate_target_url("")

    def test_unsupported_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_target_url("ftp://localhost")

    def test_empty_hostname_raises(self) -> None:
        with pytest.raises(ValueError, match="must have a hostname"):
            validate_target_url("http://")

    def test_valid_url_returns_url(self) -> None:
        assert validate_target_url("http://example.com") == "http://example.com"

    def test_valid_https_url(self) -> None:
        assert validate_target_url("https://api.example.com:443/path") == "https://api.example.com:443/path"


class TestRAGuardHTTPClientRetries:
    async def test_get_retries_on_request_error(self) -> None:
        client = RAGuardHTTPClient(max_retries=3)
        with patch.object(client, "_client") as mock:
            mock.get = AsyncMock(side_effect=httpx.RequestError("Connection error"))

            with pytest.raises(httpx.RequestError):
                await client.get("http://example.com")

            assert mock.get.call_count == 3

    async def test_get_succeeds_on_retry(self) -> None:
        client = RAGuardHTTPClient(max_retries=3)
        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = 200

        with patch.object(client, "_client") as mock:
            mock.get = AsyncMock(
                side_effect=[
                    httpx.RequestError("First fail"),
                    httpx.RequestError("Second fail"),
                    mock_response,
                ]
            )

            with patch("raguard.utils.http.validate_target_url", return_value="http://example.com"):
                response = await client.get("http://example.com")
                assert response.status_code == 200
                assert mock.get.call_count == 3

    async def test_post_retries_on_request_error(self) -> None:
        client = RAGuardHTTPClient(max_retries=2)
        with patch.object(client, "_client") as mock:
            mock.post = AsyncMock(side_effect=httpx.RequestError("Connection error"))

            with pytest.raises(httpx.RequestError):
                await client.post("http://example.com")

            assert mock.post.call_count == 2

    async def test_post_succeeds_on_retry(self) -> None:
        client = RAGuardHTTPClient(max_retries=3)
        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = 200

        with patch.object(client, "_client") as mock:
            mock.post = AsyncMock(
                side_effect=[
                    httpx.RequestError("First fail"),
                    mock_response,
                ]
            )

            response = await client.post("http://example.com", json={"key": "value"})
            assert response.status_code == 200
            assert mock.post.call_count == 2

    async def test_get_raises_after_all_retries_exhausted(self) -> None:
        client = RAGuardHTTPClient(max_retries=2)
        with patch.object(client, "_client") as mock:
            mock.get = AsyncMock(side_effect=httpx.RequestError("Always fails"))

            with pytest.raises(httpx.RequestError, match="Always fails"):
                await client.get("http://example.com")
