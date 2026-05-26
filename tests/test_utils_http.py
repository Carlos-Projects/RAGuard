"""Tests for RAGuard HTTP client utilities."""

import pytest
import pytest_httpx

from raguard.utils.http import RAGuardHTTPClient


class TestRAGuardHTTPClient:
    def test_init_defaults(self) -> None:
        client = RAGuardHTTPClient()
        assert client.timeout == 30.0
        assert client.max_retries == 3
        assert client.headers == {}

    def test_init_custom(self) -> None:
        client = RAGuardHTTPClient(
            timeout=60.0,
            max_retries=5,
            headers={"Authorization": "Bearer test"},
        )
        assert client.timeout == 60.0
        assert client.max_retries == 5
        assert client.headers == {"Authorization": "Bearer test"}

    @pytest.mark.asyncio
    async def test_get_client(self) -> None:
        client = RAGuardHTTPClient()
        httpx_client = await client.get_client()
        assert httpx_client is not None
        await client.close()

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        client = RAGuardHTTPClient()
        await client.get_client()
        await client.close()
        assert client._client is None

    @pytest.mark.asyncio
    async def test_async_context_manager(self) -> None:
        async with RAGuardHTTPClient() as client:
            assert client._client is None
            httpx_client = await client.get_client()
            assert httpx_client is not None
        assert client._client is None

    @pytest.mark.asyncio
    async def test_get_success(self, httpx_mock: pytest_httpx.HTTPXMock) -> None:
        httpx_mock.add_response(url="http://test.com/api", json={"status": "ok"})
        async with RAGuardHTTPClient() as client:
            response = await client.get("http://test.com/api")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_post_success(self, httpx_mock: pytest_httpx.HTTPXMock) -> None:
        httpx_mock.add_response(
            url="http://test.com/api",
            method="POST",
            json={"created": True},
        )
        async with RAGuardHTTPClient() as client:
            response = await client.post("http://test.com/api", json={"key": "value"})
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_with_custom_headers(self, httpx_mock: pytest_httpx.HTTPXMock) -> None:
        httpx_mock.add_response(url="http://test.com/api", json={})
        async with RAGuardHTTPClient(headers={"X-Custom": "header"}) as client:
            response = await client.get("http://test.com/api")
            assert response.status_code == 200
