"""HTTP client utilities for RAGuard."""

from __future__ import annotations

from typing import Any

import httpx


class RAGuardHTTPClient:
    """Async HTTP client with retries and timeouts for RAG scanning."""

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform GET request with retries."""
        client = await self.get_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = await client.get(url, **kwargs)
                return response
            except (httpx.RequestError, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    continue
                raise

        raise last_exc or httpx.RequestError("Max retries exceeded")

    async def post(self, url: str, json: dict | None = None, **kwargs: Any) -> httpx.Response:
        """Perform POST request with retries."""
        client = await self.get_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = await client.post(url, json=json, **kwargs)
                return response
            except (httpx.RequestError, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    continue
                raise

        raise last_exc or httpx.RequestError("Max retries exceeded")

    async def __aenter__(self) -> RAGuardHTTPClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
