"""HTTP client utilities for RAGuard."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

import httpx

# Private and reserved IP ranges that should not be targeted
_PRIVATE_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def _is_private_ip(host: str) -> bool:
    """Check if a hostname resolves to a private/internal IP."""
    try:
        addr = ip_address(host)
        for cidr in _PRIVATE_RANGES:
            network = ip_network(cidr, strict=False)
            if addr in network:  # type: ignore[operator]
                return True
        return False
    except ValueError:
        return False


def validate_target_url(url: str) -> str:
    """Validate and sanitize a target URL to prevent SSRF.

    Args:
        url: The target URL to validate.

    Returns:
        The validated URL.

    Raises:
        ValueError: If the URL is invalid or targets a private/internal host.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ValueError("URL must have a scheme (http:// or https://)")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL must have a hostname")

    hostname = parsed.hostname.lower()

    # Block private IPs and localhost
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"URL targets internal host: {hostname}. RAGuard does not scan internal services by default.")

    # Block private IP ranges
    if _is_private_ip(hostname):
        raise ValueError(
            f"URL targets private IP range: {hostname}. RAGuard does not scan internal services by default."
        )

    return url


class RAGuardHTTPClient:
    """Async HTTP client with retries and timeouts for RAG scanning.

    Security features:
    - SSRF protection via URL validation
    - Redirect following disabled by default
    - Configurable timeouts and retries
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = headers or {}
        self.follow_redirects = follow_redirects
        self._client: httpx.AsyncClient | None = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                follow_redirects=self.follow_redirects,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform GET request with retries and SSRF validation."""
        validate_target_url(url)
        client = await self.get_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = await client.get(url, **kwargs)
                return response
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    continue
                raise

        raise last_exc or httpx.RequestError("Max retries exceeded")

    async def post(self, url: str, json: dict | None = None, **kwargs: Any) -> httpx.Response:
        """Perform POST request with retries and SSRF validation."""
        validate_target_url(url)
        client = await self.get_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = await client.post(url, json=json, **kwargs)
                return response
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    continue
                raise

        raise last_exc or httpx.RequestError("Max retries exceeded")

    async def __aenter__(self) -> RAGuardHTTPClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
