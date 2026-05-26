"""Tests for HTTP client security validation."""

import pytest

from raguard.utils.http import RAGuardHTTPClient, _is_private_ip, validate_target_url


class TestIsPrivateIp:
    def test_loopback_ipv4(self) -> None:
        assert _is_private_ip("127.0.0.1") is True

    def test_private_ipv4(self) -> None:
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("192.168.1.1") is True

    def test_link_local(self) -> None:
        assert _is_private_ip("169.254.1.1") is True

    def test_public_ip(self) -> None:
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("93.184.216.34") is False

    def test_loopback_ipv6(self) -> None:
        assert _is_private_ip("::1") is True

    def test_invalid_input(self) -> None:
        assert _is_private_ip("not-an-ip") is False


class TestValidateTargetUrl:
    def test_valid_public_url(self) -> None:
        assert validate_target_url("https://api.example.com/query") == "https://api.example.com/query"

    def test_valid_with_port(self) -> None:
        assert validate_target_url("http://example.com:8080") == "http://example.com:8080"

    def test_private_ip_blocked(self) -> None:
        with pytest.raises(ValueError, match="private IP range"):
            validate_target_url("http://192.168.1.1:8000")

    def test_loopback_blocked(self) -> None:
        with pytest.raises(ValueError, match="internal host"):
            validate_target_url("http://127.0.0.1:8000")

    def test_link_local_blocked(self) -> None:
        with pytest.raises(ValueError, match="private IP range"):
            validate_target_url("http://169.254.1.1")

    def test_missing_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            validate_target_url("example.com")

    def test_unsupported_scheme(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            validate_target_url("ftp://example.com")

    def test_empty_url(self) -> None:
        with pytest.raises(ValueError):
            validate_target_url("")


class TestRAGuardHTTPClientSecurity:
    def test_follow_redirects_disabled_by_default(self) -> None:
        client = RAGuardHTTPClient()
        assert client.follow_redirects is False

    def test_follow_redirects_can_be_enabled(self) -> None:
        client = RAGuardHTTPClient(follow_redirects=True)
        assert client.follow_redirects is True

    @pytest.mark.asyncio
    async def test_get_rejects_private_ip(self) -> None:
        client = RAGuardHTTPClient()
        with pytest.raises(ValueError, match="private IP range"):
            await client.get("http://192.168.1.1:8000")

    @pytest.mark.asyncio
    async def test_post_rejects_private_ip(self) -> None:
        client = RAGuardHTTPClient()
        with pytest.raises(ValueError, match="private IP range"):
            await client.post("http://10.0.0.1:8000")

    @pytest.mark.asyncio
    async def test_get_rejects_loopback(self) -> None:
        client = RAGuardHTTPClient()
        with pytest.raises(ValueError, match="internal host"):
            await client.get("http://127.0.0.1:9200")
