"""Unit tests for egress allowlist and loopback enforcement."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from motim.cli.proxy import proxy
from motim.config import Config
from motim.proxy.addon import MotimAddon, is_host_allowed


def test_is_host_allowed_default_deny_all():
    # Empty or None allowlist must deny all hosts (zero trust)
    assert not is_host_allowed("example.com", [])
    assert not is_host_allowed("example.com", None)
    assert not is_host_allowed("localhost", [])
    assert not is_host_allowed("127.0.0.1", [])


def test_is_host_allowed_exact_match():
    allowed = ["api.example.com", "auth.service.org"]
    assert is_host_allowed("api.example.com", allowed, resolve_dns=False)
    assert is_host_allowed("API.EXAMPLE.COM", allowed, resolve_dns=False)
    assert is_host_allowed("api.example.com:443", allowed, resolve_dns=False)
    assert is_host_allowed("auth.service.org", allowed, resolve_dns=False)

    assert not is_host_allowed("evil.com", allowed, resolve_dns=False)
    assert not is_host_allowed("other.example.com", allowed, resolve_dns=False)
    assert not is_host_allowed("example.com", allowed, resolve_dns=False)


def test_is_host_allowed_wildcard():
    allowed = ["*.target.com"]
    assert is_host_allowed("api.target.com", allowed, resolve_dns=False)
    assert is_host_allowed("sub.api.target.com", allowed, resolve_dns=False)
    assert is_host_allowed("target.com", allowed, resolve_dns=False)
    assert is_host_allowed("api.target.com:8443", allowed, resolve_dns=False)

    assert not is_host_allowed("evil-target.com", allowed, resolve_dns=False)
    assert not is_host_allowed("nottarget.com", allowed, resolve_dns=False)
    assert not is_host_allowed("target.org", allowed, resolve_dns=False)


def test_is_host_allowed_global_wildcard():
    assert is_host_allowed("anything.com", ["*"], resolve_dns=False)


def test_prohibited_ip_destinations_blocked():
    """Verify that private, loopback, link-local, and metadata IPs are unconditionally blocked."""
    prohibited = [
        "127.0.0.1",
        "127.0.0.5",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
    ]
    for ip in prohibited:
        assert not is_host_allowed(ip, ["*"], resolve_dns=False), f"IP {ip} must be blocked"


def test_dns_rebinding_resolution_blocks_private_ip(monkeypatch):
    """Verify that a domain resolving to a private/loopback IP is blocked."""
    import socket

    # Simulate DNS resolving evil-rebinding.com to 127.0.0.1
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    assert not is_host_allowed("evil-rebinding.com", ["evil-rebinding.com"], resolve_dns=True)


def test_addon_request_hook_egress_blocking():
    addon = MotimAddon()
    config = Config()
    config.capture.allowed_hosts = ["api.allowed.com"]
    addon._config = config

    class MockRequest:
        def __init__(self, host: str):
            self.host = host
            self.pretty_host = host

    class MockFlow:
        def __init__(self, host: str):
            self.request = MockRequest(host)
            self.response = None

    # Disallowed request
    blocked_flow = MockFlow("evil.com")
    addon.request(blocked_flow)
    assert blocked_flow.response is not None
    assert blocked_flow.response.status_code == 403



def test_cli_proxy_start_rejects_external_bind():
    runner = CliRunner()
    result = runner.invoke(proxy, ["start", "--listen-host", "0.0.0.0"])
    assert result.exit_code != 0
    assert "Security violation" in result.output or "prohibited" in result.output

    result_public_ip = runner.invoke(proxy, ["start", "--listen-host", "192.168.1.100"])
    assert result_public_ip.exit_code != 0
    assert "Security violation" in result_public_ip.output or "prohibited" in result_public_ip.output
