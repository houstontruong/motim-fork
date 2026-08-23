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
    assert is_host_allowed("api.example.com", allowed)
    assert is_host_allowed("API.EXAMPLE.COM", allowed)
    assert is_host_allowed("api.example.com:443", allowed)
    assert is_host_allowed("auth.service.org", allowed)

    assert not is_host_allowed("evil.com", allowed)
    assert not is_host_allowed("other.example.com", allowed)
    assert not is_host_allowed("example.com", allowed)


def test_is_host_allowed_wildcard():
    allowed = ["*.target.com"]
    assert is_host_allowed("api.target.com", allowed)
    assert is_host_allowed("sub.api.target.com", allowed)
    assert is_host_allowed("target.com", allowed)
    assert is_host_allowed("api.target.com:8443", allowed)

    assert not is_host_allowed("evil-target.com", allowed)
    assert not is_host_allowed("nottarget.com", allowed)
    assert not is_host_allowed("target.org", allowed)


def test_is_host_allowed_global_wildcard():
    assert is_host_allowed("anything.com", ["*"])


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

    # Allowed request
    allowed_flow = MockFlow("api.allowed.com")
    addon.request(allowed_flow)
    assert allowed_flow.response is None

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
