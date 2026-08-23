"""Tests for auth module (Production-Safe metadata only)."""

from datetime import datetime

import pytest

from motim.auth import Auth


class TestAuth:
    """Tests for Auth metadata class."""

    def test_from_spec(self, sample_spec):
        """Test creating Auth from spec."""
        auth = Auth.from_spec(sample_spec)
        assert auth.type in ("bearer", "api_key", "custom")
        assert auth.header("Authorization") == "[REDACTED]"
        assert auth.header("X-API-Key") == "[REDACTED]"

    def test_headers_property_redacted(self, sample_spec):
        """Test headers property returns redacted metadata copy."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.headers
        assert "Authorization" in headers
        assert headers["Authorization"] == "[REDACTED]"

        # Modifying returned dict shouldn't affect auth
        headers["New-Header"] = "value"
        assert auth.header("New-Header") is None

    def test_header_case_insensitive(self, sample_spec):
        """Test that header lookup is case-insensitive."""
        auth = Auth.from_spec(sample_spec)
        assert auth.header("authorization") == "[REDACTED]"
        assert auth.header("AUTHORIZATION") == "[REDACTED]"

    def test_header_default(self):
        """Test header default value."""
        auth = Auth(_headers={})
        assert auth.header("Missing") is None
        assert auth.header("Missing", "default") == "default"

    def test_bearer_token_masked(self, sample_spec):
        """Test bearer token extraction returns [REDACTED]."""
        auth = Auth.from_spec(sample_spec)
        assert auth.bearer_token == "[REDACTED]"

    def test_bearer_token_none(self):
        """Test bearer token when not present."""
        auth = Auth(_headers={"X-API-Key": "key"})
        assert auth.bearer_token is None

    def test_api_key_masked(self, sample_spec):
        """Test API key extraction returns [REDACTED]."""
        auth = Auth.from_spec(sample_spec)
        assert auth.api_key == "[REDACTED]"

    def test_api_key_none(self):
        """Test API key when not present."""
        auth = Auth(_headers={"Authorization": "Bearer token"})
        assert auth.api_key is None

    def test_cookies_masked(self, sample_spec):
        """Test cookie names preserved with masked values."""
        auth = Auth.from_spec(sample_spec)
        cookies = auth.cookies
        assert cookies["session"] == "[REDACTED]"
        assert cookies["csrf"] == "[REDACTED]"

    def test_cookie_single(self, sample_spec):
        """Test getting single cookie."""
        auth = Auth.from_spec(sample_spec)
        assert auth.cookie("session") == "[REDACTED]"
        assert auth.cookie("missing") is None
        assert auth.cookie("missing", "default") == "default"

    def test_type_bearer(self):
        """Test auth type detection: bearer."""
        auth = Auth(_headers={"Authorization": "Bearer token"})
        assert auth.type == "bearer"

    def test_type_api_key(self):
        """Test auth type detection: api_key."""
        auth = Auth(_headers={"X-API-Key": "key123"})
        assert auth.type == "api_key"

    def test_type_cookie(self):
        """Test auth type detection: cookie."""
        auth = Auth(_headers={"Cookie": "session=abc"})
        assert auth.type == "cookie"

    def test_type_basic(self):
        """Test auth type detection: basic."""
        auth = Auth(_headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert auth.type == "basic"

    def test_type_none(self):
        """Test auth type detection: none."""
        auth = Auth(_headers={})
        assert auth.type == "none"

    def test_basic_credentials_masked(self):
        """Test basic auth credential extraction is masked."""
        auth = Auth(_headers={"Authorization": "Basic dXNlcjpwYXNz"})
        creds = auth.basic_credentials
        assert creds == ("[REDACTED]", "[REDACTED]")

    def test_to_headers_removed(self, sample_spec):
        """Verify to_headers() credential generation is removed completely."""
        auth = Auth.from_spec(sample_spec)
        assert not hasattr(auth, "to_headers")

    def test_bool_true(self, sample_spec):
        """Test Auth is truthy when has headers."""
        auth = Auth.from_spec(sample_spec)
        assert bool(auth) is True

    def test_bool_false(self):
        """Test Auth is falsy when empty."""
        auth = Auth(_headers={})
        assert bool(auth) is False

    def test_last_seen(self, sample_spec):
        """Test last_seen parsing."""
        auth = Auth.from_spec(sample_spec)
        assert auth.last_seen is not None
        assert isinstance(auth.last_seen, datetime)

    def test_from_spec_with_non_dict(self):
        """Test safe handling when spec['auth'] is a string or invalid type."""
        spec = {"auth": "Bearer secret_token"}
        auth = Auth.from_spec(spec)
        assert auth.type in ("bearer", "none", "custom")
        assert auth.bearer_token == "[REDACTED]"

