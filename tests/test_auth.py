"""Tests for auth module."""

from datetime import datetime

from motim.auth import Auth


class TestAuth:
    """Tests for Auth class."""

    def test_from_spec(self, sample_spec):
        """Test creating Auth from spec."""
        auth = Auth.from_spec(sample_spec)
        assert auth.header("Authorization") == "Bearer test-token-12345"
        assert auth.header("X-API-Key") == "api-key-67890"

    def test_headers_property(self, sample_spec):
        """Test headers property returns copy."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.headers
        assert "Authorization" in headers

        # Modifying returned dict shouldn't affect auth
        headers["New-Header"] = "value"
        assert auth.header("New-Header") is None

    def test_header_case_insensitive(self, sample_spec):
        """Test that header lookup is case-insensitive."""
        auth = Auth.from_spec(sample_spec)
        assert auth.header("authorization") == "Bearer test-token-12345"
        assert auth.header("AUTHORIZATION") == "Bearer test-token-12345"

    def test_header_default(self):
        """Test header default value."""
        auth = Auth(_headers={})
        assert auth.header("Missing") is None
        assert auth.header("Missing", "default") == "default"

    def test_bearer_token(self, sample_spec):
        """Test bearer token extraction."""
        auth = Auth.from_spec(sample_spec)
        assert auth.bearer_token == "test-token-12345"

    def test_bearer_token_none(self):
        """Test bearer token when not present."""
        auth = Auth(_headers={"X-API-Key": "key"})
        assert auth.bearer_token is None

    def test_api_key(self, sample_spec):
        """Test API key extraction."""
        auth = Auth.from_spec(sample_spec)
        assert auth.api_key == "api-key-67890"

    def test_api_key_none(self):
        """Test API key when not present."""
        auth = Auth(_headers={"Authorization": "Bearer token"})
        assert auth.api_key is None

    def test_cookies(self, sample_spec):
        """Test cookie parsing."""
        auth = Auth.from_spec(sample_spec)
        cookies = auth.cookies
        assert cookies["session"] == "abc123"
        assert cookies["csrf"] == "xyz789"

    def test_cookies_comma_separated_normalized(self):
        """Cookie header values are normalized for replay."""
        auth = Auth(_headers={"Cookie": "kdt=abc, dnt=1, auth_token=xyz"})
        assert auth.cookies["kdt"] == "abc"
        assert auth.cookies["dnt"] == "1"
        assert auth.cookie_header == "kdt=abc; dnt=1; auth_token=xyz"
        headers = auth.to_headers(include=["Cookie"])
        assert headers["Cookie"] == "kdt=abc; dnt=1; auth_token=xyz"

    def test_cookie_single(self, sample_spec):
        """Test getting single cookie."""
        auth = Auth.from_spec(sample_spec)
        assert auth.cookie("session") == "abc123"
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

    def test_basic_credentials(self):
        """Test basic auth credential extraction."""
        # "user:pass" base64 encoded
        auth = Auth(_headers={"Authorization": "Basic dXNlcjpwYXNz"})
        creds = auth.basic_credentials
        assert creds == ("user", "pass")

    def test_is_expired_with_jwt(self, jwt_token):
        """Test JWT expiry detection."""
        auth = Auth(_headers={"Authorization": f"Bearer {jwt_token}"})
        assert auth.is_expired is True

    def test_is_expired_non_jwt(self):
        """Test is_expired with non-JWT token."""
        auth = Auth(_headers={"Authorization": "Bearer not-a-jwt"})
        assert auth.is_expired is False

    def test_jwt_payload(self, jwt_token):
        """Test JWT payload extraction."""
        auth = Auth(_headers={"Authorization": f"Bearer {jwt_token}"})
        payload = auth.jwt_payload
        assert payload is not None
        assert payload["sub"] == "1234567890"
        assert payload["name"] == "John Doe"

    def test_to_headers_default(self, sample_spec):
        """Test to_headers with default profile."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.to_headers()
        # Standard profile includes auth headers
        assert "Authorization" in headers

    def test_to_headers_minimal(self, sample_spec):
        """Test to_headers with minimal profile."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.to_headers(profile="minimal")
        assert "Authorization" in headers
        assert "X-API-Key" in headers

    def test_to_headers_include(self, sample_spec):
        """Test to_headers with explicit include."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.to_headers(include=["Authorization"])
        assert "Authorization" in headers
        assert "Cookie" not in headers

    def test_to_headers_exclude(self, sample_spec):
        """Test to_headers with exclude."""
        auth = Auth.from_spec(sample_spec)
        headers = auth.to_headers(profile="full", exclude=["Cookie"])
        assert "Authorization" in headers
        assert "Cookie" not in headers

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
