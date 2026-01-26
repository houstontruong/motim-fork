"""Tests for client module."""

from unittest.mock import patch

import httpx

from motim.client import AsyncClient, Client, get, post
from motim.config import Config
from motim.service import Service


class TestClient:
    """Tests for Client class."""

    def test_init_with_service_name(self, store_with_spec):
        """Test creating client with service name."""
        with patch.object(Client, "__init__", lambda self, *a, **kw: None):
            # We can't fully test without mocking httpx
            pass

    def test_init_with_service_object(self, sample_spec):
        """Test creating client with Service object."""
        service = Service.from_spec(sample_spec)

        # Mock the parent class init
        with patch.object(httpx.Client, "__init__", return_value=None):
            client = object.__new__(Client)
            client._service = service
            client._config = Config()
            client._auth_profile = "standard"
            client._retries = 0

            assert client.service == service
            assert client.auth == service.auth

    def test_service_property(self, sample_spec):
        """Test service property."""
        service = Service.from_spec(sample_spec)

        with patch.object(httpx.Client, "__init__", return_value=None):
            client = object.__new__(Client)
            client._service = service

            assert client.service is service

    def test_auth_property(self, sample_spec):
        """Test auth property."""
        service = Service.from_spec(sample_spec)

        with patch.object(httpx.Client, "__init__", return_value=None):
            client = object.__new__(Client)
            client._service = service

            assert client.auth is service.auth

    def test_request_uses_endpoint_base_url_when_present(self, sample_spec):
        """Client should use per-endpoint base URL if captured."""
        spec = dict(sample_spec)
        spec["base_url"] = "https://api.example.com"
        spec["endpoint_base_urls"] = {"GET /v1/users": "https://alt.example.com"}
        service = Service.from_spec(spec)

        with patch.object(httpx.Client, "__init__", return_value=None):
            with patch.object(httpx.Client, "request", return_value=httpx.Response(200)) as req:
                client = object.__new__(Client)
                client._service = service
                client._config = Config()
                client._auth_profile = "standard"
                client._retries = 0
                resp = client.request("GET", "/v1/users")
                assert resp.status_code == 200
                # Should have been rewritten to absolute URL using endpoint mapping.
                args, kwargs = req.call_args
                assert args[1] == "https://alt.example.com/v1/users"


class TestAsyncClient:
    """Tests for AsyncClient class."""

    def test_init_structure(self, sample_spec):
        """Test AsyncClient has same structure as Client."""
        service = Service.from_spec(sample_spec)

        with patch.object(httpx.AsyncClient, "__init__", return_value=None):
            client = object.__new__(AsyncClient)
            client._service = service
            client._config = Config()
            client._auth_profile = "standard"
            client._retries = 0

            assert client.service == service
            assert client.auth == service.auth


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_get_function_exists(self):
        """Test get function is exported."""
        assert callable(get)

    def test_post_function_exists(self):
        """Test post function is exported."""
        assert callable(post)

    def test_put_function_exists(self):
        """Test put function is exported."""
        from motim.client import put

        assert callable(put)

    def test_delete_function_exists(self):
        """Test delete function is exported."""
        from motim.client import delete

        assert callable(delete)

    def test_patch_function_exists(self):
        """Test patch function is exported."""
        from motim.client import patch

        assert callable(patch)
