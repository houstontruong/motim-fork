"""Pytest fixtures for MOTIM tests."""

import tempfile
from pathlib import Path

import pytest

from motim.config import Config
from motim.store import Store, _cache, _cache_lock, _dirty


@pytest.fixture(autouse=True)
def reset_store_globals():
    """Reset global cache state before each test."""
    with _cache_lock:
        _cache.clear()
        _dirty.clear()
    yield
    # Cleanup after test too
    with _cache_lock:
        _cache.clear()
        _dirty.clear()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_spec():
    """Sample spec data for testing."""
    return {
        "service": "api.example.com",
        "base_url": "https://api.example.com",
        "auth": {
            "headers": {
                "Authorization": "Bearer test-token-12345",
                "X-API-Key": "api-key-67890",
                "Cookie": "session=abc123; csrf=xyz789",
            },
            "last_seen": "2024-01-15T10:30:00",
        },
        "observed_endpoints": [
            "GET /v1/users",
            "GET /v1/users/{id}",
            "POST /v1/users",
            "PUT /v1/users/{id}",
            "DELETE /v1/users/{id}",
        ],
        "samples": [
            {
                "endpoint": "GET /v1/users",
                "timestamp": "2024-01-15T10:30:00",
                "status": 200,
                "query_params": {"limit": "10", "offset": "0"},
                "response_body": {"users": [{"id": 1, "name": "Alice"}]},
            },
            {
                "endpoint": "POST /v1/users",
                "timestamp": "2024-01-15T10:31:00",
                "status": 201,
                "request_body": {"name": "Bob", "email": "bob@example.com"},
                "response_body": {"id": 2, "name": "Bob"},
            },
            {
                "endpoint": "GET /v1/users",
                "timestamp": "2024-01-15T10:32:00",
                "status": 200,
                "query_params": {"limit": "20", "offset": "10"},
                "response_body": {"users": []},
            },
        ],
        "websocket_messages": [],
    }


@pytest.fixture
def jwt_token():
    """Sample JWT token for testing."""
    # This is a valid JWT structure with exp claim in the past
    # Header: {"alg": "HS256", "typ": "JWT"}
    # Payload: {"sub": "1234567890", "name": "John Doe", "exp": 1516239022}
    return (  # noqa: E501
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )


@pytest.fixture
def jwt_token_future():
    """JWT token that expires in the future (year 2030)."""
    # Payload: {"sub": "1234567890", "name": "John Doe", "exp": 1893456000}
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxODkzNDU2MDAwfQ"
        ".abc123"
    )


@pytest.fixture
def store(temp_dir):
    """Create a Store with temporary directory."""
    specs_dir = temp_dir / "specs"
    specs_dir.mkdir()
    return Store(specs_dir=specs_dir)


@pytest.fixture
def store_with_spec(store, sample_spec):
    """Store with a sample spec already saved."""
    store.save("api_example_com", sample_spec)
    return store


@pytest.fixture
def config():
    """Default Config for testing."""
    return Config()
