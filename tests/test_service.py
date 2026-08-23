"""Tests for service module."""

import pytest

from motim.service import Sample, Service


class TestSample:
    """Tests for Sample class."""

    def test_from_dict(self):
        """Test creating Sample from dict."""
        data = {
            "endpoint": "GET /api/users",
            "timestamp": "2024-01-15T10:30:00",
            "status": 200,
            "query_params": {"limit": "10"},
        }
        sample = Sample.from_dict(data)
        assert sample.endpoint == "GET /api/users"
        assert sample.status == 200
        assert sample.query_params == {"limit": "10"}

    def test_method_property(self):
        """Test method extraction from endpoint."""
        sample = Sample(endpoint="POST /api/users", timestamp=None, status=201)
        assert sample.method == "POST"

    def test_path_property(self):
        """Test path extraction from endpoint."""
        sample = Sample(endpoint="GET /api/users", timestamp=None, status=200)
        assert sample.path == "/api/users"


class TestSampleCollection:
    """Tests for SampleCollection."""

    def test_len(self, sample_spec):
        """Test collection length."""
        service = Service.from_spec(sample_spec)
        assert len(service.samples) == 3

    def test_iter(self, sample_spec):
        """Test iteration."""
        service = Service.from_spec(sample_spec)
        samples = list(service.samples)
        assert len(samples) == 3

    def test_latest(self, sample_spec):
        """Test getting latest sample."""
        service = Service.from_spec(sample_spec)
        latest = service.samples.latest
        assert latest is not None
        # Latest should be the one with latest timestamp
        assert latest.timestamp.hour == 10
        assert latest.timestamp.minute == 32

    def test_for_endpoint(self, sample_spec):
        """Test filtering by endpoint."""
        service = Service.from_spec(sample_spec)
        get_users = service.samples.for_endpoint("GET /v1/users")
        assert len(get_users) == 2

    def test_for_method(self, sample_spec):
        """Test filtering by method."""
        service = Service.from_spec(sample_spec)
        posts = service.samples.for_method("POST")
        assert len(posts) == 1
        assert posts[0].method == "POST"

    def test_successful(self, sample_spec):
        """Test filtering successful responses."""
        service = Service.from_spec(sample_spec)
        successful = service.samples.successful()
        assert len(successful) == 3  # All are 2xx

    def test_compare(self, sample_spec):
        """Test sample comparison."""
        service = Service.from_spec(sample_spec)
        comparison = service.samples.compare("GET /v1/users")

        assert comparison.sample_count == 2
        assert 200 in comparison.status_codes
        # limit should be varying (10 vs 20)
        assert "limit" in comparison.varying_params


class TestEndpointCollection:
    """Tests for EndpointCollection."""

    def test_len(self, sample_spec):
        """Test collection length."""
        service = Service.from_spec(sample_spec)
        assert len(service.endpoints) == 5

    def test_contains(self, sample_spec):
        """Test contains check."""
        service = Service.from_spec(sample_spec)
        assert "GET /v1/users" in service.endpoints
        assert "GET /nonexistent" not in service.endpoints

    def test_filter_by_method(self, sample_spec):
        """Test filtering by HTTP method."""
        service = Service.from_spec(sample_spec)
        gets = service.endpoints.filter(method="GET")
        assert len(gets) == 2
        for endpoint in gets:
            assert endpoint.startswith("GET ")

    def test_filter_by_path(self, sample_spec):
        """Test filtering by path pattern."""
        service = Service.from_spec(sample_spec)
        users = service.endpoints.filter(path="/v1/users")
        assert len(users) >= 1

    def test_methods(self, sample_spec):
        """Test getting unique methods."""
        service = Service.from_spec(sample_spec)
        methods = service.endpoints.methods()
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "DELETE" in methods


class TestService:
    """Tests for Service class."""

    def test_from_spec(self, sample_spec):
        """Test creating Service from spec."""
        service = Service.from_spec(sample_spec)
        assert service.host == "api.example.com"
        assert service.base_url == "https://api.example.com"

    def test_load_from_store(self, store_with_spec):
        """Test loading Service from store."""
        service = Service.load("api_example_com", store=store_with_spec)
        assert service.host == "api.example.com"

    def test_load_fuzzy_match(self, store_with_spec):
        """Test loading Service with fuzzy name."""
        service = Service.load("example", store=store_with_spec)
        assert service.host == "api.example.com"

    def test_load_nonexistent_raises(self, store):
        """Test that loading nonexistent service raises."""
        with pytest.raises(FileNotFoundError):
            Service.load("nonexistent", store=store)

    def test_auth_property(self, sample_spec):
        """Test auth property."""
        service = Service.from_spec(sample_spec)
        assert service.auth.type == "bearer"
        assert service.auth.bearer_token == "[REDACTED]"


    def test_list_all(self, store_with_spec):
        """Test listing all services."""
        services = Service.list_all(store=store_with_spec)
        assert "api_example_com" in services

    def test_find(self, store_with_spec):
        """Test finding services."""
        matches = Service.find("example", store=store_with_spec)
        assert "api_example_com" in matches

    def test_raw_property(self, sample_spec):
        """Test raw spec access."""
        service = Service.from_spec(sample_spec)
        assert service.raw == sample_spec

    def test_repr(self, sample_spec):
        """Test string representation."""
        service = Service.from_spec(sample_spec)
        repr_str = repr(service)
        assert "api_example_com" in repr_str
        assert "endpoints=5" in repr_str
