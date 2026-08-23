"""Tests for store module."""

import pytest


class TestStore:
    """Tests for Store."""

    def test_services_empty(self, store):
        """Test services list when empty."""
        assert store.services == []

    def test_save_and_load(self, store, sample_spec):
        """Test saving and loading a spec."""
        store.save("test_service", sample_spec)
        loaded = store.load("test_service")
        assert loaded["service"] == sample_spec["service"]
        assert loaded["base_url"] == sample_spec["base_url"]

    def test_services_list(self, store, sample_spec):
        """Test services list after saving."""
        store.save("service_a", sample_spec)
        store.save("service_b", sample_spec)
        services = store.services
        assert "service_a" in services
        assert "service_b" in services

    def test_find_fuzzy(self, store, sample_spec):
        """Test fuzzy finding services."""
        store.save("api_notion_com", sample_spec)
        store.save("api_github_com", sample_spec)

        matches = store.find("notion")
        assert "api_notion_com" in matches
        assert "api_github_com" not in matches

    def test_exists(self, store, sample_spec):
        """Test existence check."""
        assert store.exists("nonexistent") is False
        store.save("exists_test", sample_spec)
        assert store.exists("exists_test") is True

    def test_delete(self, store, sample_spec):
        """Test deleting a spec."""
        store.save("to_delete", sample_spec)
        assert store.exists("to_delete") is True

        result = store.delete("to_delete")
        assert result is True
        assert store.exists("to_delete") is False

    def test_delete_nonexistent(self, store):
        """Test deleting nonexistent spec."""
        result = store.delete("nonexistent")
        assert result is False

    def test_clear(self, store, sample_spec):
        """Test clearing all specs."""
        store.save("service_1", sample_spec)
        store.save("service_2", sample_spec)

        count = store.clear()
        assert count == 2
        assert store.services == []

    def test_load_nonexistent_raises(self, store):
        """Test that loading nonexistent spec raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            store.load("nonexistent")

    def test_normalize_name(self, store):
        """Test name normalization."""
        assert store._normalize_name("api.example.com") == "api_example_com"
        assert store._normalize_name("api:8080") == "api_8080"

    def test_update_creates_spec(self, store):
        """Test that update creates new spec if not exists."""
        store.update(
            host="new.example.com",
            method="GET",
            path="/test",
            request_headers={"Authorization": "Bearer token"},
        )

        spec = store.load("new_example_com")
        assert spec["service"] == "new.example.com"
        assert "GET /test" in spec["observed_endpoints"]

    def test_update_adds_sample(self, store):
        """Test that update adds samples."""
        store.update(
            host="test.example.com",
            method="GET",
            path="/api/users",
            request_headers={"Authorization": "Bearer token"},
            response_body={"users": []},
            status_code=200,
        )

        spec = store.load("test_example_com")
        assert len(spec["samples"]) == 1
        assert spec["samples"][0]["status"] == 200

    def test_update_deduplicates_samples(self, store):
        """Test that identical samples are deduplicated."""
        for _ in range(5):
            store.update(
                host="test.example.com",
                method="GET",
                path="/api/users",
                request_headers={"Authorization": "Bearer token"},
                response_body={"users": []},
                status_code=200,
            )

        spec = store.load("test_example_com")
        # Should only have 1 sample (deduplicated)
        assert len(spec["samples"]) == 1

    def test_file_permissions(self, store, sample_spec):
        """Test that spec files have restricted permissions."""
        import os

        path = store.save("secure_test", sample_spec)
        store.flush()  # Force write to disk for permission check
        assert path.exists()
        if os.name != "nt":
            # Check permissions (0o600 = user read/write only) on POSIX
            assert (path.stat().st_mode & 0o777) == 0o600

    def test_flush(self, store, sample_spec):
        """Test that flush writes dirty specs to disk."""
        store.save("flush_test", sample_spec)
        path = store._get_path("flush_test")

        # File may not exist yet (buffered)
        store.flush()

        # Now it should exist
        assert path.exists()

    def test_save_is_buffered(self, store, sample_spec):
        """Test that save doesn't block on disk I/O."""
        import time

        # Save many specs - should be fast because buffered
        start = time.time()
        for i in range(50):
            store.save(f"buffered_test_{i}", sample_spec)
        elapsed = time.time() - start

        # Should complete in < 100ms (no disk I/O)
        assert elapsed < 0.1, f"Buffered saves took {elapsed:.3f}s, expected < 0.1s"
