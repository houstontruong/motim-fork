"""Tests for config module."""

import tempfile
from pathlib import Path

import pytest

from motim.config import CaptureSettings, Config, HeaderProfile


class TestHeaderProfile:
    """Tests for HeaderProfile."""

    def test_matches_exact(self):
        """Test exact header matching."""
        profile = HeaderProfile(include=["authorization", "cookie"])
        assert profile.matches("Authorization") is True
        assert profile.matches("Cookie") is True
        assert profile.matches("X-Custom") is False

    def test_matches_wildcard_prefix(self):
        """Test wildcard prefix matching."""
        profile = HeaderProfile(include=["x-*"])
        assert profile.matches("X-Custom") is True
        assert profile.matches("X-API-Key") is True
        assert profile.matches("Authorization") is False

    def test_matches_all(self):
        """Test * matches everything."""
        profile = HeaderProfile(include=["*"])
        assert profile.matches("Authorization") is True
        assert profile.matches("X-Custom") is True
        assert profile.matches("Cookie") is True

    def test_exclude_takes_precedence(self):
        """Test that exclude patterns override include."""
        profile = HeaderProfile(
            include=["x-*"],
            exclude=["x-request-id"],
        )
        assert profile.matches("X-Custom") is True
        assert profile.matches("X-Request-ID") is False

    def test_empty_include_matches_all(self):
        """Test that empty include matches everything not excluded."""
        profile = HeaderProfile(exclude=["host"])
        assert profile.matches("Authorization") is True
        assert profile.matches("Host") is False


class TestConfig:
    """Tests for Config."""

    def test_default_profiles_exist(self):
        """Test that default profiles are created."""
        config = Config()
        assert "minimal" in config.profiles
        assert "standard" in config.profiles
        assert "full" in config.profiles

    def test_get_profile(self):
        """Test getting a profile by name."""
        config = Config()
        profile = config.get_profile("minimal")
        assert isinstance(profile, HeaderProfile)

    def test_get_profile_unknown_raises(self):
        """Test that unknown profile raises ValueError."""
        config = Config()
        with pytest.raises(ValueError):
            config.get_profile("nonexistent")

    def test_save_and_load(self):
        """Test saving and loading config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"

            config = Config()
            config.defaults.timeout = 45.0
            config.save(path)

            loaded = Config.load(path)
            assert loaded.defaults.timeout == 45.0

    def test_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            "profiles": {
                "custom": {
                    "include": ["x-custom"],
                    "exclude": [],
                }
            },
            "defaults": {
                "timeout": 60,
                "profile": "custom",
            },
        }
        config = Config.from_dict(data)
        assert "custom" in config.profiles
        assert config.defaults.timeout == 60
        assert config.defaults.profile == "custom"

    def test_to_dict(self):
        """Test converting config to dictionary."""
        config = Config()
        data = config.to_dict()
        assert "profiles" in data
        assert "defaults" in data
        assert "capture" in data


class TestCaptureSettings:
    """Tests for CaptureSettings."""

    def test_defaults(self):
        """Test default capture settings."""
        settings = CaptureSettings()
        assert settings.max_samples_per_endpoint == 50
        assert settings.max_samples_total == 1000
        assert "accept-encoding" in settings.skip_headers
