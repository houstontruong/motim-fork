"""Configuration management for MOTIM."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .exceptions import ConfigError

logger = logging.getLogger(__name__)


MOTIM_DIR = Path.home() / ".motim"
CONFIG_FILE = MOTIM_DIR / "config.yaml"
DEFAULT_CONFIG_FILE = Path(__file__).parent / "default_config.yaml"


@dataclass
class HeaderProfile:
    """Defines which headers to include/exclude for requests."""

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    def matches(self, header_name: str) -> bool:
        """Check if a header should be included based on this profile."""
        name_lower = header_name.lower()

        # Check exclusions first
        for pattern in self.exclude:
            if self._matches_pattern(name_lower, pattern.lower()):
                return False

        # If no include patterns, include everything not excluded
        if not self.include:
            return True

        # Check inclusions
        for pattern in self.include:
            if self._matches_pattern(name_lower, pattern.lower()):
                return True

        return False

    @staticmethod
    def _matches_pattern(name: str, pattern: str) -> bool:
        """Match header name against pattern (supports * wildcard)."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return name.startswith(pattern[:-1])
        if pattern.startswith("*"):
            return name.endswith(pattern[1:])
        return name == pattern


@dataclass
class RedactionSettings:
    """Settings for credential and secret redaction."""

    enabled: bool = True
    profile: str = "strict"
    placeholder: str = "[REDACTED]"
    extra_sensitive_headers: list[str] = field(default_factory=list)
    extra_sensitive_params: list[str] = field(default_factory=list)
    extra_sensitive_keys: list[str] = field(default_factory=list)


@dataclass
class CaptureSettings:
    """Settings for the proxy capture behavior."""

    allowed_hosts: list[str] = field(default_factory=list)
    redaction: RedactionSettings = field(default_factory=RedactionSettings)
    skip_headers: list[str] = field(
        default_factory=lambda: [
            "accept-encoding",
            "connection",
            "content-length",
            "host",
        ]
    )
    skip_domains: list[str] = field(
        default_factory=lambda: [
            "*.google-analytics.com",
            "*.doubleclick.net",
            "*.googletagmanager.com",
            "*.facebook.com",
            "*.twitter.com",
        ]
    )
    max_samples_per_endpoint: int = 50
    max_samples_total: int = 1000
    write_specs: bool = True
    store_exchanges: bool = True
    exchange_db_path: str = "~/.motim/motim.sqlite3"
    max_body_bytes: int = 1_000_000
    exchange_db_buffered: bool = True
    exchange_db_queue_max: int = 10_000
    exchange_db_batch_size: int = 100
    exchange_db_flush_interval_ms: int = 250
    pipeline_enabled: bool = True
    pipeline_queue_max: int = 5_000
    pipeline_drop_when_full: bool = True
    pipeline_max_parse_bytes: int = 200_000
    log_every_n: int = 25
    profile_enabled: bool = False
    profile_every_n: int = 200


@dataclass
class DefaultSettings:
    """Default settings for client behavior."""

    profile: str = "standard"
    timeout: float = 30.0
    retries: int = 0
    verify_ssl: bool = True


@dataclass
class ServiceSettings:
    """Per-service configuration overrides."""

    profile: str | None = None
    timeout: float | None = None
    retries: int | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    """Main configuration object for MOTIM."""

    profiles: dict[str, HeaderProfile] = field(default_factory=dict)
    defaults: DefaultSettings = field(default_factory=DefaultSettings)
    services: dict[str, ServiceSettings] = field(default_factory=dict)
    capture: CaptureSettings = field(default_factory=CaptureSettings)

    def __post_init__(self):
        """Ensure default profiles exist."""
        if "minimal" not in self.profiles:
            self.profiles["minimal"] = HeaderProfile(
                include=["authorization", "x-api-key", "api-key"],
            )
        if "standard" not in self.profiles:
            self.profiles["standard"] = HeaderProfile(
                include=["authorization", "cookie", "x-*"],
                exclude=["x-request-id", "x-correlation-id"],
            )
        if "full" not in self.profiles:
            self.profiles["full"] = HeaderProfile(
                include=["*"],
                exclude=["host", "content-length", "connection", "accept-encoding"],
            )

    def get_profile(self, name: str) -> HeaderProfile:
        """Get a header profile by name."""
        if name not in self.profiles:
            raise ConfigError(f"Unknown profile: {name}. Available: {list(self.profiles.keys())}")
        return self.profiles[name]

    def get_service_settings(self, service_name: str) -> ServiceSettings:
        """Get settings for a specific service, with defaults applied."""
        # Try exact match first
        if service_name in self.services:
            return self.services[service_name]

        # Try partial match
        for key, settings in self.services.items():
            if key.lower() in service_name.lower() or service_name.lower() in key.lower():
                return settings

        # Return empty settings (will use defaults)
        return ServiceSettings()

    @classmethod
    def load(cls, path: Path | None = None, *, strict: bool = False) -> Config:
        """Load configuration from file."""
        if path is None:
            path = CONFIG_FILE

        if not path.exists():
            # Return default config
            return cls()

        try:
            data = yaml.safe_load(path.read_text()) or {}
            return cls.from_dict(data)
        except Exception as e:
            if strict:
                raise ConfigError(f"Failed to load config from {path}: {e}") from e
            # Log warning but return defaults
            logger.warning("Failed to load config from %s: %s", path, e)
            return cls()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Create Config from dictionary."""
        profiles = {}
        profiles_data = data.get("profiles") or {}
        for name, profile_data in profiles_data.items():
            if profile_data:  # Skip None entries
                profiles[name] = HeaderProfile(
                    include=profile_data.get("include", []),
                    exclude=profile_data.get("exclude", []),
                )

        defaults_data = data.get("defaults") or {}
        defaults = DefaultSettings(
            profile=defaults_data.get("profile", "standard"),
            timeout=defaults_data.get("timeout", 30.0),
            retries=defaults_data.get("retries", 0),
            verify_ssl=defaults_data.get("verify_ssl", True),
        )

        services = {}
        services_data = data.get("services") or {}
        for name, svc_data in services_data.items():
            if svc_data:  # Skip None entries
                services[name] = ServiceSettings(
                    profile=svc_data.get("profile"),
                    timeout=svc_data.get("timeout"),
                    retries=svc_data.get("retries"),
                    extra_headers=svc_data.get("extra_headers", {}),
                )

        capture_data = data.get("capture") or {}
        redaction_data = capture_data.get("redaction") or {}
        redaction = RedactionSettings(
            enabled=bool(redaction_data.get("enabled", True)),
            profile=str(redaction_data.get("profile", "strict")),
            placeholder=str(redaction_data.get("placeholder", REDACTED_PLACEHOLDER if "REDACTED_PLACEHOLDER" in globals() else "[REDACTED]")),
            extra_sensitive_headers=list(redaction_data.get("extra_sensitive_headers", [])),
            extra_sensitive_params=list(redaction_data.get("extra_sensitive_params", [])),
            extra_sensitive_keys=list(redaction_data.get("extra_sensitive_keys", [])),
        )

        capture = CaptureSettings(
            allowed_hosts=list(capture_data.get("allowed_hosts", [])),
            redaction=redaction,
            skip_headers=capture_data.get("skip_headers", CaptureSettings().skip_headers),
            skip_domains=capture_data.get("skip_domains", CaptureSettings().skip_domains),
            max_samples_per_endpoint=capture_data.get("max_samples_per_endpoint", 50),
            max_samples_total=capture_data.get("max_samples_total", 1000),
            write_specs=capture_data.get("write_specs", True),
            store_exchanges=capture_data.get("store_exchanges", True),
            exchange_db_path=capture_data.get("exchange_db_path", "~/.motim/motim.sqlite3"),
            max_body_bytes=capture_data.get("max_body_bytes", 1_000_000),
            exchange_db_buffered=capture_data.get("exchange_db_buffered", True),
            exchange_db_queue_max=capture_data.get("exchange_db_queue_max", 10_000),
            exchange_db_batch_size=capture_data.get("exchange_db_batch_size", 100),
            exchange_db_flush_interval_ms=capture_data.get("exchange_db_flush_interval_ms", 250),
            pipeline_enabled=capture_data.get("pipeline_enabled", True),
            pipeline_queue_max=capture_data.get("pipeline_queue_max", 5_000),
            pipeline_drop_when_full=capture_data.get("pipeline_drop_when_full", True),
            pipeline_max_parse_bytes=capture_data.get("pipeline_max_parse_bytes", 200_000),
            log_every_n=capture_data.get("log_every_n", 25),
            profile_enabled=capture_data.get("profile_enabled", False),
            profile_every_n=capture_data.get("profile_every_n", 200),
        )

        return cls(
            profiles=profiles,
            defaults=defaults,
            services=services,
            capture=capture,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert Config to dictionary for saving."""
        return {
            "profiles": {
                name: {"include": p.include, "exclude": p.exclude}
                for name, p in self.profiles.items()
            },
            "defaults": {
                "profile": self.defaults.profile,
                "timeout": self.defaults.timeout,
                "retries": self.defaults.retries,
                "verify_ssl": self.defaults.verify_ssl,
            },
            "services": {
                name: {
                    k: v
                    for k, v in {
                        "profile": s.profile,
                        "timeout": s.timeout,
                        "retries": s.retries,
                        "extra_headers": s.extra_headers or None,
                    }.items()
                    if v is not None
                }
                for name, s in self.services.items()
            },
            "capture": {
                "allowed_hosts": self.capture.allowed_hosts,
                "redaction": {
                    "enabled": self.capture.redaction.enabled,
                    "profile": self.capture.redaction.profile,
                    "placeholder": self.capture.redaction.placeholder,
                    "extra_sensitive_headers": self.capture.redaction.extra_sensitive_headers,
                    "extra_sensitive_params": self.capture.redaction.extra_sensitive_params,
                    "extra_sensitive_keys": self.capture.redaction.extra_sensitive_keys,
                },
                "skip_headers": self.capture.skip_headers,
                "skip_domains": self.capture.skip_domains,
                "max_samples_per_endpoint": self.capture.max_samples_per_endpoint,
                "max_samples_total": self.capture.max_samples_total,
                "write_specs": self.capture.write_specs,
                "store_exchanges": self.capture.store_exchanges,
                "exchange_db_path": self.capture.exchange_db_path,
                "max_body_bytes": self.capture.max_body_bytes,
                "exchange_db_buffered": self.capture.exchange_db_buffered,
                "exchange_db_queue_max": self.capture.exchange_db_queue_max,
                "exchange_db_batch_size": self.capture.exchange_db_batch_size,
                "exchange_db_flush_interval_ms": self.capture.exchange_db_flush_interval_ms,
                "pipeline_enabled": self.capture.pipeline_enabled,
                "pipeline_queue_max": self.capture.pipeline_queue_max,
                "pipeline_drop_when_full": self.capture.pipeline_drop_when_full,
                "pipeline_max_parse_bytes": self.capture.pipeline_max_parse_bytes,
                "log_every_n": self.capture.log_every_n,
                "profile_enabled": self.capture.profile_enabled,
                "profile_every_n": self.capture.profile_every_n,
            },
        }

    def save(self, path: Path | None = None) -> None:
        """Save configuration to file."""
        if path is None:
            path = CONFIG_FILE

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False))


# Global config instance (lazy loaded)
_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def reload_config() -> Config:
    """Reload configuration from disk."""
    global _config
    _config = Config.load()
    return _config
