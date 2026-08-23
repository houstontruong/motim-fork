"""Spec storage and retrieval for MOTIM.

The store persists proxy-observed requests/responses into YAML files (default:
`~/.motim/specs/*.yaml`) and provides fast querying/loading for downstream use
(Service objects, Client auth injection, analysis).
"""

from __future__ import annotations

import atexit
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .config import Config, get_config
from .exceptions import ServiceNotFoundError
from .normalize import parse_cookie_header

MOTIM_DIR = Path.home() / ".motim"
SPECS_DIR = MOTIM_DIR / "specs"

# Global in-memory cache and dirty tracking
_cache: dict[str, dict[str, Any]] = {}
_dirty: set[str] = set()
_cache_lock = threading.Lock()
_flush_thread: threading.Thread | None = None
_shutdown = False

# Flush interval in seconds
FLUSH_INTERVAL = 2.0


def _flush_dirty_specs(specs_dir: Path) -> int:
    """Flush all dirty specs to disk. Returns count flushed."""
    global _dirty
    flushed = 0

    with _cache_lock:
        dirty_services = list(_dirty)
        _dirty.clear()

    for service in dirty_services:
        # Copy reference under lock, but do expensive deep copy outside the lock.
        with _cache_lock:
            spec = _cache.get(service)
        if spec is None:
            continue
        # Deep copy to avoid modification during write
        spec_copy = json.loads(json.dumps(spec))

        path = specs_dir / f"{service}.yaml"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                yaml.dump(spec_copy, default_flow_style=False, sort_keys=False, allow_unicode=True)
            )
            path.chmod(0o600)
            flushed += 1
        except Exception:
            # Re-mark as dirty on failure
            with _cache_lock:
                _dirty.add(service)

    return flushed


def _flush_loop(specs_dir: Path):
    """Background thread that periodically flushes dirty specs."""
    global _shutdown
    while not _shutdown:
        time.sleep(FLUSH_INTERVAL)
        if _dirty:
            _flush_dirty_specs(specs_dir)


def _start_flush_thread(specs_dir: Path):
    """Start the background flush thread if not already running."""
    global _flush_thread
    if _flush_thread is None or not _flush_thread.is_alive():
        _flush_thread = threading.Thread(target=_flush_loop, args=(specs_dir,), daemon=True)
        _flush_thread.start()


def _shutdown_flush():
    """Flush all remaining dirty specs on shutdown."""
    global _shutdown
    _shutdown = True
    if _dirty:
        _flush_dirty_specs(SPECS_DIR)


# Register shutdown handler
atexit.register(_shutdown_flush)


@dataclass
class Store:
    """Manages spec file storage and retrieval with async buffered writes."""

    specs_dir: Path = field(default_factory=lambda: SPECS_DIR)
    config: Config = field(default_factory=get_config)

    def __post_init__(self):
        """Ensure specs directory exists and start flush thread."""
        self.specs_dir.mkdir(parents=True, exist_ok=True)
        _start_flush_thread(self.specs_dir)

    @property
    def services(self) -> list[str]:
        """List all captured service names."""
        if not self.specs_dir.exists():
            return []
        # Combine disk and cache
        disk_services = {f.stem for f in self.specs_dir.glob("*.yaml")}
        with _cache_lock:
            cached_services = set(_cache.keys())
        return sorted(disk_services | cached_services)

    def find(self, query: str) -> list[str]:
        """Find services matching a query (fuzzy match)."""
        query_lower = query.lower()
        matches = []
        for service in self.services:
            if query_lower in service.lower():
                matches.append(service)
        return matches

    def exists(self, service: str) -> bool:
        """Check if a spec exists for a service."""
        name = self._normalize_name(service)
        with _cache_lock:
            if name in _cache:
                return True
        return self._get_path(service).exists() or bool(self.find(service))

    def load(self, service: str) -> dict[str, Any]:
        """Load spec for a service as raw dict (from cache or disk).

        Args:
            service: Service name or partial match

        Returns:
            Raw spec dictionary

        Raises:
            FileNotFoundError: If no matching spec found
        """
        name = self._normalize_name(service)

        # Check cache first (exact match)
        with _cache_lock:
            if name in _cache:
                return _cache[name]

        # Try fuzzy match in cache
        with _cache_lock:
            for cached_name in _cache:
                if name in cached_name:
                    return _cache[cached_name]

        # Load from disk (supports fuzzy matching via _resolve_path)
        path = self._resolve_path(service)
        if not path.exists():
            suggestions = self.find(service)
            raise ServiceNotFoundError(service, suggestions=suggestions)

        spec = yaml.safe_load(path.read_text()) or self._empty_spec(service)

        # Cache it under the actual resolved name
        resolved_name = path.stem
        with _cache_lock:
            _cache[resolved_name] = spec

        return spec

    def save(self, service: str, spec: dict[str, Any]) -> Path:
        """Save spec to cache and mark dirty (async write).

        Args:
            service: Service name (will be normalized)
            spec: Spec dictionary to save

        Returns:
            Path where file will be saved
        """
        name = self._normalize_name(service)

        with _cache_lock:
            _cache[name] = spec
            _dirty.add(name)

        return self._get_path(service)

    def flush(self) -> int:
        """Force flush all dirty specs to disk. Returns count flushed."""
        return _flush_dirty_specs(self.specs_dir)

    def delete(self, service: str) -> bool:
        """Delete spec for a service.

        Returns:
            True if deleted, False if not found
        """
        name = self._normalize_name(service)
        was_cached = False

        # Remove from cache
        with _cache_lock:
            if name in _cache:
                del _cache[name]
                was_cached = True
            _dirty.discard(name)

        path = self._resolve_path(service)
        if path.exists():
            path.unlink()
            return True

        # Return True if it was in cache (even if not yet flushed to disk)
        return was_cached

    def clear(self) -> int:
        """Delete all specs.

        Returns:
            Number of specs deleted
        """
        # Get count from both cache and disk
        with _cache_lock:
            cached_names = set(_cache.keys())
            _cache.clear()
            _dirty.clear()

        disk_files = set(f.stem for f in self.specs_dir.glob("*.yaml"))

        # Total unique services (cache + disk)
        all_services = cached_names | disk_files

        # Delete disk files
        for spec_file in self.specs_dir.glob("*.yaml"):
            spec_file.unlink()

        return len(all_services)

    def update(
        self,
        host: str,
        *,
        scheme: str | None = None,
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        request_headers: dict[str, str],
        response_headers: dict[str, str] | None = None,
        request_body: Any | None = None,
        response_body: Any | None = None,
        status_code: int = 200,
        graphql_operation: str | None = None,
        is_websocket: bool = False,
        ws_direction: str | None = None,
    ) -> None:
        """Update spec with observed request/response.

        This is the main entry point for the proxy addon to record traffic.
        Now uses in-memory cache with async flushing for performance.
        """
        service = self._normalize_name(host)

        # Load from cache or disk (cached after first load)
        try:
            spec = self.load(service)
        except FileNotFoundError:
            spec = self._empty_spec(host)
            # Pre-cache it
            with _cache_lock:
                _cache[service] = spec

        # Filter headers based on config
        skip_headers = set(h.lower() for h in self.config.capture.skip_headers)
        important_headers = {}
        for name, value in request_headers.items():
            if name.lower() not in skip_headers:
                important_headers[name] = value

        if important_headers:
            spec["auth"] = {
                "headers": important_headers,
                "last_seen": datetime.now().isoformat(),
            }

            # Store cookies separately if present.
            for k, v in important_headers.items():
                if k.lower() == "cookie" and isinstance(v, str):
                    cookies = parse_cookie_header(v)
                    if cookies:
                        spec["auth"]["cookies"] = cookies
                    break

        # Capture important response headers
        if response_headers:
            resp_headers = {}
            important_resp_patterns = [
                "x-ratelimit",
                "x-rate-limit",
                "retry-after",
                "x-request-id",
                "x-correlation-id",
                "etag",
                "link",
                "x-total",
                "x-page",
                "x-per-page",
                "x-next",
                "x-cursor",
                "content-type",
            ]
            for name, value in response_headers.items():
                lower_name = name.lower()
                if any(p in lower_name for p in important_resp_patterns):
                    resp_headers[name] = value
            if resp_headers:
                spec.setdefault("response_headers_seen", {}).update(resp_headers)

        # Handle WebSocket messages separately
        if is_websocket:
            ws_sample = {
                "path": path,
                "direction": ws_direction,
                "timestamp": datetime.now().isoformat(),
                "content": self._truncate(request_body or response_body),
            }
            spec.setdefault("websocket_messages", [])
            spec["websocket_messages"] = spec["websocket_messages"][-999:] + [ws_sample]
            self.save(service, spec)
            return

        # Build endpoint identifier
        base_endpoint = f"{method} {path}"
        endpoint = base_endpoint
        if graphql_operation:
            endpoint = f"{method} {path} ({graphql_operation})"

        if endpoint not in spec["observed_endpoints"]:
            spec["observed_endpoints"].append(endpoint)

        # Track per-endpoint base URL (for endpoints across subdomains/origins).
        if scheme is None:
            # Best-effort inference; if unknown, default to https.
            scheme = "https"
        base_url = f"{scheme}://{host}"
        endpoint_base_urls = spec.setdefault("endpoint_base_urls", {})
        if isinstance(endpoint_base_urls, dict):
            endpoint_base_urls.setdefault(base_endpoint, base_url)
            endpoint_base_urls.setdefault(endpoint, base_url)

        # Store sample with full details
        sample = {
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
            "status": status_code,
        }

        if query_params:
            sample["query_params"] = query_params

        if request_body:
            sample["request_body"] = self._truncate(request_body)

        if response_body:
            sample["response_body"] = self._truncate(response_body)

        if graphql_operation:
            sample["graphql_operation"] = graphql_operation

        # Compute hash for deduplication
        sample_hash = self._compute_hash(sample)
        sample["_hash"] = sample_hash

        # Deduplicate
        existing_hashes = {s.get("_hash") for s in spec["samples"]}
        if sample_hash in existing_hashes:
            # Update timestamp of existing sample
            for s in spec["samples"]:
                if s.get("_hash") == sample_hash:
                    s["timestamp"] = sample["timestamp"]
                    break
            self.save(service, spec)
            return

        # Apply sample limits from config
        max_per_endpoint = self.config.capture.max_samples_per_endpoint
        max_total = self.config.capture.max_samples_total

        existing_for_endpoint = [s for s in spec["samples"] if s["endpoint"] == endpoint]
        other_samples = [s for s in spec["samples"] if s["endpoint"] != endpoint]

        # Keep last N for this endpoint
        existing_for_endpoint = existing_for_endpoint[-(max_per_endpoint - 1) :] + [sample]

        # Combine and keep last N total
        spec["samples"] = (other_samples + existing_for_endpoint)[-max_total:]

        self.save(service, spec)

    def _get_path(self, service: str) -> Path:
        """Get path for a service spec file."""
        name = self._normalize_name(service)
        return self.specs_dir / f"{name}.yaml"

    def _resolve_path(self, service: str) -> Path:
        """Resolve service to actual path (handles fuzzy matching)."""
        # Try exact match first
        path = self._get_path(service)
        if path.exists():
            return path

        # Try finding matches
        matches = self.find(service)
        if matches:
            return self._get_path(matches[0])

        return path  # Return expected path even if doesn't exist

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize service name for filesystem."""
        return name.replace(".", "_").replace(":", "_").replace("/", "_")

    @staticmethod
    def _empty_spec(host: str) -> dict[str, Any]:
        """Create empty spec structure."""
        return {
            "service": host,
            "base_url": f"https://{host}",
            "auth": {},
            "observed_endpoints": [],
            "samples": [],
            "websocket_messages": [],
        }

    @staticmethod
    def _compute_hash(sample: dict) -> str:
        """Compute hash for deduplication."""
        hash_data = {k: v for k, v in sample.items() if k not in ("timestamp", "_hash")}
        hash_str = str(sorted(hash_data.items()))
        return hashlib.md5(hash_str.encode()).hexdigest()[:12]

    @staticmethod
    def _truncate(data: Any) -> Any:
        """Truncate large data to prevent file bloat."""
        if isinstance(data, str) and len(data) > 1_000_000:
            return data[:1_000_000] + f"...[truncated, total {len(data)} chars]..."
        if isinstance(data, dict):
            return {k: Store._truncate(v) for k, v in data.items()}
        if isinstance(data, list):
            return [Store._truncate(item) for item in data]
        return data


# Convenience function
def get_store() -> Store:
    """Get a Store instance with default settings."""
    return Store()
