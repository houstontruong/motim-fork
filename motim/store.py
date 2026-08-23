"""Spec storage and retrieval for MOTIM (Production-Safe).

The store persists observed API schemas and endpoint samples into YAML files (default:
`~/.motim/specs/*.yaml`) with private permissions (0700 dirs, 0600 files), race-free
atomic writes, symlink defenses, and strict redaction of all persisted values.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
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
from .redact import Redactor, get_redactor

logger = logging.getLogger(__name__)

MOTIM_DIR = Path.home() / ".motim"
SPECS_DIR = MOTIM_DIR / "specs"
FLUSH_INTERVAL = 2.0


class Store:
    """Manages spec file storage and retrieval with instance-local cache and atomic writes."""

    def __init__(
        self,
        specs_dir: Path | str | None = None,
        config: Config | None = None,
    ):
        self.config = config or get_config()
        raw_specs_dir = Path(specs_dir or SPECS_DIR).expanduser()
        if raw_specs_dir.is_symlink() or raw_specs_dir.parent.is_symlink():
            raise PermissionError(f"Security violation: specs directory cannot be a symlink: {raw_specs_dir}")
        self.specs_dir = raw_specs_dir.resolve()
        self.redactor = get_redactor(
            profile=getattr(self.config.capture.redaction, "profile", "strict")
        )

        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty: set[str] = set()
        self._lock = threading.Lock()
        self._stop_flush = threading.Event()
        self._flush_thread: threading.Thread | None = None

        self._init_storage()
        self._start_flush_thread()
        atexit.register(self.close)

    def _init_storage(self) -> None:
        """Enforce 0700 permissions and ensure directory is not a symlink."""
        self.specs_dir.mkdir(parents=True, exist_ok=True)

        if os.name != "nt":
            try:
                self.specs_dir.chmod(0o700)
                current_mode = self.specs_dir.stat().st_mode & 0o777
                if current_mode != 0o700:
                    # In some filesystems or restrictive environments, chmod may be constrained,
                    # but fail closed if permission is too open (world/group accessible).
                    if current_mode & 0o077 != 0:
                        raise PermissionError(f"Failed to enforce private 0700 mode on {self.specs_dir}")
            except OSError as e:
                raise PermissionError(f"Failed to enforce directory permissions on {self.specs_dir}: {e}") from e

    def _start_flush_thread(self) -> None:
        """Start the background flush thread."""
        if self._flush_thread is None or not self._flush_thread.is_alive():
            self._stop_flush.clear()
            self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
            self._flush_thread.start()

    def _flush_loop(self) -> None:
        """Background loop for dirty spec flushing."""
        while not self._stop_flush.is_set():
            time.sleep(FLUSH_INTERVAL)
            if self._dirty:
                self.flush()

    def close(self) -> None:
        """Stop background flush thread and flush remaining dirty specs."""
        self._stop_flush.set()
        if self._flush_thread is not None and self._flush_thread.is_alive():
            try:
                self._flush_thread.join(timeout=2.0)
            except Exception:
                pass
        self.flush()

    @property
    def services(self) -> list[str]:
        """List all captured service names."""
        if not self.specs_dir.exists():
            return []
        disk_services = set()
        for f in self.specs_dir.glob("*.yaml"):
            if not f.name.startswith(".tmp_") and not f.is_symlink():
                disk_services.add(f.stem)
        with self._lock:
            cached_services = set(self._cache.keys())
        return sorted(disk_services | cached_services)

    def list_services(self) -> list[str]:
        """Return list of all captured service names."""
        return self.services

    def find(self, query: str) -> list[str]:
        """Find services matching a query (fuzzy match)."""
        query_lower = query.lower()
        return [s for s in self.services if query_lower in s.lower()]

    def exists(self, service: str) -> bool:
        """Check if a spec exists for a service."""
        name = self._normalize_name(service)
        with self._lock:
            if name in self._cache:
                return True
        path = self._get_path(service)
        return (path.exists() and not path.is_symlink()) or bool(self.find(service))

    def load(self, service: str) -> dict[str, Any]:
        """Load spec for a service as raw dict (from cache or disk)."""
        name = self._normalize_name(service)

        # Check cache first (exact match)
        with self._lock:
            if name in self._cache:
                return json.loads(json.dumps(self._cache[name]))

        # Try fuzzy match in cache
        with self._lock:
            for cached_name in self._cache:
                if name in cached_name:
                    return json.loads(json.dumps(self._cache[cached_name]))

        # Load from disk
        path = self._resolve_path(service)
        if not path.exists() or path.is_symlink():
            suggestions = self.find(service)
            raise ServiceNotFoundError(service, suggestions=suggestions)

        try:
            spec = yaml.safe_load(path.read_text(encoding="utf-8")) or self._empty_spec(service)
        except Exception:
            spec = self._empty_spec(service)

        resolved_name = path.stem
        with self._lock:
            self._cache[resolved_name] = spec

        return json.loads(json.dumps(spec))

    def save(self, service: str, spec: dict[str, Any]) -> Path:
        """Save spec to cache and mark dirty (atomic write)."""
        name = self._normalize_name(service)
        spec_copy = json.loads(json.dumps(spec))

        with self._lock:
            self._cache[name] = spec_copy
            self._dirty.add(name)

        return self._get_path(service)

    def flush(self) -> int:
        """Force flush all dirty specs to disk atomically. Returns count flushed."""
        flushed = 0
        with self._lock:
            dirty_services = list(self._dirty)

        if not dirty_services:
            return 0

        try:
            self.specs_dir.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    self.specs_dir.chmod(0o700)
                except Exception:
                    pass
        except OSError:
            pass


        for service in dirty_services:
            with self._lock:
                spec = self._cache.get(service)
                if spec is None:
                    self._dirty.discard(service)
                    continue
                spec_copy = json.loads(json.dumps(spec))

            target_path = self._get_path(service)
            temp_path = self.specs_dir / f".tmp_{service}_{os.getpid()}_{time.time_ns()}.yaml"
            try:
                # 1. Atomic file create with mode 0600
                yaml_content = yaml.dump(
                    spec_copy, default_flow_style=False, sort_keys=False, allow_unicode=True
                )
                yaml_bytes = yaml_content.encode("utf-8")

                flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(temp_path, flags, 0o600)
                try:
                    os.write(fd, yaml_bytes)
                    os.fsync(fd)
                finally:
                    os.close(fd)

                if os.name != "nt":
                    try:
                        temp_path.chmod(0o600)
                    except Exception:
                        pass

                # 2. Atomic replace
                os.replace(temp_path, target_path)
                flushed += 1
                with self._lock:
                    self._dirty.discard(service)
            except Exception as e:
                logger.error("Failed to write spec for %s to %s: %s", service, target_path, e)
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                with self._lock:
                    self._dirty.add(service)

        return flushed

    def delete(self, service: str) -> bool:
        """Delete spec for a service safely."""
        name = self._normalize_name(service)
        was_cached = False

        with self._lock:
            if name in self._cache:
                del self._cache[name]
                was_cached = True
            self._dirty.discard(name)

        path = self._resolve_path(service)
        if path.exists() and not path.is_symlink():
            path.unlink()
            return True

        return was_cached

    def clear(self) -> int:
        """Delete all specs safely."""
        with self._lock:
            cached_names = set(self._cache.keys())
            self._cache.clear()
            self._dirty.clear()

        disk_files = set()
        for spec_file in self.specs_dir.glob("*.yaml"):
            if not spec_file.name.startswith(".tmp_") and not spec_file.is_symlink():
                disk_files.add(spec_file.stem)
                spec_file.unlink()

        return len(cached_names | disk_files)

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

        Strictly redacts all headers, bodies, queries, and WebSocket frames before storage.
        """
        service = self._normalize_name(host)

        try:
            spec = self.load(service)
        except ServiceNotFoundError:
            spec = self._empty_spec(host)

        # 1. Redact and extract auth metadata (never raw credentials)
        skip_headers = set(h.lower() for h in self.config.capture.skip_headers)
        important_headers = {}
        cookie_names: list[str] = []
        auth_type = "none"

        for name, value in request_headers.items():
            name_lower = name.lower()
            if name_lower not in skip_headers:
                important_headers[name] = self.redactor.placeholder

            if name_lower == "authorization":
                val_str = str(value).lower()
                if val_str.startswith("bearer "):
                    auth_type = "bearer"
                elif val_str.startswith("basic "):
                    auth_type = "basic"
                else:
                    auth_type = "custom"
            elif any(sub in name_lower for sub in ("api-key", "apikey", "x-api-key")):
                if auth_type == "none":
                    auth_type = "api_key"
            elif name_lower == "cookie":
                if auth_type == "none":
                    auth_type = "cookie"
                try:
                    cookies = parse_cookie_header(str(value))
                    cookie_names.extend(list(cookies.keys()))
                except Exception:
                    pass

        if important_headers or cookie_names:
            spec["auth"] = {
                "type": auth_type,
                "headers": important_headers,
                "cookies": {c: self.redactor.placeholder for c in cookie_names},
                "last_seen": datetime.now().isoformat(),
            }

        # 2. Capture response headers
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
                    resp_headers[name] = str(value)
            if resp_headers:
                spec.setdefault("response_headers_seen", {}).update(resp_headers)

        # 3. Handle WebSocket messages
        if is_websocket:
            ws_content = request_body or response_body
            redacted_ws_content = self.redactor.redact_data_structure(ws_content)
            ws_sample = {
                "path": path,
                "direction": ws_direction,
                "timestamp": datetime.now().isoformat(),
                "content": self._truncate(redacted_ws_content),
            }
            spec.setdefault("websocket_messages", [])
            spec["websocket_messages"] = spec["websocket_messages"][-999:] + [ws_sample]
            self.save(service, spec)
            return

        # 4. Endpoints & base URLs
        base_endpoint = f"{method} {path}"
        endpoint = base_endpoint
        if graphql_operation:
            endpoint = f"{method} {path} ({graphql_operation})"

        if endpoint not in spec["observed_endpoints"]:
            spec["observed_endpoints"].append(endpoint)

        if scheme is None:
            scheme = "https"
        base_url = f"{scheme}://{host}"
        endpoint_base_urls = spec.setdefault("endpoint_base_urls", {})
        if isinstance(endpoint_base_urls, dict):
            endpoint_base_urls.setdefault(base_endpoint, base_url)
            endpoint_base_urls.setdefault(endpoint, base_url)

        # 5. Redact sample bodies and queries
        redacted_qp = self.redactor.redact_data_structure(query_params) if query_params else None
        redacted_req_body = (
            self.redactor.redact_data_structure(request_body) if request_body is not None else None
        )
        redacted_resp_body = (
            self.redactor.redact_data_structure(response_body) if response_body is not None else None
        )

        sample = {
            "endpoint": endpoint,
            "timestamp": datetime.now().isoformat(),
            "status": int(status_code),
        }
        if redacted_qp:
            sample["query_params"] = redacted_qp
        if redacted_req_body is not None:
            sample["request_body"] = self._truncate(redacted_req_body)
        if redacted_resp_body is not None:
            sample["response_body"] = self._truncate(redacted_resp_body)
        if graphql_operation:
            sample["graphql_operation"] = graphql_operation

        # Compute canonical hash for deduplication
        sample_hash = self._compute_hash(sample)
        sample["_hash"] = sample_hash

        existing_hashes = {s.get("_hash") for s in spec["samples"]}
        if sample_hash in existing_hashes:
            for s in spec["samples"]:
                if s.get("_hash") == sample_hash:
                    s["timestamp"] = sample["timestamp"]
                    break
            self.save(service, spec)
            return

        # 6. Apply sample limits cleanly
        max_per_endpoint = max(1, int(getattr(self.config.capture, "max_samples_per_endpoint", 50) or 50))
        max_total = max(1, int(getattr(self.config.capture, "max_samples_total", 1000) or 1000))

        existing_for_endpoint = [s for s in spec["samples"] if s["endpoint"] == endpoint]
        other_samples = [s for s in spec["samples"] if s["endpoint"] != endpoint]

        existing_for_endpoint = existing_for_endpoint[-(max_per_endpoint - 1) :] + [sample]
        spec["samples"] = (other_samples + existing_for_endpoint)[-max_total:]

        self.save(service, spec)

    def _get_path(self, service: str) -> Path:
        """Get path for a service spec file, preventing traversal."""
        name = self._normalize_name(service)
        target = (self.specs_dir / f"{name}.yaml").resolve()
        # Verify containment within specs_dir
        if not str(target).startswith(str(self.specs_dir)):
            raise ValueError(f"Path traversal detected: {service!r}")
        return target

    def _resolve_path(self, service: str) -> Path:
        """Resolve service to actual path safely."""
        path = self._get_path(service)
        if path.exists() and not path.is_symlink():
            return path

        matches = self.find(service)
        if matches:
            return self._get_path(matches[0])

        return path

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize service name for filesystem and sanitize traversal."""
        cleaned = str(name).strip().replace("\x00", "")
        # Remove directory separators and path traversal
        cleaned = cleaned.replace("..", "_").replace("/", "_").replace("\\", "_").replace(":", "_")
        cleaned = cleaned.replace(".", "_")
        if not cleaned or cleaned.startswith("_"):
            cleaned = "service" + cleaned
        return cleaned

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
        """Compute canonical hash for deduplication."""
        hash_data = {k: v for k, v in sample.items() if k not in ("timestamp", "_hash")}
        hash_str = json.dumps(hash_data, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(hash_str.encode("utf-8")).hexdigest()[:16]

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


def get_store(specs_dir: Path | str | None = None, config: Config | None = None) -> Store:
    """Get a Store instance with configured settings."""
    cfg = config or get_config()
    return Store(specs_dir=specs_dir, config=cfg)

