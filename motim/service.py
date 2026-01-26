"""Service domain object for MOTIM.

`Service` is the primary read API over captured proxy data: observed endpoints,
captured auth, request/response samples, and simple analysis helpers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator

from .auth import Auth
from .config import Config, get_config
from .store import Store, get_store


@dataclass
class Sample:
    """A captured request/response sample."""

    endpoint: str
    timestamp: datetime
    status: int
    query_params: dict[str, Any] = field(default_factory=dict)
    request_body: Any = None
    response_body: Any = None
    graphql_operation: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Sample:
        """Create Sample from dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError:
                timestamp = datetime.now()
        elif timestamp is None:
            timestamp = datetime.now()

        return cls(
            endpoint=data.get("endpoint", ""),
            timestamp=timestamp,
            status=data.get("status", 0),
            query_params=data.get("query_params", {}),
            request_body=data.get("request_body"),
            response_body=data.get("response_body"),
            graphql_operation=data.get("graphql_operation"),
        )

    @property
    def method(self) -> str:
        """Extract HTTP method from endpoint."""
        return self.endpoint.split()[0] if self.endpoint else ""

    @property
    def path(self) -> str:
        """Extract path from endpoint."""
        parts = self.endpoint.split()
        return parts[1] if len(parts) > 1 else ""


@dataclass
class SampleCollection:
    """Collection of samples with filtering and comparison."""

    _samples: list[Sample] = field(default_factory=list)

    def __iter__(self) -> Iterator[Sample]:
        return iter(self._samples)

    def __len__(self) -> int:
        return len(self._samples)

    def __getitem__(self, index: int) -> Sample:
        return self._samples[index]

    @property
    def latest(self) -> Sample | None:
        """Get most recent sample."""
        if not self._samples:
            return None
        return max(self._samples, key=lambda s: s.timestamp)

    def for_endpoint(self, endpoint: str) -> SampleCollection:
        """Filter samples by endpoint (supports partial match)."""
        endpoint_lower = endpoint.lower()
        filtered = [s for s in self._samples if endpoint_lower in s.endpoint.lower()]
        return SampleCollection(_samples=filtered)

    def for_method(self, method: str) -> SampleCollection:
        """Filter samples by HTTP method."""
        method_upper = method.upper()
        filtered = [s for s in self._samples if s.method == method_upper]
        return SampleCollection(_samples=filtered)

    def for_status(self, status: int) -> SampleCollection:
        """Filter samples by status code."""
        filtered = [s for s in self._samples if s.status == status]
        return SampleCollection(_samples=filtered)

    def successful(self) -> SampleCollection:
        """Filter to only 2xx responses."""
        filtered = [s for s in self._samples if 200 <= s.status < 300]
        return SampleCollection(_samples=filtered)

    def compare(self, endpoint: str | None = None) -> SampleComparison:
        """Compare samples to find patterns.

        Args:
            endpoint: Optional endpoint filter

        Returns:
            SampleComparison with analysis
        """
        samples = self._samples
        if endpoint:
            samples = self.for_endpoint(endpoint)._samples

        return SampleComparison.from_samples(samples)


@dataclass
class SampleComparison:
    """Analysis of multiple samples to find patterns."""

    sample_count: int = 0
    status_codes: list[int] = field(default_factory=list)
    constant_params: dict[str, Any] = field(default_factory=dict)
    varying_params: dict[str, list[Any]] = field(default_factory=dict)
    constant_body_keys: list[str] = field(default_factory=list)
    varying_body_keys: list[str] = field(default_factory=list)

    @classmethod
    def from_samples(cls, samples: list[Sample]) -> SampleComparison:
        """Create comparison from list of samples."""
        if len(samples) < 2:
            return cls(sample_count=len(samples))

        comparison = cls(
            sample_count=len(samples),
            status_codes=list(set(s.status for s in samples)),
        )

        # Compare query params
        all_params = [s.query_params for s in samples]
        all_keys: set[str] = set()
        for p in all_params:
            all_keys.update(p.keys())

        for key in all_keys:
            values = [p.get(key) for p in all_params]
            unique_values = set(str(v) for v in values if v is not None)
            if len(unique_values) == 1:
                comparison.constant_params[key] = list(unique_values)[0]
            else:
                comparison.varying_params[key] = list(unique_values)[:5]

        # Compare request bodies
        all_bodies = [s.request_body for s in samples if isinstance(s.request_body, dict)]
        if len(all_bodies) >= 2:
            all_body_keys: set[str] = set()
            for b in all_bodies:
                all_body_keys.update(b.keys())

            for key in all_body_keys:
                values = [b.get(key) for b in all_bodies]
                unique_values = set(str(v) for v in values if v is not None)
                if len(unique_values) == 1:
                    comparison.constant_body_keys.append(key)
                else:
                    comparison.varying_body_keys.append(key)

        return comparison


@dataclass
class EndpointCollection:
    """Collection of observed endpoints with filtering."""

    _endpoints: list[str] = field(default_factory=list)

    def __iter__(self) -> Iterator[str]:
        return iter(self._endpoints)

    def __len__(self) -> int:
        return len(self._endpoints)

    def __contains__(self, item: str) -> bool:
        return item in self._endpoints

    def filter(
        self,
        method: str | None = None,
        path: str | None = None,
    ) -> EndpointCollection:
        """Filter endpoints by method and/or path pattern.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Path pattern (supports * wildcard)

        Returns:
            Filtered EndpointCollection
        """
        filtered = self._endpoints

        if method:
            method_upper = method.upper()
            filtered = [e for e in filtered if e.startswith(method_upper + " ")]

        if path:
            if "*" in path:
                # Simple wildcard matching
                import fnmatch

                filtered = [
                    e for e in filtered if fnmatch.fnmatch(e.split()[1] if " " in e else e, path)
                ]
            else:
                filtered = [e for e in filtered if path in e]

        return EndpointCollection(_endpoints=filtered)

    def methods(self) -> list[str]:
        """Get unique HTTP methods."""
        methods = set()
        for endpoint in self._endpoints:
            if " " in endpoint:
                methods.add(endpoint.split()[0])
        return sorted(methods)


@dataclass
class Service:
    """Domain object representing a captured API service.

    This is the main interface for working with captured API data.
    """

    name: str
    host: str
    base_url: str
    auth: Auth
    endpoints: EndpointCollection
    samples: SampleCollection
    websocket_messages: list[dict[str, Any]] = field(default_factory=list)
    response_headers_seen: dict[str, str] = field(default_factory=dict)
    endpoint_base_urls: dict[str, str] = field(default_factory=dict)
    _raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, name: str, store: Store | None = None, config: Config | None = None) -> Service:
        """Load a service by name.

        Args:
            name: Service name or partial match (e.g., 'notion' matches 'api_notion_com')
            store: Optional Store instance
            config: Optional Config instance

        Returns:
            Service object

        Raises:
            FileNotFoundError: If no matching service found
        """
        store = store or get_store()
        config = config or get_config()

        spec = store.load(name)
        return cls.from_spec(spec, config=config)

    @classmethod
    def from_spec(cls, spec: dict[str, Any], config: Config | None = None) -> Service:
        """Create Service from spec dictionary."""
        config = config or get_config()

        host = spec.get("service", "")
        name = host.replace(".", "_").replace(":", "_")

        # Parse samples
        samples = [Sample.from_dict(s) for s in spec.get("samples", [])]

        endpoint_base_urls = spec.get("endpoint_base_urls", {})
        if not isinstance(endpoint_base_urls, dict):
            endpoint_base_urls = {}

        return cls(
            name=name,
            host=host,
            base_url=spec.get("base_url", f"https://{host}"),
            auth=Auth.from_spec(spec, config=config),
            endpoints=EndpointCollection(_endpoints=spec.get("observed_endpoints", [])),
            samples=SampleCollection(_samples=samples),
            websocket_messages=spec.get("websocket_messages", []),
            response_headers_seen=spec.get("response_headers_seen", {}),
            endpoint_base_urls=dict(endpoint_base_urls),
            _raw=spec,
        )

    @classmethod
    def list_all(cls, store: Store | None = None) -> list[str]:
        """List all available service names."""
        store = store or get_store()
        return store.services

    @classmethod
    def find(cls, query: str, store: Store | None = None) -> list[str]:
        """Find services matching a query."""
        store = store or get_store()
        return store.find(query)

    def reload(self, store: Store | None = None) -> Service:
        """Reload service from disk.

        Returns:
            New Service instance with fresh data
        """
        return Service.load(self.name, store=store)

    @property
    def raw(self) -> dict[str, Any]:
        """Access raw spec dictionary."""
        return self._raw

    def __repr__(self) -> str:
        return (
            f"Service(name={self.name!r}, "
            f"endpoints={len(self.endpoints)}, "
            f"samples={len(self.samples)}, "
            f"auth={self.auth.type!r})"
        )
