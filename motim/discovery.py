"""Discovery and schema inspection interface for MOTIM.

Provides structured, read-only discovery of observed services, endpoints,
and parameter shapes from captured traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .config import Config, get_config
from .exchange_db import ExchangeDB
from .service import Service
from .store import Store, get_store


@dataclass(frozen=True)
class EndpointSummary:
    """Summary of a discovered API endpoint."""

    method: str
    path: str
    endpoint: str
    sample_count: int = 0
    statuses_seen: list[int] = field(default_factory=list)
    graphql_operation: str | None = None


@dataclass
class ServiceDiscovery:
    """Read-only discovery and schema inspection interface for an observed service."""

    name: str
    service: Service
    db: ExchangeDB | None = None

    @property
    def endpoints(self) -> list[str]:
        """List of all observed endpoint signatures."""
        return list(self.service.endpoints)

    @property
    def auth_type(self) -> str:
        """Detected authentication scheme (e.g. 'bearer', 'cookie', 'api_key')."""
        return self.service.auth.type

    @property
    def base_url(self) -> str:
        """Primary base URL observed for this service."""
        return self.service.base_url

    def list_endpoints(self) -> list[EndpointSummary]:
        """Return structured summaries of all endpoints."""
        summaries: list[EndpointSummary] = []
        for ep in self.service.endpoints:
            samples = self.service.samples.for_endpoint(ep)
            statuses = sorted({s.status for s in samples if s.status > 0})
            method = ep.split()[0] if ep else ""
            path = ep.split()[1] if len(ep.split()) > 1 else ""
            summaries.append(
                EndpointSummary(
                    method=method,
                    path=path,
                    endpoint=ep,
                    sample_count=len(samples),
                    statuses_seen=statuses,
                )
            )
        return summaries


def discover_services(
    *,
    store: Store | None = None,
    db: ExchangeDB | None = None,
    config: Config | None = None,
) -> list[str]:
    """List all discovered service names available in the store or database."""
    cfg = config or get_config()
    st = store or get_store(config=cfg)
    services = set(st.services)
    if db is not None:
        try:
            for s in db.list_services():
                services.add(s["service_key"])
        except Exception:
            pass
    return sorted(services)


def discover(
    service_name: str,
    *,
    store: Store | None = None,
    db: ExchangeDB | None = None,
    config: Config | None = None,
) -> ServiceDiscovery:
    """Load and inspect a discovered service."""
    cfg = config or get_config()
    st = store or get_store(config=cfg)
    svc = Service.load(service_name, store=st, config=cfg)
    return ServiceDiscovery(name=service_name, service=svc, db=db)

