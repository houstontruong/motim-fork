"""Base adapter interface for exchange reconciliation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from motim.reconcile.models import Fact, Issue


@dataclass
class AdapterResult:
    facts: list[tuple[Fact, str | None]] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    is_supported: bool = True


class BaseAdapter(ABC):
    """Abstract base class for provider reconciliation adapters."""

    provider: str

    @abstractmethod
    def supports_route(self, route_key: str) -> bool:
        """Return True if this adapter supports the given synthetic route key."""
        raise NotImplementedError

    @abstractmethod
    def reconcile_exchange(self, exchange: dict[str, Any]) -> AdapterResult:
        """Translate a validated sanitized exchange object into raw facts and issues."""
        raise NotImplementedError
