"""Adapter registry for exchange reconciliation."""

from __future__ import annotations

from typing import Type

from .base import BaseAdapter
from .bybit import BybitAdapter
from .lighter import LighterAdapter

_ADAPTER_REGISTRY: dict[str, Type[BaseAdapter]] = {
    "bybit": BybitAdapter,
    "lighter": LighterAdapter,
}


def get_adapter(provider: str) -> BaseAdapter:
    """Retrieve an instantiated adapter for the given provider."""
    adapter_cls = _ADAPTER_REGISTRY.get(provider.lower().strip())
    if not adapter_cls:
        raise ValueError(f"No adapter registered for provider: {provider}")
    return adapter_cls()


def is_provider_registered(provider: str) -> bool:
    """Check if a provider adapter is registered."""
    return provider.lower().strip() in _ADAPTER_REGISTRY
