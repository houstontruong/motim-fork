"""MOTIM - Model Over Traffic, Intercept & Manage (Production-Safe Fork).

MOTIM captures, redacts, indexes, and surfaces web API schemas and endpoints
for AI agents without storing raw credentials or enabling request replay.

It provides:
1. A local MITM proxy addon that observes HTTP(S) traffic within an egress allowlist
2. Strict redaction-before-persistence across all storage boundaries
3. A local spec store written to `~/.motim/specs/` (YAML) with private permissions (0700/0600)
4. An SQLite exchange database (`~/.motim/motim.sqlite3`) for schema inspection and endpoint indexing
5. Read-only discovery APIs (`discover`, `discover_services`, `ServiceDiscovery`) for AI agents

Usage:
    # Service discovery
    from motim import discover, discover_services

    services = discover_services()
    print(services)                   # ['notion', 'bybit', ...]

    # Schema inspection
    disc = discover("notion")
    print(disc.auth_type)             # 'bearer'
    print(disc.base_url)              # 'https://api.notion.com'
    print(disc.endpoints)             # ['GET /v1/users', ...]

    # Direct spec access
    from motim import Store
    store = Store()
    spec = store.load("notion")       # Redacted spec dict
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("motim")
except PackageNotFoundError:  # pragma: no cover
    # Allow importing from a source checkout without installation.
    __version__ = "0.0.0"

# Core classes
from .auth import Auth
from .config import Config, get_config, reload_config
from .diff import diff_exchanges
from .discovery import EndpointSummary, ServiceDiscovery, discover, discover_services
from .exceptions import (
    AuthError,
    AuthExpiredError,
    AuthMissingError,
    ConfigError,
    MOTIMError,
    ServiceNotFoundError,
)
from .exchange_db import ExchangeDB, HeaderField
from .exchange_writer import BufferedExchangeWriter
from .redact import Redactor, get_redactor
from .reconcile import AccountReadResult, Fact, Issue, reconcile
from .service import EndpointCollection, Sample, SampleCollection, SampleComparison, Service
from .store import Store, get_store

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "MOTIMError",
    "ConfigError",
    "AuthError",
    "AuthMissingError",
    "AuthExpiredError",
    "ServiceNotFoundError",
    # Config
    "Config",
    "get_config",
    "reload_config",
    # Store
    "Store",
    "get_store",
    # Redaction
    "Redactor",
    "get_redactor",
    # Auth (metadata only)
    "Auth",
    # Service & Discovery
    "Service",
    "Sample",
    "SampleCollection",
    "SampleComparison",
    "EndpointCollection",
    "discover",
    "discover_services",
    "ServiceDiscovery",
    "EndpointSummary",
    # Exchange DB (agent substrate)
    "ExchangeDB",
    "HeaderField",
    "BufferedExchangeWriter",
    # Diff helpers
    "diff_exchanges",
    # Reconciliation
    "reconcile",
    "AccountReadResult",
    "Fact",
    "Issue",
]

