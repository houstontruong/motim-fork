"""MOTIM - Model Over Traffic, Intercept & Manage.

MOTIM is a system for capturing, querying, and replaying API traffic.

It provides:
1. A local MITM proxy addon that observes real HTTP(S) requests/responses
2. A local spec store written to `~/.motim/specs/` (YAML)
3. A Python client + convenience helpers to replay authenticated requests using captured auth
4. A skill file that teaches AI agents how to use the captured specs

Usage:
    # Simple one-liner
    from motim import Client
    r = Client("notion").get("/v1/users/me")

    # With more control
    from motim import Service, Client, Auth

    svc = Service.load("notion")
    print(svc.auth.type)              # 'bearer'
    print(svc.endpoints)              # ['GET /v1/users', ...]

    client = Client(svc, auth_profile="full")
    r = client.get("/v1/users/me")

    # Raw access
    from motim import Store
    store = Store()
    spec = store.load("notion")       # Raw dict
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("motim")
except PackageNotFoundError:  # pragma: no cover
    # Allow importing from a source checkout without installation.
    __version__ = "0.0.0"

# Core classes
from .agent_replay import diff_exchanges, replay_exchange
from .auth import Auth

# Convenience functions
from .client import AsyncClient, Client, delete, get, patch, post, put
from .config import Config, get_config, reload_config
from .db_client import DBClient
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
    # Auth
    "Auth",
    # Service
    "Service",
    "Sample",
    "SampleCollection",
    "SampleComparison",
    "EndpointCollection",
    # Client
    "Client",
    "AsyncClient",
    "DBClient",
    # Exchange DB (agent substrate)
    "ExchangeDB",
    "HeaderField",
    "BufferedExchangeWriter",
    # Agent replay/diff helpers
    "replay_exchange",
    "diff_exchanges",
    # Convenience functions
    "get",
    "post",
    "put",
    "delete",
    "patch",
]
