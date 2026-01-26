"""DB-backed client/auth helpers for agent-first workflows.

These utilities avoid the YAML spec layer by sourcing auth and origin data from the
SQLite exchange DB (auth_snapshots + recent exchanges).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import httpx

from .config import Config, get_config
from .exceptions import AuthMissingError
from .exchange_db import ExchangeDB


class DBClient(httpx.Client):
    """httpx.Client configured from the SQLite exchange DB.

    This is best-effort and intended for stable APIs. For complex/private APIs,
    prefer `motim replay` / `replay_exchange()` using an exemplar exchange.
    """

    def __init__(
        self,
        service_key: str,
        *,
        db: ExchangeDB | None = None,
        db_path: str | Path | None = None,
        origin: str | None = None,
        headers: Mapping[str, str] | None = None,
        config: Config | None = None,
        require_auth: bool = True,
        timeout: float | None = None,
        http2: bool = True,
        **httpx_kwargs: Any,
    ):
        config = config or get_config()
        self._owns_db = False

        if db is None:
            path = Path(db_path or config.capture.exchange_db_path).expanduser()
            db = ExchangeDB(path, max_body_bytes=config.capture.max_body_bytes)
            self._owns_db = True
        self._db = db

        resolved = db.resolve_service_key(service_key) or service_key
        snap = db.latest_auth_snapshot(resolved)
        if require_auth and not snap:
            raise AuthMissingError(
                f"No auth snapshot available for {resolved!r}. "
                "Run the proxy and perform a logged-in request, then retry."
            )

        base_origin = origin or db.latest_origin(resolved) or ""
        if not base_origin:
            # Allow callers to pass full URLs to request() even without a base_url.
            base_origin = ""

        auth_headers: dict[str, str] = {}
        if snap:
            headers_obj: object = snap.get("headers")
            if isinstance(headers_obj, dict):
                auth_headers.update({str(k): str(v) for k, v in headers_obj.items()})

        if headers:
            auth_headers.update(headers)

        if timeout is None:
            timeout = config.defaults.timeout

        if "verify" not in httpx_kwargs:
            httpx_kwargs["verify"] = config.defaults.verify_ssl

        super().__init__(
            base_url=base_origin,
            headers=auth_headers,
            timeout=timeout,
            http2=http2,
            **httpx_kwargs,
        )

    def close(self) -> None:  # noqa: D401 (consistent with httpx)
        """Close the client (and DB if owned)."""
        try:
            super().close()
        finally:
            if getattr(self, "_owns_db", False):
                try:
                    self._db.close()
                except Exception:
                    pass
