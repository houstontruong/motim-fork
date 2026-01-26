"""HTTP client for MOTIM with automatic auth injection.

The proxy captures auth headers and request/response samples. The client uses that
captured auth to replay requests to the real upstream APIs (it does not “reply as
a proxy”; it is a normal HTTP client with better defaults).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Final, Mapping

import httpx

from .auth import Auth
from .config import Config, get_config
from .normalize import templatize_path
from .service import Service

_DEFAULT_RETRY_STATUS_CODES: Final[set[int]] = {429, 500, 502, 503, 504}
_IDEMPOTENT_METHODS: Final[set[str]] = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}

logger = logging.getLogger(__name__)


def _parse_retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(int(value.strip()))
    except Exception:
        return None


def _backoff_seconds(attempt: int) -> float:
    # Exponential backoff with a bit of jitter, capped.
    base = min(8.0, 0.5 * (2**attempt))
    return float(base) + float(random.random()) * 0.1


class Client(httpx.Client):
    """HTTP client with automatic authentication from captured specs.

    Extends httpx.Client with:
    - Auto-loading auth from MOTIM specs
    - Profile-based header selection
    - Service-aware configuration

    Usage:
        # Simple - just works
        client = Client("notion")
        r = client.get("/v1/users/me")

        # With options
        client = Client("notion", auth_profile="full", timeout=60)

        # From Service object
        svc = Service.load("notion")
        client = Client(svc)

        # Context manager for connection pooling
        with Client("notion") as client:
            r1 = client.get("/v1/users")
            r2 = client.get("/v1/pages")
    """

    def __init__(
        self,
        service: str | Service,
        *,
        auth_profile: str | None = None,
        auth_include: list[str] | None = None,
        auth_exclude: list[str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        headers: Mapping[str, str] | None = None,
        config: Config | None = None,
        require_auth: bool = False,
        require_fresh_auth: bool = False,
        **httpx_kwargs: Any,
    ):
        """Initialize MOTIM client.

        Args:
            service: Service name (string) or Service object
            auth_profile: Header profile ('minimal', 'standard', 'full')
            timeout: Request timeout in seconds
            retries: Number of retries on failure
            headers: Additional headers to include
            config: Config instance (uses global if not provided)
            require_auth: If True, raise if no auth captured for the service
            require_fresh_auth: If True, raise if auth is missing or appears expired
            **httpx_kwargs: Additional arguments passed to httpx.Client
        """
        config = config or get_config()

        # Load service if string
        if isinstance(service, str):
            service = Service.load(service)

        self._service = service
        self._config = config

        # Get service-specific settings
        svc_settings = config.get_service_settings(service.name)

        # Determine effective settings (explicit > service > defaults)
        effective_profile = auth_profile or svc_settings.profile or config.defaults.profile
        effective_timeout = timeout or svc_settings.timeout or config.defaults.timeout

        # Store for later reference
        self._auth_profile = effective_profile
        self._retries = retries or svc_settings.retries or config.defaults.retries

        # Auth validation (optional strictness)
        if require_fresh_auth:
            service.auth.require_fresh()
        elif require_auth:
            service.auth.require_headers()
        else:
            if not service.auth:
                logger.warning(
                    "No auth captured for service '%s'. Requests may fail; run the proxy and "
                    "authenticate first.",
                    service.name,
                )
            elif service.auth.is_expired:
                logger.warning(
                    "Auth for service '%s' appears expired. Re-authenticate with the proxy "
                    "running if requests fail.",
                    service.name,
                )

        # Build headers from auth (optionally include/exclude for dynamic headers)
        auth_headers = service.auth.to_headers(
            profile=effective_profile,
            include=auth_include,
            exclude=auth_exclude,
        )

        # Add service-specific extra headers
        if svc_settings.extra_headers:
            auth_headers.update(svc_settings.extra_headers)

        # Add user-provided headers (highest priority)
        if headers:
            auth_headers.update(headers)

        # Initialize httpx.Client
        # Honor config default unless explicitly provided.
        if "verify" not in httpx_kwargs:
            httpx_kwargs["verify"] = config.defaults.verify_ssl

        super().__init__(
            base_url=service.base_url,
            headers=auth_headers,
            timeout=effective_timeout,
            **httpx_kwargs,
        )

    @property
    def service(self) -> Service:
        """The Service this client is configured for."""
        return self._service

    @property
    def motim_auth(self) -> Auth:
        """The MOTIM Auth credentials being used."""
        return self._service.auth

    @property
    def auth(self) -> Auth:  # type: ignore[override,misc]
        """Alias for `motim_auth`.

        Note: `httpx.Client` uses `auth` for its request authentication machinery.
        This property is provided for MOTIM convenience; prefer `motim_auth` in typed code.
        """
        return self._service.auth

    @property
    def auth_profile(self) -> str:
        """The header profile being used."""
        return self._auth_profile

    def request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        """Make a request with basic retry support.

        Retries are controlled by `retries` passed to the constructor or config defaults.
        Only idempotent methods are retried on retryable status codes (e.g. 429/5xx).
        All methods may be retried on transport errors.
        """
        retries = max(0, int(self._retries or 0))
        method_upper = method.upper()

        # If we have per-endpoint base URLs, prefer them (supports services spanning subdomains).
        if isinstance(url, str) and url.startswith("/"):
            path_only = url.split("?", 1)[0]
            templ = templatize_path(path_only)
            key = f"{method_upper} {templ}"
            base = self._service.endpoint_base_urls.get(key)
            if base:
                url = base + url

        for attempt in range(retries + 1):
            try:
                resp = super().request(method, url, **kwargs)
            except httpx.RequestError:
                if attempt >= retries:
                    raise
                time.sleep(_backoff_seconds(attempt))
                continue

            if attempt < retries and method_upper in _IDEMPOTENT_METHODS:
                if resp.status_code in _DEFAULT_RETRY_STATUS_CODES:
                    retry_after = _parse_retry_after_seconds(resp.headers.get("retry-after"))
                    resp.close()
                    time.sleep(
                        retry_after if retry_after is not None else _backoff_seconds(attempt)
                    )
                    continue

            return resp

        # Should be unreachable, but keep type-checkers happy.
        return super().request(method, url, **kwargs)


class AsyncClient(httpx.AsyncClient):
    """Async HTTP client with automatic authentication from captured specs.

    Same as Client but for async usage:

        async with AsyncClient("notion") as client:
            r = await client.get("/v1/users/me")
    """

    def __init__(
        self,
        service: str | Service,
        *,
        auth_profile: str | None = None,
        auth_include: list[str] | None = None,
        auth_exclude: list[str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        headers: Mapping[str, str] | None = None,
        config: Config | None = None,
        require_auth: bool = False,
        require_fresh_auth: bool = False,
        **httpx_kwargs: Any,
    ):
        """Initialize async MOTIM client.

        Args:
            service: Service name (string) or Service object
            auth_profile: Header profile ('minimal', 'standard', 'full')
            timeout: Request timeout in seconds
            retries: Number of retries on failure
            headers: Additional headers to include
            config: Config instance (uses global if not provided)
            require_auth: If True, raise if no auth captured for the service
            require_fresh_auth: If True, raise if auth is missing or appears expired
            **httpx_kwargs: Additional arguments passed to httpx.AsyncClient
        """
        config = config or get_config()

        # Load service if string
        if isinstance(service, str):
            service = Service.load(service)

        self._service = service
        self._config = config

        # Get service-specific settings
        svc_settings = config.get_service_settings(service.name)

        # Determine effective settings
        effective_profile = auth_profile or svc_settings.profile or config.defaults.profile
        effective_timeout = timeout or svc_settings.timeout or config.defaults.timeout

        self._auth_profile = effective_profile
        self._retries = retries or svc_settings.retries or config.defaults.retries

        if require_fresh_auth:
            service.auth.require_fresh()
        elif require_auth:
            service.auth.require_headers()
        else:
            if not service.auth:
                logger.warning(
                    "No auth captured for service '%s'. Requests may fail; run the proxy and "
                    "authenticate first.",
                    service.name,
                )
            elif service.auth.is_expired:
                logger.warning(
                    "Auth for service '%s' appears expired. Re-authenticate with the proxy "
                    "running if requests fail.",
                    service.name,
                )

        # Build headers (optionally include/exclude for dynamic headers)
        auth_headers = service.auth.to_headers(
            profile=effective_profile,
            include=auth_include,
            exclude=auth_exclude,
        )

        if svc_settings.extra_headers:
            auth_headers.update(svc_settings.extra_headers)

        if headers:
            auth_headers.update(headers)

        if "verify" not in httpx_kwargs:
            httpx_kwargs["verify"] = config.defaults.verify_ssl

        super().__init__(
            base_url=service.base_url,
            headers=auth_headers,
            timeout=effective_timeout,
            **httpx_kwargs,
        )

    @property
    def service(self) -> Service:
        """The Service this client is configured for."""
        return self._service

    @property
    def motim_auth(self) -> Auth:
        """The MOTIM Auth credentials being used."""
        return self._service.auth

    @property
    def auth(self) -> Auth:  # type: ignore[override,misc]
        """Alias for `motim_auth`. See `Client.auth` for caveats."""
        return self._service.auth

    @property
    def auth_profile(self) -> str:
        """The header profile being used."""
        return self._auth_profile

    async def request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        """Make a request with basic retry support.

        See `Client.request()` for retry semantics.
        """
        retries = max(0, int(self._retries or 0))
        method_upper = method.upper()

        if isinstance(url, str) and url.startswith("/"):
            path_only = url.split("?", 1)[0]
            templ = templatize_path(path_only)
            key = f"{method_upper} {templ}"
            base = self._service.endpoint_base_urls.get(key)
            if base:
                url = base + url

        for attempt in range(retries + 1):
            try:
                resp = await super().request(method, url, **kwargs)
            except httpx.RequestError:
                if attempt >= retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue

            if attempt < retries and method_upper in _IDEMPOTENT_METHODS:
                if resp.status_code in _DEFAULT_RETRY_STATUS_CODES:
                    retry_after = _parse_retry_after_seconds(resp.headers.get("retry-after"))
                    await resp.aclose()
                    await asyncio.sleep(
                        retry_after if retry_after is not None else _backoff_seconds(attempt)
                    )
                    continue

            return resp

        return await super().request(method, url, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────────────────


def request(
    service: str | Service,
    method: str,
    path: str,
    *,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a one-off HTTP request.

    Prefer passing `client_kwargs=` (Client constructor args) and
    `request_kwargs=` (httpx request args) for clarity.
    For backward compatibility, if `**kwargs` is provided and neither dict is provided,
    kwargs are treated as client kwargs.
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")

    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})

    # Back-compat: old helpers treated **kwargs as Client kwargs.
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)

    with Client(service, **effective_client_kwargs) as client:
        return client.request(method, path, **effective_request_kwargs)


def get(
    service: str | Service,
    path: str,
    *,
    params: Mapping[str, Any] | None = None,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a GET request.

    Convenience function for one-off requests.

    Args:
        service: Service name or Service object
        path: URL path
        params: Query parameters
        client_kwargs: Arguments passed to Client
        request_kwargs: Arguments passed to httpx request (e.g. headers, timeout)
        **kwargs: Backward-compatible alias for client kwargs (do not mix with the dict args)

    Returns:
        httpx.Response
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")
    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)
    if params is not None:
        if "params" in effective_request_kwargs:
            raise TypeError("Do not pass both params= and request_kwargs['params'].")
        effective_request_kwargs["params"] = params
    with Client(service, **effective_client_kwargs) as client:
        return client.get(path, **effective_request_kwargs)


def post(
    service: str | Service,
    path: str,
    *,
    json: Any | None = None,
    data: Mapping[str, Any] | None = None,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a POST request.

    Args:
        service: Service name or Service object
        path: URL path
        json: JSON body
        data: Form data
        client_kwargs: Arguments passed to Client
        request_kwargs: Arguments passed to httpx request (e.g. headers, timeout)
        **kwargs: Backward-compatible alias for client kwargs (do not mix with the dict args)

    Returns:
        httpx.Response
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")
    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)
    if json is not None:
        if "json" in effective_request_kwargs:
            raise TypeError("Do not pass both json= and request_kwargs['json'].")
        effective_request_kwargs["json"] = json
    if data is not None:
        if "data" in effective_request_kwargs:
            raise TypeError("Do not pass both data= and request_kwargs['data'].")
        effective_request_kwargs["data"] = data
    with Client(service, **effective_client_kwargs) as client:
        return client.post(path, **effective_request_kwargs)


def put(
    service: str | Service,
    path: str,
    *,
    json: Any | None = None,
    data: Mapping[str, Any] | None = None,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a PUT request.

    Args:
        service: Service name or Service object
        path: URL path
        json: JSON body
        data: Form data
        **kwargs: Additional arguments passed to Client

    Returns:
        httpx.Response
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")
    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)
    if json is not None:
        if "json" in effective_request_kwargs:
            raise TypeError("Do not pass both json= and request_kwargs['json'].")
        effective_request_kwargs["json"] = json
    if data is not None:
        if "data" in effective_request_kwargs:
            raise TypeError("Do not pass both data= and request_kwargs['data'].")
        effective_request_kwargs["data"] = data
    with Client(service, **effective_client_kwargs) as client:
        return client.put(path, **effective_request_kwargs)


def delete(
    service: str | Service,
    path: str,
    *,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a DELETE request.

    Args:
        service: Service name or Service object
        path: URL path
        **kwargs: Additional arguments passed to Client

    Returns:
        httpx.Response
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")
    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)
    with Client(service, **effective_client_kwargs) as client:
        return client.delete(path, **effective_request_kwargs)


def patch(
    service: str | Service,
    path: str,
    *,
    json: Any | None = None,
    data: Mapping[str, Any] | None = None,
    client_kwargs: Mapping[str, Any] | None = None,
    request_kwargs: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Make a PATCH request.

    Args:
        service: Service name or Service object
        path: URL path
        json: JSON body
        data: Form data
        **kwargs: Additional arguments passed to Client

    Returns:
        httpx.Response
    """
    if kwargs and (client_kwargs is not None or request_kwargs is not None):
        raise TypeError("Use either (**kwargs) or (client_kwargs/request_kwargs), not both.")
    effective_client_kwargs = dict(client_kwargs or {})
    effective_request_kwargs = dict(request_kwargs or {})
    if kwargs and not effective_client_kwargs and not effective_request_kwargs:
        effective_client_kwargs = dict(kwargs)
    if json is not None:
        if "json" in effective_request_kwargs:
            raise TypeError("Do not pass both json= and request_kwargs['json'].")
        effective_request_kwargs["json"] = json
    if data is not None:
        if "data" in effective_request_kwargs:
            raise TypeError("Do not pass both data= and request_kwargs['data'].")
        effective_request_kwargs["data"] = data
    with Client(service, **effective_client_kwargs) as client:
        return client.patch(path, **effective_request_kwargs)
