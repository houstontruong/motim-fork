"""Authentication credential management for MOTIM."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config import Config, get_config
from .exceptions import AuthExpiredError, AuthMissingError
from .normalize import format_cookie_header, parse_cookie_header

logger = logging.getLogger(__name__)


@dataclass
class Auth:
    """Manages authentication credentials extracted from captured traffic.

    Provides multiple levels of access:
    - Raw headers dict
    - Parsed tokens (bearer, API key)
    - Parsed cookies
    - Profile-based header selection
    """

    _headers: dict[str, str] = field(default_factory=dict)
    _cookies: dict[str, str] = field(default_factory=dict)
    _last_seen: datetime | None = None
    _type_hint: str | None = None
    _config: Config = field(default_factory=get_config)

    @classmethod
    def from_spec(cls, spec: dict[str, Any], config: Config | None = None) -> Auth:
        """Create Auth from a spec dictionary."""
        auth_data = spec.get("auth", {})
        headers_data = auth_data.get("headers", {})
        cookies_data = auth_data.get("cookies", {})
        type_hint = auth_data.get("type")

        headers: dict[str, str] = {}
        if isinstance(headers_data, dict):
            headers.update({str(k): str(v) for k, v in headers_data.items()})

        # Also check single header/value format
        if "header" in auth_data and "value" in auth_data:
            headers[str(auth_data["header"])] = str(auth_data["value"])

        last_seen = None
        if "last_seen" in auth_data:
            try:
                last_seen = datetime.fromisoformat(auth_data["last_seen"])
            except (ValueError, TypeError):
                pass

        cookies: dict[str, str] = {}
        if isinstance(cookies_data, dict):
            cookies = {str(k): str(v) for k, v in cookies_data.items()}

        # Back-compat: if cookies aren't stored separately, derive them from the header.
        if not cookies and headers:
            cookie_header = None
            for k, v in headers.items():
                if k.lower() == "cookie":
                    cookie_header = v
                    break
            if isinstance(cookie_header, str):
                cookies = parse_cookie_header(cookie_header)

        return cls(
            _headers=headers,
            _cookies=cookies,
            _last_seen=last_seen,
            _type_hint=type_hint,
            _config=config or get_config(),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Raw Access
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def headers(self) -> dict[str, str]:
        """All captured auth-related headers."""
        return dict(self._headers)

    def require_headers(self) -> None:
        """Require that some authentication has been captured.

        Raises:
            AuthMissingError: if no headers are available.
        """
        if not self._headers:
            raise AuthMissingError(
                "No auth headers captured. Run the proxy, authenticate in the target service, "
                "then retry."
            )

    def require_fresh(self) -> None:
        """Require that auth exists and does not appear expired.

        Notes:
            Expiration detection is best-effort (currently JWT `exp` only).
        """
        self.require_headers()
        if self.is_expired:
            raise AuthExpiredError(
                "Captured auth appears expired. Re-authenticate in the target service with the "
                "proxy running, then retry."
            )

    def header(self, name: str, default: str | None = None) -> str | None:
        """Get a specific header value (case-insensitive).

        Args:
            name: Header name to look up
            default: Value to return if not found

        Returns:
            Header value or default
        """
        name_lower = name.lower()
        for k, v in self._headers.items():
            if k.lower() == name_lower:
                return v
        return default

    @property
    def last_seen(self) -> datetime | None:
        """When auth was last captured."""
        return self._last_seen

    # ─────────────────────────────────────────────────────────────────────────
    # Token Extraction
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def bearer_token(self) -> str | None:
        """Extract bearer token from Authorization header.

        Returns just the token value without 'Bearer ' prefix.
        """
        auth = self.header("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return None

    @property
    def api_key(self) -> str | None:
        """Extract API key from common header names."""
        for header_name in ["X-API-Key", "API-Key", "X-Api-Key", "apikey"]:
            if value := self.header(header_name):
                return value
        return None

    @property
    def basic_credentials(self) -> tuple[str, str] | None:
        """Extract username and password from Basic auth.

        Returns:
            Tuple of (username, password) or None
        """
        auth = self.header("Authorization") or ""
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
                    return (username, password)
            except Exception:
                pass
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Cookie Access
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def cookies(self) -> dict[str, str]:
        """Parse Cookie header into dictionary."""
        if self._cookies:
            return dict(self._cookies)
        cookie_str = self.header("Cookie") or ""
        return parse_cookie_header(cookie_str)

    def cookie(self, name: str, default: str | None = None) -> str | None:
        """Get a specific cookie value.

        Args:
            name: Cookie name
            default: Value to return if not found

        Returns:
            Cookie value or default
        """
        return self.cookies.get(name, default)

    @property
    def cookie_header(self) -> str:
        """Get the full Cookie header string."""
        cookies = self.cookies
        if not cookies:
            return ""
        return format_cookie_header(cookies)

    @property
    def type(self) -> str:
        """Detect primary authentication type."""
        if self._type_hint and self._type_hint != "none":
            return self._type_hint

        if self.bearer_token:
            return "bearer"

        auth = self.header("Authorization") or ""
        if auth.lower().startswith("basic "):
            return "basic"

        if self.api_key:
            return "api_key"

        if self.cookies:
            return "cookie"

        if self._headers:
            return "custom"

        return "none"

    @property
    def is_expired(self) -> bool:
        """Check if authentication is likely expired.

        Currently checks:
        - JWT exp claim in bearer token

        Returns:
            True if auth appears expired, False otherwise
        """
        token = self.bearer_token
        if token and self._is_jwt(token):
            payload = self._decode_jwt_payload(token)
            if payload and "exp" in payload:
                try:
                    exp_time = datetime.fromtimestamp(payload["exp"])
                    return exp_time < datetime.now()
                except (ValueError, TypeError, OSError):
                    pass
        return False

    @property
    def expires_at(self) -> datetime | None:
        """Get expiration time if determinable.

        Returns:
            Expiration datetime or None if unknown
        """
        token = self.bearer_token
        if token and self._is_jwt(token):
            payload = self._decode_jwt_payload(token)
            if payload and "exp" in payload:
                try:
                    return datetime.fromtimestamp(payload["exp"])
                except (ValueError, TypeError, OSError):
                    pass
        return None

    @property
    def jwt_payload(self) -> dict[str, Any] | None:
        """Decode and return JWT payload if bearer token is a JWT.

        Returns:
            Decoded payload dict or None
        """
        token = self.bearer_token
        if token and self._is_jwt(token):
            return self._decode_jwt_payload(token)
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Header Generation
    # ─────────────────────────────────────────────────────────────────────────

    def to_headers(
        self,
        profile: str | None = None,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> dict[str, str]:
        """Convert auth to headers dict for requests.

        Args:
            profile: Profile name ('minimal', 'standard', 'full') or None for default
            include: Explicit list of headers to include (overrides profile)
            exclude: Headers to exclude (applied after profile/include)

        Returns:
            Dictionary of headers to use in requests
        """
        # If explicit include list, use that
        if include is not None:
            headers = {}
            include_lower = [h.lower() for h in include]
            for k, v in self._headers.items():
                if k.lower() in include_lower:
                    headers[k] = v
        else:
            # Use profile
            profile_name = profile or self._config.defaults.profile
            header_profile = self._config.get_profile(profile_name)
            headers = {k: v for k, v in self._headers.items() if header_profile.matches(k)}

        # Apply exclusions
        if exclude:
            exclude_lower = [h.lower() for h in exclude]
            headers = {k: v for k, v in headers.items() if k.lower() not in exclude_lower}

        # Normalize Cookie header formatting if present.
        has_cookie = any(k.lower() == "cookie" for k in headers)
        if has_cookie:
            cookies = self.cookies
            if cookies:
                # Remove all variants then add canonical.
                headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
                headers["Cookie"] = format_cookie_header(cookies)

        return headers

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_jwt(token: str) -> bool:
        """Check if token looks like a JWT."""
        parts = token.split(".")
        return len(parts) == 3

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
        """Decode JWT payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            payload = parts[1]
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def __bool__(self) -> bool:
        """Auth is truthy if it has any headers."""
        return bool(self._headers)

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"Auth(type={self.type!r}, headers={len(self._headers)}, last_seen={self._last_seen})"
        )
