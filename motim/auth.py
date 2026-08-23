"""Authentication credential and scheme metadata management for MOTIM (Production-Safe).

All credential values are strictly redacted. Auth exposes only scheme metadata,
header names, cookie names, and expiration metadata for agent inspection without
enabling request replay.
"""

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

REDACTED_PLACEHOLDER = "[REDACTED]"


@dataclass
class Auth:
    """Manages authentication scheme metadata extracted from captured traffic.

    Provides read-only inspection of detected authentication schemes:
    - Auth type detection ('bearer', 'api_key', 'cookie', 'basic', 'custom', 'none')
    - Header names and cookie names seen in traffic
    - Irreversibly redacted header and cookie placeholders
    - Expiration metadata (when determinable)
    """

    _header_names: list[str] = field(default_factory=list)
    _cookie_names: list[str] = field(default_factory=list)
    _headers: dict[str, str] = field(default_factory=dict)
    _cookies: dict[str, str] = field(default_factory=dict)
    _last_seen: datetime | None = None
    _type_hint: str | None = None
    _jwt_exp: datetime | None = None
    _jwt_payload_data: dict[str, Any] | None = None
    _config: Config = field(default_factory=get_config)

    def __post_init__(self) -> None:
        if self._headers and not self._header_names:
            self._header_names = list(self._headers.keys())
        if self._cookies and not self._cookie_names:
            self._cookie_names = list(self._cookies.keys())
        for k, v in list(self._headers.items()):
            if k.lower() == "authorization" and not self._type_hint:
                v_str = str(v).lower()
                if v_str.startswith("basic "):
                    self._type_hint = "basic"
                elif v_str.startswith("bearer "):
                    self._type_hint = "bearer"
            if k.lower() == "cookie" and not self._cookies and isinstance(v, str):
                parsed = parse_cookie_header(v)
                self._cookies = {ck: REDACTED_PLACEHOLDER for ck in parsed.keys()}
                self._cookie_names = list(parsed.keys())

    @classmethod
    def from_spec(cls, spec: dict[str, Any], config: Config | None = None) -> Auth:
        """Create Auth from a spec dictionary safely."""
        auth_data = spec.get("auth") if isinstance(spec, dict) else None
        if not isinstance(auth_data, dict):
            if isinstance(auth_data, str) and auth_data:
                return cls(
                    _headers={"Authorization": REDACTED_PLACEHOLDER},
                    _header_names=["Authorization"],
                    _type_hint="bearer" if "bearer" in auth_data.lower() else "custom",
                    _config=config or get_config(),
                )
            auth_data = {}

        headers_data = auth_data.get("headers")
        if not isinstance(headers_data, dict):
            headers_data = {}

        cookies_data = auth_data.get("cookies")
        if not isinstance(cookies_data, (dict, list)):
            cookies_data = {}

        type_hint = auth_data.get("type") if isinstance(auth_data.get("type"), str) else None

        header_names: list[str] = []
        headers: dict[str, str] = {}
        for k, v in headers_data.items():
            k_str = str(k)
            header_names.append(k_str)
            headers[k_str] = REDACTED_PLACEHOLDER
            if not type_hint:
                v_str = str(v).lower()
                if v_str.startswith("basic "):
                    type_hint = "basic"
                elif v_str.startswith("bearer ") or k_str.lower() == "authorization":
                    type_hint = "bearer"

        if "header" in auth_data:
            h_name = str(auth_data["header"])
            if h_name not in header_names:
                header_names.append(h_name)
            headers[h_name] = REDACTED_PLACEHOLDER


        cookie_names: list[str] = []
        cookies: dict[str, str] = {}
        if isinstance(cookies_data, dict):
            for k in cookies_data.keys():
                c_str = str(k)
                cookie_names.append(c_str)
                cookies[c_str] = REDACTED_PLACEHOLDER
        elif isinstance(cookies_data, list):
            for k in cookies_data:
                c_str = str(k)
                cookie_names.append(c_str)
                cookies[c_str] = REDACTED_PLACEHOLDER

        # Derive cookie names from Cookie header if not stored separately
        if not cookie_names and headers:
            for k in headers.keys():
                if k.lower() == "cookie":
                    raw_val = headers_data.get(k, "")
                    if isinstance(raw_val, str) and raw_val and raw_val != REDACTED_PLACEHOLDER:
                        parsed = parse_cookie_header(raw_val)
                        for c_k in parsed.keys():
                            if c_k not in cookie_names:
                                cookie_names.append(c_k)
                                cookies[c_k] = REDACTED_PLACEHOLDER
                    break

        last_seen = None
        if "last_seen" in auth_data and isinstance(auth_data["last_seen"], str):
            try:
                last_seen = datetime.fromisoformat(auth_data["last_seen"])
            except (ValueError, TypeError):
                pass

        # Inspect JWT claims for expiration if present in raw auth headers before redaction
        jwt_exp = None
        jwt_payload = None
        for k, v in headers_data.items():
            if isinstance(v, str) and str(k).lower() == "authorization" and v.lower().startswith("bearer "):
                raw_token = v[7:].strip()
                if cls._is_jwt(raw_token):
                    jwt_payload = cls._decode_jwt_payload(raw_token)
                    if jwt_payload and "exp" in jwt_payload:
                        try:
                            jwt_exp = datetime.fromtimestamp(jwt_payload["exp"])
                        except (ValueError, TypeError, OverflowError):
                            pass

        return cls(
            _header_names=header_names,
            _cookie_names=cookie_names,
            _headers=headers,
            _cookies=cookies,
            _last_seen=last_seen,
            _type_hint=type_hint,
            _jwt_exp=jwt_exp,
            _jwt_payload_data=jwt_payload,
            _config=config or get_config(),
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Redacted Access
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def headers(self) -> dict[str, str]:
        """All captured auth-related headers with values strictly redacted."""
        return dict(self._headers)

    @property
    def header_names(self) -> list[str]:
        """List of observed authentication header names."""
        return list(self._header_names)

    @property
    def cookie_names(self) -> list[str]:
        """List of observed cookie names."""
        return list(self._cookie_names)

    def require_headers(self) -> None:
        """Require that some authentication has been captured.

        Raises:
            AuthMissingError: if no headers are available.
        """
        if not self._headers and not self._header_names:
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
        """Get a specific header value placeholder (case-insensitive).

        Args:
            name: Header name to look up
            default: Value to return if not found

        Returns:
            Redacted header value placeholder or default
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
    # Token & Scheme Inspection (Redacted / Metadata Only)
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def bearer_token(self) -> str | None:
        """Indicate presence of Bearer token without exposing the secret.

        Returns:
            '[REDACTED]' if bearer auth was observed, else None.
        """
        for k, v in self._headers.items():
            if k.lower() == "authorization":
                val = str(v).lower()
                if val.startswith("basic "):
                    return None
                return REDACTED_PLACEHOLDER
        if self.type == "bearer":
            return REDACTED_PLACEHOLDER
        return None

    @property
    def api_key(self) -> str | None:
        """Indicate presence of API Key without exposing the secret.

        Returns:
            '[REDACTED]' if API key header was observed, else None.
        """
        names_lower = [h.lower() for h in self._header_names]
        if any(any(sub in k for sub in ("api-key", "apikey", "x-api-key")) for k in names_lower):
            return REDACTED_PLACEHOLDER
        if self.type == "api_key":
            return REDACTED_PLACEHOLDER
        return None

    @property
    def basic_credentials(self) -> tuple[str, str] | None:
        """Indicate presence of Basic credentials without exposing secrets.

        Returns:
            ('[REDACTED]', '[REDACTED]') if Basic auth was observed, else None.
        """
        if self.type == "basic":
            return (REDACTED_PLACEHOLDER, REDACTED_PLACEHOLDER)
        for k, v in self._headers.items():
            if k.lower() == "authorization" and str(v).lower().startswith("basic "):
                return (REDACTED_PLACEHOLDER, REDACTED_PLACEHOLDER)
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Cookie Access (Redacted / Names Only)
    # ─────────────────────────────────────────────────────────────────────────

    @property
    def cookies(self) -> dict[str, str]:
        """Parsed cookie dictionary with all values redacted."""
        return dict(self._cookies)

    def cookie(self, name: str, default: str | None = None) -> str | None:
        """Get a specific cookie value placeholder.

        Args:
            name: Cookie name
            default: Value to return if not found

        Returns:
            Redacted cookie value or default
        """
        return self._cookies.get(name, default)

    @property
    def cookie_header(self) -> str:
        """Get the Cookie header string with all values redacted."""
        if not self._cookies:
            return ""
        return format_cookie_header(self._cookies)

    @property
    def type(self) -> str:
        """Detect primary authentication type."""
        if self._type_hint and self._type_hint != "none":
            return self._type_hint

        for k, v in self._headers.items():
            if k.lower() == "authorization":
                val = str(v).lower()
                if val.startswith("basic "):
                    return "basic"
                elif val.startswith("bearer "):
                    return "bearer"

        names_lower = [h.lower() for h in self._header_names]
        if "authorization" in names_lower:
            return "bearer"

        for k in names_lower:
            if any(sub in k for sub in ("api-key", "apikey", "x-api-key")):
                return "api_key"

        if "cookie" in names_lower or self._cookie_names or self._cookies:
            return "cookie"

        if self._headers or self._header_names:
            return "custom"

        return "none"


    @property
    def is_expired(self) -> bool:
        """Check if authentication is likely expired.

        Currently checks:
        - JWT exp claim when extracted from metadata

        Returns:
            True if auth appears expired, False otherwise
        """
        if self._jwt_exp is not None:
            return self._jwt_exp < datetime.now()
        return False

    @property
    def expires_at(self) -> datetime | None:
        """Get expiration time if determinable.

        Returns:
            Expiration datetime or None if unknown
        """
        return self._jwt_exp

    @property
    def jwt_payload(self) -> dict[str, Any] | None:
        """Return non-sensitive JWT payload metadata if available.

        Returns:
            Decoded payload dict or None
        """
        return self._jwt_payload_data

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
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            data = json.loads(decoded)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def __bool__(self) -> bool:
        """Auth is truthy if it has any header names or cookies."""
        return bool(self._headers or self._header_names or self._cookie_names)

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"Auth(type={self.type!r}, headers={len(self._headers)}, "
            f"cookies={len(self._cookies)}, last_seen={self._last_seen})"
        )

