"""Input validation and secret rejection for motim.sanitized_exchange.v1."""

from __future__ import annotations

import math
import re
from datetime import datetime
from decimal import Decimal
from typing import Any

from collections.abc import Mapping, Sequence, Set

from .models import SCHEMA_VERSION_INPUT

RFC3339_Z_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

# Auth-shaped keywords to reject in keys
AUTH_KEY_PATTERNS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "bearer",
    "jwt",
    "apikey",
    "api_key",
    "private_key",
    "access_token",
    "auth_token",
    "sec_websocket_key",
    "sec-websocket-key",
    "client_secret",
)

# JWT / Canary / Secret value patterns
BEARER_PATTERN = re.compile(r"^Bearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE)
JWT_PATTERN = re.compile(r"^ey[A-Za-z0-9_-]{6,}\.ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")

ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "exchange_id", "provider", "captured_at", "request", "response"}
)

ALLOWED_REQUEST_KEYS = frozenset({"method", "route_key"})
ALLOWED_RESPONSE_KEYS = frozenset({"status", "content_type", "body"})


class ValidationError(Exception):
    """Raised when an input record fails validation."""

    def __init__(self, message: str, code: str = "invalid_input", exchange_id: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.exchange_id = exchange_id


def parse_rfc3339_z(ts: str) -> datetime:
    """Parse an RFC3339 UTC timestamp with trailing Z.

    Raises ValueError if format is invalid.
    """
    if not isinstance(ts, str) or not RFC3339_Z_REGEX.match(ts):
        raise ValueError("Timestamp must be an RFC3339 UTC string ending in 'Z'")
    # Remove 'Z' and parse as UTC
    return datetime.fromisoformat(ts[:-1] + "+00:00")


def contains_auth_elements(val: Any) -> bool:
    """Recursively check for auth-shaped field names or secret values in a structure."""
    if isinstance(val, (dict, Mapping)):
        for k, v in val.items():
            k_norm = str(k).lower().replace("-", "").replace("_", "")
            for pattern in AUTH_KEY_PATTERNS:
                pat_norm = pattern.replace("-", "").replace("_", "")
                if pat_norm in k_norm:
                    return True
            if contains_auth_elements(k) or contains_auth_elements(v):
                return True
    elif isinstance(val, (list, tuple, set, frozenset, Sequence, Set)) and not isinstance(val, (str, bytes, bytearray)):
        for item in val:
            if contains_auth_elements(item):
                return True
    elif isinstance(val, (bytes, bytearray)):
        try:
            s = val.decode("utf-8", errors="replace").strip()
            if BEARER_PATTERN.match(s) or JWT_PATTERN.match(s):
                return True
            s_lower = s.lower()
            if "canary" in s_lower and any(kw in s_lower for kw in ("token", "secret", "cookie", "key")):
                return True
        except Exception:
            pass
    elif isinstance(val, str):
        s = val.strip()
        if BEARER_PATTERN.match(s) or JWT_PATTERN.match(s):
            return True
        # Check for canary tokens or explicit secret patterns
        s_lower = s.lower()
        if "canary" in s_lower and any(kw in s_lower for kw in ("token", "secret", "cookie", "key")):
            return True
    return False


def contains_non_finite_values(val: Any) -> bool:
    """Recursively check for non-finite float or Decimal values."""
    if isinstance(val, (dict, Mapping)):
        for k, v in val.items():
            if contains_non_finite_values(k) or contains_non_finite_values(v):
                return True
    elif isinstance(val, (list, tuple, set, frozenset, Sequence, Set)) and not isinstance(val, (str, bytes, bytearray)):
        for item in val:
            if contains_non_finite_values(item):
                return True
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            return True
    elif isinstance(val, Decimal):
        if not val.is_finite():
            return True
    return False


def validate_sanitized_exchange(
    exchange: dict[str, Any],
    expected_provider: str,
    *,
    strict: bool = True,
    seen_exchange_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Validate a single sanitized exchange dictionary against motim.sanitized_exchange.v1.

    Returns the validated exchange dict on success.
    Raises ValidationError on violation.
    """
    if not isinstance(exchange, dict):
        raise ValidationError("Exchange record must be a JSON object")

    # 1. Secret / Auth Check
    if contains_auth_elements(exchange):
        ex_id = exchange.get("exchange_id") if isinstance(exchange.get("exchange_id"), str) else None
        raise ValidationError(
            "Rejected input containing auth-shaped field [REDACTED]",
            code="auth_field_detected",
            exchange_id=ex_id,
        )

    # 2. Non-Finite Numeric Check
    if contains_non_finite_values(exchange):
        ex_id = exchange.get("exchange_id") if isinstance(exchange.get("exchange_id"), str) else None
        raise ValidationError(
            "Rejected input containing non-finite numeric value [REDACTED]",
            code="invalid_input",
            exchange_id=ex_id,
        )

    # 2. Strict Mode Top-Level Keys
    if strict:
        unknown_keys = set(exchange.keys()) - ALLOWED_TOP_LEVEL_KEYS
        if unknown_keys:
            raise ValidationError(
                f"Unknown top-level field(s) in strict mode: {sorted(unknown_keys)}",
                code="invalid_input",
                exchange_id=exchange.get("exchange_id"),
            )

    # 3. Schema Version
    schema_version = exchange.get("schema_version")
    if schema_version != SCHEMA_VERSION_INPUT:
        raise ValidationError(
            f"Invalid schema_version: expected '{SCHEMA_VERSION_INPUT}', got {schema_version!r}",
            code="invalid_input",
            exchange_id=exchange.get("exchange_id"),
        )

    # 4. Exchange ID
    ex_id = exchange.get("exchange_id")
    if not isinstance(ex_id, str) or not ex_id.strip():
        raise ValidationError(
            "Missing or empty exchange_id",
            code="invalid_input",
            exchange_id=None,
        )
    if seen_exchange_ids is not None:
        if ex_id in seen_exchange_ids:
            raise ValidationError(
                f"Duplicate exchange_id '{ex_id}' within input",
                code="invalid_input",
                exchange_id=ex_id,
            )
        seen_exchange_ids.add(ex_id)

    # 5. Provider
    provider = exchange.get("provider")
    if provider not in ("bybit", "lighter"):
        raise ValidationError(
            f"Invalid provider '{provider}', must be 'bybit' or 'lighter'",
            code="invalid_input",
            exchange_id=ex_id,
        )
    if provider != expected_provider:
        raise ValidationError(
            f"Exchange provider '{provider}' does not match requested provider '{expected_provider}'",
            code="invalid_input",
            exchange_id=ex_id,
        )

    # 6. Captured At
    captured_at = exchange.get("captured_at")
    if not isinstance(captured_at, str):
        raise ValidationError(
            "Missing or invalid captured_at (must be RFC3339 string)",
            code="invalid_input",
            exchange_id=ex_id,
        )
    try:
        parse_rfc3339_z(captured_at)
    except Exception as e:
        raise ValidationError(
            f"captured_at must be RFC3339 UTC with 'Z': {e}",
            code="invalid_input",
            exchange_id=ex_id,
        ) from e

    # 7. Request
    req = exchange.get("request")
    if not isinstance(req, dict):
        raise ValidationError(
            "Missing or invalid 'request' object",
            code="invalid_input",
            exchange_id=ex_id,
        )
    if strict:
        unknown_req = set(req.keys()) - ALLOWED_REQUEST_KEYS
        if unknown_req:
            raise ValidationError(
                f"Request contains forbidden or unknown field(s): {sorted(unknown_req)}",
                code="invalid_input",
                exchange_id=ex_id,
            )
    method = req.get("method")
    if not isinstance(method, str) or not method.strip():
        raise ValidationError(
            "Missing or invalid request.method",
            code="invalid_input",
            exchange_id=ex_id,
        )
    route_key = req.get("route_key")
    if not isinstance(route_key, str) or not route_key.strip():
        raise ValidationError(
            "Missing or invalid request.route_key",
            code="invalid_input",
            exchange_id=ex_id,
        )

    # 8. Response
    resp = exchange.get("response")
    if not isinstance(resp, dict):
        raise ValidationError(
            "Missing or invalid 'response' object",
            code="invalid_input",
            exchange_id=ex_id,
        )
    if strict:
        unknown_resp = set(resp.keys()) - ALLOWED_RESPONSE_KEYS
        if unknown_resp:
            raise ValidationError(
                f"Response contains forbidden or unknown field(s): {sorted(unknown_resp)}",
                code="invalid_input",
                exchange_id=ex_id,
            )
    status = resp.get("status")
    if type(status) is not int:
        raise ValidationError(
            "Missing or invalid response.status (must be integer)",
            code="invalid_input",
            exchange_id=ex_id,
        )
    if "body" not in resp:
        raise ValidationError(
            "Missing required response.body",
            code="invalid_input",
            exchange_id=ex_id,
        )

    return exchange
