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
    "passphrase",
    "signature",
    "session",
    "credential",
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
    "auth",
    "authentication",
    "nonce",
)

# JWT / Canary / Secret value patterns
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
JWT_PATTERN = re.compile(r"ey[A-Za-z0-9_-]{6,}\.ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")

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


def _unquote_plus(s: Any) -> str:
    """Pure-Python URL unquoting without importing urllib (ensuring offline reconciliation contract)."""
    raw = str(s)
    if "%" not in raw and "+" not in raw:
        return raw
    raw = raw.replace("+", " ")
    parts = raw.split("%")
    if len(parts) == 1:
        return raw
    res = bytearray()
    res.extend(parts[0].encode("utf-8", errors="replace"))
    for item in parts[1:]:
        if len(item) >= 2:
            try:
                hex_byte = int(item[:2], 16)
                res.append(hex_byte)
                res.extend(item[2:].encode("utf-8", errors="replace"))
            except ValueError:
                res.append(ord("%"))
                res.extend(item.encode("utf-8", errors="replace"))
        else:
            res.append(ord("%"))
            res.extend(item.encode("utf-8", errors="replace"))
    return res.decode("utf-8", errors="replace")


def _has_percent_encoding(s: str) -> bool:
    """Check if string contains valid percent-encoded triples %XX."""
    if "%" not in s:
        return False
    parts = s.split("%")
    for p in parts[1:]:
        if len(p) >= 2:
            try:
                int(p[:2], 16)
                return True
            except ValueError:
                pass
    return False


def _fully_unquote_plus(s: Any, max_rounds: int | None = None) -> str:
    """Iteratively unquote percent-encoded characters until true fixpoint.

    A bounded decode limit derived from input length prevents runaway loops while
    reliably resolving arbitrary multi-layer nested percent-encodings.
    """
    raw = str(s)
    if "%" not in raw and "+" not in raw:
        return raw
    limit = max_rounds if max_rounds is not None else max(64, len(raw))
    for _ in range(limit):
        if "%" not in raw and "+" not in raw:
            break
        unq = _unquote_plus(raw)
        if unq == raw:
            break
        raw = unq
    return raw


def _normalize_key_name(k: Any) -> str:
    """Normalize a key name by iteratively unquoting percent-encoded characters, lowercasing, and stripping hyphens/underscores."""
    s = _fully_unquote_plus(k)
    return s.lower().replace("-", "").replace("_", "")


def _is_auth_string(raw: str) -> bool:
    s_raw = raw.strip()
    if not s_raw:
        return False

    s_unq = _fully_unquote_plus(s_raw).strip()

    # Fail closed on unresolved percent encoding after bounded decode
    if _has_percent_encoding(s_unq):
        return True

    # 1. Bearer / JWT on raw or iteratively decoded strings
    for candidate in (s_raw, s_unq):
        if BEARER_PATTERN.search(candidate) or JWT_PATTERN.search(candidate):
            return True

    # 2. Canary checks across raw and decoded forms
    for text_to_check in (s_raw.lower(), s_unq.lower()):
        if "canary" in text_to_check and any(
            kw in text_to_check
            for kw in (
                "token",
                "secret",
                "cookie",
                "key",
                "signature",
                "session",
                "credential",
                "passphrase",
                "auth",
                "nonce",
            )
        ):
            return True

    # 3. Check for URL userinfo credentials (e.g. user:pass@host or token@host or api%5Fkey@host)
    for candidate in (s_raw, s_unq):
        if "@" in candidate:
            prefix = candidate.split("@", 1)[0]
            userinfo = prefix.split("://")[-1].split("/")[-1]
            if userinfo:
                userinfo_norm = _normalize_key_name(userinfo)
                if ":" in userinfo:
                    return True
                for pattern in AUTH_KEY_PATTERNS:
                    pat_norm = pattern.replace("-", "").replace("_", "")
                    if pat_norm in userinfo_norm:
                        return True

    # 4. Check for URL query / form-shaped / fragment credentials across raw and fully unquoted strings
    segments_to_check: list[str] = []
    for candidate in (s_raw, s_unq):
        if "?" in candidate:
            q_part = candidate.split("?", 1)[1]
            if "#" in q_part:
                q_core, frag = q_part.split("#", 1)
                segments_to_check.append(q_core)
                segments_to_check.append(frag)
            else:
                segments_to_check.append(q_part)

        if "#" in candidate and not ("?" in candidate and "#" in candidate.split("?", 1)[1]):
            frag = candidate.split("#", 1)[1]
            segments_to_check.append(frag)

        if "=" in candidate:
            segments_to_check.append(candidate)

    for segment in segments_to_check:
        if "=" in segment:
            pairs = [p for p in segment.replace(";", "&").split("&") if "=" in p]
            for pair in pairs:
                k, _, v = pair.partition("=")
                k_norm = _normalize_key_name(k)
                for pattern in AUTH_KEY_PATTERNS:
                    pat_norm = pattern.replace("-", "").replace("_", "")
                    if pat_norm in k_norm:
                        return True
                v_unq = _fully_unquote_plus(v) if v else ""
                for val_check in (v, v_unq):
                    if val_check and (
                        BEARER_PATTERN.search(val_check)
                        or JWT_PATTERN.search(val_check)
                        or (
                            "canary" in val_check.lower()
                            and any(
                                kw in val_check.lower()
                                for kw in (
                                    "token",
                                    "secret",
                                    "cookie",
                                    "key",
                                    "signature",
                                    "session",
                                    "credential",
                                    "passphrase",
                                    "auth",
                                    "nonce",
                                )
                            )
                        )
                    ):
                        return True
        else:
            seg_norm = _normalize_key_name(segment)
            for pattern in AUTH_KEY_PATTERNS:
                pat_norm = pattern.replace("-", "").replace("_", "")
                if pat_norm in seg_norm:
                    return True
            seg_unq = _fully_unquote_plus(segment)
            if BEARER_PATTERN.search(seg_unq) or JWT_PATTERN.search(seg_unq) or (
                "canary" in seg_unq.lower() and any(kw in seg_unq.lower() for kw in ("token", "secret", "key", "auth", "nonce"))
            ):
                return True

    return False


def contains_auth_elements(val: Any) -> bool:
    """Recursively check for auth-shaped field names or secret values in a structure."""
    if isinstance(val, (dict, Mapping)):
        for k, v in val.items():
            k_norm = _normalize_key_name(k)
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
            if _is_auth_string(s):
                return True
        except Exception:
            pass
    elif isinstance(val, str):
        if _is_auth_string(val):
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
    normalized_method = method.strip().upper()
    if normalized_method != "GET":
        raise ValidationError(
            f"Invalid request.method '{method}': only 'GET' is accepted for account-read reconciliation",
            code="invalid_input",
            exchange_id=ex_id,
        )
    req["method"] = normalized_method
    route_key = req.get("route_key")
    if not isinstance(route_key, str) or not route_key.strip():
        raise ValidationError(
            "Missing or invalid request.route_key",
            code="invalid_input",
            exchange_id=ex_id,
        )
    if _is_auth_string(route_key):
        raise ValidationError(
            "Rejected input containing auth-shaped field [REDACTED]",
            code="auth_field_detected",
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
