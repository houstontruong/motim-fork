"""Normalization helpers for capture + replay.

These helpers are used to make captured data "replay safe":
- Cookie headers are stored/serialized consistently
- Paths can be templatized so captured patterns match replay requests
"""

from __future__ import annotations

import re
from typing import Mapping


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a Cookie header value into a dict.

    The correct HTTP delimiter is `;`, but some capture contexts may produce comma-separated
    pairs. We support both for robustness.
    """
    cookies: dict[str, str] = {}
    if not value:
        return cookies

    # Split on ';' first, then also split each chunk on ','.
    # This is intentionally permissive; cookie values containing commas are rare for the
    # scenarios MOTIM targets.
    parts: list[str] = []
    for chunk in value.split(";"):
        parts.extend(chunk.split(","))

    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip()
        if not key:
            continue
        cookies[key] = val.strip()

    return cookies


def format_cookie_header(cookies: Mapping[str, str]) -> str:
    """Format cookies dict into a canonical Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def templatize_path(path: str) -> str:
    """Replace likely IDs in paths with placeholders.

    Mirrors the proxy's capture-time templatization so replay requests can match captured
    endpoints (e.g. `/v1/users/123456` -> `/v1/users/{id}`).
    """
    # UUID pattern
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{id}",
        path,
        flags=re.IGNORECASE,
    )
    # Long hex strings (20+ chars)
    path = re.sub(r"/[a-f0-9]{20,}", "/{id}", path, flags=re.IGNORECASE)
    # Numeric IDs (6+ digits)
    path = re.sub(r"/\d{6,}", "/{id}", path)
    return path
