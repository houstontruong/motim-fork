"""Normalization helpers for capture and discovery.

These helpers are used to make captured data normalized and consistent:
- Cookie headers are stored/serialized consistently
- Paths can be templatized so captured patterns match endpoint templates
"""

from __future__ import annotations

import re
from typing import Mapping


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a Cookie header value into a dict.

    Cookie pairs in Cookie headers are strictly separated by ';' per RFC 6265.
    """
    cookies: dict[str, str] = {}
    if not value:
        return cookies

    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, val = chunk.split("=", 1)
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
