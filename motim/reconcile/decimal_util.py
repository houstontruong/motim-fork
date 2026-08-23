"""Decimal and symbol normalization utilities for reconciliation."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def to_canonical_decimal_str(val: Any) -> str:
    """Convert an int, str, float, or Decimal into a canonical base-10 decimal string.

    Never emits scientific notation or float artifacts.
    Standardizes '0.00' and '-0' to '0'.
    Strips unnecessary trailing fractional zeros (e.g. '100.5000' -> '100.5').
    """
    if val is None:
        raise ValueError("Cannot convert None to decimal")

    if isinstance(val, bool):
        raise ValueError("Boolean values are not valid decimals")

    try:
        if isinstance(val, (int, str)):
            d = Decimal(str(val).strip())
        elif isinstance(val, Decimal):
            d = val
        elif isinstance(val, float):
            d = Decimal(str(val))
        else:
            d = Decimal(str(val).strip())
    except (InvalidOperation, TypeError) as e:
        raise ValueError(f"Invalid decimal value: {val!r}") from e

    # Format without scientific notation
    s = f"{d:f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
        if not s or s == "-0":
            s = "0"
    elif s == "-0":
        s = "0"
    return s


def normalize_asset(asset: str | None) -> str:
    """Standardize asset or currency codes to uppercase strings."""
    if not asset:
        return ""
    return str(asset).strip().upper()
