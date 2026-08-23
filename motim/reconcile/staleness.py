"""Deterministic staleness calculation for reconciliation facts."""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from .models import Fact, Issue, IssueCode, Severity
from .validator import parse_rfc3339_z


def check_staleness(
    facts: Sequence[Fact],
    as_of: str | datetime,
    max_age_seconds: int = 0,
) -> list[Issue]:
    """Evaluate staleness of facts relative to as_of timestamp.

    A fact is stale when (as_of - observed_at) > max_age_seconds.
    Stale facts are flagged with an issue but NOT dropped.
    """
    if isinstance(as_of, str):
        as_of_dt = parse_rfc3339_z(as_of)
    elif isinstance(as_of, datetime):
        as_of_dt = as_of
    else:
        raise ValueError("as_of must be an RFC3339 string or datetime instance")

    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        raise ValueError("max_age_seconds must be a non-negative integer")

    issues: list[Issue] = []
    for fact in facts:
        fact_dt = parse_rfc3339_z(fact.observed_at)
        age_seconds = (as_of_dt - fact_dt).total_seconds()
        if age_seconds > max_age_seconds:
            issues.append(
                Issue(
                    code=IssueCode.STALE_FACT.value,
                    provider=fact.provider,
                    source_exchange_id=fact.source_exchange_ids[0] if fact.source_exchange_ids else None,
                    severity=Severity.WARNING.value,
                    message=(
                        f"Fact '{fact.fact_id}' observed at {fact.observed_at} "
                        f"exceeds max age of {max_age_seconds}s (age: {age_seconds:g}s)"
                    ),
                )
            )

    return issues
