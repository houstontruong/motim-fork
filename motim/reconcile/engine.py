"""Core offline reconciliation engine."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .adapters import get_adapter
from .dedup import deduplicate_facts
from .models import AccountReadResult, Fact, Issue, IssueCode, Outcome, Severity
from .staleness import check_staleness
from .validator import ValidationError, parse_rfc3339_z, validate_sanitized_exchange


class DuplicateKeyError(ValueError):
    """Raised when duplicate keys are found in a JSON object."""


class NonFiniteNumericError(ValueError):
    """Raised when non-finite numeric constants (NaN, Infinity) are found in JSON."""


def _parse_pairs_rejecting_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for k, v in pairs:
        if k in res:
            raise DuplicateKeyError("Duplicate JSON key detected [REDACTED]")
        res[k] = v
    return res


def _reject_non_finite_constant(val: str) -> Any:
    raise NonFiniteNumericError("Non-finite JSON numeric constant detected [REDACTED]")


def _parse_input_exchanges(
    exchanges: list[dict[str, Any]] | Iterable[dict[str, Any]] | str | Path,
) -> tuple[list[dict[str, Any]], list[Issue]]:
    """Parse JSON Lines string, file path, or iterable of exchange dicts."""
    issues: list[Issue] = []

    if isinstance(exchanges, Path):
        try:
            content = exchanges.read_text(encoding="utf-8")
        except Exception as e:
            return [], [
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider="",
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"Failed to read input file: {e}",
                )
            ]
        return _parse_jsonl_string(content)

    if isinstance(exchanges, str):
        # Could be a file path or direct JSONL string
        # Safely distinguish without unguarded filesystem probing
        if "\n" not in exchanges and "\r" not in exchanges and not exchanges.strip().startswith("{"):
            try:
                path_candidate = Path(exchanges)
                if path_candidate.is_file():
                    try:
                        content = path_candidate.read_text(encoding="utf-8")
                        return _parse_jsonl_string(content)
                    except Exception as e:
                        return [], [
                            Issue(
                                code=IssueCode.INVALID_INPUT.value,
                                provider="",
                                source_exchange_id=None,
                                severity=Severity.ERROR.value,
                                message=f"Failed to read input file: {e}",
                            )
                        ]
            except (OSError, ValueError):
                pass
        return _parse_jsonl_string(exchanges)

    # It's an iterable / list of dicts
    records: list[dict[str, Any]] = []
    for idx, item in enumerate(exchanges):
        if not isinstance(item, dict):
            issues.append(
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider="",
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"Input item at index {idx} is not a JSON object",
                )
            )
        else:
            records.append(item)
    return records, issues


def _parse_jsonl_string(content: str) -> tuple[list[dict[str, Any]], list[Issue]]:
    records: list[dict[str, Any]] = []
    issues: list[Issue] = []

    if not content or not content.strip():
        return [], [
            Issue(
                code=IssueCode.INVALID_INPUT.value,
                provider="",
                source_exchange_id=None,
                severity=Severity.ERROR.value,
                message="Input is empty",
            )
        ]

    # Split lines without full strip to preserve original source line numbers
    lines = content.splitlines()

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(
                line,
                object_pairs_hook=_parse_pairs_rejecting_duplicates,
                parse_constant=_reject_non_finite_constant,
            )
            if not isinstance(obj, dict):
                issues.append(
                    Issue(
                        code=IssueCode.INVALID_INPUT.value,
                        provider="",
                        source_exchange_id=None,
                        severity=Severity.ERROR.value,
                        message=f"Line {line_no} is not a JSON object",
                    )
                )
            else:
                records.append(obj)
        except (DuplicateKeyError, NonFiniteNumericError) as e:
            issues.append(
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider="",
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"JSON syntax error on line {line_no}: {e}",
                )
            )
        except json.JSONDecodeError as e:
            issues.append(
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider="",
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"JSON syntax error on line {line_no}: {e}",
                )
            )
        except Exception:
            issues.append(
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider="",
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"JSON syntax error on line {line_no} [REDACTED]",
                )
            )
    return records, issues


def reconcile(
    exchanges: list[dict[str, Any]] | Iterable[dict[str, Any]] | str | Path,
    provider: str,
    *,
    as_of: str | datetime,
    max_age_seconds: int = 0,
    strict: bool = True,
) -> AccountReadResult:
    """Reconcile sanitized exchange JSON Lines into traceable account facts.

    Pure-functional, deterministic, offline-only engine. No network or clock access.
    """
    prov = provider.lower().strip()

    # Validate max_age_seconds
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, (int, float)) or max_age_seconds < 0:
        as_of_display = as_of.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(as_of, datetime) else str(as_of)
        return AccountReadResult(
            provider=prov,
            as_of=as_of_display,
            outcome=Outcome.INVALID_INPUT.value,
            facts=[],
            issues=[
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider=prov,
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"max_age_seconds must be a non-negative integer, got {max_age_seconds!r}",
                )
            ],
        )

    # Validate as_of format
    if isinstance(as_of, datetime):
        as_of_str = as_of.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(as_of, str):
        try:
            parse_rfc3339_z(as_of)
            as_of_str = as_of
        except Exception as e:
            return AccountReadResult(
                provider=prov,
                as_of=str(as_of),
                outcome=Outcome.INVALID_INPUT.value,
                facts=[],
                issues=[
                    Issue(
                        code=IssueCode.INVALID_INPUT.value,
                        provider=prov,
                        source_exchange_id=None,
                        severity=Severity.ERROR.value,
                        message=f"Invalid as_of timestamp format: {e}",
                    )
                ],
            )
    else:
        return AccountReadResult(
            provider=prov,
            as_of=str(as_of),
            outcome=Outcome.INVALID_INPUT.value,
            facts=[],
            issues=[
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider=prov,
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message="as_of must be an RFC3339 string or datetime",
                )
            ],
        )

    if prov not in ("bybit", "lighter"):
        return AccountReadResult(
            provider=prov,
            as_of=as_of_str,
            outcome=Outcome.INVALID_INPUT.value,
            facts=[],
            issues=[
                Issue(
                    code=IssueCode.INVALID_INPUT.value,
                    provider=prov,
                    source_exchange_id=None,
                    severity=Severity.ERROR.value,
                    message=f"Unsupported provider: {provider}",
                )
            ],
        )

    # Parse inputs
    parsed_exchanges, parse_issues = _parse_input_exchanges(exchanges)
    if parse_issues:
        for issue in parse_issues:
            issue.provider = prov
        return AccountReadResult(
            provider=prov,
            as_of=as_of_str,
            outcome=Outcome.INVALID_INPUT.value,
            facts=[],
            issues=parse_issues,
        )

    adapter = get_adapter(prov)
    seen_ids: set[str] = set()
    validated_exchanges: list[dict[str, Any]] = []
    validation_issues: list[Issue] = []

    for ex in parsed_exchanges:
        try:
            val_ex = validate_sanitized_exchange(
                ex,
                expected_provider=prov,
                strict=strict,
                seen_exchange_ids=seen_ids,
            )
            validated_exchanges.append(val_ex)
        except ValidationError as ve:
            validation_issues.append(
                Issue(
                    code=ve.code,
                    provider=prov,
                    source_exchange_id=ve.exchange_id,
                    severity=Severity.ERROR.value,
                    message=ve.message,
                )
            )

    # If any input violated contract or contained secrets, return invalid_input with zero facts
    if validation_issues:
        return AccountReadResult(
            provider=prov,
            as_of=as_of_str,
            outcome=Outcome.INVALID_INPUT.value,
            facts=[],
            issues=validation_issues,
        )

    # Run adapter on each validated exchange
    raw_facts: list[tuple[Fact, str | None]] = []
    adapter_issues: list[Issue] = []
    unsupported_count = 0

    for ex in validated_exchanges:
        res = adapter.reconcile_exchange(ex)
        if not res.is_supported:
            unsupported_count += 1
        raw_facts.extend(res.facts)
        adapter_issues.extend(res.issues)

    # Deduplicate facts
    deduped_facts, dedup_issues = deduplicate_facts(raw_facts, provider=prov)

    # Staleness evaluation
    stale_issues = check_staleness(deduped_facts, as_of=as_of_str, max_age_seconds=max_age_seconds)

    all_issues = adapter_issues + dedup_issues + stale_issues

    # Determine outcome taxonomy
    if not deduped_facts:
        if unsupported_count > 0 or any(i.code == IssueCode.UNSUPPORTED_SCHEMA.value for i in all_issues):
            outcome = Outcome.UNSUPPORTED_SCHEMA.value
        elif any(i.code == IssueCode.MALFORMED_RECORD.value for i in all_issues) or any(i.code == IssueCode.CONFLICTING_DUPLICATE.value for i in all_issues):
            outcome = Outcome.PARTIAL.value
        else:
            outcome = Outcome.OK.value
    else:
        # Facts were produced
        has_partial_issues = any(
            i.code in (IssueCode.MALFORMED_RECORD.value, IssueCode.CONFLICTING_DUPLICATE.value, IssueCode.UNSUPPORTED_SCHEMA.value)
            for i in all_issues
        )
        if has_partial_issues:
            outcome = Outcome.PARTIAL.value
        else:
            outcome = Outcome.OK.value

    return AccountReadResult(
        provider=prov,
        as_of=as_of_str,
        outcome=outcome,
        facts=deduped_facts,
        issues=all_issues,
    )
