"""Deduplication and conflict resolution for reconciliation facts."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .models import Fact, Issue, IssueCode, Severity


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize a dictionary to deterministic, sorted canonical JSON bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_semantic_hash(data: dict[str, Any]) -> str:
    """Compute SHA-256 hash of canonicalized semantic data fields."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


def compute_dedup_key(fact: Fact, native_id: str | None = None) -> str:
    """Compute deduplication key: provider + account_scope + fact_type + (native_id or SHA256)."""
    key_id = native_id.strip() if native_id and str(native_id).strip() else compute_semantic_hash(fact.data)
    return f"{fact.provider}:{fact.account_scope}:{fact.fact_type}:{key_id}"


def deduplicate_facts(
    raw_facts: list[tuple[Fact, str | None]],
    provider: str,
) -> tuple[list[Fact], list[Issue]]:
    """Deduplicate facts using deduplication keys.

    `raw_facts` is a list of tuples: `(Fact, native_id | None)`.

    Rules:
    - Exact duplicates collapse into one fact and generate a `duplicate_event` issue.
    - Conflicting duplicates produce no merged fact and generate a `conflicting_duplicate` issue.
    """
    grouped: dict[str, list[Fact]] = defaultdict(list)
    for fact, native_id in raw_facts:
        key = compute_dedup_key(fact, native_id)
        grouped[key].append(fact)

    final_facts: list[Fact] = []
    issues: list[Issue] = []

    for key, group in grouped.items():
        if len(group) == 1:
            final_facts.append(group[0])
            continue

        # Check if all records in group have identical data
        first_payload_bytes = canonical_json_bytes(group[0].data)
        all_identical = True
        all_source_ids: list[str] = []
        for f in group:
            for s_id in f.source_exchange_ids:
                if s_id not in all_source_ids:
                    all_source_ids.append(s_id)
            if canonical_json_bytes(f.data) != first_payload_bytes:
                all_identical = False

        if all_identical:
            # Exact duplicate: collapse into one fact
            base_fact = group[0]
            merged_fact = Fact(
                fact_id=base_fact.fact_id,
                fact_type=base_fact.fact_type,
                provider=base_fact.provider,
                account_scope=base_fact.account_scope,
                observed_at=base_fact.observed_at,
                source_exchange_ids=all_source_ids,
                data=base_fact.data,
            )
            final_facts.append(merged_fact)
            issues.append(
                Issue(
                    code=IssueCode.DUPLICATE_EVENT.value,
                    provider=provider,
                    source_exchange_id=group[1].source_exchange_ids[0] if group[1].source_exchange_ids else None,
                    severity=Severity.INFO.value,
                    message=f"Duplicate event collapsed into single fact (source IDs: {', '.join(all_source_ids)})",
                )
            )
        else:
            # Conflicting duplicate: omit fact and emit issue
            issues.append(
                Issue(
                    code=IssueCode.CONFLICTING_DUPLICATE.value,
                    provider=provider,
                    source_exchange_id=group[0].source_exchange_ids[0] if group[0].source_exchange_ids else None,
                    severity=Severity.WARNING.value,
                    message=f"Conflicting records detected for key '{key}' (source IDs: {', '.join(all_source_ids)}); record omitted",
                )
            )

    return final_facts, issues
