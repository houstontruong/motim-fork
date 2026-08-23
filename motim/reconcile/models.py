"""Versioned models and data contracts for Motim Account-Read Reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION_INPUT = "motim.sanitized_exchange.v1"
SCHEMA_VERSION_OUTPUT = "motim.account_read.v1"


class FactType(str, Enum):
    POSITION = "position"
    FILL = "fill"
    FUNDING = "funding"
    BALANCE = "balance"
    EQUITY = "equity"
    PNL = "pnl"


class Outcome(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    INVALID_INPUT = "invalid_input"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class IssueCode(str, Enum):
    DUPLICATE_EVENT = "duplicate_event"
    CONFLICTING_DUPLICATE = "conflicting_duplicate"
    STALE_FACT = "stale_fact"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    INVALID_INPUT = "invalid_input"
    MALFORMED_RECORD = "malformed_record"
    AUTH_FIELD_DETECTED = "auth_field_detected"


@dataclass
class Fact:
    fact_id: str
    fact_type: str
    provider: str
    account_scope: str
    observed_at: str
    source_exchange_ids: list[str]
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "fact_type": self.fact_type,
            "provider": self.provider,
            "account_scope": self.account_scope,
            "observed_at": self.observed_at,
            "source_exchange_ids": list(self.source_exchange_ids),
            "data": self.data,
        }


@dataclass
class Issue:
    code: str
    provider: str
    source_exchange_id: str | None
    severity: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "provider": self.provider,
            "source_exchange_id": self.source_exchange_id,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass
class AccountReadResult:
    schema_version: str = SCHEMA_VERSION_OUTPUT
    provider: str = ""
    as_of: str = ""
    outcome: str = Outcome.OK.value
    facts: list[Fact] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "as_of": self.as_of,
            "outcome": self.outcome,
            "facts": [f.to_dict() for f in self.facts],
            "issues": [i.to_dict() for i in self.issues],
        }
